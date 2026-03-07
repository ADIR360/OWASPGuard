import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# Ensure project root (OWASPGuard) is importable - resolve to absolute path
_project_dir = Path(__file__).resolve().parent
project_root = _project_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.scan_service import run_scan as run_scan_service  # noqa: E402
from reporting.pdf_report import PDFReportGenerator  # noqa: E402

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False


def _normalize_github_url(url: str) -> str:
    """Convert various GitHub URL formats (and deep links) to a clone URL."""
    url = url.strip()

    # Normalize https://github.com/owner/repo[/...]
    if url.startswith("https://github.com/"):
        path = url[len("https://github.com/") :].strip("/")
        parts = path.split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            # Drop .git if present in repo name
            repo = repo[:-4] if repo.endswith(".git") else repo
            return f"https://github.com/{owner}/{repo}.git"
        return url

    # github.com/owner/repo[/...]
    if url.startswith("github.com/"):
        path = url[len("github.com/") :].strip("/")
        parts = path.split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            repo = repo[:-4] if repo.endswith(".git") else repo
            return f"https://github.com/{owner}/{repo}.git"
        return f"https://{url.rstrip('/')}"

    # git@github.com:owner/repo[.git]
    if url.startswith("git@github.com:"):
        user_repo = url.replace("git@github.com:", "").strip("/")
        if user_repo.endswith(".git"):
            user_repo = user_repo[:-4]
        owner, repo = user_repo.split("/", 1)
        return f"https://github.com/{owner}/{repo}.git"

    return url


class ScanRequest(BaseModel):
    project_path: str = Field(
        ...,
        description="Absolute or relative path to the project to scan, from the server's filesystem.",
    )
    languages: List[str] = Field(
        default_factory=lambda: ["python", "javascript"],
        description="Languages to scan (e.g. ['python', 'javascript']).",
    )
    max_workers: int = Field(
        default=4,
        ge=1,
        le=32,
        description="Maximum number of worker threads for parallel scanning.",
    )
    use_online_cve: bool = Field(
        default=True,
        description="Whether to use online CVE sources in addition to local/OSV databases.",
    )


class ScanGitHubRequest(BaseModel):
    repo_url: str = Field(
        ...,
        description="GitHub repository URL (e.g. https://github.com/owner/repo)",
    )
    branch: Optional[str] = Field(
        default=None,
        description="Branch to clone. Default: default branch.",
    )
    languages: List[str] = Field(
        default_factory=lambda: ["python", "javascript"],
        description="Languages to scan.",
    )
    max_workers: int = Field(default=4, ge=1, le=32)
    use_online_cve: bool = Field(default=True)


class PdfReportRequest(BaseModel):
    """Request body for generating a PDF report from existing scan results."""

    results: Dict[str, Any] = Field(
        ...,
        description="Full scan results object as returned by /api/scan or /api/scan/github.",
    )


app = FastAPI(
    title="OWASPGuard API",
    description="FastAPI backend for OWASPGuard SAST/SCA/Config scanning.",
    version="1.0.0",
)

# CORS – allow local frontends; lock down later if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict:
    """Simple health check."""
    return {"status": "ok"}


@app.get("/api/info")
async def info() -> dict:
    """API info for frontend connectivity check."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "github_scan": GIT_AVAILABLE,
        "endpoints": ["/api/scan", "/api/scan/github", "/api/report/pdf"],
    }


@app.post("/api/scan")
async def scan_project(request: ScanRequest) -> dict:
    """
    Run a full OWASPGuard scan for a given project path.

    This is a synchronous, potentially long-running operation (minutes)
    depending on project size and SCA/OSV usage.
    """
    project_path = Path(request.project_path).expanduser().resolve()
    if not project_path.exists():
        raise HTTPException(status_code=400, detail=f"Project path does not exist: {project_path}")

    try:
        results = run_scan_service(
            project_path=str(project_path),
            languages=request.languages,
            max_workers=request.max_workers,
            use_online_cve=request.use_online_cve,
        )
        return results
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/scan/github")
async def scan_github(request: ScanGitHubRequest) -> dict:
    """
    Clone a GitHub repository and run a full OWASPGuard scan.

    Accepts URLs like:
    - https://github.com/owner/repo
    - github.com/owner/repo
    - git@github.com:owner/repo.git
    """
    if not GIT_AVAILABLE:
        raise HTTPException(
            status_code=500,
            detail="GitPython is required for GitHub scanning. Install with: pip install GitPython",
        )
    clone_url = _normalize_github_url(request.repo_url)
    if "github.com" not in clone_url:
        raise HTTPException(status_code=400, detail="Only GitHub repository URLs are supported")

    temp_dir = tempfile.mkdtemp(prefix="owaspguard_scan_")
    try:
        clone_opts = {"url": clone_url, "to_path": temp_dir, "depth": 1}
        if request.branch:
            clone_opts["branch"] = request.branch
        git.Repo.clone_from(**clone_opts)

        results = run_scan_service(
            project_path=temp_dir,
            languages=request.languages,
            max_workers=request.max_workers,
            use_online_cve=request.use_online_cve,
        )
        # Add repo context to stats for the UI
        if "stats" not in results:
            results["stats"] = {}
        results["stats"]["repo_url"] = clone_url
        results["stats"]["source"] = "github"
        return results
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"GitHub scan failed: {exc}")
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


@app.post("/api/report/pdf")
async def generate_pdf_report(
    request: PdfReportRequest,
    background_tasks: BackgroundTasks,
) -> FileResponse:
    """
    Generate a PDF report from scan results and return it as a downloadable file.

    The frontend typically sends the findings, stats, and categorized data
    it already has in memory from a previous /api/scan or /api/scan/github call.
    """
    try:
        tmp_dir = tempfile.mkdtemp(prefix="owaspguard_pdf_")
        generator = PDFReportGenerator()
        pdf_path = generator.generate(request.results, output_dir=tmp_dir)

        # Clean up the temporary directory after the response is sent
        background_tasks.add_task(shutil.rmtree, tmp_dir, ignore_errors=True)

        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=Path(pdf_path).name,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {exc}")


# Serve frontend: prefer React build, fallback to static web
frontend_dist = project_root / "frontend" / "dist"
web_dir = project_root / "web"
static_dir = frontend_dist if frontend_dist.exists() else web_dir
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="web")


def main():
    """
    Convenience entry point:

    python -m OWASPGuard.api.server
    """
    import uvicorn

    uvicorn.run(
        "OWASPGuard.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()

