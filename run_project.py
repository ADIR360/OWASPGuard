#!/usr/bin/env python3
"""
Single command to run OWASPGuard: builds frontend, frees port, starts API server.
Usage: python run_project.py
"""
import os
import sys
import time
import webbrowser
import subprocess
from pathlib import Path

# Project root = parent of this script
ROOT = Path(__file__).resolve().parent
OWASP = ROOT / "OWASPGuard"
FRONTEND = OWASP / "frontend"
DIST = FRONTEND / "dist"
DEFAULT_PORT = 8000


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def err(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr, flush=True)


def kill_port(port: int) -> bool:
    """Try to kill process on given port. Returns True if freed or already free."""
    try:
        out = subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True,
            text=True,
        )
        pids = out.stdout.strip().split()
        if not pids:
            return True
        for pid in pids:
            if pid.isdigit():
                subprocess.run(["kill", "-9", pid], capture_output=True)
        time.sleep(0.5)
        return True
    except Exception:
        return False


def build_frontend() -> bool:
    """Build React frontend if dist missing or stale. Returns True on success."""
    if not (FRONTEND / "package.json").exists():
        return True
    need_build = not DIST.exists() or not (DIST / "index.html").exists()
    if not need_build:
        return True
    log("Building frontend...")
    try:
        subprocess.run(
            ["npm", "run", "build"],
            cwd=FRONTEND,
            check=True,
            capture_output=True,
        )
        log("Frontend built.")
        return True
    except subprocess.CalledProcessError as e:
        err(f"Frontend build failed: {e}")
        return False
    except FileNotFoundError:
        err("npm not found. Install Node.js or skip frontend build.")
        return True  # Still try to run backend


def start_server(port: int) -> None:
    """Start the API server (serves frontend + API)."""
    log(f"Starting OWASPGuard on http://localhost:{port}")
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        import uvicorn
        uvicorn.run(
            "OWASPGuard.api.server:app",
            host="0.0.0.0",
            port=port,
            reload=os.environ.get("OWASPGUARD_RELOAD", "1") == "1",
        )
    except ImportError:
        err("uvicorn not found. Run: pip install uvicorn fastapi")
        sys.exit(1)


def main():
    os.chdir(ROOT)
    port = int(os.environ.get("OWASPGUARD_PORT", DEFAULT_PORT))

    log("OWASPGuard - single command launcher")

    if not kill_port(port):
        err(f"Could not free port {port}. Try another: OWASPGUARD_PORT=8001 python run_project.py")
        sys.exit(1)
    log(f"Port {port} is free.")

    if not build_frontend():
        sys.exit(1)

    url = f"http://localhost:{port}"
    log(f"Open {url} in your browser")
    try:
        webbrowser.open(url)
    except Exception:
        pass

    start_server(port)


if __name__ == "__main__":
    main()
