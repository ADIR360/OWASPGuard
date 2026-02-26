"""
Shared scan service - used by CLI, GUI, and API.
Single entry point for OWASPGuard scanning logic.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.orchestrator import ScanOrchestrator


def run_scan(
    project_path: str,
    languages: List[str] = None,
    max_workers: int = 4,
    use_online_cve: bool = True,
) -> Dict[str, Any]:
    """
    Run a full OWASPGuard scan. Same logic used by CLI and GUI.

    Args:
        project_path: Path to the project to scan (filesystem path)
        languages: Languages to scan, e.g. ['python', 'javascript']
        max_workers: Worker thread count
        use_online_cve: Whether to use online CVE sources

    Returns:
        dict with keys: findings, stats, categorized
    """
    languages = languages or ['python', 'javascript']
    orchestrator = ScanOrchestrator(
        project_path=project_path,
        languages=languages,
        max_workers=max_workers,
        use_online_cve=use_online_cve,
    )
    return orchestrator.scan()
