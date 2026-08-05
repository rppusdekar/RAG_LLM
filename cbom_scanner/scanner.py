"""
Scanner orchestrator.

Walks a target directory (or single file), dispatches detectors,
runs the analyzer, and returns a ScanResult.
"""

from __future__ import annotations
import time
from pathlib import Path
from .models import ScanResult
from .detectors import GenericDetector, PythonDetector
from .analyzer import refine, deduplicate

# Directories to always skip
_SKIP_DIRS = {
    ".git", ".svn", "__pycache__", ".pytest_cache",
    "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", ".eggs",
    ".mypy_cache", ".ruff_cache",
    ".pythonlibs",  # Replit virtual packages
}

# Individual file patterns to skip
_SKIP_PATTERNS = {"*.min.js", "*.map", "*.lock", "pnpm-lock.yaml", "uv.lock"}


_DETECTORS = [
    PythonDetector(),   # AST-based, higher precision for Python
    GenericDetector(),  # Regex-based, broad language coverage
]


def scan(target: str | Path, max_file_size_kb: int = 500) -> ScanResult:
    """
    Scan *target* (file or directory) and return a ScanResult.

    Parameters
    ----------
    target          Path to scan (file or directory).
    max_file_size_kb  Skip files larger than this (binary / generated).
    """
    target = Path(target).resolve()
    result = ScanResult(target_path=str(target))
    t0 = time.monotonic()

    files = _collect_files(target, max_file_size_kb)

    for path in files:
        result.files_scanned += 1
        seen_lines: set[int] = set()

        for detector in _DETECTORS:
            if not detector.can_handle(path):
                continue
            for finding in detector.detect(path):
                # Skip if another detector already reported the same line
                if finding.line_number in seen_lines:
                    continue
                seen_lines.add(finding.line_number)
                result.findings.append(finding)

    # Post-process
    result.findings = refine(result.findings)
    result.findings = deduplicate(result.findings)
    result.scan_duration_s = time.monotonic() - t0

    return result


# ── helpers ──────────────────────────────────────────────────────────────────

def _collect_files(target: Path, max_kb: int) -> list[Path]:
    if target.is_file():
        return [target]

    max_bytes = max_kb * 1024
    out: list[Path] = []

    for path in sorted(target.rglob("*")):
        # Skip hidden/vendor dirs
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        # Skip oversized files (binaries, lock files)
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        # Skip by glob pattern
        if any(path.match(pat) for pat in _SKIP_PATTERNS):
            continue

        # At least one detector can handle this extension
        if any(d.can_handle(path) for d in _DETECTORS):
            out.append(path)

    return out
