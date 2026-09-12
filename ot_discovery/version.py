"""Resolve a version string for display in the GUI/CLI.

There's no release/tagging process yet, so we show the git commit hash
instead of a hand-maintained semantic version - it always matches what's
actually running. The frozen PyInstaller exe can't call git at runtime, so
the hash is captured at build time into _version.txt and bundled as data
(see ot_discovery.spec).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def get_version() -> str:
    """Short git commit hash the running code was built from, e.g. '983ee39'."""
    if getattr(sys, "frozen", False):
        version_file = Path(sys._MEIPASS) / "_version.txt"  # type: ignore[attr-defined]
        if version_file.is_file():
            return version_file.read_text(encoding="utf-8").strip()
        return "unknown"

    try:
        project_root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
