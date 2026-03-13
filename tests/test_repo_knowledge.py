from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_repo_knowledge_script() -> None:
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "scripts/check_repo_knowledge.py"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
