from __future__ import annotations

from pathlib import Path

from sanara.utils.command import run_cmd


def test_run_cmd_returns_127_for_missing_binary(tmp_path: Path) -> None:
    result = run_cmd(["definitely-not-a-real-binary-sanara-test"], cwd=tmp_path)
    assert result.code == 127
    assert result.stdout == ""
    assert "No such file or directory" in result.stderr
