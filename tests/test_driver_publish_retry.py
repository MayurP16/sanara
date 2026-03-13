from __future__ import annotations

from pathlib import Path

from sanara.orchestrator import driver
from sanara.utils.command import CommandError, CommandResult


def test_ensure_branch_and_push_retries_on_branch_collision(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    state = {"first_checkout": True}

    def _run_cmd_checked(cmd, cwd, **kwargs):
        _ = cwd, kwargs
        calls.append(cmd)
        if cmd[:3] == ["git", "checkout", "-b"] and state["first_checkout"]:
            state["first_checkout"] = False
            raise CommandError(
                CommandResult(cmd=cmd, code=1, stdout="", stderr="already a branch named")
            )
        return CommandResult(cmd=cmd, code=0, stdout="", stderr="")

    monkeypatch.setattr(driver, "run_cmd_checked", _run_cmd_checked)
    branch = driver._ensure_branch_and_push(tmp_path, "sanara/fix-test", retries=3)

    assert branch == "sanara/fix-test-1"
    assert ["git", "checkout", "-b", "sanara/fix-test"] in calls
    assert ["git", "checkout", "-b", "sanara/fix-test-1"] in calls
