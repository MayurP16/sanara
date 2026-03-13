from __future__ import annotations

from types import SimpleNamespace

import pytest

from sanara.orchestrator import driver


def _ctx():
    return SimpleNamespace(
        repo="org/repo",
        base_sha="base",
        head_sha="head",
        event_name="pull_request",
        actor="dev",
        is_fork=False,
    )


def test_reason_code_set_contains_expected_values() -> None:
    expected = {
        "pr_created",
        "dedup_match",
        "publish_dry_run",
        "missing_github_token",
        "fork_restriction",
        "no_changes",
        "remaining_findings",
        "tf_checks_failed",
        "missing_harness",
        "runtime_budget",
        "git_failure",
        "NOT_ALLOWLISTED",
        "BLOCKED_BY_RAIL",
    }
    assert expected.issubset(driver.ALLOWED_REASON_CODES)


def test_write_run_summary_rejects_unknown_reason_code(tmp_path) -> None:
    with pytest.raises(ValueError):
        driver._write_run_summary(
            out_dir=tmp_path,
            context=_ctx(),
            target_dirs=[],
            normalized=[],
            attempts=[],
            decision="COMMENT_ONLY",
            decision_detail={"reason_code": "not_a_real_reason", "message": "bad"},
        )


def test_write_run_summary_includes_terraform_runtime_details(tmp_path) -> None:
    payload = driver._write_run_summary(
        out_dir=tmp_path,
        context=_ctx(),
        target_dirs=[],
        normalized=[],
        attempts=[],
        decision="PR_CREATED",
        decision_detail={"reason_code": "pr_created", "message": "ok"},
        runtime_budget={"elapsed_seconds": 1, "remaining_seconds": 9, "max_runtime_seconds": 10},
        terraform_summary={
            "ok": True,
            "runs": [
                {
                    "name": "root",
                    "working_dir": "/tmp/workspace",
                    "source": "harness",
                    "ok": True,
                    "init": {
                        "cmd": ["terraform", "init", "-backend=true"],
                        "code": 0,
                        "stdout": "ok",
                        "stderr": "",
                    },
                    "validate": {
                        "cmd": ["terraform", "validate"],
                        "code": 0,
                        "stdout": "ok",
                        "stderr": "",
                    },
                    "plan": {
                        "cmd": ["terraform", "plan"],
                        "code": 0,
                        "stdout": "ok",
                        "stderr": "",
                    },
                }
            ],
        },
    )
    assert payload["terraform"]["ok"] is True
    assert payload["terraform"]["runs"][0]["init"]["cmd"] == [
        "terraform",
        "init",
        "-backend=true",
    ]
