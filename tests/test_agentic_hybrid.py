from __future__ import annotations

from types import SimpleNamespace

from sanara.orchestrator import agentic
from sanara.orchestrator.models import FindingState
from sanara.orchestrator.policy import Policy
from sanara.utils.command import CommandResult


def _finding(source_rule_id: str, file_path: str = "main.tf") -> dict:
    return {
        "schema_id": "sanara.finding",
        "schema_version": "0.1",
        "sanara_rule_id": f"checkov.unmapped.{source_rule_id.lower()}",
        "source": "checkov",
        "source_rule_id": source_rule_id,
        "severity": "medium",
        "target": {"module_dir": ".", "file_path": file_path, "line_range": "1-2"},
        "resource_type": "aws_db_instance",
        "resource_name": "app",
    }


def test_agentic_attempts_each_finding(monkeypatch, tmp_path) -> None:
    f1 = _finding("CKV_AWS_118", "main.tf")
    f2 = _finding("CKV_AWS_129", "main.tf")
    attempted_rule_ids: list[str] = []

    def _run_agentic_fallback(*args, **kwargs):
        prompt = kwargs.get("prompt") if "prompt" in kwargs else args[2]
        for finding in [f1, f2]:
            if finding["source_rule_id"] in prompt:
                attempted_rule_ids.append(finding["source_rule_id"])
        return SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff="diff --git a/main.tf b/main.tf\n+publicly_accessible = false\n",
            ledger={"files_sent": [{"path": "main.tf"}], "total_chars": 123},
            trace=[],
        )

    fixed = {"v": False}

    def _state_builder(*args, **kwargs):
        if fixed["v"]:
            return FindingState(
                clean=True, remaining=[], remaining_mapped=[], remaining_uncovered=[]
            )
        fixed["v"] = True
        return FindingState(
            clean=False, remaining=[f2], remaining_mapped=[], remaining_uncovered=[f2]
        )

    monkeypatch.setattr(agentic, "run_agentic_fallback", _run_agentic_fallback)
    monkeypatch.setattr(agentic, "_git_apply_patch", lambda *args, **kwargs: (True, ""))
    monkeypatch.setattr(
        agentic,
        "validate_patch",
        lambda *args, **kwargs: SimpleNamespace(ok=True, code="OK", message="ok"),
    )
    monkeypatch.setattr(
        agentic,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, runs=[], to_dict=lambda: {"ok": True, "runs": []}
        ),
    )
    monkeypatch.setattr(
        agentic,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(cmd=cmd, code=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(agentic, "run_scan_only", lambda *args, **kwargs: {"checkov": {}})

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(),
        repair_profiles={},
        clean=False,
        remaining=[f1, f2],
        remaining_mapped=[],
        remaining_uncovered=[f1, f2],
        diff="",
        build_current_findings_state=_state_builder,
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=10,
    )

    assert result.clean is True
    assert "CKV_AWS_118" in attempted_rule_ids


def test_agentic_respects_total_attempt_budget(monkeypatch, tmp_path) -> None:
    f = _finding("CKV_AWS_293", "main.tf")
    monkeypatch.setattr(
        agentic,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff="diff --git a/main.tf b/main.tf\n+publicly_accessible = false\n",
            ledger={"files_sent": [{"path": "main.tf"}], "total_chars": 100},
            trace=[],
        ),
    )
    monkeypatch.setattr(agentic, "_git_apply_patch", lambda *args, **kwargs: (True, ""))
    monkeypatch.setattr(
        agentic,
        "validate_patch",
        lambda *args, **kwargs: SimpleNamespace(ok=True, code="OK", message="ok"),
    )
    monkeypatch.setattr(
        agentic,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, runs=[], to_dict=lambda: {"ok": True, "runs": []}
        ),
    )
    monkeypatch.setattr(
        agentic,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(cmd=cmd, code=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(agentic, "run_scan_only", lambda *args, **kwargs: {"checkov": {}})
    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(),
        repair_profiles={},
        clean=False,
        remaining=[f],
        remaining_mapped=[],
        remaining_uncovered=[f],
        diff="",
        build_current_findings_state=lambda *args, **kwargs: FindingState(
            clean=False, remaining=[f], remaining_mapped=[], remaining_uncovered=[f]
        ),
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=3,
    )

    assert 0 < len(result.agentic_ledgers) <= 3
    assert ("budget" in result.feedback) or ("finding still present" in result.feedback)


def test_agentic_rolls_back_no_progress_patch(monkeypatch, tmp_path) -> None:
    tf = tmp_path / "main.tf"
    original = 'resource "aws_db_instance" "app" {}\n'
    tf.write_text(original, encoding="utf-8")
    f = _finding("CKV_AWS_293", "main.tf")

    monkeypatch.setattr(
        agentic,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff=(
                "diff --git a/main.tf b/main.tf\n"
                "--- a/main.tf\n"
                "+++ b/main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_db_instance" "app" {}\n'
                "+# llm edit\n"
            ),
            ledger={"files_sent": [{"path": "main.tf"}], "total_chars": 100},
            trace=[],
        ),
    )
    monkeypatch.setattr(
        agentic,
        "validate_patch",
        lambda *args, **kwargs: SimpleNamespace(ok=True, code="OK", message="ok"),
    )
    monkeypatch.setattr(
        agentic,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, runs=[], to_dict=lambda: {"ok": True, "runs": []}
        ),
    )
    monkeypatch.setattr(
        agentic,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(cmd=cmd, code=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(agentic, "run_scan_only", lambda *args, **kwargs: {"checkov": {}})

    def _state_builder(*args, **kwargs):
        return FindingState(
            clean=False, remaining=[f], remaining_mapped=[], remaining_uncovered=[f]
        )

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(),
        repair_profiles={},
        clean=False,
        remaining=[f],
        remaining_mapped=[],
        remaining_uncovered=[f],
        diff="",
        build_current_findings_state=_state_builder,
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=1,
    )

    assert result.agentic_ledgers[0]["accepted_patch"] is False
    assert result.agentic_ledgers[0]["rejection_stage"] == "no_progress"
    assert tf.read_text(encoding="utf-8") == original
