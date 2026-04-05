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
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "app" {}\n', encoding="utf-8")
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
            patch_diff=(
                "diff --git a/main.tf b/main.tf\n"
                "--- a/main.tf\n"
                "+++ b/main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_db_instance" "app" {}\n'
                "+publicly_accessible = false\n"
            ),
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
        policy=Policy(finding_policy={"hard_fail_on": ["CKV_AWS_118", "CKV_AWS_129"]}),
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
    assert attempted_rule_ids[:2] == ["CKV_AWS_118", "CKV_AWS_129"]


def test_agentic_retargets_current_remaining_after_progress(monkeypatch, tmp_path) -> None:
    (tmp_path / "a.tf").write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    (tmp_path / "b.tf").write_text('resource "aws_s3_bucket" "app2" {}\n', encoding="utf-8")
    f1 = _finding("CKV2_AWS_6", "a.tf")
    f2 = _finding("CKV_AWS_79", "b.tf")
    prompts: list[str] = []

    def _run_agentic_fallback(*args, **kwargs):
        prompt = kwargs.get("prompt") if "prompt" in kwargs else args[2]
        prompts.append(prompt)
        target_file = "a.tf" if "CKV2_AWS_6" in prompt else "b.tf"
        file_content = (
            'resource "aws_s3_bucket" "app" {}'
            if target_file == "a.tf"
            else 'resource "aws_s3_bucket" "app2" {}'
        )
        return SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff=(
                f"diff --git a/{target_file} b/{target_file}\n"
                f"--- a/{target_file}\n"
                f"+++ b/{target_file}\n"
                "@@ -1 +1,2 @@\n"
                f" {file_content}\n"
                "+# fix\n"
            ),
            ledger={"files_sent": [{"path": target_file}], "total_chars": 123},
            trace=[],
        )

    states = iter(
        [
            FindingState(
                clean=False, remaining=[f2], remaining_mapped=[], remaining_uncovered=[f2]
            ),
            FindingState(clean=True, remaining=[], remaining_mapped=[], remaining_uncovered=[]),
        ]
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
        policy=Policy(finding_policy={"hard_fail_on": ["CKV2_AWS_6", "CKV_AWS_79"]}),
        repair_profiles={},
        clean=False,
        remaining=[f1, f2],
        remaining_mapped=[],
        remaining_uncovered=[f1, f2],
        diff="",
        build_current_findings_state=lambda *args, **kwargs: next(states),
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=5,
    )

    assert result.clean is True
    assert "CKV2_AWS_6" in prompts[0]
    assert "CKV_AWS_79" in prompts[1]


def test_agentic_respects_total_attempt_budget(monkeypatch, tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "app" {}\n', encoding="utf-8")
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
        policy=Policy(finding_policy={"hard_fail_on": ["CKV_AWS_293"]}),
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


def test_agentic_stops_before_attempt_when_runtime_budget_is_nearly_exhausted(
    monkeypatch, tmp_path
) -> None:
    f = _finding("CKV_AWS_293", "main.tf")
    calls = {"agentic": 0}

    def _run_agentic_fallback(*args, **kwargs):
        calls["agentic"] += 1
        return SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff="diff --git a/main.tf b/main.tf\n+publicly_accessible = false\n",
            ledger={"files_sent": [{"path": "main.tf"}], "total_chars": 100},
            trace=[],
        )

    monkeypatch.setattr(agentic, "run_agentic_fallback", _run_agentic_fallback)
    monkeypatch.setattr(agentic.time, "time", lambda: 1000.0)

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(finding_policy={"hard_fail_on": ["CKV_AWS_293"]}),
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
        run_deadline_epoch=1060.0,
    )

    assert calls["agentic"] == 0
    assert result.feedback == "agentic runtime budget reached"
    assert result.agentic_ledgers == []


def test_agentic_stops_after_progress_when_runtime_budget_is_reached(monkeypatch, tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "app" {}\n', encoding="utf-8")
    f1 = _finding("CKV_AWS_118", "main.tf")
    f2 = _finding("CKV_AWS_129", "main.tf")
    calls = {"agentic": 0}

    def _run_agentic_fallback(*args, **kwargs):
        calls["agentic"] += 1
        return SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff=(
                "diff --git a/main.tf b/main.tf\n"
                "--- a/main.tf\n"
                "+++ b/main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_db_instance" "app" {}\n'
                "+publicly_accessible = false\n"
            ),
            ledger={"files_sent": [{"path": "main.tf"}], "total_chars": 100},
            trace=[],
        )

    time_values = iter([1000.0, 1000.0, 1120.0])
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
    monkeypatch.setattr(agentic.time, "time", lambda: next(time_values))

    states = iter(
        [
            FindingState(
                clean=False, remaining=[f2], remaining_mapped=[], remaining_uncovered=[f2]
            ),
        ]
    )

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(finding_policy={"hard_fail_on": ["CKV_AWS_118", "CKV_AWS_129"]}),
        repair_profiles={},
        clean=False,
        remaining=[f1, f2],
        remaining_mapped=[],
        remaining_uncovered=[f1, f2],
        diff="",
        build_current_findings_state=lambda *args, **kwargs: next(states),
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=5,
        run_deadline_epoch=1100.0,
    )

    assert calls["agentic"] == 1
    assert result.feedback == "agentic runtime budget reached"
    assert len(result.remaining) == 1
    assert result.remaining[0]["source_rule_id"] == "CKV_AWS_129"


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
        policy=Policy(finding_policy={"hard_fail_on": ["CKV_AWS_293"]}),
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


def test_agentic_blocks_finding_after_no_progress(monkeypatch, tmp_path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_db_instance" "app" {}\n', encoding="utf-8")
    f = _finding("CKV_AWS_293", "main.tf")
    calls = {"n": 0}

    def _run_agentic_fallback(*args, **kwargs):
        calls["n"] += 1
        return SimpleNamespace(
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
        )

    monkeypatch.setattr(agentic, "run_agentic_fallback", _run_agentic_fallback)
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
        policy=Policy(finding_policy={"hard_fail_on": ["CKV_AWS_293"]}),
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
        max_total_attempts=5,
    )

    assert calls["n"] == 1
    assert len(result.agentic_ledgers) == 1
    assert result.agentic_ledgers[0]["rejection_stage"] == "no_progress"


def test_agentic_accepts_progress_when_only_baseline_tf_failure_remains(
    monkeypatch, tmp_path
) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    f = _finding("CKV2_AWS_6", "main.tf")

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
                ' resource "aws_s3_bucket" "app" {}\n'
                '+resource "aws_s3_bucket_public_access_block" "app" {}\n'
            ),
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

    baseline_tf = {
        "ok": False,
        "runs": [
            {
                "name": "aws",
                "working_dir": str(tmp_path),
                "init": {"code": 1, "stderr": "Error: Invalid quoted type constraints"},
                "validate": {"code": 1, "stderr": "skipped: init failed"},
                "plan": {"code": 0, "stdout": "skipped"},
            }
        ],
    }

    monkeypatch.setattr(
        agentic,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=False,
            runs=baseline_tf["runs"],
            to_dict=lambda: baseline_tf,
        ),
    )
    monkeypatch.setattr(
        agentic,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(
            cmd=cmd,
            code=0,
            stdout=(
                "diff --git a/main.tf b/main.tf\n"
                "--- a/main.tf\n"
                "+++ b/main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_s3_bucket" "app" {}\n'
                '+resource "aws_s3_bucket_public_access_block" "app" {}\n'
            ),
            stderr="",
        ),
    )
    monkeypatch.setattr(agentic, "run_scan_only", lambda *args, **kwargs: {"checkov": {}})

    def _state_builder(*args, **kwargs):
        return FindingState(clean=True, remaining=[], remaining_mapped=[], remaining_uncovered=[])

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(finding_policy={"hard_fail_on": ["CKV2_AWS_6"]}),
        repair_profiles={},
        clean=False,
        remaining=[f],
        remaining_mapped=[],
        remaining_uncovered=[f],
        diff="",
        build_current_findings_state=_state_builder,
        write_terraform_logs=lambda *args, **kwargs: None,
        baseline_tf_checks=baseline_tf,
        max_total_attempts=1,
    )

    assert result.clean is True
    assert result.agentic_ledgers[0]["accepted_patch"] is True
    assert result.agentic_ledgers[0]["terraform_gate"] == "baseline_failure_unchanged"


def test_agentic_no_progress_after_tf_rescan_does_not_rescan_twice(monkeypatch, tmp_path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    f = _finding("CKV2_AWS_6", "main.tf")
    scan_calls = {"n": 0}

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
                ' resource "aws_s3_bucket" "app" {}\n'
                '+resource "aws_s3_bucket_public_access_block" "app" {}\n'
            ),
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

    baseline_tf = {
        "ok": False,
        "runs": [
            {
                "name": "aws",
                "working_dir": str(tmp_path),
                "init": {"code": 1, "stderr": "Error: Invalid quoted type constraints"},
                "validate": {"code": 1, "stderr": "skipped: init failed"},
                "plan": {"code": 0, "stdout": "skipped"},
            }
        ],
    }

    monkeypatch.setattr(
        agentic,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=False,
            runs=baseline_tf["runs"],
            to_dict=lambda: baseline_tf,
        ),
    )
    monkeypatch.setattr(
        agentic,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(
            cmd=cmd,
            code=0,
            stdout=(
                "diff --git a/main.tf b/main.tf\n"
                "--- a/main.tf\n"
                "+++ b/main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_s3_bucket" "app" {}\n'
                '+resource "aws_s3_bucket_public_access_block" "app" {}\n'
            ),
            stderr="",
        ),
    )

    def _run_scan_only(*args, **kwargs):
        scan_calls["n"] += 1
        return {"checkov": {}}

    monkeypatch.setattr(agentic, "run_scan_only", _run_scan_only)

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(finding_policy={"hard_fail_on": ["CKV2_AWS_6"]}),
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
        baseline_tf_checks=baseline_tf,
        max_total_attempts=1,
    )

    assert scan_calls["n"] == 1
    assert result.agentic_ledgers[0]["rejection_stage"] == "no_progress"
    assert result.agentic_ledgers[0]["terraform_gate"] == "baseline_failure_unchanged"


def test_agentic_rejects_changed_tf_failure_even_when_baseline_failed(
    monkeypatch, tmp_path
) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    f = _finding("CKV2_AWS_6", "main.tf")

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
                ' resource "aws_s3_bucket" "app" {}\n'
                '+resource "aws_s3_bucket_public_access_block" "app" {}\n'
            ),
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

    baseline_tf = {
        "ok": False,
        "runs": [
            {
                "name": "aws",
                "working_dir": str(tmp_path),
                "init": {"code": 1, "stderr": "Error: Invalid quoted type constraints"},
                "validate": {"code": 1, "stderr": "skipped: init failed"},
                "plan": {"code": 0, "stdout": "skipped"},
            }
        ],
    }
    current_tf = {
        "ok": False,
        "runs": [
            {
                "name": "aws",
                "working_dir": str(tmp_path),
                "init": {"code": 0, "stderr": ""},
                "validate": {"code": 1, "stderr": "Error: Unsupported argument"},
                "plan": {"code": 0, "stdout": "skipped"},
            }
        ],
    }

    monkeypatch.setattr(
        agentic,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=False,
            runs=current_tf["runs"],
            to_dict=lambda: current_tf,
        ),
    )
    monkeypatch.setattr(
        agentic,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(
            cmd=cmd,
            code=0,
            stdout=(
                "diff --git a/main.tf b/main.tf\n"
                "--- a/main.tf\n"
                "+++ b/main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_s3_bucket" "app" {}\n'
                '+resource "aws_s3_bucket_public_access_block" "app" {}\n'
            ),
            stderr="",
        ),
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
        baseline_tf_checks=baseline_tf,
        max_total_attempts=1,
    )

    assert result.agentic_ledgers[0]["accepted_patch"] is False
    assert result.agentic_ledgers[0]["rejection_stage"] == "terraform_checks"
    assert result.agentic_ledgers[0]["terraform_gate"] == "new_or_changed_failure"


def test_agentic_stops_after_provider_unavailable(monkeypatch, tmp_path) -> None:
    (tmp_path / "a.tf").write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    (tmp_path / "b.tf").write_text('resource "aws_s3_bucket" "app2" {}\n', encoding="utf-8")
    f1 = _finding("CKV2_AWS_6", "a.tf")
    f2 = _finding("CKV_AWS_79", "b.tf")
    calls = {"n": 0}

    def _run_agentic_fallback(*args, **kwargs):
        calls["n"] += 1
        return SimpleNamespace(
            ok=False,
            message="llm_provider=anthropic but ANTHROPIC_API_KEY is missing",
            patch_diff="",
            ledger={},
            trace=[],
        )

    monkeypatch.setattr(agentic, "run_agentic_fallback", _run_agentic_fallback)

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
        build_current_findings_state=lambda *args, **kwargs: FindingState(
            clean=False, remaining=[f1, f2], remaining_mapped=[], remaining_uncovered=[f1, f2]
        ),
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=5,
    )

    assert calls["n"] == 1
    assert result.feedback == "agentic provider unavailable"
    assert result.agentic_ledgers[0]["rejection_stage"] == "provider_call"


def test_agentic_canonicalizes_single_target_patch_path(monkeypatch, tmp_path) -> None:
    tf = tmp_path / "examples/complete/main.tf"
    tf.parent.mkdir(parents=True)
    tf.write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    f = {
        "source_rule_id": "CKV2_AWS_6",
        "resource_type": "aws_s3_bucket",
        "resource_name": "app",
        "target": {
            "module_dir": "examples/complete",
            "file_path": "/main.tf",
            "line_range": "1-2",
        },
    }

    monkeypatch.setattr(
        agentic,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff=(
                "diff --git a/../../main.tf b/../../main.tf\n"
                "--- a/../../main.tf\n"
                "+++ b/../../main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_s3_bucket" "app" {}\n'
                "+# llm edit\n"
            ),
            ledger={"files_sent": [{"path": "../../main.tf"}], "total_chars": 100},
            trace=[],
        ),
    )
    seen_patch = {"text": ""}
    monkeypatch.setattr(
        agentic,
        "_git_apply_patch",
        lambda workspace, patch_text: (seen_patch.__setitem__("text", patch_text) or True, ""),
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
            clean=True, remaining=[], remaining_mapped=[], remaining_uncovered=[]
        ),
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=1,
    )

    assert result.clean is True
    assert "a/examples/complete/main.tf b/examples/complete/main.tf" in seen_patch["text"]


def test_agentic_allows_one_retry_for_path_related_git_apply_failure(monkeypatch, tmp_path) -> None:
    tf = tmp_path / "examples/complete/main.tf"
    tf.parent.mkdir(parents=True)
    tf.write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    f = {
        "source_rule_id": "CKV2_AWS_6",
        "resource_type": "aws_s3_bucket",
        "resource_name": "app",
        "target": {
            "module_dir": "examples/complete",
            "file_path": "/main.tf",
            "line_range": "1-2",
        },
    }
    calls = {"n": 0}

    def _run_agentic_fallback(*args, **kwargs):
        calls["n"] += 1
        return SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff=(
                "diff --git a/../../main.tf b/../../main.tf\n"
                "--- a/../../main.tf\n"
                "+++ b/../../main.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_s3_bucket" "app" {}\n'
                "+# fix\n"
            ),
            ledger={"files_sent": [{"path": "../../main.tf"}], "total_chars": 100},
            trace=[],
        )

    def _git_apply_patch(*args, **kwargs):
        return False, "error: ../../main.tf: No such file or directory"

    monkeypatch.setattr(agentic, "run_agentic_fallback", _run_agentic_fallback)
    monkeypatch.setattr(agentic, "_git_apply_patch", _git_apply_patch)
    monkeypatch.setattr(
        agentic,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(cmd=cmd, code=0, stdout="", stderr=""),
    )

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(finding_policy={"hard_fail_on": ["CKV2_AWS_6"]}),
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
        max_total_attempts=2,
    )

    assert calls["n"] == 2
    assert result.agentic_ledgers[-1]["rejection_stage"] == "git_apply"


def test_agentic_rejects_prose_contaminated_patch_before_git_apply(monkeypatch, tmp_path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "app" {}\n', encoding="utf-8")
    f = {
        "source_rule_id": "CKV2_AWS_65",
        "resource_type": "aws_s3_bucket",
        "resource_name": "app",
        "target": {
            "module_dir": ".",
            "file_path": "/main.tf",
            "line_range": "1-2",
        },
    }
    git_apply_called = {"v": False}

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
                "@@ -1 +1 @@\n"
                "Wait, I need to see the actual content first.\n"
            ),
            ledger={"files_sent": [{"path": "main.tf"}], "total_chars": 100},
            trace=[],
        ),
    )
    monkeypatch.setattr(
        agentic,
        "_git_apply_patch",
        lambda *args, **kwargs: (git_apply_called.__setitem__("v", True) or True, ""),
    )

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(finding_policy={"hard_fail_on": ["CKV2_AWS_65"]}),
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
        max_total_attempts=1,
    )

    assert git_apply_called["v"] is False
    assert result.agentic_ledgers[0]["rejection_stage"] == "quality_gate"
    assert "non-diff content" in result.agentic_ledgers[0]["rejection_reason"]


def test_agentic_blocks_only_failed_finding_not_entire_rule(monkeypatch, tmp_path) -> None:
    f1 = {
        "source_rule_id": "CKV2_AWS_62",
        "resource_type": "aws_s3_bucket",
        "resource_name": "one",
        "target": {"module_dir": ".", "file_path": "/a.tf", "line_range": "1-2"},
    }
    f2 = {
        "source_rule_id": "CKV2_AWS_62",
        "resource_type": "aws_s3_bucket",
        "resource_name": "two",
        "target": {"module_dir": ".", "file_path": "/b.tf", "line_range": "1-2"},
    }
    (tmp_path / "a.tf").write_text('resource "aws_s3_bucket" "one" {}\n', encoding="utf-8")
    (tmp_path / "b.tf").write_text('resource "aws_s3_bucket" "two" {}\n', encoding="utf-8")
    prompts: list[str] = []
    calls = {"n": 0}

    def _run_agentic_fallback(*args, **kwargs):
        calls["n"] += 1
        prompt = kwargs.get("prompt") if "prompt" in kwargs else args[2]
        prompts.append(prompt)
        if "aws_s3_bucket.one" in prompt:
            return SimpleNamespace(
                ok=True,
                message="ok",
                patch_diff=(
                    "diff --git a/a.tf b/a.tf\n"
                    "--- a/a.tf\n"
                    "+++ b/a.tf\n"
                    "@@ -1 +1,2 @@\n"
                    ' resource "aws_s3_bucket" "one" {}\n'
                    "+# fix\n"
                ),
                ledger={"files_sent": [{"path": "a.tf"}], "total_chars": 100},
                trace=[],
            )
        return SimpleNamespace(
            ok=True,
            message="ok",
            patch_diff=(
                "diff --git a/b.tf b/b.tf\n"
                "--- a/b.tf\n"
                "+++ b/b.tf\n"
                "@@ -1 +1,2 @@\n"
                ' resource "aws_s3_bucket" "two" {}\n'
                "+# fix\n"
            ),
            ledger={"files_sent": [{"path": "b.tf"}], "total_chars": 100},
            trace=[],
        )

    def _git_apply_patch(workspace, patch_text):
        if "a.tf" in patch_text:
            return False, "error: wrong patch"
        return True, ""

    states = iter(
        [
            FindingState(clean=True, remaining=[], remaining_mapped=[], remaining_uncovered=[]),
        ]
    )

    monkeypatch.setattr(agentic, "run_agentic_fallback", _run_agentic_fallback)
    monkeypatch.setattr(agentic, "_git_apply_patch", _git_apply_patch)
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
        policy=Policy(finding_policy={"hard_fail_on": ["CKV2_AWS_62"]}),
        repair_profiles={},
        clean=False,
        remaining=[f1, f2],
        remaining_mapped=[],
        remaining_uncovered=[f1, f2],
        diff="",
        build_current_findings_state=lambda *args, **kwargs: next(states),
        write_terraform_logs=lambda *args, **kwargs: None,
        max_total_attempts=3,
    )

    assert calls["n"] == 2
    assert result.clean is True
    assert any("aws_s3_bucket.one" in prompt for prompt in prompts)
    assert any("aws_s3_bucket.two" in prompt for prompt in prompts)


def test_agentic_rejects_missing_target_before_llm_call(monkeypatch, tmp_path) -> None:
    f = {
        "source_rule_id": "CKV2_AWS_6",
        "resource_type": "aws_s3_bucket",
        "resource_name": "app",
        "target": {"module_dir": ".", "file_path": "/missing.tf", "line_range": "1-2"},
    }
    called = {"v": False}

    monkeypatch.setattr(
        agentic,
        "run_agentic_fallback",
        lambda *args, **kwargs: (called.__setitem__("v", True), None)[1],
    )

    result = agentic.run_agentic_apply(
        workspace=tmp_path,
        target_dirs=[tmp_path],
        mapping={},
        mapped_check_ids=set(),
        policy=Policy(finding_policy={"hard_fail_on": ["CKV2_AWS_6"]}),
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
        max_total_attempts=1,
    )

    assert called["v"] is False
    assert result.agentic_ledgers[0]["rejection_stage"] == "target_resolution"
    assert "missing" in result.agentic_ledgers[0]["rejection_reason"]
