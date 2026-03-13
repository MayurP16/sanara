from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from sanara.orchestrator import driver
from sanara.utils.command import CommandResult


def _event() -> dict:
    return {
        "pull_request": {
            "number": 7,
            "base": {"sha": "base", "ref": "main"},
            "head": {"sha": "head", "ref": "feature", "repo": {"fork": False}},
        },
        "sender": {"login": "dev"},
        "repository": {"full_name": "org/repo"},
    }


def _finding(module_dir: Path) -> dict:
    return {
        "schema_id": "sanara.finding",
        "schema_version": "0.1",
        "sanara_rule_id": "aws.ebs.encrypted",
        "source": "checkov",
        "source_rule_id": "CKV_AWS_3",
        "severity": "high",
        "target": {"module_dir": str(module_dir), "file_path": "main.tf", "line_range": "1-2"},
        "resource_type": "aws_ebs_volume",
        "resource_name": "data",
        "fingerprint": "a" * 64,
    }


def test_phase_artifact_contracts(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path
    artifacts = workspace / "artifacts"
    (workspace / "rules/mappings").mkdir(parents=True)
    (workspace / ".sanara").mkdir(parents=True)
    (workspace / "event.json").write_text(json.dumps(_event()), encoding="utf-8")
    (workspace / "rules/mappings/checkov_to_sanara.v0.1.json").write_text(
        json.dumps({"rule_pack_version": "v0.1.0", "mappings": {"CKV_AWS_3": "aws.ebs.encrypted"}}),
        encoding="utf-8",
    )
    (workspace / ".sanara/policy.yml").write_text(
        "allow_agentic: false\nplan_required: false\n", encoding="utf-8"
    )
    (workspace / ".sanara/harness.yml").write_text("version: 1\nruns: []\n", encoding="utf-8")

    monkeypatch.chdir(workspace)
    monkeypatch.setattr(driver, "discover_target_dirs", lambda *args, **kwargs: [workspace])
    monkeypatch.setattr(
        driver,
        "run_scan_only",
        lambda *args, **kwargs: {
            "checkov": {
                "targets": [str(workspace)],
                "results": [{"results": {"failed_checks": []}}],
            },
        },
    )
    monkeypatch.setattr(
        driver, "load_mapping", lambda *args, **kwargs: {"CKV_AWS_3": "aws.ebs.encrypted"}
    )
    n_calls = {"n": 0}

    def _normalize(*args, **kwargs):
        _ = args, kwargs
        n_calls["n"] += 1
        return [_finding(workspace)] if n_calls["n"] == 1 else []

    monkeypatch.setattr(driver, "normalize_all", _normalize)
    monkeypatch.setattr(
        driver,
        "apply_drc",
        lambda *args, **kwargs: [
            SimpleNamespace(
                sanara_rule_id="aws.ebs.encrypted",
                status="changed",
                code="OK",
                message="ok",
                contract=None,
            )
        ],
    )
    monkeypatch.setattr(
        driver,
        "validate_patch",
        lambda *args, **kwargs: SimpleNamespace(ok=True, code="OK", message="ok"),
    )
    monkeypatch.setattr(
        driver,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, runs=[], to_dict=lambda: {"ok": True, "runs": []}
        ),
    )
    monkeypatch.setattr(
        driver,
        "_git_diff",
        lambda *args, **kwargs: "diff --git a/main.tf b/main.tf\n+encrypted = true\n",
    )
    monkeypatch.setattr(driver, "_has_changes", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        driver,
        "run_cmd",
        lambda *args, **kwargs: CommandResult(cmd=["terraform"], code=0, stdout="", stderr=""),
    )

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0

    baseline = json.loads(
        (artifacts / "baseline/normalized_findings.json").read_text(encoding="utf-8")
    )
    assert "findings" in baseline and isinstance(baseline["findings"], list)
    drc = json.loads((artifacts / "drc/patch_contract.json").read_text(encoding="utf-8"))
    assert "attempts" in drc and isinstance(drc["attempts"], list)
    rescan = json.loads((artifacts / "rescan/targeted_results.json").read_text(encoding="utf-8"))
    assert "clean" in rescan and "remaining" in rescan and "attempted_rules" in rescan
