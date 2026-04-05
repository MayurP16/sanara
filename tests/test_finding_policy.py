from __future__ import annotations

from pathlib import Path

from sanara.orchestrator.policy import (
    PolicyValidationError,
    Policy,
    classify_checkov_finding,
    finding_family_name,
    finding_policy_decision,
    scan_policy_decision,
    load_policy,
)


def test_classify_checkov_finding_heuristics() -> None:
    out = classify_checkov_finding("CKV_AWS_70", "aws_s3_bucket_policy")
    assert out["category"] == "exposure"
    assert out["default_mode"] == "auto_fix_safe"

    out = classify_checkov_finding("CKV_AWS_144", "aws_s3_bucket")
    assert out["category"] in {"recovery_resilience", "architecture_conditional"}
    assert out["default_mode"] == "suggest_only"


def test_finding_policy_decision_global_lists() -> None:
    policy = Policy(
        finding_policy={
            "ignore": ["CKV_AWS_70"],
            "suggest_only": ["CKV_AWS_145"],
            "hard_fail_on": ["CKV_AWS_145"],
        }
    )
    finding1 = {"source_rule_id": "CKV_AWS_70", "resource_type": "aws_s3_bucket_policy"}
    d1 = finding_policy_decision(policy, finding1)
    assert d1["auto_fix_mode"] == "ignore"
    assert d1["decision_mode"] == "ignore"

    finding2 = {"source_rule_id": "CKV_AWS_145", "resource_type": "aws_s3_bucket"}
    d2 = finding_policy_decision(policy, finding2)
    assert d2["auto_fix_mode"] == "suggest_only"
    assert d2["decision_mode"] == "hard_fail"


def test_scan_policy_include_skip_ids() -> None:
    finding = {
        "source_rule_id": "CKV_AWS_70",
        "sanara_rule_id": "aws.s3.policy_secure_transport",
        "resource_type": "aws_s3_bucket_policy",
    }
    assert finding_family_name(finding) == "aws.s3"

    p = Policy(scan_policy={"skip_ids": ["CKV_AWS_70"]})
    d = scan_policy_decision(p, finding)
    assert d["include"] is False
    assert d["reason"] == "skip_id"

    p = Policy(scan_policy={"include_ids": ["CKV_AWS_145"]})
    d = scan_policy_decision(p, finding)
    assert d["include"] is False
    assert d["reason"] == "not_in_include_ids"


def test_load_policy_applies_environment_overrides(tmp_path: Path, monkeypatch) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        """
rule_pack_version: v0.1.0-alpha.1
allow_agentic: false
agentic_max_attempts: 12
advisor:
  enabled: true
  use_llm: false
  max_findings: 5
  min_severity: moderate
scan_policy:
  skip_ids: [CKV_AWS_144]
finding_policy:
  suggest_only: [CKV_AWS_18]
environments:
  prod:
    allow_agentic: true
    agentic_max_attempts: 6
    advisor:
      use_llm: true
      max_findings: 3
    scan_policy:
      include_ids: [CKV_AWS_70]
    finding_policy:
      hard_fail_on: [CKV_AWS_70]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SANARA_ENVIRONMENT", "prod")
    policy = load_policy(tmp_path)
    assert policy.environment == "prod"
    assert policy.allow_agentic is True
    assert policy.agentic_max_attempts == 6
    assert policy.scan_policy["skip_ids"] == ["CKV_AWS_144"]
    assert policy.scan_policy["include_ids"] == ["CKV_AWS_70"]
    assert policy.finding_policy["suggest_only"] == ["CKV_AWS_18"]
    assert policy.finding_policy["hard_fail_on"] == ["CKV_AWS_70"]
    assert policy.advisor_enabled is True
    assert policy.advisor_use_llm is True
    assert policy.advisor_max_findings == 3


def test_load_policy_fails_fast_on_unknown_top_level_key(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "allow_agentic: false\nallow_agnetic: true\n", encoding="utf-8"
    )
    try:
        load_policy(tmp_path)
        assert False, "expected PolicyValidationError"
    except PolicyValidationError as exc:
        assert "unknown keys in policy root" in str(exc)
        assert "allow_agnetic" in str(exc)


def test_load_policy_fails_fast_on_unknown_scan_policy_key(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "scan_policy:\n  skp_ids: [CKV_AWS_70]\n", encoding="utf-8"
    )
    try:
        load_policy(tmp_path)
        assert False, "expected PolicyValidationError"
    except PolicyValidationError as exc:
        assert "unknown keys in scan_policy" in str(exc)
        assert "skp_ids" in str(exc)


def test_load_policy_fails_fast_on_invalid_type(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text("allow_agentic: maybe\n", encoding="utf-8")
    try:
        load_policy(tmp_path)
        assert False, "expected PolicyValidationError"
    except PolicyValidationError as exc:
        assert "schema validation failed" in str(exc)


def test_load_policy_fails_fast_on_advanced_finding_policy_key(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "finding_policy:\n  by_check_id:\n    CKV_AWS_145:\n      auto_fix_mode: suggest_only\n",
        encoding="utf-8",
    )
    try:
        load_policy(tmp_path)
        assert False, "expected PolicyValidationError"
    except PolicyValidationError as exc:
        assert "unknown keys in finding_policy" in str(exc)
        assert "by_check_id" in str(exc)


def test_finding_policy_by_path_marks_examples_advisory() -> None:
    policy = Policy(
        finding_policy={
            "by_path": [
                {
                    "path": "examples/**",
                    "auto_fix_mode": "suggest_only",
                    "category": "module_examples",
                }
            ]
        }
    )
    finding = {
        "source_rule_id": "CKV_AWS_18",
        "resource_type": "aws_s3_bucket",
        "resource_name": "data",
        "file_path": "examples/complete/main.tf",
        "sanara_rule_id": "aws.s3.access_logging_enabled",
    }
    decision = finding_policy_decision(policy, finding)
    assert decision["auto_fix_mode"] == "suggest_only"
    assert decision["decision_mode"] == "soft_fail"


def test_finding_policy_by_path_overrides_auto_fix_allow() -> None:
    policy = Policy(
        finding_policy={
            "auto_fix_allow": ["CKV_AWS_18"],
            "by_path": [
                {
                    "path": "examples/**",
                    "auto_fix_mode": "suggest_only",
                    "category": "module_examples",
                }
            ],
        }
    )
    finding = {
        "source_rule_id": "CKV_AWS_18",
        "resource_type": "aws_s3_bucket",
        "resource_name": "data",
        "file_path": "examples/complete/main.tf",
        "sanara_rule_id": "aws.s3.access_logging_enabled",
    }
    decision = finding_policy_decision(policy, finding)
    assert decision["auto_fix_mode"] == "suggest_only"
    assert decision["decision_mode"] == "soft_fail"
    assert decision["matched_policy_source"] == "by_path[0]"


def test_finding_policy_by_path_uses_normalized_target_file_path() -> None:
    policy = Policy(
        finding_policy={
            "auto_fix_allow": ["CKV_AWS_18"],
            "by_path": [
                {
                    "path": "examples/**",
                    "auto_fix_mode": "suggest_only",
                    "category": "module_examples",
                }
            ],
        }
    )
    finding = {
        "source_rule_id": "CKV_AWS_18",
        "resource_type": "aws_s3_bucket",
        "resource_name": "data",
        "target": {
            "module_dir": "/github/workspace/examples/complete",
            "file_path": "examples/complete/main.tf",
            "line_range": "1-2",
        },
        "sanara_rule_id": "aws.s3.access_logging_enabled",
    }
    decision = finding_policy_decision(policy, finding)
    assert decision["auto_fix_mode"] == "suggest_only"
    assert decision["decision_mode"] == "soft_fail"
    assert decision["matched_policy_source"] == "by_path[0]"


def test_finding_policy_by_path_resolves_module_dir_relative_file() -> None:
    policy = Policy(
        finding_policy={
            "auto_fix_allow": ["CKV_AWS_18"],
            "by_path": [
                {
                    "path": "examples/**",
                    "auto_fix_mode": "suggest_only",
                    "category": "module_examples",
                }
            ],
        }
    )
    finding = {
        "source_rule_id": "CKV_AWS_18",
        "resource_type": "aws_s3_bucket",
        "resource_name": "data",
        "target": {
            "module_dir": "/github/workspace/examples/complete",
            "file_path": "/main.tf",
            "line_range": "1-2",
        },
        "sanara_rule_id": "aws.s3.access_logging_enabled",
    }
    decision = finding_policy_decision(policy, finding)
    assert decision["auto_fix_mode"] == "suggest_only"
    assert decision["decision_mode"] == "soft_fail"
    assert decision["matched_policy_source"] == "by_path[0]"


def test_load_policy_module_repo_defaults_applies_examples_by_path(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "module_repo_defaults: true\nfinding_policy:\n  by_path:\n    - path: modules/**\n      auto_fix_mode: auto_fix_safe\n",
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy.module_repo_defaults is True
    by_path = policy.finding_policy["by_path"]
    assert by_path[0]["path"] == "examples/**"
    assert by_path[0]["auto_fix_mode"] == "suggest_only"
    assert by_path[1]["path"] == "modules/**"
