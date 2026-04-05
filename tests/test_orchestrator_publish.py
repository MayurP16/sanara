from __future__ import annotations

import json
from pathlib import Path

from sanara.orchestrator.publish import (
    build_dedup_payload,
    build_fix_branch_name,
    build_fix_pr_body,
    build_fix_pr_title,
    has_dedup_match,
)
from sanara.utils.hashing import sha256_text


class _FakeClient:
    def __init__(self, prs: list[dict] | None = None):
        self._prs = prs or []

    def dedup_key(
        self, base_sha: str, attempted_rule_ids: list[str], target_dirs: list[str], patch_hash: str
    ) -> str:
        return f"{base_sha}:{','.join(sorted(attempted_rule_ids))}:{','.join(sorted(target_dirs))}:{patch_hash}"

    def list_open_prs(self) -> list[dict]:
        return self._prs

    @staticmethod
    def dedup_marker(payload: dict) -> str:
        return f"<!-- sanara-dedup:{json.dumps(payload, sort_keys=True)} -->"

    @staticmethod
    def parse_dedup_marker(body: str):
        start = body.find("<!-- sanara-dedup:")
        if start < 0:
            return None
        end = body.find("-->", start)
        if end < 0:
            return None
        return json.loads(body[start + len("<!-- sanara-dedup:") : end])


def test_build_dedup_payload_is_sorted_and_hashed() -> None:
    client = _FakeClient()
    payload = build_dedup_payload(
        client=client,
        base_sha="abc123",
        attempted_rules={"rule-b", "rule-a"},
        target_dirs=[Path("b/module"), Path("a/module")],
        patch_diff="diff --git a/main.tf b/main.tf\n+encrypted = true\n",
    )
    assert payload["base_sha"] == "abc123"
    assert payload["attempted_rule_ids"] == ["rule-a", "rule-b"]
    assert payload["target_dirs"] == ["a/module", "b/module"]
    assert payload["patch_hash"] == sha256_text(
        "diff --git a/main.tf b/main.tf\n+encrypted = true\n"
    )
    assert payload["dedup_key"].startswith("abc123:rule-a,rule-b:a/module,b/module:")


def test_has_dedup_match_detects_matching_payload() -> None:
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["rule-a"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    marker = _FakeClient.dedup_marker(payload)
    client = _FakeClient(prs=[{"body": marker}, {"body": "no marker"}])
    assert has_dedup_match(client, payload) is True
    assert has_dedup_match(_FakeClient(prs=[{"body": "no marker"}]), payload) is False


def test_build_fix_branch_name_uses_run_id(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setattr("sanara.orchestrator.publish.time.time", lambda: 1700000000)
    assert build_fix_branch_name() == "sanara/fix-42-1700000000"


def test_build_fix_pr_title_is_compact_and_readable() -> None:
    assert build_fix_pr_title(1, clean=True) == "Sanara: 1 Terraform fix"
    assert build_fix_pr_title(8, clean=True) == "Sanara: 8 Terraform fixes"
    assert build_fix_pr_title(3, clean=False) == "Sanara: 3 Terraform fixes for review"
    assert build_fix_pr_title(8, clean=True, llm_reduced_count=2) == "Sanara: 10 Terraform fixes"
    assert (
        build_fix_pr_title(3, clean=False, llm_reduced_count=1)
        == "Sanara: 4 Terraform fixes for review"
    )


def test_build_fix_pr_body_includes_marker_and_rules() -> None:
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["rule-a"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    body = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"rule-a", "rule-b"},
        agentic_enabled=True,
        llm_attempts=2,
        llm_accepted_attempts=1,
        llm_rejection_counts={"git_apply": 1, "accepted": 1},
        llm_improved_findings=[
            {
                "source_rule_id": "CKV_AWS_21",
                "sanara_rule_id": "aws.s3.versioning_enabled",
                "resource_type": "aws_s3_bucket",
                "resource_name": "data",
                "file_path": "/s3.tf",
            }
        ],
        llm_improved_count=1,
        findings_count=5,
        attempts_count=2,
        changed_attempts=2,
        no_change_attempts=0,
        clean=True,
        blocking_remaining=0,
        advisory_remaining=3,
        ignored_remaining=0,
        baseline_checkov_failed=10,
        final_checkov_failed=4,
        plan_required=True,
        environment="staging",
        terraform_init_ok=True,
        terraform_validate_ok=True,
        terraform_plan_ok=True,
        policy_overrides_loaded=True,
        changed_findings=[
            {"sanara_rule_id": "rule-a"},
            {"sanara_rule_id": "rule-b"},
        ],
        advisory_remaining_findings=[
            {"source_rule_id": "CKV_AWS_21", "sanara_rule_id": "aws.s3.versioning_enabled"},
            {"source_rule_id": "CKV_AWS_21", "sanara_rule_id": "aws.s3.versioning_enabled"},
            {"source_rule_id": "CKV_AWS_145", "sanara_rule_id": "checkov.unmapped.CKV_AWS_145"},
        ],
        advisor_findings=[
            {
                "id": "SANARA_ADV_AWS_S3_ACCOUNT_PAB_DISABLED",
                "severity": "critical",
                "source": "llm",
                "title": "Account-level S3 public access block is not fully enforced",
                "file_path": "main.tf",
                "resource_type": "aws_s3_account_public_access_block",
                "resource_name": "this",
                "recommendation": "Set all four account-level flags to true.",
            }
        ],
    )
    assert "<!-- sanara-dedup:" in body
    assert "Sanara applied 2 Deterministic Remediation Compiler (DRC) fixes." in body
    assert "LLM reduced 1 additional finding." in body
    assert "## Summary" in body
    assert "- DRC fixes applied: 2" in body
    assert "- LLM-assisted finding reductions: 1" in body
    assert body.index("## Fixed in This PR by Sanara DRC") < body.index("## Validation")
    assert body.index("## Fixed in This PR by LLM") < body.index("## What Still Needs Attention")
    assert body.index("## What Still Needs Attention") < body.index("## Validation")
    assert "## Validation" in body
    assert "- [x] Terraform init" in body
    assert "- [x] Terraform validate" in body
    assert "- [x] Terraform plan" in body
    assert "- [x] Terraform init / validate / plan" not in body
    assert "## Fixed in This PR by Sanara DRC" in body
    assert "Rule A (`rule-a`)" in body
    assert "Rule B (`rule-b`)" in body
    assert "No blocking findings remain under current policy." in body
    assert "### Run Details" in body
    assert "- Raw Checkov failures: 10 at baseline, 4 after remediation" in body
    assert "- LLM remediation fallback: 2 attempts, 1 accepted" in body
    assert "- Non-accepted LLM attempt outcomes: git apply mismatch (1)" in body
    assert "<summary>Run details and evidence</summary>" in body
    assert "### Policy Context" not in body
    assert "- Environment: staging" not in body
    assert "## Fixed in This PR by LLM" in body
    assert "- These findings were reduced by accepted LLM-assisted remediation attempts:" in body
    assert "  - Versioning Enabled (`CKV_AWS_21`) on aws_s3_bucket.data in /s3.tf" in body
    assert "## Additional Hardening Suggestions" in body
    assert body.index("## What Still Needs Attention") < body.index(
        "## Additional Hardening Suggestions"
    )
    assert body.index("## Additional Hardening Suggestions") < body.index("## Validation")
    assert "LLM-inferred suggestions are additional hardening ideas" in body
    assert "## What Still Needs Attention" in body
    assert (
        "Versioning Enabled (`CKV_AWS_21`): 2 instances — transform available, eligible for auto-fix"
        in body
    )
    assert "`CKV_AWS_145`" in body
    assert "no transform, manual fix required" in body
    assert "- Providers represented: AWS (2)." in body
    assert "## How to Auto-Fix More Next Run" not in body
    assert "To enable auto-fix for the eligible findings next run" in body
    assert "finding_policy:" in body
    assert "- CKV_AWS_21" in body
    assert "- CKV_AWS_145" not in body
    assert "[CRITICAL]" in body
    assert "[LLM]" not in body
    assert "Account-level S3 public access block is not fully enforced" in body
    assert "workflow artifact: `sanara-artifacts`" in body
    assert "Versioning Enabled (`CKV_AWS_21`)" in body


def test_build_fix_pr_body_shows_empty_hardening_section_when_no_advisor_findings() -> None:
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["rule-a"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    body = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"rule-a"},
        agentic_enabled=False,
        llm_attempts=0,
        llm_accepted_attempts=0,
        llm_rejection_counts={},
        llm_improved_findings=[],
        llm_improved_count=0,
        findings_count=1,
        attempts_count=1,
        changed_attempts=1,
        no_change_attempts=0,
        clean=True,
        blocking_remaining=0,
        advisory_remaining=0,
        ignored_remaining=0,
        baseline_checkov_failed=2,
        final_checkov_failed=1,
        plan_required=True,
        advisor_findings=[],
    )
    assert "## Additional Hardening Suggestions" in body
    assert "- None returned for this run." in body


def test_build_fix_pr_body_reflects_skipped_plan_gate() -> None:
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["rule-a"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    body = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"rule-a"},
        agentic_enabled=False,
        llm_attempts=0,
        llm_accepted_attempts=0,
        llm_rejection_counts={},
        llm_improved_findings=[],
        llm_improved_count=0,
        findings_count=1,
        attempts_count=1,
        changed_attempts=1,
        no_change_attempts=0,
        clean=True,
        blocking_remaining=0,
        advisory_remaining=0,
        ignored_remaining=0,
        baseline_checkov_failed=2,
        final_checkov_failed=1,
        plan_required=False,
    )
    assert "- [x] Terraform fmt" in body
    assert "- [ ] Terraform init / validate / plan skipped" in body


def test_build_fix_pr_body_pre_existing_tf_failure_note() -> None:
    # When init/validate actually ran at baseline and failed, the PR body should include the note.
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["rule-a"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    body_with_failure = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"rule-a"},
        agentic_enabled=False,
        llm_attempts=0,
        llm_accepted_attempts=0,
        llm_rejection_counts={},
        llm_improved_findings=[],
        llm_improved_count=0,
        findings_count=1,
        attempts_count=1,
        changed_attempts=1,
        no_change_attempts=0,
        clean=True,
        blocking_remaining=0,
        advisory_remaining=0,
        ignored_remaining=0,
        baseline_checkov_failed=2,
        final_checkov_failed=1,
        plan_required=True,
        pre_existing_tf_failure=True,
        terraform_init_ok=True,
        terraform_validate_ok=True,
        terraform_plan_ok=True,
    )
    assert "terraform init" in body_with_failure
    assert "already failing on the base branch" in body_with_failure

    # When the baseline run never executed terraform (e.g. working_dir_missing),
    # pre_existing_tf_failure is False and the note must NOT appear.
    body_no_failure = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"rule-a"},
        agentic_enabled=False,
        llm_attempts=0,
        llm_accepted_attempts=0,
        llm_rejection_counts={},
        llm_improved_findings=[],
        llm_improved_count=0,
        findings_count=1,
        attempts_count=1,
        changed_attempts=1,
        no_change_attempts=0,
        clean=True,
        blocking_remaining=0,
        advisory_remaining=0,
        ignored_remaining=0,
        baseline_checkov_failed=2,
        final_checkov_failed=1,
        plan_required=True,
        pre_existing_tf_failure=False,
        terraform_init_ok=True,
        terraform_validate_ok=True,
        terraform_plan_ok=True,
    )
    assert "already failing on the base branch" not in body_no_failure


def test_build_fix_pr_body_suppresses_superseded_auto_fix_suggestion() -> None:
    # CKV_AWS_20 (acl_private) is advisory, has a transform, but aws.s3.acl_disabled was
    # applied in this run. The PR body must NOT suggest adding CKV_AWS_20 to auto_fix_allow
    # because BucketOwnerEnforced (applied by acl_disabled) disables ACL support entirely,
    # making CKV_AWS_20 unresolvable and a guaranteed PR blocker if added.
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["aws.s3.acl_disabled"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    body = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"aws.s3.acl_disabled"},
        agentic_enabled=False,
        llm_attempts=0,
        llm_accepted_attempts=0,
        llm_rejection_counts={},
        llm_improved_findings=[],
        findings_count=5,
        attempts_count=1,
        changed_attempts=1,
        no_change_attempts=0,
        clean=True,
        blocking_remaining=0,
        advisory_remaining=1,
        ignored_remaining=0,
        advisory_remaining_findings=[
            {"source_rule_id": "CKV_AWS_20", "sanara_rule_id": "aws.s3.acl_private"},
        ],
    )
    # CKV_AWS_20 must NOT appear in the auto_fix_allow suggestion block
    assert "    - CKV_AWS_20" not in body
    # A conflict warning must be shown instead, inline in "What Still Needs Attention"
    assert "CKV_AWS_20" in body
    assert "not eligible" in body
    assert "conflicting fix already applied" in body


def test_build_fix_pr_body_uses_changed_rules_not_attempted_rules() -> None:
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["aws.s3.versioning_enabled", "aws.kms.rotation_enabled"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    body = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"aws.s3.versioning_enabled", "aws.kms.rotation_enabled"},
        agentic_enabled=False,
        llm_attempts=0,
        llm_accepted_attempts=0,
        llm_rejection_counts={},
        llm_improved_findings=[],
        findings_count=5,
        attempts_count=2,
        changed_attempts=1,
        no_change_attempts=1,
        clean=False,
        blocking_remaining=1,
        advisory_remaining=0,
        ignored_remaining=0,
        changed_findings=[
            {"sanara_rule_id": "aws.s3.versioning_enabled"},
        ],
    )
    assert "Versioning Enabled" in body
    assert "Rotation Enabled" not in body


def test_build_fix_pr_body_marks_by_path_advisory_findings_as_policy_excluded() -> None:
    payload = {
        "base_sha": "abc123",
        "attempted_rule_ids": ["aws.s3.versioning_enabled"],
        "target_dirs": ["module"],
        "patch_hash": "hash",
        "dedup_key": "k",
    }
    body = build_fix_pr_body(
        client=_FakeClient(),
        dedup_payload=payload,
        attempted_rules={"aws.s3.versioning_enabled"},
        agentic_enabled=False,
        llm_attempts=0,
        llm_accepted_attempts=0,
        llm_rejection_counts={},
        llm_improved_findings=[],
        findings_count=5,
        attempts_count=1,
        changed_attempts=1,
        no_change_attempts=0,
        clean=False,
        blocking_remaining=1,
        advisory_remaining=2,
        ignored_remaining=0,
        changed_findings=[
            {"sanara_rule_id": "aws.s3.versioning_enabled"},
        ],
        advisory_remaining_findings=[
            {
                "source_rule_id": "CKV_AWS_7",
                "sanara_rule_id": "aws.kms.rotation_enabled",
                "policy": {
                    "auto_fix_mode": "suggest_only",
                    "matched_policy_source": "by_path[0]",
                },
            },
            {
                "source_rule_id": "CKV2_AWS_64",
                "sanara_rule_id": "aws.kms.policy_present",
                "policy": {
                    "auto_fix_mode": "suggest_only",
                    "matched_policy_source": "by_path[0]",
                },
            },
        ],
    )
    assert "- Intentionally left advisory by policy: 2" in body
    assert "intentionally left unchanged by policy" in body
    assert "currently held back by path policy" in body
    assert "    - CKV_AWS_7" not in body
    assert "    - CKV2_AWS_64" not in body
