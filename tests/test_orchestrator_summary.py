from __future__ import annotations

from sanara.orchestrator.summary import SummaryView, build_summary_lines


def test_build_summary_lines_from_summary_view() -> None:
    summary = SummaryView(
        environment="dev",
        policy_overrides_loaded=True,
        final_decision="COMMENT_ONLY",
        final_reason_code="remaining_findings",
        clean=False,
        elapsed_seconds=12,
        normalized=[{"sanara_rule_id": "aws.s3.public_access_block"}],
        normalized_actionable=[{"sanara_rule_id": "aws.s3.public_access_block"}],
        normalized_suggest_only=[{"sanara_rule_id": "aws.kms.rotation_enabled"}],
        normalized_ignored=[],
        scan_excluded_mapped=[],
        uncovered_scan_excluded=[],
        baseline_checkov_failed=10,
        attempts_dict=[{"sanara_rule_id": "aws.s3.public_access_block"}],
        baseline_mapped_blocking=2,
        drc_changed_attempts=1,
        drc_no_change_attempts=0,
        drc_fixed_blocking_mapped=1,
        post_drc_mapped_nonblocking=1,
        drc_raw_checkov_delta=5,
        post_drc_remaining_total=5,
        post_drc_remaining_mapped=0,
        post_drc_remaining_uncovered=5,
        post_drc_advisory_total=1,
        post_drc_ignored_total=0,
        rescan_checkov_failed=5,
        agentic_used=True,
        llm_attempts=3,
        llm_accepted_attempts=1,
        llm_rejection_counts={"git_apply": 2, "accepted": 1},
        llm_improved_rule_ids=["CKV2_AWS_62"],
        agentic_fixed_targeted_total=4,
        agentic_fixed_targeted_mapped=0,
        agentic_fixed_targeted_uncovered=4,
        agentic_raw_checkov_delta=4,
        final_checkov_failed=1,
        final_remaining_total=1,
        final_remaining_mapped=0,
        final_remaining_uncovered=1,
        blocking_remaining_final=[{"sanara_rule_id": "checkov.unmapped.ckv_aws_144"}],
        advisory_remaining_final=[],
        ignored_remaining_final=[],
        advisor_findings=[{"id": "SANARA_ADV_1"}],
        advisor_llm_used=False,
        advisor_llm_ok=False,
    )

    lines = build_summary_lines(summary)
    text = "\n".join(lines)
    assert lines[0] == "# Sanara v0.1 Summary"
    assert "- Decision: COMMENT_ONLY (`remaining_findings`)" in text
    assert "- Policy-aware clean: False" in text
    assert "- Policy overrides loaded: Yes (env: dev)" in text
    assert "- LLM remediation fallback used: Yes (3 attempts, 1 accepted)" in text
    assert "- LLM-assisted fixes: `CKV2_AWS_62`" in text
    assert "- Deterministic attempts: 1 (1 changed, 0 no-change)" in text
    assert "- Blocking findings remaining: 1" in text
    assert "git_apply (2)" in text
    assert "LLM attempt outcomes (top)" in text
    assert "## Post-Fix Advisor" in text
    assert "- Additional critical/moderate guidance items: 1" in text
    assert "Blocking families (top)" in text
