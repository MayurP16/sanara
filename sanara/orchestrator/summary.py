from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sanara.policy import counts_by_family


@dataclass
class SummaryView:
    environment: str
    policy_overrides_loaded: bool
    final_decision: str | None
    final_reason_code: str | None
    clean: bool
    elapsed_seconds: int
    normalized: list[dict[str, Any]]
    normalized_actionable: list[dict[str, Any]]
    normalized_suggest_only: list[dict[str, Any]]
    normalized_ignored: list[dict[str, Any]]
    scan_excluded_mapped: list[dict[str, Any]]
    uncovered_scan_excluded: list[dict[str, Any]]
    baseline_checkov_failed: int
    attempts_dict: list[dict[str, Any]]
    baseline_mapped_blocking: int
    drc_changed_attempts: int
    drc_no_change_attempts: int
    drc_fixed_blocking_mapped: int
    post_drc_mapped_nonblocking: int
    drc_raw_checkov_delta: int
    post_drc_remaining_total: int
    post_drc_remaining_mapped: int
    post_drc_remaining_uncovered: int
    post_drc_advisory_total: int
    post_drc_ignored_total: int
    rescan_checkov_failed: int
    agentic_used: bool
    llm_attempts: int
    llm_accepted_attempts: int
    llm_rejection_counts: dict[str, int]
    llm_improved_rule_ids: list[str]
    agentic_fixed_targeted_total: int
    agentic_fixed_targeted_mapped: int
    agentic_fixed_targeted_uncovered: int
    agentic_raw_checkov_delta: int
    final_checkov_failed: int
    final_remaining_total: int
    final_remaining_mapped: int
    final_remaining_uncovered: int
    blocking_remaining_final: list[dict[str, Any]]
    advisory_remaining_final: list[dict[str, Any]]
    ignored_remaining_final: list[dict[str, Any]]
    advisor_findings: list[dict[str, Any]]
    advisor_llm_used: bool
    advisor_llm_ok: bool


def _family_counts_json(findings: list[dict[str, Any]]) -> str:
    return json.dumps(counts_by_family(findings), sort_keys=True)


def _family_counts_inline(findings: list[dict[str, Any]], top_n: int = 5) -> str:
    counts = counts_by_family(findings)
    if not counts:
        return "none"
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]
    return ", ".join(f"{k} ({v})" for k, v in items)


def _next_action(summary: SummaryView) -> str | None:
    reason = (summary.final_reason_code or "").strip()
    if reason == "missing_github_token":
        return "Add `GITHUB_TOKEN` to allow Sanara to publish a fix PR."
    if reason == "remaining_findings":
        return "Review `rescan/targeted_results_final.json` and adjust policy or add deterministic coverage for remaining blocking findings."
    if reason == "tf_checks_failed":
        return "Review `terraform/*.log` artifacts and fix Terraform validation/plan issues before rerunning."
    if reason in {"NOT_ALLOWLISTED", "BLOCKED_BY_RAIL"}:
        return "Review rails/policy constraints and the generated patch diff to understand why the patch was blocked."
    if reason == "no_changes":
        return "No publishable changes were produced. Review policy settings and baseline findings to confirm expected behavior."
    return None


def _llm_rejection_summary(summary: SummaryView) -> str:
    if not summary.llm_rejection_counts:
        return "none"
    items = sorted(summary.llm_rejection_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"{stage} ({count})" for stage, count in items[:3])


def build_summary_lines(summary: SummaryView) -> list[str]:
    lines = [
        "# Sanara v0.1 Summary",
        "",
        "## Outcome",
        f"- Decision: {summary.final_decision} (`{summary.final_reason_code}`)",
        f"- Policy-aware clean: {summary.clean}",
        f"- Elapsed: {summary.elapsed_seconds}s",
        f"- Policy overrides loaded: {'Yes' if summary.policy_overrides_loaded else 'No'} (env: {summary.environment})",
        "",
        "## What Happened",
        f"- Deterministic attempts: {len(summary.attempts_dict)} ({summary.drc_changed_attempts} changed, {summary.drc_no_change_attempts} no-change)",
        (
            f"- LLM remediation fallback used: Yes ({summary.llm_attempts} attempts, "
            f"{summary.llm_accepted_attempts} accepted)"
            if summary.agentic_used
            else "- LLM remediation fallback used: No"
        ),
        (
            f"- LLM attempt outcomes (top): {_llm_rejection_summary(summary)}"
            if summary.agentic_used and summary.llm_rejection_counts
            else None
        ),
        (
            "- LLM-assisted fixes: "
            + ", ".join(f"`{rid}`" for rid in summary.llm_improved_rule_ids)
            if summary.agentic_used and summary.llm_improved_rule_ids
            else None
        ),
        f"- Raw Checkov failures (baseline -> final): {summary.baseline_checkov_failed} -> {summary.final_checkov_failed}",
        "",
        "## Final Findings (Policy-Aware)",
        f"- Blocking findings remaining: {summary.final_remaining_total}",
        f"- Advisory findings remaining: {len(summary.advisory_remaining_final)}",
        f"- Ignored findings remaining: {len(summary.ignored_remaining_final)}",
        f"- Blocking families (top): {_family_counts_inline(summary.blocking_remaining_final)}",
        f"- Advisory families (top): {_family_counts_inline(summary.advisory_remaining_final)}",
        "",
        "## Post-Fix Advisor",
        f"- Additional critical/moderate guidance items: {len(summary.advisor_findings)}",
        f"- LLM advisor used: {'Yes' if summary.advisor_llm_used else 'No'} (ok: {summary.advisor_llm_ok})",
        "- See `advisor/findings.json` for structured guidance beyond scanner detections.",
    ]
    lines = [line for line in lines if line is not None]
    action = _next_action(summary)
    if action:
        lines.extend(["", "## Next Action", f"- {action}"])
    lines.extend(
        [
            "",
            "## Notes",
            "- `final_targeted_clean` is policy-aware (no blocking findings remain). Raw scanner findings may still exist as advisory/ignored.",
            "- See `summary_detailed.md` and `policy/evaluation.json` for detailed stage-by-stage evidence.",
        ]
    )
    return lines


def build_summary_detailed_lines(summary: SummaryView) -> list[str]:
    lines = [
        "# Sanara v0.1 Run Summary (Detailed)",
        f"- decision: {summary.final_decision}",
        f"- reason_code: {summary.final_reason_code}",
        f"- final_targeted_clean: {summary.clean}",
        f"- elapsed_seconds: {summary.elapsed_seconds}",
        f"- environment: {summary.environment}",
        f"- policy_overrides_loaded: {summary.policy_overrides_loaded}",
        "",
        "## Baseline",
        f"- mapped_findings_baseline: {len(summary.normalized)}",
        f"- mapped_auto_fix_eligible_baseline: {len(summary.normalized_actionable)}",
        f"- mapped_suggest_only_baseline: {len(summary.normalized_suggest_only)}",
        f"- mapped_ignored_baseline: {len(summary.normalized_ignored)}",
        f"- scan_excluded_mapped_baseline: {len(summary.scan_excluded_mapped)}",
        f"- scan_excluded_uncovered_baseline: {len(summary.uncovered_scan_excluded)}",
        f"- suggest_only_by_policy_family_baseline: {_family_counts_json(summary.normalized_suggest_only)}",
        f"- ignored_by_policy_family_baseline: {_family_counts_json(summary.normalized_ignored)}",
        f"- raw_checkov_failed_baseline: {summary.baseline_checkov_failed}",
        "",
        "## Deterministic (DRC)",
        f"- drc_attempts: {len(summary.attempts_dict)}",
        f"- baseline_mapped_blocking_findings: {summary.baseline_mapped_blocking}",
        f"- drc_changed_attempts: {summary.drc_changed_attempts}",
        f"- drc_no_change_attempts: {summary.drc_no_change_attempts}",
        f"- drc_fixed_blocking_mapped_findings: {summary.drc_fixed_blocking_mapped}",
        f"- mapped_nonblocking_after_drc: {summary.post_drc_mapped_nonblocking}",
        f"- drc_raw_checkov_delta: {summary.drc_raw_checkov_delta}",
        f"- remaining_after_drc_total: {summary.post_drc_remaining_total}",
        f"- remaining_after_drc_mapped: {summary.post_drc_remaining_mapped}",
        f"- remaining_after_drc_uncovered: {summary.post_drc_remaining_uncovered}",
        f"- advisory_after_drc_total: {summary.post_drc_advisory_total}",
        f"- ignored_after_drc_total: {summary.post_drc_ignored_total}",
        f"- raw_checkov_failed_post_drc: {summary.rescan_checkov_failed}",
        "",
        "## Agentic Fallback",
        f"- agentic_enabled: {summary.agentic_used}",
        f"- llm_attempts: {summary.llm_attempts}",
        f"- llm_accepted_attempts: {summary.llm_accepted_attempts}",
        f"- llm_attempt_outcomes: {_llm_rejection_summary(summary)}",
        f"- llm_improved_rule_ids: {json.dumps(summary.llm_improved_rule_ids)}",
        f"- agentic_executed: {summary.agentic_used and summary.llm_attempts > 0}",
        "",
        "## Final-stage Cleanup",
        "- note: final-stage deltas reflect the final pass after post_drc (agentic if enabled, plus deterministic cleanup if needed).",
        f"- final_stage_fixed_targeted_total: {summary.agentic_fixed_targeted_total}",
        f"- final_stage_fixed_targeted_mapped: {summary.agentic_fixed_targeted_mapped}",
        f"- final_stage_fixed_targeted_uncovered: {summary.agentic_fixed_targeted_uncovered}",
        f"- final_stage_raw_checkov_delta: {summary.agentic_raw_checkov_delta}",
        f"- raw_checkov_failed_final: {summary.final_checkov_failed}",
        "",
        "## Final",
        f"- remaining_final_total: {summary.final_remaining_total}",
        f"- remaining_final_mapped: {summary.final_remaining_mapped}",
        f"- remaining_final_uncovered: {summary.final_remaining_uncovered}",
        f"- remaining_by_family_final: {_family_counts_json(summary.blocking_remaining_final)}",
        f"- advisory_final_total: {len(summary.advisory_remaining_final)}",
        f"- advisory_by_policy_family_final: {_family_counts_json(summary.advisory_remaining_final)}",
        f"- ignored_final_total: {len(summary.ignored_remaining_final)}",
        f"- ignored_by_policy_family_final: {_family_counts_json(summary.ignored_remaining_final)}",
        "",
        "## Post-Fix Advisor",
        f"- advisor_findings_total: {len(summary.advisor_findings)}",
        f"- advisor_llm_used: {summary.advisor_llm_used}",
        f"- advisor_llm_ok: {summary.advisor_llm_ok}",
        "- artifacts: advisor/findings.json, advisor/raw_response.txt (when available)",
        "- artifacts: rescan/checkov_post_drc.json, rescan/checkov_final.json, rescan/targeted_results_post_drc.json, rescan/targeted_results_final.json",
    ]
    return lines


def build_artifact_index_lines(summary: SummaryView) -> list[str]:
    return [
        "# Sanara Artifact Index",
        "",
        "## Start Here",
        "- `summary.md` - compact human-readable outcome and next action",
        "- `summary_detailed.md` - detailed stage-by-stage counters and policy-aware totals",
        "- `run_summary.json` - machine-readable run outcome and deterministic attempts",
        "",
        "## Outcome",
        f"- Decision: `{summary.final_decision}` (`{summary.final_reason_code}`)",
        f"- Policy-aware clean: `{summary.clean}`",
        "",
        "## Policy",
        "- `policy/effective_config.json` - resolved environment + effective policy counts/precedence",
        "- `policy/evaluation.json` - canonical per-stage policy evaluation snapshots",
        "- `baseline/policy_review.json` - mapped findings with policy decisions at baseline",
        "- `baseline/scan_policy_review.json` - scan scope inclusion/exclusion at baseline",
        "- `rescan/policy_review_post_drc.json` - policy decisions after deterministic remediation",
        "- `rescan/targeted_results_post_drc.json` - blocking/advisory/ignored partitions after DRC",
        "- `rescan/targeted_results_final.json` - final-stage partitions (agentic and/or cleanup)",
        "",
        "## Scanner Outputs",
        "- `baseline/checkov.json` - raw baseline scanner output",
        "- `rescan/checkov_post_drc.json` - raw rescan after DRC",
        "- `rescan/checkov_final.json` - raw final-stage rescan",
        "",
        "## Remediation",
        "- `drc/patch.diff` - deterministic remediation patch",
        "- `drc/patch_contract.json` - patch contracts and invariants",
        "- `agentic/summary.json` - accepted/rejected LLM attempt counts and rejection reasons",
        "- `agentic/llm_ledger.json` - agentic attempts/outcomes (if agentic was enabled)",
        "- `agentic/patch.diff` - final LLM patch candidate (if agentic was enabled)",
        "- `advisor/findings.json` - post-fix advisory guidance (critical/moderate, non-blocking)",
        "- `advisor/raw_response.txt` - raw LLM advisor response when available",
        "",
        "## Terraform Gates / Runtime",
        "- `terraform/*.log` - fmt/init/validate/plan logs",
        "- `runlog.jsonl` - phase transitions and durations",
        "- `meta.json` - toolchain versions and scanner filters",
    ]
