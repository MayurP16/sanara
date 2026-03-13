from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from sanara.drc.registry import REGISTRY
from sanara.github.client import GitHubClient
from sanara.utils.hashing import sha256_text

# Maps a source_rule_id to the sanara_rule_id that supersedes it.
# If the superseding rule was applied in this run, the source rule cannot be
# meaningfully auto-fixed and should not be suggested in auto_fix_allow.
_SUPERSEDED_BY: dict[str, str] = {
    "CKV_AWS_20": "aws.s3.acl_disabled",  # acl=private is invalid when BucketOwnerEnforced is set
}


def build_dedup_payload(
    client: GitHubClient,
    base_sha: str,
    attempted_rules: set[str],
    target_dirs: list[Path],
    patch_diff: str,
) -> dict[str, Any]:
    patch_hash = sha256_text(patch_diff)
    target_dir_strings = [str(x) for x in target_dirs]
    attempted_rule_list = sorted(attempted_rules)
    return {
        "base_sha": base_sha,
        "attempted_rule_ids": attempted_rule_list,
        "target_dirs": sorted(target_dir_strings),
        "patch_hash": patch_hash,
        "dedup_key": client.dedup_key(
            base_sha, attempted_rule_list, target_dir_strings, patch_hash
        ),
    }


def has_dedup_match(client: GitHubClient, dedup_payload: dict[str, Any]) -> bool:
    existing = client.list_open_prs()
    return any(client.parse_dedup_marker(pr.get("body", "")) == dedup_payload for pr in existing)


def build_fix_branch_name() -> str:
    return f"sanara/fix-{os.environ.get('GITHUB_RUN_ID', 'local')}-{int(time.time())}"


def build_fix_pr_title(changed_attempts: int, clean: bool, llm_reduced_count: int = 0) -> str:
    total_fixes = changed_attempts + llm_reduced_count
    noun = "fix" if total_fixes == 1 else "fixes"
    if clean:
        return f"Sanara: {total_fixes} Terraform {noun}"
    return f"Sanara: {total_fixes} Terraform {noun} for review"


def build_fix_pr_body(
    client: GitHubClient,
    dedup_payload: dict[str, Any],
    attempted_rules: set[str],
    *,
    agentic_enabled: bool,
    llm_attempts: int,
    llm_accepted_attempts: int = 0,
    llm_rejection_counts: dict[str, int] | None = None,
    llm_improved_findings: list[dict[str, str]] | None = None,
    findings_count: int,
    attempts_count: int,
    changed_attempts: int,
    no_change_attempts: int,
    clean: bool,
    blocking_remaining: int,
    advisory_remaining: int,
    ignored_remaining: int,
    baseline_checkov_failed: int | None = None,
    final_checkov_failed: int | None = None,
    plan_required: bool = True,
    environment: str | None = None,
    policy_overrides_loaded: bool | None = None,
    advisory_remaining_findings: list[dict[str, Any]] | None = None,
    advisor_findings: list[dict[str, Any]] | None = None,
    checkov_to_sanara: dict[str, str] | None = None,
    terraform_init_ok: bool | None = None,
    terraform_validate_ok: bool | None = None,
    terraform_plan_ok: bool | None = None,
) -> str:
    def _pretty_rule_label(rule: str) -> str:
        custom_labels = {
            "aws.kms.policy_present": "KMS Key Policy Present",
        }
        if rule in custom_labels:
            return custom_labels[rule]
        parts = rule.split(".")
        name = parts[-1] if parts else rule
        words = name.replace("-", " ").replace("_", " ").split()
        acronyms = {"acl", "cmk", "ebs", "kms", "pitr", "rds", "s3", "sns", "sqs", "sse"}
        out: list[str] = []
        for word in words:
            if word.lower() in acronyms:
                out.append(word.upper())
            else:
                out.append(word.capitalize())
        return " ".join(out)

    def _group_rules(rules: set[str]) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for rule in sorted(rules):
            parts = rule.split(".")
            if len(parts) >= 2:
                key = f"{parts[0].upper()} / {parts[1].upper()}"
            else:
                key = "OTHER"
            groups.setdefault(key, []).append(rule)
        return groups

    def _source_rule_label(source_rule_id: str, sanara_rule_id: str | None = None) -> str:
        if sanara_rule_id and not sanara_rule_id.startswith("checkov.unmapped."):
            return _pretty_rule_label(sanara_rule_id)
        return str(source_rule_id).strip().upper()

    def _format_source_rule(source_rule_id: str, sanara_rule_id: str | None = None) -> str:
        label = _source_rule_label(source_rule_id, sanara_rule_id)
        if label == str(source_rule_id).strip().upper():
            return f"`{source_rule_id}`"
        return f"{label} (`{source_rule_id}`)"

    def _llm_outcome_label(stage: str) -> str:
        labels = {
            "accepted": "accepted",
            "git_apply": "git apply mismatch",
            "no_progress": "no progress after validation",
            "quality_gate": "quality gate failed",
            "rails": "rails check failed",
            "terraform_checks": "terraform validation failed",
            "provider_call": "provider call failed",
        }
        return labels.get(stage, stage.replace("_", " "))

    # Build reverse map: sanara_rule_id -> sorted list of Checkov IDs
    sanara_to_checkov: dict[str, list[str]] = {}
    for ckv_id, sid in (checkov_to_sanara or {}).items():
        sanara_to_checkov.setdefault(sid, []).append(ckv_id)

    marker = client.dedup_marker(dedup_payload)
    llm_reduced_count = len(llm_improved_findings or [])
    fix_noun = "fix" if changed_attempts == 1 else "fixes"
    status_line = (
        f"Sanara applied {changed_attempts} Deterministic Remediation Compiler (DRC) {fix_noun}."
    )
    if agentic_enabled and llm_reduced_count:
        llm_noun = "finding" if llm_reduced_count == 1 else "findings"
        status_line += f" LLM reduced {llm_reduced_count} additional {llm_noun}."
    if clean:
        status_line += " No blocking findings remain under current policy."
    else:
        status_line += " Review is still required before this can be considered clean."

    advisory_rule_counts: dict[str, int] = {}
    advisory_rule_transform_available: dict[str, bool] = {}
    advisory_rule_sanara_ids: dict[str, str] = {}
    for finding in advisory_remaining_findings or []:
        rid = str(finding.get("source_rule_id", "")).strip().upper()
        if not rid:
            continue
        advisory_rule_counts[rid] = advisory_rule_counts.get(rid, 0) + 1
        sanara_rule_id = str(finding.get("sanara_rule_id", "")).strip()
        if sanara_rule_id and rid not in advisory_rule_sanara_ids:
            advisory_rule_sanara_ids[rid] = sanara_rule_id
        has_transform = bool(sanara_rule_id and sanara_rule_id in REGISTRY)
        advisory_rule_transform_available[rid] = (
            advisory_rule_transform_available.get(rid, False) or has_transform
        )

    def _check(ok: bool | None) -> str:
        return "[x]" if ok else "[ ]"

    lines: list[str] = [
        marker,
        "",
        status_line,
        "",
        "## Summary",
        f"- DRC fixes applied: {changed_attempts}",
    ]
    if agentic_enabled:
        lines.append(f"- LLM-assisted finding reductions: {llm_reduced_count}")
    lines.extend(
        [
            f"- Blocking findings remaining: {blocking_remaining}",
            (
                f"- Advisory findings remaining: {advisory_remaining} across "
                f"{len(advisory_rule_counts)} rule IDs"
                if advisory_rule_counts
                else f"- Advisory findings remaining: {advisory_remaining}"
            ),
        ]
    )
    lines.extend(
        [
            "",
            "## Fixed in This PR by Sanara DRC",
        ]
    )

    grouped_rules = _group_rules(attempted_rules)

    if not grouped_rules:
        lines.append("- none")
    else:
        for family, rules in grouped_rules.items():
            lines.append(f"- {family} ({len(rules)})")
            for rule in rules:
                ckv_ids = sorted(sanara_to_checkov.get(rule, []))
                if ckv_ids:
                    lines.append(
                        f"  - {_pretty_rule_label(rule)} ({', '.join(f'`{ckv}`' for ckv in ckv_ids)})"
                    )
                else:
                    lines.append(f"  - {_pretty_rule_label(rule)} (`{rule}`)")
    if advisory_rule_counts:
        eligible_rule_ids = [
            rid
            for rid in sorted(advisory_rule_counts)
            if advisory_rule_transform_available.get(rid, False)
            and _SUPERSEDED_BY.get(rid) not in attempted_rules
        ]
    advisor = list(advisor_findings or [])
    if agentic_enabled and llm_improved_findings:
        lines.extend(
            [
                "",
                "## Fixed in This PR by LLM",
                "- These findings were reduced by accepted LLM-assisted remediation attempts:",
            ]
        )
        for item in llm_improved_findings:
            lines.append(
                "  - "
                + _format_source_rule(
                    str(item.get("source_rule_id", "")),
                    str(item.get("sanara_rule_id", "")).strip() or None,
                )
            )

    if advisory_rule_counts:
        lines.extend(
            [
                "",
                "## What Still Needs Attention",
            ]
        )
        for rid in sorted(advisory_rule_counts):
            count = advisory_rule_counts[rid]
            sanara_id = advisory_rule_sanara_ids.get(rid)
            label = _format_source_rule(rid, sanara_id)
            instance_word = "instance" if count == 1 else "instances"
            if _SUPERSEDED_BY.get(rid) in attempted_rules:
                lines.append(
                    f"- {label}: {count} {instance_word}"
                    " — Not eligible for auto-fix (a conflicting fix was already applied in this PR)"
                )
            elif not advisory_rule_transform_available.get(rid, False):
                no_label_suffix = (
                    " (no friendly labels yet)"
                    if not sanara_id or sanara_id.startswith("checkov.unmapped.")
                    else ""
                )
                lines.append(
                    f"- {label}{no_label_suffix}: {count} {instance_word}"
                    " — no transform available, manual fix required"
                )
            else:
                lines.append(f"- {label}: {count} {instance_word}")
        if eligible_rule_ids:
            lines.extend(
                [
                    "",
                    "To enable auto-fix for the eligible findings next run, add to your config:",
                    "```yaml",
                    "finding_policy:",
                    "  auto_fix_allow:",
                ]
            )
            for rid in eligible_rule_ids:
                lines.append(f"    - {rid}")
            lines.append("```")

    lines.extend(
        [
            "",
            "## Additional Hardening Suggestions",
        ]
    )
    if advisor:
        lines.append(
            "- These LLM-inferred suggestions are additional hardening ideas not already surfaced by scanner findings."
        )
        for item in advisor[:3]:
            location = ""
            file_path = str(item.get("file_path", "")).strip()
            resource_type = str(item.get("resource_type", "")).strip()
            resource_name = str(item.get("resource_name", "")).strip()
            if file_path:
                location = file_path
            if resource_type or resource_name:
                resource = f"{resource_type}.{resource_name}".strip(".")
                location = f"{location} ({resource})".strip()
            source = str(item.get("source", "")).strip().upper() or "ADVISOR"
            lines.append(
                f"- [{str(item.get('severity', '')).upper()}][{source}] {str(item.get('title', '')).strip() or 'Additional security guidance'}"
                + (f" - `{location}`" if location else "")
            )
            recommendation = str(item.get("recommendation", "")).strip()
            if recommendation:
                lines.append(f"  - Recommendation: {recommendation}")
    else:
        lines.append("- None returned for this run.")

    lines.extend(
        [
            "",
            "## Validation",
            "- [x] Terraform fmt",
        ]
    )
    if terraform_init_ok is not None:
        lines.extend(
            [
                f"- {_check(terraform_init_ok)} Terraform init",
                f"- {_check(terraform_validate_ok)} Terraform validate",
                f"- {_check(terraform_plan_ok)} Terraform plan",
            ]
        )
    elif not plan_required:
        lines.extend(
            [
                "- [ ] Terraform init / validate / plan skipped",
                "  - Terraform plan gate was intentionally skipped because no runnable harness was configured.",
            ]
        )
    else:
        lines.append("- [ ] Terraform init / validate / plan not run")

    lines.extend(
        [
            "",
            "<details>",
            "<summary>Run details and evidence</summary>",
            "",
            "### Run Details",
            f"- Ignored findings remaining: {ignored_remaining}",
            f"- Deterministic attempts: {attempts_count} ({changed_attempts} changed, {no_change_attempts} no-change)",
            f"- Mapped findings seen at baseline: {findings_count}",
        ]
    )
    if agentic_enabled:
        lines.append(
            f"- LLM remediation fallback: {llm_attempts} attempts, {llm_accepted_attempts} accepted"
        )
    if agentic_enabled and llm_rejection_counts:
        accepted_count = llm_rejection_counts.get("accepted", 0)
        nonaccepted_items = [
            (stage, count)
            for stage, count in sorted(llm_rejection_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            if stage != "accepted"
        ]
        if nonaccepted_items:
            lines.append(
                "- Non-accepted LLM attempt outcomes: "
                + ", ".join(
                    f"{_llm_outcome_label(stage)} ({count})"
                    for stage, count in nonaccepted_items[:3]
                )
            )
        elif accepted_count:
            lines.append("- Non-accepted LLM attempt outcomes: none")
    if baseline_checkov_failed is not None and final_checkov_failed is not None:
        lines.extend(
            [
                f"- Raw Checkov failures: {baseline_checkov_failed} at baseline, {final_checkov_failed} after remediation",
                "",
            ]
        )
    else:
        lines.append("")
    lines.extend(
        [
            "### Toolchain",
            "- terraform: 1.9.8",
            "- checkov: 3.2.504",
        ]
    )
    lines.extend(
        [
            "",
            "### Evidence",
            "- Full evidence bundle is uploaded as the workflow artifact: `sanara-artifacts`",
            "- Key files in bundle:",
            "  - `artifacts/summary.md`",
            "  - `artifacts/summary_detailed.md`",
            "  - `artifacts/run_summary.json`",
            "  - `artifacts/drc/patch_contract.json`",
            "  - `artifacts/rescan/targeted_results_final.json`",
            "",
            "</details>",
        ]
    )
    return "\n".join(lines)
