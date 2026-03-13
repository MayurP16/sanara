from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sanara import RULE_PACK_VERSION, __version__
from sanara.artifacts.bundle import (
    ensure_artifact_files,
    policy_hash,
    write_json_file,
    write_meta,
    write_summary,
    write_text,
)
from sanara.drc.engine import apply_drc
from sanara.github.client import GitHubClient
from sanara.normalize.mapper import load_mapping, normalize_all
from sanara.normalize.schema_validate import validate_payload
from sanara.orchestrator.agentic import run_agentic_apply
from sanara.orchestrator.advisor import run_post_fix_advisor
from sanara.orchestrator.context import detect_context, load_event
from sanara.orchestrator.discovery import discover_target_dirs
from sanara.orchestrator.models import FinalState, FindingState, RunState, ScanPayload
from sanara.orchestrator.rescan_stage import apply_rescan_stage
from sanara.policy import (
    annotate_and_filter_mapped_findings,
    apply_scan_policy_to_findings,
    effective_policy_overview,
    load_policy,
    policy_eval_snapshot,
)
from sanara.orchestrator.publish import (
    build_dedup_payload,
    build_fix_branch_name,
    build_fix_pr_body,
    build_fix_pr_title,
    has_dedup_match,
)
from sanara.orchestrator.repair import (
    _finding_key,
    _load_repair_profiles,
)
from sanara.orchestrator.summary import (
    SummaryView,
    build_artifact_index_lines,
    build_summary_detailed_lines,
    build_summary_lines,
)
from sanara.rails.validator import validate_patch
from sanara.scanners.runners import checkov_cli_filter_args, run_scan_only
from sanara.terraform.harness import run_harness_checks
from sanara.utils.command import CommandError, CommandResult, run_cmd, run_cmd_checked
from sanara.utils.logging import RunLogger

REQUIRED_ARTIFACTS = [
    "meta.json",
    "target_dirs.json",
    "baseline/checkov.json",
    "baseline/normalized_findings.json",
    "drc/patch.diff",
    "drc/patch_contract.json",
    "terraform/fmt.log",
    "terraform/init.log",
    "terraform/validate.log",
    "terraform/plan.log",
    "rescan/checkov.json",
    "rescan/targeted_results.json",
    "runlog.jsonl",
    "artifacts/index.md",
    "summary.md",
    "summary_detailed.md",
    "advisor/findings.json",
]
_DEFAULT_SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"
_IMAGE_SCHEMAS_DIR = Path("/app/schemas")
SCHEMAS_DIR = Path(os.environ.get("SANARA_SCHEMAS_DIR", _DEFAULT_SCHEMAS_DIR))
if not SCHEMAS_DIR.exists():
    SCHEMAS_DIR = _IMAGE_SCHEMAS_DIR
ALLOWED_REASON_CODES = {
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
    "unknown",
}
_LOG = logging.getLogger(__name__)


def _transition(
    logger: RunLogger, state: str, fn, phase_timings_ms: dict[str, int] | None = None
) -> Any:
    """Wrap a run phase with structured logging and duration capture."""
    start = time.time()
    logger.log(state, "start")
    _LOG.info("phase=%s status=start", state)
    try:
        result = fn()
        duration_ms = int((time.time() - start) * 1000)
        logger.log(state, "ok", {"duration_ms": duration_ms})
        _LOG.info("phase=%s status=ok duration_ms=%d", state, duration_ms)
        if phase_timings_ms is not None:
            phase_timings_ms[state] = duration_ms
        return result
    except Exception as e:  # pragma: no cover
        duration_ms = int((time.time() - start) * 1000)
        logger.log(state, "error", {"duration_ms": duration_ms, "error": str(e)})
        _LOG.exception("phase=%s status=error duration_ms=%d error=%s", state, duration_ms, e)
        raise


def _git_diff(workspace: Path) -> str:
    return run_cmd(["git", "diff"], cwd=workspace).stdout


def _first_nonempty_line(text: str) -> str:
    for line in (text or "").splitlines():
        s = line.strip()
        if s:
            return s
    return ""


def _resolve_tool_versions(workspace: Path) -> dict[str, str]:
    """Capture best-effort tool version strings for artifact metadata."""

    def _capture(cmd: list[str]) -> str:
        try:
            result = run_cmd(cmd, cwd=workspace, timeout_seconds=15)
        except Exception:
            return "unavailable"
        text = _first_nonempty_line(result.stdout) or _first_nonempty_line(result.stderr)
        if result.code != 0:
            return f"error(code={result.code}) {text}".strip()
        return text or "ok"

    checkov_bin = os.environ.get("SANARA_CHECKOV_BIN", "").strip() or "checkov"
    return {
        "terraform": _capture(["terraform", "version"]),
        "checkov": _capture([checkov_bin, "--version"]),
    }


def _write_run_summary(
    out_dir: Path,
    context,
    target_dirs: list[Path],
    normalized: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
    decision: str,
    decision_detail: dict[str, Any] | None = None,
    agentic_summary: dict[str, Any] | None = None,
    terraform_summary: dict[str, Any] | None = None,
    phase_timings_ms: dict[str, int] | None = None,
    runtime_budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist the top-level run summary and validate it against the published schema."""
    detail = decision_detail or {"reason_code": "unknown", "message": ""}
    if "reason_code" not in detail:
        detail["reason_code"] = "unknown"
    if "message" not in detail:
        detail["message"] = ""
    reason_code = str(detail.get("reason_code", "")).strip()
    if reason_code and reason_code not in ALLOWED_REASON_CODES:
        raise ValueError(f"unknown decision reason_code: {reason_code}")
    payload = {
        "schema_id": "sanara.run_summary",
        "schema_version": "0.2",
        "sanara_version": __version__,
        "rule_pack_version": RULE_PACK_VERSION,
        "run_metadata": {
            "run_id": os.environ.get("GITHUB_RUN_ID", "local-run"),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "repo": context.repo,
            "base_sha": context.base_sha,
            "head_sha": context.head_sha,
            "event_type": context.event_name,
            "actor": context.actor,
            "is_fork": context.is_fork,
        },
        "targets": [str(x) for x in target_dirs],
        "findings_count": len(normalized),
        "attempts": attempts,
        "decision": decision,
        "decision_detail": detail,
        "agentic": agentic_summary
        or {"used": False, "attempts": 0, "accepted_attempts": 0, "rejection_counts": {}},
        "terraform": terraform_summary or {"ok": False, "runs": []},
        "phase_timings_ms": phase_timings_ms or {},
        "runtime_budget": runtime_budget or {},
    }
    write_json_file(out_dir, "run_summary.json", payload)
    validate_payload(SCHEMAS_DIR / "sanara.run_summary.v0.2.json", payload)
    return payload


def _write_terraform_logs(
    artifacts_dir: Path, tf_checks: dict[str, Any], fmt_stdout: str, fmt_stderr: str
) -> None:
    """Flatten per-target Terraform logs into stable artifact files."""
    write_text(artifacts_dir, "terraform/fmt.log", fmt_stdout + "\n" + fmt_stderr)
    init_logs: list[str] = []
    validate_logs: list[str] = []
    plan_logs: list[str] = []
    for run in tf_checks.get("runs", []):
        init = run.get("init", {})
        validate = run.get("validate", {})
        plan = run.get("plan", {})
        init_logs.append(
            f"[{run.get('name')}] code={init.get('code')}\n{init.get('stdout', '')}\n{init.get('stderr', '')}"
        )
        validate_logs.append(
            f"[{run.get('name')}] code={validate.get('code')}\n{validate.get('stdout', '')}\n{validate.get('stderr', '')}"
        )
        plan_logs.append(
            f"[{run.get('name')}] code={plan.get('code')}\n{plan.get('stdout', '')}\n{plan.get('stderr', '')}"
        )
    write_text(artifacts_dir, "terraform/init.log", "\n\n".join(init_logs))
    write_text(artifacts_dir, "terraform/validate.log", "\n\n".join(validate_logs))
    write_text(artifacts_dir, "terraform/plan.log", "\n\n".join(plan_logs))


def _validate_findings_schema(normalized: list[dict[str, Any]]) -> None:
    schema = SCHEMAS_DIR / "sanara.finding.v0.1.json"
    for finding in normalized:
        validate_payload(schema, finding)


def _validate_contracts_schema(attempts: list[dict[str, Any]]) -> None:
    schema = SCHEMAS_DIR / "sanara.patch_contract.v0.1.json"
    for attempt in attempts:
        contract = attempt.get("contract")
        if contract:
            validate_payload(schema, contract)


def _validate_targeted_results_schema(payload: dict[str, Any]) -> None:
    schema = SCHEMAS_DIR / "sanara.targeted_results.v0.1.json"
    validate_payload(schema, payload)


def _validate_advisor_findings_schema(payload: dict[str, Any]) -> None:
    schema = SCHEMAS_DIR / "sanara.advisor.findings.v0.1.json"
    validate_payload(schema, payload)


def _parse_checkov_resource(resource: str) -> tuple[str, str]:
    value = (resource or "").strip()
    if not value:
        return "", ""
    if value.count(".") == 2:
        p0, p1, p2 = value.split(".")
        value = f"{p0}_{p1}.{p2}"
    match = re.match(r"^(?P<rtype>[a-zA-Z0-9_]+)\.(?P<rname>[a-zA-Z0-9_\\-]+)$", value)
    if not match:
        return "", ""
    return match.group("rtype"), match.group("rname")


def _checkov_failed_items(checkov_payload: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for report in checkov_payload.get("results", []):
        reports: list[dict[str, Any]] = []
        if isinstance(report, list):
            reports.extend(x for x in report if isinstance(x, dict))
        elif isinstance(report, dict):
            reports.append(report)
        for entry in reports:
            failed = entry.get("results", {}).get("failed_checks", [])
            for item in failed:
                if isinstance(item, dict):
                    out.append(item)
    return out


def _unmapped_checkov_findings(
    checkov_payload: dict[str, Any], mapped_check_ids: set[str], workspace: Path
) -> list[dict[str, Any]]:
    """Preserve visible scanner failures even when the rule pack has no mapping for them yet."""
    findings: list[dict[str, Any]] = []
    for item in _checkov_failed_items(checkov_payload):
        source_rule_id = str(item.get("check_id", "")).strip()
        if not source_rule_id or source_rule_id in mapped_check_ids:
            continue
        file_path = str(item.get("file_path", "")).strip() or "/unknown.tf"
        line_range = item.get("file_line_range", [0, 0])
        if not (isinstance(line_range, list) and len(line_range) >= 2):
            line_range = [0, 0]
        resource_type, resource_name = _parse_checkov_resource(str(item.get("resource", "")))
        file_abs = str(item.get("file_abs_path", "")).strip()
        module_dir = str(Path(file_abs).parent) if file_abs else str(workspace)
        findings.append(
            {
                "schema_id": "sanara.finding",
                "schema_version": "0.1",
                "sanara_rule_id": f"checkov.unmapped.{source_rule_id.lower()}",
                "source": "checkov",
                "source_rule_id": source_rule_id,
                "severity": "medium",
                "target": {
                    "module_dir": module_dir,
                    "file_path": file_path,
                    "line_range": f"{line_range[0]}-{line_range[1]}",
                },
                "resource_type": resource_type,
                "resource_name": resource_name,
            }
        )
    return sorted(findings, key=_finding_key)


def _merge_remaining_findings(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Combine mapped and unmapped findings with stable deduplication."""
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for group in groups:
        for finding in group:
            merged[_finding_key(finding)] = finding
    return [merged[k] for k in sorted(merged)]


def _partition_uncovered(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    mapped: list[dict[str, Any]] = []
    uncovered: list[dict[str, Any]] = []
    for finding in findings:
        if str(finding.get("sanara_rule_id", "")).startswith("checkov.unmapped."):
            uncovered.append(finding)
        else:
            mapped.append(finding)
    return mapped, uncovered


def _build_current_findings_state(
    scan_payload: dict[str, Any],
    mapping: dict[str, str],
    mapped_check_ids: set[str],
    workspace: Path,
) -> FindingState:
    """Reconstruct the current finding set after baseline or rescan phases."""
    normalized = normalize_all(scan_payload["checkov"], mapping)
    uncovered = _unmapped_checkov_findings(scan_payload["checkov"], mapped_check_ids, workspace)
    current = _merge_remaining_findings(normalized, uncovered)
    current_mapped, current_uncovered = _partition_uncovered(current)
    return FindingState(
        clean=len(current) == 0,
        remaining=current,
        remaining_mapped=current_mapped,
        remaining_uncovered=current_uncovered,
    )


def _write_targeted_results(
    artifacts_dir: Path,
    findings_state: FindingState,
    attempted_rules: set[str],
    rel_path: str = "rescan/targeted_results.json",
) -> None:
    payload = {
        "clean": findings_state.clean,
        "remaining": findings_state.remaining,
        "remaining_mapped": findings_state.remaining_mapped,
        "remaining_uncovered": findings_state.remaining_uncovered,
        "attempted_rules": sorted(attempted_rules),
    }
    _validate_targeted_results_schema(payload)
    write_json_file(artifacts_dir, rel_path, payload)


def _has_changes(workspace: Path) -> bool:
    result = run_cmd(["git", "status", "--porcelain"], cwd=workspace)
    return bool(result.stdout.strip())


def _ensure_branch_and_push(
    workspace: Path, branch: str, artifacts_dir: Path | None = None, retries: int = 3
) -> str:
    """Create a remediation branch, commit changes, and retry on branch-name collisions."""
    suffix = 0
    for _ in range(max(1, retries)):
        candidate = branch if suffix == 0 else f"{branch}-{suffix}"
        suffix += 1
        try:
            run_cmd_checked(["git", "checkout", "-b", candidate], cwd=workspace)
            run_cmd_checked(["git", "add", "-A"], cwd=workspace)
            if artifacts_dir is not None:
                try:
                    rel_artifacts = artifacts_dir.resolve().relative_to(workspace.resolve())
                    rel_path = str(rel_artifacts)
                    # Ensure generated artifacts are never part of remediation PR commits.
                    # Unstage only; keep files on disk so workflow artifact upload still works.
                    run_cmd(["git", "reset", "HEAD", "--", rel_path], cwd=workspace)
                except Exception:
                    # If artifacts are outside workspace (or path resolution fails), there is nothing to exclude.
                    pass
            # Unstage checkov's github_conf directory if present (created when GitHub env vars are set).
            run_cmd(["git", "reset", "HEAD", "--", "github_conf"], cwd=workspace)
            run_cmd_checked(["git", "commit", "-m", "Sanara remediation v0.1"], cwd=workspace)
            run_cmd_checked(["git", "push", "-u", "origin", candidate], cwd=workspace)
            return candidate
        except CommandError as exc:
            msg = f"{str(exc)} {exc.result.stderr}".lower()
            collision = (
                "already exists" in msg or "not unique" in msg or "already a branch named" in msg
            )
            if not collision:
                raise
    raise CommandError(
        CommandResult(
            cmd=["git", "checkout", "-b", branch], code=1, stdout="", stderr="branch collision"
        )
    )


def _post_comment_if_possible(
    client: GitHubClient | None, pr_number: int | None, body: str
) -> None:
    if client and pr_number:
        client.comment_pr(pr_number, body)


def _safe_finalize(artifacts_dir: Path, summary_lines: list[str]) -> None:
    """Write summary artifacts and verify the required bundle shape is present."""
    write_summary(artifacts_dir, summary_lines)
    ensure_artifact_files(artifacts_dir, REQUIRED_ARTIFACTS)


def _write_skip_artifacts(
    artifacts_dir: Path,
    context,
    phase_timings_ms: dict[str, int],
    policy,
) -> None:
    """Emit a minimal artifact bundle for follow-up runs that are intentionally skipped."""
    message = (
        "This is a follow-up run on a Sanara-generated fix branch. The original remediation "
        "run already produced the patch and PR body; this follow-up branch run is skipped to "
        "avoid self-triggered remediation loops."
    )
    decision_detail = {
        "reason_code": "no_changes",
        "message": message,
    }
    _write_run_summary(
        artifacts_dir,
        context,
        target_dirs=[],
        normalized=[],
        attempts=[],
        decision="SKIPPED",
        decision_detail=decision_detail,
        phase_timings_ms=phase_timings_ms,
        runtime_budget={
            "elapsed_seconds": 0,
            "remaining_seconds": policy.max_runtime_seconds,
            "max_runtime_seconds": policy.max_runtime_seconds,
        },
    )
    write_text(
        artifacts_dir,
        "summary_detailed.md",
        "\n".join(
            [
                "# Sanara v0.1 Run Summary (Detailed)",
                "- decision: SKIPPED",
                f"- reason_code: {context.skip_reason}",
                "- final_targeted_clean: false",
                "- note: this artifact bundle is from the follow-up run on a generated `sanara/fix-*` branch.",
                "- note: the original remediation run already performed remediation and created the PR body.",
                "- note: inspect the original remediation run artifacts or PR body for fix details.",
            ]
        ),
    )
    write_text(
        artifacts_dir,
        "artifacts/index.md",
        "\n".join(
            [
                "# Sanara Artifact Index",
                "",
                "## Skipped Follow-up Run",
                "- This artifact bundle is from a follow-up run on a generated `sanara/fix-*` branch.",
                "- The original remediation run already produced the patch and PR body.",
                "- This follow-up branch run is skipped to avoid self-triggered loops.",
                "- `summary.md` and `run_summary.json` explain the follow-up skip reason.",
                "- Review the original remediation run or PR body for the actual fix details.",
            ]
        ),
    )


@dataclass
class BaselinePhaseResult:
    target_dirs: list[Path]
    mapping: dict[str, str]
    mapped_check_ids: set[str]
    repair_profiles: dict[str, dict[str, Any]]
    normalized: list[dict[str, Any]]
    normalized_actionable: list[dict[str, Any]]
    normalized_suggest_only: list[dict[str, Any]]
    normalized_ignored: list[dict[str, Any]]
    scan_excluded_mapped: list[dict[str, Any]]
    uncovered_baseline: list[dict[str, Any]]
    uncovered_scan_excluded: list[dict[str, Any]]
    scan_policy_review: dict[str, Any]
    mapped_policy_review: dict[str, Any]
    baseline_scan: ScanPayload


@dataclass
class RepairPhaseResult:
    attempts_dict: list[dict[str, Any]]
    attempted_rules: set[str]
    diff: str


def _runtime_budget_snapshot(run_start: float, max_runtime_seconds: int) -> dict[str, Any]:
    elapsed = max(0, int(time.time() - run_start))
    return {
        "elapsed_seconds": elapsed,
        "remaining_seconds": max(0, max_runtime_seconds - elapsed),
        "max_runtime_seconds": max_runtime_seconds,
    }


def _phase_scan(
    logger: RunLogger,
    workspace: Path,
    artifacts_dir: Path,
    context,
    policy,
    phase_timings_ms: dict[str, int],
) -> BaselinePhaseResult:
    target_dirs = _transition(
        logger,
        "DISCOVER_TARGET_DIRS",
        lambda: discover_target_dirs(workspace, context.base_sha, context.head_sha),
        phase_timings_ms,
    )
    write_json_file(artifacts_dir, "target_dirs.json", [str(x) for x in target_dirs])
    baseline_raw = _transition(
        logger,
        "SCAN_BASELINE",
        lambda: run_scan_only(workspace, target_dirs, scan_policy=policy.scan_policy),
        phase_timings_ms,
    )
    baseline_scan = ScanPayload.from_raw(baseline_raw)
    write_json_file(artifacts_dir, "baseline/checkov.json", baseline_scan.to_dict()["checkov"])
    mapping = load_mapping(workspace)
    mapped_check_ids = set(mapping.keys())
    repair_profiles = _load_repair_profiles(workspace)
    normalized_all = _transition(
        logger,
        "NORMALIZE_FINDINGS",
        lambda: normalize_all(baseline_scan.to_dict()["checkov"], mapping),
        phase_timings_ms,
    )
    _validate_findings_schema(normalized_all)
    normalized, scan_excluded_mapped, scan_review_mapped = apply_scan_policy_to_findings(
        policy, normalized_all
    )
    normalized_payload = {
        "schema_id": "sanara.findings",
        "schema_version": "0.1",
        "sanara_version": __version__,
        "rule_pack_version": policy.rule_pack_version,
        "run_metadata": {
            "run_id": os.environ.get("GITHUB_RUN_ID", "local-run"),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "repo": context.repo,
            "base_sha": context.base_sha,
            "head_sha": context.head_sha,
            "event_type": context.event_name,
            "actor": context.actor,
            "is_fork": context.is_fork,
        },
        "findings": normalized,
    }
    write_json_file(artifacts_dir, "baseline/normalized_findings.json", normalized_payload)
    normalized_actionable, normalized_suggest_only, normalized_ignored, policy_review = (
        annotate_and_filter_mapped_findings(policy, normalized)
    )
    write_json_file(artifacts_dir, "baseline/policy_review.json", policy_review)
    uncovered_baseline_all = _unmapped_checkov_findings(
        baseline_scan.to_dict()["checkov"], mapped_check_ids, workspace
    )
    uncovered_baseline, uncovered_scan_excluded, scan_review_uncovered = (
        apply_scan_policy_to_findings(policy, uncovered_baseline_all)
    )
    baseline_scan_policy_review = {
        "mapped": scan_review_mapped,
        "uncovered": scan_review_uncovered,
    }
    write_json_file(
        artifacts_dir,
        "baseline/scan_policy_review.json",
        baseline_scan_policy_review,
    )
    _LOG.info(
        "baseline scan complete targets=%d mapped_findings=%d actionable_mapped=%d suggest_only=%d ignored=%d uncovered_baseline=%d raw_checkov_failed=%d scan_excluded_mapped=%d scan_excluded_uncovered=%d",
        len(target_dirs),
        len(normalized),
        len(normalized_actionable),
        len(normalized_suggest_only),
        len(normalized_ignored),
        len(uncovered_baseline),
        len(_checkov_failed_items(baseline_scan.to_dict()["checkov"])),
        len(scan_excluded_mapped),
        len(uncovered_scan_excluded),
    )
    return BaselinePhaseResult(
        target_dirs=target_dirs,
        mapping=mapping,
        mapped_check_ids=mapped_check_ids,
        repair_profiles=repair_profiles,
        normalized=normalized,
        normalized_actionable=normalized_actionable,
        normalized_suggest_only=normalized_suggest_only,
        normalized_ignored=normalized_ignored,
        scan_excluded_mapped=scan_excluded_mapped,
        uncovered_baseline=uncovered_baseline,
        uncovered_scan_excluded=uncovered_scan_excluded,
        scan_policy_review=baseline_scan_policy_review,
        mapped_policy_review=policy_review,
        baseline_scan=baseline_scan,
    )


def _phase_repair(
    logger: RunLogger,
    workspace: Path,
    artifacts_dir: Path,
    normalized: list[dict[str, Any]],
    policy,
    phase_timings_ms: dict[str, int],
) -> RepairPhaseResult:
    _transition(logger, "SELECT_ATTEMPTS", lambda: None, phase_timings_ms)
    drc_attempts = _transition(
        logger,
        "DRC_APPLY",
        lambda: apply_drc(workspace, normalized, policy),
        phase_timings_ms,
    )
    attempts_dict = [a.__dict__ for a in drc_attempts]
    _validate_contracts_schema(attempts_dict)
    write_json_file(artifacts_dir, "drc/patch_contract.json", {"attempts": attempts_dict})
    diff = _git_diff(workspace)
    write_text(artifacts_dir, "drc/patch.diff", diff)
    attempted_rules = {a.sanara_rule_id for a in drc_attempts if a.status != "failed"}
    changed_count = sum(1 for a in drc_attempts if a.status == "changed")
    failed_count = sum(1 for a in drc_attempts if a.status == "failed")
    _LOG.info(
        "drc apply complete attempts=%d changed=%d failed=%d attempted_rules=%d",
        len(drc_attempts),
        changed_count,
        failed_count,
        len(attempted_rules),
    )
    return RepairPhaseResult(
        attempts_dict=attempts_dict, attempted_rules=attempted_rules, diff=diff
    )


def _exit_comment_only(
    logger: RunLogger,
    artifacts_dir: Path,
    context,
    target_dirs: list[Path],
    normalized: list[dict[str, Any]],
    attempts_dict: list[dict[str, Any]],
    reason: str,
    reason_message: str | None = None,
    decision: str = "COMMENT_ONLY",
    client: GitHubClient | None = None,
    comment: str | None = None,
    agentic_summary: dict[str, Any] | None = None,
    terraform_summary: dict[str, Any] | None = None,
    phase_timings_ms: dict[str, int] | None = None,
    runtime_budget: dict[str, Any] | None = None,
) -> int:
    if comment:
        _post_comment_if_possible(client, context.pr_number, comment)
    _write_run_summary(
        artifacts_dir,
        context,
        target_dirs,
        normalized,
        attempts_dict,
        decision,
        {"reason_code": reason, "message": reason_message or ""},
        agentic_summary=agentic_summary,
        terraform_summary=terraform_summary,
        phase_timings_ms=phase_timings_ms,
        runtime_budget=runtime_budget,
    )
    _transition(logger, "COMMENT_ONLY", lambda: None)
    _transition(logger, "FINALIZE", lambda: None)
    _safe_finalize(
        artifacts_dir, ["# Sanara v0.1 Run Summary", f"- decision: {decision} ({reason})"]
    )
    return 0


def run_driver(workspace: Path, event_path: Path, artifacts_dir: Path) -> int:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    logger = RunLogger(artifacts_dir / "runlog.jsonl")
    run_start = time.time()
    phase_timings_ms: dict[str, int] = {}
    _LOG.info(
        "run start workspace=%s event=%s artifacts=%s repo_env=%s run_id=%s",
        workspace,
        event_path,
        artifacts_dir,
        os.environ.get("GITHUB_REPOSITORY", "local/sanara"),
        os.environ.get("GITHUB_RUN_ID", "local-run"),
    )
    resolved_tool_versions = _resolve_tool_versions(workspace)
    _LOG.info(
        "tool_versions terraform=%s checkov=%s",
        resolved_tool_versions.get("terraform", "unknown"),
        resolved_tool_versions.get("checkov", "unknown"),
    )

    def _t(state: str, fn):
        return _transition(logger, state, fn, phase_timings_ms)

    event = load_event(event_path)
    _t("INIT", lambda: None)
    context = _t("DETECT_CONTEXT", lambda: detect_context(event, dict(os.environ)))
    action_inputs = {
        "environment": os.environ.get("INPUT_ENVIRONMENT"),
        "allow_agentic": os.environ.get("INPUT_ALLOW_AGENTIC"),
        "llm_context_mode": os.environ.get("INPUT_LLM_CONTEXT_MODE"),
        "llm_provider": os.environ.get("INPUT_LLM_PROVIDER"),
        "anthropic_model": os.environ.get("INPUT_ANTHROPIC_MODEL"),
        "openai_model": os.environ.get("INPUT_OPENAI_MODEL"),
        "agentic_max_attempts": os.environ.get("INPUT_AGENTIC_MAX_ATTEMPTS"),
        "plan_required": os.environ.get("INPUT_PLAN_REQUIRED"),
        "publish_dry_run": os.environ.get("INPUT_PUBLISH_DRY_RUN"),
    }
    if isinstance(action_inputs["allow_agentic"], str):
        action_inputs["allow_agentic"] = action_inputs["allow_agentic"].lower() == "true"
    if isinstance(action_inputs["plan_required"], str):
        action_inputs["plan_required"] = action_inputs["plan_required"].lower() == "true"
    if isinstance(action_inputs["publish_dry_run"], str):
        action_inputs["publish_dry_run"] = action_inputs["publish_dry_run"].lower() == "true"
    policy = _t("LOAD_POLICY", lambda: load_policy(workspace, action_inputs))
    effective_checkov_filter_args = checkov_cli_filter_args(policy.scan_policy)
    _LOG.info("scan_filters checkov_cli_args=%s", effective_checkov_filter_args)
    effective_policy = effective_policy_overview(policy)
    policy_overrides_loaded = bool(
        (effective_policy.get("finding_policy", {}) or {}).get("configured")
        or (effective_policy.get("scan_policy", {}) or {}).get("configured")
        or (effective_policy.get("advisor", {}) or {}).get("configured")
    )
    write_json_file(artifacts_dir, "policy/effective_config.json", effective_policy)
    advisor_bootstrap = {
        "schema_id": "sanara.advisor.findings",
        "schema_version": "0.1",
        "status": "not_run",
        "findings": [],
        "llm": {"used": False, "ok": False, "message": ""},
    }
    _validate_advisor_findings_schema(advisor_bootstrap)
    write_json_file(
        artifacts_dir,
        "advisor/findings.json",
        advisor_bootstrap,
    )

    write_meta(
        artifacts_dir,
        {
            "run_id": os.environ.get("GITHUB_RUN_ID", "local-run"),
            "repo": context.repo,
            "base_sha": context.base_sha,
            "head_sha": context.head_sha,
            "base_ref": context.base_ref,
            "head_ref": context.head_ref,
            "github_ref": context.github_ref,
            "github_ref_name": context.github_ref_name,
            "github_base_ref": context.github_base_ref,
            "github_head_ref": context.github_head_ref,
            "rule_pack_version": policy.rule_pack_version,
            "environment": policy.environment,
            "policy_hash": policy_hash(policy.to_dict()),
            "toolchain": {
                "terraform": resolved_tool_versions.get("terraform", "unknown"),
                "checkov": resolved_tool_versions.get("checkov", "unknown"),
            },
            "scanner_filters": {
                "checkov_cli_args": effective_checkov_filter_args,
                "scan_policy": policy.scan_policy,
            },
        },
    )
    policy_evaluation_artifact: dict[str, Any] = {
        "schema_id": "sanara.policy_evaluation",
        "schema_version": "0.1",
        "environment": policy.environment,
        "scan_policy": policy.scan_policy,
        "finding_policy": policy.finding_policy,
        "snapshots": {},
    }

    if context.skip:
        _LOG.info("run skipped reason=%s", context.skip_reason)
        _write_skip_artifacts(artifacts_dir, context, phase_timings_ms, policy)
        _t("FINALIZE", lambda: None)
        _safe_finalize(
            artifacts_dir,
            [
                "# Sanara v0.1 Summary",
                "",
                f"- Decision: SKIPPED (`{context.skip_reason}`)",
                "- This is a follow-up run on a generated `sanara/fix-*` branch.",
                "- The original remediation run already produced the patch and PR body.",
                "- This follow-up branch run is skipped to avoid self-triggered loops.",
                "- Review the original remediation run artifacts or PR body for the actual fix details.",
            ],
        )
        return 0

    token = os.environ.get("GITHUB_TOKEN")
    client = GitHubClient(token, context.repo) if token else None

    baseline_phase = _phase_scan(
        logger=logger,
        workspace=workspace,
        artifacts_dir=artifacts_dir,
        context=context,
        policy=policy,
        phase_timings_ms=phase_timings_ms,
    )
    target_dirs = baseline_phase.target_dirs
    mapping = baseline_phase.mapping
    mapped_check_ids = baseline_phase.mapped_check_ids
    repair_profiles = baseline_phase.repair_profiles
    normalized = baseline_phase.normalized
    normalized_actionable = baseline_phase.normalized_actionable
    normalized_suggest_only = baseline_phase.normalized_suggest_only
    normalized_ignored = baseline_phase.normalized_ignored
    scan_excluded_mapped = baseline_phase.scan_excluded_mapped
    uncovered_baseline = baseline_phase.uncovered_baseline
    uncovered_scan_excluded = baseline_phase.uncovered_scan_excluded
    baseline_scan_policy_review = baseline_phase.scan_policy_review
    baseline_mapped_policy_review = baseline_phase.mapped_policy_review
    baseline_checkov_failed = len(
        _checkov_failed_items(baseline_phase.baseline_scan.to_dict()["checkov"])
    )
    policy_evaluation_artifact["snapshots"]["baseline"] = policy_eval_snapshot(
        stage="baseline",
        scan_policy_review=baseline_scan_policy_review,
        policy_review=baseline_mapped_policy_review,
    )

    repair_phase = _phase_repair(
        logger=logger,
        workspace=workspace,
        artifacts_dir=artifacts_dir,
        normalized=normalized_actionable,
        policy=policy,
        phase_timings_ms=phase_timings_ms,
    )
    attempts_dict = repair_phase.attempts_dict
    diff = repair_phase.diff

    rails = _t("RAILS_VALIDATE_PATCH", lambda: validate_patch(diff, workspace, policy))
    _LOG.info("rails validate result ok=%s code=%s", rails.ok, getattr(rails, "code", ""))
    if not rails.ok:
        return _exit_comment_only(
            logger=logger,
            artifacts_dir=artifacts_dir,
            context=context,
            target_dirs=target_dirs,
            normalized=normalized,
            attempts_dict=attempts_dict,
            reason=rails.code,
            reason_message=rails.message,
            client=client,
            comment=f"Sanara did not create a fix PR. Rail failed: {rails.code} ({rails.message}). See artifacts.",
            phase_timings_ms=phase_timings_ms,
            runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
        )

    if time.time() - run_start > policy.max_runtime_seconds:
        return _exit_comment_only(
            logger=logger,
            artifacts_dir=artifacts_dir,
            context=context,
            target_dirs=target_dirs,
            normalized=normalized,
            attempts_dict=attempts_dict,
            reason="runtime_budget",
            reason_message="Runtime budget exceeded before publish decision.",
            client=client,
            comment="Sanara did not create a fix PR because runtime budget was exceeded.",
            phase_timings_ms=phase_timings_ms,
            runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
        )

    tf_checks = None
    tf_dict: dict[str, Any] = {"ok": False, "runs": []}

    def _run_final_terraform_checks():
        nonlocal tf_checks, tf_dict
        fmt = run_cmd(["terraform", "fmt", "-recursive"], cwd=workspace)
        tf_checks = _t(
            "TF_CHECKS", lambda: run_harness_checks(workspace, workspace / ".sanara/harness.yml")
        )
        tf_dict = tf_checks.to_dict()
        inferred_root_runs = sum(
            1 for run in tf_checks.runs if run.get("source") == "inferred_root"
        )
        _LOG.info(
            "terraform checks result ok=%s runs=%d inferred_root_runs=%d",
            tf_checks.ok,
            len(tf_checks.runs),
            inferred_root_runs,
        )
        for run in tf_dict.get("runs", []):
            init_phase = run.get("init", {})
            validate_phase = run.get("validate", {})
            plan_phase = run.get("plan", {})
            _LOG.info(
                "terraform run name=%s source=%s working_dir=%s",
                run.get("name", "unknown"),
                run.get("source", "unknown"),
                run.get("working_dir", ""),
            )
            _LOG.info(
                "terraform init code=%s cmd=%s",
                init_phase.get("code"),
                " ".join(str(x) for x in init_phase.get("cmd", [])),
            )
            if str(init_phase.get("stdout", "")).strip():
                _LOG.info("terraform init stdout:\n%s", init_phase.get("stdout", ""))
            if str(init_phase.get("stderr", "")).strip():
                _LOG.info("terraform init stderr:\n%s", init_phase.get("stderr", ""))
            _LOG.info(
                "terraform validate code=%s cmd=%s",
                validate_phase.get("code"),
                " ".join(str(x) for x in validate_phase.get("cmd", [])),
            )
            if str(validate_phase.get("stdout", "")).strip():
                _LOG.info("terraform validate stdout:\n%s", validate_phase.get("stdout", ""))
            if str(validate_phase.get("stderr", "")).strip():
                _LOG.info("terraform validate stderr:\n%s", validate_phase.get("stderr", ""))
            _LOG.info(
                "terraform plan code=%s cmd=%s",
                plan_phase.get("code"),
                " ".join(str(x) for x in plan_phase.get("cmd", [])),
            )
            if str(plan_phase.get("stdout", "")).strip():
                _LOG.info("terraform plan stdout:\n%s", plan_phase.get("stdout", ""))
            if str(plan_phase.get("stderr", "")).strip():
                _LOG.info("terraform plan stderr:\n%s", plan_phase.get("stderr", ""))
        if inferred_root_runs:
            _LOG.info(
                "terraform checks used inferred root fallback because no explicit harness was configured"
            )
        write_json_file(artifacts_dir, "terraform/checks.json", tf_dict)
        _write_terraform_logs(artifacts_dir, tf_dict, fmt.stdout, fmt.stderr)

    attempted_rules = repair_phase.attempted_rules
    uncovered_attempted_rules = {f["sanara_rule_id"] for f in uncovered_baseline}
    attempted_rules_all = attempted_rules | uncovered_attempted_rules
    run_state = RunState(diff=diff)

    rescan_raw = _t(
        "RESCAN_TARGETED",
        lambda: run_scan_only(workspace, target_dirs, scan_policy=policy.scan_policy),
    )
    post_drc_stage = apply_rescan_stage(
        stage="post_drc",
        artifacts_dir=artifacts_dir,
        scan_raw=rescan_raw,
        policy=policy,
        mapping=mapping,
        mapped_check_ids=mapped_check_ids,
        workspace=workspace,
        attempted_rules=attempted_rules_all,
        build_current_findings_state=_build_current_findings_state,
        write_targeted_results=_write_targeted_results,
        checkov_failed_items=_checkov_failed_items,
        policy_evaluation_artifact=policy_evaluation_artifact,
        write_primary_rescan_alias=True,
    )
    rescan_checkov_failed = post_drc_stage.raw_checkov_failed
    run_state.clean = post_drc_stage.effective_state.clean
    run_state.candidate_remaining = post_drc_stage.scan_state.remaining
    run_state.blocking_remaining = post_drc_stage.effective_state.remaining
    run_state.advisory_remaining = post_drc_stage.decision_partition.advisory
    run_state.ignored_remaining = post_drc_stage.decision_partition.ignored
    run_state.remaining_mapped = post_drc_stage.effective_state.remaining_mapped
    run_state.remaining_uncovered = post_drc_stage.effective_state.remaining_uncovered

    clean = run_state.clean
    remaining = run_state.remaining_mapped
    uncovered_remaining = run_state.remaining_uncovered
    advisory_remaining_all = run_state.advisory_remaining
    ignored_remaining_all = run_state.ignored_remaining
    blocking_remaining_all = run_state.blocking_remaining
    post_drc_remaining_total = len(blocking_remaining_all)
    post_drc_remaining_mapped = len(remaining)
    post_drc_remaining_uncovered = len(uncovered_remaining)
    post_drc_advisory_total = len(advisory_remaining_all)
    post_drc_ignored_total = len(ignored_remaining_all)
    _LOG.info(
        "post_drc rescan raw_checkov_failed=%d remaining_total=%d mapped=%d uncovered=%d clean=%s",
        rescan_checkov_failed,
        post_drc_remaining_total,
        post_drc_remaining_mapped,
        post_drc_remaining_uncovered,
        clean,
    )

    agentic_used = False
    llm_attempts = 0
    llm_accepted_attempts = 0
    llm_rejection_counts: dict[str, int] = {}
    llm_improved_findings: list[dict[str, str]] = []
    agentic_feedback = ""
    final_checkov_failed = rescan_checkov_failed
    advisory_remaining_final = run_state.advisory_remaining
    ignored_remaining_final = run_state.ignored_remaining
    final_stage = apply_rescan_stage(
        stage="final",
        artifacts_dir=artifacts_dir,
        scan_raw=post_drc_stage.scan.to_dict(),
        policy=policy,
        mapping=mapping,
        mapped_check_ids=mapped_check_ids,
        workspace=workspace,
        attempted_rules=attempted_rules_all,
        build_current_findings_state=_build_current_findings_state,
        write_targeted_results=_write_targeted_results,
        checkov_failed_items=_checkov_failed_items,
        policy_evaluation_artifact=policy_evaluation_artifact,
        write_primary_rescan_alias=False,
    )

    def _agentic_summary_payload() -> dict[str, Any]:
        top_rejections: list[dict[str, Any]] = []
        if "agentic_result" in locals():
            for entry in agentic_result.agentic_ledgers:
                stage = str(entry.get("rejection_stage", "")).strip()
                if not stage:
                    continue
                top_rejections.append(
                    {
                        "attempt": int(entry.get("attempt", 0) or 0),
                        "stage": stage,
                        "reason": str(entry.get("rejection_reason", "")).strip(),
                        "target_file": str(entry.get("target_file", "")).strip(),
                        "target_file_exists_before": bool(
                            entry.get("target_file_exists_before", False)
                        ),
                        "changed_files": list(entry.get("changed_files", []) or []),
                    }
                )
                if len(top_rejections) >= 5:
                    break
        return {
            "used": agentic_used,
            "attempts": llm_attempts,
            "accepted_attempts": llm_accepted_attempts,
            "rejection_counts": llm_rejection_counts,
            "final_feedback": agentic_feedback,
            "top_rejections": top_rejections,
        }

    if not run_state.clean and policy.allow_agentic and not context.is_fork:
        agentic_used = True
        _LOG.info(
            "agentic start blocking_total=%d remaining_mapped=%d remaining_uncovered=%d",
            len(run_state.blocking_remaining),
            len(remaining),
            len(uncovered_remaining),
        )
        agentic_result = _t(
            "AGENTIC_APPLY",
            lambda: run_agentic_apply(
                workspace=workspace,
                target_dirs=target_dirs,
                mapping=mapping,
                mapped_check_ids=mapped_check_ids,
                policy=policy,
                repair_profiles=repair_profiles,
                clean=run_state.clean,
                remaining=list(run_state.blocking_remaining),
                remaining_mapped=remaining,
                remaining_uncovered=uncovered_remaining,
                diff=run_state.diff,
                build_current_findings_state=_build_current_findings_state,
                write_terraform_logs=lambda tf, fmt_out, fmt_err: _write_terraform_logs(
                    artifacts_dir, tf, fmt_out, fmt_err
                ),
                max_total_attempts=policy.agentic_max_attempts,
            ),
        )
        run_state.diff = agentic_result.diff
        write_json_file(
            artifacts_dir,
            "agentic/llm_ledger.json",
            {
                "attempts": agentic_result.agentic_ledgers,
                "final_feedback": agentic_result.feedback,
            },
        )
        llm_attempts = len(agentic_result.agentic_ledgers)
        llm_accepted_attempts = sum(
            1 for entry in agentic_result.agentic_ledgers if bool(entry.get("accepted_patch"))
        )
        improved_map: dict[str, dict[str, str]] = {}
        for entry in agentic_result.agentic_ledgers:
            if not (bool(entry.get("accepted_patch")) and bool(entry.get("progressed"))):
                continue
            finding = entry.get("finding") or {}
            source_rule_id = str(finding.get("source_rule_id", "")).strip().upper()
            if not source_rule_id:
                continue
            improved_map[source_rule_id] = {
                "source_rule_id": source_rule_id,
                "sanara_rule_id": str(finding.get("sanara_rule_id", "")).strip(),
            }
        llm_improved_findings = [improved_map[k] for k in sorted(improved_map)]
        agentic_feedback = agentic_result.feedback
        for entry in agentic_result.agentic_ledgers:
            stage = str(entry.get("rejection_stage", "")).strip() or "accepted"
            llm_rejection_counts[stage] = llm_rejection_counts.get(stage, 0) + 1
        write_json_file(
            artifacts_dir,
            "agentic/summary.json",
            _agentic_summary_payload(),
        )
        final_stage = apply_rescan_stage(
            stage="final",
            artifacts_dir=artifacts_dir,
            scan_raw=agentic_result.final_scan_raw or post_drc_stage.scan.to_dict(),
            policy=policy,
            mapping=mapping,
            mapped_check_ids=mapped_check_ids,
            workspace=workspace,
            attempted_rules=attempted_rules_all,
            build_current_findings_state=_build_current_findings_state,
            write_targeted_results=_write_targeted_results,
            checkov_failed_items=_checkov_failed_items,
            policy_evaluation_artifact=policy_evaluation_artifact,
            write_primary_rescan_alias=False,
        )
        run_state.clean = final_stage.effective_state.clean
        run_state.candidate_remaining = final_stage.scan_state.remaining
        run_state.blocking_remaining = final_stage.effective_state.remaining
        run_state.advisory_remaining = final_stage.decision_partition.advisory
        run_state.ignored_remaining = final_stage.decision_partition.ignored
        run_state.remaining_mapped = final_stage.effective_state.remaining_mapped
        run_state.remaining_uncovered = final_stage.effective_state.remaining_uncovered
        clean = run_state.clean
        remaining = run_state.remaining_mapped
        uncovered_remaining = run_state.remaining_uncovered
        advisory_remaining_all = run_state.advisory_remaining
        ignored_remaining_all = run_state.ignored_remaining
        blocking_remaining_all = run_state.blocking_remaining
        advisory_remaining_final = advisory_remaining_all
        ignored_remaining_final = ignored_remaining_all
        final_checkov_failed = final_stage.raw_checkov_failed
        _LOG.info(
            "agentic complete attempts=%d accepted=%d clean=%s remaining_total=%d feedback=%s",
            llm_attempts,
            llm_accepted_attempts,
            clean,
            len(run_state.candidate_remaining),
            (agentic_result.feedback or "").strip()[:200],
        )
        _LOG.info("agentic rejection_counts=%s", llm_rejection_counts)
        write_json_file(artifacts_dir, "agentic/trace.jsonl", agentic_result.agentic_traces)
        write_text(artifacts_dir, "agentic/response.txt", agentic_result.final_response)
        write_text(artifacts_dir, "agentic/patch.diff", agentic_result.final_patch)
        _LOG.info(
            "final-stage rescan raw_checkov_failed=%d remaining_total=%d mapped=%d uncovered=%d clean=%s",
            final_checkov_failed,
            len(blocking_remaining_all),
            len(remaining),
            len(uncovered_remaining),
            clean,
        )

        if remaining and not clean:
            _LOG.info("final-stage deterministic cleanup start remaining_mapped=%d", len(remaining))
            cleanup_attempts = apply_drc(workspace, remaining, policy)
            if any(a.status == "changed" for a in cleanup_attempts):
                run_state.diff = _git_diff(workspace)
                cleanup_scan_raw = run_scan_only(
                    workspace, target_dirs, use_cache=False, scan_policy=policy.scan_policy
                )
                final_stage = apply_rescan_stage(
                    stage="final",
                    artifacts_dir=artifacts_dir,
                    scan_raw=cleanup_scan_raw,
                    policy=policy,
                    mapping=mapping,
                    mapped_check_ids=mapped_check_ids,
                    workspace=workspace,
                    attempted_rules=attempted_rules_all,
                    build_current_findings_state=_build_current_findings_state,
                    write_targeted_results=_write_targeted_results,
                    checkov_failed_items=_checkov_failed_items,
                    policy_evaluation_artifact=policy_evaluation_artifact,
                    write_primary_rescan_alias=False,
                )
                run_state.clean = final_stage.effective_state.clean
                run_state.candidate_remaining = final_stage.scan_state.remaining
                run_state.blocking_remaining = final_stage.effective_state.remaining
                run_state.advisory_remaining = final_stage.decision_partition.advisory
                run_state.ignored_remaining = final_stage.decision_partition.ignored
                run_state.remaining_mapped = final_stage.effective_state.remaining_mapped
                run_state.remaining_uncovered = final_stage.effective_state.remaining_uncovered
                clean = run_state.clean
                remaining = run_state.remaining_mapped
                uncovered_remaining = run_state.remaining_uncovered
                advisory_remaining_all = run_state.advisory_remaining
                ignored_remaining_all = run_state.ignored_remaining
                advisory_remaining_final = advisory_remaining_all
                ignored_remaining_final = ignored_remaining_all
                blocking_remaining_all = run_state.blocking_remaining
                final_checkov_failed = final_stage.raw_checkov_failed
                _LOG.info(
                    "final-stage deterministic cleanup complete clean=%s remaining_total=%d mapped=%d uncovered=%d",
                    clean,
                    len(blocking_remaining_all),
                    len(remaining),
                    len(uncovered_remaining),
                )
            else:
                _LOG.info(
                    "final-stage deterministic cleanup no_change remaining_mapped=%d",
                    len(remaining),
                )

    if (not agentic_used) and remaining and not clean:
        _LOG.info("post_drc deterministic cleanup start remaining_mapped=%d", len(remaining))
        cleanup_attempts = apply_drc(workspace, remaining, policy)
        if any(a.status == "changed" for a in cleanup_attempts):
            run_state.diff = _git_diff(workspace)
            cleanup_scan_raw = run_scan_only(
                workspace, target_dirs, use_cache=False, scan_policy=policy.scan_policy
            )
            final_stage = apply_rescan_stage(
                stage="final",
                artifacts_dir=artifacts_dir,
                scan_raw=cleanup_scan_raw,
                policy=policy,
                mapping=mapping,
                mapped_check_ids=mapped_check_ids,
                workspace=workspace,
                attempted_rules=attempted_rules_all,
                build_current_findings_state=_build_current_findings_state,
                write_targeted_results=_write_targeted_results,
                checkov_failed_items=_checkov_failed_items,
                policy_evaluation_artifact=policy_evaluation_artifact,
                write_primary_rescan_alias=False,
            )
            run_state.clean = final_stage.effective_state.clean
            run_state.candidate_remaining = final_stage.scan_state.remaining
            run_state.blocking_remaining = final_stage.effective_state.remaining
            run_state.advisory_remaining = final_stage.decision_partition.advisory
            run_state.ignored_remaining = final_stage.decision_partition.ignored
            run_state.remaining_mapped = final_stage.effective_state.remaining_mapped
            run_state.remaining_uncovered = final_stage.effective_state.remaining_uncovered
            clean = run_state.clean
            remaining = run_state.remaining_mapped
            uncovered_remaining = run_state.remaining_uncovered
            advisory_remaining_all = run_state.advisory_remaining
            ignored_remaining_all = run_state.ignored_remaining
            advisory_remaining_final = advisory_remaining_all
            ignored_remaining_final = ignored_remaining_all
            blocking_remaining_all = run_state.blocking_remaining
            final_checkov_failed = final_stage.raw_checkov_failed
            _LOG.info(
                "post_drc deterministic cleanup complete clean=%s remaining_total=%d mapped=%d uncovered=%d",
                clean,
                len(blocking_remaining_all),
                len(remaining),
                len(uncovered_remaining),
            )
        else:
            _LOG.info(
                "post_drc deterministic cleanup no_change remaining_mapped=%d", len(remaining)
            )

    final_remaining_total = len(run_state.blocking_remaining)
    final_remaining_mapped = len(remaining)
    final_remaining_uncovered = len(uncovered_remaining)
    baseline_mapped_blocking = int(
        (baseline_mapped_policy_review.get("counts", {}) or {}).get("hard_fail", 0)
    )
    drc_changed_attempts = sum(1 for a in attempts_dict if str(a.get("status")) == "changed")
    drc_no_change_attempts = sum(1 for a in attempts_dict if str(a.get("status")) == "no_change")
    drc_fixed_blocking_mapped = max(0, baseline_mapped_blocking - post_drc_remaining_mapped)
    post_drc_mapped_nonblocking = max(
        0,
        len(post_drc_stage.scan_state.remaining_mapped)
        - len(post_drc_stage.effective_state.remaining_mapped),
    )
    drc_raw_checkov_delta = baseline_checkov_failed - rescan_checkov_failed
    agentic_fixed_targeted_total = max(0, post_drc_remaining_total - final_remaining_total)
    agentic_fixed_targeted_mapped = max(0, post_drc_remaining_mapped - final_remaining_mapped)
    agentic_fixed_targeted_uncovered = max(
        0, post_drc_remaining_uncovered - final_remaining_uncovered
    )
    agentic_raw_checkov_delta = rescan_checkov_failed - final_checkov_failed

    _run_final_terraform_checks()
    if not tf_checks.runs:
        if policy.plan_required:
            return _exit_comment_only(
                logger=logger,
                artifacts_dir=artifacts_dir,
                context=context,
                target_dirs=target_dirs,
                normalized=normalized,
                attempts_dict=attempts_dict,
                reason="missing_harness",
                reason_message="No runnable harness found and plan_required=true.",
                client=client,
                comment="Sanara could not safely remediate because no runnable harness exists. Add examples/** or .sanara/harness.yml.",
                agentic_summary=_agentic_summary_payload(),
                terraform_summary=tf_dict,
                phase_timings_ms=phase_timings_ms,
                runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
            )
        write_text(
            artifacts_dir,
            "terraform/plan.log",
            "plan_required=false opt-in active; no harness found; plan gate skipped.\n",
        )

    if tf_checks.runs and not tf_checks.ok:
        return _exit_comment_only(
            logger=logger,
            artifacts_dir=artifacts_dir,
            context=context,
            target_dirs=target_dirs,
            normalized=normalized,
            attempts_dict=attempts_dict,
            reason="tf_checks_failed",
            reason_message="Terraform init/validate/plan gates failed.",
            client=client,
            comment="Sanara did not create a fix PR. Terraform validation gates failed. See artifacts.",
            agentic_summary=_agentic_summary_payload(),
            terraform_summary=tf_dict,
            phase_timings_ms=phase_timings_ms,
            runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
        )

    advisor_result = _t(
        "ADVISOR_GUIDE",
        lambda: run_post_fix_advisor(
            workspace,
            policy,
            run_state.diff,
            scanner_visible_findings=run_state.candidate_remaining,
        ),
    )
    advisor_findings = advisor_result.findings
    advisor_payload = {
        "schema_id": "sanara.advisor.findings",
        "schema_version": "0.1",
        "status": "ok",
        "findings": advisor_findings,
        "llm": {
            "used": advisor_result.llm_used,
            "ok": advisor_result.llm_ok,
            "message": advisor_result.llm_message,
        },
    }
    _validate_advisor_findings_schema(advisor_payload)
    write_json_file(
        artifacts_dir,
        "advisor/findings.json",
        advisor_payload,
    )
    if advisor_result.llm_raw.strip():
        write_text(artifacts_dir, "advisor/raw_response.txt", advisor_result.llm_raw)
    _LOG.info(
        "advisor guide findings=%d llm_used=%s llm_ok=%s",
        len(advisor_findings),
        advisor_result.llm_used,
        advisor_result.llm_ok,
    )

    _t("DECIDE", lambda: None)
    final_state = FinalState(decision="COMMENT_ONLY", reason_code="unknown")

    if clean and diff.strip() and not context.is_fork and client and _has_changes(workspace):
        _t("DEDUP_CHECK", lambda: None)
        dedup_payload = build_dedup_payload(
            client=client,
            base_sha=context.base_sha,
            attempted_rules=attempted_rules,
            target_dirs=target_dirs,
            patch_diff=diff,
        )
        if has_dedup_match(client, dedup_payload):
            _LOG.info("decision=DEDUP_SKIP reason=dedup_match")
            final_state.decision = "DEDUP_SKIP"
            final_state.reason_code = "dedup_match"
            _write_run_summary(
                artifacts_dir,
                context,
                target_dirs,
                normalized,
                attempts_dict,
                "DEDUP_SKIP",
                {
                    "reason_code": "dedup_match",
                    "message": "Open PR already exists for dedup marker.",
                },
                terraform_summary=tf_dict,
                phase_timings_ms=phase_timings_ms,
                runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
            )
            _t("FINALIZE", lambda: None)
            _safe_finalize(artifacts_dir, ["# Sanara v0.1 Run Summary", "- decision: DEDUP_SKIP"])
            return 0

        if policy.publish_dry_run:
            _LOG.info("decision=DRY_RUN_READY reason=publish_dry_run")
            return _exit_comment_only(
                logger=logger,
                artifacts_dir=artifacts_dir,
                context=context,
                target_dirs=target_dirs,
                normalized=normalized,
                attempts_dict=attempts_dict,
                reason="publish_dry_run",
                reason_message="publish_dry_run=true; publish step intentionally skipped.",
                decision="DRY_RUN_READY",
                client=client,
                comment="Sanara dry-run mode: remediation generated and validated, but PR publish was skipped by policy.",
                agentic_summary=_agentic_summary_payload(),
                terraform_summary=tf_dict,
                phase_timings_ms=phase_timings_ms,
                runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
            )

        branch = build_fix_branch_name()
        try:
            branch = _ensure_branch_and_push(workspace, branch, artifacts_dir=artifacts_dir)
        except CommandError as exc:
            return _exit_comment_only(
                logger=logger,
                artifacts_dir=artifacts_dir,
                context=context,
                target_dirs=target_dirs,
                normalized=normalized,
                attempts_dict=attempts_dict,
                reason="git_failure",
                reason_message=str(exc),
                client=client,
                comment=f"Sanara failed while preparing fix branch: {exc}",
                agentic_summary=_agentic_summary_payload(),
                terraform_summary=tf_dict,
                phase_timings_ms=phase_timings_ms,
                runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
            )

        body = build_fix_pr_body(
            client=client,
            dedup_payload=dedup_payload,
            attempted_rules=attempted_rules,
            agentic_enabled=agentic_used,
            llm_attempts=llm_attempts,
            llm_accepted_attempts=llm_accepted_attempts,
            llm_rejection_counts=llm_rejection_counts,
            llm_improved_findings=llm_improved_findings,
            findings_count=len(normalized),
            attempts_count=len(attempts_dict),
            changed_attempts=drc_changed_attempts,
            no_change_attempts=drc_no_change_attempts,
            clean=clean,
            blocking_remaining=len(run_state.blocking_remaining),
            advisory_remaining=len(advisory_remaining_final),
            ignored_remaining=len(ignored_remaining_final),
            baseline_checkov_failed=baseline_checkov_failed,
            final_checkov_failed=final_checkov_failed,
            plan_required=policy.plan_required,
            environment=policy.environment,
            policy_overrides_loaded=policy_overrides_loaded,
            advisory_remaining_findings=advisory_remaining_final,
            advisor_findings=advisor_findings,
            checkov_to_sanara=mapping,
            terraform_init_ok=(
                all(r.get("init", {}).get("code") == 0 for r in tf_checks.runs)
                if tf_checks.runs
                else None
            ),
            terraform_validate_ok=(
                all(r.get("validate", {}).get("code") == 0 for r in tf_checks.runs)
                if tf_checks.runs
                else None
            ),
            terraform_plan_ok=(
                all(r.get("plan", {}).get("code") == 0 for r in tf_checks.runs)
                if tf_checks.runs
                else None
            ),
        )
        _t(
            "PR_CREATE",
            lambda: client.create_pr(
                build_fix_pr_title(drc_changed_attempts, clean, len(llm_improved_findings)),
                body,
                branch,
                context.pr_branch or "main",
            ),
        )
        _LOG.info("decision=PR_CREATED reason=pr_created")
        _write_run_summary(
            artifacts_dir,
            context,
            target_dirs,
            normalized,
            attempts_dict,
            "PR_CREATED",
            {"reason_code": "pr_created", "message": "Fix PR created successfully."},
            agentic_summary=_agentic_summary_payload(),
            terraform_summary=tf_dict,
            phase_timings_ms=phase_timings_ms,
            runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
        )
        final_state.decision = "PR_CREATED"
        final_state.reason_code = "pr_created"
    else:
        reason_code = "unknown"
        reason_message = "PR not created."
        if not clean:
            reason_code = "remaining_findings"
            reason_message = "Targeted rescan is not clean after remediation."
        elif not diff.strip() or not _has_changes(workspace):
            reason_code = "no_changes"
            reason_message = "No repository changes to publish."
        elif context.is_fork:
            reason_code = "fork_restriction"
            reason_message = "Fork PR context disables branch push and PR creation."
        elif not client:
            reason_code = "missing_github_token"
            reason_message = "GITHUB_TOKEN is missing; cannot publish branch or PR."
        _post_comment_if_possible(
            client,
            context.pr_number,
            f"Sanara did not create a fix PR. reason={reason_code}. See artifacts for details.",
        )
        _LOG.info(
            "decision=COMMENT_ONLY reason=%s clean=%s has_diff=%s",
            reason_code,
            clean,
            bool(diff.strip()),
        )
        _t("COMMENT_ONLY", lambda: None)
        _write_run_summary(
            artifacts_dir,
            context,
            target_dirs,
            normalized,
            attempts_dict,
            "COMMENT_ONLY",
            {"reason_code": reason_code, "message": reason_message},
            agentic_summary=_agentic_summary_payload(),
            terraform_summary=tf_dict,
            phase_timings_ms=phase_timings_ms,
            runtime_budget=_runtime_budget_snapshot(run_start, policy.max_runtime_seconds),
        )
        final_state.decision = "COMMENT_ONLY"
        final_state.reason_code = reason_code

    _t("FINALIZE", lambda: None)
    policy_evaluation_artifact["final_decision"] = {
        "decision": final_state.decision,
        "reason_code": final_state.reason_code,
    }
    write_json_file(artifacts_dir, "policy/evaluation.json", policy_evaluation_artifact)
    _LOG.info(
        "run complete decision=%s reason=%s elapsed_seconds=%d",
        final_state.decision,
        final_state.reason_code,
        int(time.time() - run_start),
    )
    summary_view = SummaryView(
        environment=policy.environment,
        policy_overrides_loaded=policy_overrides_loaded,
        final_decision=final_state.decision,
        final_reason_code=final_state.reason_code,
        clean=clean,
        elapsed_seconds=int(time.time() - run_start),
        normalized=normalized,
        normalized_actionable=normalized_actionable,
        normalized_suggest_only=normalized_suggest_only,
        normalized_ignored=normalized_ignored,
        scan_excluded_mapped=scan_excluded_mapped,
        uncovered_scan_excluded=uncovered_scan_excluded,
        baseline_checkov_failed=baseline_checkov_failed,
        attempts_dict=attempts_dict,
        baseline_mapped_blocking=baseline_mapped_blocking,
        drc_changed_attempts=drc_changed_attempts,
        drc_no_change_attempts=drc_no_change_attempts,
        drc_fixed_blocking_mapped=drc_fixed_blocking_mapped,
        post_drc_mapped_nonblocking=post_drc_mapped_nonblocking,
        drc_raw_checkov_delta=drc_raw_checkov_delta,
        post_drc_remaining_total=post_drc_remaining_total,
        post_drc_remaining_mapped=post_drc_remaining_mapped,
        post_drc_remaining_uncovered=post_drc_remaining_uncovered,
        post_drc_advisory_total=post_drc_advisory_total,
        post_drc_ignored_total=post_drc_ignored_total,
        rescan_checkov_failed=rescan_checkov_failed,
        agentic_used=agentic_used,
        llm_attempts=llm_attempts,
        llm_accepted_attempts=llm_accepted_attempts,
        llm_rejection_counts=llm_rejection_counts,
        llm_improved_rule_ids=[
            str(item.get("source_rule_id", "")).strip().upper()
            for item in llm_improved_findings
            if str(item.get("source_rule_id", "")).strip()
        ],
        agentic_fixed_targeted_total=agentic_fixed_targeted_total,
        agentic_fixed_targeted_mapped=agentic_fixed_targeted_mapped,
        agentic_fixed_targeted_uncovered=agentic_fixed_targeted_uncovered,
        agentic_raw_checkov_delta=agentic_raw_checkov_delta,
        final_checkov_failed=final_checkov_failed,
        final_remaining_total=final_remaining_total,
        final_remaining_mapped=final_remaining_mapped,
        final_remaining_uncovered=final_remaining_uncovered,
        blocking_remaining_final=run_state.blocking_remaining,
        advisory_remaining_final=advisory_remaining_final,
        ignored_remaining_final=ignored_remaining_final,
        advisor_findings=advisor_findings,
        advisor_llm_used=advisor_result.llm_used,
        advisor_llm_ok=advisor_result.llm_ok,
    )
    _LOG.info(
        "summary outcome decision=%s reason=%s policy_clean=%s elapsed=%ss",
        summary_view.final_decision,
        summary_view.final_reason_code,
        summary_view.clean,
        summary_view.elapsed_seconds,
    )
    _LOG.info(
        "summary remediation drc_attempts=%d changed=%d no_change=%d llm_used=%s llm_attempts=%d raw_checkov=%d->%d",
        len(summary_view.attempts_dict),
        summary_view.drc_changed_attempts,
        summary_view.drc_no_change_attempts,
        summary_view.agentic_used,
        summary_view.llm_attempts,
        summary_view.baseline_checkov_failed,
        summary_view.final_checkov_failed,
    )
    _LOG.info(
        "summary findings blocking=%d advisory=%d ignored=%d policy_overrides=%s env=%s",
        summary_view.final_remaining_total,
        len(summary_view.advisory_remaining_final),
        len(summary_view.ignored_remaining_final),
        summary_view.policy_overrides_loaded,
        summary_view.environment,
    )
    write_text(
        artifacts_dir, "summary_detailed.md", "\n".join(build_summary_detailed_lines(summary_view))
    )
    write_text(
        artifacts_dir, "artifacts/index.md", "\n".join(build_artifact_index_lines(summary_view))
    )
    _safe_finalize(artifacts_dir, build_summary_lines(summary_view))
    return 0
