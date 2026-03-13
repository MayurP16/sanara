from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from sanara.artifacts.bundle import write_json_file
from sanara.orchestrator.models import (
    DecisionPartition,
    FindingState,
    RescanStageResult,
    ScanPayload,
)
from sanara.policy import (
    apply_decision_policy_to_findings,
    apply_scan_policy_to_findings,
    policy_eval_snapshot,
    policy_review_for_findings,
)


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


def apply_rescan_stage(
    *,
    stage: str,
    artifacts_dir: Path,
    scan_raw: dict[str, Any],
    policy: Any,
    mapping: dict[str, str],
    mapped_check_ids: set[str],
    workspace: Path,
    attempted_rules: set[str],
    build_current_findings_state: Callable[
        [dict[str, Any], dict[str, str], set[str], Path], FindingState
    ],
    write_targeted_results: Callable[[Path, FindingState, set[str], str], None],
    checkov_failed_items: Callable[[dict[str, Any]], list[dict[str, Any]]],
    policy_evaluation_artifact: dict[str, Any] | None = None,
    write_primary_rescan_alias: bool = False,
) -> RescanStageResult:
    scan = ScanPayload.from_raw(scan_raw)
    scan_dict = scan.to_dict()
    checkov_payload = scan_dict["checkov"]
    raw_checkov_failed = len(checkov_failed_items(checkov_payload))

    if write_primary_rescan_alias:
        write_json_file(artifacts_dir, "rescan/checkov.json", checkov_payload)
    write_json_file(artifacts_dir, f"rescan/checkov_{stage}.json", checkov_payload)

    current_state = build_current_findings_state(scan_dict, mapping, mapped_check_ids, workspace)
    scan_included, scan_excluded, scan_policy_review = apply_scan_policy_to_findings(
        policy, current_state.remaining
    )
    scan_mapped, scan_uncovered = _partition_uncovered(scan_included)
    scan_state = FindingState(
        clean=len(scan_included) == 0,
        remaining=scan_included,
        remaining_mapped=scan_mapped,
        remaining_uncovered=scan_uncovered,
    )
    write_json_file(artifacts_dir, f"rescan/scan_policy_review_{stage}.json", scan_policy_review)

    blocking, advisory, ignored = apply_decision_policy_to_findings(policy, scan_state.remaining)
    blocking_mapped, blocking_uncovered = _partition_uncovered(blocking)
    effective_state = FindingState(
        clean=len(blocking) == 0,
        remaining=blocking,
        remaining_mapped=blocking_mapped,
        remaining_uncovered=blocking_uncovered,
    )
    write_targeted_results(
        artifacts_dir, effective_state, attempted_rules, "rescan/targeted_results.json"
    )
    write_targeted_results(
        artifacts_dir, effective_state, attempted_rules, f"rescan/targeted_results_{stage}.json"
    )

    finding_policy_review = policy_review_for_findings(policy, scan_state.remaining)
    write_json_file(artifacts_dir, f"rescan/policy_review_{stage}.json", finding_policy_review)

    if policy_evaluation_artifact is not None:
        policy_evaluation_artifact.setdefault("snapshots", {})[stage] = policy_eval_snapshot(
            stage=stage,
            scan_policy_review=scan_policy_review,
            policy_review=finding_policy_review,
            clean=effective_state.clean,
        )

    return RescanStageResult(
        stage=stage,
        scan=scan,
        raw_checkov_failed=raw_checkov_failed,
        scan_state=scan_state,
        effective_state=effective_state,
        scan_excluded=scan_excluded,
        scan_policy_review=scan_policy_review,
        finding_policy_review=finding_policy_review,
        decision_partition=DecisionPartition(blocking=blocking, advisory=advisory, ignored=ignored),
    )
