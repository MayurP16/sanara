from __future__ import annotations

from typing import Any

from sanara.policy.classify import finding_family_name
from sanara.policy.evaluate import finding_policy_decision, scan_policy_decision
from sanara.policy.models import Policy


def counts_by_family(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        fam = finding_family_name(finding)
        counts[fam] = counts.get(fam, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[0]))


def apply_scan_policy_to_findings(
    policy: Policy, findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    included: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}
    annotated: list[dict[str, Any]] = []
    for finding in findings:
        decision = scan_policy_decision(policy, finding)
        f = dict(finding)
        f["scan_policy"] = decision
        annotated.append(f)
        if bool(decision.get("include", True)):
            included.append(f)
        else:
            excluded.append(f)
            reason = str(decision.get("reason", "excluded"))
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    review = {
        "counts": {
            "total": len(findings),
            "included": len(included),
            "excluded": len(excluded),
            "excluded_by_reason": dict(sorted(reason_counts.items())),
        },
        "excluded_by_family": counts_by_family(excluded),
        "annotated_findings": annotated,
    }
    return included, excluded, review


def annotate_and_filter_mapped_findings(
    policy: Policy, normalized: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    actionable: list[dict[str, Any]] = []
    suggest_only: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    counts = {
        "mapped_total": len(normalized),
        "auto_fix_safe": 0,
        "auto_fix_opt_in": 0,
        "suggest_only": 0,
        "ignore": 0,
        "hard_fail": 0,
        "soft_fail": 0,
    }
    by_category: dict[str, int] = {}
    annotated: list[dict[str, Any]] = []
    for finding in normalized:
        decision = finding_policy_decision(policy, finding)
        f = dict(finding)
        f["policy"] = decision
        annotated.append(f)
        mode = decision.get("auto_fix_mode", "")
        counts[mode] = counts.get(mode, 0) + 1
        dmode = decision.get("decision_mode", "")
        counts[dmode] = counts.get(dmode, 0) + 1
        cat = str(decision.get("category", "unknown"))
        by_category[cat] = by_category.get(cat, 0) + 1
        if mode in {"auto_fix_safe", "auto_fix_opt_in"}:
            actionable.append(f)
        elif mode == "ignore":
            ignored.append(f)
        else:
            suggest_only.append(f)
    counts["by_category"] = by_category
    return (
        actionable,
        suggest_only,
        ignored,
        {"counts": counts, "annotated_mapped_findings": annotated},
    )


def apply_decision_policy_to_findings(
    policy: Policy, findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    blocking: list[dict[str, Any]] = []
    advisory: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for finding in findings:
        decision = finding_policy_decision(policy, finding)
        f = dict(finding)
        f["policy"] = decision
        mode = decision.get("decision_mode", "hard_fail")
        if mode == "ignore":
            ignored.append(f)
        elif mode == "soft_fail":
            advisory.append(f)
        else:
            blocking.append(f)
    return blocking, advisory, ignored


def policy_review_for_findings(policy: Policy, findings: list[dict[str, Any]]) -> dict[str, Any]:
    annotated: list[dict[str, Any]] = []
    counts = {
        "total": len(findings),
        "blocking": 0,
        "advisory": 0,
        "ignored": 0,
        "auto_fix_safe": 0,
        "auto_fix_opt_in": 0,
        "suggest_only": 0,
        "ignore": 0,
    }
    for finding in findings:
        decision = finding_policy_decision(policy, finding)
        f = dict(finding)
        f["policy"] = decision
        annotated.append(f)
        counts[str(decision.get("auto_fix_mode", ""))] = (
            counts.get(str(decision.get("auto_fix_mode", "")), 0) + 1
        )
        dmode = str(decision.get("decision_mode", "hard_fail"))
        if dmode == "ignore":
            counts["ignored"] += 1
        elif dmode == "soft_fail":
            counts["advisory"] += 1
        else:
            counts["blocking"] += 1
    return {"counts": counts, "annotated_findings": annotated}


def policy_eval_snapshot(
    *,
    stage: str,
    scan_policy_review: dict[str, Any] | None,
    policy_review: dict[str, Any] | None,
    clean: bool | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"stage": stage}
    if clean is not None:
        out["clean"] = bool(clean)
    if scan_policy_review is not None:
        out["scan_policy_review"] = scan_policy_review
    if policy_review is not None:
        out["finding_policy_review"] = policy_review
    return out
