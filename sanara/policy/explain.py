from __future__ import annotations

from typing import Any

from sanara.policy.models import Policy

SCAN_POLICY_PRECEDENCE = [
    "include_ids",
    "skip_ids",
    "default_include",
]

FINDING_POLICY_PRECEDENCE = [
    "global_lists(auto_fix_allow/deny,suggest_only,ignore)",
    "hard_fail_on/soft_fail_on",
    "classifier_defaults",
]


def _count_list(v: Any) -> int:
    return len(v) if isinstance(v, list) else 0


def _count_dict(v: Any) -> int:
    return len(v) if isinstance(v, dict) else 0


def effective_policy_overview(policy: Policy) -> dict[str, Any]:
    scan = policy.scan_policy if isinstance(policy.scan_policy, dict) else {}
    finding = policy.finding_policy if isinstance(policy.finding_policy, dict) else {}
    return {
        "environment": policy.environment,
        "precedence": {
            "scan_policy": SCAN_POLICY_PRECEDENCE,
            "finding_policy": FINDING_POLICY_PRECEDENCE,
        },
        "scan_policy": {
            "configured": bool(scan),
            "include_ids": _count_list(scan.get("include_ids")),
            "skip_ids": _count_list(scan.get("skip_ids")),
        },
        "finding_policy": {
            "configured": bool(finding),
            "auto_fix_allow": _count_list(finding.get("auto_fix_allow")),
            "auto_fix_deny": _count_list(finding.get("auto_fix_deny")),
            "suggest_only": _count_list(finding.get("suggest_only")),
            "ignore": _count_list(finding.get("ignore")),
            "hard_fail_on": _count_list(finding.get("hard_fail_on")),
            "soft_fail_on": _count_list(finding.get("soft_fail_on")),
        },
        "advisor": {
            "configured": True,
            "enabled": bool(policy.advisor_enabled),
            "use_llm": bool(policy.advisor_use_llm),
            "max_findings": int(policy.advisor_max_findings),
            "min_severity": str(policy.advisor_min_severity),
        },
        "mutation_paths": {
            "allow_paths": list(policy.allow_paths),
            "deny_paths": list(policy.deny_paths),
        },
    }
