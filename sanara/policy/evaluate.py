from __future__ import annotations

from datetime import date
from fnmatch import fnmatch
import os
from pathlib import Path
from typing import Any

from sanara.policy.classify import (
    _coerce_upper_set,
    _sanara_family,
    classify_checkov_finding,
    finding_family_name,
)
from sanara.policy.models import Policy


def _expiry_active(expiry: str | None) -> bool:
    """Treat invalid expiry data as active so malformed suppressions do not unblock findings."""
    if not expiry:
        return True
    try:
        return date.today() <= date.fromisoformat(str(expiry))
    except Exception:
        return True


def _normalized_rel_path(path: str) -> str:
    return str(path or "").strip().replace("\\", "/").lstrip("/")


def _workspace_relative_policy_path(finding: dict[str, Any]) -> str:
    target = finding.get("target", {}) if isinstance(finding.get("target"), dict) else {}
    raw_file_path = _normalized_rel_path(
        str(target.get("file_path") or finding.get("file_path", ""))
    )
    if not raw_file_path:
        return ""
    if "/" in raw_file_path:
        return raw_file_path

    module_dir = str(target.get("module_dir", "")).strip()
    if not module_dir:
        return raw_file_path

    module_path = Path(module_dir)
    combined = module_path / raw_file_path

    workspace_root = str(os.environ.get("GITHUB_WORKSPACE", "")).strip()
    if workspace_root:
        try:
            return combined.relative_to(Path(workspace_root)).as_posix()
        except ValueError:
            pass

    # GitHub Actions runs inside /github/workspace by default; keep a fallback so
    # path-based policy still works even if GITHUB_WORKSPACE is unavailable.
    for marker in ("/github/workspace/", "/github/workspace"):
        combined_posix = combined.as_posix()
        idx = combined_posix.find(marker)
        if idx >= 0:
            rel = combined_posix[idx + len(marker) :]
            return _normalized_rel_path(rel)

    return raw_file_path


def _match_suppression(cfg: dict[str, Any], finding: dict[str, Any]) -> dict[str, str] | None:
    """Return the first active suppression that matches the finding."""
    suppressions = cfg.get("suppressions", [])
    if not isinstance(suppressions, list):
        return None
    check_id = str(finding.get("source_rule_id", "")).upper()
    entity = str(finding.get("resource_type", ""))
    name = str(finding.get("resource_name", ""))
    resource_key = f"{entity}.{name}".rstrip(".")
    file_path = _workspace_relative_policy_path(finding)
    for i, s in enumerate(suppressions):
        if not isinstance(s, dict):
            continue
        if s.get("check_id") and str(s.get("check_id")).upper() != check_id:
            continue
        if s.get("entity") and str(s.get("entity")) != entity:
            continue
        if s.get("resource") and str(s.get("resource")) != resource_key:
            continue
        if s.get("path") and not fnmatch(file_path, str(s.get("path"))):
            continue
        expiry = str(s.get("expiry") or s.get("until") or "")
        if not _expiry_active(expiry or None):
            continue
        mode = str(s.get("mode", "ignore"))
        return {
            "auto_fix_mode": "ignore" if mode == "ignore" else "suggest_only",
            "decision_mode": "ignore" if mode == "ignore" else "soft_fail",
            "suppression_reason": str(s.get("reason", "")),
            "suppression_expiry": expiry,
            "matched_policy_source": f"suppressions[{i}]",
        }
    return None


def scan_policy_decision(policy: Policy, finding: dict[str, Any]) -> dict[str, Any]:
    """Decide whether a finding should be visible to later stages at all."""
    cfg = policy.scan_policy if isinstance(policy.scan_policy, dict) else {}
    check_id = str(finding.get("source_rule_id", "")).upper()
    family = finding_family_name(finding)
    include_ids = _coerce_upper_set(cfg.get("include_ids", []))
    skip_ids = _coerce_upper_set(cfg.get("skip_ids", []))

    if include_ids and check_id not in include_ids:
        return {
            "include": False,
            "reason": "not_in_include_ids",
            "family": family,
            "matched_policy_source": "scan_policy.include_ids",
        }
    if check_id in skip_ids:
        return {
            "include": False,
            "reason": "skip_id",
            "family": family,
            "matched_policy_source": "scan_policy.skip_ids",
        }
    return {
        "include": True,
        "reason": "included",
        "family": family,
        "matched_policy_source": "scan_policy.default",
    }


def finding_policy_decision(policy: Policy, finding: dict[str, Any]) -> dict[str, str]:
    """Resolve the effective remediation and gating mode for a single finding."""
    source_rule_id = str(finding.get("source_rule_id", "")).strip().upper()
    resource_type = str(finding.get("resource_type", "")).strip()
    resource_name = str(finding.get("resource_name", "")).strip()
    file_path = _workspace_relative_policy_path(finding)
    sanara_rule_id = str(finding.get("sanara_rule_id", "")).strip()
    classification = classify_checkov_finding(source_rule_id, resource_type)
    cfg = policy.finding_policy if isinstance(policy.finding_policy, dict) else {}
    by_check = cfg.get("by_check_id", {}) if isinstance(cfg.get("by_check_id", {}), dict) else {}
    by_family = cfg.get("by_family", {}) if isinstance(cfg.get("by_family", {}), dict) else {}
    by_entity = cfg.get("by_entity", {}) if isinstance(cfg.get("by_entity", {}), dict) else {}
    by_resource = cfg.get("by_resource", {}) if isinstance(cfg.get("by_resource", {}), dict) else {}
    by_check_entity = (
        cfg.get("by_check_id_entity", {})
        if isinstance(cfg.get("by_check_id_entity", {}), dict)
        else {}
    )
    by_path = cfg.get("by_path", []) if isinstance(cfg.get("by_path", []), list) else []
    overrides = (
        by_check.get(source_rule_id, {})
        if isinstance(by_check.get(source_rule_id, {}), dict)
        else {}
    )
    ignore = _coerce_upper_set(cfg.get("ignore", []))
    suggest_only = _coerce_upper_set(cfg.get("suggest_only", []))
    auto_fix_allow = _coerce_upper_set(cfg.get("auto_fix_allow", []))
    auto_fix_deny = _coerce_upper_set(cfg.get("auto_fix_deny", []))
    hard_fail_on = _coerce_upper_set(cfg.get("hard_fail_on", []))
    soft_fail_on = _coerce_upper_set(cfg.get("soft_fail_on", []))

    mode = str(overrides.get("auto_fix_mode", classification["default_mode"]))
    category = str(overrides.get("category", classification["category"]))
    matched_source = "default"
    if overrides:
        matched_source = "by_check_id"

    # Precedence moves from broad policy buckets to increasingly specific selectors.
    # Later matches intentionally override earlier defaults so operators can carve
    # out exceptions without rewriting the whole policy tree.
    family = _sanara_family(sanara_rule_id)
    fam_over = by_family.get(family)
    if isinstance(fam_over, dict):
        mode = str(fam_over.get("auto_fix_mode", mode))
        category = str(fam_over.get("category", category))
        matched_source = f"by_family:{family}"
    ent_over = by_entity.get(resource_type)
    if isinstance(ent_over, dict):
        mode = str(ent_over.get("auto_fix_mode", mode))
        category = str(ent_over.get("category", category))
        matched_source = f"by_entity:{resource_type}"
    resource_key = f"{resource_type}.{resource_name}".rstrip(".")
    res_over = by_resource.get(resource_key)
    if isinstance(res_over, dict):
        mode = str(res_over.get("auto_fix_mode", mode))
        category = str(res_over.get("category", category))
        matched_source = f"by_resource:{resource_key}"
    ce_over = by_check_entity.get(source_rule_id)
    if isinstance(ce_over, dict):
        eov = ce_over.get(resource_type)
        if isinstance(eov, dict):
            mode = str(eov.get("auto_fix_mode", mode))
            category = str(eov.get("category", category))
            matched_source = f"by_check_id_entity:{source_rule_id}:{resource_type}"
    if source_rule_id in ignore:
        mode = "ignore"
    elif source_rule_id in suggest_only:
        mode = "suggest_only"
    elif source_rule_id in auto_fix_allow:
        mode = "auto_fix_safe"
    elif source_rule_id in auto_fix_deny and mode.startswith("auto_fix"):
        mode = "suggest_only"

    # Path rules are the last normal override so operators can carve out
    # directories such as examples/** even when a rule is globally allowed.
    for idx, item in enumerate(by_path):
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("path", ""))
        if pattern and file_path and fnmatch(file_path, pattern):
            mode = str(item.get("auto_fix_mode", mode))
            category = str(item.get("category", category))
            matched_source = f"by_path[{idx}]"

    # Decision mode follows the final auto-fix mode unless the policy forces an
    # explicit pass/fail posture for this scanner rule.
    if source_rule_id in hard_fail_on:
        decision_mode = "hard_fail"
    elif source_rule_id in soft_fail_on:
        decision_mode = "soft_fail"
    elif mode == "ignore":
        decision_mode = "ignore"
    elif mode == "suggest_only":
        decision_mode = "soft_fail"
    else:
        decision_mode = "hard_fail"

    out = {
        "category": category,
        "auto_fix_mode": mode,
        "decision_mode": decision_mode,
        "matched_policy_source": matched_source,
    }
    suppression = _match_suppression(cfg, finding)
    if suppression:
        # Suppressions are applied last because they are treated as temporary,
        # operational exceptions over the normal policy precedence chain.
        out.update(suppression)
    return out
