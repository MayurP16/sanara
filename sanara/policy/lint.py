from __future__ import annotations

from typing import Any


def _upper_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        text = str(value).strip().upper()
        if text:
            out.append(text)
    return out


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    dups: set[str] = set()
    for value in values:
        if value in seen:
            dups.add(value)
        seen.add(value)
    return sorted(dups)


def _intersect(a: list[str], b: list[str]) -> list[str]:
    return sorted(set(a).intersection(set(b)))


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _lint_scope(scope: str, cfg: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    scan = cfg.get("scan_policy", {}) if isinstance(cfg.get("scan_policy"), dict) else {}
    finding = cfg.get("finding_policy", {}) if isinstance(cfg.get("finding_policy"), dict) else {}

    include_ids = _upper_list(scan.get("include_ids"))
    skip_ids = _upper_list(scan.get("skip_ids"))
    auto_fix_allow = _upper_list(finding.get("auto_fix_allow"))
    auto_fix_deny = _upper_list(finding.get("auto_fix_deny"))
    suggest_only = _upper_list(finding.get("suggest_only"))
    ignore = _upper_list(finding.get("ignore"))
    hard_fail_on = _upper_list(finding.get("hard_fail_on"))
    soft_fail_on = _upper_list(finding.get("soft_fail_on"))

    for name, values in (
        ("scan_policy.include_ids", include_ids),
        ("scan_policy.skip_ids", skip_ids),
        ("finding_policy.auto_fix_allow", auto_fix_allow),
        ("finding_policy.auto_fix_deny", auto_fix_deny),
        ("finding_policy.suggest_only", suggest_only),
        ("finding_policy.ignore", ignore),
        ("finding_policy.hard_fail_on", hard_fail_on),
        ("finding_policy.soft_fail_on", soft_fail_on),
    ):
        dups = _duplicates(values)
        if dups:
            warnings.append(f"{scope}: duplicate values in {name}: {', '.join(dups)}")

    overlap = _intersect(include_ids, skip_ids)
    if overlap:
        errors.append(f"{scope}: scan_policy include_ids overlaps skip_ids: {', '.join(overlap)}")

    overlap = _intersect(auto_fix_allow, auto_fix_deny)
    if overlap:
        errors.append(
            f"{scope}: finding_policy auto_fix_allow overlaps auto_fix_deny: {', '.join(overlap)}"
        )
    overlap = _intersect(hard_fail_on, soft_fail_on)
    if overlap:
        errors.append(
            f"{scope}: finding_policy hard_fail_on overlaps soft_fail_on: {', '.join(overlap)}"
        )

    for label, values in (
        ("auto_fix_allow", auto_fix_allow),
        ("auto_fix_deny", auto_fix_deny),
        ("suggest_only", suggest_only),
        ("hard_fail_on", hard_fail_on),
        ("soft_fail_on", soft_fail_on),
    ):
        overlap = _intersect(ignore, values)
        if overlap:
            warnings.append(
                f"{scope}: finding_policy ignore overlaps {label}: {', '.join(overlap)}"
            )

    overlap = _intersect(suggest_only, auto_fix_allow)
    if overlap:
        warnings.append(
            f"{scope}: finding_policy suggest_only overlaps auto_fix_allow: {', '.join(overlap)}"
        )
    overlap = _intersect(suggest_only, auto_fix_deny)
    if overlap:
        warnings.append(
            f"{scope}: finding_policy suggest_only overlaps auto_fix_deny: {', '.join(overlap)}"
        )


def lint_policy_config(data: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    scopes_checked: list[str] = []

    if not isinstance(data, dict):
        return {
            "ok": False,
            "errors": ["policy root must be a mapping"],
            "warnings": [],
            "scopes_checked": [],
        }

    _lint_scope("root", data, errors, warnings)
    scopes_checked.append("root")

    envs = data.get("environments")
    if isinstance(envs, dict):
        base = {k: v for k, v in data.items() if k != "environments"}
        for env_name in sorted(envs.keys()):
            env_cfg = envs.get(env_name)
            if not isinstance(env_cfg, dict):
                continue
            merged = _deep_merge(base, env_cfg)
            scope = f"environments.{env_name}"
            _lint_scope(scope, merged, errors, warnings)
            scopes_checked.append(scope)

    return {
        "ok": len(errors) == 0,
        "errors": sorted(errors),
        "warnings": sorted(warnings),
        "scopes_checked": scopes_checked,
    }
