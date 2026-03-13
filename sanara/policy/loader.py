from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sanara.policy.models import Policy
from sanara.policy.validate import validate_policy_config
from sanara.utils.io import read_yaml


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _resolve_environment_name(data: dict[str, Any], action_inputs: dict[str, Any] | None) -> str:
    explicit = None
    if action_inputs:
        explicit = action_inputs.get("environment")
    explicit = explicit or data.get("environment")
    explicit = (
        explicit or os.environ.get("INPUT_ENVIRONMENT") or os.environ.get("SANARA_ENVIRONMENT")
    )
    if explicit:
        return str(explicit)
    ref_name = str(
        os.environ.get("GITHUB_BASE_REF") or os.environ.get("GITHUB_REF_NAME") or ""
    ).lower()
    if ref_name in {"main", "master", "prod", "production"}:
        return "prod"
    if ref_name in {"staging", "stage", "qa"}:
        return "staging"
    if ref_name in {"dev", "develop"}:
        return "dev"
    return "default"


def _apply_environment_overrides(data: dict[str, Any], env_name: str) -> dict[str, Any]:
    envs = data.get("environments")
    if not isinstance(envs, dict):
        return data
    selected = envs.get(env_name)
    if not isinstance(selected, dict):
        return data
    merged = _deep_merge(data, selected)
    merged["environment"] = env_name
    return merged


def load_policy(workspace: Path, action_inputs: dict[str, Any] | None = None) -> Policy:
    path = workspace / ".sanara/policy.yml"
    data = read_yaml(path) if path.exists() else {}
    data = data or {}
    validate_policy_config(data)
    if action_inputs:
        data = {**data, **{k: v for k, v in action_inputs.items() if v is not None}}
    env_name = _resolve_environment_name(data, action_inputs)
    data = _apply_environment_overrides(data, env_name)
    advisor = data.get("advisor", {}) if isinstance(data.get("advisor", {}), dict) else {}
    return Policy(
        rule_pack_version=data.get("rule_pack_version", "v0.1.0-alpha.1"),
        environment=str(env_name or data.get("environment", "default")),
        allow_agentic=bool(data.get("allow_agentic", False)),
        require_cmk_for=list(data.get("require_cmk_for", [])),
        allow_rules=list(data.get("allow_rules", [])),
        deny_paths=list(data.get("deny_paths", ["**/.terraform/**"])),
        allow_paths=list(data.get("allow_paths", ["**/*.tf", "**/*.tfvars"])),
        max_diff_lines=int(data.get("max_diff_lines", 600)),
        apply_opt_in_rules=list(data.get("apply_opt_in_rules", [])),
        llm_context_mode=str(data.get("llm_context_mode", "minimal")),
        llm_provider=str(data.get("llm_provider", "anthropic")),
        anthropic_model=str(data.get("anthropic_model", "claude-sonnet-4-6")),
        openai_model=str(data.get("openai_model", "gpt-4o-mini")),
        max_runtime_seconds=int(data.get("max_runtime_seconds", 1800)),
        agentic_max_chars=int(data.get("agentic_max_chars", 120000)),
        agentic_max_attempts=int(data.get("agentic_max_attempts", 16)),
        allow_globs=list(data.get("allow_globs", ["**/*.tf", "**/*.tfvars", "**/*.md"])),
        deny_globs=list(data.get("deny_globs", ["**/.terraform/**", "**/*.pem", "**/*.key"])),
        plan_required=bool(data.get("plan_required", True)),
        publish_dry_run=bool(data.get("publish_dry_run", False)),
        advisor_enabled=bool(advisor.get("enabled", True)),
        advisor_use_llm=bool(advisor.get("use_llm", False)),
        advisor_max_findings=int(advisor.get("max_findings", 5)),
        advisor_min_severity=str(advisor.get("min_severity", "moderate")),
        scan_policy=dict(data.get("scan_policy", {}) or {}),
        finding_policy=dict(data.get("finding_policy", {}) or {}),
    )
