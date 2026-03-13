from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sanara.normalize.schema_validate import validate_payload, SchemaValidationError


_DEFAULT_SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"
_IMAGE_SCHEMAS_DIR = Path("/app/schemas")
SCHEMAS_DIR = Path(
    os.environ.get(
        "SANARA_SCHEMAS_DIR",
        _DEFAULT_SCHEMAS_DIR if _DEFAULT_SCHEMAS_DIR.exists() else _IMAGE_SCHEMAS_DIR,
    )
)


class PolicyValidationError(RuntimeError):
    pass


_TOP_LEVEL_KEYS = {
    "rule_pack_version",
    "environment",
    "allow_agentic",
    "require_cmk_for",
    "allow_rules",
    "deny_paths",
    "allow_paths",
    "max_diff_lines",
    "apply_opt_in_rules",
    "llm_context_mode",
    "llm_provider",
    "anthropic_model",
    "openai_model",
    "max_runtime_seconds",
    "agentic_max_chars",
    "agentic_max_attempts",
    "allow_globs",
    "deny_globs",
    "plan_required",
    "publish_dry_run",
    "advisor",
    "scan_policy",
    "finding_policy",
    "environment",
    "environments",
}
_ADVISOR_KEYS = {"enabled", "use_llm", "max_findings", "min_severity"}

_SCAN_POLICY_KEYS = {"include_ids", "skip_ids"}
_FINDING_POLICY_KEYS = {
    "auto_fix_allow",
    "auto_fix_deny",
    "suggest_only",
    "ignore",
    "hard_fail_on",
    "soft_fail_on",
}


def _fail_unknown_keys(where: str, data: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data.keys()) - allowed)
    if unknown:
        raise PolicyValidationError(f"unknown keys in {where}: {', '.join(unknown)}")


def _validate_known_keys(data: dict[str, Any]) -> None:
    _fail_unknown_keys("policy root", data, _TOP_LEVEL_KEYS)
    scan = data.get("scan_policy")
    if isinstance(scan, dict):
        _fail_unknown_keys("scan_policy", scan, _SCAN_POLICY_KEYS)
    finding = data.get("finding_policy")
    if isinstance(finding, dict):
        _fail_unknown_keys("finding_policy", finding, _FINDING_POLICY_KEYS)
    advisor = data.get("advisor")
    if isinstance(advisor, dict):
        _fail_unknown_keys("advisor", advisor, _ADVISOR_KEYS)
    envs = data.get("environments")
    if isinstance(envs, dict):
        for env_name, env_cfg in envs.items():
            if not isinstance(env_cfg, dict):
                continue
            _fail_unknown_keys(
                f"environments.{env_name}", env_cfg, _TOP_LEVEL_KEYS - {"environments"}
            )
            scan2 = env_cfg.get("scan_policy")
            if isinstance(scan2, dict):
                _fail_unknown_keys(f"environments.{env_name}.scan_policy", scan2, _SCAN_POLICY_KEYS)
            finding2 = env_cfg.get("finding_policy")
            if isinstance(finding2, dict):
                _fail_unknown_keys(
                    f"environments.{env_name}.finding_policy", finding2, _FINDING_POLICY_KEYS
                )
            advisor2 = env_cfg.get("advisor")
            if isinstance(advisor2, dict):
                _fail_unknown_keys(f"environments.{env_name}.advisor", advisor2, _ADVISOR_KEYS)


def validate_policy_config(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise PolicyValidationError("policy file must be a YAML object (mapping)")
    schema = SCHEMAS_DIR / "sanara.policy_config.v0.1.json"
    try:
        validate_payload(schema, data)
    except SchemaValidationError as exc:
        raise PolicyValidationError(str(exc)) from exc
    _validate_known_keys(data)
