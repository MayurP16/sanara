from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Policy:
    rule_pack_version: str = "v0.1.0-alpha.1"
    environment: str = "default"
    allow_agentic: bool = False
    require_cmk_for: list[str] = field(default_factory=list)
    allow_rules: list[str] = field(default_factory=list)
    deny_paths: list[str] = field(default_factory=lambda: ["**/.terraform/**"])
    allow_paths: list[str] = field(default_factory=lambda: ["**/*.tf", "**/*.tfvars"])
    max_diff_lines: int = 600
    apply_opt_in_rules: list[str] = field(default_factory=list)
    llm_context_mode: str = "minimal"
    llm_provider: str = "anthropic"
    anthropic_model: str = "claude-sonnet-4-6"
    openai_model: str = "gpt-4o-mini"
    max_runtime_seconds: int = 1800
    agentic_max_chars: int = 120000
    agentic_max_attempts: int = 16
    allow_globs: list[str] = field(default_factory=lambda: ["**/*.tf", "**/*.tfvars", "**/*.md"])
    deny_globs: list[str] = field(
        default_factory=lambda: ["**/.terraform/**", "**/*.pem", "**/*.key"]
    )
    plan_required: bool = True
    publish_dry_run: bool = False
    advisor_enabled: bool = True
    advisor_use_llm: bool = False
    advisor_max_findings: int = 5
    advisor_min_severity: str = "moderate"
    scan_policy: dict[str, Any] = field(default_factory=dict)
    finding_policy: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
