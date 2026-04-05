from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sanara.drc.models import DrcError
from sanara.drc.registry import REGISTRY
from sanara.orchestrator.policy import Policy


@dataclass
class Attempt:
    sanara_rule_id: str
    status: str
    code: str
    message: str
    contract: dict[str, Any] | None


def _dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """Identify one remediation attempt target regardless of duplicate scanner rows."""
    target = finding.get("target", {}) if isinstance(finding.get("target"), dict) else {}
    return (
        str(finding.get("sanara_rule_id", "")),
        str(finding.get("resource_type", "")),
        str(finding.get("resource_name", "")),
        str(target.get("file_path", "")),
        str(target.get("module_dir", "")),
    )


def apply_drc(workspace: Path, findings: list[dict[str, Any]], policy: Policy) -> list[Attempt]:
    """Apply registered deterministic remediation transforms to unique actionable findings."""
    attempts: list[Attempt] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for f in findings:
        rule = f["sanara_rule_id"]
        if rule not in REGISTRY:
            continue
        key = _dedupe_key(f)
        if key in seen:
            continue
        seen.add(key)
        transform = REGISTRY[rule]
        target = f.get("target", {})
        try:
            # Resolve module_dir: may be absolute (from scanner) or relative to workspace.
            raw_module_dir = target.get("module_dir", ".")
            module_dir = Path(raw_module_dir)
            if not module_dir.is_absolute():
                module_dir = workspace / module_dir

            # Resolve file_path: scanners emit paths relative to module_dir but may
            # include a leading slash (e.g. "/s3.tf").  Strip it before joining so that
            # Path("/workspace") / "/s3.tf" does not silently resolve to "/s3.tf" (root).
            raw_file_path = target.get("file_path", "main.tf")
            file_path = (
                module_dir / Path(raw_file_path).relative_to("/")
                if Path(raw_file_path).is_absolute()
                else module_dir / raw_file_path
            )

            # Transforms receive the module root and concrete file path so they can
            # make localized edits without having to re-discover repository context.
            result = transform(
                module_dir,
                file_path,
                f.get("resource_type", ""),
                f.get("resource_name", ""),
                policy,
            )
            attempts.append(
                Attempt(
                    sanara_rule_id=rule,
                    status="changed" if result.changed else "no_change",
                    code="OK",
                    message="transform applied",
                    contract=result.contract.to_dict(),
                )
            )
        except DrcError as e:
            attempts.append(
                Attempt(
                    sanara_rule_id=rule,
                    status="failed",
                    code=e.code,
                    message=e.message,
                    contract=None,
                )
            )
    return attempts
