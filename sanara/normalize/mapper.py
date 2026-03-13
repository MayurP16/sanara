from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sanara.utils.hashing import sha256_text
from sanara.utils.io import read_json
from sanara.normalize.models import NormalizedFinding


SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
RESOURCE_RE = re.compile(r"^(?P<rtype>[a-zA-Z0-9_]+)\.(?P<rname>[a-zA-Z0-9_\\-]+)$")
DEFAULT_MAPPING_PATH = (
    Path(__file__).resolve().parents[2] / "rules/mappings/checkov_to_sanara.v0.1.json"
)
IMAGE_MAPPING_PATH = Path("/app/rules/mappings/checkov_to_sanara.v0.1.json")


def load_mapping(workspace: Path) -> dict[str, str]:
    """Load rule mappings with workspace overrides taking precedence over packaged defaults."""
    local_path = workspace / "rules/mappings/checkov_to_sanara.v0.1.json"
    if local_path.exists():
        path = local_path
    elif DEFAULT_MAPPING_PATH.exists():
        path = DEFAULT_MAPPING_PATH
    else:
        path = IMAGE_MAPPING_PATH
    data = read_json(path)
    return {str(k): str(v) for k, v in data["mappings"].items()}


def _line_range(item: dict[str, Any]) -> str:
    start = item.get("file_line_range", [0, 0])
    if isinstance(start, list) and len(start) >= 2:
        return f"{start[0]}-{start[1]}"
    return "0-0"


def _fingerprint(
    sanara_rule_id: str,
    source_rule_id: str,
    file_path: str,
    resource_type: str,
    resource_name: str,
    line_range: str,
) -> str:
    # Resource-qualified findings remain stable even when line numbers drift.
    # Line ranges are only used as a fallback for scanner results without a clear resource.
    if resource_type and resource_name:
        raw = f"{sanara_rule_id}|{source_rule_id}|{file_path}|{resource_type}.{resource_name}"
    else:
        raw = f"{sanara_rule_id}|{source_rule_id}|{file_path}|{line_range}"
    return sha256_text(raw)


def _module_dir(file_path: str, file_abs_path: str) -> str:
    if file_abs_path:
        return str(Path(file_abs_path).parent)
    if file_path:
        return str(Path(file_path).parent)
    return "."


def _parse_resource(resource: str) -> tuple[str, str]:
    # Checkov sometimes reports module-style resources with an extra namespace
    # segment, for example `module.bucket.aws_s3_bucket.example`.
    normalized = resource.strip()
    if normalized.count(".") == 2:
        p0, p1, p2 = normalized.split(".")
        normalized = f"{p0}_{p1}.{p2}"
    m = RESOURCE_RE.match(normalized)
    if not m:
        return "", ""
    return m.group("rtype"), m.group("rname")


def normalize_checkov(raw: dict[str, Any], mapping: dict[str, str]) -> list[NormalizedFinding]:
    """Convert raw Checkov reports into the repository's canonical finding model."""
    findings: list[NormalizedFinding] = []
    reports: list[dict[str, Any]] = []
    for report in raw.get("results", []):
        if isinstance(report, list):
            reports.extend(x for x in report if isinstance(x, dict))
        elif isinstance(report, dict):
            reports.append(report)

    for report in reports:
        failed = report.get("results", {}).get("failed_checks", [])
        for item in failed:
            source_rule_id = item.get("check_id", "")
            sanara_rule = mapping.get(source_rule_id)
            if not sanara_rule:
                continue
            file_path = item.get("file_path", "")
            resource_type, resource_name = _parse_resource(item.get("resource", ""))
            lr = _line_range(item)
            fp = _fingerprint(
                sanara_rule, source_rule_id, file_path, resource_type, resource_name, lr
            )
            findings.append(
                NormalizedFinding(
                    schema_id="sanara.finding",
                    schema_version="0.1",
                    sanara_rule_id=sanara_rule,
                    source="checkov",
                    source_rule_id=source_rule_id,
                    severity=SEV_MAP.get(str(item.get("severity", "MEDIUM")).upper(), "medium"),
                    module_dir=_module_dir(file_path, item.get("file_abs_path", "")),
                    file_path=file_path,
                    line_range=lr,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    fingerprint=fp,
                )
            )
    return sorted(findings, key=lambda f: f.sort_key())


def normalize_all(checkov_raw: dict[str, Any], mapping: dict[str, str]) -> list[dict[str, Any]]:
    """Serialize normalized findings into plain dictionaries for artifact output."""
    findings = normalize_checkov(checkov_raw, mapping)
    return [f.to_dict() for f in findings]
