from __future__ import annotations

from typing import Any


def classify_checkov_finding(source_rule_id: str, resource_type: str) -> dict[str, str]:
    """Bucket raw scanner findings into coarse policy categories and default fix modes."""
    rid = str(source_rule_id or "").upper()
    rtype = str(resource_type or "").lower()
    text = f"{rid} {rtype}"
    # These heuristics intentionally favor broad families over perfect accuracy so
    # policy authors get stable defaults even for unmapped or newly added rules.
    if any(k in text for k in ["PUBLIC", "PRINCIPAL", "ACL", "INGRESS", "EXPOSED"]) or rid in {
        "CKV_AWS_70"
    }:
        category = "exposure"
    elif any(k in text for k in ["KMS", "ENCRYPT", "CMK"]):
        category = "data_protection"
    elif any(k in text for k in ["LOG", "TRAIL", "AUDIT", "NOTIFICATION"]):
        category = "observability"
    elif any(k in text for k in ["REPLICATION", "PITR", "BACKUP"]):
        category = "recovery_resilience"
    elif any(k in text for k in ["LIFECYCLE", "ROTATION"]):
        category = "hygiene"
    else:
        category = "architecture_conditional"

    if rid in {"CKV_AWS_144", "CKV2_AWS_61", "CKV2_AWS_62", "CKV2_AWS_65"}:
        mode = "suggest_only"
    elif rid in {"CKV_AWS_18"}:
        mode = "auto_fix_opt_in"
    elif category in {"exposure", "data_protection"}:
        mode = "auto_fix_safe"
    elif category in {"hygiene", "observability"}:
        mode = "auto_fix_opt_in"
    else:
        mode = "suggest_only"
    return {"category": category, "default_mode": mode}


def _coerce_upper_set(values: Any) -> set[str]:
    """Normalize policy lists into case-insensitive membership sets."""
    return {str(x).upper() for x in (values or [])}


def _sanara_family(sanara_rule_id: str) -> str:
    """Collapse a fully qualified Sanara rule into its family prefix."""
    parts = [p for p in str(sanara_rule_id or "").split(".") if p]
    return ".".join(parts[:2]) if len(parts) >= 2 else str(sanara_rule_id or "")


def _provider_family_from_source_rule_id(source_rule_id: str) -> str:
    """Infer the upstream scanner family when the finding has no mapped Sanara rule."""
    rid = str(source_rule_id or "").upper()
    if rid.startswith(("CKV_AWS_", "CKV2_AWS_")):
        return "aws.checkov"
    if rid.startswith(("CKV_AZURE_", "CKV2_AZURE_")):
        return "azure.checkov"
    if rid.startswith(("CKV_GCP_", "CKV2_GCP_")):
        return "gcp.checkov"
    if rid.startswith("CKV_"):
        return "checkov"
    return "unknown"


def finding_family_name(finding: dict[str, Any]) -> str:
    # Prefer Sanara families because they remain stable even if the provider emits
    # multiple source-rule namespaces for the same logical control.
    sanara_rule_id = str(finding.get("sanara_rule_id", "")).strip()
    if sanara_rule_id and not sanara_rule_id.startswith("checkov.unmapped."):
        return _sanara_family(sanara_rule_id)
    return _provider_family_from_source_rule_id(str(finding.get("source_rule_id", "")))
