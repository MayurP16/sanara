from __future__ import annotations

import json
import logging
import os
import re
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sanara.agentic.fallback import run_agentic_fallback

_LOG = logging.getLogger(__name__)


@dataclass
class AdvisorResult:
    findings: list[dict[str, Any]]
    llm_used: bool
    llm_ok: bool
    llm_message: str
    llm_raw: str


def _changed_tf_files_from_diff(diff_text: str) -> list[str]:
    """Extract changed Terraform files from a unified git diff."""
    files: list[str] = []
    for match in re.finditer(r"^diff --git a/(.+?) b/(.+?)$", diff_text, flags=re.MULTILINE):
        rel = str(match.group(2)).strip().lstrip("/").replace("\\", "/")
        if rel.endswith(".tf"):
            files.append(rel)
    return sorted(set(files))


def _collect_tf_files(workspace: Path, diff_text: str) -> list[Path]:
    # Prefer changed files so the LLM sees the narrowest possible context, but
    # fall back to root-level Terraform files when the diff does not identify any.
    changed = _changed_tf_files_from_diff(diff_text)
    if changed:
        out: list[Path] = []
        for rel in changed:
            p = workspace / rel
            if p.exists():
                out.append(p)
        if out:
            return sorted(out)
    return sorted(workspace.glob("*.tf"))


def _extract_json_payload(text: str) -> str:
    """Accept plain JSON or fenced JSON blocks from provider responses."""
    payload = (text or "").strip()
    if not payload:
        return ""
    if payload.startswith("[") or payload.startswith("{"):
        return payload
    fenced = re.findall(r"```(?:json)?\s*\n(.*?)```", payload, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced[0].strip()
    return ""


def _normalize_llm_findings(items: Any) -> list[dict[str, Any]]:
    """Coerce provider output into the advisor schema and severity vocabulary."""
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        sev_raw = str(item.get("severity", "")).strip().lower()
        if sev_raw in {"critical", "high"}:
            severity = "critical"
        elif sev_raw in {"moderate", "medium"}:
            severity = "moderate"
        else:
            continue
        out.append(
            {
                "id": str(item.get("id", "")).strip() or f"SANARA_ADV_LLM_{idx+1}",
                "severity": severity,
                "confidence": float(item.get("confidence", 0.55)),
                "signal_type": "llm_inference",
                "title": str(item.get("title", "")).strip() or "Additional risk signal",
                "description": str(item.get("description", "")).strip(),
                "file_path": str(item.get("file_path", "")).strip(),
                "resource_type": str(item.get("resource_type", "")).strip(),
                "resource_name": str(item.get("resource_name", "")).strip(),
                "recommendation": str(item.get("recommendation", "")).strip(),
                "related_scanner_rule_ids": [
                    str(x).strip().upper()
                    for x in (item.get("related_scanner_rule_ids") or [])
                    if str(x).strip()
                ],
                "source": "llm",
            }
        )
    return out


def _severity_rank(value: str) -> int:
    sev = str(value or "").strip().lower()
    if sev == "critical":
        return 2
    if sev in {"moderate", "medium"}:
        return 1
    return 0


def _canonical_topic(item: dict[str, Any]) -> str:
    # Topic signatures let the advisor collapse near-duplicate suggestions that
    # are worded differently but point to the same underlying issue.
    text = " ".join(
        [
            str(item.get("title", "")),
            str(item.get("description", "")),
            str(item.get("recommendation", "")),
        ]
    ).lower()
    tokens = re.findall(r"[a-z0-9_]+", text)
    stop = {
        "the",
        "a",
        "an",
        "is",
        "are",
        "to",
        "for",
        "of",
        "and",
        "or",
        "with",
        "all",
        "set",
        "add",
        "enable",
        "enabled",
        "not",
        "fully",
        "missing",
        "configuration",
    }
    filtered = [t for t in tokens if t not in stop and len(t) > 2]
    if not filtered:
        return str(item.get("id", "")).strip().lower() or "generic"
    uniq = sorted(set(filtered))
    return "|".join(uniq[:12])


def _topic_overlap(topic_a: str, topic_b: str) -> float:
    a = {t for t in topic_a.split("|") if t}
    b = {t for t in topic_b.split("|") if t}
    if not a or not b:
        return 0.0
    return len(a.intersection(b)) / float(max(len(a), len(b)))


def _scanner_index(findings: list[dict[str, Any]] | None) -> tuple[set[str], list[dict[str, str]]]:
    """Build a compact, deduplicated scanner view for overlap checks and prompting."""
    ids: set[str] = set()
    compact: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings or []:
        rid = str(finding.get("source_rule_id", "")).strip().upper()
        if rid:
            ids.add(rid)
        target = finding.get("target", {}) if isinstance(finding.get("target"), dict) else {}
        file_path = (
            str(target.get("file_path", "")).strip() or str(finding.get("file_path", "")).strip()
        )
        row = {
            "source_rule_id": rid,
            "sanara_rule_id": str(finding.get("sanara_rule_id", "")).strip(),
            "file_path": file_path,
            "resource_type": str(finding.get("resource_type", "")).strip(),
            "resource_name": str(finding.get("resource_name", "")).strip(),
        }
        key = (row["source_rule_id"], row["file_path"], row["resource_type"], row["resource_name"])
        if key in seen:
            continue
        seen.add(key)
        compact.append(row)
    compact.sort(
        key=lambda x: (x["source_rule_id"], x["file_path"], x["resource_type"], x["resource_name"])
    )
    return ids, compact


def _norm_path(path: str) -> str:
    return str(path or "").strip().lstrip("/").replace("\\", "/")


def _drop_scanner_overlaps(
    llm_items: list[dict[str, Any]],
    scanner_visible_findings: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Discard LLM findings that point to the same rule/resource pair the scanner already surfaced."""
    _, scanner_rows = _scanner_index(scanner_visible_findings)

    def _resource_key(
        file_path: str, resource_type: str, resource_name: str
    ) -> tuple[str, str, str]:
        return (
            _norm_path(file_path),
            str(resource_type or "").strip(),
            str(resource_name or "").strip(),
        )

    scanner_rule_resource_keys = {
        (
            str(row.get("source_rule_id", "")).strip().upper(),
            _resource_key(
                row.get("file_path", ""),
                row.get("resource_type", ""),
                row.get("resource_name", ""),
            ),
        )
        for row in scanner_rows
        if str(row.get("source_rule_id", "")).strip()
        and str(row.get("resource_type", "")).strip()
        and str(row.get("resource_name", "")).strip()
    }

    out: list[dict[str, Any]] = []
    for item in llm_items:
        file_path = _norm_path(str(item.get("file_path", "")))
        resource_type = str(item.get("resource_type", "")).strip()
        resource_name = str(item.get("resource_name", "")).strip()
        key = _resource_key(file_path, resource_type, resource_name)
        has_precise_resource = bool(resource_type and resource_name)

        related_ids = {
            str(v).strip().upper()
            for v in (item.get("related_scanner_rule_ids") or [])
            if str(v).strip()
        }

        if has_precise_resource and any(
            (rid, key) in scanner_rule_resource_keys for rid in related_ids
        ):
            _LOG.info(
                "advisor drop_overlap id=%s resource=%s/%s related_ids=%s",
                item.get("id", ""),
                resource_type,
                resource_name,
                sorted(related_ids),
            )
            continue

        out.append(item)
    return out


def _enrich_and_filter(
    findings: list[dict[str, Any]], min_severity: str, max_findings: int
) -> list[dict[str, Any]]:
    """Rank and deduplicate advisor findings before they become user-visible artifacts."""
    min_rank = _severity_rank(min_severity)
    grouped: list[dict[str, Any]] = []
    for item in findings:
        if _severity_rank(str(item.get("severity", ""))) < min_rank:
            continue
        confidence = float(item.get("confidence", 0.0) or 0.0)
        topic = _canonical_topic(item)
        file_path = _norm_path(str(item.get("file_path", "")))
        resource_type = str(item.get("resource_type", "")).strip()
        resource_name = str(item.get("resource_name", "")).strip()
        existing_idx = None
        existing = None
        for idx, candidate in enumerate(grouped):
            # Duplicate detection is scoped to the same resource tuple. Topic overlap
            # then decides whether two descriptions are close enough to collapse.
            if (
                _norm_path(str(candidate.get("file_path", ""))) == file_path
                and str(candidate.get("resource_type", "")).strip() == resource_type
                and str(candidate.get("resource_name", "")).strip() == resource_name
            ):
                overlap = _topic_overlap(str(candidate.get("_topic", "")), topic)
                if overlap >= 0.45:
                    existing_idx = idx
                    existing = candidate
                    break
        if existing is not None:
            existing_conf = float(existing.get("confidence", 0.0) or 0.0)
            if confidence <= existing_conf:
                continue
        key_material = "|".join([topic, file_path, resource_type, resource_name])
        enriched = dict(item)
        enriched["_topic"] = topic
        enriched["fingerprint"] = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        if existing_idx is None:
            grouped.append(enriched)
        else:
            grouped[existing_idx] = enriched
    for item in grouped:
        item.pop("_topic", None)
    grouped.sort(
        key=lambda x: (
            -_severity_rank(str(x.get("severity", ""))),
            -float(x.get("confidence", 0.0)),
            str(x.get("id", "")),
        )
    )
    return grouped[: max(1, int(max_findings or 5))]


def _llm_findings(
    workspace: Path,
    tf_files: list[Path],
    policy,
    diff_text: str,
    scanner_visible_findings: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], bool, bool, str, str]:
    """Query the fallback LLM for high-signal concerns outside scanner coverage."""
    _, scanner_compact = _scanner_index(scanner_visible_findings)
    prompt = "\n".join(
        [
            "Task: review Terraform code and return only JSON array of additional security concerns not already covered by scanner findings.",
            "Focus on high-signal, non-noisy, actionable checks.",
            "Return at most 5 items with severity critical|moderate.",
            "Output JSON array only with keys: id, severity, title, description, file_path, resource_type, resource_name, recommendation, related_scanner_rule_ids.",
            "Only populate related_scanner_rule_ids when the finding is the exact same check as an existing scanner finding for that resource — leave it empty for new concerns.",
            "Skip issues that are identical to an existing scanner finding (same rule, same resource). Only return genuinely new signals.",
            "Do not return patch/diff.",
            f"Changed files count: {len(tf_files)}",
            f"Diff length: {len(diff_text)}",
            "Scanner-visible findings (latest run):",
            json.dumps(scanner_compact, sort_keys=True),
        ]
    )
    try:
        result = run_agentic_fallback(
            workspace=workspace,
            module_dirs=[workspace],
            prompt=prompt,
            mode=policy.llm_context_mode,
            llm_provider=policy.llm_provider,
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            anthropic_model=policy.anthropic_model,
            openai_model=policy.openai_model,
            allow_globs=["**/*.tf"],
            deny_globs=["**/.terraform/**"],
            focus_files=[str(p.relative_to(workspace)) for p in tf_files],
            max_chars=min(policy.agentic_max_chars, 60000),
            json_mode=True,
        )
    except Exception as exc:  # pragma: no cover - defensive guard for network/runtime failures
        return [], False, False, f"advisor llm unavailable: {exc}", ""
    used = bool(result.used)
    ok = bool(result.ok)
    msg = str(result.message or "").strip()
    raw = str(result.patch_diff or "")
    if not (used and ok and raw.strip()):
        return [], used, ok, msg, raw
    payload = _extract_json_payload(raw)
    if not payload:
        return [], used, False, "llm returned non-json payload", raw
    try:
        parsed = json.loads(payload)
    except Exception:
        return [], used, False, "llm json parse failed", raw
    findings = _normalize_llm_findings(parsed)
    return findings[:5], used, True, msg or "ok", raw


def run_post_fix_advisor(
    workspace: Path,
    policy,
    diff_text: str,
    *,
    scanner_visible_findings: list[dict[str, Any]] | None = None,
) -> AdvisorResult:
    """Run the optional post-remediation advisor and return normalized findings."""
    if not bool(getattr(policy, "advisor_enabled", True)):
        return AdvisorResult(
            findings=[],
            llm_used=False,
            llm_ok=False,
            llm_message="advisor disabled by policy",
            llm_raw="",
        )
    changed_tf_files = _changed_tf_files_from_diff(diff_text)
    tf_files = _collect_tf_files(workspace, diff_text)
    if bool(getattr(policy, "advisor_use_llm", False)) and changed_tf_files:
        llm_items, llm_used, llm_ok, llm_message, llm_raw = _llm_findings(
            workspace,
            tf_files,
            policy,
            diff_text,
            scanner_visible_findings=scanner_visible_findings,
        )
    elif bool(getattr(policy, "advisor_use_llm", False)) and not changed_tf_files:
        llm_items, llm_used, llm_ok, llm_message, llm_raw = (
            [],
            False,
            False,
            "llm skipped: no .tf changes in patch diff",
            "",
        )
    else:
        llm_items, llm_used, llm_ok, llm_message, llm_raw = (
            [],
            False,
            False,
            "llm disabled by policy",
            "",
        )

    raw_count = len(llm_items)
    llm_items = _drop_scanner_overlaps(llm_items, scanner_visible_findings)
    post_overlap_count = len(llm_items)
    findings = _enrich_and_filter(
        llm_items,
        min_severity=str(getattr(policy, "advisor_min_severity", "moderate")),
        max_findings=int(getattr(policy, "advisor_max_findings", 5)),
    )
    _LOG.info(
        "advisor filter llm_raw=%d post_overlap=%d post_enrich=%d",
        raw_count,
        post_overlap_count,
        len(findings),
    )
    return AdvisorResult(
        findings=findings,
        llm_used=llm_used,
        llm_ok=llm_ok,
        llm_message=llm_message,
        llm_raw=llm_raw,
    )
