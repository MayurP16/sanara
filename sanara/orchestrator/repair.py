from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

DEFAULT_REPAIR_PROFILES_PATH = (
    Path(__file__).resolve().parents[2] / "rules/repair_profiles/checkov_repair_profiles.v0.1.json"
)
IMAGE_REPAIR_PROFILES_PATH = Path("/app/rules/repair_profiles/checkov_repair_profiles.v0.1.json")


def _extract_unified_diff(text: str) -> str:
    payload = (text or "").strip()
    if not payload:
        return ""
    if payload.startswith("diff --git "):
        return payload + ("\n" if not payload.endswith("\n") else "")

    fence_matches = re.findall(
        r"```(?:diff|patch)?\s*\n(.*?)```", payload, flags=re.DOTALL | re.IGNORECASE
    )
    for block in fence_matches:
        block_text = block.strip()
        idx = block_text.find("diff --git ")
        if idx >= 0:
            candidate = block_text[idx:].strip()
            return candidate + ("\n" if not candidate.endswith("\n") else "")

    idx = payload.find("diff --git ")
    if idx >= 0:
        candidate = payload[idx:].strip()
        return candidate + ("\n" if not candidate.endswith("\n") else "")
    return ""


def _normalize_rel_path(path: str) -> str:
    return str(path or "").strip().lstrip("/").replace("\\", "/")


def _focus_files_from_findings(findings: list[dict[str, Any]]) -> list[str]:
    out: set[str] = set()
    for finding in findings:
        target = finding.get("target", {})
        file_path = _normalize_rel_path(str(target.get("file_path", "")))
        if file_path.endswith(".tf"):
            out.add(file_path)
    return sorted(out)


def _changed_files_from_diff(diff_text: str) -> list[str]:
    changed: list[str] = []
    for match in re.finditer(r"^diff --git a/(.+?) b/(.+?)$", diff_text, flags=re.MULTILINE):
        changed.append(_normalize_rel_path(match.group(2)))
    return changed


def _patch_touches_only_allowed(diff_text: str, allowed_files: set[str]) -> bool:
    changed = set(_changed_files_from_diff(diff_text))
    if not changed:
        return False
    return changed.issubset(allowed_files)


def _finding_key(f: dict[str, Any]) -> tuple[str, str, str, str]:
    t = f.get("target", {})
    rid = f.get("resource_type", "") + "." + f.get("resource_name", "")
    return (f.get("source_rule_id", ""), rid, t.get("file_path", ""), t.get("module_dir", ""))


def _target_file_for_finding(finding: dict[str, Any]) -> str:
    return _normalize_rel_path(str(finding.get("target", {}).get("file_path", "")))


def _remaining_brief(remaining: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for finding in remaining[:20]:
        lines.append(
            "- "
            + f"{finding.get('source_rule_id')} "
            + f"({finding.get('sanara_rule_id')}) in "
            + f"{_normalize_rel_path(str(finding.get('target', {}).get('file_path', '')))} "
            + f"on {finding.get('resource_type', '')}.{finding.get('resource_name', '')}"
        )
    return "\n".join(lines)


def _rule_recipe(source_rule_id: str) -> str:
    _ = source_rule_id
    return "Apply the minimal secure change required to clear this exact finding."


def _load_repair_profiles(workspace: Path) -> dict[str, dict[str, Any]]:
    local = workspace / "rules/repair_profiles/checkov_repair_profiles.v0.1.json"
    if local.exists():
        source = local
    elif DEFAULT_REPAIR_PROFILES_PATH.exists():
        source = DEFAULT_REPAIR_PROFILES_PATH
    else:
        source = IMAGE_REPAIR_PROFILES_PATH
    if not source.exists():
        return {}
    data = json.loads(source.read_text(encoding="utf-8"))
    profiles = data.get("profiles", {})
    if isinstance(profiles, dict):
        return {str(k): v for k, v in profiles.items() if isinstance(v, dict)}
    return {}


def _profile_recipe(source_rule_id: str, repair_profiles: dict[str, dict[str, Any]]) -> str:
    profile = repair_profiles.get(source_rule_id, {})
    recipe = str(profile.get("recipe_text", "")).strip()
    if recipe:
        return recipe
    return _rule_recipe(source_rule_id)


def _patch_quality_ok(
    patch: str,
    finding: dict[str, Any],
    allowed_files: set[str],
    repair_profiles: dict[str, dict[str, Any]],
) -> tuple[bool, str]:
    if not patch.startswith("diff --git"):
        return False, "patch is not a unified diff"
    if allowed_files and not _patch_touches_only_allowed(patch, allowed_files):
        touched = sorted(set(_changed_files_from_diff(patch)))
        return (
            False,
            f"patch touched files outside allowlist: touched={touched}, allowed={sorted(allowed_files)}",
        )
    target_file = _target_file_for_finding(finding)
    if target_file and target_file not in set(_changed_files_from_diff(patch)):
        return False, f"patch did not modify target file {target_file}"
    src = str(finding.get("source_rule_id", ""))
    required = repair_profiles.get(src, {}).get("required_patch_tokens", [])
    if isinstance(required, list):
        for token in [str(x) for x in required]:
            if token and token not in patch:
                return False, f"patch missing required token '{token}' for {src}"
    return True, "ok"


_DIFF_FEW_SHOT_EXAMPLE = """\
Example of the exact output format required (a valid unified diff):
diff --git a/main.tf b/main.tf
--- a/main.tf
+++ b/main.tf
@@ -12,7 +12,7 @@ resource "aws_kms_key" "example" {
   description             = "Example key"
   deletion_window_in_days = 10
-  enable_key_rotation     = false
+  enable_key_rotation     = true
 }"""


def _build_agentic_prompt(
    remaining: list[dict[str, Any]],
    allowed_files: list[str],
    repair_profiles: dict[str, dict[str, Any]],
    feedback: str = "",
) -> str:
    lines = [
        "Task: Produce ONLY a raw unified diff that fixes the remaining Terraform findings.",
        "Output requirements:",
        "- Return only patch text beginning with 'diff --git'.",
        "- No markdown, no prose, no explanation.",
        "- Edit only these files:",
    ]
    lines.extend([f"  - {p}" for p in allowed_files])
    lines.extend(
        [
            _DIFF_FEW_SHOT_EXAMPLE,
            "Remaining findings to fix:",
            _remaining_brief(remaining) or "- none",
            "Finding-specific repair requirements:",
        ]
    )
    lines.extend(
        [
            f"- {f.get('source_rule_id')} in {_target_file_for_finding(f)}: {_profile_recipe(str(f.get('source_rule_id', '')), repair_profiles)}"
            for f in remaining[:20]
        ]
    )
    lines.append("Do not modify unrelated resources or files.")
    if feedback.strip():
        lines.extend(["Feedback from previous attempt:", feedback.strip()])
    return "\n".join(lines)
