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


def _allowed_file_for_raw_path(raw: str, allowed_files: set[str]) -> str:
    if not raw or not allowed_files:
        return ""
    normalized_allowed = {_normalize_rel_path(path) for path in allowed_files if path}
    if raw in normalized_allowed:
        return raw
    basename_matches = [
        candidate
        for candidate in sorted(normalized_allowed)
        if Path(candidate).name == Path(raw).name
    ]
    if len(basename_matches) == 1:
        return basename_matches[0]
    return ""


def _normalize_rel_path(path: str) -> str:
    return str(path or "").strip().lstrip("/").replace("\\", "/")


def _workspace_root(workspace: Path) -> Path:
    return workspace.resolve(strict=False)


def _canonical_workspace_rel_path(path: str, workspace: "Path | None") -> str:
    if workspace is None:
        return _normalize_rel_path(path)
    normalized = _normalize_rel_path(path)
    if not normalized:
        return ""
    root = _workspace_root(workspace)
    abs_path = (root / normalized).resolve(strict=False)
    try:
        return abs_path.relative_to(root).as_posix()
    except ValueError:
        return ""


def _finding_workspace_rel_path(finding: dict[str, Any], workspace: "Path | None") -> str:
    """Return the workspace-relative path for a finding's target file.

    Findings store file_path relative to module_dir (e.g. "/s3.tf" within
    "/github/workspace/terraform/aws").  When workspace is provided, reconstruct
    the full workspace-relative path ("terraform/aws/s3.tf").  Falls back to the
    bare normalised name when workspace is absent or path resolution fails.

    Some checkov versions populate repo_file_path (the full workspace-relative
    path, e.g. "terraform/aws/s3.tf"), which is stored as file_path.  Joining
    that with module_dir doubles the directory segments.  When the module-relative
    path does not exist on disk, fall back to treating file_path as a direct
    workspace-relative path.
    """
    target = finding.get("target", {})
    file_path = _normalize_rel_path(str(target.get("file_path", "")))
    if not file_path.endswith(".tf") or workspace is None:
        return file_path
    module_dir = str(target.get("module_dir", "")).strip()
    if not module_dir:
        return file_path
    ws_root = _workspace_root(workspace)
    try:
        module_abs = Path(module_dir)
        if not module_abs.is_absolute():
            module_abs = workspace / module_abs
        resolved = (module_abs / file_path).resolve(strict=False)
        rel = resolved.relative_to(ws_root).as_posix()
        if (ws_root / rel).exists():
            return rel
        # Some Checkov payloads already carry a nested workspace-relative path in
        # file_path (for example "terraform/aws/s3.tf"). Only use that fallback
        # when it is meaningfully nested; plain basenames such as "main.tf"
        # should continue to resolve relative to module_dir.
        if "/" in file_path:
            direct = (ws_root / file_path).resolve(strict=False)
            try:
                direct_rel = direct.relative_to(ws_root).as_posix()
            except ValueError:
                direct_rel = ""
            if direct_rel and (ws_root / direct_rel).exists():
                return direct_rel
        return rel
    except ValueError:
        pass
    return file_path


def _focus_files_from_findings(
    findings: list[dict[str, Any]], workspace: "Path | None" = None
) -> list[str]:
    out: set[str] = set()
    for finding in findings:
        resolved = _finding_workspace_rel_path(finding, workspace)
        if resolved.endswith(".tf"):
            out.add(resolved)
    return sorted(out)


def _changed_files_from_diff(
    diff_text: str,
    *,
    workspace: "Path | None" = None,
    allowed_files: "set[str] | None" = None,
) -> list[str]:
    changed: list[str] = []
    for match in re.finditer(r"^diff --git a/(.+?) b/(.+?)$", diff_text, flags=re.MULTILINE):
        raw = _normalize_rel_path(match.group(2))
        normalized = _canonical_workspace_rel_path(raw, workspace)
        if normalized:
            changed.append(normalized)
            continue
        candidate = _allowed_file_for_raw_path(raw, allowed_files or set())
        if candidate:
            changed.append(candidate)
            continue
        changed.append(raw)
    return changed


def _patch_touches_only_allowed(
    diff_text: str,
    allowed_files: set[str],
    workspace: "Path | None" = None,
) -> bool:
    changed = set(
        _changed_files_from_diff(diff_text, workspace=workspace, allowed_files=allowed_files)
    )
    if not changed:
        return False
    return changed.issubset(allowed_files)


def _rewrite_diff_paths(diff_text: str, replacements: dict[str, str]) -> str:
    if not replacements:
        return diff_text
    out: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git a/"):
            match = re.match(r"^diff --git a/(.+?) b/(.+?)$", line)
            if match:
                a_path = replacements.get(_normalize_rel_path(match.group(1)), match.group(1))
                b_path = replacements.get(_normalize_rel_path(match.group(2)), match.group(2))
                out.append(f"diff --git a/{a_path} b/{b_path}")
                continue
        if line.startswith("--- a/"):
            path = _normalize_rel_path(line[6:])
            out.append(f"--- a/{replacements.get(path, path)}")
            continue
        if line.startswith("+++ b/"):
            path = _normalize_rel_path(line[6:])
            out.append(f"+++ b/{replacements.get(path, path)}")
            continue
        out.append(line)
    return "\n".join(out) + ("\n" if diff_text.endswith("\n") else "")


def _canonicalize_patch_paths(
    patch: str,
    *,
    workspace: "Path | None" = None,
    allowed_files: "set[str] | None" = None,
) -> tuple[str, str]:
    if not patch.startswith("diff --git"):
        return patch, ""
    allowed_files = allowed_files or set()
    raw_paths = _changed_files_from_diff(patch)
    if not raw_paths:
        return patch, ""
    replacements: dict[str, str] = {}
    for raw in raw_paths:
        canonical = _canonical_workspace_rel_path(raw, workspace)
        if canonical:
            replacements[raw] = canonical
            continue
        target = _allowed_file_for_raw_path(raw, allowed_files)
        if target:
            replacements[raw] = target
            continue
        return patch, f"path '{raw}' escapes workspace or is not canonical"
    rewritten = _rewrite_diff_paths(patch, replacements)
    if rewritten != patch:
        return rewritten, "rewrote diff paths to workspace-relative target paths"
    return patch, ""


def _validate_patch_structure(patch: str) -> tuple[bool, str]:
    if not patch.startswith("diff --git "):
        return False, "patch is not a unified diff"
    lines = patch.splitlines()
    if not lines:
        return False, "patch is empty"
    in_hunk = False
    saw_diff = False
    for line in lines:
        if line.startswith("diff --git "):
            saw_diff = True
            in_hunk = False
            continue
        if not saw_diff:
            return False, "patch is not a unified diff"
        if line.startswith("@@"):
            in_hunk = True
            continue
        if in_hunk:
            if line.startswith((" ", "+", "-", "\\ No newline at end of file")):
                continue
            return False, f"patch contains non-diff content inside hunk: {line[:120]}"
        if line.startswith(
            (
                "--- ",
                "+++ ",
                "index ",
                "new file mode ",
                "deleted file mode ",
                "old mode ",
                "new mode ",
                "similarity index ",
                "rename from ",
                "rename to ",
                "Binary files ",
            )
        ):
            continue
        return False, f"patch contains non-diff content: {line[:120]}"
    return True, "ok"


def _patch_has_real_file_anchor(
    patch: str,
    *,
    workspace: "Path | None" = None,
    allowed_files: "set[str] | None" = None,
) -> bool:
    if workspace is None:
        return True

    file_anchors: dict[str, list[str]] = {}
    current_file = ""
    in_hunk = False
    saw_any_anchor = False

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current_file = ""
            in_hunk = False
            match = re.match(r"^diff --git a/(.+?) b/(.+?)$", line)
            if match:
                raw = _normalize_rel_path(match.group(2))
                current_file = (
                    _canonical_workspace_rel_path(raw, workspace)
                    or _allowed_file_for_raw_path(raw, allowed_files or set())
                    or raw
                )
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk or not current_file:
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith(" "):
            file_anchors.setdefault(current_file, []).append(line[1:])
            saw_any_anchor = True
            continue
        if line.startswith("-") and not line.startswith("--- "):
            file_anchors.setdefault(current_file, []).append(line[1:])
            saw_any_anchor = True
            continue
        if line.startswith("diff --git "):
            in_hunk = False

    if not saw_any_anchor:
        return True

    root = _workspace_root(workspace)
    for rel_path, anchors in file_anchors.items():
        try:
            content = (root / rel_path).read_text(encoding="utf-8")
        except OSError:
            return False
        if any(anchor in content for anchor in anchors if anchor):
            return True
    return False


def _finding_key(f: dict[str, Any]) -> tuple[str, str, str, str]:
    t = f.get("target", {})
    rid = f.get("resource_type", "") + "." + f.get("resource_name", "")
    return (f.get("source_rule_id", ""), rid, t.get("file_path", ""), t.get("module_dir", ""))


def _target_file_for_finding(finding: dict[str, Any], workspace: "Path | None" = None) -> str:
    resolved = _finding_workspace_rel_path(finding, workspace)
    return resolved if resolved.endswith(".tf") else ""


def _remaining_brief(remaining: list[dict[str, Any]], workspace: "Path | None" = None) -> str:
    lines: list[str] = []
    for finding in remaining[:20]:
        lines.append(
            "- "
            + f"{finding.get('source_rule_id')} "
            + f"({finding.get('sanara_rule_id')}) in "
            + f"{_target_file_for_finding(finding, workspace)} "
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
    workspace: "Path | None" = None,
) -> tuple[bool, str]:
    ok_structure, structure_reason = _validate_patch_structure(patch)
    if not ok_structure:
        return False, structure_reason
    if allowed_files and not _patch_touches_only_allowed(patch, allowed_files, workspace=workspace):
        touched = sorted(
            set(_changed_files_from_diff(patch, workspace=workspace, allowed_files=allowed_files))
        )
        return (
            False,
            f"patch touched files outside allowlist: touched={touched}, allowed={sorted(allowed_files)}",
        )
    target_file = _target_file_for_finding(finding, workspace)
    if target_file and target_file not in set(
        _changed_files_from_diff(patch, workspace=workspace, allowed_files=allowed_files)
    ):
        return False, f"patch did not modify target file {target_file}"
    if not _patch_has_real_file_anchor(patch, workspace=workspace, allowed_files=allowed_files):
        return False, "patch anchor does not match target file content"
    src = str(finding.get("source_rule_id", ""))
    required = repair_profiles.get(src, {}).get("required_patch_tokens", [])
    if isinstance(required, list):
        for token in [str(x) for x in required]:
            if token and token not in patch:
                return False, f"patch missing required token '{token}' for {src}"
    return True, "ok"


def _filter_diff_to_files(diff: str, files: list[str]) -> str:
    """Return only the diff hunks that touch the given workspace-relative file paths."""
    if not diff or not files:
        return ""
    file_set = set(files)
    out: list[str] = []
    current_block: list[str] = []
    current_file: str | None = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if current_block and current_file in file_set:
                out.extend(current_block)
                out.append("")
            current_block = [line]
            m = re.search(r" b/(.+)$", line)
            current_file = _normalize_rel_path(m.group(1)) if m else None
        else:
            current_block.append(line)
    if current_block and current_file in file_set:
        out.extend(current_block)
    return "\n".join(out)


_DIFF_FEW_SHOT_EXAMPLE = """\
Examples of the exact output format required (a valid unified diff):

Example 1 — modifying an attribute inside an existing resource:
diff --git a/main.tf b/main.tf
--- a/main.tf
+++ b/main.tf
@@ -12,7 +12,7 @@ resource "aws_kms_key" "example" {
   description             = "Example key"
   deletion_window_in_days = 10
-  enable_key_rotation     = false
+  enable_key_rotation     = true
 }

Example 2 — appending a new companion resource block at the END of the file (preferred for new resources):
diff --git a/terraform/aws/s3.tf b/terraform/aws/s3.tf
--- a/terraform/aws/s3.tf
+++ b/terraform/aws/s3.tf
@@ -52,0 +53,10 @@
+
+resource "aws_s3_bucket_versioning" "data" {
+  bucket = aws_s3_bucket.data.id
+
+  versioning_configuration {
+    status = "Enabled"
+  }
+}"""


def _build_agentic_prompt(
    remaining: list[dict[str, Any]],
    allowed_files: list[str],
    repair_profiles: dict[str, dict[str, Any]],
    feedback: str = "",
    workspace: "Path | None" = None,
    drc_diff: str = "",
) -> str:
    lines = [
        "Task: Produce ONLY a raw unified diff that fixes the remaining Terraform findings.",
        "Output requirements:",
        "- Return only patch text beginning with 'diff --git'.",
        "- No markdown, no prose, no explanation.",
        "- Use the exact file paths shown below (workspace-relative, e.g. terraform/aws/s3.tf).",
        "- Edit only these files:",
    ]
    lines.extend([f"  - {p}" for p in allowed_files])
    lines.extend(
        [
            "- When adding a NEW companion resource block, ALWAYS append it at the END of the file",
            "  using @@ -N,0 +N+1,M @@ (zero context lines). Do NOT insert inline.",
            _DIFF_FEW_SHOT_EXAMPLE,
            "Remaining findings to fix:",
            _remaining_brief(remaining, workspace) or "- none",
            "Finding-specific repair requirements:",
        ]
    )
    lines.extend(
        [
            f"- {f.get('source_rule_id')} in {_target_file_for_finding(f, workspace)}: {_profile_recipe(str(f.get('source_rule_id', '')), repair_profiles)}"
            for f in remaining[:20]
        ]
    )
    lines.append("Do not modify unrelated resources or files.")
    if drc_diff.strip():
        filtered = _filter_diff_to_files(drc_diff, allowed_files)
        if filtered.strip():
            lines.extend(
                [
                    "Context: the following changes were already applied to these files by the",
                    "deterministic repair compiler. Your patch must be additive and compatible —",
                    "do not re-apply or conflict with these changes:",
                    filtered[:2000],
                ]
            )
    if feedback.strip():
        lines.extend(["Feedback from previous attempt:", feedback.strip()])
    return "\n".join(lines)
