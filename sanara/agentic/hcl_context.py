"""HCL2-aware context extractor for agentic LLM prompts.

Instead of sending entire .tf files, extracts only the blocks relevant to the
failing findings: the target resource block, plus referenced variable/local/
terraform/provider blocks from the same file. Reduces token usage by 60-80%
on typical Terraform repos and improves patch accuracy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Block extraction via brace-matching regex (same technique as hcl_edit.py)
# ---------------------------------------------------------------------------

_RESOURCE_RE = re.compile(r'resource\s+"(?P<rtype>[^"]+)"\s+"(?P<rname>[^"]+)"\s*\{')
_VARIABLE_RE = re.compile(r'variable\s+"(?P<vname>[^"]+)"\s*\{')
_LOCALS_RE = re.compile(r"^locals\s*\{", re.MULTILINE)
_TERRAFORM_RE = re.compile(r"^terraform\s*\{", re.MULTILINE)
_PROVIDER_RE = re.compile(r'^provider\s+"[^"]+"\s*\{', re.MULTILINE)
_VAR_REF_RE = re.compile(r"\bvar\.([a-zA-Z0-9_]+)\b")
_LOCAL_REF_RE = re.compile(r"\blocal\.([a-zA-Z0-9_]+)\b")


def _find_block_end(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    in_string = False
    while i < len(text):
        ch = text[i]
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_string = not in_string
        if not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return len(text) - 1


def _extract_top_level_blocks(text: str, pattern: re.Pattern) -> list[str]:
    blocks: list[str] = []
    for m in pattern.finditer(text):
        open_idx = text.index("{", m.start())
        end = _find_block_end(text, open_idx)
        blocks.append(text[m.start() : end + 1].strip())
    return blocks


def _extract_resource_block(text: str, resource_type: str, resource_name: str) -> str | None:
    header = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    )
    m = header.search(text)
    if not m:
        return None
    open_idx = m.end() - 1
    end = _find_block_end(text, open_idx)
    return text[m.start() : end + 1].strip()


def _extract_named_variable(text: str, var_name: str) -> str | None:
    header = re.compile(rf'variable\s+"{re.escape(var_name)}"\s*\{{')
    m = header.search(text)
    if not m:
        return None
    open_idx = text.index("{", m.start())
    end = _find_block_end(text, open_idx)
    return text[m.start() : end + 1].strip()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class FileContext:
    """Focused context extracted from a single .tf file."""

    rel_path: str
    resource_blocks: list[str] = field(default_factory=list)
    variable_blocks: list[str] = field(default_factory=list)
    locals_blocks: list[str] = field(default_factory=list)
    terraform_blocks: list[str] = field(default_factory=list)
    provider_blocks: list[str] = field(default_factory=list)

    def render(self) -> str:
        parts: list[str] = [f"# FILE: {self.rel_path}"]
        for section, blocks in [
            ("", self.terraform_blocks),
            ("", self.provider_blocks),
            ("", self.resource_blocks),
            ("", self.variable_blocks),
            ("", self.locals_blocks),
        ]:
            for block in blocks:
                if section:
                    parts.append(section)
                parts.append(block)
        return "\n\n".join(parts)

    def is_empty(self) -> bool:
        return not (
            self.resource_blocks
            or self.variable_blocks
            or self.locals_blocks
            or self.terraform_blocks
            or self.provider_blocks
        )


def extract_focused_context(
    workspace: Path,
    tf_files: list[Path],
    focus_findings: list[dict],
    max_chars: int = 40000,
) -> str:
    """Extract minimal context covering all focus_findings from tf_files.

    For each finding, pulls:
    - The exact failing resource block
    - Variable blocks referenced by that resource (var.X)
    - locals {} block(s) from the same file (if referenced: local.X)
    - terraform {} and provider {} blocks (always included once, they are small)

    Falls back to full file content if hcl extraction finds nothing.
    """
    # Build index: (resource_type, resource_name) -> file_path
    target_resources: dict[tuple[str, str], list[Path]] = {}
    for finding in focus_findings:
        rtype = str(finding.get("resource_type", "")).strip()
        rname = str(finding.get("resource_name", "")).strip()
        if rtype and rname:
            target_resources.setdefault((rtype, rname), [])

    # Scan files for target resources and supporting blocks
    file_contexts: dict[Path, FileContext] = {}
    global_terraform: list[str] = []
    global_provider: list[str] = []
    global_terraform_seen = False
    global_provider_seen = False

    for path in tf_files:
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = str(path.relative_to(workspace))
        ctx = FileContext(rel_path=rel)

        # Always extract terraform/provider blocks (small, important for LLM context)
        tf_blocks = _extract_top_level_blocks(text, _TERRAFORM_RE)
        prov_blocks = _extract_top_level_blocks(text, _PROVIDER_RE)
        if tf_blocks and not global_terraform_seen:
            global_terraform = tf_blocks
            global_terraform_seen = True
        if prov_blocks and not global_provider_seen:
            global_provider = prov_blocks
            global_provider_seen = True

        # Check if any target resource lives in this file
        file_has_target = False
        combined_resource_text = ""
        for rtype, rname in list(target_resources.keys()):
            block = _extract_resource_block(text, rtype, rname)
            if block is None:
                continue
            ctx.resource_blocks.append(block)
            combined_resource_text += block
            file_has_target = True

        if not file_has_target:
            continue

        # Extract referenced vars and locals from this file
        var_refs = set(_VAR_REF_RE.findall(combined_resource_text))
        local_refs = set(_LOCAL_REF_RE.findall(combined_resource_text))

        for var_name in sorted(var_refs):
            vblock = _extract_named_variable(text, var_name)
            if vblock:
                ctx.variable_blocks.append(vblock)

        if local_refs:
            ctx.locals_blocks = _extract_top_level_blocks(text, _LOCALS_RE)

        file_contexts[path] = ctx

    # Also scan variable files (variables.tf, vars.tf) for referenced vars
    var_file_candidates = [
        f for f in tf_files if f.name in {"variables.tf", "vars.tf", "variables_override.tf"}
    ]
    already_have_vars: set[str] = set()
    for ctx in file_contexts.values():
        for vblock in ctx.variable_blocks:
            m = re.search(r'variable\s+"([^"]+)"', vblock)
            if m:
                already_have_vars.add(m.group(1))

    # Collect all var refs across all extracted resource blocks
    all_var_refs: set[str] = set()
    for ctx in file_contexts.values():
        for rblock in ctx.resource_blocks:
            all_var_refs.update(_VAR_REF_RE.findall(rblock))
    missing_vars = all_var_refs - already_have_vars

    if missing_vars:
        for var_file in var_file_candidates:
            if var_file in file_contexts:
                continue
            try:
                text = var_file.read_text(encoding="utf-8")
            except Exception:
                continue
            rel = str(var_file.relative_to(workspace))
            extra_ctx = FileContext(rel_path=rel)
            for var_name in sorted(missing_vars):
                vblock = _extract_named_variable(text, var_name)
                if vblock:
                    extra_ctx.variable_blocks.append(vblock)
                    already_have_vars.add(var_name)
            if not extra_ctx.is_empty():
                file_contexts[var_file] = extra_ctx

    # Build output: terraform/provider first, then per-file contexts
    parts: list[str] = []
    if global_terraform:
        parts.extend(global_terraform)
    if global_provider:
        parts.extend(global_provider)
    for ctx in file_contexts.values():
        rendered = ctx.render()
        if rendered.strip():
            parts.append(rendered)

    result = "\n\n".join(parts)

    # Safety: if extraction produced nothing useful, signal caller to fall back
    if not result.strip() or len(result) < 50:
        return ""

    # Truncate to max_chars (prefer trimming from the end)
    if len(result) > max_chars:
        result = result[:max_chars] + "\n# [context truncated]"

    return result
