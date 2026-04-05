from __future__ import annotations

import fnmatch
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from sanara.artifacts.bundle import file_sha256
from sanara.agentic.hcl_context import extract_focused_context


@dataclass
class AgenticResult:
    used: bool
    ok: bool
    message: str
    patch_diff: str
    ledger: dict[str, Any]
    trace: list[dict[str, Any]]


SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]+-----|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})"
)


def _is_allowed(path: str, allow_globs: list[str], deny_globs: list[str]) -> bool:
    """Apply allow/deny glob rules with support for `**/` prefixes."""

    def _match(pattern: str) -> bool:
        if fnmatch.fnmatch(path, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
            return True
        return False

    if any(_match(p) for p in deny_globs):
        return False
    if allow_globs:
        return any(_match(p) for p in allow_globs)
    return True


def _redact_text(text: str) -> str:
    """Best-effort secret scrubbing for prompts, traces, and provider errors."""
    return SECRET_RE.sub("***REDACTED***", text)


def _collect_context(
    module_dirs: list[Path], mode: str, allow_globs: list[str], deny_globs: list[str]
) -> list[Path]:
    files: list[Path] = []
    for d in module_dirs:
        if not d.exists():
            continue
        for p in sorted(d.rglob("*.tf")):
            rel = str(p)
            if _is_allowed(rel, allow_globs, deny_globs):
                files.append(p)
        if mode == "minimal":
            break
    return files


_OPENAI_COMPAT_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1/chat/completions",
}


def _select_provider(
    preferred: str,
    anthropic_api_key: str | None,
    openai_api_key: str | None,
) -> tuple[str | None, str]:
    """Resolve the configured LLM provider only when its credentials are present."""
    pref = (preferred or "").strip().lower()
    if pref == "anthropic":
        if anthropic_api_key:
            return "anthropic", "selected anthropic"
        return None, "llm_provider=anthropic but ANTHROPIC_API_KEY is missing"
    if pref == "openai":
        if openai_api_key:
            return "openai", "selected openai"
        return None, "llm_provider=openai but OPENAI_API_KEY is missing"
    return None, "invalid llm_provider (expected one of: anthropic, openai)"


def _call_anthropic(
    api_key: str, model: str, payload_prompt: str, json_mode: bool = False
) -> tuple[bool, str, str, int]:
    """Call Anthropic's messages API and return a normalized success tuple."""
    if json_mode:
        system = (
            "You are a security analysis tool. Respond with valid JSON only, no prose or markdown."
        )
    else:
        system = (
            "You are the LLM remediation component of Sanara, an automated Terraform security "
            "remediation system that runs as a GitHub Action. "
            "Sanara scans infrastructure-as-code with Checkov to find security misconfigurations, "
            "then applies deterministic fixes via its Deterministic Remediation Compiler (DRC) for "
            "well-known patterns. You handle the remaining findings that the DRC could not fix — "
            "cases that require reasoning about the specific resource configuration.\n\n"
            "Your job: given a set of failing Checkov findings and the current Terraform source files, "
            "produce a git unified diff that fixes ONLY those findings. The diff will be applied with "
            "'git apply', then validated with 'terraform init' and 'terraform validate', and finally "
            "re-scanned with Checkov to confirm the findings are cleared. If any step fails, the patch "
            "is rejected.\n\n"
            "Constraints:\n"
            "- The DRC may have already modified some files. Your patch must be additive and compatible "
            "with those changes — do not re-apply or conflict with them.\n"
            "- Your patch must produce syntactically valid HCL that passes terraform validate.\n"
            "- Only modify the files listed in the prompt. Do not touch unrelated resources.\n"
            "- When adding a new companion resource block, append it at the END of the file.\n\n"
            "Output format:\n"
            "- Return ONLY the raw unified diff text, starting with 'diff --git'.\n"
            "- No markdown code fences, no explanations, no prose before or after the diff."
        )
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": 6000,
        "messages": [{"role": "user", "content": payload_prompt}],
    }
    body["system"] = system
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        data=json.dumps(body),
        timeout=60,
    )
    if r.status_code >= 300:
        detail = ""
        try:
            detail = r.text
        except Exception:
            detail = ""
        detail = _redact_text(detail)[:800]
        return False, "", f"anthropic request failed ({r.status_code}): {detail}", r.status_code

    data = r.json()
    content = ""
    for item in data.get("content", []):
        if item.get("type") == "text":
            content += item.get("text", "")
    return True, content, "anthropic response received", r.status_code


def _call_openai_compat(
    api_key: str, model: str, payload_prompt: str, base_url: str, json_mode: bool = False
) -> tuple[bool, str, str, int]:
    """Call an OpenAI-compatible chat-completions endpoint with consistent parsing."""
    provider_name = next(
        (k for k, v in _OPENAI_COMPAT_BASE_URLS.items() if v == base_url), "openai-compat"
    )
    if json_mode:
        system = (
            "You are a security analysis tool. Respond with valid JSON only, no prose or markdown."
        )
    else:
        system = (
            "You are the LLM remediation component of Sanara, an automated Terraform security "
            "remediation system that runs as a GitHub Action. "
            "Sanara scans infrastructure-as-code with Checkov to find security misconfigurations, "
            "then applies deterministic fixes via its Deterministic Remediation Compiler (DRC) for "
            "well-known patterns. You handle the remaining findings that the DRC could not fix — "
            "cases that require reasoning about the specific resource configuration.\n\n"
            "Your job: given a set of failing Checkov findings and the current Terraform source files, "
            "produce a git unified diff that fixes ONLY those findings. The diff will be applied with "
            "'git apply', then validated with 'terraform init' and 'terraform validate', and finally "
            "re-scanned with Checkov to confirm the findings are cleared. If any step fails, the patch "
            "is rejected.\n\n"
            "Constraints:\n"
            "- The DRC may have already modified some files. Your patch must be additive and compatible "
            "with those changes — do not re-apply or conflict with them.\n"
            "- Your patch must produce syntactically valid HCL that passes terraform validate.\n"
            "- Only modify the files listed in the prompt. Do not touch unrelated resources.\n"
            "- When adding a new companion resource block, append it at the END of the file.\n\n"
            "Output format:\n"
            "- Return ONLY the raw unified diff text, starting with 'diff --git'.\n"
            "- No markdown code fences, no explanations, no prose before or after the diff."
        )
    body: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": payload_prompt},
        ],
        "temperature": 0,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    r = requests.post(
        base_url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        },
        data=json.dumps(body),
        timeout=60,
    )
    if r.status_code >= 300:
        detail = ""
        try:
            detail = r.text
        except Exception:
            detail = ""
        detail = _redact_text(detail)[:800]
        return (
            False,
            "",
            f"{provider_name} request failed ({r.status_code}): {detail}",
            r.status_code,
        )

    data = r.json()
    content = ""
    choices = data.get("choices", [])
    if choices:
        msg = choices[0].get("message", {})
        c = msg.get("content", "")
        if isinstance(c, str):
            content = c
        elif isinstance(c, list):
            content = "".join(part.get("text", "") for part in c if isinstance(part, dict))
    return True, content, f"{provider_name} response received", r.status_code


def run_agentic_fallback(
    workspace: Path,
    module_dirs: list[Path],
    prompt: str,
    mode: str = "minimal",
    llm_provider: str = "anthropic",
    anthropic_api_key: str | None = None,
    openai_api_key: str | None = None,
    anthropic_model: str = "claude-opus-4-6",
    openai_model: str = "gpt-5.2",
    allow_globs: list[str] | None = None,
    deny_globs: list[str] | None = None,
    max_chars: int = 120000,
    focus_files: list[str] | None = None,
    focus_resources: list[dict] | None = None,
    json_mode: bool = False,
) -> AgenticResult:
    """Collect bounded Terraform context and send it to the configured LLM provider."""
    provider, provider_message = _select_provider(llm_provider, anthropic_api_key, openai_api_key)
    if not provider:
        return AgenticResult(False, False, provider_message, "", {}, [])

    allow_globs = allow_globs or ["**/*.tf", "**/*.tfvars"]
    deny_globs = deny_globs or ["**/.terraform/**", "**/*.pem", "**/*.key"]
    files: list[Path] = []
    if focus_files:
        seen: set[Path] = set()
        for rel in focus_files:
            rel_norm = rel.strip().lstrip("/").replace("\\", "/")
            p = workspace / rel_norm
            if p in seen or not p.exists() or p.suffix != ".tf":
                continue
            if _is_allowed(rel_norm, allow_globs, deny_globs):
                files.append(p)
                seen.add(p)
    else:
        files = _collect_context(module_dirs, mode, allow_globs, deny_globs)

    sent = []
    total_chars = len(prompt)

    # Always include the exact current target file text in the patch prompt.
    # Focused HCL context is appended as supporting context rather than
    # replacing the file snapshot, which makes git-apply-safe diffs more likely.
    text_parts = []
    for f in files:
        text = _redact_text(f.read_text(encoding="utf-8"))
        next_chunk = f"# FILE {f.relative_to(workspace)}\n{text}"
        if total_chars + len(next_chunk) > max_chars:
            continue
        sent.append(
            {
                "path": str(f.relative_to(workspace)),
                "sha256": file_sha256(f),
                "bytes": len(text.encode()),
            }
        )
        text_parts.append(next_chunk)
        total_chars += len(next_chunk)

    # HCL2-aware context windowing: append only the blocks relevant to the
    # failing findings as supporting context.
    hcl_context = ""
    context_mode = "full"
    if focus_resources:
        hcl_context = extract_focused_context(
            workspace,
            files,
            focus_resources,
            max_chars=max(4000, max_chars - total_chars - 200),
        )
        if hcl_context:
            context_mode = "full_plus_hcl_windowed"
            supporting_chunk = "# SUPPORTING HCL CONTEXT\n" + hcl_context
            if total_chars + len(supporting_chunk) <= max_chars:
                text_parts.append(supporting_chunk)
                total_chars += len(supporting_chunk)

    payload_prompt = prompt + "\n\n" + "\n\n".join(text_parts)

    _model_map = {
        "anthropic": anthropic_model,
        "openai": openai_model,
    }
    model_used = _model_map.get(provider, openai_model)

    trace = [
        {
            "ts": time.time(),
            "event": "request",
            "chars": len(payload_prompt),
            "provider": provider,
            "model": model_used,
        }
    ]

    if provider == "anthropic":
        ok, content, message, status_code = _call_anthropic(
            anthropic_api_key or "", anthropic_model, payload_prompt, json_mode=json_mode
        )
    else:
        base_url = _OPENAI_COMPAT_BASE_URLS.get(provider, _OPENAI_COMPAT_BASE_URLS["openai"])
        api_key = openai_api_key or ""
        ok, content, message, status_code = _call_openai_compat(
            api_key, model_used, payload_prompt, base_url, json_mode=json_mode
        )

    if not ok:
        trace.append(
            {
                "ts": time.time(),
                "event": "error",
                "code": status_code,
                "provider": provider,
                "message": message[:800],
            }
        )
        return AgenticResult(
            used=True,
            ok=False,
            message=message,
            patch_diff="",
            ledger={
                "provider": provider,
                "provider_selection": provider_message,
                "model": model_used,
                "files_sent": sent,
                "mode": mode,
                "context_mode": context_mode,
                "total_chars": len(payload_prompt),
                "rationale": "targeted remediation",
                "allow_globs": allow_globs,
                "deny_globs": deny_globs,
            },
            trace=trace,
        )

    trace.append(
        {
            "ts": time.time(),
            "event": "response",
            "chars": len(content),
            "provider": provider,
            "model": model_used,
        }
    )

    return AgenticResult(
        used=True,
        ok=True,
        message=message,
        patch_diff=content,
        ledger={
            "provider": provider,
            "provider_selection": provider_message,
            "model": model_used,
            "files_sent": sent,
            "mode": mode,
            "context_mode": context_mode,
            "total_chars": len(payload_prompt),
            "rationale": "targeted remediation",
            "allow_globs": allow_globs,
            "deny_globs": deny_globs,
        },
        trace=trace,
    )
