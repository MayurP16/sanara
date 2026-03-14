from __future__ import annotations

import hashlib
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Callable

from sanara.agentic.fallback import run_agentic_fallback
from sanara.orchestrator.models import FindingState
from sanara.orchestrator.policy import Policy
from sanara.orchestrator.repair import (
    _build_agentic_prompt,
    _changed_files_from_diff,
    _extract_unified_diff,
    _finding_key,
    _focus_files_from_findings,
    _patch_quality_ok,
    _target_file_for_finding,
)
from sanara.rails.validator import validate_patch
from sanara.scanners.runners import run_scan_only
from sanara.terraform.harness import run_harness_checks
from sanara.utils.command import run_cmd

_LOG = logging.getLogger(__name__)


def _preview_text(text: str, max_lines: int = 16, max_chars: int = 1200) -> str:
    payload = (text or "").strip()
    if not payload:
        return ""
    lines = payload.splitlines()[:max_lines]
    preview = "\n".join(lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars]
    return preview


@dataclass
class AgenticApplyResult:
    clean: bool
    remaining: list[dict[str, Any]]
    remaining_mapped: list[dict[str, Any]]
    remaining_uncovered: list[dict[str, Any]]
    feedback: str
    final_response: str
    final_patch: str
    agentic_ledgers: list[dict[str, Any]]
    agentic_traces: list[dict[str, Any]]
    diff: str
    final_scan_raw: dict[str, Any] | None


def _git_apply_patch(workspace: Path, patch_text: str) -> tuple[bool, str]:
    apply_result = subprocess.run(
        ["git", "apply", "--recount", "--whitespace=nowarn", "-"],
        cwd=workspace,
        input=patch_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if apply_result.returncode != 0:
        return False, (apply_result.stderr or "").strip()[:400]
    return True, ""


def _snapshot_files(workspace: Path, paths: list[str]) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for rel_path in paths:
        p = workspace / rel_path
        entry: dict[str, Any] = {"exists": p.exists()}
        if p.exists():
            entry["content"] = p.read_text(encoding="utf-8")
        snapshot[rel_path] = entry
    return snapshot


def _restore_snapshot(workspace: Path, snapshot: dict[str, dict[str, Any]]) -> None:
    for rel_path, entry in snapshot.items():
        p = workspace / rel_path
        if entry.get("exists"):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(str(entry.get("content", "")), encoding="utf-8")
        elif p.exists():
            p.unlink()


def run_agentic_apply(
    workspace: Path,
    target_dirs: list[Path],
    mapping: dict[str, str],
    mapped_check_ids: set[str],
    policy: Policy,
    repair_profiles: dict[str, dict[str, Any]],
    clean: bool,
    remaining: list[dict[str, Any]],
    remaining_mapped: list[dict[str, Any]],
    remaining_uncovered: list[dict[str, Any]],
    diff: str,
    build_current_findings_state: Callable[
        [dict[str, Any], dict[str, str], set[str], Path],
        FindingState,
    ],
    write_terraform_logs: Callable[[dict[str, Any], str, str], None],
    max_total_attempts: int = 16,
) -> AgenticApplyResult:
    feedback = ""
    agentic_traces: list[dict[str, Any]] = []
    agentic_ledgers: list[dict[str, Any]] = []
    final_response = ""
    final_patch = ""
    final_scan_raw: dict[str, Any] | None = None
    # Prompts that already failed quality gate or git apply within this run.
    # If the same prompt would be sent again (identical context, same feedback),
    # the LLM would return the same unusable response — skip the API call.
    _failed_prompt_hashes: set[str] = set()

    if not remaining:
        return AgenticApplyResult(
            clean=True,
            remaining=[],
            remaining_mapped=remaining_mapped,
            remaining_uncovered=remaining_uncovered,
            feedback=feedback,
            final_response=final_response,
            final_patch=final_patch,
            agentic_ledgers=agentic_ledgers,
            agentic_traces=agentic_traces,
            diff=diff,
            final_scan_raw=final_scan_raw,
        )

    def _rescan_update() -> tuple[bool, list[dict[str, Any]]]:
        nonlocal clean, remaining, remaining_mapped, remaining_uncovered, final_scan_raw
        # Agentic flow mutates files repeatedly in tight loops; bypass scan cache so
        # post-apply state reflects current workspace contents.
        rescan = run_scan_only(
            workspace, target_dirs, use_cache=False, scan_policy=policy.scan_policy
        )
        final_scan_raw = rescan
        current_state = build_current_findings_state(rescan, mapping, mapped_check_ids, workspace)
        clean = current_state.clean
        remaining = current_state.remaining
        remaining_mapped = current_state.remaining_mapped
        remaining_uncovered = current_state.remaining_uncovered
        _LOG.info(
            "agentic rescan clean=%s remaining_total=%d mapped=%d uncovered=%d",
            clean,
            len(remaining),
            len(remaining_mapped),
            len(remaining_uncovered),
        )
        return clean, remaining

    def _post_apply_validate() -> tuple[bool, str, str]:
        nonlocal diff, feedback
        diff = run_cmd(["git", "diff"], cwd=workspace).stdout
        rails = validate_patch(diff, workspace, policy)
        if not rails.ok:
            feedback = f"rail failed {rails.code}: {rails.message}"
            return False, "rails", rails.message
        fmt = run_cmd(["terraform", "fmt", "-recursive"], cwd=workspace)
        tf_checks = run_harness_checks(
            workspace,
            workspace / ".sanara/harness.yml",
            run_plan=policy.plan_required,
        )
        write_terraform_logs(tf_checks.to_dict(), fmt.stdout, fmt.stderr)
        if (not tf_checks.runs and not policy.plan_required) or tf_checks.ok:
            _rescan_update()
            return True, "", ""
        feedback = "terraform checks failed after apply"
        return False, "terraform_checks", feedback

    total_attempts = 0

    def _attempt_batch(
        findings_batch: list[dict[str, Any]], *, strategy: str, attempt_number: int
    ) -> bool:
        nonlocal total_attempts, feedback, final_response, final_patch
        if total_attempts >= max_total_attempts:
            feedback = "agentic attempt budget reached"
            return False
        current_keys = {_finding_key(x) for x in remaining}
        active_batch = [f for f in findings_batch if _finding_key(f) in current_keys]
        if not active_batch:
            return False

        finding = active_batch[0]
        allowed_files = set(_focus_files_from_findings(active_batch))
        before_keys = {_finding_key(x) for x in remaining}
        prompt = _build_agentic_prompt(
            active_batch, sorted(allowed_files), repair_profiles, feedback
        )
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        if prompt_hash in _failed_prompt_hashes:
            _LOG.info(
                "agentic attempt skipped n=%d strategy=%s reason=cached_failure prompt_hash=%s",
                total_attempts + 1,
                strategy,
                prompt_hash[:12],
            )
            feedback = (
                f"Attempt {attempt_number}: skipped — identical prompt already failed in this run."
            )
            return False
        _LOG.info(
            "agentic attempt start n=%d strategy=%s group_size=%d finding=%s",
            total_attempts + 1,
            strategy,
            len(active_batch),
            finding.get("source_rule_id"),
        )
        agentic = run_agentic_fallback(
            workspace,
            target_dirs,
            prompt,
            mode=policy.llm_context_mode,
            llm_provider=policy.llm_provider,
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            anthropic_model=policy.anthropic_model,
            openai_model=policy.openai_model,
            allow_globs=policy.allow_globs,
            deny_globs=policy.deny_globs,
            max_chars=policy.agentic_max_chars,
            focus_files=sorted(allowed_files),
            focus_resources=active_batch,
        )
        total_attempts += 1
        final_response = agentic.patch_diff
        final_patch = _extract_unified_diff(agentic.patch_diff)
        changed_files = _changed_files_from_diff(final_patch)
        target_file = _target_file_for_finding(finding)
        agentic_ledgers.append(
            {
                "attempt": total_attempts,
                "ok": agentic.ok,
                "message": agentic.message,
                "ledger": agentic.ledger,
                "finding": finding,
                "strategy": strategy,
                "provider": policy.llm_provider,
                "group_size": len(active_batch),
                "accepted_patch": False,
                "rejection_stage": "",
                "rejection_reason": "",
                "progressed": False,
                "remaining_before": len(before_keys),
                "remaining_after": len(before_keys),
                "changed_files": changed_files,
                "allowed_files": sorted(allowed_files),
                "target_file": target_file,
                "target_file_exists_before": bool(
                    target_file and (workspace / target_file).exists()
                ),
                "changed_file_exists_before": {
                    path: bool((workspace / path).exists()) for path in changed_files
                },
                "prompt_hash": prompt_hash,
                "response_preview": _preview_text(agentic.patch_diff),
                "extracted_patch_preview": _preview_text(final_patch),
                "patch_line_count": len(final_patch.splitlines()) if final_patch else 0,
            }
        )
        ledger_entry = agentic_ledgers[-1]
        agentic_traces.extend(
            [
                {
                    "attempt": attempt_number,
                    "finding": finding.get("source_rule_id"),
                    "strategy": strategy,
                    **t,
                }
                for t in agentic.trace
            ]
        )

        if not agentic.ok:
            feedback = f"Attempt {attempt_number}: provider call failed: {agentic.message}"
            ledger_entry["rejection_stage"] = "provider_call"
            ledger_entry["rejection_reason"] = str(agentic.message)
            _LOG.info(
                "agentic attempt result n=%d accepted=false reason=provider_call_failed",
                total_attempts,
            )
            return False
        ok_quality, reason = _patch_quality_ok(final_patch, finding, allowed_files, repair_profiles)
        if not ok_quality:
            feedback = f"Attempt {attempt_number}: quality gate failed: {reason}"
            ledger_entry["rejection_stage"] = "quality_gate"
            ledger_entry["rejection_reason"] = reason
            _failed_prompt_hashes.add(prompt_hash)
            _LOG.info(
                "agentic attempt result n=%d accepted=false reason=quality_gate", total_attempts
            )
            return False
        snapshot_paths = sorted({*changed_files, *([target_file] if target_file else [])})
        pre_apply_snapshot = _snapshot_files(workspace, snapshot_paths)
        applied, apply_err = _git_apply_patch(workspace, final_patch)
        if not applied:
            feedback = f"Attempt {attempt_number}: git apply failed: {apply_err}"
            ledger_entry["rejection_stage"] = "git_apply"
            ledger_entry["rejection_reason"] = apply_err
            _failed_prompt_hashes.add(prompt_hash)
            _LOG.info("agentic attempt result n=%d accepted=false reason=git_apply", total_attempts)
            return False
        validated, failed_stage, failed_reason = _post_apply_validate()
        if not validated:
            _restore_snapshot(workspace, pre_apply_snapshot)
            _rescan_update()
            ledger_entry["rejection_stage"] = failed_stage or "post_apply_validate"
            ledger_entry["rejection_reason"] = failed_reason or feedback
            _LOG.info(
                "agentic attempt result n=%d accepted=false progressed=false reason=%s",
                total_attempts,
                (failed_stage or "post_apply_validate"),
            )
            return False
        after_keys = {_finding_key(x) for x in remaining}
        progressed = len(after_keys) < len(before_keys)
        if not progressed:
            feedback = f"Attempt {attempt_number}: finding still present after apply."
            _restore_snapshot(workspace, pre_apply_snapshot)
            _rescan_update()
            ledger_entry["rejection_stage"] = "no_progress"
            ledger_entry["rejection_reason"] = "finding still present after apply"
            after_keys = {_finding_key(x) for x in remaining}
        else:
            ledger_entry["accepted_patch"] = True
        ledger_entry["progressed"] = progressed
        ledger_entry["remaining_after"] = len(after_keys)
        _LOG.info(
            "agentic attempt result n=%d accepted=%s progressed=%s remaining_before=%d remaining_after=%d",
            total_attempts,
            ledger_entry["accepted_patch"],
            progressed,
            len(before_keys),
            len(after_keys),
        )
        return progressed

    for finding in list(remaining):
        if clean or total_attempts >= max_total_attempts:
            break
        _attempt_batch([finding], strategy="per_finding", attempt_number=1)

    if total_attempts >= max_total_attempts:
        feedback = "agentic attempt budget reached"
    _LOG.info(
        "agentic finish clean=%s total_attempts=%d remaining_total=%d feedback=%s",
        clean,
        total_attempts,
        len(remaining),
        (feedback or "").strip()[:200],
    )

    return AgenticApplyResult(
        clean=clean,
        remaining=remaining,
        remaining_mapped=remaining_mapped,
        remaining_uncovered=remaining_uncovered,
        feedback=feedback,
        final_response=final_response,
        final_patch=final_patch,
        agentic_ledgers=agentic_ledgers,
        agentic_traces=agentic_traces,
        diff=diff,
        final_scan_raw=final_scan_raw,
    )
