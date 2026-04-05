from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Callable

from sanara.agentic.fallback import run_agentic_fallback
from sanara.orchestrator.models import FindingState
from sanara.orchestrator.policy import Policy
from sanara.policy.review import apply_decision_policy_to_findings
from sanara.orchestrator.repair import (
    _build_agentic_prompt,
    _canonicalize_patch_paths,
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
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mKHFJsu]|\x1b\][^\x07]*\x07")
_MIN_PROVIDER_ATTEMPT_WINDOW_SECONDS = 75


def _preview_text(text: str, max_lines: int = 16, max_chars: int = 1200) -> str:
    payload = (text or "").strip()
    if not payload:
        return ""
    lines = payload.splitlines()[:max_lines]
    preview = "\n".join(lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars]
    return preview


def _normalized_tf_text(text: str, max_chars: int = 600) -> str:
    return _ANSI_RE.sub("", str(text or "")).strip()[:max_chars]


def _first_tf_failure(tf_checks: dict[str, Any]) -> dict[str, str]:
    for run in tf_checks.get("runs", []):
        init = run.get("init", {})
        if "init" in run and init.get("code", 0) != 0:
            detail = _normalized_tf_text(init.get("stderr", "") or init.get("stdout", ""))
            return {
                "run_name": str(run.get("name", "")),
                "working_dir": str(run.get("working_dir", "")),
                "phase": "init",
                "code": str(init.get("code", "")),
                "detail": detail,
                "signature": f"{run.get('name', '')}|init|{detail}",
            }
        validate = run.get("validate", {})
        if validate.get("code", 0) != 0:
            detail = _normalized_tf_text(validate.get("stderr", "") or validate.get("stdout", ""))
            return {
                "run_name": str(run.get("name", "")),
                "working_dir": str(run.get("working_dir", "")),
                "phase": "validate",
                "code": str(validate.get("code", "")),
                "detail": detail,
                "signature": f"{run.get('name', '')}|validate|{detail}",
            }
        plan = run.get("plan", {})
        if plan.get("code", 0) != 0:
            detail = _normalized_tf_text(plan.get("stderr", "") or plan.get("stdout", ""))
            return {
                "run_name": str(run.get("name", "")),
                "working_dir": str(run.get("working_dir", "")),
                "phase": "plan",
                "code": str(plan.get("code", "")),
                "detail": detail,
                "signature": f"{run.get('name', '')}|plan|{detail}",
            }
    return {}


def _tf_failure_preview(failure: dict[str, str]) -> str:
    if not failure:
        return ""
    detail = str(failure.get("detail", "")).splitlines()
    headline = next((line.strip() for line in detail if line.strip()), "")
    parts = [
        str(failure.get("run_name", "")).strip(),
        str(failure.get("phase", "")).strip(),
        str(failure.get("code", "")).strip(),
        headline[:180],
    ]
    return " | ".join(part for part in parts if part)


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
        ["git", "apply", "--recount", "--whitespace=nowarn", "--ignore-whitespace", "-C1", "-"],
        cwd=workspace,
        input=patch_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if apply_result.returncode == 0:
        return True, ""
    return False, (apply_result.stderr or "").strip()[:400]


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
    baseline_tf_checks: dict[str, Any] | None = None,
    max_total_attempts: int = 16,
    run_deadline_epoch: float | None = None,
) -> AgenticApplyResult:
    feedback = ""
    agentic_traces: list[dict[str, Any]] = []
    agentic_ledgers: list[dict[str, Any]] = []
    final_response = ""
    final_patch = ""
    final_scan_raw: dict[str, Any] | None = None
    # Snapshot of the DRC-only diff before any LLM attempts mutate `diff`.
    # Used as prompt context so the LLM understands what DRC already changed.
    drc_diff = diff
    # Prompts that already failed quality gate or git apply within this run.
    # If the same prompt would be sent again (identical context, same feedback),
    # the LLM would return the same unusable response — skip the API call.
    _failed_prompt_hashes: set[str] = set()
    # Findings whose patches consistently fail git apply, rails, or terraform checks.
    # Block only the specific finding instance so one bad module/resource does not
    # suppress the entire rule family.
    _failed_git_apply_finding_keys: set[tuple[str, str, str, str]] = set()
    _failed_git_apply_path_retry_finding_keys: set[tuple[str, str, str, str]] = set()
    _failed_rail_finding_keys: set[tuple[str, str, str, str]] = set()
    _failed_terraform_finding_keys: set[tuple[str, str, str, str]] = set()
    _failed_no_progress_finding_keys: set[tuple[str, str, str, str]] = set()
    provider_unavailable = False
    runtime_budget_exhausted = False

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
        # _build_current_findings_state does not apply policy decisions, so findings have no
        # policy.decision_mode. Apply policy here to get only blocking findings — this prevents
        # the for-loop from iterating over advisory/informational findings (10-20× the blocking
        # count) after the first failed rescan.
        blocking, _, _ = apply_decision_policy_to_findings(policy, current_state.remaining)
        clean = len(blocking) == 0
        remaining = blocking
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

    baseline_tf_failure = _first_tf_failure(baseline_tf_checks or {})

    def _post_apply_validate(
        ledger_entry: dict[str, Any], llm_patch: str = ""
    ) -> tuple[bool, str, str, bool]:
        nonlocal diff, feedback
        diff = run_cmd(["git", "diff"], cwd=workspace).stdout
        # Validate the LLM's incremental patch only — the DRC diff already passed rails
        # in RAILS_VALIDATE_PATCH. Validating the full accumulated diff causes false
        # positives when DRC's modifications to a resource block combine with the LLM's
        # additions to produce `-resource` lines in the unified diff.
        patch_for_rails = llm_patch if llm_patch else diff
        rails = validate_patch(patch_for_rails, workspace, policy)
        if not rails.ok:
            feedback = f"rail failed {rails.code}: {rails.message}"
            return False, "rails", rails.message, False
        tf_checks = run_harness_checks(
            workspace,
            workspace / ".sanara/harness.yml",
            run_plan=policy.plan_required,
        )
        current_tf_dict = tf_checks.to_dict()
        write_terraform_logs(current_tf_dict, "", "")
        if (not tf_checks.runs and not policy.plan_required) or tf_checks.ok:
            ledger_entry["terraform_gate"] = "passed"
            _rescan_update()
            return True, "", "", True
        current_tf_failure = _first_tf_failure(current_tf_dict)
        ledger_entry["terraform_failure_baseline"] = baseline_tf_failure
        ledger_entry["terraform_failure_current"] = current_tf_failure
        if baseline_tf_failure and current_tf_failure:
            same_failure = baseline_tf_failure.get("signature") == current_tf_failure.get(
                "signature"
            )
            ledger_entry["terraform_gate"] = (
                "baseline_failure_unchanged" if same_failure else "new_or_changed_failure"
            )
            _LOG.info(
                "agentic terraform delta same_failure=%s baseline=%s current=%s",
                same_failure,
                _tf_failure_preview(baseline_tf_failure),
                _tf_failure_preview(current_tf_failure),
            )
            if same_failure:
                _rescan_update()
                return True, "", "", True
        tf_err = current_tf_failure.get("detail", "")
        feedback = (
            f"terraform checks failed: {tf_err}"
            if tf_err
            else "terraform checks failed after apply"
        )
        return False, "terraform_checks", feedback, False

    total_attempts = 0

    def _runtime_budget_reached(*, reserve_provider_window: bool = False) -> bool:
        nonlocal feedback, runtime_budget_exhausted
        if run_deadline_epoch is None:
            return False
        remaining_seconds = run_deadline_epoch - time.time()
        threshold = _MIN_PROVIDER_ATTEMPT_WINDOW_SECONDS if reserve_provider_window else 0
        if remaining_seconds > threshold:
            return False
        runtime_budget_exhausted = True
        feedback = "agentic runtime budget reached"
        return True

    def _attempt_batch(
        findings_batch: list[dict[str, Any]], *, strategy: str, attempt_number: int
    ) -> bool:
        nonlocal total_attempts, feedback, final_response, final_patch, provider_unavailable
        if _runtime_budget_reached(reserve_provider_window=True):
            return False
        if provider_unavailable:
            feedback = "agentic provider unavailable"
            return False
        if total_attempts >= max_total_attempts:
            feedback = "agentic attempt budget reached"
            return False
        current_keys = {_finding_key(x) for x in remaining}
        active_batch = [f for f in findings_batch if _finding_key(f) in current_keys]
        if not active_batch:
            return False

        finding = active_batch[0]
        allowed_files = set(_focus_files_from_findings(active_batch, workspace))
        before_keys = {_finding_key(x) for x in remaining}
        target_file = _target_file_for_finding(finding, workspace)
        target_file_exists = bool(target_file and (workspace / target_file).exists())
        if not allowed_files:
            feedback = (
                f"Attempt {attempt_number}: no target file could be resolved for "
                f"{finding.get('source_rule_id')}."
            )
            _LOG.info(
                "agentic attempt skipped n=%d strategy=%s reason=no_target_file rule=%s file_path=%s module_dir=%s",
                total_attempts + 1,
                strategy,
                finding.get("source_rule_id"),
                finding.get("target", {}).get("file_path", ""),
                finding.get("target", {}).get("module_dir", ""),
            )
            agentic_ledgers.append(
                {
                    "attempt": total_attempts,
                    "ok": False,
                    "message": feedback,
                    "ledger": {},
                    "finding": finding,
                    "strategy": strategy,
                    "provider": policy.llm_provider,
                    "group_size": len(active_batch),
                    "accepted_patch": False,
                    "rejection_stage": "target_resolution",
                    "rejection_reason": "no allowed files resolved for finding",
                    "progressed": False,
                    "remaining_before": len(before_keys),
                    "remaining_after": len(before_keys),
                    "changed_files": [],
                    "allowed_files": [],
                    "target_file": target_file,
                    "target_file_exists_before": target_file_exists,
                    "changed_file_exists_before": {},
                    "prompt_hash": "",
                    "response_preview": "",
                    "extracted_patch_preview": "",
                    "patch_line_count": 0,
                    "path_canonicalization": "",
                    "terraform_gate": "",
                    "terraform_failure_baseline": baseline_tf_failure,
                    "terraform_failure_current": {},
                }
            )
            _failed_no_progress_finding_keys.add(_finding_key(finding))
            return False
        if target_file and not target_file_exists:
            feedback = (
                f"Attempt {attempt_number}: resolved target file '{target_file}' does not exist."
            )
            _LOG.info(
                "agentic attempt skipped n=%d strategy=%s reason=target_file_missing rule=%s target_file=%s",
                total_attempts + 1,
                strategy,
                finding.get("source_rule_id"),
                target_file,
            )
            agentic_ledgers.append(
                {
                    "attempt": total_attempts,
                    "ok": False,
                    "message": feedback,
                    "ledger": {},
                    "finding": finding,
                    "strategy": strategy,
                    "provider": policy.llm_provider,
                    "group_size": len(active_batch),
                    "accepted_patch": False,
                    "rejection_stage": "target_resolution",
                    "rejection_reason": f"resolved target file missing: {target_file}",
                    "progressed": False,
                    "remaining_before": len(before_keys),
                    "remaining_after": len(before_keys),
                    "changed_files": [],
                    "allowed_files": sorted(allowed_files),
                    "target_file": target_file,
                    "target_file_exists_before": target_file_exists,
                    "changed_file_exists_before": {},
                    "prompt_hash": "",
                    "response_preview": "",
                    "extracted_patch_preview": "",
                    "patch_line_count": 0,
                    "path_canonicalization": "",
                    "terraform_gate": "",
                    "terraform_failure_baseline": baseline_tf_failure,
                    "terraform_failure_current": {},
                }
            )
            _failed_no_progress_finding_keys.add(_finding_key(finding))
            return False
        prompt = _build_agentic_prompt(
            active_batch,
            sorted(allowed_files),
            repair_profiles,
            feedback,
            workspace=workspace,
            drc_diff=drc_diff,
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
            total_attempts += 1
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
        final_patch, canonicalize_message = _canonicalize_patch_paths(
            final_patch,
            workspace=workspace,
            allowed_files=allowed_files,
        )
        changed_files = _changed_files_from_diff(
            final_patch,
            workspace=workspace,
            allowed_files=allowed_files,
        )
        _LOG.info(
            "agentic patch extracted n=%d changed_files=%s patch_lines=%d patch_head=%s",
            total_attempts,
            changed_files,
            len(final_patch.splitlines()) if final_patch else 0,
            (final_patch or "")[:120].replace("\n", "\\n"),
        )
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
                "target_file_exists_before": target_file_exists,
                "changed_file_exists_before": {
                    path: bool((workspace / path).exists()) for path in changed_files
                },
                "prompt_hash": prompt_hash,
                "response_preview": _preview_text(agentic.patch_diff),
                "extracted_patch_preview": _preview_text(final_patch),
                "patch_line_count": len(final_patch.splitlines()) if final_patch else 0,
                "path_canonicalization": canonicalize_message,
                "terraform_gate": "",
                "terraform_failure_baseline": baseline_tf_failure,
                "terraform_failure_current": {},
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
            message_lower = str(agentic.message or "").lower()
            if "api_key is missing" in message_lower or "invalid llm_provider" in message_lower:
                provider_unavailable = True
                _LOG.info(
                    "agentic provider unavailable; stopping further attempts message=%s",
                    str(agentic.message)[:200],
                )
            _LOG.info(
                "agentic attempt result n=%d accepted=false reason=provider_call_failed",
                total_attempts,
            )
            return False
        ok_quality, reason = _patch_quality_ok(
            final_patch, finding, allowed_files, repair_profiles, workspace=workspace
        )
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
            rule_id = str(finding.get("source_rule_id", "")).strip()
            finding_key = _finding_key(finding)
            apply_err = (apply_err or "").strip()
            path_related_git_apply = (
                "No such file or directory" in apply_err
                or "does not exist in index" in apply_err
                or "can't open patch" in apply_err
            )
            if path_related_git_apply:
                allowed_list = ", ".join(sorted(allowed_files))
                feedback = (
                    f"Attempt {attempt_number}: git apply failed because the patch used the wrong "
                    f"path. Use exactly one of: {allowed_list}. Error: {apply_err}"
                )
            else:
                feedback = f"Attempt {attempt_number}: git apply failed: {apply_err}"
            ledger_entry["rejection_stage"] = "git_apply"
            ledger_entry["rejection_reason"] = apply_err
            _failed_prompt_hashes.add(prompt_hash)
            if rule_id and (not path_related_git_apply):
                _failed_git_apply_finding_keys.add(finding_key)
            elif rule_id and finding_key in _failed_git_apply_path_retry_finding_keys:
                _failed_git_apply_finding_keys.add(finding_key)
            elif rule_id and path_related_git_apply:
                _failed_git_apply_path_retry_finding_keys.add(finding_key)
            _LOG.info(
                "agentic attempt result n=%d accepted=false reason=git_apply error=%s patch_lines=%d",
                total_attempts,
                apply_err[:200] if apply_err else "",
                len(final_patch.splitlines()) if final_patch else 0,
            )
            return False
        validated, failed_stage, failed_reason, already_rescanned = _post_apply_validate(
            ledger_entry, llm_patch=final_patch
        )
        if not validated:
            _restore_snapshot(workspace, pre_apply_snapshot)
            _rescan_update()
            ledger_entry["rejection_stage"] = failed_stage or "post_apply_validate"
            ledger_entry["rejection_reason"] = failed_reason or feedback
            if failed_stage == "rails":
                rule_id = str(finding.get("source_rule_id", "")).strip()
                if rule_id:
                    _failed_rail_finding_keys.add(_finding_key(finding))
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
            if not already_rescanned:
                _rescan_update()
            ledger_entry["rejection_stage"] = "no_progress"
            ledger_entry["rejection_reason"] = "finding still present after apply"
            _failed_no_progress_finding_keys.add(_finding_key(finding))
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

    while (
        remaining
        and not clean
        and total_attempts < max_total_attempts
        and not provider_unavailable
        and not runtime_budget_exhausted
    ):
        if clean or total_attempts >= max_total_attempts or _runtime_budget_reached():
            break
        finding = None
        rule_id = ""
        for candidate in remaining:
            candidate_rule_id = str(candidate.get("source_rule_id", "")).strip()
            candidate_key = _finding_key(candidate)
            if candidate_rule_id and candidate_key in _failed_git_apply_finding_keys:
                _LOG.info(
                    "agentic attempt skipped n=%d strategy=per_finding reason=git_apply_rule_blocked rule=%s",
                    total_attempts + 1,
                    candidate_rule_id,
                )
                continue
            if candidate_rule_id and candidate_key in _failed_rail_finding_keys:
                _LOG.info(
                    "agentic attempt skipped n=%d strategy=per_finding reason=rail_rule_blocked rule=%s",
                    total_attempts + 1,
                    candidate_rule_id,
                )
                continue
            if candidate_rule_id and candidate_key in _failed_terraform_finding_keys:
                _LOG.info(
                    "agentic attempt skipped n=%d strategy=per_finding reason=terraform_rule_blocked rule=%s",
                    total_attempts + 1,
                    candidate_rule_id,
                )
                continue
            if candidate_rule_id and candidate_key in _failed_no_progress_finding_keys:
                _LOG.info(
                    "agentic attempt skipped n=%d strategy=per_finding reason=no_progress_rule_blocked rule=%s",
                    total_attempts + 1,
                    candidate_rule_id,
                )
                continue
            finding = candidate
            rule_id = candidate_rule_id
            break
        if finding is None:
            break
        ledger_len_before = len(agentic_ledgers)
        _attempt_batch([finding], strategy="per_finding", attempt_number=1)
        # Terraform-check failures carry a specific error message in `feedback`.
        # Give the LLM one retry with that error as context before blocking the rule.
        if (
            len(agentic_ledgers) > ledger_len_before
            and agentic_ledgers[-1].get("rejection_stage") == "terraform_checks"
            and rule_id
            and _finding_key(finding) not in _failed_terraform_finding_keys
            and not clean
            and total_attempts < max_total_attempts
        ):
            _LOG.info(
                "agentic terraform retry n=%d strategy=per_finding rule=%s",
                total_attempts + 1,
                rule_id,
            )
            _attempt_batch([finding], strategy="per_finding", attempt_number=2)
            if (
                len(agentic_ledgers) > ledger_len_before + 1
                and agentic_ledgers[-1].get("rejection_stage") == "terraform_checks"
                and rule_id
            ):
                _failed_terraform_finding_keys.add(_finding_key(finding))

    if provider_unavailable:
        feedback = "agentic provider unavailable"
    elif runtime_budget_exhausted:
        feedback = "agentic runtime budget reached"
    elif total_attempts >= max_total_attempts:
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
