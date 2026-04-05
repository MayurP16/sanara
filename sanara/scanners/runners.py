from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from sanara.utils.command import run_cmd


CHECKOV_DEFAULT_BIN = "checkov"
SCAN_MAX_WORKERS_DEFAULT = 4
_SCAN_CACHE: dict[tuple[str, str, str, str], Any] = {}
logger = logging.getLogger(__name__)


def _checkov_cli_filters(scan_policy: dict[str, Any] | None) -> list[str]:
    """Translate scan-policy allow/deny lists into Checkov CLI flags."""
    if not isinstance(scan_policy, dict):
        return []
    args: list[str] = []
    include_ids = [
        str(x).upper() for x in (scan_policy.get("include_ids", []) or []) if str(x).strip()
    ]
    skip_ids = [str(x).upper() for x in (scan_policy.get("skip_ids", []) or []) if str(x).strip()]
    if include_ids:
        args.extend(["--check", ",".join(sorted(dict.fromkeys(include_ids)))])
    if skip_ids:
        args.extend(["--skip-check", ",".join(sorted(dict.fromkeys(skip_ids)))])
    return args


def checkov_cli_filter_args(scan_policy: dict[str, Any] | None) -> list[str]:
    """Public helper for observability/debugging of effective Checkov CLI filters."""
    return _checkov_cli_filters(scan_policy)


def _checkov_cmd(target: Path, *, scan_policy: dict[str, Any] | None = None) -> list[str]:
    checkov_bin = (
        os.environ.get("SANARA_CHECKOV_BIN", CHECKOV_DEFAULT_BIN).strip() or CHECKOV_DEFAULT_BIN
    )
    return [
        checkov_bin,
        "-o",
        "json",
        "--quiet",
        *_checkov_cli_filters(scan_policy),
        "-d",
        str(target),
    ]


def _decode_json_output(stdout: str, stderr: str) -> Any:
    try:
        payload = json.loads(stdout)
        if isinstance(payload, (dict, list)):
            return payload
    except Exception:
        pass
    return {"parse_error": True, "raw": stdout, "stderr": stderr}


def _stderr_preview(stderr: str, limit: int = 240) -> str:
    text = (stderr or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _is_expected_nonzero(tool_name: str, code: int, parse_error: bool) -> bool:
    # Checkov exits non-zero when findings are present; treat that as expected when
    # it still returned parseable JSON so action logs stay focused on real failures.
    return tool_name == "checkov" and code == 1 and not parse_error


def _coerce_checkov_payload(payload: Any, *, stderr: str, code: int) -> Any:
    # Normalization keeps downstream stages operating on a predictable shape even
    # when Checkov changes its JSON layout or returns partial output.
    if isinstance(payload, list):
        if all(isinstance(report, dict) for report in payload):
            return payload
        return {
            "results": {"failed_checks": []},
            "parse_error": True,
            "stderr": stderr,
            "code": code,
            "raw_payload": payload,
        }
    results = payload.get("results")
    if isinstance(results, dict):
        failed = results.get("failed_checks")
        if isinstance(failed, list):
            return payload
    return {
        "results": {"failed_checks": []},
        "parse_error": True,
        "stderr": stderr,
        "code": code,
        "raw_payload": payload,
    }


def _target_signature(target: Path) -> str:
    # Signature is used for per-run cache safety: if terraform inputs changed, cache miss is forced.
    entries: list[str] = []
    if target.is_dir():
        for pattern in ("**/*.tf", "**/*.tfvars"):
            for file_path in sorted(target.glob(pattern)):
                if not file_path.is_file():
                    continue
                rel = file_path.relative_to(target)
                st = file_path.stat()
                entries.append(f"{rel}:{st.st_mtime_ns}:{st.st_size}")
    elif target.exists():
        st = target.stat()
        entries.append(f"{target.name}:{st.st_mtime_ns}:{st.st_size}")
    return "|".join(entries)


def _scan_target(
    workspace: Path,
    target: Path,
    *,
    tool_name: str,
    cmd_builder,
    empty_payload: dict[str, Any],
    coerce_payload,
    timeout_seconds: int,
    use_cache: bool = True,
) -> Any:
    """Run one scanner target with caching, timeout handling, and parse hardening."""
    cmd = cmd_builder(target)
    start = time.perf_counter()
    workspace_resolved = str(workspace.resolve())
    signature = _target_signature(target)
    cache_key = (
        tool_name,
        workspace_resolved,
        str(target),
        signature,
        json.dumps(cmd, sort_keys=False),
    )
    cache_enabled = (
        use_cache and os.environ.get("SANARA_SCAN_CACHE_ENABLED", "true").strip().lower() == "true"
    )
    if cache_enabled:
        cached = _SCAN_CACHE.get(cache_key)
        if cached is not None:
            logger.debug(
                "scanner cache hit",
                extra={"tool": tool_name, "target": str(target), "workspace": workspace_resolved},
            )
            return cached

    logger.debug(
        "scanner command start",
        extra={
            "tool": tool_name,
            "target": str(target),
            "workspace": workspace_resolved,
            "cmd": cmd,
            "timeout_seconds": timeout_seconds,
            "cache_enabled": cache_enabled,
        },
    )
    try:
        # Prevent Checkov from reaching back into GitHub during runs. The scanner
        # should operate strictly on local workspace state for deterministic output.
        extra_env = {"CKV_GITHUB_CONFIG_FETCH_DATA": "false"} if tool_name == "checkov" else None
        result = run_cmd(cmd, cwd=workspace, timeout_seconds=timeout_seconds, env=extra_env)
        result_code = result.code
        result_stderr = result.stderr
        if result.stdout.strip():
            payload = _decode_json_output(result.stdout, result.stderr)
            coerced = coerce_payload(payload, stderr=result.stderr, code=result.code)
        else:
            coerced = {**empty_payload, "stderr": result.stderr, "code": result.code}
    except Exception as exc:
        logger.exception(
            "scanner command exception",
            extra={
                "tool": tool_name,
                "target": str(target),
                "workspace": workspace_resolved,
                "cmd": cmd,
                "timeout_seconds": timeout_seconds,
                "error_type": type(exc).__name__,
            },
        )
        coerced = {
            **empty_payload,
            "parse_error": True,
            "code": 98,
            "stderr": str(exc),
            "error_type": type(exc).__name__,
        }
        result_code = 98
        result_stderr = str(exc)

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    if isinstance(coerced, dict):
        parse_error = bool(coerced.get("parse_error"))
        exit_code = int(coerced.get("code", result_code))
        stderr_value = str(coerced.get("stderr", result_stderr))
    else:
        parse_error = False
        exit_code = int(result_code)
        stderr_value = str(result_stderr)
    expected_nonzero = _is_expected_nonzero(tool_name, exit_code, parse_error)
    log_level = (
        logging.WARNING
        if parse_error or (exit_code != 0 and not expected_nonzero)
        else logging.DEBUG
    )
    logger.log(
        log_level,
        "scanner command complete",
        extra={
            "tool": tool_name,
            "target": str(target),
            "workspace": workspace_resolved,
            "code": exit_code,
            "parse_error": parse_error,
            "expected_nonzero": expected_nonzero,
            "elapsed_ms": elapsed_ms,
            "stderr_preview": _stderr_preview(stderr_value),
        },
    )
    if cache_enabled:
        _SCAN_CACHE[cache_key] = coerced
    return coerced


def _scan_with_defaults(
    workspace: Path,
    targets: list[Path],
    tool_name: str,
    cmd_builder,
    empty_payload: dict[str, Any],
    coerce_payload,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Fan out scanner runs while preserving result order by target index."""
    outputs: list[Any] = [{} for _ in targets]
    timeout_seconds = int(os.environ.get("SANARA_SCAN_TIMEOUT_SECONDS", "120"))
    max_workers = int(os.environ.get("SANARA_SCAN_MAX_WORKERS", str(SCAN_MAX_WORKERS_DEFAULT)))
    worker_count = max(1, min(max_workers, len(targets))) if targets else 1
    logger.debug(
        "scanner parallel mode",
        extra={"tool": tool_name, "target_count": len(targets), "worker_count": worker_count},
    )
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                _scan_target,
                workspace,
                target,
                tool_name=tool_name,
                cmd_builder=cmd_builder,
                empty_payload=empty_payload,
                coerce_payload=coerce_payload,
                timeout_seconds=timeout_seconds,
                use_cache=use_cache,
            ): idx
            for idx, target in enumerate(targets)
        }
        for future in as_completed(futures):
            idx = futures[future]
            target = targets[idx]
            try:
                outputs[idx] = future.result()
            except Exception as exc:
                logger.exception(
                    "scanner worker exception",
                    extra={
                        "tool": tool_name,
                        "target": str(target),
                        "index": idx,
                        "error_type": type(exc).__name__,
                    },
                )
                outputs[idx] = {
                    **empty_payload,
                    "parse_error": True,
                    "code": 98,
                    "stderr": str(exc),
                    "error_type": type(exc).__name__,
                }
    response = {"targets": [str(t) for t in targets], "results": outputs}
    logger.debug(
        "scanner batch complete",
        extra={"tool": tool_name, "target_count": len(targets), "mode": "parallel"},
    )
    return response


def _scan_checkov(
    workspace: Path,
    targets: list[Path],
    *,
    use_cache: bool = True,
    scan_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    def checkov_builder(target: Path) -> list[str]:
        return _checkov_cmd(target, scan_policy=scan_policy)

    return _scan_with_defaults(
        workspace,
        targets,
        "checkov",
        checkov_builder,
        {"results": {"failed_checks": []}},
        _coerce_checkov_payload,
        use_cache=use_cache,
    )


def run_scan_only(
    workspace: Path,
    targets: list[Path],
    *,
    use_cache: bool = True,
    scan_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the configured scanners without attempting remediation."""
    logger.info(
        "scan run start",
        extra={"workspace": str(workspace), "target_count": len(targets), "use_cache": use_cache},
    )
    output = {
        "checkov": _scan_checkov(workspace, targets, use_cache=use_cache, scan_policy=scan_policy),
    }
    logger.info(
        "scan run complete",
        extra={"workspace": str(workspace), "target_count": len(targets), "use_cache": use_cache},
    )
    return output
