from __future__ import annotations

from pathlib import Path

from sanara.scanners import runners


class _Result:
    def __init__(self, code: int, stdout: str, stderr: str = ""):
        self.code = code
        self.stdout = stdout
        self.stderr = stderr


def test_run_scan_only_parses_checkov_json(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()

    def _run(cmd, cwd, **kwargs):
        _ = cwd, kwargs
        return _Result(0, '{"results":{"failed_checks":[{"check_id":"CKV_AWS_3"}]}}')

    monkeypatch.setattr(runners, "run_cmd", _run)
    out = runners.run_scan_only(tmp_path, [tmp_path])

    assert out["checkov"]["results"][0]["results"]["failed_checks"][0]["check_id"] == "CKV_AWS_3"


def test_run_scan_only_handles_parse_errors(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()
    monkeypatch.setattr(runners, "run_cmd", lambda *args, **kwargs: _Result(1, "not-json", "boom"))
    out = runners.run_scan_only(tmp_path, [tmp_path])

    assert out["checkov"]["results"][0]["parse_error"] is True


def test_run_scan_only_checkov_empty_output(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()

    monkeypatch.setattr(
        runners, "run_cmd", lambda *args, **kwargs: _Result(0, "", "checkov-stderr")
    )
    out = runners.run_scan_only(tmp_path, [tmp_path])

    assert out["checkov"]["results"][0]["results"]["failed_checks"] == []
    assert out["checkov"]["results"][0]["stderr"] == "checkov-stderr"
    assert out["checkov"]["results"][0]["code"] == 0


def test_run_scan_only_honors_custom_checkov_bin(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()
    seen_cmds: list[list[str]] = []

    def _run(cmd, cwd, **kwargs):
        _ = cwd, kwargs
        seen_cmds.append(cmd)
        return _Result(0, '{"results":{"failed_checks":[]}}')

    monkeypatch.setenv("SANARA_CHECKOV_BIN", "custom-checkov")
    monkeypatch.setattr(runners, "run_cmd", _run)

    out = runners.run_scan_only(tmp_path, [tmp_path])

    assert out["checkov"]["results"][0]["results"]["failed_checks"] == []
    assert any(cmd[0] == "custom-checkov" for cmd in seen_cmds)


def test_run_scan_only_passes_scan_policy_checkov_filters(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()
    seen_cmds: list[list[str]] = []

    def _run(cmd, cwd, **kwargs):
        _ = cwd, kwargs
        seen_cmds.append(cmd)
        return _Result(0, '{"results":{"failed_checks":[]}}')

    monkeypatch.setattr(runners, "run_cmd", _run)
    out = runners.run_scan_only(
        tmp_path,
        [tmp_path],
        scan_policy={"include_ids": ["CKV_AWS_70", "CKV_AWS_145"], "skip_ids": ["CKV_AWS_144"]},
    )

    assert out["checkov"]["results"][0]["results"]["failed_checks"] == []
    checkov_cmd = next(cmd for cmd in seen_cmds if "checkov" in cmd[0])
    assert "--check" in checkov_cmd and "CKV_AWS_145,CKV_AWS_70" in checkov_cmd
    assert "--skip-check" in checkov_cmd and "CKV_AWS_144" in checkov_cmd


def test_checkov_cli_filter_args_helper() -> None:
    args = runners.checkov_cli_filter_args(
        {"include_ids": ["ckv_aws_70"], "skip_ids": ["CKV_AWS_144", "CKV_AWS_144"]}
    )
    assert args == ["--check", "CKV_AWS_70", "--skip-check", "CKV_AWS_144"]


def test_run_scan_only_coerces_malformed_scanner_shapes(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()

    monkeypatch.setattr(
        runners,
        "run_cmd",
        lambda *args, **kwargs: _Result(0, '{"results":{"failed_checks":"bad-type"}}', ""),
    )
    out = runners.run_scan_only(tmp_path, [tmp_path])

    checkov_payload = out["checkov"]["results"][0]
    assert checkov_payload["results"]["failed_checks"] == []
    assert checkov_payload["parse_error"] is True


def test_run_scan_only_uses_cache_for_unchanged_targets(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()
    call_count = {"n": 0}

    def _run(cmd, cwd, **kwargs):
        _ = cwd, kwargs
        call_count["n"] += 1
        return _Result(0, '{"results":{"failed_checks":[]}}')

    monkeypatch.setattr(runners, "run_cmd", _run)

    out1 = runners.run_scan_only(tmp_path, [tmp_path])
    out2 = runners.run_scan_only(tmp_path, [tmp_path])

    assert out1["checkov"]["results"][0]["results"]["failed_checks"] == []
    assert out2["checkov"]["results"][0]["results"]["failed_checks"] == []
    assert call_count["n"] == 1


def test_run_scan_only_cache_can_be_disabled(monkeypatch, tmp_path: Path) -> None:
    runners._SCAN_CACHE.clear()
    call_count = {"n": 0}

    def _run(cmd, cwd, **kwargs):
        _ = cmd, cwd, kwargs
        call_count["n"] += 1
        return _Result(0, '{"results":{"failed_checks":[]}}')

    monkeypatch.setenv("SANARA_SCAN_CACHE_ENABLED", "false")
    monkeypatch.setattr(runners, "run_cmd", _run)

    runners.run_scan_only(tmp_path, [tmp_path])
    runners.run_scan_only(tmp_path, [tmp_path])
    assert call_count["n"] == 2
