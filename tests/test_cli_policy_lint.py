from __future__ import annotations

import json
import sys
from pathlib import Path

from sanara import cli


def test_cli_policy_lint_ok_with_warning(tmp_path: Path, capsys, monkeypatch) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "finding_policy:\n" "  auto_fix_allow:\n" "    - CKV_AWS_21\n" "    - CKV_AWS_21\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["sanara", "policy", "lint", "--workspace", str(tmp_path)])
    rc = cli.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["path"] == str(policy_dir / "policy.yml")
    assert any("duplicate values" in msg for msg in payload["warnings"])


def test_cli_policy_lint_fails_on_overlap(tmp_path: Path, capsys, monkeypatch) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "finding_policy:\n"
        "  auto_fix_allow:\n"
        "    - CKV_AWS_21\n"
        "  auto_fix_deny:\n"
        "    - CKV_AWS_21\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["sanara", "policy", "lint", "--workspace", str(tmp_path)])
    rc = cli.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["ok"] is False
    assert any("auto_fix_allow overlaps auto_fix_deny" in msg for msg in payload["errors"])


def test_cli_policy_lint_checks_environment_effective_merge(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "finding_policy:\n"
        "  auto_fix_allow:\n"
        "    - CKV_AWS_21\n"
        "environments:\n"
        "  staging:\n"
        "    finding_policy:\n"
        "      auto_fix_deny:\n"
        "        - CKV_AWS_21\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["sanara", "policy", "lint", "--workspace", str(tmp_path)])
    rc = cli.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["ok"] is False
    assert "environments.staging" in " ".join(payload["errors"])
