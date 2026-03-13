from __future__ import annotations

import json
import sys
from pathlib import Path

from sanara import cli


def test_cli_validate_policy_ok(tmp_path: Path, capsys, monkeypatch) -> None:
    policy = tmp_path / "policy.yml"
    policy.write_text(
        "allow_agentic: false\nscan_policy:\n  skip_ids: [CKV_AWS_70]\n", encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["sanara", "validate", "--policy", str(policy)])
    rc = cli.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["path"] == str(policy)


def test_cli_validate_policy_fails_fast(tmp_path: Path, capsys, monkeypatch) -> None:
    policy = tmp_path / "policy.yml"
    policy.write_text("allow_agnetic: true\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["sanara", "validate", "--policy", str(policy)])
    rc = cli.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["ok"] is False
    assert "unknown keys in policy root" in payload["error"]
