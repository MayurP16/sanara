from __future__ import annotations

import json
import sys
from pathlib import Path

from sanara import cli


def test_cli_policy_explain_outputs_decisions(tmp_path: Path, capsys, monkeypatch) -> None:
    policy_dir = tmp_path / ".sanara"
    policy_dir.mkdir()
    (policy_dir / "policy.yml").write_text(
        "finding_policy:\n"
        "  auto_fix_allow:\n"
        "    - CKV_AWS_70\n"
        "scan_policy:\n"
        "  skip_ids:\n"
        "    - CKV_AWS_999\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sanara",
            "policy",
            "explain",
            "--workspace",
            str(tmp_path),
            "--check-id",
            "CKV_AWS_70",
            "--resource-type",
            "aws_s3_bucket_policy",
            "--resource-name",
            "public_bucket",
            "--file-path",
            "main.tf",
        ],
    )
    rc = cli.main()
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["scan_policy"]["decision"]["include"] is True
    assert payload["finding_policy"]["decision"]["auto_fix_mode"].startswith("auto_fix")
    assert payload["finding_policy"]["decision"]["matched_policy_source"] == "default"
