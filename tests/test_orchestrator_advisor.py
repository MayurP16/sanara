from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import sanara.orchestrator.advisor as advisor_module
from sanara.orchestrator.advisor import run_post_fix_advisor
from sanara.orchestrator.policy import Policy


def _w(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_advisor_llm_skipped_when_no_tf_files_changed_in_diff(tmp_path: Path, monkeypatch) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.setenv("OPENAI_API_KEY", "x")

    def _boom(*args, **kwargs):
        _ = args, kwargs
        raise AssertionError("LLM call should be skipped when no .tf changed in diff")

    monkeypatch.setattr(advisor_module, "run_agentic_fallback", _boom)
    out = run_post_fix_advisor(
        tmp_path, Policy(advisor_use_llm=True), "diff --git a/README.md b/README.md\n+docs\n"
    )
    assert out.llm_used is False
    assert "no .tf changes" in out.llm_message


def test_advisor_dedupes_semantic_duplicates_from_llm(tmp_path: Path, monkeypatch) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_account_public_access_block" "this" {}')
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    # LLM returns two semantically overlapping findings for the same resource.
    llm_payload = """
[
  {
    "id": "LLM_PAB_1",
    "severity": "critical",
    "confidence": 0.9,
    "title": "S3 account-level public access block is fully disabled",
    "description": "All account-level block settings are false.",
    "file_path": "main.tf",
    "resource_type": "aws_s3_account_public_access_block",
    "resource_name": "this",
    "recommendation": "Set all four attributes to true."
  },
  {
    "id": "LLM_PAB_2",
    "severity": "critical",
    "confidence": 0.7,
    "title": "S3 account public access block attributes are disabled",
    "description": "block_public_acls and others are false.",
    "file_path": "main.tf",
    "resource_type": "aws_s3_account_public_access_block",
    "resource_name": "this",
    "recommendation": "Enable all public access block attributes."
  }
]
"""
    monkeypatch.setattr(
        advisor_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            used=True,
            ok=True,
            message="ok",
            patch_diff=llm_payload,
            ledger={},
            trace=[],
        ),
    )
    diff = "diff --git a/main.tf b/main.tf\n+dummy = true\n"
    out = run_post_fix_advisor(tmp_path, Policy(advisor_use_llm=True), diff)
    pab = [
        x for x in out.findings if x.get("resource_type") == "aws_s3_account_public_access_block"
    ]
    assert len(pab) == 1
    assert pab[0]["source"] == "llm"
    assert pab[0]["id"] == "LLM_PAB_1"


def test_advisor_filters_llm_topics_already_visible_to_scanner(tmp_path: Path, monkeypatch) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    llm_payload = """
[
  {
    "id": "LLM_SSE",
    "severity": "critical",
    "title": "S3 bucket missing server-side encryption configuration",
    "description": "No default encryption.",
    "file_path": "main.tf",
    "resource_type": "aws_s3_bucket",
    "resource_name": "data",
    "recommendation": "Add SSE config.",
    "related_scanner_rule_ids": ["CKV_AWS_145"]
  },
  {
    "id": "LLM_VER",
    "severity": "moderate",
    "title": "S3 bucket versioning is not enabled",
    "description": "Versioning missing.",
    "file_path": "main.tf",
    "resource_type": "aws_s3_bucket",
    "resource_name": "data",
    "recommendation": "Enable versioning.",
    "related_scanner_rule_ids": ["CKV_AWS_21"]
  }
]
"""
    monkeypatch.setattr(
        advisor_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            used=True,
            ok=True,
            message="ok",
            patch_diff=llm_payload,
            ledger={},
            trace=[],
        ),
    )
    scanner_visible = [
        {
            "source_rule_id": "CKV_AWS_145",
            "sanara_rule_id": "aws.s3.sse_kms_default",
            "file_path": "main.tf",
            "resource_type": "aws_s3_bucket",
            "resource_name": "data",
        },
        {
            "source_rule_id": "CKV_AWS_21",
            "sanara_rule_id": "aws.s3.versioning_enabled",
            "file_path": "main.tf",
            "resource_type": "aws_s3_bucket",
            "resource_name": "data",
        },
    ]
    out = run_post_fix_advisor(
        tmp_path,
        Policy(advisor_use_llm=True),
        "diff --git a/main.tf b/main.tf\n+dummy = true\n",
        scanner_visible_findings=scanner_visible,
    )
    assert out.findings == []


def test_advisor_keeps_same_resource_hardening_signal_without_related_ids(
    tmp_path: Path, monkeypatch
) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_kms_key" "terraform_locks_cmk" {}')
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    llm_payload = """
[
  {
    "id": "LLM_ROTATION",
    "severity": "critical",
    "title": "KMS key missing key rotation",
    "description": "Key rotation is not enabled.",
    "file_path": "/main.tf",
    "resource_type": "aws_kms_key",
    "resource_name": "terraform_locks_cmk",
    "recommendation": "Add enable_key_rotation = true."
  }
]
"""
    monkeypatch.setattr(
        advisor_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            used=True,
            ok=True,
            message="ok",
            patch_diff=llm_payload,
            ledger={},
            trace=[],
        ),
    )
    scanner_visible = [
        {
            "source_rule_id": "CKV_AWS_7",
            "file_path": "main.tf",
            "resource_type": "aws_kms_key",
            "resource_name": "terraform_locks_cmk",
        }
    ]
    out = run_post_fix_advisor(
        tmp_path,
        Policy(advisor_use_llm=True),
        "diff --git a/main.tf b/main.tf\n+dummy = true\n",
        scanner_visible_findings=scanner_visible,
    )
    assert len(out.findings) == 1
    assert out.findings[0]["resource_type"] == "aws_kms_key"
    assert out.findings[0]["resource_name"] == "terraform_locks_cmk"


def test_advisor_keeps_account_level_signal_when_scanner_rule_matches_different_resource(
    tmp_path: Path, monkeypatch
) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_account_public_access_block" "this" {
          block_public_acls       = false
          block_public_policy     = false
          ignore_public_acls      = false
          restrict_public_buckets = false
        }
        resource "aws_s3_bucket" "public_bucket" {}
        """,
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    llm_payload = """
[
  {
    "id": "CUSTOM_001",
    "severity": "critical",
    "title": "S3 account-level public access block is fully disabled",
    "description": "All four account-level settings are false.",
    "file_path": "/main.tf",
    "resource_type": "aws_s3_account_public_access_block",
    "resource_name": "this",
    "recommendation": "Set all four flags to true.",
    "related_scanner_rule_ids": ["CKV2_AWS_61"]
  }
]
"""
    monkeypatch.setattr(
        advisor_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            used=True,
            ok=True,
            message="ok",
            patch_diff=llm_payload,
            ledger={},
            trace=[],
        ),
    )
    # Same scanner rule id, but different resource target (bucket-level finding).
    scanner_visible = [
        {
            "source_rule_id": "CKV2_AWS_61",
            "file_path": "main.tf",
            "resource_type": "aws_s3_bucket",
            "resource_name": "public_bucket",
        }
    ]
    out = run_post_fix_advisor(
        tmp_path,
        Policy(advisor_use_llm=True),
        "diff --git a/main.tf b/main.tf\n+dummy = true\n",
        scanner_visible_findings=scanner_visible,
    )
    assert len(out.findings) == 1
    assert out.findings[0]["resource_type"] == "aws_s3_account_public_access_block"
    assert out.findings[0]["resource_name"] == "this"


def test_advisor_accepts_single_object_json_payload(tmp_path: Path, monkeypatch) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_account_public_access_block" "this" {
          block_public_acls       = false
          block_public_policy     = false
          ignore_public_acls      = false
          restrict_public_buckets = false
        }
        """,
    )
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    llm_payload = """
{
  "id": "TF-AWS-S3-ACCOUNT-PAB-DISABLED",
  "severity": "critical",
  "title": "S3 account-level Public Access Block is disabled",
  "description": "All four account-level settings are false.",
  "file_path": "/main.tf",
  "resource_type": "aws_s3_account_public_access_block",
  "resource_name": "this",
  "recommendation": "Set all four flags to true.",
  "related_scanner_rule_ids": []
}
"""
    monkeypatch.setattr(
        advisor_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: SimpleNamespace(
            used=True,
            ok=True,
            message="ok",
            patch_diff=llm_payload,
            ledger={},
            trace=[],
        ),
    )
    out = run_post_fix_advisor(
        tmp_path,
        Policy(advisor_use_llm=True),
        "diff --git a/main.tf b/main.tf\n+dummy = true\n",
        scanner_visible_findings=[],
    )
    assert len(out.findings) == 1
    assert out.findings[0]["id"] == "TF-AWS-S3-ACCOUNT-PAB-DISABLED"
