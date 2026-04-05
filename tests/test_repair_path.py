from __future__ import annotations

from pathlib import Path

from sanara.orchestrator.repair import (
    _canonicalize_patch_paths,
    _focus_files_from_findings,
    _target_file_for_finding,
    _patch_quality_ok,
    _extract_unified_diff,
)


def _finding(file_path: str, module_dir: str, rule_id: str = "CKV2_AWS_6") -> dict:
    return {
        "source_rule_id": rule_id,
        "resource_type": "aws_s3_bucket",
        "resource_name": "data",
        "target": {
            "file_path": file_path,
            "module_dir": module_dir,
            "line_range": "1-5",
        },
    }


def test_focus_files_resolves_module_dir(tmp_path: Path) -> None:
    """file_path is relative to module_dir, not workspace — resolve correctly."""
    workspace = tmp_path
    finding = _finding("/s3.tf", str(workspace / "terraform" / "aws"))
    result = _focus_files_from_findings([finding], workspace)
    assert result == ["terraform/aws/s3.tf"]


def test_focus_files_without_workspace_falls_back(tmp_path: Path) -> None:
    """Without workspace, return the bare normalised name (backward compat)."""
    finding = _finding("/s3.tf", str(tmp_path / "terraform" / "aws"))
    result = _focus_files_from_findings([finding])
    assert result == ["s3.tf"]


def test_target_file_resolves_module_dir(tmp_path: Path) -> None:
    workspace = tmp_path
    finding = _finding("/db-app.tf", str(workspace / "terraform" / "aws"))
    assert _target_file_for_finding(finding, workspace) == "terraform/aws/db-app.tf"


def test_target_file_resolves_relative_module_dir(tmp_path: Path) -> None:
    workspace = tmp_path
    finding = _finding("/main.tf", "examples/complete")
    assert _target_file_for_finding(finding, workspace) == "examples/complete/main.tf"


def test_target_file_without_workspace_falls_back(tmp_path: Path) -> None:
    finding = _finding("/db-app.tf", str(tmp_path / "terraform" / "aws"))
    assert _target_file_for_finding(finding) == "db-app.tf"


def test_patch_quality_ok_uses_resolved_paths(tmp_path: Path) -> None:
    """Quality gate must accept a patch that targets the workspace-relative path."""
    workspace = tmp_path
    target = workspace / "terraform" / "aws" / "ecr.tf"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('resource "aws_ecr_repository" "repo" {\n}\n', encoding="utf-8")
    finding = _finding("/ecr.tf", str(workspace / "terraform" / "aws"), "CKV_AWS_136")
    allowed = {"terraform/aws/ecr.tf"}
    patch = (
        "diff --git a/terraform/aws/ecr.tf b/terraform/aws/ecr.tf\n"
        "--- a/terraform/aws/ecr.tf\n"
        "+++ b/terraform/aws/ecr.tf\n"
        "@@ -1,4 +1,8 @@\n"
        ' resource "aws_ecr_repository" "repo" {\n'
        "+  encryption_configuration {\n"
        '+    encryption_type = "KMS"\n'
        "+  }\n"
        " }\n"
    )
    ok, reason = _patch_quality_ok(patch, finding, allowed, {}, workspace=workspace)
    assert ok, reason


def test_patch_quality_ok_accepts_valid_append_only_hunk(tmp_path: Path) -> None:
    workspace = tmp_path
    (workspace / "main.tf").write_text('resource "aws_s3_bucket" "this" {}\n', encoding="utf-8")
    finding = _finding("/main.tf", str(workspace), "CKV2_AWS_6")
    allowed = {"main.tf"}
    patch = (
        "diff --git a/main.tf b/main.tf\n"
        "--- a/main.tf\n"
        "+++ b/main.tf\n"
        "@@ -1459,0 +1460,11 @@\n"
        "+\n"
        '+resource "aws_s3_bucket_public_access_block" "this_always" {\n'
        "+  count = local.create_bucket && !var.is_directory_bucket ? 1 : 0\n"
        "+\n"
        "+  bucket = aws_s3_bucket.this[0].id\n"
        "+\n"
        "+  block_public_acls       = true\n"
        "+  block_public_policy     = true\n"
        "+  ignore_public_acls      = true\n"
        "+  restrict_public_buckets = true\n"
        "+}\n"
    )
    ok, reason = _patch_quality_ok(patch, finding, allowed, {}, workspace=workspace)
    assert ok, reason


def test_patch_quality_ok_rejects_workspace_escape(tmp_path: Path) -> None:
    workspace = tmp_path
    finding = _finding("/main.tf", "examples/complete", "CKV2_AWS_6")
    allowed = {"examples/complete/main.tf"}
    patch = (
        "diff --git a/../../other.tf b/../../other.tf\n"
        "--- a/../../other.tf\n"
        "+++ b/../../other.tf\n"
        "@@ -1 +1,2 @@\n"
        ' resource "aws_s3_bucket" "data" {}\n'
        "+# llm edit\n"
    )
    ok, reason = _patch_quality_ok(patch, finding, allowed, {}, workspace=workspace)
    assert ok is False
    assert "outside allowlist" in reason


def test_canonicalize_patch_paths_rewrites_single_target_basename_match(tmp_path: Path) -> None:
    workspace = tmp_path
    patch = (
        "diff --git a/../../main.tf b/../../main.tf\n"
        "--- a/../../main.tf\n"
        "+++ b/../../main.tf\n"
        "@@ -1 +1,2 @@\n"
        ' resource "aws_s3_bucket" "data" {}\n'
        "+# llm edit\n"
    )
    rewritten, message = _canonicalize_patch_paths(
        patch,
        workspace=workspace,
        allowed_files={"examples/complete/main.tf"},
    )
    assert "rewrote diff paths" in message
    assert "diff --git a/examples/complete/main.tf b/examples/complete/main.tf" in rewritten


def test_canonicalize_patch_paths_rewrites_duplicate_single_target_basename_match(
    tmp_path: Path,
) -> None:
    workspace = tmp_path
    patch = (
        "diff --git a/../../main.tf b/../../main.tf\n"
        "--- a/../../main.tf\n"
        "+++ b/../../main.tf\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "diff --git a/../../main.tf b/../../main.tf\n"
        "--- a/../../main.tf\n"
        "+++ b/../../main.tf\n"
        "@@ -3 +3 @@\n"
        "-old2\n"
        "+new2\n"
    )
    rewritten, message = _canonicalize_patch_paths(
        patch,
        workspace=workspace,
        allowed_files={"examples/complete/main.tf"},
    )
    assert "rewrote diff paths" in message
    assert "../../main.tf" not in rewritten
    assert (
        rewritten.count("diff --git a/examples/complete/main.tf b/examples/complete/main.tf") == 2
    )


def test_patch_quality_ok_rejects_non_diff_prose_in_hunk(tmp_path: Path) -> None:
    workspace = tmp_path
    target = workspace / "examples" / "complete" / "main.tf"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('resource "aws_s3_bucket" "data" {}\n', encoding="utf-8")
    finding = _finding("/main.tf", "examples/complete", "CKV2_AWS_65")
    allowed = {"examples/complete/main.tf"}
    patch = (
        "diff --git a/examples/complete/main.tf b/examples/complete/main.tf\n"
        "--- a/examples/complete/main.tf\n"
        "+++ b/examples/complete/main.tf\n"
        "@@ -1 +1 @@\n"
        " Wait, I need to see the actual content first.\n"
    )
    ok, reason = _patch_quality_ok(patch, finding, allowed, {}, workspace=workspace)
    assert ok is False
    assert "anchor does not match target file content" in reason


def test_extract_unified_diff_from_fenced_block_preserves_patch_only() -> None:
    text = (
        "Here is the patch:\n\n"
        "```diff\n"
        "diff --git a/main.tf b/main.tf\n"
        "--- a/main.tf\n"
        "+++ b/main.tf\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
        "```\n"
        "Trailing explanation outside the fence.\n"
    )
    patch = _extract_unified_diff(text)
    assert patch.startswith("diff --git a/main.tf b/main.tf\n")
    assert "Trailing explanation outside the fence." not in patch
