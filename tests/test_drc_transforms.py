"""Regression tests for DRC deterministic transforms.

Each test:
  1. Writes a minimal Terraform fixture with a failing resource to tmp_path
  2. Applies the transform
  3. Asserts the output contains the expected secure attribute/block
  4. Asserts no unrelated resources were modified
"""

from __future__ import annotations

import re
import shutil
import subprocess
import os
import json
from pathlib import Path

import pytest

from sanara.drc.engine import apply_drc
from sanara.drc.transforms.core import (
    t4_rds_not_public,
    t5_ebs_encrypted,
    t9_dynamodb_pitr,
    t11_s3_acl_private,
    t13_kms_key_rotation,
    t20_lambda_tracing,
    t21_rds_deletion_protection,
    t22_ecr_scan_on_push,
    t23_cloudtrail_log_file_validation,
    t25_ecr_kms_encryption,
    t26_ec2_imdsv2,
    t27_rds_backup_retention,
    t28_secretsmanager_kms,
    t29_cloudtrail_multi_region,
    t30_rds_storage_encrypted,
)
from sanara.orchestrator.policy import Policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tf(tmp_path: Path, content: str, name: str = "main.tf") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _read(tmp_path: Path, name: str = "main.tf") -> str:
    return (tmp_path / name).read_text(encoding="utf-8")


def _checkov_failed_ids(module_dir: Path, check_id: str) -> set[str]:
    checkov_bin = _resolve_checkov_bin()
    cmd = [
        checkov_bin,
        "-o",
        "json",
        "--quiet",
        "--skip-download",
        "-s",
        "--framework",
        "terraform",
        "--check",
        check_id,
        "-d",
        str(module_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if not proc.stdout.strip():
        pytest.fail(f"checkov produced no JSON output for {check_id}: {proc.stderr}")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"checkov output was not valid JSON for {check_id}: {exc}\nstderr={proc.stderr}"
        )

    reports = payload if isinstance(payload, list) else [payload]
    failed_ids: set[str] = set()
    for report in reports:
        checks = (
            report.get("results", {}).get("failed_checks", []) if isinstance(report, dict) else []
        )
        for finding in checks:
            if isinstance(finding, dict) and finding.get("check_id"):
                failed_ids.add(str(finding["check_id"]).upper())
    return failed_ids


def _checkov_supported_ids() -> set[str]:
    checkov_bin = _resolve_checkov_bin()
    cmd = [checkov_bin, "-l", "--framework", "terraform", "--skip-download"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    ids = set(re.findall(r"\b(CKV2?_AWS_\d+)\b", proc.stdout))
    return {x.upper() for x in ids}


def _resolve_checkov_bin() -> str:
    env_bin = os.environ.get("SANARA_CHECKOV_BIN", "").strip()
    if env_bin:
        return env_bin
    repo_bin = Path(".venv/bin/checkov")
    if repo_bin.exists():
        return str(repo_bin)
    return "checkov"


_CHECKOV_CASES: list[tuple[str, str, str, str, str, Policy]] = [
    (
        "aws.s3.public_access_block",
        "CKV_AWS_53",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_public_access_block" "data_pab" {
          bucket                  = aws_s3_bucket.data.id
          block_public_acls       = false
          block_public_policy     = true
          ignore_public_acls      = true
          restrict_public_buckets = true
        }
        """,
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.s3.sse_default",
        "CKV_AWS_19",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
          bucket = aws_s3_bucket.data.id
          rule {
            apply_server_side_encryption_by_default {
              sse_algorithm = "DES"
            }
          }
        }
        """,
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.s3.versioning_enabled",
        "CKV_AWS_21",
        'resource "aws_s3_bucket" "data" {}',
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.rds.not_public",
        "CKV_AWS_17",
        """
        resource "aws_db_instance" "db" {
          publicly_accessible = true
        }
        """,
        "aws_db_instance",
        "db",
        Policy(),
    ),
    (
        "aws.ebs.encrypted",
        "CKV_AWS_3",
        """
        resource "aws_ebs_volume" "vol" {
          encrypted = false
        }
        """,
        "aws_ebs_volume",
        "vol",
        Policy(),
    ),
    (
        "aws.ebs.default_encryption_enabled",
        "CKV_AWS_106",
        """
        resource "aws_ebs_encryption_by_default" "this" {
          enabled = false
        }
        """,
        "aws_ebs_encryption_by_default",
        "this",
        Policy(apply_opt_in_rules=["aws.ebs.default_encryption_enabled"]),
    ),
    (
        "aws.sns.encrypted",
        "CKV_AWS_26",
        """
        resource "aws_sns_topic" "topic" {
          name = "topic"
        }
        """,
        "aws_sns_topic",
        "topic",
        Policy(),
    ),
    (
        "aws.sqs.encrypted",
        "CKV_AWS_27",
        """
        resource "aws_sqs_queue" "queue" {
          name = "queue"
        }
        """,
        "aws_sqs_queue",
        "queue",
        Policy(),
    ),
    (
        "aws.dynamodb.kms_cmk_encrypted",
        "CKV_AWS_119",
        """
        resource "aws_dynamodb_table" "tbl" {
          name         = "tbl"
          billing_mode = "PAY_PER_REQUEST"
          hash_key     = "id"
          attribute {
            name = "id"
            type = "S"
          }
        }
        """,
        "aws_dynamodb_table",
        "tbl",
        Policy(),
    ),
    (
        "aws.cloudwatch.log_group_encrypted",
        "CKV_AWS_158",
        """
        resource "aws_cloudwatch_log_group" "lg" {
          name = "x"
        }
        """,
        "aws_cloudwatch_log_group",
        "lg",
        Policy(),
    ),
    (
        "aws.s3.acl_private",
        "CKV_AWS_20",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_acl" "data_acl" {
          bucket = aws_s3_bucket.data.id
          acl    = "public-read"
        }
        """,
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.dynamodb.pitr_enabled",
        "CKV_AWS_28",
        """
        resource "aws_dynamodb_table" "tbl" {
          name         = "tbl"
          billing_mode = "PAY_PER_REQUEST"
          hash_key     = "id"
          attribute {
            name = "id"
            type = "S"
          }
        }
        """,
        "aws_dynamodb_table",
        "tbl",
        Policy(),
    ),
    (
        "aws.kms.rotation_enabled",
        "CKV_AWS_7",
        """
        resource "aws_kms_key" "k" {
          description         = "x"
          enable_key_rotation = false
        }
        """,
        "aws_kms_key",
        "k",
        Policy(),
    ),
    (
        "aws.s3.policy_secure_transport",
        "CKV_AWS_70",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_policy" "data" {
          bucket = aws_s3_bucket.data.id
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [{
              Principal = "*"
              Effect    = "Allow"
              Action    = ["s3:GetObject"]
              Resource  = "${aws_s3_bucket.data.arn}/*"
            }]
          })
        }
        """,
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.s3.sse_kms_default",
        "CKV_AWS_145",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
          bucket = aws_s3_bucket.data.id
          rule {
            apply_server_side_encryption_by_default {
              sse_algorithm = "AES256"
            }
          }
        }
        """,
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.s3.access_logging_enabled",
        "CKV_AWS_18",
        'resource "aws_s3_bucket" "data" {}',
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.kms.policy_present",
        "CKV2_AWS_64",
        """
        resource "aws_kms_key" "k" {
          description = "x"
        }
        """,
        "aws_kms_key",
        "k",
        Policy(),
    ),
    (
        "aws.s3.acl_disabled",
        "CKV2_AWS_65",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_ownership_controls" "data_ownership_controls" {
          bucket = aws_s3_bucket.data.id
          rule {
            object_ownership = "ObjectWriter"
          }
        }
        """,
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.s3.event_notifications_enabled",
        "CKV2_AWS_62",
        'resource "aws_s3_bucket" "data" {}',
        "aws_s3_bucket",
        "data",
        Policy(),
    ),
    (
        "aws.lambda.tracing_enabled",
        "CKV_AWS_50",
        """
        resource "aws_lambda_function" "fn" {
          function_name = "test"
          role          = "arn:aws:iam::123456789012:role/does-not-matter"
          handler       = "index.handler"
          runtime       = "python3.11"
          filename      = "lambda.zip"
        }
        """,
        "aws_lambda_function",
        "fn",
        Policy(),
    ),
    (
        "aws.rds.deletion_protection",
        "CKV_AWS_293",
        """
        resource "aws_db_instance" "db" {
          deletion_protection = false
        }
        """,
        "aws_db_instance",
        "db",
        Policy(),
    ),
    (
        "aws.ecr.scan_on_push",
        "CKV_AWS_163",
        """
        resource "aws_ecr_repository" "repo" {
          name = "repo"
          image_scanning_configuration {
            scan_on_push = false
          }
        }
        """,
        "aws_ecr_repository",
        "repo",
        Policy(),
    ),
    (
        "aws.cloudtrail.log_file_validation",
        "CKV_AWS_36",
        """
        resource "aws_cloudtrail" "trail" {
          name                       = "x"
          enable_log_file_validation = false
        }
        """,
        "aws_cloudtrail",
        "trail",
        Policy(),
    ),
    (
        "aws.cloudtrail.kms_encrypted",
        "CKV_AWS_35",
        """
        resource "aws_cloudtrail" "trail" {
          name = "x"
        }
        """,
        "aws_cloudtrail",
        "trail",
        Policy(),
    ),
    (
        "aws.ecr.kms_encryption",
        "CKV_AWS_136",
        """
        resource "aws_ecr_repository" "repo" {
          name = "repo"
          encryption_configuration {
            encryption_type = "AES256"
          }
        }
        """,
        "aws_ecr_repository",
        "repo",
        Policy(),
    ),
    (
        "aws.ec2.imdsv2_required",
        "CKV_AWS_79",
        """
        resource "aws_instance" "web" {
          ami           = "ami-1234567890abcdef0"
          instance_type = "t3.micro"
          metadata_options {
            http_tokens   = "optional"
            http_endpoint = "enabled"
          }
        }
        """,
        "aws_instance",
        "web",
        Policy(),
    ),
    (
        "aws.rds.backup_retention",
        "CKV_AWS_133",
        """
        resource "aws_db_instance" "db" {
          backup_retention_period = 0
        }
        """,
        "aws_db_instance",
        "db",
        Policy(),
    ),
    (
        "aws.secretsmanager.kms_encrypted",
        "CKV_AWS_149",
        """
        resource "aws_secretsmanager_secret" "sec" {
          name = "sec"
        }
        """,
        "aws_secretsmanager_secret",
        "sec",
        Policy(),
    ),
    (
        "aws.cloudtrail.multi_region_enabled",
        "CKV_AWS_67",
        """
        resource "aws_cloudtrail" "trail" {
          name                  = "x"
          is_multi_region_trail = false
        }
        """,
        "aws_cloudtrail",
        "trail",
        Policy(),
    ),
    (
        "aws.rds.storage_encrypted",
        "CKV_AWS_16",
        """
        resource "aws_db_instance" "db" {
          storage_encrypted = false
        }
        """,
        "aws_db_instance",
        "db",
        Policy(),
    ),
]

_CHECKOV_KNOWN_MISMATCHES: dict[str, str] = {}


@pytest.mark.parametrize(
    "sanara_rule_id,check_id,fixture_hcl,resource_type,resource_name,policy",
    _CHECKOV_CASES,
    ids=[f"{rule}:{check_id}" for rule, check_id, *_ in _CHECKOV_CASES],
)
def test_drc_transform_checkov_fail_to_pass_all_30(
    tmp_path: Path,
    sanara_rule_id: str,
    check_id: str,
    fixture_hcl: str,
    resource_type: str,
    resource_name: str,
    policy: Policy,
) -> None:
    checkov_bin = _resolve_checkov_bin()
    if shutil.which(checkov_bin) is None:
        pytest.skip("checkov binary not available; skipping fail->pass integration matrix")
    assert len(_CHECKOV_CASES) == 30
    if check_id in _CHECKOV_KNOWN_MISMATCHES:
        pytest.skip(_CHECKOV_KNOWN_MISMATCHES[check_id])
    supported_ids = _checkov_supported_ids()
    if check_id.upper() not in supported_ids:
        pytest.skip(f"{check_id} not available in installed checkov terraform checks")

    tf_file = tmp_path / "main.tf"
    tf_file.write_text(fixture_hcl.strip() + "\n", encoding="utf-8")

    before_ids = _checkov_failed_ids(tmp_path, check_id)
    assert check_id in before_ids, f"expected {check_id} to fail before applying {sanara_rule_id}"

    attempts = apply_drc(
        tmp_path,
        [
            {
                "sanara_rule_id": sanara_rule_id,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "target": {
                    "module_dir": ".",
                    "file_path": "main.tf",
                },
            }
        ],
        policy,
    )
    assert len(attempts) == 1
    assert attempts[0].status in {"changed", "no_change"}
    assert attempts[0].code == "OK"

    after_ids = _checkov_failed_ids(tmp_path, check_id)
    assert check_id not in after_ids, f"expected {check_id} to pass after applying {sanara_rule_id}"


def test_checkov_mapping_does_not_include_inaccurate_t29_legacy_id() -> None:
    mapping_path = Path("rules/mappings/checkov_to_sanara.v0.1.json")
    mappings = json.loads(mapping_path.read_text(encoding="utf-8")).get("mappings", {})
    assert "CKV_AWS_274" not in mappings


# ---------------------------------------------------------------------------
# T4: RDS not public
# ---------------------------------------------------------------------------


def test_t4_rds_not_public_sets_false(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n')
    result = t4_rds_not_public(tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy())
    assert result.changed
    assert "publicly_accessible = false" in _read(tmp_path)


def test_t4_rds_not_public_no_change_when_already_false(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  publicly_accessible = false\n}\n')
    result = t4_rds_not_public(tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy())
    assert not result.changed


# ---------------------------------------------------------------------------
# T5: EBS encrypted
# ---------------------------------------------------------------------------


def test_t5_ebs_encrypted_adds_attribute(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_ebs_volume" "vol" {\n  size = 20\n}\n')
    result = t5_ebs_encrypted(tmp_path, tmp_path / "main.tf", "aws_ebs_volume", "vol", Policy())
    assert result.changed
    assert "encrypted = true" in _read(tmp_path)


# ---------------------------------------------------------------------------
# T9: DynamoDB PITR
# ---------------------------------------------------------------------------


def test_t9_dynamodb_pitr_adds_block(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_dynamodb_table" "tbl" {\n  name = "test"\n}\n')
    t9_dynamodb_pitr(tmp_path, tmp_path / "main.tf", "aws_dynamodb_table", "tbl", Policy())
    text = _read(tmp_path)
    assert "point_in_time_recovery" in text
    assert "enabled = true" in text


def test_t9_dynamodb_pitr_fixes_false(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        'resource "aws_dynamodb_table" "tbl" {\n  point_in_time_recovery {\n    enabled = false\n  }\n}\n',
    )
    t9_dynamodb_pitr(tmp_path, tmp_path / "main.tf", "aws_dynamodb_table", "tbl", Policy())
    assert "enabled = true" in _read(tmp_path)
    assert "enabled = false" not in _read(tmp_path)


# ---------------------------------------------------------------------------
# T13: KMS key rotation
# ---------------------------------------------------------------------------


def test_t13_kms_key_rotation_sets_true(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_kms_key" "k" {\n  description = "test"\n}\n')
    result = t13_kms_key_rotation(tmp_path, tmp_path / "main.tf", "aws_kms_key", "k", Policy())
    assert result.changed
    assert "enable_key_rotation = true" in _read(tmp_path)


def test_t13_kms_rotation_flips_false_to_true(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_kms_key" "k" {\n  enable_key_rotation = false\n}\n')
    result = t13_kms_key_rotation(tmp_path, tmp_path / "main.tf", "aws_kms_key", "k", Policy())
    assert result.changed
    assert "enable_key_rotation = true" in _read(tmp_path)
    assert "enable_key_rotation = false" not in _read(tmp_path)


# ---------------------------------------------------------------------------
# T20: Lambda tracing
# ---------------------------------------------------------------------------


def test_t20_lambda_tracing_adds_block(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_lambda_function" "fn" {\n  function_name = "test"\n}\n')
    result = t20_lambda_tracing(
        tmp_path, tmp_path / "main.tf", "aws_lambda_function", "fn", Policy()
    )
    text = _read(tmp_path)
    assert result.changed
    assert "tracing_config" in text
    assert '"Active"' in text


def test_t20_lambda_tracing_upgrades_passthrough(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        'resource "aws_lambda_function" "fn" {\n  tracing_config {\n    mode = "PassThrough"\n  }\n}\n',
    )
    t20_lambda_tracing(tmp_path, tmp_path / "main.tf", "aws_lambda_function", "fn", Policy())
    text = _read(tmp_path)
    assert '"Active"' in text
    assert '"PassThrough"' not in text


# ---------------------------------------------------------------------------
# T21: RDS deletion protection
# ---------------------------------------------------------------------------


def test_t21_rds_deletion_protection_adds_true(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n')
    result = t21_rds_deletion_protection(
        tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy()
    )
    assert result.changed
    assert "deletion_protection = true" in _read(tmp_path)


# ---------------------------------------------------------------------------
# T22: ECR scan on push
# ---------------------------------------------------------------------------


def test_t22_ecr_scan_on_push_adds_block(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_ecr_repository" "repo" {\n  name = "test"\n}\n')
    result = t22_ecr_scan_on_push(
        tmp_path, tmp_path / "main.tf", "aws_ecr_repository", "repo", Policy()
    )
    text = _read(tmp_path)
    assert result.changed
    assert "image_scanning_configuration" in text
    assert "scan_on_push = true" in text


def test_t22_ecr_scan_on_push_flips_false(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        'resource "aws_ecr_repository" "repo" {\n  image_scanning_configuration {\n    scan_on_push = false\n  }\n}\n',
    )
    t22_ecr_scan_on_push(tmp_path, tmp_path / "main.tf", "aws_ecr_repository", "repo", Policy())
    text = _read(tmp_path)
    assert "scan_on_push = true" in text
    assert "scan_on_push = false" not in text


# ---------------------------------------------------------------------------
# T23: CloudTrail log file validation
# ---------------------------------------------------------------------------


def test_t23_cloudtrail_log_validation_sets_true(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_cloudtrail" "trail" {\n  name = "test"\n}\n')
    result = t23_cloudtrail_log_file_validation(
        tmp_path, tmp_path / "main.tf", "aws_cloudtrail", "trail", Policy()
    )
    assert result.changed
    assert "enable_log_file_validation = true" in _read(tmp_path)


def test_t23_cloudtrail_log_validation_flips_false(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_cloudtrail" "trail" {\n  enable_log_file_validation = false\n}\n')
    t23_cloudtrail_log_file_validation(
        tmp_path, tmp_path / "main.tf", "aws_cloudtrail", "trail", Policy()
    )
    text = _read(tmp_path)
    assert "enable_log_file_validation = true" in text
    assert "enable_log_file_validation = false" not in text


# ---------------------------------------------------------------------------
# T25: ECR KMS encryption
# ---------------------------------------------------------------------------


def test_t25_ecr_kms_encryption_adds_block(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_ecr_repository" "repo" {\n  name = "test"\n}\n')
    result = t25_ecr_kms_encryption(
        tmp_path, tmp_path / "main.tf", "aws_ecr_repository", "repo", Policy()
    )
    text = _read(tmp_path)
    assert result.changed
    assert "encryption_configuration" in text
    assert '"KMS"' in text


def test_t25_ecr_kms_encryption_upgrades_aes256(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        'resource "aws_ecr_repository" "repo" {\n  encryption_configuration {\n    encryption_type = "AES256"\n  }\n}\n',
    )
    t25_ecr_kms_encryption(tmp_path, tmp_path / "main.tf", "aws_ecr_repository", "repo", Policy())
    text = _read(tmp_path)
    assert '"KMS"' in text
    assert '"AES256"' not in text


# ---------------------------------------------------------------------------
# T26: EC2 IMDSv2
# ---------------------------------------------------------------------------


def test_t26_ec2_imdsv2_adds_metadata_options(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        'resource "aws_instance" "web" {\n  ami           = "ami-12345"\n  instance_type = "t3.micro"\n}\n',
    )
    result = t26_ec2_imdsv2(tmp_path, tmp_path / "main.tf", "aws_instance", "web", Policy())
    text = _read(tmp_path)
    assert result.changed
    assert "metadata_options" in text
    assert "http_tokens" in text
    assert '"required"' in text


def test_t26_ec2_imdsv2_patches_existing_block(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        'resource "aws_instance" "web" {\n  metadata_options {\n    http_tokens   = "optional"\n    http_endpoint = "enabled"\n  }\n}\n',
    )
    result = t26_ec2_imdsv2(tmp_path, tmp_path / "main.tf", "aws_instance", "web", Policy())
    text = _read(tmp_path)
    assert result.changed
    assert '"required"' in text
    assert '"optional"' not in text


# ---------------------------------------------------------------------------
# T27: RDS backup retention
# ---------------------------------------------------------------------------


def test_t27_rds_backup_retention_adds_period(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  engine = "mysql"\n}\n')
    result = t27_rds_backup_retention(
        tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy()
    )
    assert result.changed
    assert "backup_retention_period = 7" in _read(tmp_path)


def test_t27_rds_backup_retention_no_change_when_sufficient(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  backup_retention_period = 14\n}\n')
    result = t27_rds_backup_retention(
        tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy()
    )
    assert not result.changed


def test_t27_rds_backup_retention_fixes_zero(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  backup_retention_period = 0\n}\n')
    result = t27_rds_backup_retention(
        tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy()
    )
    assert result.changed
    assert "backup_retention_period = 7" in _read(tmp_path)


# ---------------------------------------------------------------------------
# T28: Secrets Manager KMS
# ---------------------------------------------------------------------------


def test_t28_secretsmanager_kms_adds_key(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_secretsmanager_secret" "sec" {\n  name = "test"\n}\n')
    result = t28_secretsmanager_kms(
        tmp_path, tmp_path / "main.tf", "aws_secretsmanager_secret", "sec", Policy()
    )
    assert result.changed
    assert "kms_key_id" in _read(tmp_path)


def test_t28_secretsmanager_kms_no_change_when_cmk_present(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        'resource "aws_kms_key" "sec_cmk" {}\n\nresource "aws_secretsmanager_secret" "sec" {\n  kms_key_id = aws_kms_key.sec_cmk.arn\n}\n',
    )
    result = t28_secretsmanager_kms(
        tmp_path, tmp_path / "main.tf", "aws_secretsmanager_secret", "sec", Policy()
    )
    assert not result.changed


# ---------------------------------------------------------------------------
# T29: CloudTrail multi-region
# ---------------------------------------------------------------------------


def test_t29_cloudtrail_multi_region_adds_true(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_cloudtrail" "trail" {\n  name = "test"\n}\n')
    result = t29_cloudtrail_multi_region(
        tmp_path, tmp_path / "main.tf", "aws_cloudtrail", "trail", Policy()
    )
    assert result.changed
    assert "is_multi_region_trail = true" in _read(tmp_path)


def test_t29_cloudtrail_multi_region_flips_false(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_cloudtrail" "trail" {\n  is_multi_region_trail = false\n}\n')
    result = t29_cloudtrail_multi_region(
        tmp_path, tmp_path / "main.tf", "aws_cloudtrail", "trail", Policy()
    )
    assert result.changed
    assert "is_multi_region_trail = true" in _read(tmp_path)
    assert "is_multi_region_trail = false" not in _read(tmp_path)


# ---------------------------------------------------------------------------
# T30: RDS storage encrypted
# ---------------------------------------------------------------------------


def test_t30_rds_storage_encrypted_adds_true(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n')
    result = t30_rds_storage_encrypted(
        tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy()
    )
    assert result.changed
    assert "storage_encrypted = true" in _read(tmp_path)


def test_t30_rds_storage_encrypted_no_change_when_true(tmp_path: Path) -> None:
    _tf(tmp_path, 'resource "aws_db_instance" "db" {\n  storage_encrypted = true\n}\n')
    result = t30_rds_storage_encrypted(
        tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy()
    )
    assert not result.changed


# ---------------------------------------------------------------------------
# t11_s3_acl_private: BucketOwnerEnforced guard
# ---------------------------------------------------------------------------


def test_t11_acl_private_skips_when_bucket_owner_enforced(tmp_path: Path) -> None:
    # BucketOwnerEnforced disables ACL support at the AWS API level.
    # t11 must not set acl = "private" on aws_s3_bucket_acl when that mode is active,
    # as it would cause a runtime error ("The bucket does not allow ACLs").
    _tf(
        tmp_path,
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_ownership_controls" "data_ownership_controls" {
          bucket = aws_s3_bucket.data.id
          rule {
            object_ownership = "BucketOwnerEnforced"
          }
        }
        resource "aws_s3_bucket_acl" "data_acl" {
          bucket = aws_s3_bucket.data.id
          acl    = "public-read"
        }
        """,
    )
    result = t11_s3_acl_private(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert not result.changed
    text = _read(tmp_path)
    # ACL resource must remain untouched — public-read is left as-is
    assert '"public-read"' in text


def test_t11_acl_private_applies_when_no_ownership_controls(tmp_path: Path) -> None:
    _tf(
        tmp_path,
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_acl" "data_acl" {
          bucket = aws_s3_bucket.data.id
          acl    = "public-read"
        }
        """,
    )
    result = t11_s3_acl_private(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert result.changed
    assert '"private"' in _read(tmp_path)


# ---------------------------------------------------------------------------
# Cross-cutting: transforms must not modify unrelated resources
# ---------------------------------------------------------------------------


def test_transforms_do_not_touch_unrelated_resources(tmp_path: Path) -> None:
    content = (
        'resource "aws_kms_key" "other" {\n  description = "unrelated"\n}\n\n'
        'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n'
    )
    _tf(tmp_path, content)
    t21_rds_deletion_protection(tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy())
    text = _read(tmp_path)
    # RDS resource patched
    assert "deletion_protection = true" in text
    # KMS resource untouched
    assert 'resource "aws_kms_key" "other"' in text
    assert "enable_key_rotation" not in text
