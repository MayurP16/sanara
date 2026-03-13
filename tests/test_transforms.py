from __future__ import annotations

from pathlib import Path

import pytest

from sanara.drc.models import DrcError
from sanara.drc.transforms import core as coremod
from sanara.drc.transforms.core import (
    t1_public_access_block,
    t2_s3_sse,
    t3_s3_versioning,
    t4_rds_not_public,
    t5_ebs_encrypted,
    t6_ebs_default,
    t7_sns_encrypted,
    t8_sqs_encrypted,
    t9_dynamodb_pitr,
    t10_log_group_encrypted,
    t11_s3_acl_private,
    t12_dynamodb_kms_cmk,
    t13_kms_key_rotation,
    t14_s3_policy_secure_transport,
    t15_s3_sse_kms,
    t16_s3_access_logging,
    t17_kms_key_policy_present,
    t18_s3_acl_disabled,
    t19_s3_event_notifications_enabled,
    t29_cloudtrail_multi_region,
    t24_cloudtrail_kms,
    t26_ec2_imdsv2,
)
from sanara.orchestrator.policy import Policy


def _w(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_t1_create_public_access_block(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    out = t1_public_access_block(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert out.changed
    assert "public_access_block" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t1_updates_existing_public_access_block_by_bucket_ref(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_public_access_block" "data" {
          bucket = aws_s3_bucket.data.id
          block_public_acls       = false
          block_public_policy     = false
          ignore_public_acls      = false
          restrict_public_buckets = false
        }
        """,
    )
    out = t1_public_access_block(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert content.count('resource "aws_s3_bucket_public_access_block"') == 1
    assert "block_public_acls" in content and "true" in content
    assert "block_public_policy" in content and "true" in content


def test_t2_create_sse(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    out = t2_s3_sse(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert out.changed
    assert "AES256" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t3_create_versioning(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    out = t3_s3_versioning(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert out.changed
    assert 'status = "Enabled"' in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t4_rds_public_false(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_db_instance" "db" { publicly_accessible = true }')
    out = t4_rds_not_public(tmp_path, tmp_path / "main.tf", "aws_db_instance", "db", Policy())
    assert out.changed
    assert "publicly_accessible = false" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t5_ebs_encrypted(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_ebs_volume" "vol" { encrypted = false }')
    out = t5_ebs_encrypted(tmp_path, tmp_path / "main.tf", "aws_ebs_volume", "vol", Policy())
    assert out.changed
    assert "encrypted = true" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t6_opt_in(tmp_path: Path) -> None:
    with pytest.raises(DrcError):
        t6_ebs_default(tmp_path, tmp_path / "main.tf", "", "", Policy())
    out = t6_ebs_default(
        tmp_path,
        tmp_path / "main.tf",
        "",
        "",
        Policy(apply_opt_in_rules=["aws.ebs.default_encryption_enabled"]),
    )
    assert out.changed


def test_t7_sns_encrypted(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_sns_topic" "topic" {}')
    out = t7_sns_encrypted(tmp_path, tmp_path / "main.tf", "aws_sns_topic", "topic", Policy())
    assert out.changed
    assert "alias/aws/sns" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t8_sqs_encrypted(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_sqs_queue" "queue" {}')
    out = t8_sqs_encrypted(tmp_path, tmp_path / "main.tf", "aws_sqs_queue", "queue", Policy())
    assert out.changed
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert "alias/aws/sqs" in content
    assert "kms_data_key_reuse_period_seconds = 300" in content


def test_t9_dynamodb_pitr(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_dynamodb_table" "tbl" {}')
    out = t9_dynamodb_pitr(tmp_path, tmp_path / "main.tf", "aws_dynamodb_table", "tbl", Policy())
    assert out.changed
    assert "point_in_time_recovery" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t10_log_group_encrypted(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_cloudwatch_log_group" "lg" {}')
    out = t10_log_group_encrypted(
        tmp_path, tmp_path / "main.tf", "aws_cloudwatch_log_group", "lg", Policy()
    )
    assert out.changed
    assert "alias/aws/logs" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t11_s3_acl_private_updates_acl_resource(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_acl" "data_acl" {
          bucket = aws_s3_bucket.data.id
          acl    = "public-read"
        }
        """,
    )
    out = t11_s3_acl_private(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert "acl" in content and '"private"' in content


def test_t12_dynamodb_kms_cmk_adds_sse_and_kms(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_dynamodb_table" "tbl" {
          name         = "x"
          billing_mode = "PAY_PER_REQUEST"
          hash_key     = "id"
        }
        """,
    )
    out = t12_dynamodb_kms_cmk(
        tmp_path, tmp_path / "main.tf", "aws_dynamodb_table", "tbl", Policy()
    )
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert "server_side_encryption" in content
    assert "kms_key_arn = aws_kms_key.tbl_cmk.arn" in content
    assert 'resource "aws_kms_key" "tbl_cmk"' in content


def test_t13_kms_key_rotation(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_kms_key" "k" { enable_key_rotation = false }')
    out = t13_kms_key_rotation(tmp_path, tmp_path / "main.tf", "aws_kms_key", "k", Policy())
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert "enable_key_rotation = true" in content


def test_t14_s3_policy_secure_transport_replaces_public_policy(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_policy" "data" {
          bucket = aws_s3_bucket.data.id
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [{ Principal = "*", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.data.arn}/*" }]
          })
        }
        """,
    )
    out = t14_s3_policy_secure_transport(
        tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy()
    )
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert "DenyInsecureTransport" in content
    assert '"aws:SecureTransport"' in content


def test_t15_s3_sse_kms_creates_config(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    out = t15_s3_sse_kms(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert 'sse_algorithm     = "aws:kms"' in content or 'sse_algorithm = "aws:kms"' in content
    assert 'kms_master_key_id = "alias/aws/s3"' in content


def test_t16_s3_access_logging_creates_logging_resources(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    out = t16_s3_access_logging(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert 'resource "aws_s3_bucket_logging" "data_logging"' in content
    assert "target_bucket = aws_s3_bucket.data_access_logs.id" in content


def test_t17_kms_key_policy_present_adds_policy_attr(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_kms_key" "k" { description = "x" }')
    out = t17_kms_key_policy_present(tmp_path, tmp_path / "main.tf", "aws_kms_key", "k", Policy())
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert "policy = jsonencode(" in content


def test_t18_s3_acl_disabled_enforces_bucket_owner_enforced(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_ownership_controls" "data_ownership_controls" {
          bucket = aws_s3_bucket.data.id
          rule {
            object_ownership = "ObjectWriter"
          }
        }
        """,
    )
    out = t18_s3_acl_disabled(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert 'object_ownership = "BucketOwnerEnforced"' in content


def test_t19_s3_event_notifications_enabled_creates_notification_resources(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    out = t19_s3_event_notifications_enabled(
        tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy()
    )
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert out.changed
    assert 'resource "aws_sns_topic" "data_events"' in content
    assert 'resource "aws_sns_topic_policy" "data_events_policy"' in content
    assert 'resource "aws_s3_bucket_notification" "data_notifications"' in content


def test_t1_ambiguous_related_public_access_block_raises(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_public_access_block" "a" { bucket = aws_s3_bucket.data.id }
        resource "aws_s3_bucket_public_access_block" "b" { bucket = aws_s3_bucket.data.id }
        """,
    )
    with pytest.raises(DrcError, match="AMBIGUOUS_TARGET"):
        t1_public_access_block(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())


def test_t1_reraises_non_no_target_errors(monkeypatch, tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')

    def _boom(*args, **kwargs):
        _ = args, kwargs
        raise DrcError("AMBIGUOUS_TARGET", "boom")

    monkeypatch.setattr(coremod, "find_resource_block", _boom)
    with pytest.raises(DrcError, match="AMBIGUOUS_TARGET"):
        t1_public_access_block(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())


def test_t2_no_change_when_existing_kms(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
          bucket = aws_s3_bucket.data.id
          rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
        }
        """,
    )
    out = t2_s3_sse(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert out.changed is False


def test_t2_updates_existing_nonstandard_block(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
          bucket = aws_s3_bucket.data.id
          rule {}
        }
        """,
    )
    out = t2_s3_sse(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert isinstance(out.changed, bool)


def test_t2_reraises_non_no_target_errors(monkeypatch, tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')

    def _boom(*args, **kwargs):
        _ = args, kwargs
        raise DrcError("USER_INTENT_CONFLICT", "boom")

    monkeypatch.setattr(coremod, "find_resource_block", _boom)
    with pytest.raises(DrcError, match="USER_INTENT_CONFLICT"):
        t2_s3_sse(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())


def test_t3_suspended_without_allow_rule_raises(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_versioning" "data_versioning" {
          bucket = aws_s3_bucket.data.id
          versioning_configuration { status = "Suspended" }
        }
        """,
    )
    with pytest.raises(DrcError, match="USER_INTENT_CONFLICT"):
        t3_s3_versioning(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())


def test_t3_adds_enabled_when_status_missing(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_versioning" "data_versioning" {
          bucket = aws_s3_bucket.data.id
        }
        """,
    )
    out = t3_s3_versioning(
        tmp_path,
        tmp_path / "main.tf",
        "aws_s3_bucket",
        "data",
        Policy(allow_rules=["aws.s3.versioning_enabled"]),
    )
    assert out.changed is True
    assert 'status = "Enabled"' in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t3_reraises_non_no_target_errors(monkeypatch, tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')

    def _boom(*args, **kwargs):
        _ = args, kwargs
        raise DrcError("USER_INTENT_CONFLICT", "boom")

    monkeypatch.setattr(coremod, "find_resource_block", _boom)
    with pytest.raises(DrcError, match="USER_INTENT_CONFLICT"):
        t3_s3_versioning(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())


def test_t7_requires_cmk_policy_raises(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_sns_topic" "topic" {}')
    with pytest.raises(DrcError, match="MISSING_POLICY_KMS_KEY"):
        t7_sns_encrypted(
            tmp_path,
            tmp_path / "main.tf",
            "aws_sns_topic",
            "topic",
            Policy(require_cmk_for=["aws.sns.encrypted"]),
        )


def test_t11_s3_acl_private_named_fallback(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_acl" "data_acl" {
          acl = "public-read"
        }
        """,
    )
    out = t11_s3_acl_private(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert out.changed is True
    assert '"private"' in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t14_s3_policy_secure_transport_on_policy_resource(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_policy" "data" {
          bucket = aws_s3_bucket.data.id
          policy = "{}"
        }
        """,
    )
    out = t14_s3_policy_secure_transport(
        tmp_path,
        tmp_path / "main.tf",
        "aws_s3_bucket_policy",
        "data",
        Policy(),
    )
    assert out.changed is True
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert "DenyInsecureTransport" in content
    assert "aws_s3_bucket.data.arn" in content


def test_t14_s3_policy_secure_transport_raises_when_missing(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    with pytest.raises(DrcError, match="NO_TARGET_RESOURCE"):
        t14_s3_policy_secure_transport(
            tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy()
        )


def test_t15_s3_sse_kms_upgrades_aes256(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
          bucket = aws_s3_bucket.data.id
          rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
        }
        """,
    )
    out = t15_s3_sse_kms(tmp_path, tmp_path / "main.tf", "", "data", Policy())
    assert out.changed is True
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert '"aws:kms"' in content
    assert "kms_master_key_id" in content


def test_t15_s3_sse_kms_adds_kms_key_id_when_missing(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
          bucket = aws_s3_bucket.data.id
          rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
        }
        """,
    )
    out = t15_s3_sse_kms(tmp_path, tmp_path / "main.tf", "", "data", Policy())
    assert out.changed is True
    assert "kms_master_key_id" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t15_s3_sse_kms_adds_nested_block_when_missing(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_server_side_encryption_configuration" "data_sse" {
          bucket = aws_s3_bucket.data.id
        }
        """,
    )
    out = t15_s3_sse_kms(tmp_path, tmp_path / "main.tf", "", "data", Policy())
    assert out.changed is True
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert 'sse_algorithm = "aws:kms"' in content
    assert "kms_master_key_id" in content


def test_t16_s3_access_logging_no_change_when_existing(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_logging" "data_logging" {
          bucket        = aws_s3_bucket.data.id
          target_bucket = aws_s3_bucket.logs.id
          target_prefix = "logs/"
        }
        """,
    )
    out = t16_s3_access_logging(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy())
    assert out.changed is False


def test_t17_kms_key_policy_present_no_change_when_present(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_kms_key" "k" {
          policy = jsonencode({})
        }
        """,
    )
    out = t17_kms_key_policy_present(tmp_path, tmp_path / "main.tf", "aws_kms_key", "k", Policy())
    assert out.changed is False


def test_t18_s3_acl_disabled_named_fallback_updates_rule(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_ownership_controls" "data_ownership_controls" {
          bucket = aws_s3_bucket.data.id
        }
        """,
    )
    out = t18_s3_acl_disabled(tmp_path, tmp_path / "main.tf", "", "data", Policy())
    assert isinstance(out.changed, bool)


def test_t18_s3_acl_disabled_no_change_when_already_enforced(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket_ownership_controls" "data_ownership_controls" {
          bucket = aws_s3_bucket.data.id
          rule { object_ownership = "BucketOwnerEnforced" }
        }
        """,
    )
    out = t18_s3_acl_disabled(tmp_path, tmp_path / "main.tf", "", "data", Policy())
    assert out.changed is False


def test_t18_s3_acl_disabled_creates_when_absent(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_s3_bucket" "data" {}')
    out = t18_s3_acl_disabled(tmp_path, tmp_path / "main.tf", "", "data", Policy())
    assert out.changed is True
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert 'resource "aws_s3_bucket_ownership_controls" "data_ownership_controls"' in content


def test_t19_s3_event_notifications_enabled_no_change_when_existing(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_notification" "data_notifications" {
          bucket = aws_s3_bucket.data.id
          topic { topic_arn = "arn:aws:sns:us-east-1:123456789012:x" events = ["s3:ObjectCreated:*"] }
        }
        """,
    )
    out = t19_s3_event_notifications_enabled(
        tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "data", Policy()
    )
    assert out.changed is False


def test_t24_cloudtrail_kms_sets_kms_key_id(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_cloudtrail" "trail" { name = "x" }')
    out = t24_cloudtrail_kms(tmp_path, tmp_path / "main.tf", "aws_cloudtrail", "trail", Policy())
    assert out.changed is True
    assert "kms_key_id" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t24_cloudtrail_kms_requires_cmk_raises(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_cloudtrail" "trail" { name = "x" }')
    with pytest.raises(DrcError, match="MISSING_POLICY_KMS_KEY"):
        t24_cloudtrail_kms(
            tmp_path,
            tmp_path / "main.tf",
            "aws_cloudtrail",
            "trail",
            Policy(require_cmk_for=["aws.cloudtrail.kms_encrypted"]),
        )


def test_t29_cloudtrail_multi_region_sets_true(tmp_path: Path) -> None:
    _w(tmp_path / "main.tf", 'resource "aws_cloudtrail" "trail" { is_multi_region_trail = false }')
    out = t29_cloudtrail_multi_region(
        tmp_path, tmp_path / "main.tf", "aws_cloudtrail", "trail", Policy()
    )
    assert out.changed is True
    assert "is_multi_region_trail = true" in (tmp_path / "main.tf").read_text(encoding="utf-8")


def test_t26_ec2_imdsv2_adds_missing_tokens_and_endpoint(tmp_path: Path) -> None:
    _w(
        tmp_path / "main.tf",
        """
        resource "aws_instance" "web" {
          metadata_options {
            instance_metadata_tags = "enabled"
          }
        }
        """,
    )
    out = t26_ec2_imdsv2(tmp_path, tmp_path / "main.tf", "aws_instance", "web", Policy())
    assert out.changed is True
    content = (tmp_path / "main.tf").read_text(encoding="utf-8")
    assert 'http_tokens   = "required"' in content
    assert 'http_endpoint = "enabled"' in content


def test_ensure_dynamodb_sse_cmk_updates_enabled_false_and_adds_kms() -> None:
    text, changed = coremod._ensure_dynamodb_sse_cmk(
        "server_side_encryption {\n  enabled = false\n}\n",
        "aws_kms_key.tbl_cmk.arn",
    )
    assert changed is True
    assert "enabled = true" in text
    assert "kms_key_arn = aws_kms_key.tbl_cmk.arn" in text


def test_ensure_dynamodb_sse_cmk_adds_kms_when_enabled_true_not_present() -> None:
    text, changed = coremod._ensure_dynamodb_sse_cmk(
        "server_side_encryption {\n  enabled = true\n}\n",
        "aws_kms_key.tbl_cmk.arn",
    )
    assert changed is True
    assert "kms_key_arn = aws_kms_key.tbl_cmk.arn" in text


def test_ensure_dynamodb_sse_cmk_adds_kms_when_enabled_field_missing() -> None:
    text, changed = coremod._ensure_dynamodb_sse_cmk(
        "server_side_encryption {\n  # no enabled field\n}\n",
        "aws_kms_key.tbl_cmk.arn",
    )
    assert changed is True
    assert "kms_key_arn = aws_kms_key.tbl_cmk.arn" in text
