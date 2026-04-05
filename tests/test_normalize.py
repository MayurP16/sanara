from __future__ import annotations

from sanara.normalize.mapper import normalize_all


def test_checkov_normalization_stable_and_fingerprint() -> None:
    checkov = {
        "results": [
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_3",
                            "severity": "HIGH",
                            "file_path": "main.tf",
                            "file_abs_path": "module",
                            "resource": "aws.ebs_volume.data",
                            "file_line_range": [1, 4],
                        },
                        {
                            "check_id": "CKV_AWS_17",
                            "severity": "MEDIUM",
                            "file_path": "db.tf",
                            "file_abs_path": "module",
                            "resource": "aws.db_instance.main",
                            "file_line_range": [5, 9],
                        },
                    ]
                }
            }
        ]
    }
    mapping = {
        "CKV_AWS_3": "aws.ebs.encrypted",
        "CKV_AWS_17": "aws.rds.not_public",
    }

    out = normalize_all(checkov, mapping)

    assert len(out) == 2
    assert out[0]["sanara_rule_id"] == "aws.ebs.encrypted"
    assert out[1]["sanara_rule_id"] == "aws.rds.not_public"
    assert len(out[0]["fingerprint"]) == 64


def test_checkov_normalization_parses_module_indexed_resource() -> None:
    checkov = {
        "results": [
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_18",
                            "severity": "MEDIUM",
                            "file_path": "examples/complete/main.tf",
                            "file_abs_path": "/tmp/examples/complete/main.tf",
                            "resource": "module.s3_bucket.aws_s3_bucket.this[0]",
                            "file_line_range": [1, 4],
                        }
                    ]
                }
            }
        ]
    }
    mapping = {"CKV_AWS_18": "aws.s3.access_logging_enabled"}
    out = normalize_all(checkov, mapping)
    assert out[0]["resource_type"] == "aws_s3_bucket"
    assert out[0]["resource_name"] == "this"


def test_checkov_normalization_prefers_repo_file_path_over_escaped_file_path() -> None:
    checkov = {
        "results": [
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV2_AWS_6",
                            "severity": "MEDIUM",
                            "file_path": "/../../main.tf",
                            "repo_file_path": "/main.tf",
                            "file_abs_path": "/github/workspace/main.tf",
                            "resource": "module.wrapper.aws_s3_bucket.this",
                            "file_line_range": [45, 57],
                        }
                    ]
                }
            }
        ]
    }
    mapping = {"CKV2_AWS_6": "aws.s3.public_access_block"}

    out = normalize_all(checkov, mapping)

    assert out[0]["target"]["file_path"] == "/main.tf"
    assert out[0]["target"]["module_dir"] == "/github/workspace"


def test_checkov_normalization_uses_file_abs_basename_when_file_path_escapes() -> None:
    checkov = {
        "results": [
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV2_AWS_62",
                            "severity": "MEDIUM",
                            "file_path": "/../../main.tf",
                            "file_abs_path": "/github/workspace/main.tf",
                            "resource": "module.wrapper.aws_s3_bucket.this",
                            "file_line_range": [45, 57],
                        }
                    ]
                }
            }
        ]
    }
    mapping = {"CKV2_AWS_62": "aws.s3.event_notifications_enabled"}

    out = normalize_all(checkov, mapping)

    assert out[0]["target"]["file_path"] == "/main.tf"
    assert out[0]["target"]["module_dir"] == "/github/workspace"


def test_checkov_normalization_deduplicates_after_canonicalizing_paths() -> None:
    checkov = {
        "results": [
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV2_AWS_6",
                            "severity": "MEDIUM",
                            "file_path": "/../../main.tf",
                            "repo_file_path": "/main.tf",
                            "file_abs_path": "/github/workspace/main.tf",
                            "resource": "module.wrapper.aws_s3_bucket.this",
                            "file_line_range": [45, 57],
                        },
                        {
                            "check_id": "CKV2_AWS_6",
                            "severity": "MEDIUM",
                            "file_path": "/../main.tf",
                            "repo_file_path": "/main.tf",
                            "file_abs_path": "/github/workspace/main.tf",
                            "resource": "module.wrapper.aws_s3_bucket.this",
                            "file_line_range": [45, 57],
                        },
                        {
                            "check_id": "CKV2_AWS_6",
                            "severity": "MEDIUM",
                            "file_path": "/main.tf",
                            "repo_file_path": "/main.tf",
                            "file_abs_path": "/github/workspace/main.tf",
                            "resource": "module.wrapper.aws_s3_bucket.this",
                            "file_line_range": [45, 57],
                        },
                    ]
                }
            }
        ]
    }
    mapping = {"CKV2_AWS_6": "aws.s3.public_access_block"}

    out = normalize_all(checkov, mapping)

    assert len(out) == 1
    assert out[0]["target"]["file_path"] == "/main.tf"


def test_checkov_normalization_preserves_module_instance_identity_in_fingerprint() -> None:
    checkov = {
        "results": [
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV2_AWS_6",
                            "severity": "MEDIUM",
                            "file_path": "/main.tf",
                            "repo_file_path": "/main.tf",
                            "file_abs_path": "/github/workspace/main.tf",
                            "resource": "module.wrapper.aws_s3_bucket.this",
                            "file_line_range": [45, 57],
                        },
                        {
                            "check_id": "CKV2_AWS_6",
                            "severity": "MEDIUM",
                            "file_path": "/main.tf",
                            "repo_file_path": "/main.tf",
                            "file_abs_path": "/github/workspace/main.tf",
                            "resource": "module.disabled.aws_s3_bucket.this[0]",
                            "file_line_range": [45, 57],
                        },
                    ]
                }
            }
        ]
    }
    mapping = {"CKV2_AWS_6": "aws.s3.public_access_block"}

    out = normalize_all(checkov, mapping)

    assert len(out) == 2
    assert len({item["fingerprint"] for item in out}) == 2
