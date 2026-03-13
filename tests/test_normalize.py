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
