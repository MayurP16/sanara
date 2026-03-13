#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def parse_target(args: list[str]) -> Path:
    target = "."
    for i, arg in enumerate(args):
        if arg == "-d" and i + 1 < len(args):
            target = args[i + 1]
            break
    return Path(target)


def main() -> int:
    target = parse_target(sys.argv[1:])
    tf_files = sorted(target.rglob("*.tf"))
    file_text = {p: p.read_text(encoding="utf-8") for p in tf_files}
    text = "\n".join(file_text.values())

    failed: list[dict[str, object]] = []

    def find_file(resource_type: str, resource_name: str) -> str:
        needle = f'resource "{resource_type}" "{resource_name}"'
        for p, content in file_text.items():
            if needle in content:
                return str(p.relative_to(target))
        return "main.tf"

    def add(check_id: str, resource: str, file_path: str | None = None) -> None:
        if file_path is None:
            parts = resource.split(".", 1)
            if len(parts) == 2:
                file_path = find_file(parts[0], parts[1])
            else:
                file_path = "main.tf"
        failed.append(
            {
                "check_id": check_id,
                "severity": "HIGH",
                "file_path": file_path,
                "file_abs_path": str((target / file_path).resolve()),
                "resource": resource,
                "file_line_range": [1, 2],
            }
        )

    if 'resource "aws_s3_bucket" "logs"' in text:
        has_pab = 'resource "aws_s3_bucket_public_access_block" "logs_pab"' in text
        has_sse = (
            'resource "aws_s3_bucket_server_side_encryption_configuration" "logs_sse"' in text
            and ('sse_algorithm = "AES256"' in text or 'sse_algorithm = "aws:kms"' in text)
        )
        has_ver = (
            'resource "aws_s3_bucket_versioning" "logs_versioning"' in text
            and 'status = "Enabled"' in text
        )
        if not has_pab:
            add("CKV2_AWS_6", "aws_s3_bucket.logs")
        if not has_sse:
            add("CKV_AWS_19", "aws_s3_bucket.logs")
        if not has_ver:
            add("CKV_AWS_21", "aws_s3_bucket.logs")

    if 'resource "aws_db_instance" "app"' in text and not re.search(
        r"publicly_accessible\s*=\s*false", text
    ):
        add("CKV_AWS_17", "aws_db_instance.app")

    if 'resource "aws_ebs_volume" "data"' in text and not re.search(r"encrypted\s*=\s*true", text):
        add("CKV_AWS_3", "aws_ebs_volume.data")

    if 'resource "aws_ebs_encryption_by_default" "this"' not in text:
        add("CKV_AWS_106", "aws_ebs_volume.data")

    if 'resource "aws_sns_topic" "alerts"' in text and not re.search(
        r'kms_master_key_id\s*=\s*"alias/aws/sns"', text
    ):
        add("CKV_AWS_26", "aws_sns_topic.alerts")

    if 'resource "aws_sqs_queue" "events"' in text and not re.search(
        r'kms_master_key_id\s*=\s*"alias/aws/sqs"', text
    ):
        add("CKV_AWS_27", "aws_sqs_queue.events")

    has_pitr = (
        'resource "aws_dynamodb_table" "events"' in text
        and "point_in_time_recovery" in text
        and "enabled = true" in text
    )
    if not has_pitr:
        add("CKV_AWS_28", "aws_dynamodb_table.events")

    if 'resource "aws_cloudwatch_log_group" "app"' in text and not re.search(
        r'kms_key_id\s*=\s*"alias/aws/logs"', text
    ):
        add("CKV_AWS_158", "aws_cloudwatch_log_group.app")

    print(json.dumps({"results": {"failed_checks": failed}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
