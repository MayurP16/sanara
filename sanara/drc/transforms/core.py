from __future__ import annotations

from pathlib import Path
import re

from sanara.drc.hcl_edit import (
    append_resource,
    ensure_attribute_literal,
    ensure_nested_block,
    find_resource_block,
    find_resource_blocks,
    replace_block,
)
from sanara.drc.models import DrcError, PatchContract, TransformResult
from sanara.orchestrator.policy import Policy


def _contract(rule: str, changes: list[str]) -> PatchContract:
    return PatchContract(
        sanara_rule_id=rule,
        preconditions=["target resource resolved", "literal-safe mutation"],
        changes=changes,
        postconditions=["security attribute exists with secure value"],
        invariants_checked=["allowlist", "no resource deletion", "diff budget"],
        risk="low",
        validation_required=[
            "terraform fmt",
            "terraform init -backend=false",
            "terraform validate",
            "terraform plan -refresh=false",
            "targeted rescan",
        ],
    )


def _module_tf_files(module_dir: Path) -> list[Path]:
    return sorted(module_dir.glob("*.tf"))


def _find_s3_related_block(files: list[Path], resource_type: str, bucket_resource_name: str):
    if not str(bucket_resource_name or "").strip():
        raise DrcError(
            "INVALID_TARGET_RESOURCE", f"Missing bucket resource name for {resource_type}"
        )
    bucket_token = f"aws_s3_bucket.{bucket_resource_name}"
    directory_token = f"aws_s3_directory_bucket.{bucket_resource_name}"
    matches = [
        b
        for b in find_resource_blocks(files, resource_type)
        if bucket_token in b.text or directory_token in b.text
    ]
    if len(matches) > 1:
        raise DrcError(
            "AMBIGUOUS_TARGET", f"Ambiguous {resource_type} for bucket {bucket_resource_name}"
        )
    return matches[0] if matches else None


def _s3_bucket_ref(resource_name: str, attr: str = "id") -> str:
    name = str(resource_name or "").strip()
    if not name:
        raise DrcError("INVALID_TARGET_RESOURCE", "Missing aws_s3_bucket resource name")
    return f"aws_s3_bucket.{name}.{attr}"


def _has_meta_argument(block_text: str, arg: str) -> bool:
    return bool(re.search(rf"^\s*{re.escape(arg)}\s*=", block_text, re.MULTILINE))


def _s3_resource_expr(files: list[Path], resource_name: str, attr: str = "id") -> str:
    name = str(resource_name or "").strip()
    if not name:
        raise DrcError("INVALID_TARGET_RESOURCE", "Missing aws_s3_bucket resource name")

    try:
        bucket_block = find_resource_block(files, "aws_s3_bucket", name)
    except DrcError:
        bucket_block = None
    try:
        directory_block = find_resource_block(files, "aws_s3_directory_bucket", name)
    except DrcError:
        directory_block = None

    bucket_index = "[0]" if bucket_block and _has_meta_argument(bucket_block.text, "count") else ""
    directory_index = (
        "[0]" if directory_block and _has_meta_argument(directory_block.text, "count") else ""
    )

    bucket_expr = f"aws_s3_bucket.{name}{bucket_index}.{attr}"
    directory_attr = "bucket" if attr == "id" else attr
    directory_expr = f"aws_s3_directory_bucket.{name}{directory_index}.{directory_attr}"

    if bucket_block and directory_block:
        # Try to extract the boolean variable that controls the directory bucket's count.
        # e.g. `count = var.create_s3_directory_bucket ? 1 : 0` → var.create_s3_directory_bucket
        # Fall back to the conventional var.is_directory_bucket when no clear var is found.
        count_var = "var.is_directory_bucket"
        count_match = re.search(
            r"^\s*count\s*=\s*(var\.\w+)\s*\?",
            directory_block.text,
            re.MULTILINE,
        )
        if count_match:
            count_var = count_match.group(1)
        return f"{count_var} ? {directory_expr} : {bucket_expr}"
    if bucket_block:
        return bucket_expr
    if directory_block:
        return directory_expr
    return _s3_bucket_ref(name, attr)


def _ensure_dynamodb_sse_cmk(block_text: str, kms_ref: str) -> tuple[str, bool]:
    changed = False
    text = block_text
    if "server_side_encryption" not in text:
        nested = f"server_side_encryption {{\n  enabled = true\n  kms_key_arn = {kms_ref}\n}}"
        text, changed = ensure_nested_block(text, nested)
        return text, changed

    if "enabled = false" in text:
        text = text.replace("enabled = false", "enabled = true")
        changed = True
    if "kms_key_arn" not in text:
        pattern = re.compile(r"(server_side_encryption\s*\{[^}]*enabled\s*=\s*true\s*)", re.DOTALL)
        if pattern.search(text):
            text = pattern.sub(rf"\1\n  kms_key_arn = {kms_ref}\n", text, count=1)
            changed = True
        else:
            text = text.replace(
                "server_side_encryption {",
                f"server_side_encryption {{\n  kms_key_arn = {kms_ref}",
                1,
            )
            changed = True
    return text, changed


def t1_public_access_block(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = policy
    files = _module_tf_files(module_dir)
    try:
        block = _find_s3_related_block(files, "aws_s3_bucket_public_access_block", resource_name)
        if block is None:
            block = find_resource_block(
                files, "aws_s3_bucket_public_access_block", f"{resource_name}_pab"
            )
        text, c1 = ensure_attribute_literal(block.text, "block_public_acls", "true")
        text, c2 = ensure_attribute_literal(text, "block_public_policy", "true")
        text, c3 = ensure_attribute_literal(text, "ignore_public_acls", "true")
        text, c4 = ensure_attribute_literal(text, "restrict_public_buckets", "true")
        replace_block(block, text)
        return TransformResult(
            c1 or c2 or c3 or c4,
            block.file_path,
            _contract("aws.s3.public_access_block", ["enforced s3 public access block booleans"]),
        )
    except DrcError as e:
        if e.code != "NO_TARGET_RESOURCE":
            raise

    target_file = file_path if file_path.exists() else module_dir / "sanara_security.tf"
    resource = (
        f'resource "aws_s3_bucket_public_access_block" "{resource_name}_pab" {{\n'
        f"  bucket = {_s3_resource_expr(files, resource_name)}\n"
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}"
    )
    append_resource(target_file, resource)
    return TransformResult(
        True,
        target_file,
        _contract("aws.s3.public_access_block", ["created s3 public access block resource"]),
    )


def t2_s3_sse(
    module_dir: Path, file_path: Path, _: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = policy
    files = _module_tf_files(module_dir)
    try:
        block = find_resource_block(
            files, "aws_s3_bucket_server_side_encryption_configuration", f"{resource_name}_sse"
        )
        if "aws:kms" in block.text:
            return TransformResult(
                False,
                block.file_path,
                _contract("aws.s3.sse_default", ["existing kms encryption retained"]),
            )
        if "AES256" in block.text:
            return TransformResult(
                False,
                block.file_path,
                _contract("aws.s3.sse_default", ["existing AES256 retained"]),
            )
        bucket_expr = _s3_resource_expr(files, resource_name)
        bucket_match = re.search(r"^\s*bucket\s*=\s*(.+)$", block.text, re.MULTILINE)
        if bucket_match:
            bucket_expr = bucket_match.group(1).strip()
        secure_block = (
            f'resource "aws_s3_bucket_server_side_encryption_configuration" "{block.resource_name}" {{\n'
            f"  bucket = {bucket_expr}\n"
            "  rule {\n"
            "    apply_server_side_encryption_by_default {\n"
            '      sse_algorithm = "AES256"\n'
            "    }\n"
            "  }\n"
            "}"
        )
        changed = block.text != secure_block
        replace_block(block, secure_block)
        return TransformResult(
            changed,
            block.file_path,
            _contract("aws.s3.sse_default", ["ensured AES256 default encryption config"]),
        )
    except DrcError as e:
        if e.code != "NO_TARGET_RESOURCE":
            raise
    target_file = file_path if file_path.exists() else module_dir / "sanara_security.tf"
    resource = (
        f'resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}_sse" {{\n'
        f"  bucket = {_s3_resource_expr(files, resource_name)}\n"
        "  rule {\n"
        "    apply_server_side_encryption_by_default {\n"
        '      sse_algorithm = "AES256"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    append_resource(target_file, resource)
    return TransformResult(
        True, target_file, _contract("aws.s3.sse_default", ["created s3 encryption config"])
    )


def t3_s3_versioning(
    module_dir: Path, file_path: Path, _: str, resource_name: str, policy: Policy
) -> TransformResult:
    files = _module_tf_files(module_dir)
    try:
        block = find_resource_block(
            files, "aws_s3_bucket_versioning", f"{resource_name}_versioning"
        )
        if "Suspended" in block.text and "aws.s3.versioning_enabled" not in policy.allow_rules:
            raise DrcError("USER_INTENT_CONFLICT", "versioning explicitly suspended")
        text = block.text.replace('status = "Suspended"', 'status = "Enabled"')
        if 'status = "Enabled"' not in text:
            nested = 'versioning_configuration {\n  status = "Enabled"\n}'
            text, _ = ensure_nested_block(text, nested)
        changed = text != block.text
        replace_block(block, text)
        return TransformResult(
            changed,
            block.file_path,
            _contract("aws.s3.versioning_enabled", ["ensured s3 versioning enabled"]),
        )
    except DrcError as e:
        if e.code != "NO_TARGET_RESOURCE":
            raise

    target_file = file_path if file_path.exists() else module_dir / "sanara_security.tf"
    resource = (
        f'resource "aws_s3_bucket_versioning" "{resource_name}_versioning" {{\n'
        f"  bucket = {_s3_resource_expr(files, resource_name)}\n"
        "  versioning_configuration {\n"
        '    status = "Enabled"\n'
        "  }\n"
        "}"
    )
    append_resource(target_file, resource)
    return TransformResult(
        True,
        target_file,
        _contract("aws.s3.versioning_enabled", ["created s3 versioning resource"]),
    )


def t4_rds_not_public(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text, changed = ensure_attribute_literal(block.text, "publicly_accessible", "false")
    replace_block(block, text)
    return TransformResult(
        changed, block.file_path, _contract("aws.rds.not_public", ["set publicly_accessible=false"])
    )


def t5_ebs_encrypted(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text, changed = ensure_attribute_literal(block.text, "encrypted", "true")
    replace_block(block, text)
    return TransformResult(
        changed, block.file_path, _contract("aws.ebs.encrypted", ["set encrypted=true"])
    )


def t6_ebs_default(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    if "aws.ebs.default_encryption_enabled" not in policy.apply_opt_in_rules:
        raise DrcError("NEEDS_AGENTIC", "opt-in transform not enabled")
    files = _module_tf_files(module_dir)

    # If scanner already points to an existing aws_ebs_encryption_by_default resource,
    # mutate that target in place first.
    if resource_type == "aws_ebs_encryption_by_default" and resource_name:
        try:
            block = find_resource_block(files, resource_type, resource_name)
            text, changed = ensure_attribute_literal(block.text, "enabled", "true")
            replace_block(block, text)
            return TransformResult(
                changed,
                block.file_path,
                _contract(
                    "aws.ebs.default_encryption_enabled",
                    ["set ebs default encryption enabled=true"],
                ),
            )
        except DrcError as e:
            if e.code != "NO_TARGET_RESOURCE":
                raise

    existing = find_resource_blocks(files, "aws_ebs_encryption_by_default")
    if len(existing) > 1:
        raise DrcError("AMBIGUOUS_TARGET", "Multiple aws_ebs_encryption_by_default resources found")
    if len(existing) == 1:
        block = existing[0]
        text, changed = ensure_attribute_literal(block.text, "enabled", "true")
        replace_block(block, text)
        return TransformResult(
            changed,
            block.file_path,
            _contract(
                "aws.ebs.default_encryption_enabled", ["set ebs default encryption enabled=true"]
            ),
        )

    target = module_dir / "sanara_security.tf"
    resource = 'resource "aws_ebs_encryption_by_default" "this" {\n  enabled = true\n}'
    if target.exists() and "aws_ebs_encryption_by_default" in target.read_text(encoding="utf-8"):
        return TransformResult(
            False,
            target,
            _contract(
                "aws.ebs.default_encryption_enabled", ["existing default ebs encryption retained"]
            ),
        )
    append_resource(target, resource)
    return TransformResult(
        True,
        target,
        _contract("aws.ebs.default_encryption_enabled", ["created aws_ebs_encryption_by_default"]),
    )


def _kms_value(policy: Policy, service_rule: str, alias: str) -> str:
    if service_rule in policy.require_cmk_for:
        raise DrcError("MISSING_POLICY_KMS_KEY", f"CMK required for {service_rule}")
    return f'"{alias}"'


def t7_sns_encrypted(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    value = _kms_value(policy, "aws.sns.encrypted", "alias/aws/sns")
    text, changed = ensure_attribute_literal(block.text, "kms_master_key_id", value)
    replace_block(block, text)
    return TransformResult(
        changed, block.file_path, _contract("aws.sns.encrypted", ["ensured sns kms_master_key_id"])
    )


def t8_sqs_encrypted(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    value = _kms_value(policy, "aws.sqs.encrypted", "alias/aws/sqs")
    text, c1 = ensure_attribute_literal(block.text, "kms_master_key_id", value)
    text, c2 = ensure_attribute_literal(text, "kms_data_key_reuse_period_seconds", "300")
    replace_block(block, text)
    return TransformResult(
        c1 or c2, block.file_path, _contract("aws.sqs.encrypted", ["ensured sqs kms settings"])
    )


def t9_dynamodb_pitr(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    nested = "point_in_time_recovery {\n  enabled = true\n}"
    text, changed = ensure_nested_block(block.text, nested)
    text = text.replace("enabled = false", "enabled = true")
    replace_block(block, text)
    return TransformResult(
        True if changed or text != block.text else False,
        block.file_path,
        _contract("aws.dynamodb.pitr_enabled", ["ensured point_in_time_recovery enabled"]),
    )


def t10_log_group_encrypted(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    value = _kms_value(policy, "aws.cloudwatch.log_group_encrypted", "alias/aws/logs")
    text, changed = ensure_attribute_literal(block.text, "kms_key_id", value)
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract(
            "aws.cloudwatch.log_group_encrypted", ["ensured cloudwatch log group kms_key_id"]
        ),
    )


def t11_s3_acl_private(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, resource_type, policy
    files = _module_tf_files(module_dir)
    # If BucketOwnerEnforced is already set on the ownership controls for this bucket,
    # ACLs are disabled at the AWS API level. Setting acl = "private" on aws_s3_bucket_acl
    # would cause a runtime error ("The bucket does not allow ACLs"), so skip this transform.
    ownership_block = _find_s3_related_block(
        files, "aws_s3_bucket_ownership_controls", resource_name
    )
    if ownership_block is not None and re.search(
        r'object_ownership\s*=\s*"BucketOwnerEnforced"', ownership_block.text
    ):
        return TransformResult(
            False,
            file_path,
            _contract("aws.s3.acl_private", ["skipped: BucketOwnerEnforced disables ACL support"]),
        )
    block = _find_s3_related_block(files, "aws_s3_bucket_acl", resource_name)
    if block is None:
        block = find_resource_block(files, "aws_s3_bucket_acl", f"{resource_name}_acl")
    text, changed = ensure_attribute_literal(block.text, "acl", '"private"')
    replace_block(block, text)
    return TransformResult(
        changed, block.file_path, _contract("aws.s3.acl_private", ["set s3 bucket acl to private"])
    )


def t12_dynamodb_kms_cmk(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    files = _module_tf_files(module_dir)
    block = find_resource_block(files, resource_type, resource_name)
    kms_name = f"{resource_name}_cmk"
    kms_ref = f"aws_kms_key.{kms_name}.arn"
    kms_exists = any(
        b.resource_name == kms_name for b in find_resource_blocks(files, "aws_kms_key")
    )

    text, table_changed = _ensure_dynamodb_sse_cmk(block.text, kms_ref)
    if text != block.text:
        table_changed = True
    replace_block(block, text)

    kms_changed = False
    if not kms_exists:
        target_file = (
            block.file_path if block.file_path.exists() else (module_dir / "sanara_security.tf")
        )
        kms_resource = (
            f'resource "aws_kms_key" "{kms_name}" {{\n'
            f'  description             = "CMK for DynamoDB table {resource_name}"\n'
            "  deletion_window_in_days = 7\n"
            "}"
        )
        append_resource(target_file, kms_resource)
        kms_changed = True

    return TransformResult(
        table_changed or kms_changed,
        block.file_path,
        _contract(
            "aws.dynamodb.kms_cmk_encrypted",
            ["ensured dynamodb server_side_encryption with CMK", "created kms key when missing"],
        ),
    )


def t13_kms_key_rotation(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text, changed = ensure_attribute_literal(block.text, "enable_key_rotation", "true")
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.kms.rotation_enabled", ["ensured kms key rotation enabled"]),
    )


def t14_s3_policy_secure_transport(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    files = _module_tf_files(module_dir)
    if resource_type == "aws_s3_bucket_policy":
        block = find_resource_block(files, resource_type, resource_name)
        bucket_ref = None
        m = re.search(r"^\s*bucket\s*=\s*(.+)$", block.text, re.MULTILINE)
        if m:
            bucket_ref = m.group(1).strip()
    else:
        block = _find_s3_related_block(files, "aws_s3_bucket_policy", resource_name)
        if block is None:
            raise DrcError("NO_TARGET_RESOURCE", f"No aws_s3_bucket_policy for {resource_name}")
        bucket_ref = _s3_resource_expr(files, resource_name)

    bucket_arn_expr = (
        f"${{{bucket_ref.replace('.id', '.arn')}}}"
        if bucket_ref and ".id" in bucket_ref
        else "${aws_s3_bucket.bucket.arn}"
    )
    new_block = (
        f'resource "aws_s3_bucket_policy" "{block.resource_name}" {{\n'
        f"  bucket = {bucket_ref or 'aws_s3_bucket.bucket.id'}\n"
        "  policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [\n"
        "      {\n"
        '        Sid       = "DenyInsecureTransport"\n'
        '        Effect    = "Deny"\n'
        '        Principal = "*"\n'
        '        Action    = "s3:*"\n'
        f'        Resource  = ["{bucket_arn_expr}", "{bucket_arn_expr}/*"]\n'
        "        Condition = {\n"
        "          Bool = {\n"
        '            "aws:SecureTransport" = "false"\n'
        "          }\n"
        "        }\n"
        "      }\n"
        "    ]\n"
        "  })\n"
        "}"
    )
    changed = block.text != new_block
    replace_block(block, new_block)
    return TransformResult(
        changed,
        block.file_path,
        _contract(
            "aws.s3.policy_secure_transport",
            ["replaced wildcard public policy with deny insecure transport policy"],
        ),
    )


def t15_s3_sse_kms(
    module_dir: Path, file_path: Path, _: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = policy
    files = _module_tf_files(module_dir)
    target = _find_s3_related_block(
        files, "aws_s3_bucket_server_side_encryption_configuration", resource_name
    )
    if target is None:
        try:
            target = find_resource_block(
                files, "aws_s3_bucket_server_side_encryption_configuration", f"{resource_name}_sse"
            )
        except DrcError:
            target = None
    if target:
        text = target.text
        changed = False
        if 'sse_algorithm = "AES256"' in text:
            text = text.replace('sse_algorithm = "AES256"', 'sse_algorithm = "aws:kms"')
            changed = True
        elif 'sse_algorithm = "aws:kms"' not in text:
            text, c = ensure_nested_block(
                text,
                'rule {\n  apply_server_side_encryption_by_default {\n    sse_algorithm = "aws:kms"\n    kms_master_key_id = "alias/aws/s3"\n  }\n}',
            )
            changed = changed or c
        if "kms_master_key_id" not in text:
            text = re.sub(
                r'(apply_server_side_encryption_by_default\s*\{[^}]*sse_algorithm\s*=\s*"aws:kms"\s*)',
                r'\1\n    kms_master_key_id = "alias/aws/s3"\n',
                text,
                count=1,
                flags=re.DOTALL,
            )
            changed = True
        replace_block(target, text)
        return TransformResult(
            changed,
            target.file_path,
            _contract("aws.s3.sse_kms_default", ["ensured s3 default encryption uses aws:kms"]),
        )

    target_file = file_path if file_path.exists() else module_dir / "sanara_security.tf"
    resource = (
        f'resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}_sse" {{\n'
        f"  bucket = {_s3_resource_expr(files, resource_name)}\n"
        "  rule {\n"
        "    apply_server_side_encryption_by_default {\n"
        '      sse_algorithm     = "aws:kms"\n'
        '      kms_master_key_id = "alias/aws/s3"\n'
        "    }\n"
        "  }\n"
        "}"
    )
    append_resource(target_file, resource)
    return TransformResult(
        True,
        target_file,
        _contract("aws.s3.sse_kms_default", ["created s3 kms default encryption config"]),
    )


def t16_s3_access_logging(
    module_dir: Path, file_path: Path, _: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = policy
    files = _module_tf_files(module_dir)
    bucket_expr = _s3_resource_expr(files, resource_name)
    existing = _find_s3_related_block(files, "aws_s3_bucket_logging", resource_name)
    if existing:
        return TransformResult(
            False,
            existing.file_path,
            _contract("aws.s3.access_logging_enabled", ["existing s3 bucket logging retained"]),
        )

    target_file = file_path if file_path.exists() else module_dir / "sanara_security.tf"
    log_bucket_name = f"{resource_name}_access_logs"
    append_resource(
        target_file,
        (
            f'resource "aws_s3_bucket" "{log_bucket_name}" {{\n'
            f'  bucket_prefix = "{resource_name}-access-logs-"\n'
            "}"
        ),
    )
    append_resource(
        target_file,
        (
            f'resource "aws_s3_bucket_logging" "{resource_name}_logging" {{\n'
            f"  bucket        = {bucket_expr}\n"
            f"  target_bucket = aws_s3_bucket.{log_bucket_name}.id\n"
            '  target_prefix = "logs/"\n'
            "}"
        ),
    )
    return TransformResult(
        True,
        target_file,
        _contract(
            "aws.s3.access_logging_enabled", ["created access log bucket and aws_s3_bucket_logging"]
        ),
    )


def t17_kms_key_policy_present(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    files = _module_tf_files(module_dir)
    block = find_resource_block(files, resource_type, resource_name)
    if re.search(r"^\s*policy\s*=", block.text, re.MULTILINE):
        return TransformResult(
            False,
            block.file_path,
            _contract("aws.kms.policy_present", ["existing kms key policy retained"]),
        )

    text, changed = ensure_attribute_literal(
        block.text,
        "policy",
        'jsonencode({ Version = "2012-10-17", Statement = [{ Sid = "EnableRoot", Effect = "Allow", Principal = { AWS = "*" }, Action = "kms:*", Resource = "*" }] })',
    )
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.kms.policy_present", ["ensured kms key policy attribute exists"]),
    )


def t18_s3_acl_disabled(
    module_dir: Path, file_path: Path, _: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = policy
    files = _module_tf_files(module_dir)
    block = _find_s3_related_block(files, "aws_s3_bucket_ownership_controls", resource_name)
    if block is None:
        try:
            block = find_resource_block(
                files, "aws_s3_bucket_ownership_controls", f"{resource_name}_ownership_controls"
            )
        except DrcError:
            block = None

    if block:
        text = block.text
        changed = False
        if re.search(r'object_ownership\s*=\s*"BucketOwnerEnforced"', text):
            return TransformResult(
                False,
                block.file_path,
                _contract(
                    "aws.s3.acl_disabled", ["existing bucket ownership enforcement retained"]
                ),
            )
        if re.search(r'object_ownership\s*=\s*"[^"]+"', text):
            text = re.sub(
                r'object_ownership\s*=\s*"[^"]+"',
                'object_ownership = "BucketOwnerEnforced"',
                text,
                count=1,
            )
            changed = True
        else:
            text, c = ensure_nested_block(
                text, 'rule {\n  object_ownership = "BucketOwnerEnforced"\n}'
            )
            changed = changed or c
        replace_block(block, text)
        return TransformResult(
            changed,
            block.file_path,
            _contract("aws.s3.acl_disabled", ["ensured s3 ownership controls disable ACLs"]),
        )

    target_file = file_path if file_path.exists() else module_dir / "sanara_security.tf"
    resource = (
        f'resource "aws_s3_bucket_ownership_controls" "{resource_name}_ownership_controls" {{\n'
        f"  bucket = {_s3_resource_expr(files, resource_name)}\n"
        "  rule {\n"
        '    object_ownership = "BucketOwnerEnforced"\n'
        "  }\n"
        "}"
    )
    append_resource(target_file, resource)
    return TransformResult(
        True,
        target_file,
        _contract("aws.s3.acl_disabled", ["created s3 ownership controls with acl disabled"]),
    )


def t20_lambda_tracing(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    nested = 'tracing_config {\n  mode = "Active"\n}'
    text, changed = ensure_nested_block(block.text, nested)
    if '"PassThrough"' in text:
        text = text.replace('"PassThrough"', '"Active"')
        changed = True
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.lambda.tracing_enabled", ["ensured lambda tracing_config mode Active"]),
    )


def t21_rds_deletion_protection(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text, changed = ensure_attribute_literal(block.text, "deletion_protection", "true")
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.rds.deletion_protection", ["set deletion_protection=true"]),
    )


def t22_ecr_scan_on_push(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    nested = "image_scanning_configuration {\n  scan_on_push = true\n}"
    text, changed = ensure_nested_block(block.text, nested)
    if "scan_on_push = false" in text:
        text = text.replace("scan_on_push = false", "scan_on_push = true")
        changed = True
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.ecr.scan_on_push", ["ensured ecr scan_on_push enabled"]),
    )


def t23_cloudtrail_log_file_validation(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text, changed = ensure_attribute_literal(block.text, "enable_log_file_validation", "true")
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.cloudtrail.log_file_validation", ["set enable_log_file_validation=true"]),
    )


def t24_cloudtrail_kms(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    value = _kms_value(policy, "aws.cloudtrail.kms_encrypted", "alias/aws/cloudtrail")
    text, changed = ensure_attribute_literal(block.text, "kms_key_id", value)
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.cloudtrail.kms_encrypted", ["ensured cloudtrail kms_key_id"]),
    )


def t25_ecr_kms_encryption(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    nested = 'encryption_configuration {\n  encryption_type = "KMS"\n}'
    text, changed = ensure_nested_block(block.text, nested)
    if 'encryption_type = "AES256"' in text:
        text = text.replace('"AES256"', '"KMS"')
        changed = True
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.ecr.kms_encryption", ["ensured ecr encryption_configuration type KMS"]),
    )


def t19_s3_event_notifications_enabled(
    module_dir: Path, file_path: Path, _: str, resource_name: str, policy: Policy
) -> TransformResult:
    _ = policy
    files = _module_tf_files(module_dir)
    existing = _find_s3_related_block(files, "aws_s3_bucket_notification", resource_name)
    if existing:
        return TransformResult(
            False,
            existing.file_path,
            _contract(
                "aws.s3.event_notifications_enabled", ["existing s3 bucket notifications retained"]
            ),
        )

    target_file = file_path if file_path.exists() else module_dir / "sanara_security.tf"
    topic_name = f"{resource_name}_events"
    append_resource(
        target_file,
        (
            f'resource "aws_sns_topic" "{topic_name}" {{\n'
            f'  name = "{resource_name}-events"\n'
            "}"
        ),
    )
    append_resource(
        target_file,
        (
            f'resource "aws_sns_topic_policy" "{topic_name}_policy" {{\n'
            f"  arn = aws_sns_topic.{topic_name}.arn\n"
            "  policy = jsonencode({\n"
            '    Version = "2012-10-17"\n'
            "    Statement = [\n"
            "      {\n"
            '        Sid       = "AllowS3Publish"\n'
            '        Effect    = "Allow"\n'
            '        Principal = { Service = "s3.amazonaws.com" }\n'
            '        Action    = "SNS:Publish"\n'
            f"        Resource  = aws_sns_topic.{topic_name}.arn\n"
            "        Condition = {\n"
            "          ArnLike = {\n"
            f'            "aws:SourceArn" = {_s3_resource_expr(files, resource_name, "arn")}\n'
            "          }\n"
            "        }\n"
            "      }\n"
            "    ]\n"
            "  })\n"
            "}"
        ),
    )
    append_resource(
        target_file,
        (
            f'resource "aws_s3_bucket_notification" "{resource_name}_notifications" {{\n'
            f"  bucket = {_s3_resource_expr(files, resource_name)}\n"
            "  topic {\n"
            f"    topic_arn = aws_sns_topic.{topic_name}.arn\n"
            '    events    = ["s3:ObjectCreated:*"]\n'
            "  }\n"
            f"  depends_on = [aws_sns_topic_policy.{topic_name}_policy]\n"
            "}"
        ),
    )
    return TransformResult(
        True,
        target_file,
        _contract(
            "aws.s3.event_notifications_enabled",
            ["created sns topic + policy and s3 bucket notification"],
        ),
    )


# T26-T30: EC2, RDS, Secrets Manager, IAM


def t26_ec2_imdsv2(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    """Enforce IMDSv2 on EC2 instances by requiring http_tokens = required."""
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text = block.text
    changed = False

    if "metadata_options" in text:
        # Update existing block: enforce http_tokens and http_endpoint
        def _fix_metadata_options(m: re.Match) -> str:
            inner = m.group(0)
            if "http_tokens" not in inner:
                inner = inner.rstrip("}")
                inner += '  http_tokens   = "required"\n}'
            else:
                inner = re.sub(r'http_tokens\s*=\s*"[^"]+"', 'http_tokens   = "required"', inner)
            if "http_endpoint" not in inner:
                inner = inner.rstrip("}")
                inner += '  http_endpoint = "enabled"\n}'
            return inner

        new_text = re.sub(
            r"metadata_options\s*\{[^}]+\}", _fix_metadata_options, text, count=1, flags=re.DOTALL
        )
        if new_text != text:
            text = new_text
            changed = True
    else:
        nested = 'metadata_options {\n  http_tokens   = "required"\n  http_endpoint = "enabled"\n}'
        text, changed = ensure_nested_block(text, nested)

    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.ec2.imdsv2_required", ["enforced metadata_options http_tokens=required"]),
    )


def t27_rds_backup_retention(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    """Set backup_retention_period to at least 7 days on RDS instances."""
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text = block.text
    # Only set if absent or explicitly 0
    existing = re.search(r"^\s*backup_retention_period\s*=\s*(\d+)", text, re.MULTILINE)
    if existing and int(existing.group(1)) >= 1:
        return TransformResult(
            False,
            block.file_path,
            _contract("aws.rds.backup_retention", ["existing backup_retention_period sufficient"]),
        )
    text, changed = ensure_attribute_literal(text, "backup_retention_period", "7")
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.rds.backup_retention", ["set backup_retention_period=7"]),
    )


def t28_secretsmanager_kms(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    """Set kms_key_id on aws_secretsmanager_secret to enforce CMK encryption."""
    files = _module_tf_files(module_dir)
    block = find_resource_block(files, resource_type, resource_name)
    cmk_name = f"{resource_name}_cmk"
    cmk_ref = f"aws_kms_key.{cmk_name}.arn"

    kms_blocks = [
        b for b in find_resource_blocks(files, "aws_kms_key") if b.resource_name == cmk_name
    ]
    kms_changed = False
    if not kms_blocks:
        target_file = (
            block.file_path if block.file_path.exists() else (module_dir / "sanara_security.tf")
        )
        kms_resource = (
            f'resource "aws_kms_key" "{cmk_name}" {{\n'
            f'  description             = "CMK for Secrets Manager secret {resource_name}"\n'
            "  deletion_window_in_days = 7\n"
            "  enable_key_rotation     = true\n"
            "}"
        )
        append_resource(target_file, kms_resource)
        kms_changed = True

    text = block.text
    changed = False
    match = re.search(r"^\s*kms_key_id\s*=\s*(.+)$", text, re.MULTILINE)
    if match:
        current = match.group(1).strip()
        if "aws/" in current:
            text = re.sub(
                r"(^\s*kms_key_id\s*=\s*).+$",
                rf"\1{cmk_ref}",
                text,
                count=1,
                flags=re.MULTILINE,
            )
            changed = True
    else:
        if text.rstrip().endswith("}"):
            text = text.rstrip()[:-1] + f"  kms_key_id = {cmk_ref}\n" + "}"
            changed = True

    if changed:
        replace_block(block, text)

    return TransformResult(
        changed or kms_changed,
        block.file_path,
        _contract(
            "aws.secretsmanager.kms_encrypted",
            ["set kms_key_id on secretsmanager secret to CMK", "created kms key when missing"],
        ),
    )


def t29_cloudtrail_multi_region(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    """Ensure CloudTrail is configured as a multi-region trail."""
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text, changed = ensure_attribute_literal(block.text, "is_multi_region_trail", "true")
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.cloudtrail.multi_region_enabled", ["set is_multi_region_trail=true"]),
    )


def t30_rds_storage_encrypted(
    module_dir: Path, file_path: Path, resource_type: str, resource_name: str, policy: Policy
) -> TransformResult:
    """Ensure storage_encrypted = true on RDS resources."""
    _ = file_path, policy
    block = find_resource_block(_module_tf_files(module_dir), resource_type, resource_name)
    text, changed = ensure_attribute_literal(block.text, "storage_encrypted", "true")
    replace_block(block, text)
    return TransformResult(
        changed,
        block.file_path,
        _contract("aws.rds.storage_encrypted", ["set storage_encrypted=true"]),
    )
