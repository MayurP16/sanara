# T13 aws.kms.rotation_enabled

- Purpose: enable automatic rotation on KMS keys.
- Source mapping: `CKV_AWS_7` -> `aws.kms.rotation_enabled`.
- Preconditions: target `aws_kms_key` resource resolves.
- Patch strategy: set `enable_key_rotation = true` in-place.
- Placement rules: in-place edit only.
- Postconditions: KMS key rotation attribute is explicitly enabled.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`.
