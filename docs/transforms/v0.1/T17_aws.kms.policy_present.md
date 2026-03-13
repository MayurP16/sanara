# T17 aws.kms.policy_present

- Purpose: ensure KMS keys define a `policy` attribute.
- Source mapping: `CKV2_AWS_64` -> `aws.kms.policy_present`.
- Preconditions: target `aws_kms_key` resource resolves.
- Patch strategy: add a default `policy = jsonencode(...)` attribute when absent; retain existing policy unchanged.
- Placement rules: in-place edit only.
- Postconditions: `policy` attribute exists on the KMS key resource.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`.
