# T10 aws.cloudwatch.log_group_encrypted

- Purpose: enforce CloudWatch log group encryption key.
- Source mapping: `CKV_AWS_158` -> `aws.cloudwatch.log_group_encrypted`.
- Preconditions: target log group resolves; CMK policy may require custom key.
- Patch strategy: set `kms_key_id` to `alias/aws/logs` unless CMK-required policy.
- Placement rules: in-place edit.
- Postconditions: literal kms key id present.
- Failure codes: `MISSING_POLICY_KMS_KEY`, `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`.
