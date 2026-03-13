# T28 aws.secretsmanager.kms_encrypted

- Purpose: ensure Secrets Manager secrets use a customer-managed KMS key.
- Source mapping: `CKV_AWS_149` -> `aws.secretsmanager.kms_encrypted`.
- Preconditions: target `aws_secretsmanager_secret` resource resolves.
- Patch strategy: create `<secret>_cmk` when missing and set `kms_key_id = aws_kms_key.<secret>_cmk.arn`; replace AWS-managed alias values with the CMK reference.
- Placement rules: update the secret in place; append the generated KMS key resource to the same file when possible.
- Postconditions: secret `kms_key_id` references a CMK, not an `aws/` managed alias.
- Failure codes: `NO_TARGET_RESOURCE`, `MISSING_POLICY_KMS_KEY`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
