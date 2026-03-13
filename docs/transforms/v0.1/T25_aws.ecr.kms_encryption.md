# T25 aws.ecr.kms_encryption

- Purpose: ensure ECR repositories use KMS encryption.
- Source mapping: `CKV_AWS_136` -> `aws.ecr.kms_encryption`.
- Preconditions: target `aws_ecr_repository` resource resolves.
- Patch strategy: add `encryption_configuration { encryption_type = "KMS" }` when absent; replace `"AES256"` with `"KMS"` when present.
- Placement rules: in-place edit only.
- Postconditions: `encryption_configuration.encryption_type = "KMS"`.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
