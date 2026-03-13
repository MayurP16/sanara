# T30 aws.rds.storage_encrypted

- Purpose: ensure RDS instances encrypt storage at rest.
- Source mapping: `CKV_AWS_16` -> `aws.rds.storage_encrypted`.
- Preconditions: target `aws_db_instance` resource resolves.
- Patch strategy: add or update `storage_encrypted = true`.
- Placement rules: in-place edit only.
- Postconditions: `storage_encrypted = true`.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
