# T21 aws.rds.deletion_protection

- Purpose: ensure RDS instances enforce deletion protection.
- Source mapping: `CKV_AWS_293`, `CKV2_AWS_60` -> `aws.rds.deletion_protection`.
- Preconditions: target `aws_db_instance` or `aws_rds_cluster` resource resolves.
- Patch strategy: add or update `deletion_protection = true`.
- Placement rules: in-place edit only.
- Postconditions: `deletion_protection = true`.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
