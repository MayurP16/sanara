# T27 aws.rds.backup_retention

- Purpose: ensure RDS resources keep automated backups for at least 7 days.
- Source mapping: `CKV_AWS_133`, `CKV2_AWS_21` -> `aws.rds.backup_retention`.
- Preconditions: target `aws_db_instance` or `aws_rds_cluster` resource resolves.
- Patch strategy: add `backup_retention_period = 7` when absent; replace `0` with `7`; retain existing values >= 1.
- Placement rules: in-place edit only.
- Postconditions: `backup_retention_period >= 1` with Sanara defaulting to `7`.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
