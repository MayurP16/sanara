# T4 aws.rds.not_public

- Purpose: disable public accessibility for RDS instances.
- Source mapping: `CKV_AWS_17` -> `aws.rds.not_public`.
- Preconditions: resource type must be `aws_db_instance` or `aws_rds_cluster_instance`; attribute must be literal/missing.
- Patch strategy: set `publicly_accessible = false` when missing or true.
- Placement rules: in-place resource edit only.
- Postconditions: resource has literal `publicly_accessible = false`.
- Failure codes: `NO_TARGET_RESOURCE`, `AMBIGUOUS_TARGET`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
