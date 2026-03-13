# T23 aws.cloudtrail.log_file_validation

- Purpose: ensure CloudTrail enables log file validation.
- Source mapping: `CKV_AWS_36` -> `aws.cloudtrail.log_file_validation`.
- Preconditions: target `aws_cloudtrail` resource resolves.
- Patch strategy: add or update `enable_log_file_validation = true`.
- Placement rules: in-place edit only.
- Postconditions: `enable_log_file_validation = true`.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
