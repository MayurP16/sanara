# T29 aws.cloudtrail.multi_region_enabled

- Purpose: ensure CloudTrail is enabled across all AWS regions.
- Source mapping: `CKV_AWS_67` -> `aws.cloudtrail.multi_region_enabled`.
- Preconditions: target `aws_cloudtrail` resource resolves.
- Patch strategy: add or update `is_multi_region_trail = true`.
- Placement rules: in-place edit only.
- Postconditions: `is_multi_region_trail = true`.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
