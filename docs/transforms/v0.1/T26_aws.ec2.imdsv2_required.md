# T26 aws.ec2.imdsv2_required

- Purpose: require IMDSv2 on EC2 instances.
- Source mapping: `CKV_AWS_79` -> `aws.ec2.imdsv2_required`.
- Preconditions: target `aws_instance`, `aws_launch_template`, or `aws_launch_configuration` resource resolves.
- Patch strategy: add `metadata_options { http_tokens = "required" http_endpoint = "enabled" }` when absent; upgrade weak values in an existing block.
- Placement rules: in-place edit only.
- Postconditions: `metadata_options.http_tokens = "required"` and `metadata_options.http_endpoint = "enabled"`.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
