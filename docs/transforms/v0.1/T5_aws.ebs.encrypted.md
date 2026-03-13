# T5 aws.ebs.encrypted

- Purpose: enforce EBS volume encryption.
- Source mapping: `CKV_AWS_3` -> `aws.ebs.encrypted`.
- Preconditions: `aws_ebs_volume` target resolved and attribute literal-safe.
- Patch strategy: set `encrypted = true` if missing or false.
- Placement rules: in-place resource edit.
- Postconditions: literal encryption enabled.
- Failure codes: `NO_TARGET_RESOURCE`, `AMBIGUOUS_TARGET`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
