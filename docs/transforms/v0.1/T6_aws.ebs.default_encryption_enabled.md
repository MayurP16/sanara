# T6 aws.ebs.default_encryption_enabled

- Purpose: enforce account default EBS encryption.
- Source mapping: `CKV_AWS_106` -> `aws.ebs.default_encryption_enabled`.
- Preconditions: rule must be opt-in allowlisted.
- Patch strategy: create `aws_ebs_encryption_by_default` with `enabled = true`.
- Placement rules: append to module security file.
- Postconditions: singleton default encryption resource exists.
- Failure codes: `NEEDS_AGENTIC`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
