# T1 aws.s3.public_access_block

- Purpose: ensure each S3 bucket has an `aws_s3_bucket_public_access_block` with all four protective booleans set to `true`.
- Source mapping: `CKV2_AWS_6` -> `aws.s3.public_access_block`.
- Preconditions: target `aws_s3_bucket.<name>` must resolve unambiguously in module scope.
- Patch strategy:
  - update existing `aws_s3_bucket_public_access_block` if present;
  - otherwise create `<bucket>_pab` referencing `aws_s3_bucket.<name>.id`.
- Placement rules: write in source file when known, else append to `sanara_security.tf`.
- Postconditions: `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` are true.
- Failure codes: `NO_TARGET_RESOURCE`, `AMBIGUOUS_TARGET`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`, `NEEDS_AGENTIC`.
