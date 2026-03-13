# T2 aws.s3.sse_default

- Purpose: ensure default encryption for S3 buckets.
- Source mapping: `CKV_AWS_19` -> `aws.s3.sse_default`.
- Preconditions: target bucket resolved; existing stronger KMS config must not be downgraded.
- Patch strategy:
  - add/update `aws_s3_bucket_server_side_encryption_configuration`;
  - default to `AES256` unless KMS already configured.
- Placement rules: in-place update if resource exists, otherwise append deterministic resource block.
- Postconditions: encryption configuration exists and is at least SSE-S3.
- Failure codes: `NO_TARGET_RESOURCE`, `AMBIGUOUS_TARGET`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
