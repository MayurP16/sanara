# T15 aws.s3.sse_kms_default

- Purpose: enforce S3 default encryption using KMS (`aws:kms`).
- Source mapping: `CKV_AWS_145` -> `aws.s3.sse_kms_default`.
- Preconditions: target S3 bucket resolves; optional existing SSE config may or may not exist.
- Patch strategy: update existing `aws_s3_bucket_server_side_encryption_configuration` to `aws:kms` with `kms_master_key_id = "alias/aws/s3"`; otherwise create a new SSE config resource.
- Placement rules: in-place edit when config exists; append new resource to target file or `sanara_security.tf` when missing.
- Postconditions: S3 bucket has a default SSE config using KMS.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`.
