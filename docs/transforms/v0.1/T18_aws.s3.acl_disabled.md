# T18 aws.s3.acl_disabled

- Purpose: disable ACL-based ownership for S3 buckets by enforcing bucket-owner ownership controls.
- Source mapping: `CKV2_AWS_65` -> `aws.s3.acl_disabled`.
- Preconditions: target S3 bucket resolves; ownership controls may or may not already exist.
- Patch strategy: ensure `aws_s3_bucket_ownership_controls` exists for the bucket and set `object_ownership = "BucketOwnerEnforced"`.
- Placement rules: in-place update when ownership controls exist; otherwise append a new ownership controls resource.
- Postconditions: bucket ownership controls enforce `BucketOwnerEnforced`.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`.
