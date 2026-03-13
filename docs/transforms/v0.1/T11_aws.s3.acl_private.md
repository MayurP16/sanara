# T11 aws.s3.acl_private

- Purpose: force S3 bucket ACL resources to private.
- Source mapping: `CKV_AWS_20` -> `aws.s3.acl_private`.
- Preconditions: target S3 ACL resource resolves (`aws_s3_bucket_acl` for bucket or `<bucket>_acl` fallback).
- Patch strategy: set `acl = "private"` in-place on the bucket ACL resource.
- Placement rules: in-place edit only.
- Postconditions: ACL literal is `private`.
- Failure codes: `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`.
