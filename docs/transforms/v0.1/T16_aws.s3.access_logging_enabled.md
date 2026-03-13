# T16 aws.s3.access_logging_enabled

- Purpose: enable S3 access logging for a bucket.
- Source mapping: `CKV_AWS_18` -> `aws.s3.access_logging_enabled`.
- Preconditions: target S3 bucket resolves; existing logging resource may or may not exist.
- Patch strategy: if no logging resource exists, create a companion access-log bucket plus `aws_s3_bucket_logging` resource.
- Placement rules: append helper resources to target file or `sanara_security.tf`.
- Postconditions: target bucket has `aws_s3_bucket_logging`; helper access-log bucket exists.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`.
