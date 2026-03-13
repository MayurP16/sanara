# T14 aws.s3.policy_secure_transport

- Purpose: replace insecure/public S3 bucket policy patterns with a deny-insecure-transport policy.
- Source mapping: `CKV_AWS_70` -> `aws.s3.policy_secure_transport` (also addresses many `CKV_AWS_379` policy-shape cases).
- Preconditions: target `aws_s3_bucket_policy` resolves directly or can be found for the referenced bucket.
- Patch strategy: replace the bucket policy resource body with a `DenyInsecureTransport` `jsonencode(...)` policy using the target bucket ARN.
- Placement rules: in-place replacement of the policy resource block.
- Postconditions: bucket policy denies requests where `aws:SecureTransport = false`.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`.
