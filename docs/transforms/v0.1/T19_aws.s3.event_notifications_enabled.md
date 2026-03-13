# T19 aws.s3.event_notifications_enabled

- Purpose: ensure S3 buckets have event notifications configured.
- Source mapping: `CKV2_AWS_62` -> `aws.s3.event_notifications_enabled`.
- Preconditions: target S3 bucket resolves; notification resources may or may not already exist.
- Patch strategy: if no bucket notification exists, create an SNS topic, SNS topic policy, and `aws_s3_bucket_notification` for `s3:ObjectCreated:*` events.
- Placement rules: append helper resources to target file or `sanara_security.tf`.
- Postconditions: target bucket has a notification resource with an event destination.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`.
