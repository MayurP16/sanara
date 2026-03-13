# T3 aws.s3.versioning_enabled

- Purpose: ensure S3 versioning status is `Enabled`.
- Source mapping: `CKV_AWS_21` -> `aws.s3.versioning_enabled`.
- Preconditions: bucket/versioning target must resolve; explicit `Suspended` may represent user intent.
- Patch strategy:
  - ensure `aws_s3_bucket_versioning` with `versioning_configuration.status = "Enabled"`.
  - if explicit suspended and override not allowed, fail.
- Placement rules: update existing versioning block or create `<bucket>_versioning`.
- Postconditions: literal enabled versioning present.
- Failure codes: `USER_INTENT_CONFLICT`, `NO_TARGET_RESOURCE`, `AMBIGUOUS_TARGET`, `BLOCKED_BY_RAIL`.
