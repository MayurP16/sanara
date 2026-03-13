# T24 aws.cloudtrail.kms_encrypted

- Purpose: ensure CloudTrail uses a KMS key for at-rest encryption.
- Source mapping: `CKV_AWS_35` -> `aws.cloudtrail.kms_encrypted`.
- Preconditions: target `aws_cloudtrail` resource resolves; policy must not require an out-of-band CMK that is unavailable.
- Patch strategy: add or update `kms_key_id`; default path uses `alias/aws/cloudtrail` unless policy requires a customer-managed key.
- Placement rules: in-place edit only.
- Postconditions: `kms_key_id` exists on the CloudTrail resource.
- Failure codes: `NO_TARGET_RESOURCE`, `MISSING_POLICY_KMS_KEY`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
