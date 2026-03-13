# T7 aws.sns.encrypted

- Purpose: ensure SNS topic encryption key is configured.
- Source mapping: `CKV_AWS_26` -> `aws.sns.encrypted`.
- Preconditions: target SNS topic resolves; CMK policy may override AWS-managed key default.
- Patch strategy: set `kms_master_key_id` to `alias/aws/sns` unless CMK required.
- Placement rules: in-place edit.
- Postconditions: kms key attribute present with allowed value.
- Failure codes: `MISSING_POLICY_KMS_KEY`, `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`.
