# T8 aws.sqs.encrypted

- Purpose: ensure SQS queue encryption settings exist.
- Source mapping: `CKV_AWS_27` -> `aws.sqs.encrypted`.
- Preconditions: target queue resolved; CMK policy considered.
- Patch strategy:
  - set `kms_master_key_id` to `alias/aws/sqs` unless CMK required;
  - set `kms_data_key_reuse_period_seconds = 300`.
- Placement rules: in-place edit.
- Postconditions: key id and reuse period are literal-secure values.
- Failure codes: `MISSING_POLICY_KMS_KEY`, `NO_TARGET_RESOURCE`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`.
