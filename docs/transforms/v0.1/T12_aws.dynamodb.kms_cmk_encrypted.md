# T12 aws.dynamodb.kms_cmk_encrypted

- Purpose: enforce DynamoDB table encryption using a customer-managed KMS key.
- Source mapping: `CKV_AWS_119` -> `aws.dynamodb.kms_cmk_encrypted`.
- Preconditions: target DynamoDB table resource resolves.
- Patch strategy: ensure `server_side_encryption` block references `aws_kms_key.<table>_cmk.arn`; create the KMS key resource when missing.
- Placement rules: table edited in-place; new KMS key may be appended to target file or `sanara_security.tf`.
- Postconditions: table has SSE enabled with CMK reference; supporting KMS key exists.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`.
