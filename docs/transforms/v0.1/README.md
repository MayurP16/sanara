# Transform Catalog v0.1

This catalog lists the deterministic Terraform remediations Sanara can apply in the `v0.1` rule pack.

Use these pages as reference material when you want to understand exactly what a transform is expected to change for a given finding. These are implementation-oriented specs, not setup guides.

- T1 `aws.s3.public_access_block` <- `CKV2_AWS_6`
- T2 `aws.s3.sse_default` <- `CKV_AWS_19`
- T3 `aws.s3.versioning_enabled` <- `CKV_AWS_21`
- T4 `aws.rds.not_public` <- `CKV_AWS_17`
- T5 `aws.ebs.encrypted` <- `CKV_AWS_3`
- T6 `aws.ebs.default_encryption_enabled` <- `CKV_AWS_106` (opt-in)
- T7 `aws.sns.encrypted` <- `CKV_AWS_26`
- T8 `aws.sqs.encrypted` <- `CKV_AWS_27`
- T9 `aws.dynamodb.pitr_enabled` <- `CKV_AWS_28`
- T10 `aws.cloudwatch.log_group_encrypted` <- `CKV_AWS_158`
- T11 `aws.s3.acl_private` <- `CKV_AWS_20`
- T12 `aws.dynamodb.kms_cmk_encrypted` <- `CKV_AWS_119`
- T13 `aws.kms.rotation_enabled` <- `CKV_AWS_7`
- T14 `aws.s3.policy_secure_transport` <- `CKV_AWS_70` (also addresses `CKV_AWS_379` policy shape cases)
- T15 `aws.s3.sse_kms_default` <- `CKV_AWS_145`
- T16 `aws.s3.access_logging_enabled` <- `CKV_AWS_18`
- T17 `aws.kms.policy_present` <- `CKV2_AWS_64`
- T18 `aws.s3.acl_disabled` <- `CKV2_AWS_65`
- T19 `aws.s3.event_notifications_enabled` <- `CKV2_AWS_62`
- T20 `aws.lambda.tracing_enabled` <- `CKV_AWS_50`
- T21 `aws.rds.deletion_protection` <- `CKV_AWS_293`, `CKV2_AWS_60`
- T22 `aws.ecr.scan_on_push` <- `CKV_AWS_163`
- T23 `aws.cloudtrail.log_file_validation` <- `CKV_AWS_36`
- T24 `aws.cloudtrail.kms_encrypted` <- `CKV_AWS_35`
- T25 `aws.ecr.kms_encryption` <- `CKV_AWS_136`
- T26 `aws.ec2.imdsv2_required` <- `CKV_AWS_79`
- T27 `aws.rds.backup_retention` <- `CKV_AWS_133`, `CKV2_AWS_21`
- T28 `aws.secretsmanager.kms_encrypted` <- `CKV_AWS_149`
- T29 `aws.cloudtrail.multi_region_enabled` <- `CKV_AWS_67`
- T30 `aws.rds.storage_encrypted` <- `CKV_AWS_16`
