# T9 aws.dynamodb.pitr_enabled

- Purpose: ensure DynamoDB point-in-time recovery is enabled.
- Source mapping: `CKV_AWS_28` -> `aws.dynamodb.pitr_enabled`.
- Preconditions: target table resolves and nested enabled flag is literal-safe.
- Patch strategy: ensure `point_in_time_recovery { enabled = true }` exists.
- Placement rules: in-place edit.
- Postconditions: PITR nested block enabled.
- Failure codes: `NO_TARGET_RESOURCE`, `AMBIGUOUS_TARGET`, `NON_LITERAL_ATTR`, `BLOCKED_BY_RAIL`.
