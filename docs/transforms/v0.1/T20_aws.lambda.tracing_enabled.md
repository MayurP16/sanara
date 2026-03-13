# T20 aws.lambda.tracing_enabled

- Purpose: ensure Lambda functions enable X-Ray tracing.
- Source mapping: `CKV_AWS_50` -> `aws.lambda.tracing_enabled`.
- Preconditions: target `aws_lambda_function` resource resolves.
- Patch strategy: add `tracing_config { mode = "Active" }` when absent; replace `"PassThrough"` with `"Active"` when present.
- Placement rules: in-place edit only.
- Postconditions: Lambda has `tracing_config.mode = "Active"`.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
