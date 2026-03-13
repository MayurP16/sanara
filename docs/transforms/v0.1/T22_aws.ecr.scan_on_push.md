# T22 aws.ecr.scan_on_push

- Purpose: ensure ECR repositories enable image scanning on push.
- Source mapping: `CKV_AWS_163` -> `aws.ecr.scan_on_push`.
- Preconditions: target `aws_ecr_repository` resource resolves.
- Patch strategy: add `image_scanning_configuration { scan_on_push = true }` when absent; replace `false` with `true` when present.
- Placement rules: in-place edit only.
- Postconditions: `image_scanning_configuration.scan_on_push = true`.
- Failure codes: `NO_TARGET_RESOURCE`, `BLOCKED_BY_RAIL`, `NOT_ALLOWLISTED`.
