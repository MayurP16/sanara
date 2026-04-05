# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0a4] - 2026-04-05

### Added

- Repair profiles for 9 previously unguided rules: `CKV2_AWS_6`, `CKV2_AWS_62`, `CKV_AWS_145`, `CKV_AWS_18`, `CKV_AWS_21`, `CKV_AWS_3`, `CKV_AWS_7`, `CKV_AWS_17`, `CKV2_AWS_64`. Rules requiring new resource blocks now include explicit placement and reference instructions.
- Baseline terraform run details logged per-run (init/validate exit codes and stderr) so failures are visible in logs without digging into the artifact.

### Changed

- Terraform validation gate is delta-based — pre-existing failures are noted in the PR body but do not block PR creation. Only regressions introduced by Sanara's patch block.
- `pre_existing_tf_failure` is now only set when `terraform init` or `validate` actually ran and exited non-zero. Structural harness errors no longer trigger the misleading "already failing on the base branch" PR note.
- Agentic LLM budget is now spread across distinct rules. After the first `git apply` failure for a rule, remaining instances of that rule are skipped so the budget covers different rules each run.
- Advisor prompt no longer instructs the LLM to tag uncertain findings with `related_scanner_rule_ids`, which was causing the overlap filter to drop all returned findings on repos with large numbers of existing scanner results.
- Advisor finding count in the PR body is now driven entirely by `advisor.max_findings` in policy — the hardcoded display cap is removed.
- `[LLM]` source tag removed from advisor finding badges in the PR body — redundant given the section header.
- Fork handling is based on whether the PR is cross-repository rather than whether the repo itself is a fork.
- Agentic fallback runs for all event contexts including cross-repository fork PRs.
- PR-body advisory summaries are formatted more clearly, with provider coverage called out as a separate summary line.

### Fixed

- Advisor returning zero findings on repos with many existing scanner results, caused by the prompt over-tagging `related_scanner_rule_ids`.
- LLM attempt budget being exhausted on repeated instances of one rule before any other rule was tried.
- Repositories with pre-existing `terraform init` or `validate` failures no longer have remediation silently blocked.
- Agentic path resolution is more resilient when Checkov reports workspace-relative paths for findings inside nested module contexts.

## [0.1.0a3] - 2026-03-14

### Fixed

- Honored `plan_required: false` by skipping `terraform plan` while still running `terraform init` and `terraform validate` during harness checks.

### Changed

- Clarified GitHub Action setup docs to recommend built-in `secrets.GITHUB_TOKEN` by default and documented the repository Actions settings required for PR creation.

## [0.1.0a2] - 2026-03-13

### Fixed

- Excluded generated Terraform plan artifacts such as `tfplan` and `*.tfplan` from Sanara remediation PR commits.

## [0.1.0a1] - 2026-03-13

### Added

- PR-native Terraform remediation flow with deterministic fixes, Terraform validation gates, and GitHub PR/comment publishing.
- 30 deterministic HCL transforms for AWS security controls across S3, EBS, DynamoDB, RDS, KMS, CloudTrail, ECR, EC2, Lambda, SNS, SQS, Secrets Manager, and CloudWatch Logs.
- Policy engine with `scan_policy`, `finding_policy`, environment overrides, `sanara policy explain`, `sanara policy lint`, and policy validation.
- Optional agentic fallback with focused HCL context extraction, secret redaction, attempt ledgers, and prompt deduplication.
- Post-fix advisor flow for non-blocking guidance after remediation.
- Reproducible artifacts for scans, patch contracts, rescans, summaries, policy evaluation, and agentic/advisor outputs.
- Patch safety rails for path scope, destructive resource removal, and network or IAM policy widening prevention.
- Automated test coverage across transforms, policy flows, rails, scanners, advisor logic, publish/dedup behavior, artifact contracts, and orchestrator integration paths.
