# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
