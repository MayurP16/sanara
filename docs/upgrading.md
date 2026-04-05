# Upgrading Sanara

This guide is for repositories already using the Sanara GitHub Action.

## Recommended upgrade path

1. Read the release notes for the new version.
2. Update your workflow pin to the new immutable tag.
3. Run the new version with `publish_dry_run: "true"` first.
4. Review the uploaded artifacts and `artifacts/run_summary.json`.
5. If the run looks correct, keep the new pin and remove dry-run mode when ready.

## Safer rollout habits

- prefer immutable tags such as `v0.1.0-alpha.3`
- update one repo or environment first before broader rollout
- keep `plan_required: "true"` unless you intentionally want weaker validation
- review release notes for policy, schema, or behavior changes

## What to check after upgrading

- whether the workflow still completes successfully
- whether `decision_detail.reason_code` changed
- whether Terraform validation still runs as expected
- whether generated patches and artifacts look normal

## Behavior changes to be aware of

### Terraform validation gate (delta-based)

Previously, any `terraform init` or `validate` failure blocked Sanara from creating a PR, even if the failure existed before Sanara's fix. The gate now compares pre-fix and post-fix Terraform state. Pre-existing failures are noted in the PR body but no longer block. Only failures that Sanara's patch introduced will block (`reason_code: tf_regression`).

If you were relying on `reason_code: tf_checks_failed` to detect Terraform gate blocks, note that this code is now only generated for pre-existing-failure informational cases. New regressions introduced by Sanara use `tf_regression`.

A new artifact `terraform/baseline_checks.json` is written on every run.

### Partial fixes now create PRs

Previously Sanara only created a PR when all findings were fixed. Now it creates a PR for any progress — the PR title will say "for review" and the body lists remaining findings. `reason_code: remaining_findings` will appear less often as a result.

### Fork behavior

Cross-repository fork PRs (external contributor's fork → your repo) now receive a diff comment on the PR instead of silence. Same-repo forks and push events on forks now produce a full remediation PR.

For rollout details, see `docs/github-action-setup.md`.
