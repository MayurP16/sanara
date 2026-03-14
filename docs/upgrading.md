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

For rollout details, see `docs/github-action-setup.md`.
