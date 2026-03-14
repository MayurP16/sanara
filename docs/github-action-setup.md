# GitHub Action Adoption

This guide explains how repositories outside your org can run Sanara as a GitHub Action.

Sanara scans Terraform changes in a pull request, applies supported fixes, runs Terraform safety gates, and then either opens a remediation PR or leaves evidence-backed artifacts and comments.

## Recommended first rollout

For a first rollout, keep the setup conservative:

- pin the action to an immutable tag
- start with `publish_dry_run: "true"`
- keep `allow_agentic: "false"` at first
- confirm your Terraform validation setup (`examples/**` or `.sanara/harness.yml`)
- keep `plan_required: "true"` unless you intentionally want weaker safety checks

## Distribution models

### Public action repository
- Keep this repository public.
- Consumers reference a tagged release:
  - `uses: MayurP16/sanara@v0.1.0a1`
- This is the simplest onboarding path and supports broad community adoption.

### Private action repository
- Keep this repository private.
- Consumers need explicit access to the private action repository.
- Their workflows can still call tagged refs once access is granted.
- Operationally this behaves like an allowlist model and increases support overhead.

## Consumer workflow requirements

Each consumer repository needs:
- Action invocation pinned to a tag:
  - `uses: MayurP16/sanara@v0.1.0a1`
- Permissions:
  - `contents: write`
  - `pull-requests: write`
- `actions/checkout@v4` with `fetch-depth: 0`
- Environment secrets:
  - `GITHUB_TOKEN` (required for comments/PRs)
  - `ANTHROPIC_API_KEY` and/or `OPENAI_API_KEY` (required only if `allow_agentic: true`)

## Recommended workflow snippet

```yaml
name: sanara
on:
  pull_request:
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  remediate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: MayurP16/sanara@v0.1.0a1
        with:
          publish_dry_run: "true"
          allow_agentic: "false"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

If your repository needs Terraform validation before Sanara can open remediation PRs, also make sure it has a runnable Terraform setup. See `docs/terraform-validation.md`.

## Variations

### Agentic-enabled rollout

If you want to enable the optional agentic fallback, add the provider choice and corresponding API key:

```yaml
- uses: MayurP16/sanara@v0.1.0a1
  with:
    allow_agentic: "true"
    llm_provider: "anthropic"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Self-hosted runner / enterprise environment

For self-hosted runners, the workflow shape is the same. The main difference is `runs-on` and, in many teams, using `publish_dry_run: "true"` during rollout:

```yaml
jobs:
  remediate:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: MayurP16/sanara@v0.1.0a1
        with:
          publish_dry_run: "true"
          allow_agentic: "false"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## What to verify after the first run

- confirm artifacts were uploaded
- inspect `summary.md` and `artifacts/run_summary.json`
- review `decision_detail.reason_code`
- check `drc/patch.diff` for unexpected edits

## Common reasons no PR is created

- `publish_dry_run: "true"` was enabled for rollout
- no runnable Terraform harness was available while `plan_required: "true"`
- no findings produced a valid patch
- blocking findings still remained after rescan
- fork or token restrictions prevented publish actions

When this happens, inspect `artifacts/run_summary.json` and the uploaded artifacts before changing the workflow.

## Ongoing operating habits

- keep the action pin updated on your release cadence
- monitor failures by `decision_detail.reason_code`
- run regression validation before major upgrades
- use the configuration guide when you need repository-specific policy controls

## Related docs

- `docs/configuration.md`
- `docs/terraform-validation.md`
- `docs/debugging.md`

## Release hygiene for consumers

- Use immutable tags for production rollout (for example `v0.1.0-alpha.1`).
- Keep a moving major tag for easier upgrades (`v0` -> latest `v0.x.y`).
- Publish release notes with behavior and policy changes.
