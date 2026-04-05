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
  - `uses: MayurP16/sanara@v0.1.0a4`
- This is the simplest onboarding path and supports broad community adoption.

### Private action repository
- Keep this repository private.
- Consumers need explicit access to the private action repository.
- Their workflows can still call tagged refs once access is granted.
- Operationally this behaves like an allowlist model and increases support overhead.

## Consumer workflow requirements

Each consumer repository needs:
- Action invocation pinned to a tag:
  - `uses: MayurP16/sanara@v0.1.0a4`
- Permissions:
  - `contents: write`
  - `pull-requests: write`
- Repository Actions settings:
  - `Workflow permissions` set to `Read and write permissions`
  - `Allow GitHub Actions to create and approve pull requests` enabled
- `actions/checkout@v4` with `fetch-depth: 0`
- Environment secrets:
  - `GITHUB_TOKEN` (pass the built-in `${{ secrets.GITHUB_TOKEN }}` for comments/PRs)
  - `ANTHROPIC_API_KEY` and/or `OPENAI_API_KEY` (required only if `allow_agentic: true`)

Use a fine-grained PAT only if repository or organization policy prevents the built-in `secrets.GITHUB_TOKEN` from creating PRs.

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
      - uses: MayurP16/sanara@v0.1.0a4
        with:
          publish_dry_run: "true"
          allow_agentic: "false"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## How Triggers Affect Scan Scope

Sanara behaves differently depending on which GitHub event starts the workflow:

- `pull_request`
  - scans only `.tf` files changed in the PR
  - use this for normal developer-facing remediation during review
- `workflow_dispatch`
  - manual run from the Actions tab
  - scans all `.tf` files in the repository checkout
- `push`
  - scans all `.tf` files in the repository checkout
  - useful after a PR merge, because the merge creates a push event on the default branch

This matters if you want to remediate Terraform that already exists on `main`. A `pull_request` run will not sweep the full repository baseline. For that, use `workflow_dispatch`, `schedule`, or `push` on the default branch.

Example post-merge baseline trigger:

```yaml
on:
  pull_request:
  workflow_dispatch:
  push:
    branches:
      - main
```

If you only want the post-merge run when Terraform-related files changed, add path filters:

```yaml
on:
  push:
    branches:
      - main
    paths:
      - "**/*.tf"
      - ".sanara/**"
```

If your repository needs Terraform validation before Sanara can open remediation PRs, also make sure it has a runnable Terraform setup. See `docs/terraform-validation.md`.

If Sanara reaches `PR_CREATE` and GitHub returns `403 Forbidden`, the usual cause is repository or organization Actions settings, not a missing PAT.

## Variations

### Agentic-enabled rollout

If you want to enable the optional agentic fallback, add the provider choice and corresponding API key:

```yaml
- uses: MayurP16/sanara@v0.1.0a3
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
      - uses: MayurP16/sanara@v0.1.0a3
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

## Fork behavior

Sanara handles fork contexts differently depending on how the workflow is triggered:

- **Cross-repository fork PR** (external contributor opens a PR from their fork to your repo): Sanara cannot push a branch to the upstream repository because the `GITHUB_TOKEN` is restricted by GitHub's security model. Instead, Sanara posts a comment on the PR containing the full diff and instructions to apply it. The contributor applies the patch to their branch manually.

- **Push or PR on the fork itself** (the fork author runs Sanara on their own fork's CI): Sanara has full write access to the fork and creates a remediation PR within the fork as normal.

The distinction is whether the PR head and base come from different repositories, not whether the repository itself is a fork.

## Partial fix behavior

Sanara creates a PR whenever it has made at least one security fix, even if some findings remain. The PR title will include "for review" and the PR body will list any remaining findings. Previously Sanara only created a PR when all findings were fixed.

## Common reasons no PR is created

- `publish_dry_run: "true"` was enabled for rollout
- no runnable Terraform harness was available while `plan_required: "true"`
- no findings produced a valid patch (no changes to commit)
- Sanara's patch caused `terraform init` or `validate` to fail on a repo where it was passing before (`tf_regression`)
- cross-repository fork PR — a diff comment is posted instead
- `GITHUB_TOKEN` is missing
- GitHub Actions was not allowed to create pull requests in repository or organization settings

When this happens, inspect `artifacts/run_summary.json` and `decision_detail.reason_code` in the uploaded artifacts before changing the workflow.

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

- Use immutable tags for production rollout (for example `v0.1.0-alpha.3`).
- Keep a moving major tag for easier upgrades (`v0` -> latest `v0.x.y`).
- Publish release notes with behavior and policy changes.
