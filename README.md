# Sanara v0.1

![status](https://img.shields.io/badge/status-alpha-orange) ![scope](https://img.shields.io/badge/scope-Terraform%20%7C%20AWS%20%7C%20GitHub%20Actions-blue)

Sanara is a PR-native Terraform remediation engine for GitHub Actions. It scans infrastructure findings, applies deterministic fixes first, validates every patch with Terraform checks and targeted rescans, and only proposes changes when the result is safe and explainable.

**Status:** alpha. Deterministic remediation is the primary product surface. Agentic fallback is optional and experimental.

## Looking for design partners and early feedback

If you manage Terraform and deal with scanner backlogs, I'd love to hear from you — especially on:

- **Setup friction** — was the workflow and config clear enough to get running?
- **Remediation quality** — false positives, low-value fixes, or patches you wouldn't merge?
- **Rule coverage** — findings Sanara doesn't handle that you expected it to
- **LLM paths** — if you've tried the LLM fallback or LLM Advisor, was the output useful? Too noisy? Would you trust it enough to act on?

Two ways to reach me:

- [Book time with me](https://calendly.com/patelm95/quick-chat) — open to anything: feedback, questions, how it fits your setup, or working through the integration together on your repo
- [Open an issue](https://github.com/MayurP16/sanara/issues/new) — feedback, bug reports, questions, or feature requests

## Why Sanara

Security scanners find problems. They rarely fix them.

When a scanner flags 40 Terraform findings, someone still has to read each one, understand the fix, write the patch, validate it doesn't break anything, and get it through review. At scale, that work either piles up in a backlog or gets delegated to AI tools that suggest plausible-looking changes with no validation, no audit trail, and no guarantee the result still plans cleanly.

Sanara is built around a different idea: **remediation should be as trustworthy as the code it fixes**.

That means:

- **Deterministic fixes first.** Known findings get known fixes — not suggestions, not diffs that need interpretation. A structured transform is applied, the result is validated, and the patch either passes or it doesn't.
- **Validation before publish.** Every patch runs through Terraform validate and plan checks. Sanara does not open a PR for a fix it cannot verify.
- **A clear audit trail.** Every run produces an artifact bundle with the findings, the patch, the validation results, and the remediation decision. Teams can review what changed and why.
- **Policy-controlled behavior.** Scope, severity thresholds, agentic mode, publish controls — all configurable per repository.
- **LLM assistance without LLM risk.** When a finding falls outside the deterministic ruleset, an optional model-assisted path can fill the gap — but it stays behind the same validation gates and explicit opt-in requirements as everything else.

The result is a remediation path that fits into real pull request workflows: reviewable, repeatable, and safe to run in CI.

## How Sanara works

Sanara runs as a GitHub Action on pull requests. When triggered, it:

1. **Scans** — runs Checkov against the Terraform in the PR and normalizes findings into a stable internal schema
2. **Remediates** — applies deterministic fixes for known findings; each fix is a structured transform, not a generated suggestion
3. **Validates** — runs `terraform fmt`, `terraform init`, `terraform plan` and a targeted rescan of the patched resources to confirm the fix is clean
4. **Publishes** — opens or updates a PR with the patch only if validation passes; findings that fail validation are skipped
5. **Advises** — optionally runs the LLM Advisor on changed `.tf` files to surface additional security concerns outside the deterministic ruleset
6. **Audits** — writes a full artifact bundle per run: findings, patch, validation results, advisor output, and remediation decisions

## Prerequisites

Before adding Sanara to a repository, confirm you have:

- A GitHub repository with Terraform (`.tf`) files
- GitHub Actions enabled
- GitHub Actions repository settings configured to allow PR creation:
  - `Settings` -> `Actions` -> `General` -> `Workflow permissions` -> `Read and write permissions`
  - enable `Allow GitHub Actions to create and approve pull requests`
- Familiarity with [Checkov](https://www.checkov.io/) findings is helpful but not required — Sanara normalizes findings internally
- AWS credentials available as repository secrets (only required if `plan_required: true`)
- The built-in `secrets.GITHUB_TOKEN` available to GitHub Actions workflows
  - add workflow permissions for `contents: write` and `pull-requests: write`
  - use a fine-grained PAT only if your repo/org policy blocks the built-in token
- An `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` — create a key from your [Anthropic Console](https://console.anthropic.com/) or [OpenAI dashboard](https://platform.openai.com/api-keys) and add it as a repository secret (only required if LLM fallback or the LLM Advisor is enabled)

## Quick start

Sanara requires one file in your repository, with two optional configuration files:

| File | Required | Purpose |
|------|----------|---------|
| `.github/workflows/sanara.yml` | Required | GitHub Actions workflow |
| `.sanara/policy.yml` | Optional | Controls remediation behavior — which findings to fix, suggest, or skip |
| `.sanara/harness.yml` | Optional | Controls how Terraform is initialized, validated, and planned |

Starter templates for all three are in the [templates/](templates/) directory. Copy them into your repository and adjust to your environment.

A minimal workflow looks like this:

```yaml
name: sanara
on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  id-token: write  # optional — only required if plan_required: true

env:
  TF_IN_AUTOMATION: true

jobs:
  remediate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required — Sanara uses full git history to identify changed files

      - name: Setup Git
        run: |
          git config user.name "Sanara[bot]"
          git config user.email "sanara-bot@users.noreply.github.com"

      - uses: hashicorp/setup-terraform@v3

      # Optional — only required if plan_required: true in policy.yml or action inputs.
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - uses: MayurP16/sanara@v0.1.0a3  # replace with the latest tag from the releases page
        with:
          publish_dry_run: "true"  # preview mode — switch to "false" once validated
          allow_agentic: "false"   # set to "true" to enable LLM fallback
          plan_required: "true"    # set to "false" to skip terraform plan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sanara-artifacts
          path: artifacts
```

Start with `publish_dry_run: "true"` on first rollout. Sanara will validate and log what it would remediate without opening any PRs. Switch to `"false"` once you're comfortable with the output.

### Trigger behavior

Sanara changes scope based on the GitHub event that starts the workflow:

- `pull_request`
  - scans only `.tf` files changed in the PR
  - use this for normal PR remediation during review
- `workflow_dispatch`
  - manual run from the Actions tab
  - scans all `.tf` files in the checked-out repository workspace
- `push`
  - scans all `.tf` files in the checked-out repository workspace
  - useful for baseline remediation after a PR is merged into `main`

If you want Sanara to remediate Terraform that already exists on `main`, not just Terraform changed in an open PR, add a `push` trigger for your default branch or run the workflow manually with `workflow_dispatch`.

**What happens when validation fails?** Findings that don't pass validation are skipped and recorded in the artifact bundle with a reason. The workflow step exits successfully — it does not fail CI — so a finding with no safe fix never blocks the PR it came from.

For full rollout guidance, see [docs/github-action-setup.md](docs/github-action-setup.md).

## Coverage

### Deterministic ruleset

Sanara v0.1 ships **30 remediation rules** covering **36 AWS Checkov rule IDs**. These are not generated fixes — each rule is a validated transform that has been tested to apply cleanly and pass a rescan.

Coverage is intentionally focused on high-frequency, high-confidence hardening patterns across the most commonly misconfigured AWS services:

- **S3:** public access blocks, encryption defaults, KMS-backed encryption, versioning, logging, ACL handling, secure transport, and event notifications
- **Data and state:** DynamoDB PITR and CMK encryption, EBS encryption, KMS key rotation, and Secrets Manager encryption
- **Platform:** RDS public access and deletion protection, RDS backup retention, EC2 IMDSv2, ECR image scanning and encryption, Lambda tracing, CloudWatch log encryption, and CloudTrail hardening

The ruleset is narrow by design. Rules are added when a finding is common enough to matter, the fix is safe to apply without broader context, and the validation semantics are unambiguous. A smaller ruleset with high confidence is more useful in production than broad coverage with unpredictable results.

The ruleset will grow over time. For findings outside the current set, the LLM fallback and LLM Advisor provide supplementary coverage.

### Current limits

Sanara v0.1 is currently focused on:

- Terraform only (no CloudFormation, CDK, or Pulumi)
- AWS-oriented Checkov findings
- GitHub Actions-based PR remediation

## LLM features

> **Quick distinction:** LLM fallback *patches findings* — it generates a fix and runs it through the same validation pipeline as deterministic rules. LLM Advisor *surfaces findings* — it reviews changed files and reports concerns, but never modifies code or blocks a PR.

Both features are disabled by default and require a `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` to be set.

### LLM fallback

The deterministic ruleset covers common, well-understood findings. Not everything fits that mold.

LLM fallback handles the long tail: findings that don't yet have a deterministic rule, repository-specific Terraform layouts where the right fix depends on surrounding context, and cases where the intended change is clear but too variable to encode as a reusable transform.

When enabled, Sanara attempts deterministic remediation first. If a finding isn't covered, and LLM fallback is authorized, Sanara uses a model to generate the patch — then runs it through the same validation pipeline: format checks, init, targeted rescan, and publish controls. A model-generated fix that doesn't pass validation doesn't ship.

This path is **experimental**. It is off by default and should be treated as a controlled supplement to the deterministic path, not a replacement for it.

Governance controls apply in LLM mode just as in deterministic mode:

- **Explicit opt-in** — enable via `allow_agentic: "true"` in the action or policy config
- **Bring your own key** — `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`; no keys are hosted or shared by Sanara
- **Attempt limits** — configurable via `agentic_max_attempts` to bound model usage per run
- **Policy eligibility checks** — findings are screened against policy before a model is invoked
- **Full validation gates** — same post-patch checks as deterministic remediation; no special treatment for LLM-generated diffs

### LLM Advisor

Sanara includes an optional **LLM Advisor** that provides supplementary security guidance beyond what the deterministic scanner and LLM fallback detects. It runs as a non-blocking, advisory-only stage after remediation is complete.

The advisor reviews Terraform files changed in the PR and surfaces additional high-signal security findings that fall outside the Checkov ruleset or require broader context to identify. Results are written to an artifact bundle and can be surfaced in the PR summary, but they never block publish or force additional remediation cycles.

## Local development

```bash
pip install -e .[dev]
python -m pytest
python scripts/check_repo_knowledge.py  # validates that all Checkov rule IDs in the ruleset have corresponding rule implementations
bash scripts/dry_run_local.sh           # dry run against this workspace; artifacts written to ./artifacts
```

Requires Python 3.11+, Terraform, and Checkov installed separately (`pip install checkov==3.2.504`). For full setup instructions, environment variables, and the simulation harness, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- Setting up Sanara in another repository: [docs/github-action-setup.md](docs/github-action-setup.md)
- Configuring policy and runtime behavior: [docs/configuration.md](docs/configuration.md)
- Full configuration reference: [docs/configuration-reference.md](docs/configuration-reference.md)
- Understanding Terraform validation: [docs/terraform-validation.md](docs/terraform-validation.md)
- Understanding how Sanara works: [ARCHITECTURE.md](ARCHITECTURE.md)
- Debugging runs and artifacts: [docs/debugging.md](docs/debugging.md)
- Security model: [docs/security/safety-rails.md](docs/security/safety-rails.md)
- LLM data handling: [docs/security/llm-data-handling.md](docs/security/llm-data-handling.md)
- Upgrading Sanara in an existing repo: [docs/upgrading.md](docs/upgrading.md)
- simulation workspace: [simulations/sanara-sim3/README.md](simulations/sanara-sim3/README.md)

## Project docs

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reporting: [SECURITY.md](SECURITY.md)
- Support: [SUPPORT.md](SUPPORT.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
