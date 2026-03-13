# Sanara v0.1

Sanara is a PR-native Terraform remediation engine for GitHub Actions. It scans infrastructure findings, applies deterministic fixes first, validates every patch with Terraform checks and targeted rescans, and only proposes changes when the result is safe and explainable.

**Status:** alpha. Deterministic remediation is the primary product surface. Agentic fallback is optional and experimental.

## Why Sanara

Most infrastructure security tools stop at detection. Most AI coding tools can suggest edits, but not always in a way that is predictable, reviewable, or safe to merge.

Sanara focuses on **trusted remediation**:

- deterministic fixes first
- validation gates before publish
- policy-controlled behavior
- artifact bundles for explainability and auditability
- optional LLM fallback only when explicitly enabled

The goal is not just to suggest a fix, but to produce a remediation path that teams can inspect, validate, and use in real pull request workflows.

## How Sanara works

At a high level, Sanara:

1. scans Terraform findings using Checkov
2. normalizes findings into stable internal schemas
3. attempts deterministic remediation first
4. runs validation gates such as Terraform checks and targeted rescans
5. publishes remediation only when the patch passes safety and verification requirements
6. writes an artifact bundle for debugging, review, and auditability

## Current scope

Sanara v0.1 is currently focused on:

- Terraform
- AWS-oriented Checkov findings
- GitHub Action based PR remediation

Sanara does **not** aim to provide full Checkov coverage today. The current deterministic ruleset is intentionally narrow and weighted toward common, high-value Terraform issues that can be fixed safely and repeatably.

## Deterministic support today

Sanara currently ships deterministic remediation for **36 AWS Checkov rule IDs**, mapped into **30 remediation rules** in the bundled ruleset.

Current coverage is intentionally focused on common Terraform hardening patterns, including:

- **S3 hardening:** public access blocks, encryption defaults, KMS-backed encryption, versioning, logging, ACL handling, secure transport, and event notifications
- **Data and state protection:** DynamoDB PITR and CMK encryption, EBS encryption, KMS rotation, and Secrets Manager encryption
- **Platform guardrails:** RDS public access, deletion protection, backup retention, EC2 IMDSv2, ECR scanning and encryption, Lambda tracing, CloudWatch encryption, and CloudTrail hardening

This is a subset of the broader AWS Checkov catalog, not full coverage. The deterministic ruleset is expected to expand over time, with priority given to findings that can be fixed safely, consistently, and with clear validation semantics.

## LLM fallback

Sanara also includes an optional LLM-assisted fallback path for findings that sit outside the deterministic ruleset or require broader contextual changes than a fixed transform can safely express.

This path is **experimental** and should be treated as a controlled long-tail remediation option.

Typical cases include:

- findings that do not yet have a deterministic remediation rule
- repository-specific Terraform layouts where a safe fix depends on surrounding context
- higher-context edits where the intended change is clear but not yet encoded as a reusable deterministic transform

LLM fallback does **not** replace the deterministic path. Sanara always attempts deterministic remediation first, and only then uses model-assisted changes when explicitly enabled.

Even in LLM mode, Sanara keeps core governance in place:

- bring your own model API key (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`)
- explicit opt-in via policy or action inputs
- configurable attempt limits such as `agentic_max_attempts`
- policy-aware eligibility checks for remediation
- post-patch validation gates, targeted rescans, and publish controls

Over time, this path is expected to evolve into a more capable remediation system that can better decide when deterministic logic is sufficient and when model-assisted edits are the better fit. In v0.1, deterministic remediation remains the primary path, with LLM fallback acting as a controlled supplement.

## Quick start

Use Sanara from another repository as a pinned GitHub Action:

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

      - uses: your-org/sanara@<release-tag>
        with:
          allow_agentic: "false"
          publish_dry_run: "false"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

## Quick start

Use Sanara from another repository as a pinned GitHub Action:

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
      - uses: your-org/sanara@<release-tag>
        with:
          allow_agentic: "false"
          publish_dry_run: "false"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

For rollout guidance, see [docs/github-action-setup.md](docs/github-action-setup.md).

## Local development

```bash
pip install -e .[dev]
python -m pytest
python scripts/check_repo_knowledge.py
python -m sanara.cli run --event .sanara/event.json --workspace . --artifacts artifacts
```

Useful local references:
- simulation workspace: [simulations/sanara-sim3/README.md](simulations/sanara-sim3/README.md)
- configuration guide: [docs/configuration.md](docs/configuration.md)
- debugging guide: [docs/debugging.md](docs/debugging.md)

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

## Project docs

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reporting: [SECURITY.md](SECURITY.md)
- Support: [SUPPORT.md](SUPPORT.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
