# Configuration Guide

This guide covers the configuration most teams need to get Sanara running safely.

If you want the full key-by-key reference, see `docs/configuration-reference.md`.

## Mental model

Sanara configuration comes from three places:

1. GitHub Action inputs
2. `.sanara/policy.yml`
3. built-in defaults

In practice:
- you can start without a policy file at all
- add a small `.sanara/policy.yml` when you want repository-specific control
- use action inputs for per-workflow overrides
- use the reference doc only when you need advanced behavior

## Where configuration lives

- GitHub Action inputs
  - Best for workflow-level overrides such as `publish_dry_run`, `allow_agentic`, or model selection.
- `.sanara/policy.yml`
  - Best for repository policy such as scan scope, remediation behavior, and environment overrides.
  - Optional for first-time use.

## Minimal policy example

```yaml
allow_agentic: false
plan_required: true
publish_dry_run: true
```

This is enough for many first rollouts.
These same keys can also be set as GitHub Action inputs; use policy for repository defaults and workflow inputs for per-run overrides.

## Recommended first rollout

For most teams, a safe first rollout looks like this:

- keep `allow_agentic: false`
- keep `plan_required: true`
- set `publish_dry_run: true`
- add only a small amount of policy at first

Example workflow inputs (`sanara.yml`):

```yaml
- uses: your-org/sanara@<release-tag>
  with:
    allow_agentic: "false"
    plan_required: "true"
    publish_dry_run: "true"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Example repository policy (`.sanara/policy.yml`):

```yaml
scan_policy:
  skip_ids:
    - CKV_AWS_999

finding_policy:
  suggest_only:
    - CKV_AWS_70
```

Then:

1. Run in dry-run mode first.
2. Review `summary.md` and `artifacts/run_summary.json`.
3. Confirm the harness and Terraform gates behave as expected.
4. Turn off `publish_dry_run` when you are comfortable with the output.

## What to configure first

### `allow_agentic`

- Default: `false`
- Enables the optional LLM fallback path for findings without deterministic coverage.
- Recommended default for first rollout: `false`

### `plan_required`

- Default: `true`
- Requires a runnable Terraform harness before Sanara will create a remediation PR.
- Recommended default: keep this `true`

### `publish_dry_run`

- Default: `false`
- Runs the full pipeline and writes artifacts, but does not push a branch or open a PR.
- Recommended for first rollout: `true`

### `scan_policy`

Use `scan_policy` to control what is in scope for remediation and final decisioning.

Most common keys:
- `include_ids`
- `skip_ids`

Example:

```yaml
scan_policy:
  skip_ids:
    - CKV_AWS_999
```

### `finding_policy`

Use `finding_policy` to control how Sanara treats findings after detection.

Think of these controls as two separate decisions:

1. Should Sanara try to change code for this finding?
2. If the finding remains, should it block the final outcome?

### Remediation controls

- `auto_fix_allow`
  - Sanara is allowed to auto-fix this rule.
  - Use this when you trust automatic remediation for that finding.

- `auto_fix_deny`
  - Sanara must not auto-fix this rule.
  - Use this when the finding is too sensitive or context-dependent for automatic edits.

- `suggest_only`
  - Sanara may report the finding, but should not change code for it.
  - Use this for "show me the problem, but do not touch it" cases.

- `ignore`
  - Sanara should ignore the finding.
  - Use this sparingly for intentional exceptions or known noise.

### Blocking controls

- `hard_fail_on`
  - The finding is blocking if it remains.
  - Use this for issues you consider mandatory to resolve.

- `soft_fail_on`
  - The finding is advisory if it remains.
  - Use this for issues you still want surfaced, but not treated as blocking.

### Quick mental model

- `ignore` = hide it
- `suggest_only` = show it, do not change it
- `auto_fix_allow` = okay to fix it
- `auto_fix_deny` = never fix it
- `hard_fail_on` = blocking
- `soft_fail_on` = advisory

`suggest_only` and `soft_fail_on` are different:
- `suggest_only` controls whether Sanara edits code
- `soft_fail_on` controls whether the remaining finding blocks the final result

Example:

```yaml
finding_policy:
  suggest_only:
    - CKV_AWS_70
```

### `environment` and `environments`

Use these when you want different behavior by environment.

The active environment can be selected by action input, policy file, environment variable, or branch-based inference.

Example:

```yaml
environment: dev
environments:
  prod:
    allow_agentic: false
  dev:
    publish_dry_run: true
```

## Action inputs

The most common action inputs are:
- `allow_agentic`
- `plan_required`
- `publish_dry_run`
- `environment`
- `artifacts_dir`

LLM-related inputs also exist:
- `llm_provider`
  - Allowed values: `anthropic`, `openai`
- `anthropic_model`
  - Anthropic model ID, for example `claude-sonnet-4-6`
- `openai_model`
  - OpenAI model ID, for example `gpt-4o-mini`
- `agentic_max_attempts`
  - Maximum number of LLM remediation attempts in one run
  - Default: `16`
- `llm_context_mode`
  - Allowed values: `minimal`, `module`, `repo`
  - `minimal` is the narrowest context and the default
  - `module` and `repo` allow broader context collection when needed

Model selection is a normal configuration choice if your team wants to control cost, provider, or output quality.

## When you may not need policy yet

If you are only trying Sanara for the first time, you may not need much policy at all.

Start with:
- a basic workflow
- `publish_dry_run: true`
- `allow_agentic: false`

Then add `.sanara/policy.yml` once you want finer control over:
- scan scope
- remediation behavior
- blocking behavior
- environment-specific overrides

## What to read next

- `docs/terraform-validation.md` for Terraform validation behavior
- `docs/security/safety-rails.md` for patch safety rails
- `docs/security/llm-data-handling.md` for LLM handling and redaction
- `docs/configuration-reference.md` for the full configuration reference
