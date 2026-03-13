# Configuration Reference

This document lists the full configuration surface for Sanara.

Use this document when you need the exact input names, policy keys, and environment variables.
For a more approachable starting point, see `docs/configuration.md`.

There are three configuration layers:
- GitHub Action inputs in your workflow
- repository defaults in `.sanara/policy.yml`
- environment variables for runtime/tooling overrides

## Precedence

For policy keys exposed as action inputs:
1. GitHub Action input (`INPUT_*`)
2. `.sanara/policy.yml`
3. built-in default in `sanara/policy/`

For scanner/tool environment:
1. Explicit environment variable
2. Default binary/value in code

## GitHub Action Inputs

Defined in `action.yml`.

Action inputs are workflow-level overrides. Use them when you want to change behavior per workflow or per run.

- `allow_agentic` (`true|false`, default `false`)
- `llm_context_mode` (`minimal|module|repo`, default `minimal`)
- `llm_provider` (`anthropic|openai`, default `anthropic`)
- `anthropic_model` (default `claude-sonnet-4-6`)
- `openai_model` (default `gpt-4o-mini`)
- `agentic_max_attempts` (default `16`)
- `plan_required` (`true|false`, default `true`)
- `publish_dry_run` (`true|false`, default `false`)
- `environment` (optional)
- `log_level` (`DEBUG|INFO|WARNING|ERROR`, default `INFO`)
- `artifacts_dir` (default `artifacts`)

## Policy File Keys

Path: `.sanara/policy.yml`

Policy keys are repository-level defaults. Use them when you want behavior to live with the target repo rather than the workflow file.
Some keys overlap with GitHub Action inputs. In that case, the workflow input wins for that run.

Core runtime and safety:
- `rule_pack_version`
- `allow_agentic`
- `plan_required`
- `publish_dry_run`
- `max_runtime_seconds`
- `max_diff_lines`

Mutation scope:
- `allow_paths`
- `deny_paths`
- `allow_globs`
- `deny_globs`

LLM and advisor:
- `llm_context_mode`
- `llm_provider`
- `anthropic_model`
- `openai_model`
- `agentic_max_chars`
- `agentic_max_attempts`
- `advisor`

Scan and remediation policy:
- `scan_policy`
- `finding_policy`
- `apply_opt_in_rules`
- `allow_rules`
- `require_cmk_for`

Environment selection:
- `environment`
- `environments`

Template: `templates/policy.yml`

Schema references:
- `schemas/sanara.policy_config.v0.1.json`
- `schemas/sanara.policy_evaluation.v0.1.json`

## Scan Policy

`scan_policy` controls which findings remain in scope for remediation and final decisioning.

Current keys:
- `include_ids`
- `skip_ids`

Notes:
- `include_ids` / `skip_ids` are passed through to Checkov CLI (`--check` / `--skip-check`)

Artifacts:
- `policy/effective_config.json`
- `baseline/scan_policy_review.json`
- `rescan/scan_policy_review_post_drc.json`
- `rescan/scan_policy_review_final.json`

## Finding Policy

`finding_policy` controls how Sanara treats findings after detection.

Direct controls:
- `auto_fix_allow`
- `auto_fix_deny`
- `suggest_only`
- `ignore`
- `hard_fail_on`
- `soft_fail_on`

Artifacts:
- `baseline/policy_review.json`
- `rescan/policy_review_post_drc.json`
- `rescan/policy_review_final.json`
- `policy/evaluation.json`

## Advisor Policy

`advisor` controls the non-blocking post-fix guidance step.

Keys:
- `enabled` (`true|false`, default `true`)
- `use_llm` (`true|false`, default `false`)
- `max_findings` (default `5`)
- `min_severity` (`moderate|critical`, default `moderate`)

Artifacts:
- `advisor/findings.json`
- `advisor/raw_response.txt`

## Policy Precedence

Treat policy evaluation as three layers:

1. `scan_policy`
2. `finding_policy`
3. decision policy (`hard_fail_on` / `soft_fail_on`)

Within `scan_policy`, precedence is:
1. `include_ids`
2. `skip_ids`
3. default include

Within `finding_policy`, effective behavior is resolved in this order:
1. global lists
2. decision overrides
3. classifier defaults

## Policy CLI helpers

Inspect a policy decision:

```bash
python -m sanara.cli policy explain \
  --workspace . \
  --check-id CKV_AWS_70 \
  --resource-type aws_s3_bucket_policy \
  --resource-name public_bucket \
  --file-path main.tf
```

Lint policy logic:

```bash
python -m sanara.cli policy lint --workspace .
```

Validate policy schema:

```bash
python -m sanara.cli validate --policy .sanara/policy.yml
```

## Environment Overrides

Sanara supports deep-merged environment-specific overrides:

```yaml
environment: dev
environments:
  prod:
    allow_agentic: false
  dev:
    allow_agentic: true
    publish_dry_run: true
```

Resolution order for environment name:
1. `INPUT_ENVIRONMENT`
2. top-level `environment` in `.sanara/policy.yml`
3. `SANARA_ENVIRONMENT`
4. branch name inference:
   - `main`, `master`, `prod`, `production` → `prod`
   - `staging`, `stage`, `qa` → `staging`
   - `dev`, `develop` → `dev`

## Environment Variables

- `GITHUB_TOKEN`
  - Required for PR comments and PR creation.
- `ANTHROPIC_API_KEY`
  - Required when using Anthropic-backed LLM behavior.
- `OPENAI_API_KEY`
  - Required when using OpenAI-backed LLM behavior.
- `SANARA_SCHEMAS_DIR`
  - Overrides the schema directory used for validation.
- `SANARA_ENVIRONMENT`
  - Selects the active environment for policy overrides.
- `SANARA_CHECKOV_BIN`
  - Overrides the Checkov binary path or command name.
- `SANARA_SCAN_MAX_WORKERS`
  - Sets the maximum scanner worker count.
- `SANARA_SCAN_TIMEOUT_SECONDS`
  - Sets the per-target scanner timeout in seconds.
- `SANARA_SCAN_CACHE_ENABLED`
  - Enables or disables the in-process scan result cache.

## Runtime Outputs

Sanara also emits runtime artifacts such as:
- `artifacts/run_summary.json`
- `policy/evaluation.json`
- `policy/effective_config.json`

These are useful for debugging and automation, but they are output contracts rather than configuration.
