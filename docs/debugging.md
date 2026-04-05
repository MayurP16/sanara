# Debugging Runbook

When remediation fails, inspect artifacts in order:
1. `baseline/normalized_findings.json`
   Confirm mapping and target extraction.
2. `drc/patch_contract.json`
   Check transform failure code and preconditions.
3. `drc/patch.diff`
   Validate patch shape and path scope.
4. `terraform/baseline_checks.json`
   Check whether `terraform init` / `validate` was already failing before Sanara's fix.
   If `ok: false` here, the repo had a pre-existing Terraform failure — not caused by Sanara.
5. `terraform/*.log`
   Identify `init` / `validate` / `plan` gate failure in the post-fix run.
   Compare against `terraform/baseline_checks.json` to confirm whether Sanara introduced the failure (`tf_regression`) or it was pre-existing.
6. `rescan/targeted_results_final.json`
   Determine final blocking, advisory, and ignored findings after the last remediation stage.
   `rescan/targeted_results.json` is a convenience alias to the latest targeted results.
7. `runlog.jsonl`
   Locate failure state and timings.
8. `agentic/*` if used
   Review ledger scope and response trace.

Code navigation for triage:
- `sanara/orchestrator/driver.py`
  Run-state transitions and high-level decision wiring.
- `sanara/orchestrator/agentic.py`
  Fallback apply rounds, retry behavior, and post-apply checks.
- `sanara/orchestrator/publish.py`
  Dedup payload construction and remediation PR body generation.

## Common Commands

```bash
# Activate venv
source .venv/bin/activate

# Full test suite
.venv/bin/python -m pytest -q

# If scanner env vars are set in your shell, use this variant to avoid test mocking issues:
# env -u SANARA_CHECKOV_BIN -u SANARA_TFLINT_BIN .venv/bin/python -m pytest -q

# Simulation smoke
simulations/sanara-sim3/run_scenario.sh all10 mixed COMMENT_ONLY true

# Golden artifact assertions
python3 scripts/assert_simulation_golden.py simulations/sanara-sim3/artifacts

# Version consistency check
bash scripts/check_version_consistency.sh

# Policy preflight checks
.venv/bin/python -m sanara.cli validate --policy .sanara/policy.yml
.venv/bin/python -m sanara.cli policy lint --workspace .
```

## Local End-to-End Dry Run

Run Sanara against a target Terraform workspace without creating a remediation PR:

```bash
PYTHONPATH="$PWD" \
SANARA_CHECKOV_BIN="$PWD/.venv/bin/checkov" \
GITHUB_EVENT_NAME=pull_request \
GITHUB_RUN_ID=local-run \
GITHUB_ACTOR=local-dev \
INPUT_ALLOW_AGENTIC=false \
INPUT_PUBLISH_DRY_RUN=true \
INPUT_LLM_CONTEXT_MODE=minimal \
INPUT_LLM_PROVIDER=anthropic \
INPUT_PLAN_REQUIRED=false \
.venv/bin/python -m sanara.cli run \
  --event /path/to/target-repo/.sanara/event.local.json \
  --workspace /path/to/target-repo \
  --artifacts ./sanara-artifacts
```

Then inspect:

```bash
cat sanara-artifacts/summary.md
cat sanara-artifacts/policy/effective_config.json
ls sanara-artifacts/rescan/*_final.json
```

Release-specific steps are maintained privately with the maintainer release process.
