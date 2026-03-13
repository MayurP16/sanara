# Sanara Simulation: `sanara-sim3`

Local simulation workspace to exercise Sanara behavior before running in a real repository.

Quick help:
```bash
simulations/sanara-sim3/run_scenario.sh --help
```
You can also assert expected outcomes:
```bash
simulations/sanara-sim3/run_scenario.sh all10 mixed PR_CREATED true
```

Regression pack (fixture-driven):
```bash
simulations/sanara-sim3/run_regression_pack.sh
# or
make sim-regression
```
Scenarios are defined in:
- deterministic default pack: `simulations/sanara-sim3/scenarios.yml`
- LLM/fallback pack (opt-in): `simulations/sanara-sim3/scenarios.llm.yml`

## What this includes
- `main.tf`: generated working file for each scenario run.
- `*.tf` (mixed profile): 8-file realistic module layout for broader accuracy testing.
- `templates/main.vulnerable.tmpl`: realistic vulnerable Terraform baseline.
- `templates/mixed/*.tf.tmpl`: vulnerable multi-file baseline.
- `.sanara/policy.yml` and `.sanara/harness.yml`: scenario policy/harness inputs.
- `tools/`: scanner stubs used for deterministic simulation modes.

## Scenarios
Run from repo root:

1. `all10` (deterministic full rule-pack)
```bash
simulations/sanara-sim3/run_scenario.sh all10 mixed
# or
make sim-all10
```
- Uses stub scanners.
- Emits all 10 mapped Checkov findings.
- Runs DRC transforms and validates targeted rescan behavior.

2. `fallback` (forced agentic initiation)
```bash
simulations/sanara-sim3/run_scenario.sh fallback mixed
# or
make sim-fallback
```
- Forces unresolved findings after DRC to trigger `AGENTIC_APPLY`.
- Uses explicit `llm_provider` selection in policy (default `anthropic`).
- If neither `ANTHROPIC_API_KEY` nor `OPENAI_API_KEY` is set, fallback is initiated but no LLM patch is applied.
- Scenario policy pins models to:
  - `claude-sonnet-4-6` (Anthropic)
  - `gpt-4o-mini` (OpenAI)

3. `real` (use installed local scanners)
```bash
simulations/sanara-sim3/run_scenario.sh real mixed
# or
make sim-real
```
- Uses the real `checkov` binary from your PATH.

4. `real-fallback` (real scanners + forced fallback path)
```bash
simulations/sanara-sim3/run_scenario.sh real-fallback mixed
```
- Uses the real `checkov` binary from your PATH.
- Applies a simulation-only mapping overlay so at least one mapped finding remains after DRC.
- Intended to exercise `AGENTIC_APPLY` with real scanner output.

5. `real-fallback-llm` (force real LLM attempts)
```bash
simulations/sanara-sim3/run_scenario.sh real-fallback-llm mixed
```
- Same as `real-fallback`, but requires an LLM API key to be set so agentic attempts run against the real LLM.

6. one-shot accuracy evaluation
```bash
simulations/sanara-sim3/evaluate_accuracy.sh
```
- Runs deterministic (`all10`) and fallback (`fallback`) on mixed profile.
- Prints targeted rescan + run summary + agentic ledger/trace.

Profiles:
- `mixed` (default): 8 Terraform files (recommended for realism).
- `single`: original one-file baseline.
- `public-s3`: your provided insecure public S3 + DynamoDB lock-table example.

Run your new profile:
```bash
simulations/sanara-sim3/run_scenario.sh real public-s3
```

## Reset
```bash
simulations/sanara-sim3/reset_vulnerable.sh mixed
```
- Restores `main.tf` to vulnerable baseline.
- For `public-s3`, restores your provided insecure public S3 baseline.
- Clears generated artifacts and security file.
- Keeps this simulation as an isolated local git repo for clean diff behavior.

## Artifacts
Scenario runs write to:
- `simulations/sanara-sim3/artifacts/`

Key files to inspect:
- `run_summary.json`
- `runlog.jsonl`
- `baseline/normalized_findings.json`
- `drc/patch_contract.json`
- `rescan/targeted_results.json`

After each run, `run_scenario.sh` also prints a quick console summary:
- decision
- baseline findings count
- DRC attempts count
- targeted rescan clean status
- remaining findings count
- agentic attempt count (when fallback runs)

Optional run assertions:
- Positional arg 3: expected decision (`PR_CREATED`, `COMMENT_ONLY`, `DRY_RUN_READY`, `DEDUP_SKIP`, ...)
- Positional arg 4: expected targeted clean (`true` or `false`)
- Script exits non-zero when assertions fail.
- CI uses this assertion mode for smoke coverage.

Note on LLM behavior:
- Default regression pack avoids forcing LLM attempts.
- Use `make sim-regression-llm` only when you explicitly want to test fallback/LLM paths.
