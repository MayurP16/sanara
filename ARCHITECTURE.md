# Sanara v0.1 Architecture

Sanara is a PR-native Terraform remediation engine delivered as a GitHub Action.

At a high level, Sanara:

1. discovers relevant Terraform targets
2. scans them with Checkov and normalizes findings into a stable internal format
3. applies deterministic fixes first
4. validates those fixes with safety rails and Terraform checks
5. optionally uses an LLM fallback for uncovered findings
6. optionally runs the LLM Advisor to surface additional findings beyond the deterministic ruleset
7. decides whether to create a remediation PR or fall back to comment-only output

The system is designed to be deterministic-first. LLM behavior is optional and only used after deterministic transforms have had a chance to resolve the finding set.

## End-to-end flow

```text
┌─ Init ──────────────────────────────────────────────────────────┐
│  start → load policy → detect repo context → find tf targets    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─ Scan ──────────────────────────────────────────────────────────┐
│  run Checkov → normalize findings → select findings to fix      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─ Deterministic remediation ─────────────────────────────────────┐
│  apply fix → validate patch → rescan                            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─ Agentic fallback (optional) ───────────────────────────────────┐
│  LLM generates fix → deterministic cleanup pass → final rescan  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─ Terraform checks ──────────────────────────────────────────────┐
│  fmt → init → validate → plan                                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─ LLM Advisor (optional) ────────────────────────────────────────┐
│  review changed tf files → surface additional findings          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─ Outcome ───────────────────────────────────────────────────────┐
│  decide → check for duplicate PRs                               │
│               ↓                        ↓                        │
│          open PR                  comment only                  │
│               └──────────┬──────────┘                          │
│                         done                                    │
└─────────────────────────────────────────────────────────────────┘
```

Each transition is appended to `artifacts/runlog.jsonl` with timestamps and durations for auditability.

## How Sanara makes changes safely

Sanara does not publish Terraform edits immediately after finding a match.

Before a remediation PR is created, the system can enforce:

- deterministic transform rules for mapped findings
- patch safety rails
- Terraform validation (`fmt`, `init -backend=false`, `validate`, `plan -refresh=false`)
- targeted rescans after patch application
- policy-aware final decisioning

If a safe remediation path is not available, Sanara can fall back to comment-only output instead of creating a PR.

## Main subsystems

- `sanara/orchestrator/`
  - Owns the top-level run lifecycle, state transitions, gating, decisioning, dedup, and publishing.
  - Internal split:
    - `driver.py`: primary orchestration and artifact wiring
    - `agentic.py`: LLM fallback apply loop and post-apply validation
    - `rescan_stage.py`: shared post-DRC and final rescan/policy pipeline
    - `publish.py`: PR/comment publishing and dedup helpers
    - `summary.py`: human-readable artifact summaries

- `sanara/policy/`
  - Loads `.sanara/policy.yml`, validates config, applies environment overrides, and evaluates scan/finding policy decisions.

- `sanara/scanners/`
  - Runs Checkov for target directories.
  - Uses an in-process per-run cache keyed on file signature. Post-patch rescans bypass the cache.

- `sanara/normalize/`
  - Converts scanner-native findings into stable Sanara finding objects.
  - Produces deterministic ordering and fingerprints.

- `sanara/drc/`
  - Deterministic remediation compiler and transform registry.
  - Uses parser-backed HCL discovery and minimal HCL edits with explicit failure codes.

- `sanara/rails/`
  - Applies global patch safety rules independently of any specific scanner or transform.

- `sanara/terraform/`
  - Resolves and runs Terraform validation.
  - Validation roots come from `examples/**` first, then `.sanara/harness.yml`.

- `sanara/github/`
  - Handles GitHub API interactions for dedup checks, comments, and remediation PR creation.

- `sanara/artifacts/`
  - Writes the evidence bundle for each run.

- `sanara/agentic/`
  - Optional LLM-backed fallback lane.
  - Includes HCL-aware context extraction, provider dispatch, and per-attempt tracing/ledger output.

## Deterministic and agentic behavior

- Deterministic remediation remains the primary path for mapped rules.
- Agentic fallback is optional and only considered for findings not resolved by deterministic transforms.
- Even with agentic disabled, a final deterministic cleanup pass may run if deterministic helper resources introduce newly mappable findings.

## Policy and Terraform validation

Policy is loaded from `.sanara/policy.yml` and can be overridden by GitHub Action inputs for a given run.

Important policy areas include:

- scan scope via `scan_policy`
- remediation and blocking behavior via `finding_policy`
- optional environment-specific overrides via `environments`

Terraform validation runs in this order:

1. `examples/**` — subdirectories of the `examples/` directory, if it exists
2. `.sanara/harness.yml` — explicit harness configuration
3. workspace root (`inferred_root`) — fallback if neither of the above is present
4. comment-only mode if `plan_required: true` and no runs succeeded

If `plan_required: true` and no runnable Terraform setup exists, Sanara does not create a remediation PR.

## Important contracts

Sanara relies on stable internal contracts for findings, summaries, patches, and policy artifacts. Important files include:

- `schemas/sanara.finding.v0.1.json`
- `schemas/sanara.run_summary.v0.1.json`
- `schemas/sanara.patch_contract.v0.1.json`
- `schemas/sanara.agent_trace.v0.1.json`
- `rules/mappings/checkov_to_sanara.v0.1.json`

## Extension points

- new scanner adapters can be added without changing the top-level orchestration contract
- target discovery can support additional Terraform layouts in future adapters
- deterministic transforms are registry-driven and versioned through `rule_pack_version`
