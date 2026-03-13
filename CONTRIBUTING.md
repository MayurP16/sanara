# Contributing to Sanara

Thanks for contributing.

## Development setup

### Prerequisites

Before setting up the project locally, make sure you have:

- **Python 3.11+** — required; check with `python --version`
- **Terraform** — required for validation and plan checks; install via [tfenv](https://github.com/tfutils/tfenv) or the [official installer](https://developer.hashicorp.com/terraform/install)
- **Checkov** — required for scanning; not bundled in the package, install separately:

```bash
pip install checkov==3.2.504
```

If you have Checkov installed at a non-default path, set `SANARA_CHECKOV_BIN` to point to it:

```bash
export SANARA_CHECKOV_BIN=/path/to/checkov
```

### Install

1. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install the package with dev dependencies:

```bash
pip install -e '.[dev]'
```

If you are working inside the project virtual environment, `.venv/bin/python -m ...` is often the most reliable form.

### Run tests

```bash
python -m pytest -q
python scripts/check_repo_knowledge.py
```

### Lint and format

```bash
ruff check sanara tests
black --check sanara tests
```

### Local dry run

Use the provided helper script to run Sanara against this repository locally without opening any PRs:

```bash
bash scripts/dry_run_local.sh
```

This generates `.sanara/event.local.json` and runs `python -m sanara.cli run` with `INPUT_PUBLISH_DRY_RUN=true`. Artifacts are written to `./artifacts`.

To run against a different workspace or target repository, pass paths explicitly:

```bash
bash scripts/dry_run_local.sh /path/to/event.json /path/to/artifacts
```

For a full end-to-end dry run with explicit environment variable control:

```bash
GITHUB_EVENT_NAME=pull_request \
GITHUB_RUN_ID=local-run \
GITHUB_ACTOR=local-dev \
INPUT_ALLOW_AGENTIC=false \
INPUT_PUBLISH_DRY_RUN=true \
INPUT_PLAN_REQUIRED=false \
python -m sanara.cli run \
  --event .sanara/event.local.json \
  --workspace . \
  --artifacts artifacts
```

Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in your environment if testing LLM features.

### Simulation harness

The `simulations/sanara-sim3/` directory contains a full regression harness with pre-built Terraform fixtures:

```bash
make sim-regression        # full regression pack
make sim-all10             # all-10 deterministic scenario
make sim-fallback          # LLM fallback scenario
```

See [simulations/sanara-sim3/README.md](simulations/sanara-sim3/README.md) for details.

## Pull requests

- create a feature branch from `main`
- keep changes scoped and reviewable
- add or update tests for behavior changes
- explain the problem, approach, and test evidence in the PR
- say whether the change was primarily written by hand or with AI-assisted / "vibe coding" help

There is no preference either way. This is only so reviewers know how to approach validation and testing.

## Changing deterministic remediation

When adding or changing a deterministic transform:

1. Update the implementation in `sanara/drc/transforms/core.py` and any registry wiring.
2. Update `rules/mappings/checkov_to_sanara.v0.1.json`.
3. Update repair profiles if needed.
4. Update the corresponding transform doc under `docs/transforms/v0.1/`.
5. Add or update tests in:
   - `tests/test_drc_transforms.py`
   - `tests/test_transforms.py`
   - `tests/test_transforms_golden.py`

If you change transform or mapping behavior, remember to bump `rule_pack_version`.

If you change schema shape, add a new versioned schema instead of mutating an old one.

## Useful checks

- full test suite:

```bash
python -m pytest
```

- version consistency:

```bash
bash scripts/check_version_consistency.sh
```

- release-level local validation:

```bash
make release-check
```

`make release-check` is mainly for release preparation and broader validation, not required for every small contribution.

## Security

Do not include secrets, tokens, or private customer data in issues, PRs, logs, or test fixtures.

If you believe you found a security issue, follow [SECURITY.md](SECURITY.md).

## Code of conduct

Please follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) when participating in the project.
