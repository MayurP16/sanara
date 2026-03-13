# Contributing to Sanara

Thanks for contributing.

## Development setup

1. Use Python 3.11.
2. Install dependencies:

```bash
python -m pip install -e '.[dev]'
```

3. Run a basic test pass:

```bash
python -m pytest -q
python scripts/check_repo_knowledge.py
```

If you are working inside the project virtual environment, `.venv/bin/python -m ...` is often the most reliable form.

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
