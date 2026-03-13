.PHONY: version-check test test-cov release-check sim-all10 sim-fallback sim-real sim-regression sim-regression-llm

# Prefer the project virtualenv when it exists.
PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

# Verify package version files are aligned.
version-check:
	bash scripts/check_version_consistency.sh

# Fast local test pass.
test:
	$(PYTHON) -m pytest

# Coverage gate used in broader validation and release prep.
test-cov:
	$(PYTHON) -m pytest --cov=sanara/orchestrator --cov=sanara/drc --cov=sanara/rails --cov-fail-under=70

# Maintainer-oriented local release validation.
release-check: version-check test test-cov sim-regression
	@echo "Release checks passed."

# Simulation scenarios for local regression/debugging.
sim-all10:
	simulations/sanara-sim3/run_scenario.sh all10 mixed

sim-fallback:
	simulations/sanara-sim3/run_scenario.sh fallback mixed

sim-real:
	simulations/sanara-sim3/run_scenario.sh real mixed

# Full simulation regression packs.
sim-regression:
	simulations/sanara-sim3/run_regression_pack.sh

sim-regression-llm:
	simulations/sanara-sim3/run_regression_pack.sh simulations/sanara-sim3/scenarios.llm.yml
