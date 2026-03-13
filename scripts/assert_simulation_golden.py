#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: assert_simulation_golden.py <artifacts_dir>", file=sys.stderr)
        return 2
    artifacts = Path(sys.argv[1])
    failures: list[str] = []

    run_summary = artifacts / "run_summary.json"
    summary_md = artifacts / "summary.md"
    policy_effective = artifacts / "policy/effective_config.json"
    policy_eval = artifacts / "policy/evaluation.json"
    targeted = artifacts / "rescan/targeted_results.json"

    for p in [run_summary, summary_md, policy_effective, policy_eval, targeted]:
        if not p.exists():
            failures.append(f"missing artifact: {p}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    rs = _load(run_summary)
    pe = _load(policy_effective)
    pv = _load(policy_eval)
    tr = _load(targeted)
    sm = summary_md.read_text(encoding="utf-8")

    if "decision" not in rs or "decision_detail" not in rs:
        failures.append("run_summary missing decision fields")
    if "environment" not in pe or "precedence" not in pe:
        failures.append("policy/effective_config missing environment/precedence")
    if pv.get("schema_id") != "sanara.policy_evaluation":
        failures.append("policy/evaluation schema_id mismatch")
    snapshots = pv.get("snapshots")
    if isinstance(snapshots, dict):
        if "baseline" not in snapshots:
            failures.append("policy/evaluation missing snapshots.baseline")
    elif "baseline" not in pv:
        # Backward-compatible check for older artifact shape.
        failures.append("policy/evaluation missing baseline snapshot")
    if "clean" not in tr:
        failures.append("targeted_results missing clean field")

    # Summary should expose policy-aware clean semantics and decision context.
    for needle in [
        "- Decision:",
        "- Policy-aware clean:",
        "Raw Checkov failures (baseline -> final):",
        "Advisory findings remaining:",
        "Policy overrides loaded:",
    ]:
        if needle not in sm:
            failures.append(f"summary.md missing line: {needle}")

    detailed = artifacts / "summary_detailed.md"
    index_md = artifacts / "artifacts/index.md"
    for p in [detailed, index_md]:
        if not p.exists():
            failures.append(f"missing artifact: {p}")
    if not failures:
        dm = detailed.read_text(encoding="utf-8")
        im = index_md.read_text(encoding="utf-8")
        for needle in ["- decision:", "- reason_code:", "- raw_checkov_failed_baseline:"]:
            if needle not in dm:
                failures.append(f"summary_detailed.md missing line: {needle}")
        for needle in ["# Sanara Artifact Index", "`summary.md`", "`run_summary.json`"]:
            if needle not in im:
                failures.append(f"artifacts/index.md missing line: {needle}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("simulation artifact golden assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
