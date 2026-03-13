from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sanara.orchestrator.driver import run_driver
from sanara.orchestrator.policy import load_policy
from sanara.policy import (
    FINDING_POLICY_PRECEDENCE,
    SCAN_POLICY_PRECEDENCE,
    PolicyValidationError,
    classify_checkov_finding,
    finding_policy_decision,
    lint_policy_config,
    scan_policy_decision,
    validate_policy_config,
)
from sanara.scanners.runners import run_scan_only
from sanara.terraform.harness import run_harness_checks
from sanara.utils.io import read_yaml
from sanara.utils.logging_runtime import configure_logging


def _default_event_path() -> Path:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if path:
        return Path(path)
    return Path(".sanara/event.json")


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser(prog="sanara")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_parser = sub.add_parser("run")
    run_parser.add_argument("--event", type=Path, default=_default_event_path())
    run_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    run_parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))

    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--targets", nargs="+", required=True)
    scan_parser.add_argument("--workspace", type=Path, default=Path.cwd())

    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    validate_parser.add_argument("--harness", type=Path, default=Path(".sanara/harness.yml"))
    validate_parser.add_argument("--policy", type=Path, help="Validate a policy YAML file and exit")

    policy_parser = sub.add_parser("policy")
    policy_sub = policy_parser.add_subparsers(dest="policy_cmd", required=True)
    explain_parser = policy_sub.add_parser("explain")
    explain_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    explain_parser.add_argument("--check-id", required=True)
    explain_parser.add_argument("--resource-type", default="")
    explain_parser.add_argument("--resource-name", default="")
    explain_parser.add_argument("--file-path", default="")
    explain_parser.add_argument("--sanara-rule-id", default="")
    lint_parser = policy_sub.add_parser("lint")
    lint_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    lint_parser.add_argument(
        "--policy",
        type=Path,
        help="Path to policy YAML; defaults to <workspace>/.sanara/policy.yml",
    )

    args = parser.parse_args()

    if args.cmd == "run":
        return run_driver(args.workspace, args.event, args.artifacts)
    if args.cmd == "scan":
        policy = load_policy(args.workspace)
        result = run_scan_only(
            args.workspace, [Path(t) for t in args.targets], scan_policy=policy.scan_policy
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.cmd == "validate":
        if args.policy:
            try:
                data = read_yaml(args.policy)
                data = data or {}
                validate_policy_config(data)
                print(json.dumps({"ok": True, "path": str(args.policy)}, indent=2, sort_keys=True))
                return 0
            except (OSError, PolicyValidationError) as exc:
                print(
                    json.dumps(
                        {"ok": False, "path": str(args.policy), "error": str(exc)},
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 1
        result = run_harness_checks(args.workspace, args.harness)
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.ok else 1
    if args.cmd == "policy":
        if args.policy_cmd == "explain":
            policy = load_policy(args.workspace)
            finding = {
                "source_rule_id": str(args.check_id).upper(),
                "resource_type": str(args.resource_type),
                "resource_name": str(args.resource_name),
                "file_path": str(args.file_path),
                "sanara_rule_id": str(args.sanara_rule_id),
            }
            classification = classify_checkov_finding(
                finding["source_rule_id"], finding["resource_type"]
            )
            scan_decision = scan_policy_decision(policy, finding)
            finding_decision = finding_policy_decision(policy, finding)
            payload = {
                "ok": True,
                "environment": policy.environment,
                "finding": finding,
                "classification_default": classification,
                "scan_policy": {
                    "decision": scan_decision,
                    "precedence": SCAN_POLICY_PRECEDENCE,
                },
                "finding_policy": {
                    "decision": finding_decision,
                    "precedence": FINDING_POLICY_PRECEDENCE,
                },
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        if args.policy_cmd == "lint":
            policy_path = args.policy or (args.workspace / ".sanara/policy.yml")
            try:
                data = read_yaml(policy_path)
                data = data or {}
                validate_policy_config(data)
                report = lint_policy_config(data)
                payload = {"ok": bool(report.get("ok", False)), "path": str(policy_path), **report}
                print(json.dumps(payload, indent=2, sort_keys=True))
                return 0 if payload["ok"] else 1
            except (OSError, PolicyValidationError) as exc:
                print(
                    json.dumps(
                        {"ok": False, "path": str(policy_path), "error": str(exc)},
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
