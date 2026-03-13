from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sanara.utils.command import run_cmd
from sanara.utils.io import read_yaml


@dataclass
class HarnessRun:
    name: str
    working_dir: Path
    source: str = "configured"
    backend: bool = False
    refresh: bool = False
    init_args: list[str] = field(default_factory=list)
    validate_args: list[str] = field(default_factory=list)
    plan_args: list[str] = field(default_factory=list)
    var_files: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300


@dataclass
class HarnessResult:
    ok: bool
    runs: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "runs": self.runs}


def _has_root_terraform_files(workspace: Path) -> bool:
    return any(p.is_file() and p.suffix == ".tf" for p in workspace.iterdir())


def _normalize_args(values: Any) -> list[str]:
    if not values:
        return []
    if isinstance(values, list):
        return [str(v) for v in values if str(v).strip()]
    return [str(values)]


def _normalize_backend_config(values: Any) -> list[str]:
    if not values:
        return []
    if isinstance(values, dict):
        out: list[str] = []
        for key, value in values.items():
            out.append(f"-backend-config={key}={value}")
        return out
    if isinstance(values, list):
        return [f"-backend-config={v}" for v in values if str(v).strip()]
    return [f"-backend-config={values}"]


def discover_harness_runs(workspace: Path, harness_file: Path) -> list[HarnessRun]:
    if not harness_file.is_absolute():
        harness_file = workspace / harness_file
    examples = workspace / "examples"
    if examples.exists():
        runs = []
        for d in sorted(p for p in examples.iterdir() if p.is_dir()):
            runs.append(
                HarnessRun(
                    name=f"example-{d.name}",
                    working_dir=d,
                    source="examples",
                    backend=False,
                    refresh=False,
                    var_files=[],
                )
            )
        if runs:
            return runs

    if harness_file.exists():
        data = read_yaml(harness_file) or {}
        out: list[HarnessRun] = []
        for item in data.get("runs", []):
            init = item.get("init", {}) or {}
            validate = item.get("validate", {}) or {}
            plan = item.get("plan", {}) or {}
            out.append(
                HarnessRun(
                    name=item.get("name", "run"),
                    working_dir=workspace / item.get("working_dir", "."),
                    source="harness",
                    backend=bool(init.get("backend", False)),
                    refresh=bool(plan.get("refresh", False)),
                    init_args=_normalize_args(init.get("args"))
                    + _normalize_backend_config(init.get("backend_config")),
                    validate_args=_normalize_args(validate.get("args")),
                    plan_args=_normalize_args(plan.get("args")),
                    var_files=list(item.get("var_files", [])),
                    env=dict(item.get("env", {})),
                    timeout_seconds=int(item.get("timeout_seconds", 300)),
                )
            )
        return out
    if _has_root_terraform_files(workspace):
        return [
            HarnessRun(
                name="inferred-root",
                working_dir=workspace,
                source="inferred_root",
                backend=False,
                refresh=False,
                var_files=[],
            )
        ]
    return []


def _run_one(run: HarnessRun, workspace: Path) -> dict[str, object]:
    wd = run.working_dir if run.working_dir.is_absolute() else workspace / run.working_dir
    if not wd.exists():
        return {
            "name": run.name,
            "working_dir": str(wd),
            "error": "working_dir_missing",
            "ok": False,
        }
    init_cmd = ["terraform", "init", f"-backend={'true' if run.backend else 'false'}"]
    init_cmd.extend(run.init_args)
    init = run_cmd(init_cmd, cwd=wd, timeout_seconds=run.timeout_seconds, env=run.env)
    validate_cmd = ["terraform", "validate", *run.validate_args]
    validate = run_cmd(validate_cmd, cwd=wd, timeout_seconds=run.timeout_seconds, env=run.env)
    plan_cmd = ["terraform", "plan", f"-refresh={'true' if run.refresh else 'false'}"]
    for vf in run.var_files or []:
        plan_cmd.extend(["-var-file", vf])
    plan_cmd.extend(run.plan_args)
    plan = run_cmd(plan_cmd, cwd=wd, timeout_seconds=run.timeout_seconds, env=run.env)
    return {
        "name": run.name,
        "working_dir": str(wd),
        "source": run.source,
        "init": {
            "cmd": init_cmd,
            "code": init.code,
            "stdout": init.stdout,
            "stderr": init.stderr,
        },
        "validate": {
            "cmd": validate_cmd,
            "code": validate.code,
            "stdout": validate.stdout,
            "stderr": validate.stderr,
        },
        "plan": {
            "cmd": plan_cmd,
            "code": plan.code,
            "stdout": plan.stdout,
            "stderr": plan.stderr,
        },
        "ok": init.code == 0 and validate.code == 0 and plan.code == 0,
    }


def run_harness_checks(
    workspace: Path, harness_file: Path = Path(".sanara/harness.yml")
) -> HarnessResult:
    runs = discover_harness_runs(workspace, harness_file)
    if not runs:
        return HarnessResult(ok=False, runs=[])

    out = [_run_one(r, workspace) for r in runs]
    return HarnessResult(ok=all(bool(x["ok"]) for x in out), runs=out)
