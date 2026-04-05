from __future__ import annotations

from sanara.orchestrator.driver import _terraform_delta_summary


def _run(name: str, working_dir: str, *, init=0, validate=0, plan=0, stderr: str = "") -> dict:
    return {
        "name": name,
        "working_dir": working_dir,
        "init": {"code": init, "stderr": stderr if init else "", "stdout": ""},
        "validate": {"code": validate, "stderr": stderr if validate else "", "stdout": ""},
        "plan": {"code": plan, "stderr": stderr if plan else "", "stdout": ""},
        "ok": init == 0 and validate == 0 and plan == 0,
    }


def test_terraform_delta_detects_new_failure_even_when_other_baseline_failure_unchanged() -> None:
    baseline = {
        "ok": False,
        "runs": [
            _run(
                "example-a", "/repo/examples/a", init=1, stderr="Unsupported Terraform Core version"
            ),
            _run("example-b", "/repo/examples/b"),
        ],
    }
    current = {
        "ok": False,
        "runs": [
            _run(
                "example-a", "/repo/examples/a", init=1, stderr="Unsupported Terraform Core version"
            ),
            _run("example-b", "/repo/examples/b", validate=1, stderr="Invalid attribute name"),
        ],
    }
    summary = _terraform_delta_summary(baseline, current)
    assert summary["pre_existing_tf_failure"] is True
    assert summary["tf_regression"] is True
    assert len(summary["changed_failures"]) == 1


def test_terraform_delta_treats_same_baseline_failure_as_non_regression() -> None:
    baseline = {
        "ok": False,
        "runs": [
            _run(
                "example-a", "/repo/examples/a", init=1, stderr="Unsupported Terraform Core version"
            ),
        ],
    }
    current = {
        "ok": False,
        "runs": [
            _run(
                "example-a", "/repo/examples/a", init=1, stderr="Unsupported Terraform Core version"
            ),
        ],
    }
    summary = _terraform_delta_summary(baseline, current)
    assert summary["pre_existing_tf_failure"] is True
    assert summary["tf_regression"] is False


def test_terraform_delta_treats_changed_failure_signature_as_regression() -> None:
    baseline = {
        "ok": False,
        "runs": [
            _run(
                "example-a", "/repo/examples/a", init=1, stderr="Unsupported Terraform Core version"
            ),
        ],
    }
    current = {
        "ok": False,
        "runs": [
            _run("example-a", "/repo/examples/a", validate=1, stderr="Invalid attribute name"),
        ],
    }
    summary = _terraform_delta_summary(baseline, current)
    assert summary["tf_regression"] is True
    assert summary["pre_existing_tf_failure"] is False
