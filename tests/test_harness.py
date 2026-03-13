from __future__ import annotations

from pathlib import Path

from sanara.terraform import harness


class _Result:
    def __init__(self, code: int = 0):
        self.code = code
        self.stdout = "ok"
        self.stderr = ""


def test_harness_with_examples(monkeypatch, tmp_path: Path) -> None:
    ex = tmp_path / "examples" / "basic"
    ex.mkdir(parents=True)
    (ex / "main.tf").write_text("terraform {}\n", encoding="utf-8")

    monkeypatch.setattr(harness, "run_cmd", lambda cmd, cwd, **kwargs: _Result(0))

    result = harness.run_harness_checks(tmp_path)
    assert result.ok
    assert len(result.runs) == 1
    assert result.runs[0]["source"] == "examples"
    assert result.runs[0]["init"]["cmd"] == ["terraform", "init", "-backend=false"]
    assert result.runs[0]["validate"]["cmd"] == ["terraform", "validate"]
    assert result.runs[0]["plan"]["cmd"] == ["terraform", "plan", "-refresh=false"]


def test_harness_infers_root_when_no_explicit_harness(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("terraform {}\n", encoding="utf-8")

    monkeypatch.setattr(harness, "run_cmd", lambda cmd, cwd, **kwargs: _Result(0))

    result = harness.run_harness_checks(tmp_path)
    assert result.ok
    assert len(result.runs) == 1
    assert result.runs[0]["name"] == "inferred-root"
    assert result.runs[0]["source"] == "inferred_root"
    assert result.runs[0]["working_dir"] == str(tmp_path)
    assert result.runs[0]["init"]["cmd"] == ["terraform", "init", "-backend=false"]
    assert result.runs[0]["validate"]["cmd"] == ["terraform", "validate"]
    assert result.runs[0]["plan"]["cmd"] == ["terraform", "plan", "-refresh=false"]


def test_harness_supports_explicit_init_and_plan_args(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / ".sanara").mkdir()
    (tmp_path / "main.tf").write_text("terraform {}\n", encoding="utf-8")
    (tmp_path / ".sanara/harness.yml").write_text(
        "\n".join(
            [
                "version: 1",
                "runs:",
                "  - name: root",
                "    working_dir: .",
                "    init:",
                "      backend: true",
                "      backend_config:",
                "        bucket: terraform-sbx-state",
                "        key: terraform-sample-module/terraform.tfstate",
                "        region: us-east-1",
                "      args:",
                "        - -input=false",
                "    validate:",
                "      args:",
                "        - -no-color",
                "    plan:",
                "      refresh: true",
                "      args:",
                "        - -input=false",
                "        - -no-color",
                "        - -out=tfplan",
                "    var_files:",
                "      - dev.tfvars",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    seen: list[list[str]] = []

    def _run(cmd, cwd, **kwargs):
        seen.append(cmd)
        return _Result(0)

    monkeypatch.setattr(harness, "run_cmd", _run)

    result = harness.run_harness_checks(tmp_path)
    assert result.ok
    assert len(result.runs) == 1
    run = result.runs[0]
    assert run["source"] == "harness"
    assert run["init"]["cmd"] == [
        "terraform",
        "init",
        "-backend=true",
        "-input=false",
        "-backend-config=bucket=terraform-sbx-state",
        "-backend-config=key=terraform-sample-module/terraform.tfstate",
        "-backend-config=region=us-east-1",
    ]
    assert run["validate"]["cmd"] == ["terraform", "validate", "-no-color"]
    assert run["plan"]["cmd"] == [
        "terraform",
        "plan",
        "-refresh=true",
        "-var-file",
        "dev.tfvars",
        "-input=false",
        "-no-color",
        "-out=tfplan",
    ]
    assert seen == [run["init"]["cmd"], run["validate"]["cmd"], run["plan"]["cmd"]]
