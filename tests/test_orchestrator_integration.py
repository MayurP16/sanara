from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from sanara.orchestrator import agentic as agentic_module
from sanara.orchestrator import driver
from sanara.utils.command import CommandError, CommandResult
from sanara.utils.hashing import sha256_text


class FakeGitHubClient:
    instances: list["FakeGitHubClient"] = []

    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.created_prs: list[dict] = []
        self.comments: list[str] = []
        self.open_prs: list[dict] = []
        FakeGitHubClient.instances.append(self)

    def dedup_key(
        self, base_sha: str, attempted_rule_ids: list[str], target_dirs: list[str], patch_hash: str
    ) -> str:
        return f"dedup:{base_sha}:{','.join(sorted(attempted_rule_ids))}:{patch_hash}"

    @staticmethod
    def dedup_marker(dedup_payload: dict) -> str:
        return f"<!-- sanara-dedup:{json.dumps(dedup_payload, sort_keys=True)} -->"

    @staticmethod
    def parse_dedup_marker(body: str):
        start = body.find("<!-- sanara-dedup:")
        if start < 0:
            return None
        end = body.find("-->", start)
        if end < 0:
            return None
        try:
            return json.loads(body[start + len("<!-- sanara-dedup:") : end])
        except Exception:
            return None

    def list_open_prs(self, head_branch_prefix: str = "sanara/fix-"):
        _ = head_branch_prefix
        return self.open_prs

    def create_pr(self, title: str, body: str, head: str, base: str, draft: bool = False):
        payload = {"title": title, "body": body, "head": head, "base": base, "draft": draft}
        self.created_prs.append(payload)
        return payload

    def comment_pr(self, pr_number: int, body: str):
        self.comments.append(f"{pr_number}:{body}")
        return {"id": 1}


class FakeAgentic:
    def __init__(self, ok: bool, patch_diff: str):
        self.used = True
        self.ok = ok
        self.message = "ok"
        self.patch_diff = patch_diff
        self.ledger = {"files_sent": [], "mode": "minimal", "total_chars": 0}
        self.trace = [{"event": "request"}, {"event": "response"}]


def _event(is_fork: bool = False) -> dict:
    return {
        "pull_request": {
            "number": 42,
            "base": {"sha": "base", "ref": "main"},
            "head": {"sha": "head", "ref": "feature", "repo": {"fork": is_fork}},
        },
        "sender": {"login": "dev"},
        "repository": {"full_name": "org/repo"},
    }


def _finding(module_dir: Path) -> dict:
    return {
        "schema_id": "sanara.finding",
        "schema_version": "0.1",
        "sanara_rule_id": "aws.ebs.encrypted",
        "source": "checkov",
        "source_rule_id": "CKV_AWS_3",
        "severity": "high",
        "target": {"module_dir": str(module_dir), "file_path": "main.tf", "line_range": "1-2"},
        "resource_type": "aws_ebs_volume",
        "resource_name": "data",
        "fingerprint": "a" * 64,
    }


def _unmapped_checkov_result() -> dict:
    return {
        "results": [
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_999",
                            "file_path": "/main.tf",
                            "file_abs_path": "/tmp/main.tf",
                            "file_line_range": [1, 2],
                            "resource": "aws_s3_bucket.public_bucket",
                        }
                    ]
                }
            }
        ]
    }


def _setup_workspace(
    tmp_path: Path, *, is_fork: bool = False, policy_extra: str = ""
) -> tuple[Path, Path]:
    workspace = tmp_path
    artifacts = workspace / "artifacts"
    FakeGitHubClient.instances.clear()
    (workspace / "rules/mappings").mkdir(parents=True)
    (workspace / ".sanara").mkdir(parents=True)

    mapping = {
        "rule_pack_version": "v0.1.0",
        "mappings": {"CKV_AWS_3": "aws.ebs.encrypted"},
    }
    (workspace / "rules/mappings/checkov_to_sanara.v0.1.json").write_text(
        json.dumps(mapping), encoding="utf-8"
    )
    (workspace / ".sanara/policy.yml").write_text(
        "allow_agentic: false\nplan_required: true\n" + policy_extra, encoding="utf-8"
    )
    (workspace / ".sanara/harness.yml").write_text("version: 1\nruns: []\n", encoding="utf-8")
    (workspace / "event.json").write_text(json.dumps(_event(is_fork=is_fork)), encoding="utf-8")
    return workspace, artifacts


def _patch_driver_basics(monkeypatch, workspace: Path, *, clean: bool = True) -> None:
    def discover(*args, **kwargs):
        return [workspace]

    def scan_only(*args, **kwargs):
        return {"checkov": {"results": [{"results": {"failed_checks": []}}]}}

    def mapping(*args, **kwargs):
        return {"CKV_AWS_3": "aws.ebs.encrypted"}

    def validate(*args, **kwargs):
        return SimpleNamespace(ok=True, code="OK", message="ok")

    def _harness_payload() -> dict:
        return {
            "ok": True,
            "runs": [
                {
                    "name": "x",
                    "source": "harness",
                    "working_dir": str(workspace),
                    "init": {
                        "cmd": ["terraform", "init"],
                        "code": 0,
                        "stdout": "",
                        "stderr": "",
                    },
                    "validate": {
                        "cmd": ["terraform", "validate"],
                        "code": 0,
                        "stdout": "",
                        "stderr": "",
                    },
                    "plan": {
                        "cmd": ["terraform", "plan"],
                        "code": 0,
                        "stdout": "",
                        "stderr": "",
                    },
                    "ok": True,
                }
            ],
        }

    def harness(*args, **kwargs):
        payload = _harness_payload()
        return SimpleNamespace(ok=True, runs=payload["runs"], to_dict=lambda: payload)

    def run_cmd_stub(*args, **kwargs):
        return CommandResult(cmd=["terraform"], code=0, stdout="", stderr="")

    monkeypatch.setattr(driver, "discover_target_dirs", discover)
    monkeypatch.setattr(
        driver,
        "run_scan_only",
        scan_only,
    )
    monkeypatch.setattr(agentic_module, "run_scan_only", scan_only)
    monkeypatch.setattr(driver, "load_mapping", mapping)
    normalize_calls = {"n": 0}

    def _normalize_all(*args, **kwargs):
        _ = args, kwargs
        normalize_calls["n"] += 1
        if normalize_calls["n"] == 1:
            return [_finding(workspace)]
        return [] if clean else [_finding(workspace)]

    monkeypatch.setattr(driver, "normalize_all", _normalize_all)
    # Agentic module no longer imports normalize_all directly.
    monkeypatch.setattr(
        driver,
        "apply_drc",
        lambda *args, **kwargs: [
            SimpleNamespace(
                sanara_rule_id="aws.ebs.encrypted",
                status="changed",
                code="OK",
                message="ok",
                contract=None,
            )
        ],
    )
    monkeypatch.setattr(driver, "validate_patch", validate)
    monkeypatch.setattr(agentic_module, "validate_patch", validate)
    monkeypatch.setattr(driver, "run_harness_checks", harness)
    monkeypatch.setattr(agentic_module, "run_harness_checks", harness)
    monkeypatch.setattr(
        driver,
        "_git_diff",
        lambda *args, **kwargs: "diff --git a/main.tf b/main.tf\n+encrypted = true\n",
    )
    monkeypatch.setattr(driver, "_has_changes", lambda *args, **kwargs: True)
    monkeypatch.setattr(driver, "_ensure_branch_and_push", lambda *args, **kwargs: None)
    monkeypatch.setattr(driver, "run_cmd", run_cmd_stub)
    monkeypatch.setattr(agentic_module, "run_cmd", run_cmd_stub)


def test_comment_only_when_missing_harness(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(tmp_path)
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace)
    monkeypatch.setattr(
        driver,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=False, runs=[], to_dict=lambda: {"ok": False, "runs": []}
        ),
    )

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert (artifacts / "summary.md").exists()
    assert (artifacts / "terraform/fmt.log").exists()
    summary = json.loads((artifacts / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["schema_version"] == "0.2"


def test_opt_in_plan_required_false_allows_no_harness(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(tmp_path, policy_extra="plan_required: false\n")
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace)
    monkeypatch.setattr(
        driver,
        "run_harness_checks",
        lambda *args, **kwargs: SimpleNamespace(
            ok=False, runs=[], to_dict=lambda: {"ok": False, "runs": []}
        ),
    )

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(driver, "GitHubClient", FakeGitHubClient)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert FakeGitHubClient.instances[-1].created_prs


def test_fork_disables_pr_creation(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(tmp_path, is_fork=True)
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(driver, "GitHubClient", FakeGitHubClient)
    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert not FakeGitHubClient.instances[-1].created_prs


def test_dedup_skips_pr_creation(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(tmp_path)
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(driver, "GitHubClient", FakeGitHubClient)

    client = FakeGitHubClient("token", "org/repo")
    dedup_payload = {
        "base_sha": "base",
        "attempted_rule_ids": ["aws.ebs.encrypted"],
        "target_dirs": [str(workspace)],
        "patch_hash": sha256_text("diff --git a/main.tf b/main.tf\n+encrypted = true\n"),
        "dedup_key": "dedup:base:aws.ebs.encrypted:"
        + sha256_text("diff --git a/main.tf b/main.tf\n+encrypted = true\n"),
    }
    client.open_prs = [
        {"body": FakeGitHubClient.dedup_marker(dedup_payload), "head": {"ref": "sanara/fix-1"}}
    ]
    monkeypatch.setattr(driver, "GitHubClient", lambda token, repo: client)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert not client.created_prs


def test_git_failure_falls_back_to_comment(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(tmp_path)
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    client = FakeGitHubClient("token", "org/repo")
    monkeypatch.setattr(driver, "GitHubClient", lambda token, repo: client)

    def _raise(*args, **kwargs):
        raise CommandError(CommandResult(cmd=["git", "push"], code=1, stdout="", stderr="boom"))

    monkeypatch.setattr(driver, "_ensure_branch_and_push", _raise)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert any("failed while preparing fix branch" in c for c in client.comments)


def test_agentic_success_creates_fix_pr(monkeypatch, tmp_path: Path) -> None:
    # CKV_AWS_3 must be in auto_fix_allow to be a blocking (hard_fail) finding.
    # LLM is now policy-governed and only attempts findings that are blocking;
    # advisory/suggest_only findings are left for the PR reviewer to action.
    workspace, artifacts = _setup_workspace(
        tmp_path,
        policy_extra=(
            "allow_agentic: true\n" "finding_policy:\n" "  auto_fix_allow:\n" "    - CKV_AWS_3\n"
        ),
    )
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace, clean=False)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic")
    client = FakeGitHubClient("token", "org/repo")
    monkeypatch.setattr(driver, "GitHubClient", lambda token, repo: client)

    monkeypatch.setattr(
        agentic_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: FakeAgentic(
            ok=True,
            patch_diff=(
                "Here is your patch.\n\n"
                "```diff\n"
                "diff --git a/main.tf b/main.tf\n"
                "+encrypted = true\n"
                "```\n"
            ),
        ),
    )
    monkeypatch.setattr(agentic_module, "_git_apply_patch", lambda *args, **kwargs: (True, ""))
    monkeypatch.setattr(
        agentic_module,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(
            cmd=cmd,
            code=0,
            stdout=(
                "diff --git a/main.tf b/main.tf\n+encrypted = true\n"
                if cmd[:2] == ["git", "diff"]
                else ""
            ),
            stderr="",
        ),
    )
    normalize_calls = {"n": 0}

    def _normalize_all(*args, **kwargs):
        _ = args, kwargs
        normalize_calls["n"] += 1
        if normalize_calls["n"] <= 2:
            return [_finding(workspace)]
        return []

    monkeypatch.setattr(driver, "normalize_all", _normalize_all)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert client.created_prs
    assert (artifacts / "agentic/response.txt").exists()
    assert (artifacts / "agentic/patch.diff").exists()


def test_final_terraform_checks_run_after_agentic(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(
        tmp_path,
        policy_extra=(
            "allow_agentic: true\n" "finding_policy:\n" "  auto_fix_allow:\n" "    - CKV_AWS_3\n"
        ),
    )
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace, clean=False)

    call_order: list[str] = []

    def _driver_harness(*args, **kwargs):
        _ = args, kwargs
        call_order.append("driver")
        return SimpleNamespace(
            ok=True,
            runs=[
                {
                    "name": "x",
                    "source": "harness",
                    "working_dir": str(workspace),
                    "init": {"code": 0, "cmd": ["terraform", "init"], "stdout": "", "stderr": ""},
                    "validate": {
                        "code": 0,
                        "cmd": ["terraform", "validate"],
                        "stdout": "",
                        "stderr": "",
                    },
                    "plan": {"code": 0, "cmd": ["terraform", "plan"], "stdout": "", "stderr": ""},
                    "ok": True,
                }
            ],
            to_dict=lambda: {
                "ok": True,
                "runs": [
                    {
                        "name": "x",
                        "source": "harness",
                        "working_dir": str(workspace),
                        "init": {
                            "code": 0,
                            "cmd": ["terraform", "init"],
                            "stdout": "",
                            "stderr": "",
                        },
                        "validate": {
                            "code": 0,
                            "cmd": ["terraform", "validate"],
                            "stdout": "",
                            "stderr": "",
                        },
                        "plan": {
                            "code": 0,
                            "cmd": ["terraform", "plan"],
                            "stdout": "",
                            "stderr": "",
                        },
                        "ok": True,
                    }
                ],
            },
        )

    def _agentic_harness(*args, **kwargs):
        _ = args, kwargs
        call_order.append("agentic")
        return _driver_harness()

    monkeypatch.setattr(driver, "run_harness_checks", _driver_harness)
    monkeypatch.setattr(agentic_module, "run_harness_checks", _agentic_harness)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic")
    client = FakeGitHubClient("token", "org/repo")
    monkeypatch.setattr(driver, "GitHubClient", lambda token, repo: client)

    monkeypatch.setattr(
        agentic_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: FakeAgentic(
            ok=True,
            patch_diff=(
                "```diff\n" "diff --git a/main.tf b/main.tf\n" "+encrypted = true\n" "```\n"
            ),
        ),
    )
    monkeypatch.setattr(agentic_module, "_git_apply_patch", lambda *args, **kwargs: (True, ""))
    monkeypatch.setattr(
        agentic_module,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(
            cmd=cmd,
            code=0,
            stdout=(
                "diff --git a/main.tf b/main.tf\n+encrypted = true\n"
                if cmd[:2] == ["git", "diff"]
                else ""
            ),
            stderr="",
        ),
    )
    normalize_calls = {"n": 0}

    def _normalize_all(*args, **kwargs):
        _ = args, kwargs
        normalize_calls["n"] += 1
        if normalize_calls["n"] <= 2:
            return [_finding(workspace)]
        return []

    monkeypatch.setattr(driver, "normalize_all", _normalize_all)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert client.created_prs
    assert "agentic" in call_order
    assert call_order[-1] == "driver"


def test_agentic_runs_for_unmapped_checkov_findings(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(
        tmp_path,
        policy_extra=(
            "allow_agentic: true\n"
            "plan_required: false\n"
            "finding_policy:\n"
            "  hard_fail_on:\n"
            "    - CKV_AWS_999\n"
        ),
    )
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace, clean=True)

    scan_calls = {"n": 0}

    def _scan_only(*args, **kwargs):
        _ = args, kwargs
        scan_calls["n"] += 1
        checkov = (
            _unmapped_checkov_result()
            if scan_calls["n"] < 3
            else {"results": [{"results": {"failed_checks": []}}]}
        )
        return {"checkov": checkov}

    monkeypatch.setattr(driver, "run_scan_only", _scan_only)
    monkeypatch.setattr(agentic_module, "run_scan_only", _scan_only)
    monkeypatch.setattr(driver, "normalize_all", lambda *args, **kwargs: [])
    monkeypatch.setattr(driver, "apply_drc", lambda *args, **kwargs: [])

    called = {"agentic": 0}
    monkeypatch.setattr(
        agentic_module,
        "run_agentic_fallback",
        lambda *args, **kwargs: called.__setitem__("agentic", called["agentic"] + 1)
        or FakeAgentic(ok=True, patch_diff="diff --git a/main.tf b/main.tf\n+dummy = true\n"),
    )
    monkeypatch.setattr(agentic_module, "_git_apply_patch", lambda *args, **kwargs: (True, ""))
    monkeypatch.setattr(
        agentic_module,
        "run_cmd",
        lambda cmd, cwd, **kwargs: CommandResult(
            cmd=cmd,
            code=0,
            stdout=(
                "diff --git a/main.tf b/main.tf\n+dummy = true\n"
                if cmd[:2] == ["git", "diff"]
                else ""
            ),
            stderr="",
        ),
    )

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic")
    monkeypatch.setattr(driver, "GitHubClient", FakeGitHubClient)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert called["agentic"] >= 1
    ledger = json.loads((artifacts / "agentic/llm_ledger.json").read_text(encoding="utf-8"))
    assert "attempts" in ledger
    assert isinstance(ledger["attempts"], list)
    assert len(ledger["attempts"]) >= 1
    first = ledger["attempts"][0]
    assert "target_file" in first
    assert "target_file_exists_before" in first
    assert "changed_files" in first
    assert "allowed_files" in first
    assert "response_preview" in first
    assert "extracted_patch_preview" in first
    summary = json.loads((artifacts / "run_summary.json").read_text(encoding="utf-8"))
    assert "agentic" in summary
    assert "top_rejections" in summary["agentic"]


def test_sanara_fix_branch_skip_writes_structured_artifacts(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path
    artifacts = workspace / "artifacts"
    (workspace / "rules/mappings").mkdir(parents=True)
    (workspace / ".sanara").mkdir(parents=True)
    (workspace / ".sanara/policy.yml").write_text(
        "allow_agentic: false\nplan_required: true\n", encoding="utf-8"
    )
    (workspace / "event.json").write_text(
        json.dumps(
            {
                "pull_request": {
                    "number": 42,
                    "base": {"sha": "base", "ref": "main"},
                    "head": {
                        "sha": "head",
                        "ref": "sanara/fix-123",
                        "repo": {"fork": False},
                    },
                },
                "sender": {"login": "dev"},
                "repository": {"full_name": "org/repo"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(workspace)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0

    summary = json.loads((artifacts / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["decision"] == "SKIPPED"
    assert summary["decision_detail"]["reason_code"] == "no_changes"
    assert "self-triggered remediation loops" in summary["decision_detail"]["message"]

    summary_md = (artifacts / "summary.md").read_text(encoding="utf-8")
    assert "Decision: SKIPPED (`sanara_branch`)" in summary_md
    assert "original remediation run artifacts" in summary_md

    details_md = (artifacts / "summary_detailed.md").read_text(encoding="utf-8")
    assert "follow-up run on a generated `sanara/fix-*` branch" in details_md

    index_md = (artifacts / "artifacts/index.md").read_text(encoding="utf-8")
    assert "Skipped Follow-up Run" in index_md


def test_publish_dry_run_skips_pr_and_sets_decision_detail(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(tmp_path, policy_extra="publish_dry_run: true\n")
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    client = FakeGitHubClient("token", "org/repo")
    monkeypatch.setattr(driver, "GitHubClient", lambda token, repo: client)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    assert not client.created_prs
    summary = json.loads((artifacts / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["decision"] == "DRY_RUN_READY"
    assert summary["decision_detail"]["reason_code"] == "publish_dry_run"


def test_comment_only_reason_code_missing_token(monkeypatch, tmp_path: Path) -> None:
    workspace, artifacts = _setup_workspace(tmp_path)
    monkeypatch.chdir(workspace)
    _patch_driver_basics(monkeypatch, workspace)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    rc = driver.run_driver(workspace, workspace / "event.json", artifacts)
    assert rc == 0
    summary = json.loads((artifacts / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["decision"] == "COMMENT_ONLY"
    assert summary["decision_detail"]["reason_code"] == "missing_github_token"


def test_artifact_contract_files_exist(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    driver.ensure_artifact_files(artifacts, driver.REQUIRED_ARTIFACTS)
    for rel in driver.REQUIRED_ARTIFACTS:
        assert (artifacts / rel).exists(), rel
