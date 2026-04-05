from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sanara.utils.io import read_json


@dataclass
class RunContext:
    event_name: str
    actor: str
    repo: str
    base_sha: str
    head_sha: str
    base_ref: str
    head_ref: str
    github_ref: str
    github_ref_name: str
    github_base_ref: str
    github_head_ref: str
    pr_number: int | None
    pr_branch: str
    is_fork: bool
    is_cross_repo_pr: bool
    skip: bool
    skip_reason: str | None


def load_event(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return read_json(path)


def detect_context(event: dict[str, Any], env: dict[str, str]) -> RunContext:
    has_pr = "pull_request" in event
    if has_pr:
        # Synthetic/local test events and real PR payloads should take precedence over
        # ambient runner env vars like GITHUB_EVENT_NAME=push from the outer CI job.
        event_name = str(event.get("event_name", "pull_request"))
    else:
        event_name = str(
            event.get("event_name") or env.get("GITHUB_EVENT_NAME") or "workflow_dispatch"
        )
    actor = env.get("GITHUB_ACTOR", event.get("sender", {}).get("login", "unknown"))
    repo = env.get(
        "GITHUB_REPOSITORY", event.get("repository", {}).get("full_name", "unknown/unknown")
    )

    pr = event.get("pull_request", {})
    if event_name == "pull_request":
        base_sha = pr.get("base", {}).get("sha", env.get("GITHUB_SHA", ""))
        head_sha = pr.get("head", {}).get("sha", env.get("GITHUB_SHA", ""))
    else:
        base_sha = ""
        head_sha = ""
    base_ref = str(pr.get("base", {}).get("ref", env.get("GITHUB_BASE_REF", "")) or "")
    head_ref = str(
        pr.get("head", {}).get("ref", env.get("GITHUB_HEAD_REF", env.get("GITHUB_REF_NAME", "")))
        or ""
    )
    github_ref = str(env.get("GITHUB_REF", ""))
    github_ref_name = str(env.get("GITHUB_REF_NAME", ""))
    github_base_ref = str(env.get("GITHUB_BASE_REF", ""))
    github_head_ref = str(env.get("GITHUB_HEAD_REF", ""))
    pr_branch = head_ref
    is_fork = bool(pr.get("head", {}).get("repo", {}).get("fork", False))
    head_repo_name = str(pr.get("head", {}).get("repo", {}).get("full_name", "") or "")
    base_repo_name = str(pr.get("base", {}).get("repo", {}).get("full_name", "") or "")
    is_cross_repo_pr = bool(
        event_name == "pull_request"
        and head_repo_name
        and base_repo_name
        and head_repo_name != base_repo_name
    )
    pr_number = pr.get("number")

    skip = False
    reason = None
    if pr_branch.startswith("sanara/"):
        skip = True
        reason = "sanara_branch"
    elif actor == "github-actions[bot]":
        skip = True
        reason = "bot_actor"

    return RunContext(
        event_name=event_name,
        actor=actor,
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        base_ref=base_ref,
        head_ref=head_ref,
        github_ref=github_ref,
        github_ref_name=github_ref_name,
        github_base_ref=github_base_ref,
        github_head_ref=github_head_ref,
        pr_number=pr_number,
        pr_branch=pr_branch,
        is_fork=is_fork,
        is_cross_repo_pr=is_cross_repo_pr,
        skip=skip,
        skip_reason=reason,
    )
