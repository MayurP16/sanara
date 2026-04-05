from __future__ import annotations

from sanara.orchestrator.context import detect_context


def test_detect_context_workflow_dispatch_does_not_use_github_sha() -> None:
    ctx = detect_context(
        event={},
        env={
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": "abc123",
            "GITHUB_REPOSITORY": "org/repo",
        },
    )

    assert ctx.event_name == "workflow_dispatch"
    assert ctx.base_sha == ""
    assert ctx.head_sha == ""


def test_detect_context_pr_payload_wins_over_ambient_env() -> None:
    ctx = detect_context(
        event={
            "pull_request": {
                "base": {"sha": "base", "ref": "main", "repo": {"full_name": "org/repo"}},
                "head": {
                    "sha": "head",
                    "ref": "feature",
                    "repo": {"fork": False, "full_name": "org/repo"},
                },
            }
        },
        env={
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SHA": "abc123",
            "GITHUB_REPOSITORY": "org/repo",
        },
    )

    assert ctx.event_name == "pull_request"
    assert ctx.base_sha == "base"
    assert ctx.head_sha == "head"
    assert ctx.is_cross_repo_pr is False


def test_detect_context_cross_repo_pr_detected() -> None:
    ctx = detect_context(
        event={
            "pull_request": {
                "number": 10,
                "base": {"sha": "base", "ref": "main", "repo": {"full_name": "org/repo"}},
                "head": {
                    "sha": "head",
                    "ref": "fix",
                    "repo": {"fork": True, "full_name": "contributor/repo"},
                },
            }
        },
        env={"GITHUB_REPOSITORY": "org/repo"},
    )

    assert ctx.is_cross_repo_pr is True
    assert ctx.is_fork is True


def test_detect_context_same_repo_pr_not_cross_repo() -> None:
    ctx = detect_context(
        event={
            "pull_request": {
                "number": 11,
                "base": {"sha": "base", "ref": "main", "repo": {"full_name": "org/repo"}},
                "head": {
                    "sha": "head",
                    "ref": "feature",
                    "repo": {"fork": False, "full_name": "org/repo"},
                },
            }
        },
        env={"GITHUB_REPOSITORY": "org/repo"},
    )

    assert ctx.is_cross_repo_pr is False


def test_detect_context_push_event_not_cross_repo() -> None:
    ctx = detect_context(
        event={"event_name": "push"},
        env={"GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "org/repo"},
    )

    assert ctx.is_cross_repo_pr is False


def test_detect_context_explicit_event_name_wins_for_non_pr_event() -> None:
    ctx = detect_context(
        event={"event_name": "workflow_dispatch"},
        env={
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_SHA": "abc123",
            "GITHUB_REPOSITORY": "org/repo",
        },
    )

    assert ctx.event_name == "workflow_dispatch"
    assert ctx.base_sha == ""
    assert ctx.head_sha == ""
