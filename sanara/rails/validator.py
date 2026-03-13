from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from sanara.orchestrator.policy import Policy


@dataclass
class RailResult:
    ok: bool
    code: str
    message: str


def _match_any(path: str, patterns: list[str]) -> bool:
    norm = path
    if norm.startswith("./"):
        norm = norm[2:]
    if norm.startswith("/"):
        norm = norm[1:]
    for pattern in patterns:
        if fnmatch.fnmatch(norm, pattern):
            return True
        # Python fnmatch does not treat ** specially for root-level files.
        if pattern.startswith("**/") and fnmatch.fnmatch(norm, pattern[3:]):
            return True
    return False


def validate_patch(diff_text: str, workspace: Path, policy: Policy) -> RailResult:
    _ = workspace
    changed_files = [
        line.split(" b/")[-1].strip()
        for line in diff_text.splitlines()
        if line.startswith("diff --git ") and " b/" in line
    ]

    for rel in changed_files:
        if policy.allow_paths and not _match_any(rel, policy.allow_paths):
            return RailResult(False, "NOT_ALLOWLISTED", f"File not in allowlist: {rel}")
        if policy.deny_paths and _match_any(rel, policy.deny_paths):
            return RailResult(False, "BLOCKED_BY_RAIL", f"File denied: {rel}")

    added_lines = [
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]

    if len(added_lines) > policy.max_diff_lines:
        return RailResult(False, "BLOCKED_BY_RAIL", "Diff budget exceeded")

    if any(line.startswith("-resource ") for line in diff_text.splitlines()):
        return RailResult(False, "BLOCKED_BY_RAIL", "Resource deletions are blocked")

    widen_patterns = [
        "0.0.0.0/0",
        "::/0",
        'cidr_blocks = ["0.0.0.0/0"]',
        'ipv6_cidr_blocks = ["::/0"]',
        "publicly_accessible = true",
        '"Principal": "*"',
        '"Action": "*"',
    ]
    for added in added_lines:
        if any(p in added for p in widen_patterns):
            return RailResult(
                False, "BLOCKED_BY_RAIL", f"Network/policy widening blocked: {added.strip()[:120]}"
            )

    return RailResult(True, "OK", "rails passed")
