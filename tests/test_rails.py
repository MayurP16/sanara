from __future__ import annotations

from pathlib import Path

from sanara.orchestrator.policy import Policy
from sanara.rails.validator import validate_patch


def test_rails_blocks_non_allowlisted_paths() -> None:
    policy = Policy(allow_paths=["**/*.tf"], deny_paths=["**/.terraform/**"], max_diff_lines=50)
    diff = "diff --git a/.github/workflows/x.yml b/.github/workflows/x.yml\n+name: x\n"
    result = validate_patch(diff, Path("."), policy)
    assert not result.ok
    assert result.code == "NOT_ALLOWLISTED"
