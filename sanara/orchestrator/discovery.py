from __future__ import annotations

from pathlib import Path

from sanara.utils.command import CommandError, CommandResult, run_cmd


def discover_target_dirs(workspace: Path, base_sha: str, head_sha: str) -> list[Path]:
    if not base_sha or not head_sha:
        files = [p for p in workspace.rglob("*.tf")]
    else:
        diff = run_cmd(["git", "diff", "--name-only", f"{base_sha}..{head_sha}"], cwd=workspace)
        if diff.code != 0:
            stderr = (diff.stderr or "").strip()
            raise CommandError(
                CommandResult(
                    cmd=diff.cmd,
                    code=diff.code,
                    stdout=diff.stdout,
                    stderr=(
                        f"discover_target_dirs git diff failed: {stderr}"
                        if stderr
                        else "discover_target_dirs git diff failed"
                    ),
                )
            )
        files = [
            workspace / line.strip()
            for line in diff.stdout.splitlines()
            if line.strip().endswith(".tf")
        ]

    dirs: set[Path] = set()
    for file in files:
        if not file.exists():
            continue
        dirs.add(file.parent)

    ordered = sorted(dirs)
    return ordered
