from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass
class CommandResult:
    cmd: list[str]
    code: int
    stdout: str
    stderr: str


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult):
        super().__init__(f"command failed ({result.code}): {' '.join(result.cmd)}")
        self.result = result


def run_cmd(
    cmd: list[str],
    cwd: Path,
    timeout_seconds: int | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env={**os.environ, **(dict(env) if env else {})},
        )
        return CommandResult(cmd=cmd, code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except FileNotFoundError as exc:
        return CommandResult(cmd=cmd, code=127, stdout="", stderr=str(exc))


def run_cmd_checked(
    cmd: list[str],
    cwd: Path,
    timeout_seconds: int | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    result = run_cmd(cmd, cwd=cwd, timeout_seconds=timeout_seconds, env=env)
    if result.code != 0:
        raise CommandError(result)
    return result
