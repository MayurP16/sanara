from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from pathlib import Path
from typing import Any

from sanara import __version__
from sanara.utils.hashing import sha256_text
from sanara.utils.io import write_json


def write_meta(path: Path, data: dict[str, Any]) -> None:
    payload = {
        "sanara_version": __version__,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": platform.python_version(),
        "os": platform.platform(),
        **data,
    }
    write_json(path / "meta.json", payload)


def write_summary(path: Path, lines: list[str]) -> None:
    (path / "summary.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(8192)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def redact(text: str) -> str:
    secrets = [
        os.environ.get("GITHUB_TOKEN", ""),
        os.environ.get("ANTHROPIC_API_KEY", ""),
    ]
    out = text
    for s in secrets:
        if s:
            out = out.replace(s, "***REDACTED***")
    return out


def write_text(path: Path, rel: str, content: str) -> None:
    p = path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(redact(content), encoding="utf-8")


def write_json_file(path: Path, rel: str, content: Any) -> None:
    p = path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(content, f, indent=2, sort_keys=True)
        f.write("\n")


def ensure_artifact_files(path: Path, required_paths: list[str]) -> None:
    for rel in required_paths:
        p = path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            continue
        if p.suffix == ".json":
            p.write_text("{}\n", encoding="utf-8")
        else:
            p.write_text("", encoding="utf-8")


def policy_hash(data: dict[str, Any]) -> str:
    return sha256_text(json.dumps(data, sort_keys=True))
