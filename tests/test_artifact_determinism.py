from __future__ import annotations

from pathlib import Path

from sanara.artifacts.bundle import ensure_artifact_files, policy_hash, write_json_file


def test_write_json_file_is_sorted_and_stable(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    payload = {"z": 1, "a": {"k2": 2, "k1": 1}, "m": [3, 2, 1]}

    write_json_file(root, "x.json", payload)
    first = (root / "x.json").read_text(encoding="utf-8")
    write_json_file(root, "x.json", payload)
    second = (root / "x.json").read_text(encoding="utf-8")

    assert first == second
    assert first.index('"a"') < first.index('"m"') < first.index('"z"')


def test_required_artifacts_created_deterministically(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    required = ["b/file.log", "a/file.json", "c/file.txt"]
    ensure_artifact_files(root, required)

    assert (root / "a/file.json").read_text(encoding="utf-8") == "{}\n"
    assert (root / "b/file.log").read_text(encoding="utf-8") == ""
    assert (root / "c/file.txt").read_text(encoding="utf-8") == ""


def test_policy_hash_is_stable_with_key_order_changes() -> None:
    p1 = {"b": 2, "a": 1, "nested": {"y": 2, "x": 1}}
    p2 = {"a": 1, "nested": {"x": 1, "y": 2}, "b": 2}

    assert policy_hash(p1) == policy_hash(p2)
