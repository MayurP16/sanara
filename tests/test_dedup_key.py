from __future__ import annotations

from sanara.github.client import GitHubClient


def test_dedup_key_stable() -> None:
    c = GitHubClient(token="x", repo="o/r")
    a = c.dedup_key("abc", ["r2", "r1"], ["b", "a"], "patch")
    b = c.dedup_key("abc", ["r1", "r2"], ["a", "b"], "patch")
    assert a == b
