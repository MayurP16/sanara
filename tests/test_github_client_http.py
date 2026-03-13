from __future__ import annotations

import pytest
import requests

from sanara.github.client import GitHubClient


class FakeResponse:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status={self.status_code}")

    def json(self):
        return self._payload


def test_list_open_prs_filters_by_prefix(monkeypatch) -> None:
    c = GitHubClient(token="t", repo="o/r", max_retries=1)

    def fake_request(method, url, timeout, **kwargs):
        _ = method, url, timeout, kwargs
        return FakeResponse(
            200,
            [
                {"head": {"ref": "sanara/fix-1"}},
                {"head": {"ref": "feature/foo"}},
            ],
        )

    monkeypatch.setattr("requests.request", fake_request)
    prs = c.list_open_prs()
    assert len(prs) == 1


def test_create_pr_raises_on_http_error(monkeypatch) -> None:
    c = GitHubClient(token="t", repo="o/r", max_retries=1)

    def fake_request(method, url, timeout, **kwargs):
        _ = method, url, timeout, kwargs
        return FakeResponse(422, {"message": "Validation Failed"})

    monkeypatch.setattr("requests.request", fake_request)
    with pytest.raises(requests.HTTPError):
        c.create_pr("title", "body", "head", "main")


def test_comment_pr_success(monkeypatch) -> None:
    c = GitHubClient(token="t", repo="o/r", max_retries=1)

    def fake_request(method, url, timeout, **kwargs):
        _ = method, url, timeout, kwargs
        return FakeResponse(201, {"id": 123})

    monkeypatch.setattr("requests.request", fake_request)
    out = c.comment_pr(10, "hello")
    assert out["id"] == 123


def test_request_retries_on_500(monkeypatch) -> None:
    c = GitHubClient(token="t", repo="o/r", max_retries=3)
    calls = {"n": 0}

    def fake_request(method, url, timeout, **kwargs):
        _ = method, url, timeout, kwargs
        calls["n"] += 1
        if calls["n"] < 3:
            return FakeResponse(500, {"message": "server error"})
        return FakeResponse(200, [{"head": {"ref": "sanara/fix-1"}}])

    monkeypatch.setattr("requests.request", fake_request)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    prs = c.list_open_prs()
    assert len(prs) == 1
    assert calls["n"] == 3
