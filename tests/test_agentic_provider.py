from __future__ import annotations

import json
from pathlib import Path

from sanara.agentic import fallback


class _Resp:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_explicit_anthropic_provider(monkeypatch, tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")

    def fake_post(url, headers, data, timeout):
        _ = headers, data, timeout
        assert url == "https://api.anthropic.com/v1/messages"
        return _Resp(
            200, {"content": [{"type": "text", "text": "diff --git a/main.tf b/main.tf\n"}]}
        )

    monkeypatch.setattr(fallback.requests, "post", fake_post)
    res = fallback.run_agentic_fallback(
        workspace=tmp_path,
        module_dirs=[tmp_path],
        prompt="patch",
        llm_provider="anthropic",
        anthropic_api_key="a",
        openai_api_key=None,
    )
    assert res.ok
    assert res.ledger["provider"] == "anthropic"


def test_explicit_openai_provider(monkeypatch, tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")

    def fake_post(url, headers, data, timeout):
        _ = headers, data, timeout
        assert url == "https://api.openai.com/v1/chat/completions"
        return _Resp(
            200, {"choices": [{"message": {"content": "diff --git a/main.tf b/main.tf\n"}}]}
        )

    monkeypatch.setattr(fallback.requests, "post", fake_post)
    res = fallback.run_agentic_fallback(
        workspace=tmp_path,
        module_dirs=[tmp_path],
        prompt="patch",
        llm_provider="openai",
        anthropic_api_key=None,
        openai_api_key="o",
    )
    assert res.ok
    assert res.ledger["provider"] == "openai"


def test_invalid_provider_returns_error(tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    res = fallback.run_agentic_fallback(
        workspace=tmp_path,
        module_dirs=[tmp_path],
        prompt="patch",
        llm_provider="invalid-provider",
        anthropic_api_key="a",
        openai_api_key="o",
    )
    assert not res.ok
    assert "invalid llm_provider" in res.message


def test_explicit_provider_missing_key_returns_error(tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    res = fallback.run_agentic_fallback(
        workspace=tmp_path,
        module_dirs=[tmp_path],
        prompt="patch",
        llm_provider="openai",
        anthropic_api_key=None,
        openai_api_key=None,
    )
    assert not res.ok
    assert "OPENAI_API_KEY" in res.message


def test_openai_error_propagates(monkeypatch, tmp_path: Path) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")

    def fake_post(url, headers, data, timeout):
        _ = url, headers, data, timeout
        return _Resp(401, {"error": {"message": "unauthorized"}})

    monkeypatch.setattr(fallback.requests, "post", fake_post)
    res = fallback.run_agentic_fallback(
        workspace=tmp_path,
        module_dirs=[tmp_path],
        prompt="patch",
        llm_provider="openai",
        openai_api_key="o",
    )
    assert not res.ok
    assert "openai request failed" in res.message


def test_focus_files_limits_context(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text('resource "aws_s3_bucket" "a" {}\n', encoding="utf-8")
    (tmp_path / "b.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")

    def fake_post(url, headers, data, timeout):
        _ = url, headers, timeout
        payload = json.loads(data)
        msg = payload["messages"][0]["content"]
        assert "# FILE a.tf" in msg
        assert "# FILE b.tf" not in msg
        return _Resp(200, {"content": [{"type": "text", "text": "diff --git a/a.tf b/a.tf\n"}]})

    monkeypatch.setattr(fallback.requests, "post", fake_post)
    res = fallback.run_agentic_fallback(
        workspace=tmp_path,
        module_dirs=[tmp_path],
        prompt="patch",
        llm_provider="anthropic",
        anthropic_api_key="a",
        focus_files=["a.tf"],
    )
    assert res.ok


def test_focus_resources_keeps_full_target_file_in_prompt(monkeypatch, tmp_path: Path) -> None:
    main_tf = tmp_path / "main.tf"
    main_tf.write_text(
        "\n".join(
            [
                'provider "aws" {',
                '  region = "us-east-1"',
                "}",
                "",
                'resource "aws_s3_bucket" "a" {',
                '  bucket = "example-bucket"',
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    def fake_post(url, headers, data, timeout):
        _ = url, headers, timeout
        payload = json.loads(data)
        msg = payload["messages"][0]["content"]
        assert '# FILE main.tf\nprovider "aws" {' in msg
        assert 'resource "aws_s3_bucket" "a" {' in msg
        assert "# SUPPORTING HCL CONTEXT" in msg
        assert "# FILE: main.tf" in msg
        return _Resp(
            200, {"content": [{"type": "text", "text": "diff --git a/main.tf b/main.tf\n"}]}
        )

    monkeypatch.setattr(fallback.requests, "post", fake_post)
    res = fallback.run_agentic_fallback(
        workspace=tmp_path,
        module_dirs=[tmp_path],
        prompt="patch",
        llm_provider="anthropic",
        anthropic_api_key="a",
        focus_files=["main.tf"],
        focus_resources=[
            {
                "resource_type": "aws_s3_bucket",
                "resource_name": "a",
            }
        ],
    )
    assert res.ok
    assert res.ledger["context_mode"] == "full_plus_hcl_windowed"
