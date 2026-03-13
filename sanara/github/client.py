from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import requests

from sanara.utils.hashing import sha256_text


@dataclass
class GitHubClient:
    token: str
    repo: str
    api_url: str = "https://api.github.com"
    timeout_seconds: int = 30
    max_retries: int = 3

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        delay = 0.3
        last_exc: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.request(method, url, timeout=self.timeout_seconds, **kwargs)
                if response.status_code >= 500 and attempt < self.max_retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                response.raise_for_status()
                return response
            except requests.RequestException as exc:
                last_exc = exc
                if attempt >= self.max_retries:
                    raise
                time.sleep(delay)
                delay *= 2
        if last_exc:
            raise last_exc
        raise RuntimeError("unreachable")

    def dedup_key(
        self, base_sha: str, attempted_rule_ids: list[str], target_dirs: list[str], patch_hash: str
    ) -> str:
        payload = {
            "base_sha": base_sha,
            "attempted_rule_ids": sorted(set(attempted_rule_ids)),
            "target_dirs": sorted(set(target_dirs)),
            "patch_hash": patch_hash,
        }
        return sha256_text(json.dumps(payload, sort_keys=True))

    @staticmethod
    def dedup_marker(dedup_payload: dict[str, Any]) -> str:
        return f"<!-- sanara-dedup:{json.dumps(dedup_payload, sort_keys=True)} -->"

    @staticmethod
    def parse_dedup_marker(body: str) -> dict[str, Any] | None:
        start = body.find("<!-- sanara-dedup:")
        if start < 0:
            return None
        end = body.find("-->", start)
        if end < 0:
            return None
        payload = body[start + len("<!-- sanara-dedup:") : end]
        try:
            return json.loads(payload)
        except Exception:
            return None

    def list_open_prs(self, head_branch_prefix: str = "sanara/fix-") -> list[dict[str, Any]]:
        url = f"{self.api_url}/repos/{self.repo}/pulls"
        r = self._request(
            "GET", url, headers=self._headers(), params={"state": "open", "per_page": 100}
        )
        return [
            x for x in r.json() if x.get("head", {}).get("ref", "").startswith(head_branch_prefix)
        ]

    def create_ref(self, branch: str, sha: str) -> None:
        url = f"{self.api_url}/repos/{self.repo}/git/refs"
        body = {"ref": f"refs/heads/{branch}", "sha": sha}
        self._request("POST", url, headers=self._headers(), json=body)

    def create_pr(
        self, title: str, body: str, head: str, base: str, draft: bool = False
    ) -> dict[str, Any]:
        url = f"{self.api_url}/repos/{self.repo}/pulls"
        data = {"title": title, "body": body, "head": head, "base": base, "draft": draft}
        r = self._request("POST", url, headers=self._headers(), json=data)
        return r.json()

    def comment_pr(self, pr_number: int, body: str) -> dict[str, Any]:
        url = f"{self.api_url}/repos/{self.repo}/issues/{pr_number}/comments"
        r = self._request("POST", url, headers=self._headers(), json={"body": body})
        return r.json()
