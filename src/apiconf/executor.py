"""HTTP execution of test requests."""
from __future__ import annotations

import httpx


class Executor:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)

    def request(self, method: str, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        return self.client.request(method, url, headers=headers or {})

    def close(self) -> None:
        self.client.close()
