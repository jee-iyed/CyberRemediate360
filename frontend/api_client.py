"""Thin HTTP client used by the Streamlit UI. The UI never touches the database directly."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1"


class ApiError(Exception):
    def __init__(self, message: str, status: int | None = None, details: Any = None):
        super().__init__(message)
        self.message, self.status, self.details = message, status, details


@dataclass
class ApiClient:
    base_url: str = os.getenv("CR360_API_URL", DEFAULT_API_URL)
    api_key: str | None = os.getenv("CR360_API_KEY") or None
    actor: str = "dashboard-user"
    timeout: float = 30.0

    def _headers(self) -> dict[str, str]:
        headers = {"X-Actor": self.actor}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            response = httpx.request(
                method,
                f"{self.base_url}{path}",
                headers=self._headers(),
                timeout=self.timeout,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise ApiError(
                f"API unreachable at {self.base_url} ({type(exc).__name__}). "
                "Start it with: uvicorn app.main:app --app-dir backend"
            ) from exc
        if response.status_code >= 400:
            try:
                err = response.json().get("error", {})
            except ValueError:
                err = {}
            raise ApiError(
                err.get("message") or response.text[:300], response.status_code, err.get("details")
            )
        return response

    def get(self, path: str, **params) -> Any:
        clean = {k: v for k, v in params.items() if v not in (None, "", [])}
        return self._request("GET", path, params=clean).json()

    def get_all(self, path: str, page_size: int = 500, max_pages: int = 20, **params) -> list:
        items: list = []
        for page in range(1, max_pages + 1):
            data = self.get(path, page=page, page_size=page_size, **params)
            items.extend(data["items"])
            if len(items) >= data["total"]:
                break
        return items

    def post(self, path: str, json: dict) -> Any:
        return self._request("POST", path, json=json).json()

    def patch(self, path: str, json: dict) -> Any:
        return self._request("PATCH", path, json=json).json()

    def upload(self, filename: str, content: bytes, source: str, mode: str) -> Any:
        files = {"file": (filename, content, "application/octet-stream")}
        return self._request(
            "POST", "/imports", files=files, data={"source": source, "mode": mode}
        ).json()

    def download(self, fmt: str, include_demo: bool) -> bytes:
        return self._request(
            "GET", "/reports/export", params={"format": fmt, "include_demo": include_demo}
        ).content
