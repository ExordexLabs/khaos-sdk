"""Helpers for authenticated requests to the ingestion API."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from .config import CloudConfig, load_cloud_config

DEFAULT_TIMEOUT = 5.0


class CloudAuthError(RuntimeError):
    """Raised when stored credentials are missing or invalid."""


class RecoverableAuthError(CloudAuthError):
    """Auth error that can be fixed by re-authenticating.

    This is raised for errors like:
    - 401: Token rejected/expired
    - 403: Access denied (wrong project or permissions)
    - 404: Project not found
    - Project mismatch between queued job and current credentials

    The CLI should catch this and offer to re-login automatically.
    """

    def __init__(self, message: str, *, hint: str | None = None):
        super().__init__(message)
        self.hint = hint or "Run `khaos login` to re-authenticate."


@dataclass
class CloudSession:
    config: CloudConfig

    def require_token(self) -> tuple[str, str, str]:
        if not self.config.token or not self.config.project_id:
            raise CloudAuthError(
                "Cloud credentials not configured. Run `khaos login`, or set"
                "`KHAOS_API_URL`, `KHAOS_API_TOKEN`, and `KHAOS_PROJECT_SLUG` (recommended for CI)."
            )
        api_url = self.config.api_url.rstrip("/")
        return api_url, self.config.project_id, self.config.token


def get_cloud_session() -> CloudSession:
    return CloudSession(load_cloud_config())


def _request_with_token(url: str, token: str) -> httpx.Response:
    try:
        response = httpx.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=DEFAULT_TIMEOUT,
        )
    except httpx.RequestError as exc:  # pragma: no cover - network errors
        raise CloudAuthError(f"Unable to reach ingestion API at {url}: {exc}") from exc
    if response.status_code == 401:
        raise CloudAuthError("Token rejected by the ingestion API (401).")
    if response.status_code >= 400:
        raise CloudAuthError(
            f"Ingestion API returned {response.status_code}: {response.text.strip() or 'Unknown error'}"
        )
    return response


def validate_token(api_url: str, token: str) -> None:
    url = f"{api_url.rstrip('/')}/runs/"
    _request_with_token(url, token)


def fetch_ingestion_status(config: CloudConfig) -> dict:
    api_url, _, token = CloudSession(config).require_token()
    url = f"{api_url.rstrip('/')}/ingest/status"
    response = _request_with_token(url, token)
    try:
        return response.json()
    except ValueError as exc:
        raise CloudAuthError("Ingestion status endpoint returned invalid JSON") from exc


def get_authenticated_client(config: CloudConfig) -> httpx.Client:
    api_url, _, token = CloudSession(config).require_token()
    return httpx.Client(
        base_url=api_url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=DEFAULT_TIMEOUT,
    )
