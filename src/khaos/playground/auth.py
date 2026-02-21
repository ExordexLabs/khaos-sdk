"""Playground authentication and session management.

This module handles cloud-based session validation for the playground,
including session limits for free users.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from ..cloud.config import load_cloud_config


class PlaygroundAuthError(Exception):
    """Base error for playground authentication."""
    pass


class NotLoggedInError(PlaygroundAuthError):
    """User is not logged in with the CLI."""
    pass


@dataclass
class SessionLimitError(PlaygroundAuthError):
    """Session limit reached for free tier."""

    message: str
    sessions_used: int
    sessions_limit: int
    upgrade_url: str
    resets_at: datetime | None

    def __str__(self) -> str:
        return self.message


@dataclass
class PlaygroundSessionInfo:
    """Information about an authorized playground session."""

    session_token: str
    session_id: str
    tier: str
    sessions_used: int | None = None
    sessions_limit: int | None = None


def get_cloud_api_url() -> str:
    """Get the cloud API URL from environment or config."""
    # Check environment first
    env_url = os.environ.get("KHAOS_CLOUD_API_URL") or os.environ.get("KHAOS_API_URL")
    if env_url:
        return env_url.rstrip("/")

    # Fall back to config
    config = load_cloud_config()
    return config.api_url.rstrip("/")


def get_dashboard_url() -> str:
    """Get the dashboard URL from environment or config."""
    env_url = os.environ.get("KHAOS_DASHBOARD_URL")
    if env_url:
        return env_url.rstrip("/")

    config = load_cloud_config()
    return config.get_dashboard_url()


async def request_playground_session(
    agent_name: str | None = None,
) -> PlaygroundSessionInfo:
    """Request a playground session from the cloud API.

    Args:
        agent_name: Optional name of the agent being tested (for analytics).

    Returns:
        PlaygroundSessionInfo with the signed session token and metadata.

    Raises:
        NotLoggedInError: If the CLI is not logged in.
        SessionLimitError: If the user has reached their session limit.
        PlaygroundAuthError: For other authentication failures.
    """
    # Load CLI config and token
    config = load_cloud_config()
    if not config.token:
        raise NotLoggedInError(
            "Not logged in. Run 'khaos login' to authenticate."
        )

    # Get dashboard API URL (playground auth is on dashboard, not backend)
    dashboard_url = get_dashboard_url()
    auth_url = f"{dashboard_url}/api/playground/auth"

    # Request session
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(
                auth_url,
                json={
                    "cliToken": config.token,
                    "agentName": agent_name,
                },
            )
        except httpx.RequestError as e:
            raise PlaygroundAuthError(f"Failed to connect to Khaos Cloud: {e}")

        if response.status_code == 401:
            raise NotLoggedInError(
                "Invalid or expired token. Run 'khaos login' to re-authenticate."
            )

        if response.status_code == 403:
            # Session limit reached
            try:
                data = response.json()
                resets_at = None
                if data.get("resetsAt"):
                    try:
                        resets_at = datetime.fromisoformat(
                            data["resetsAt"].replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                raise SessionLimitError(
                    message=data.get("error", "Session limit reached"),
                    sessions_used=data.get("sessionsUsed", 0),
                    sessions_limit=data.get("sessionsLimit", 3),
                    upgrade_url=data.get("upgradeUrl", "https://khaos.exordex.com/pricing"),
                    resets_at=resets_at,
                )
            except (ValueError, KeyError) as e:
                raise PlaygroundAuthError(f"Failed to parse session limit response: {e}")

        if response.status_code == 429:
            raise PlaygroundAuthError("Too many requests. Please try again later.")

        if not response.is_success:
            try:
                data = response.json()
                error = data.get("error", f"HTTP {response.status_code}")
            except ValueError:
                error = f"HTTP {response.status_code}"
            raise PlaygroundAuthError(f"Authentication failed: {error}")

        # Parse successful response
        try:
            data = response.json()
            return PlaygroundSessionInfo(
                session_token=data["sessionToken"],
                session_id=data["sessionId"],
                tier=data["tier"],
                sessions_used=data.get("sessionsUsed"),
                sessions_limit=data.get("sessionsLimit"),
            )
        except (ValueError, KeyError) as e:
            raise PlaygroundAuthError(f"Invalid response from server: {e}")


def request_playground_session_sync(
    agent_name: str | None = None,
) -> PlaygroundSessionInfo:
    """Synchronous version of request_playground_session.

    Args:
        agent_name: Optional name of the agent being tested (for analytics).

    Returns:
        PlaygroundSessionInfo with the signed session token and metadata.

    Raises:
        NotLoggedInError: If the CLI is not logged in.
        SessionLimitError: If the user has reached their session limit.
        PlaygroundAuthError: For other authentication failures.
    """
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in async context - use nest_asyncio or return a coroutine
        raise RuntimeError(
            "Cannot call sync version from async context. "
            "Use 'await request_playground_session()' instead."
        )

    return asyncio.run(request_playground_session(agent_name))


def is_authenticated() -> bool:
    """Check if the CLI has a valid token stored.

    Note: This doesn't validate the token with the server,
    just checks if one is present.
    """
    config = load_cloud_config()
    return bool(config.token)
