"""Local storage for cloud sync credentials.

SECURITY FIX: Now supports OS keychain storage for secure credential management.
Token storage priority:
1. OS Keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
2. File-based storage with 0600 permissions (fallback)

The config file (cloud.json) stores metadata; the token is stored securely in keychain.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..state import get_state_dir
from . import keychain

logger = logging.getLogger(__name__)


def _first_env(*keys: str) -> str | None:
    for key in keys:
        value = os.environ.get(key)
        if value is not None and value.strip():
            return value.strip()
    return None


@dataclass
class CloudConfig:
    """Represents persisted CLI cloud settings."""

    api_url: str = "https://api.exordex.com"
    dashboard_url: str | None = None
    project_id: str | None = None
    token: str | None = None
    scopes: list[str] = field(default_factory=list)
    token_preview: str | None = None
    saved_at: str | None = None
    last_sync_at: str | None = None
    last_sync_uploaded: int = 0
    last_sync_error: str | None = None
    last_sync_remaining: int = 0
    # Internal flag: True if token is stored in keychain
    _token_in_keychain: bool = field(default=False, repr=False)

    def masked_token(self) -> str:
        if not self.token:
            return ""
        if len(self.token) <= 6:
            return self.token
        return f"…{self.token[-4:]}"

    def get_dashboard_url(self) -> str:
        """Return dashboard URL with fallback to environment or default."""
        if self.dashboard_url:
            return self.dashboard_url.rstrip("/")
        return os.environ.get("KHAOS_DASHBOARD_URL", "https://khaos.exordex.com").rstrip("/")


def _default_cloud_config_path() -> Path:
    return get_state_dir() / "cloud.json"

DEFAULT_CLOUD_CONFIG_PATH = _default_cloud_config_path()


def apply_env_overrides(config: CloudConfig) -> CloudConfig:
    """Return a CloudConfig with non-interactive CI env vars applied.

    Supported (recommended for CI):
    - KHAOS_API_URL
    - KHAOS_API_TOKEN
    - KHAOS_PROJECT_SLUG (or KHAOS_PROJECT_ID / KHAOS_PROJECT)
    - KHAOS_DASHBOARD_URL (optional)
    """

    api_url = _first_env("KHAOS_API_URL", "KHAOS_INGEST_URL")
    token = _first_env("KHAOS_API_TOKEN")
    project_id = _first_env("KHAOS_PROJECT_SLUG", "KHAOS_PROJECT_ID", "KHAOS_PROJECT")
    dashboard_url = _first_env("KHAOS_DASHBOARD_URL")

    if api_url:
        config.api_url = api_url
    if dashboard_url:
        config.dashboard_url = dashboard_url

    # Only override auth fields when explicitly provided.
    if token:
        config.token = token
        config.token_preview = CloudConfig(token=token).masked_token()
    if project_id:
        config.project_id = project_id

    return config


def _load_token_from_keychain() -> str | None:
    """Try to load token from OS keychain."""
    if not keychain.is_keychain_available():
        return None

    result = keychain.retrieve_token()
    if result.success and result.value:
        logger.debug("Token loaded from OS keychain")
        return result.value
    return None


def _save_token_to_keychain(token: str) -> bool:
    """Try to save token to OS keychain.

    Returns True if successful, False otherwise.
    """
    if not keychain.is_keychain_available():
        return False

    result = keychain.store_token(token)
    if result.success:
        logger.debug("Token stored in OS keychain")
        return True

    logger.warning("Failed to store token in keychain: %s", result.error)
    return False


def _delete_token_from_keychain() -> bool:
    """Delete token from OS keychain if present."""
    if not keychain.is_keychain_available():
        return False

    result = keychain.delete_token()
    return result.success


def load_cloud_config(path: Path | None = None) -> CloudConfig:
    """Load cloud configuration from disk and optionally keychain.

    Token retrieval priority:
    1. Environment variable (KHAOS_API_TOKEN)
    2. OS Keychain (if available)
    3. File-based storage (legacy/fallback)
    """
    target = path or _default_cloud_config_path()

    # Start with defaults
    if not target.exists():
        config = CloudConfig()
        # Try to load token from keychain even without config file
        keychain_token = _load_token_from_keychain()
        if keychain_token:
            config.token = keychain_token
            config.token_preview = config.masked_token()
            config._token_in_keychain = True
        return apply_env_overrides(config)

    try:
        payload = json.loads(target.read_text())
        if "scopes" not in payload or payload["scopes"] is None:
            payload["scopes"] = []
        # Remove internal fields that shouldn't be loaded from file
        payload.pop("_token_in_keychain", None)
        config = CloudConfig(**payload)
    except (json.JSONDecodeError, TypeError):
        config = CloudConfig()

    # Try to load token from keychain (takes precedence over file)
    keychain_token = _load_token_from_keychain()
    if keychain_token:
        config.token = keychain_token
        config.token_preview = config.masked_token()
        config._token_in_keychain = True
    elif config.token:
        # Token is in file but not keychain - could migrate on next save
        config._token_in_keychain = False

    return apply_env_overrides(config)


def save_cloud_config(config: CloudConfig, path: Path | None = None) -> Path:
    """Save cloud configuration to disk and optionally keychain.

    Token storage priority:
    1. OS Keychain (if available) - token NOT stored in file
    2. File-based storage with 0600 permissions (fallback)
    """
    target = path or _default_cloud_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    # Prepare config dict for saving
    save_dict = asdict(config)
    # Remove internal fields
    save_dict.pop("_token_in_keychain", None)

    # Try to store token in keychain
    token_in_keychain = False
    if config.token:
        if _save_token_to_keychain(config.token):
            token_in_keychain = True
            # Don't store token in file if it's in keychain
            save_dict["token"] = None
            # Keep the preview for display purposes
            save_dict["token_preview"] = config.masked_token()
            logger.info("Token securely stored in OS keychain")

    # Write config file
    target.write_text(json.dumps(save_dict, indent=2))

    # Set restrictive permissions
    try:
        os.chmod(target, 0o600)
    except OSError as e:
        # Log warning if not in CI
        if not os.getenv("CI"):
            logger.warning("Failed to set file permissions on %s: %s", target, e)

    # Update config state
    config._token_in_keychain = token_in_keychain

    return target


def clear_credentials(path: Path | None = None) -> None:
    """Clear all stored credentials from both keychain and file.

    Use this when logging out or revoking access.
    """
    # Delete from keychain
    _delete_token_from_keychain()

    # Clear token from file
    target = path or _default_cloud_config_path()
    if target.exists():
        try:
            payload = json.loads(target.read_text())
            payload["token"] = None
            payload["token_preview"] = None
            payload["scopes"] = []
            target.write_text(json.dumps(payload, indent=2))
            logger.info("Credentials cleared from config file")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to clear credentials from file: %s", e)


def get_token_storage_info() -> dict[str, bool]:
    """Get information about token storage capabilities.

    Returns dict with:
    - keychain_available: True if OS keychain can be used
    - keychain_enabled: True if keychain is not disabled by config
    """
    return {
        "keychain_available": keychain.is_keychain_available(),
        "keychain_enabled": keychain._is_keychain_enabled(),
    }
