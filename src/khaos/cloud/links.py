"""Helpers for building dashboard URLs for synced runs."""

from __future__ import annotations

import re

from .config import CloudConfig
from .queue import UploadJob

EVALUATION_ID_DELIMITER = "__"


def _slugify(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value[:80] or "evaluation"


def encode_evaluation_id(
    *,
    run_id: str,
    name: str | None = None,
    pack_name: str | None = None,
    scenario_identifier: str | None = None,
    agent_name: str | None = None,
    agent_version: str | None = None,
) -> str:
    base = name or pack_name or scenario_identifier or "evaluation"
    agent_part = " ".join([p for p in [agent_name, agent_version] if p]).strip()
    label = " ".join([p for p in [base, agent_part] if p]).strip()
    slug = _slugify(label)
    return f"{slug}{EVALUATION_ID_DELIMITER}{run_id}"


def dashboard_evaluation_url_for_job(config: CloudConfig, job: UploadJob) -> str | None:
    if not config.project_id:
        return None
    dashboard_url = config.get_dashboard_url()
    evaluation_id = encode_evaluation_id(
        run_id=job.run_id,
        name=job.name,
        pack_name=job.pack_name,
        scenario_identifier=job.scenario_id,
        agent_name=job.agent_name,
        agent_version=job.agent_version,
    )
    return f"{dashboard_url}/{config.project_id}/evaluations/{evaluation_id}"


def dashboard_evaluation_url(
    config: CloudConfig,
    *,
    run_id: str,
    name: str | None = None,
    pack_name: str | None = None,
    scenario_identifier: str | None = None,
    agent_name: str | None = None,
    agent_version: str | None = None,
) -> str | None:
    """Best-effort dashboard evaluation URL for a run_id (even before upload)."""
    if not config.project_id:
        return None
    dashboard_url = config.get_dashboard_url()
    evaluation_id = encode_evaluation_id(
        run_id=run_id,
        name=name,
        pack_name=pack_name,
        scenario_identifier=scenario_identifier,
        agent_name=agent_name,
        agent_version=agent_version,
    )
    return f"{dashboard_url}/{config.project_id}/evaluations/{evaluation_id}"
