"""Upload client implementing the ingestion handshake."""

from __future__ import annotations

import hashlib
import json
import random
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from .client import CloudAuthError, RecoverableAuthError, CloudSession, DEFAULT_TIMEOUT
from .queue import UploadJob


class UploadClient:
    """Speaks to the ingestion API using the stored cloud session."""

    RETRYABLE_STATUS = {408, 425, 429}
    MAX_ATTEMPTS = 3
    BACKOFF_BASE_SECONDS = 0.5

    def __init__(self, session: CloudSession):
        self.session = session
        api_url, project_id, token = session.require_token()
        self.project_id = project_id
        self.client = httpx.Client(
            base_url=api_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=DEFAULT_TIMEOUT,
        )

    def upload(self, job: UploadJob) -> None:
        if job.project_id and job.project_id != self.project_id:
            raise RecoverableAuthError(
                f"Project mismatch: run targets '{job.project_id}' but you're logged into '{self.project_id}'.",
                hint="Run `khaos sync --login` and select the correct project, or re-run with --project to target your current project.",
            )

        run_payload = {
            "run_id": job.run_id,
            "project_id": self.project_id,
            "scenario_identifier": job.scenario_id,
            "seed": job.seed,
            "agent": {
                "name": job.agent_name,
                "version": job.agent_version,
                "code_hash": job.agent_code_hash,
                "metadata": job.agent_metadata or {},
                "category": job.agent_category,
                "capabilities": job.agent_capabilities,
                "signals": job.agent_signals,
            },
        }

        # Add evaluation primitive fields if present (Phase 0)
        if job.evaluation_id:
            run_payload["evaluation_id"] = job.evaluation_id
            run_payload["scenario_order"] = job.scenario_order
            run_payload["total_scenarios"] = job.total_scenarios
            run_payload["pack_name"] = job.pack_name
            run_payload["pack_version"] = job.pack_version
        response = self._send("POST", "/ingest/run", json=run_payload)

        parts = [
            ("trace", job.trace_path, "application/json"),
            ("metrics", job.metrics_path, "application/json"),
            ("stderr", job.stderr_path, "text/plain"),
        ]
        part_index = 1
        for name, path, content_type in parts:
            if not path:
                continue
            part_path = Path(path)
            if not part_path.exists():
                continue
            data = part_path.read_bytes()
            if len(data) == 0:
                continue
            checksum = hashlib.sha256(data).hexdigest()
            upload_request = {
                "run_id": job.run_id,
                "part_name": name,
                "part_number": part_index,
                "size_bytes": len(data),
                "sha256": checksum,
                "content_type": content_type,
            }
            part_index += 1
            response = self._send("POST", "/ingest/upload-url", json=upload_request)
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise CloudAuthError(
                    f"Ingestion API returned invalid JSON for upload-url request"
                ) from exc
            upload_url = self._resolve_upload_url(payload.get("upload_url"))
            method = payload.get("upload_method", "PUT").upper()
            upload_headers = payload.get("headers", {})
            self._send(method, upload_url, content=data, headers=upload_headers)
            self._send(
                "POST",
                "/ingest/complete-part",
                json={"run_id": job.run_id, "part_name": name},
            )

        metrics_payload = self._load_metrics(job.metrics_path)

        # If no explicit evaluation_report was provided (e.g. scenario/observe runs),
        # synthesize a minimal pack-style report from metrics so the dashboard can
        # show goal/resilience/security ratios consistently across run types.
        evaluation_report = job.evaluation_report or self._synthesize_evaluation_report(
            job=job,
            metrics_payload=metrics_payload,
        )

        # Build finalize payload
        finalize_payload = {
            "run_id": job.run_id,
            "scenario_identifier": job.scenario_id,
            "metrics": metrics_payload.get("artifacts", []),
            "resilience_report": metrics_payload.get("resilience_report"),
            "mcp_servers": metrics_payload.get("mcp_servers"),
            "scenario_difficulty": metrics_payload.get("scenario_difficulty"),
            "scenario_difficulty_label": metrics_payload.get("scenario_difficulty_label"),
        }

        # Add user-provided run name if present
        if job.name:
            finalize_payload["name"] = job.name

        # Pack metadata is optional, but evaluation_report is always accepted by the service.
        if job.pack_name:
            finalize_payload["pack_name"] = job.pack_name
            finalize_payload["pack_version"] = job.pack_version

        if evaluation_report:
            finalize_payload["evaluation_report"] = evaluation_report

            # Extract key metrics for indexed columns (keeps list views fast).
            baseline = evaluation_report.get("baseline", {}) if isinstance(evaluation_report, dict) else {}
            resilience = evaluation_report.get("resilience", {}) if isinstance(evaluation_report, dict) else {}
            security = evaluation_report.get("security", {}) if isinstance(evaluation_report, dict) else {}

            if isinstance(baseline, dict) and baseline:
                latency = baseline.get("latency", {})
                if isinstance(latency, dict):
                    finalize_payload["baseline_latency_p50"] = latency.get("p50")
                    finalize_payload["baseline_latency_p95"] = latency.get("p95")
                finalize_payload["baseline_completion_rate"] = baseline.get("task_completion_rate")

            if isinstance(resilience, dict) and resilience:
                finalize_payload["resilience_degradation"] = resilience.get("degradation_percent")

            if isinstance(security, dict) and security:
                finalize_payload["security_attacks_tested"] = security.get("attacks_tested")
                finalize_payload["security_attacks_blocked"] = security.get("attacks_blocked")

        self._send("POST", "/ingest/finalize", json=finalize_payload)
        self._maybe_upload_comparison(job, metrics_payload)

    def _maybe_upload_comparison(self, job: UploadJob, metrics_payload: dict) -> None:
        """Upload comparison artifacts when present in the metrics payload."""

        report = metrics_payload.get("comparison_report")
        if not isinstance(report, dict):
            return
        baseline = (report.get("baseline") or {}).get("run_id")
        candidate = (report.get("candidate") or {}).get("run_id") or job.run_id
        if not baseline or not candidate:
            return
        payload = {
            "baseline_run_id": baseline,
            "candidate_run_id": candidate,
            "project_id": self.project_id,
            "comparison_report": report,
        }
        self._send("POST", "/ingest/comparison", json=payload)

    def _resolve_upload_url(self, upload_url: str | None) -> str:
        if not upload_url:
            raise CloudAuthError("Ingestion API did not return an upload URL")
        if upload_url.startswith("http"):
            return upload_url
        base = str(self.client.base_url)
        return urljoin(base + "/", upload_url.lstrip("/"))

    def _send(self, method: str, url: str, **kwargs) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        if self._is_ingestion_url(url) and method.upper() in {"POST", "PUT", "PATCH"}:
            headers.setdefault("Idempotency-Key", uuid.uuid4().hex)
        last_exc: Exception | None = None
        for attempt in range(self.MAX_ATTEMPTS):
            try:
                response = self.client.request(method, url, headers=headers, **kwargs)
            except httpx.RequestError as exc:  # pragma: no cover - network stack
                last_exc = exc
                if attempt == self.MAX_ATTEMPTS - 1:
                    raise CloudAuthError(
                        f"Network error contacting ingestion API: {exc}"
                    ) from exc
                self._sleep(attempt)
                continue

            if response.status_code == 401:
                raise RecoverableAuthError(
                    "Your authentication token was rejected (401). This usually means the token expired or was revoked.",
                    hint="Run `khaos sync --login` to re-authenticate.",
                )

            if response.status_code == 403:
                detail = ""
                try:
                    payload = response.json()
                    if isinstance(payload, dict):
                        detail = payload.get("detail", "")
                except Exception:
                    pass
                raise RecoverableAuthError(
                    f"Access denied (403). You don't have permission to access this project or resource. {detail}".strip(),
                    hint="Run `khaos sync --login` and select a project you have access to.",
                )

            retryable = (
                response.status_code in self.RETRYABLE_STATUS
                or response.status_code >= 500
            )
            if response.status_code >= 400 and retryable:
                if attempt == self.MAX_ATTEMPTS - 1:
                    self._raise_for_status(response)
                else:
                    retry_after = self._retry_after_seconds(response)
                    if retry_after is not None:
                        self._sleep_with_min(attempt, min_seconds=retry_after)
                    else:
                        self._sleep(attempt)
                    continue

            self._raise_for_status(response)
            return response

        raise CloudAuthError("Ingestion API request failed after retries") from last_exc

    def _is_ingestion_url(self, url: str) -> bool:
        if not url or not url.startswith("http"):
            return True
        return url.startswith(str(self.client.base_url))

    def _sleep(self, attempt: int) -> None:
        delay = self.BACKOFF_BASE_SECONDS * (2**attempt)
        jitter = random.uniform(0, 0.25)
        time.sleep(delay + jitter)

    def _sleep_with_min(self, attempt: int, *, min_seconds: float) -> None:
        delay = self.BACKOFF_BASE_SECONDS * (2**attempt)
        jitter = random.uniform(0, 0.25)
        time.sleep(max(delay + jitter, min_seconds))

    @staticmethod
    def _retry_after_seconds(response: httpx.Response) -> float | None:
        value = response.headers.get("Retry-After")
        if not value:
            return None
        try:
            seconds = float(value)
        except ValueError:
            return None
        if seconds <= 0:
            return None
        return seconds

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.status_code >= 400:
            detail_text = response.text.strip() or response.reason_phrase
            try:
                payload = response.json()
            except Exception:
                payload = None

            if isinstance(payload, dict):
                detail = payload.get("detail")
                if isinstance(detail, str) and detail:
                    detail_text = detail

                if response.status_code == 404 and isinstance(detail_text, str) and "project not found" in detail_text.lower():
                    raise RecoverableAuthError(
                        "Project not found (404). The project you're trying to sync to doesn't exist or you don't have access.",
                        hint="Run `khaos sync --login` and select a valid project.",
                    )

            raise CloudAuthError(f"Ingestion API error {response.status_code}: {detail_text}")

    @staticmethod
    def _load_metrics(path: str | None) -> dict:
        if not path:
            return {}
        metrics_path = Path(path)
        if not metrics_path.exists():
            return {}
        try:
            return json.loads(metrics_path.read_text())
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _metric_map(metrics_payload: dict) -> dict[str, dict]:
        artifacts = metrics_payload.get("artifacts")
        if not isinstance(artifacts, list):
            return {}
        out: dict[str, dict] = {}
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name:
                out[name] = item
        return out

    @classmethod
    def _synthesize_evaluation_report(cls, *, job: UploadJob, metrics_payload: dict) -> dict | None:
        """Best-effort pack-style evaluation report for non-pack runs.

        The dashboard's aggregate views expect a pack-like report shape with
        baseline/resilience/security sections for ratios and quick comparisons.
        """
        metrics = cls._metric_map(metrics_payload)
        if not metrics:
            return None

        timestamp = None
        if isinstance(metrics_payload.get("timestamp"), str):
            timestamp = metrics_payload.get("timestamp")

        # Goal counts (baseline.goals_met / goals_total).
        goals_met = goals_total = None
        goal_metric = metrics.get("goal.score")
        if isinstance(goal_metric, dict):
            details = goal_metric.get("details")
            if isinstance(details, dict):
                completed = details.get("completed")
                goal_count = details.get("goal_count")
                if isinstance(completed, int) and isinstance(goal_count, int):
                    goals_met = completed
                    goals_total = goal_count

        # Security counts.
        sec_metric = metrics.get("security.score")
        attacks_tested = attacks_blocked = attacks_inconclusive = attacks_passed = None
        attack_results: list[dict] = []
        if isinstance(sec_metric, dict):
            details = sec_metric.get("details")
            if isinstance(details, dict):
                tested = details.get("attacks_tested")
                blocked = details.get("attacks_blocked")
                inconclusive = details.get("attacks_inconclusive")
                passed = details.get("attacks_passed")
                if isinstance(tested, int):
                    attacks_tested = tested
                if isinstance(blocked, int):
                    attacks_blocked = blocked
                if isinstance(inconclusive, int):
                    attacks_inconclusive = inconclusive
                if isinstance(passed, int):
                    attacks_passed = passed

                results_list = details.get("results")
                if isinstance(results_list, list):
                    for row in results_list:
                        if not isinstance(row, dict):
                            continue
                        attack_id = row.get("attack_id")
                        attack_type = row.get("attack_type")
                        result = row.get("result")
                        if not isinstance(attack_id, str) or not attack_id:
                            continue
                        classification = "inconclusive"
                        if isinstance(result, str):
                            r = result.lower()
                            if r in {"blocked", "refused"}:
                                classification = "blocked"
                            elif r in {"exploited", "compromised", "passed"}:
                                classification = "compromised"
                        attack_results.append(
                            {
                                "attack_id": attack_id,
                                "attack_name": row.get("attack_name") or attack_id,
                                "attack_type": attack_type or "unknown",
                                "severity": row.get("severity") or "medium",
                                "injection_vector": row.get("injection_vector") or "user_input",
                                "is_custom": bool(row.get("is_custom", False)),
                                "classification": classification,
                            }
                        )

        # Overall score: prefer explicit overall_score, else average available score artifacts.
        overall_score = None
        if isinstance(metrics_payload.get("overall_score"), (int, float)):
            overall_score = float(metrics_payload.get("overall_score"))
        else:
            scores: list[float] = []
            for key in ("resilience.score", "goal.score", "security.score"):
                m = metrics.get(key)
                if isinstance(m, dict) and isinstance(m.get("value"), (int, float)):
                    scores.append(float(m["value"]))
            if scores:
                overall_score = sum(scores) / len(scores)

        report: dict[str, Any] = {
            "contract_version": "1.0",
            "pack_name": job.pack_name or job.scenario_id or "",
            "pack_version": job.pack_version or "",
            "timestamp": timestamp or datetime.utcnow().isoformat(),
            "run_id": job.run_id,
            "agent": {
                "name": job.agent_name,
                "version": job.agent_version,
                "code_hash": job.agent_code_hash,
                "framework": None,
                "entrypoint": None,
                "metadata": job.agent_metadata or {},
            },
            "baseline": None,
            "resilience": None,
            "security": None,
            "overall_score": round(overall_score, 1) if overall_score is not None else 0.0,
            "input_results": [],
            "capabilities": {},
            "skipped": {},
        }

        if goals_met is not None and goals_total is not None:
            report["baseline"] = {
                "runs": 0,
                "latency": {},
                "tokens": {},
                "cost_usd": None,
                "task_completion_rate": 1.0 if goals_total > 0 and goals_met == goals_total else 0.0,
                "error_rate": 0.0,
                "expectations_rate": 1.0 if goals_total > 0 and goals_met == goals_total else 0.0,
                "goals_met": goals_met,
                "goals_total": goals_total,
            }

        if attacks_tested is not None and attacks_blocked is not None:
            report["security"] = {
                "score": float(sec_metric.get("value")) if isinstance(sec_metric, dict) and isinstance(sec_metric.get("value"), (int, float)) else 0.0,
                "severity_score": None,
                "attacks_tested": attacks_tested,
                "attacks_blocked": attacks_blocked,
                "attacks_passed": attacks_passed if attacks_passed is not None else max(attacks_tested - attacks_blocked, 0),
                "attacks_inconclusive": attacks_inconclusive if attacks_inconclusive is not None else 0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "dangerous_actions": 0,
                "data_exposures": 0,
                "policy_slips": 0,
                "vulnerable_categories": [],
                "vulnerabilities": [],
                "attack_results": attack_results,
            }

        res_metric = metrics.get("resilience.score")
        if isinstance(res_metric, dict) and isinstance(res_metric.get("value"), (int, float)):
            report["resilience"] = {
                "score": float(res_metric.get("value")),
                "runs": 0,
                "total_faults": 0,
                "recovery_rate": 0.0,
                "degradation_percent": None,
                "fault_impacts": [],
                "fault_coverage": {},
            }

        return report
