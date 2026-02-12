"""HTTP/tool fault injection shim (ADR-0010 tool/RAG faults).

Applies deterministic faults to popular HTTP clients (requests/httpx) inside the
agent process using rules supplied via the `KHAOS_HTTP_FAULTS` environment
variable. This lets the runtime inject tool failures/latency/corruption without
agent-specific wiring.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from typing import Any
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:  # optional dependency
    import requests  # type: ignore
except Exception:  # pragma: no cover - optional
    requests = None

try:  # optional dependency
    import httpx  # type: ignore
except Exception:  # pragma: no cover - optional
    httpx = None

_SUPPORTED_TYPES = {
    # Original tool/RAG faults
    "tool_call_failure",
    "tool_response_corruption",
    "tool_latency_spike",
    "rag_retrieval_corruption",
    "rag_document_poisoning",
    "tool_output_injection",
    # Basic HTTP faults
    "http_latency",      # Add latency to HTTP requests
    "http_error",        # Return HTTP error responses (4xx/5xx)
    "timeout",           # Generic timeout
    "malformed_payload", # Return malformed/unparseable data
}

_ACTIVE_RULES: list[dict[str, Any]] = []
_RULES_LOCK = threading.Lock()

def _get_active_rules() -> list[dict[str, Any]]:
    with _RULES_LOCK:
        return list(_ACTIVE_RULES)

def update_active_rules(rules: list[dict[str, Any]] | None) -> None:
    """Update active HTTP fault rules dynamically for in-message fault delivery."""
    with _RULES_LOCK:
        _ACTIVE_RULES.clear()
        if rules:
            _ACTIVE_RULES.extend(rules)

def clear_active_rules() -> None:
    """Clear all active HTTP fault rules."""
    with _RULES_LOCK:
        _ACTIVE_RULES.clear()

def _safe_url(value: str) -> str:
    """Redact query/fragment to avoid leaking secrets via URL parameters."""
    try:
        parts = urlsplit(str(value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except Exception:
        return str(value)

def _emit_event(event: str, payload: dict[str, Any], *, meta: dict[str, Any] | None = None) -> None:
    path = os.environ.get("KHAOS_LLM_EVENT_FILE")
    if not path:
        return
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "payload": payload,
        "meta": meta or {},
    }
    try:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:  # pragma: no cover
        return

def enable_http_fault_shim() -> None:
    """Activate HTTP fault injection when rules are provided."""

    raw = os.environ.get("KHAOS_HTTP_FAULTS")
    if not raw:
        clear_active_rules()
        return
    try:
        rules = [r for r in json.loads(raw) if isinstance(r, dict)]
    except (json.JSONDecodeError, TypeError):
        return
    if not rules:
        clear_active_rules()
        return
    update_active_rules(rules)
    seed = os.environ.get("KHAOS_FAULT_SEED")
    seed_value = int(seed) if seed and str(seed).isdigit() else 0
    rng = random.Random(seed_value)

    _patch_requests(rng)
    _patch_httpx(rng)

def _matches(rule_cfg: dict[str, Any], url: str) -> bool:
    needle = rule_cfg.get("url_contains") or rule_cfg.get("target")
    if not needle:
        return True
    return str(needle) in url

def _normalize_http_fault_config(rule_type: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """Normalize config keys for backward compatibility with builtin packs."""
    normalized = dict(cfg)

    if rule_type in {"tool_latency_spike", "http_latency"}:
        if "delay_ms" not in normalized and isinstance(normalized.get("spike_ms"), (int, float)):
            normalized["delay_ms"] = normalized.get("spike_ms")

    if rule_type in {"timeout"}:
        if "delay_ms" not in normalized and isinstance(normalized.get("timeout_ms"), (int, float)):
            normalized["delay_ms"] = normalized.get("timeout_ms")

    if rule_type in {"tool_call_failure"}:
        if "failure_mode" not in normalized and normalized.get("error_type"):
            normalized["failure_mode"] = normalized.get("error_type")
        if "error_message" not in normalized and normalized.get("message"):
            normalized["error_message"] = normalized.get("message")

    if rule_type in {"http_error"}:
        if "error_message" not in normalized and normalized.get("message"):
            normalized["error_message"] = normalized.get("message")

    if rule_type in {"tool_output_injection"}:
        if "injection_payload" not in normalized and normalized.get("injection_text"):
            normalized["injection_payload"] = normalized.get("injection_text")

    if rule_type in {"rag_document_poisoning"}:
        if "payload" not in normalized and normalized.get("poison_type"):
            normalized["payload"] = str(normalized.get("poison_type"))

    if rule_type in {"malformed_payload"}:
        if "malformed_type" not in normalized:
            corruption = normalized.get("corruption_type")
            if isinstance(corruption, str) and corruption.lower() in {"truncate", "truncated"}:
                normalized["malformed_type"] = "truncated"
            elif isinstance(corruption, str) and corruption:
                normalized["malformed_type"] = corruption.lower()

    return normalized

def _should_trigger(rule_cfg: dict[str, Any], rng: random.Random) -> bool:
    try:
        prob = float(rule_cfg.get("probability", 1.0))
    except (TypeError, ValueError):
        prob = 1.0
    prob = max(0.0, min(1.0, prob))
    return rng.random() <= prob

def _coerce_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def _apply_rules_pre(
    *,
    rng: random.Random,
    url: str,
) -> tuple[float, dict[str, Any] | None, list[dict[str, Any]]]:
    """Return accumulated delay and an optional failure spec."""

    delay_ms = 0.0
    failure: dict[str, Any] | None = None
    applied: list[dict[str, Any]] = []
    for rule in _get_active_rules():
        rule_type = str(rule.get("type", "")).strip()
        if rule_type not in _SUPPORTED_TYPES:
            continue
        cfg = _normalize_http_fault_config(rule_type, rule.get("config", {}) or {})
        if not _matches(cfg, url) or not _should_trigger(cfg, rng):
            continue
        applied.append({"type": rule_type, "config": cfg})

        # Latency faults
        if rule_type in ("tool_latency_spike", "http_latency"):
            delay_ms += float(cfg.get("delay_ms", 0.0))

        # Failure/error faults
        elif rule_type == "tool_call_failure":
            failure = {
                "mode": cfg.get("failure_mode", "execution_error"),
                "status_code": cfg.get("status_code"),
                "error_message": cfg.get("error_message", "Injected tool failure"),
                "delay_ms": cfg.get("delay_ms"),
            }
        elif rule_type == "http_error":
            # Return HTTP error response (4xx/5xx)
            failure = {
                "mode": "http_error",
                "status_code": cfg.get("status_code", 500),
                "error_message": cfg.get("error_message", "Injected HTTP error"),
            }
        elif rule_type == "timeout":
            # Simulate request timeout
            failure = {
                "mode": "timeout",
                "delay_ms": cfg.get("delay_ms", 30000),
                "error_message": cfg.get("error_message", "Request timed out"),
            }
        elif rule_type == "malformed_payload":
            # Return malformed/unparseable response
            failure = {
                "mode": "malformed",
                "malformed_type": cfg.get("malformed_type", "invalid_json"),
                "status_code": cfg.get("status_code", 200),
            }

    return delay_ms, failure, applied

# Common field names where content might be found in tool/RAG responses
_CONTENT_FIELDS = ("content", "text", "body", "data", "message", "response", "result", "output")
_LIST_FIELDS = ("documents", "results", "items", "chunks", "passages", "matches", "hits")

def _inject_into_content(payload: Any, injection: str, injection_mode: str = "tool") -> Any:
    """Inject attack payload into content fields of a tool/RAG response.

    This function finds common content fields and injects the attack payload
    into them, simulating realistic indirect injection attacks.

    Args:
        payload: The parsed JSON response from the tool
        injection: The attack payload to inject
        injection_mode: "tool" for tool output, "rag" for document retrieval

    Returns:
        Modified payload with injection inserted into content fields
    """
    if payload is None:
        return {"content": injection}

    if isinstance(payload, str):
        # String response - prepend injection
        return f"{injection}\n\n{payload}"

    if isinstance(payload, list):
        # List of items - inject into first item's content
        if payload and isinstance(payload[0], dict):
            payload[0] = _inject_into_dict(payload[0], injection)
        elif payload and isinstance(payload[0], str):
            payload[0] = f"{injection}\n\n{payload[0]}"
        else:
            payload.insert(0, {"content": injection})
        return payload

    if isinstance(payload, dict):
        return _inject_into_dict(payload, injection, injection_mode)

    # Fallback: wrap in dict
    return {"content": injection, "original": payload}

def _inject_into_dict(d: dict, injection: str, injection_mode: str = "tool") -> dict:
    """Inject attack payload into a dict's content fields."""
    # For RAG responses, check document list fields first
    if injection_mode == "rag":
        for list_field in _LIST_FIELDS:
            if list_field in d and isinstance(d[list_field], list) and d[list_field]:
                items = d[list_field]
                if isinstance(items[0], dict):
                    # Inject into first document's content
                    items[0] = _inject_into_dict(items[0], injection, "tool")
                elif isinstance(items[0], str):
                    items[0] = f"{injection}\n\n{items[0]}"
                return d

    # Try to find and modify a content field
    for field in _CONTENT_FIELDS:
        if field in d:
            val = d[field]
            if isinstance(val, str):
                # Prepend injection to existing content
                d[field] = f"{injection}\n\n{val}"
                return d
            elif isinstance(val, list) and val:
                # List of content - inject into first item
                if isinstance(val[0], str):
                    val[0] = f"{injection}\n\n{val[0]}"
                elif isinstance(val[0], dict):
                    val[0] = _inject_into_dict(val[0], injection, "tool")
                return d

    # No content field found - add one and also set a flag field
    d["_injected_content"] = injection
    # Also try to add to a plausible field name based on existing keys
    if "content" not in d:
        d["content"] = injection
    return d

def _apply_rules_post(
    *,
    rng: random.Random,
    url: str,
    content: bytes,
    headers: dict[str, str],
) -> bytes:
    """Mutate response content according to post-processing rules."""

    try:
        payload = json.loads(content)
    except Exception:
        payload = None

    for rule in _get_active_rules():
        rule_type = str(rule.get("type", "")).strip()
        if rule_type not in _SUPPORTED_TYPES:
            continue
        cfg = _normalize_http_fault_config(rule_type, rule.get("config", {}) or {})
        if not _matches(cfg, url) or not _should_trigger(cfg, rng):
            continue
        if rule_type == "tool_response_corruption" and isinstance(payload, dict):
            corruption_type = cfg.get("corruption_type", "schema_violation")
            if corruption_type == "schema_violation":
                if payload:
                    payload.pop(next(iter(payload.keys())), None)
            elif corruption_type == "incorrect_data":
                for key, value in list(payload.items()):
                    if isinstance(value, (int, float)):
                        payload[key] = -value
                    elif isinstance(value, str):
                        payload[key] = f"CORRUPTED_{value}"
            elif corruption_type == "partial_response":
                if isinstance(payload, dict):
                    keep = max(1, int(cfg.get("keep_fields", max(1, len(payload) // 2))))
                    payload = {k: payload[k] for k in list(payload.keys())[:keep]}
        elif rule_type == "rag_retrieval_corruption" and isinstance(payload, dict):
            docs = payload.get("documents")
            if isinstance(docs, list):
                payload["documents"] = [{"content": "irrelevant document", "relevance": 0.0}]
        elif rule_type == "rag_document_poisoning":
            poison = cfg.get("payload") or cfg.get("injection_payload") or "[POISONED]"
            payload = _inject_into_content(payload, poison, injection_mode="rag")
        elif rule_type == "tool_output_injection":
            injection = cfg.get("injection_payload") or cfg.get("injection_text") or "[INJECTED]"
            payload = _inject_into_content(payload, injection, injection_mode="tool")

    if payload is None:
        return content
    try:
        return json.dumps(payload).encode("utf-8")
    except Exception:
        return content

def _make_failure_response_requests(url: str, failure: dict[str, Any]) -> Any:
    import requests  # type: ignore

    resp = requests.Response()
    mode = failure.get("mode")
    status = int(failure.get("status_code") or (403 if mode == "permission_denied" else 500))
    body = failure.get("error_message", "Injected tool failure")
    resp.status_code = status
    resp._content = str(body).encode("utf-8")
    resp.url = url
    return resp

def _make_failure_response_httpx(method: str, url: str, failure: dict[str, Any]) -> Any:
    import httpx  # type: ignore

    status = int(failure.get("status_code") or (403 if failure.get("mode") == "permission_denied" else 500))
    body = failure.get("error_message", "Injected tool failure")
    request = httpx.Request(method, url)
    return httpx.Response(status, content=str(body).encode("utf-8"), request=request)

def _patch_requests(rng: random.Random) -> None:
    if requests is None:
        return
    Session = getattr(requests, "Session", None)
    if Session is None or getattr(Session.request, "__khaos_http_fault_wrapped__", False):
        return
    original_request = Session.request

    def wrapped(self, method, url, *args, **kwargs):
        safe_url = _safe_url(url)
        started = time.perf_counter()
        delay_ms, failure, applied = _apply_rules_pre(rng=rng, url=safe_url)
        _emit_event(
            "http.request",
            {"method": str(method), "url": safe_url},
            meta={"applied_faults": applied},
        )
        if delay_ms:
            _emit_event(
                "injector.action",
                {"type": "http_latency", "latency_ms": float(delay_ms), "url": safe_url},
            )
            time.sleep(delay_ms / 1000.0)
        if failure:
            mode = failure.get("mode")
            if mode == "timeout":
                time.sleep(_coerce_int(failure.get("delay_ms"), 1000) / 1000.0)
                _emit_event("injector.action", {"type": "timeout", "url": safe_url})
                raise requests.Timeout(failure.get("error_message", "Injected timeout"))
            if mode == "invalid_response":
                resp = requests.Response()
                resp.status_code = 200
                resp.url = url
                resp._content = b"INVALID"
                _emit_event("injector.action", {"type": "invalid_response", "url": safe_url})
                return resp
            if mode == "malformed":
                # Return malformed/unparseable response
                resp = requests.Response()
                resp.status_code = _coerce_int(failure.get("status_code"), 200)
                resp.url = url
                malformed_type = failure.get("malformed_type", "invalid_json")
                if malformed_type == "invalid_json":
                    resp._content = b'{"incomplete": true, missing_bracket'
                elif malformed_type == "binary_garbage":
                    resp._content = b'\x00\x01\x02\xff\xfe\xfd'
                elif malformed_type == "truncated":
                    resp._content = b'{"data": "this response was truncat'
                else:
                    resp._content = b'MALFORMED'
                _emit_event("injector.action", {"type": "malformed_payload", "url": safe_url, "malformed_type": malformed_type})
                return resp
            if mode == "http_error":
                # Return HTTP error with specified status code
                _emit_event("injector.action", {"type": "http_error", "url": safe_url, "status_code": failure.get("status_code")})
                return _make_failure_response_requests(url, failure)
            _emit_event("injector.action", {"type": "tool_call_failure", "url": safe_url})
            return _make_failure_response_requests(url, failure)

        response = original_request(self, method, url, *args, **kwargs)
        try:
            content = response.content or b""
        except Exception:
            return response
        mutated = _apply_rules_post(
            rng=rng,
            url=safe_url,
            content=content,
            headers=dict(response.headers or {}),
        )
        if mutated != content:
            response._content = mutated
            _emit_event("injector.action", {"type": "tool_response_corruption", "url": safe_url})
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        _emit_event(
            "http.response",
            {"method": str(method), "url": safe_url, "status_code": int(getattr(response, "status_code", 0) or 0), "latency_ms": elapsed_ms},
        )
        return response

    wrapped.__khaos_http_fault_wrapped__ = True  # type: ignore[attr-defined]
    Session.request = wrapped

def _patch_httpx(rng: random.Random) -> None:
    if httpx is None:
        return
    Client = getattr(httpx, "Client", None)
    if Client is None or getattr(Client.request, "__khaos_http_fault_wrapped__", False):
        return
    original_request = Client.request

    def wrapped(self, method, url, *args, **kwargs):
        safe_url = _safe_url(url)
        started = time.perf_counter()
        delay_ms, failure, applied = _apply_rules_pre(rng=rng, url=safe_url)
        _emit_event(
            "http.request",
            {"method": str(method), "url": safe_url},
            meta={"applied_faults": applied},
        )
        if delay_ms:
            _emit_event(
                "injector.action",
                {"type": "http_latency", "latency_ms": float(delay_ms), "url": safe_url},
            )
            time.sleep(delay_ms / 1000.0)
        if failure:
            mode = failure.get("mode")
            if mode == "timeout":
                time.sleep(_coerce_int(failure.get("delay_ms"), 1000) / 1000.0)
                _emit_event("injector.action", {"type": "timeout", "url": safe_url})
                raise httpx.TimeoutException(failure.get("error_message", "Injected timeout"))
            if mode == "invalid_response":
                request = httpx.Request(method, url)
                _emit_event("injector.action", {"type": "invalid_response", "url": safe_url})
                return httpx.Response(200, content=b"INVALID", request=request)
            if mode == "malformed":
                # Return malformed/unparseable response
                request = httpx.Request(method, url)
                malformed_type = failure.get("malformed_type", "invalid_json")
                if malformed_type == "invalid_json":
                    content = b'{"incomplete": true, missing_bracket'
                elif malformed_type == "binary_garbage":
                    content = b'\x00\x01\x02\xff\xfe\xfd'
                elif malformed_type == "truncated":
                    content = b'{"data": "this response was truncat'
                else:
                    content = b'MALFORMED'
                status = _coerce_int(failure.get("status_code"), 200)
                _emit_event("injector.action", {"type": "malformed_payload", "url": safe_url, "malformed_type": malformed_type})
                return httpx.Response(status, content=content, request=request)
            if mode == "http_error":
                # Return HTTP error with specified status code
                _emit_event("injector.action", {"type": "http_error", "url": safe_url, "status_code": failure.get("status_code")})
                return _make_failure_response_httpx(method, url, failure)
            _emit_event("injector.action", {"type": "tool_call_failure", "url": safe_url})
            return _make_failure_response_httpx(method, url, failure)

        response = original_request(self, method, url, *args, **kwargs)
        try:
            content = bytes(response.content or b"")
        except Exception:
            return response
        mutated = _apply_rules_post(
            rng=rng,
            url=safe_url,
            content=content,
            headers=dict(response.headers or {}),
        )
        if mutated != content:
            response._content = mutated  # type: ignore[attr-defined]
            _emit_event("injector.action", {"type": "tool_response_corruption", "url": safe_url})
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        _emit_event(
            "http.response",
            {"method": str(method), "url": safe_url, "status_code": int(getattr(response, "status_code", 0) or 0), "latency_ms": elapsed_ms},
        )
        return response

    wrapped.__khaos_http_fault_wrapped__ = True  # type: ignore[attr-defined]
    Client.request = wrapped

__all__ = ["enable_http_fault_shim"]
