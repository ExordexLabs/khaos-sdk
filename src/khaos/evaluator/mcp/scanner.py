"""MCP server discovery and fingerprinting.

Powers ``khaos mcp scan``.  Connects to a server, enumerates tools and
resources, and performs static risk assessment on tool schemas.

Risk detection is performed WITHOUT calling any tools — it only
analyses the *schemas* returned by ``tools/list`` and ``resources/list``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .client import MCPServerSpec, MCPTestClient, ToolInfo, ResourceInfo


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RiskFinding:
    """A single risk identified during schema analysis."""

    category: str       # e.g. "input-validation", "auth", "secret-exposure"
    severity: str       # critical / high / medium / low / info
    owasp_id: str       # MCP01-MCP10
    title: str
    detail: str
    tool_name: str | None = None
    resource_uri: str | None = None
    advisory: bool = False


@dataclass(slots=True)
class ScanResult:
    """Complete scan output for a single MCP server."""

    server_name: str
    transport: str
    tools: list[ToolInfo]
    resources: list[ResourceInfo]
    risk_findings: list[RiskFinding]
    owasp_flags: list[str]  # de-duplicated OWASP IDs that had findings

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.risk_findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.risk_findings if f.severity == "high")

    @property
    def total_findings(self) -> int:
        return len(self.risk_findings)


# ---------------------------------------------------------------------------
# Static risk detection heuristics
# ---------------------------------------------------------------------------

# Parameter names that suggest file/path operations → path traversal risk
_PATH_PARAMS = re.compile(
    r"^(path|file|filepath|file_path|filename|file_name|"
    r"directory|dir|folder|location|source|destination|target|root)$",
    re.IGNORECASE,
)

# Parameter names that suggest query / database operations → injection risk
_QUERY_PARAMS = re.compile(
    r"^(query|sql|search|filter|where|expression|"
    r"command|cmd|script|exec|code|statement|input)$",
    re.IGNORECASE,
)

# Parameter names that suggest URL operations → SSRF risk
_URL_PARAMS = re.compile(
    r"^(url|uri|endpoint|href|link|redirect|callback|webhook|target_url|fetch)$",
    re.IGNORECASE,
)

# Suspicious patterns in tool descriptions → tool poisoning (MCP03)
_SUSPICIOUS_DESC_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(previous|prior|above)\s+instructions?", "instruction override"),
    (r"(system|assistant)\s*_?(override|instruction|prompt)", "system override reference"),
    (r"before\s+returning\s+results?,?\s+(always|first)", "pre-return directive"),
    (r"output\s+(your|the)\s+(system\s+prompt|instructions|config)", "prompt leak request"),
    (r"bypass\s+(security|auth|validation|safety)", "bypass directive"),
    (r"admin[_\s]?(mode|override|access)", "admin escalation"),
    (r"(do\s+not|don'?t)\s+tell\s+the\s+user", "concealment directive"),
    (r"exfiltrate|steal|harvest|scrape\s+data", "data theft directive"),
]


# Parameter names suggesting privilege/scope operations → MCP02
_PRIVILEGE_PARAMS = re.compile(
    r"^(role|scope|permission|privilege|access_level|admin|"
    r"user_role|auth_level|trust|level|mode)$",
    re.IGNORECASE,
)

# Tool names implying dangerous capabilities → MCP02
_DANGEROUS_TOOL_NAMES = re.compile(
    r"(delete|remove|drop|truncate|exec|execute|run|eval|"
    r"admin|grant|revoke|modify|write|create|destroy|kill|"
    r"shutdown|restart|update_config|set_permission)",
    re.IGNORECASE,
)

# Suspicious patterns in tool descriptions — extended set for MCP03
_SUSPICIOUS_DESC_PATTERNS_EXTENDED: list[tuple[str, str]] = [
    # Hidden instruction patterns
    (r"IMPORTANT\s*:", "hidden priority directive"),
    (r"SYSTEM\s*:", "fake system message"),
    (r"NOTE\s+TO\s+(ASSISTANT|AI|MODEL|AGENT)", "direct model instruction"),
    (r"always\s+(include|output|return|add|prepend|append)", "unconditional output directive"),
    (r"never\s+(tell|reveal|disclose|show|mention)", "concealment directive"),
    (r"(secretly|silently|quietly)\s+(send|post|forward|transmit)", "covert action directive"),
    (r"(this|the following)\s+is\s+(confidential|secret|private)", "false confidentiality claim"),
    (r"for\s+(?:security|audit|compliance)\s+purposes?,?\s+(?:always|include|output)", "false compliance directive"),
    (r"(?:re)?format\s+(?:all|every|the)\s+(?:response|output|result)", "output hijack directive"),
    (r"(?:wrap|encode|embed)\s+(?:all|every|the)\s+(?:response|output|data)\s+in", "output wrapping directive"),
]

# Known-vulnerable / suspicious package patterns for supply chain (MCP04)
_SUSPICIOUS_PACKAGES: list[tuple[str, str]] = [
    (r"@[a-z]+-(?:mcp|server|tool)s?/", "potential typosquat (non-official org)"),
    (r"mcp-(?:server|tool)-[a-z]+(?!.*\d)", "unversioned community MCP package"),
]

# Patterns in server env vars that suggest secret leakage (MCP09)
_SUSPICIOUS_ENV_KEYS = re.compile(
    r"(password|secret|token|api_key|apikey|private_key|"
    r"aws_secret|credentials|auth_token|session_key)",
    re.IGNORECASE,
)


def _analyze_tool_schema(tool: ToolInfo) -> list[RiskFinding]:
    """Analyze a single tool's schema for risk indicators."""
    findings: list[RiskFinding] = []

    # Extract parameter definitions from input_schema
    properties = tool.input_schema.get("properties", {})
    required = set(tool.input_schema.get("required", []))

    for param_name, param_def in properties.items():
        param_type = param_def.get("type", "string")
        param_desc = str(param_def.get("description", "")).lower()

        # PATH TRAVERSAL RISK (MCP05)
        if _PATH_PARAMS.match(param_name) or "file" in param_desc or "path" in param_desc:
            findings.append(RiskFinding(
                category="input-validation",
                severity="high",
                owasp_id="MCP05",
                title=f"Path traversal risk: parameter '{param_name}'",
                detail=(
                    f"Tool '{tool.name}' accepts a path-like parameter "
                    f"'{param_name}' ({param_type}). Without server-side validation, "
                    f"payloads like '../../etc/passwd' may traverse outside allowed directories."
                ),
                tool_name=tool.name,
            ))

        # SQL / COMMAND INJECTION RISK (MCP05)
        if _QUERY_PARAMS.match(param_name) or "query" in param_desc or "sql" in param_desc:
            findings.append(RiskFinding(
                category="input-validation",
                severity="high",
                owasp_id="MCP05",
                title=f"Injection risk: parameter '{param_name}'",
                detail=(
                    f"Tool '{tool.name}' accepts a query/command parameter "
                    f"'{param_name}' ({param_type}). This may be vulnerable to "
                    f"SQL injection, command injection, or code injection attacks."
                ),
                tool_name=tool.name,
            ))

        # SSRF RISK (MCP05)
        if _URL_PARAMS.match(param_name) or "url" in param_desc or "endpoint" in param_desc:
            findings.append(RiskFinding(
                category="input-validation",
                severity="high",
                owasp_id="MCP05",
                title=f"SSRF risk: parameter '{param_name}'",
                detail=(
                    f"Tool '{tool.name}' accepts a URL parameter "
                    f"'{param_name}' ({param_type}). Without validation, "
                    f"this may be exploited for SSRF (e.g., http://169.254.169.254/)."
                ),
                tool_name=tool.name,
            ))

        # Unrestricted string with no validation hints
        if (
            param_type == "string"
            and param_name not in required
            and not param_def.get("enum")
            and not param_def.get("pattern")
            and not param_def.get("maxLength")
        ):
            # Only flag if it's a potentially dangerous param name
            if _PATH_PARAMS.match(param_name) or _QUERY_PARAMS.match(param_name):
                findings.append(RiskFinding(
                    category="input-validation",
                    severity="medium",
                    owasp_id="MCP05",
                    title=f"No input constraints on '{param_name}'",
                    detail=(
                        f"Tool '{tool.name}' parameter '{param_name}' has no "
                        f"enum, pattern, or maxLength constraints in its schema."
                    ),
                    tool_name=tool.name,
                ))

    # TOOL DESCRIPTION POISONING (MCP03)
    desc_text = tool.description or ""
    for pattern, pattern_name in _SUSPICIOUS_DESC_PATTERNS:
        if re.search(pattern, desc_text, re.IGNORECASE):
            findings.append(RiskFinding(
                category="tool-poisoning",
                severity="critical",
                owasp_id="MCP03",
                title=f"Suspicious tool description: {pattern_name}",
                detail=(
                    f"Tool '{tool.name}' description contains a suspicious pattern "
                    f"({pattern_name}): may embed hidden instructions for the LLM."
                ),
                tool_name=tool.name,
            ))

    # PRIVILEGE ESCALATION RISK (MCP02) — tools with role/scope params
    for param_name, param_def in properties.items():
        if _PRIVILEGE_PARAMS.match(param_name):
            has_enum = bool(param_def.get("enum"))
            findings.append(RiskFinding(
                category="privilege-escalation",
                severity="high" if not has_enum else "medium",
                owasp_id="MCP02",
                title=f"Privilege parameter: '{param_name}' on '{tool.name}'",
                detail=(
                    f"Tool '{tool.name}' accepts a privilege-related parameter "
                    f"'{param_name}'. {'No enum constraint — arbitrary values accepted.' if not has_enum else 'Enum-constrained but escalation may still be possible.'}"
                ),
                tool_name=tool.name,
            ))

    # PRIVILEGE ESCALATION RISK (MCP02) — dangerous tool capabilities
    tool_name_lower = tool.name.lower()
    if _DANGEROUS_TOOL_NAMES.search(tool_name_lower):
        # Check if tool has scope/confirmation params (mitigation)
        has_scope = any(
            _PRIVILEGE_PARAMS.match(p) or p.lower() in ("confirm", "dry_run", "dryrun", "safe_mode")
            for p in properties
        )
        if not has_scope:
            findings.append(RiskFinding(
                category="privilege-escalation",
                severity="high",
                owasp_id="MCP02",
                title=f"Unscoped dangerous tool: '{tool.name}'",
                detail=(
                    f"Tool '{tool.name}' performs a destructive/privileged operation "
                    f"but has no scope, confirmation, or dry-run parameter."
                ),
                tool_name=tool.name,
            ))

    # TOOL DESCRIPTION POISONING — extended patterns (MCP03)
    for pattern, pattern_name in _SUSPICIOUS_DESC_PATTERNS_EXTENDED:
        if re.search(pattern, desc_text, re.IGNORECASE):
            findings.append(RiskFinding(
                category="tool-poisoning",
                severity="critical",
                owasp_id="MCP03",
                title=f"Suspicious tool description: {pattern_name}",
                detail=(
                    f"Tool '{tool.name}' description contains a suspicious pattern "
                    f"({pattern_name}): may embed hidden instructions for the LLM."
                ),
                tool_name=tool.name,
            ))

    # LACK OF AUDIT (MCP08) — check if description mentions logging/audit
    # (This is a positive signal; absence is noted at the server level)

    return findings


def _analyze_resource(resource: ResourceInfo) -> list[RiskFinding]:
    """Analyze a single resource for risk indicators."""
    findings: list[RiskFinding] = []
    uri = resource.uri

    # Broad URI patterns → privilege scope risk (MCP02)
    if "*" in uri or "{" in uri:
        findings.append(RiskFinding(
            category="privilege-scope",
            severity="medium",
            owasp_id="MCP02",
            title=f"Broad resource URI pattern: {uri}",
            detail=(
                f"Resource '{resource.name or uri}' uses a wildcard or template URI pattern, "
                f"which may grant overly broad access."
            ),
            resource_uri=uri,
        ))

    # File:// scheme → potential arbitrary file access
    if uri.lower().startswith("file://"):
        findings.append(RiskFinding(
            category="input-validation",
            severity="high",
            owasp_id="MCP05",
            title=f"File-scheme resource: {uri}",
            detail=(
                f"Resource uses file:// URI scheme which may allow access to "
                f"sensitive local files."
            ),
            resource_uri=uri,
        ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _analyze_server_spec(spec: MCPServerSpec, tools: list[ToolInfo]) -> list[RiskFinding]:
    """Analyze the server specification itself for risks."""
    findings: list[RiskFinding] = []

    # ===================================================================
    # MCP04 — Supply Chain Attacks
    # ===================================================================

    if spec.transport == "stdio" and spec.command:
        cmd = spec.command
        args_str = " ".join(spec.args or [])
        full_cmd = f"{cmd} {args_str}".strip()

        # npx without version pinning
        if cmd == "npx":
            has_version = any(
                "@" in a and any(c.isdigit() for c in a.split("@")[-1])
                for a in (spec.args or [])
                if a.startswith("@") or "/" in a
            )
            if not has_version:
                findings.append(RiskFinding(
                    category="supply-chain",
                    severity="medium",
                    owasp_id="MCP04",
                    title="npx without version pinning",
                    detail=(
                        f"Server runs via 'npx' without version pinning: {full_cmd}. "
                        f"This fetches the latest version at runtime, vulnerable to "
                        f"supply chain attacks if the package is compromised."
                    ),
                ))

            # -y flag (auto-confirm) amplifies risk
            if "-y" in (spec.args or []):
                findings.append(RiskFinding(
                    category="supply-chain",
                    severity="high",
                    owasp_id="MCP04",
                    title="npx -y auto-confirms package installation",
                    detail=(
                        f"Server uses 'npx -y' which auto-confirms package installation "
                        f"without user review: {full_cmd}. Combined with no version pinning, "
                        f"this enables silent supply chain attacks."
                    ),
                ))

        # pip install / pipx run without version
        if cmd in ("pip", "pipx", "pip3"):
            findings.append(RiskFinding(
                category="supply-chain",
                severity="medium",
                owasp_id="MCP04",
                title=f"Python package manager as MCP server command",
                detail=(
                    f"Server command uses '{cmd}': {full_cmd}. "
                    f"Verify the package source and pin the version."
                ),
            ))

        # Check for suspicious package patterns
        for pattern, reason in _SUSPICIOUS_PACKAGES:
            if re.search(pattern, full_cmd):
                findings.append(RiskFinding(
                    category="supply-chain",
                    severity="medium",
                    owasp_id="MCP04",
                    title=f"Suspicious package pattern: {reason}",
                    detail=(
                        f"Server command references a package matching a suspicious "
                        f"pattern ({reason}): {full_cmd}"
                    ),
                ))

    # ===================================================================
    # MCP08 — Lack of Audit Logging
    # ===================================================================

    # Check if any tool suggests logging/audit capabilities
    audit_keywords = ("log", "audit", "history", "trace", "event", "monitor")
    has_audit_tool = any(
        any(kw in (t.name.lower() + " " + (t.description or "").lower()) for kw in audit_keywords)
        for t in tools
    )

    if not has_audit_tool and len(tools) > 0:
        findings.append(RiskFinding(
            category="audit",
            severity="info",
            owasp_id="MCP08",
            title="MCP protocol lacks audit logging standard",
            detail=(
                f"Server '{spec.name}' exposes {len(tools)} tool(s) but none "
                f"appear to provide logging, audit trails, or event monitoring. "
                f"The MCP protocol does not define an audit logging standard. "
                f"This is a protocol limitation, not a server bug."
            ),
            advisory=True,
        ))

    # ===================================================================
    # MCP09 — Shadow Servers (config-level risks)
    # ===================================================================

    # Check env vars for secrets passed to server
    if spec.env:
        for key, value in spec.env.items():
            if _SUSPICIOUS_ENV_KEYS.search(key):
                findings.append(RiskFinding(
                    category="shadow-server",
                    severity="high",
                    owasp_id="MCP09",
                    title=f"Secret in server env var: {key}",
                    detail=(
                        f"Server '{spec.name}' receives a secret-like environment "
                        f"variable '{key}'. If this server is compromised or "
                        f"unauthorized, these credentials are exposed."
                    ),
                ))

    # Servers running arbitrary scripts (not from known package managers)
    if spec.transport == "stdio" and spec.command:
        cmd = spec.command
        if cmd.endswith((".sh", ".bash", ".py", ".js", ".ts")):
            findings.append(RiskFinding(
                category="shadow-server",
                severity="medium",
                owasp_id="MCP09",
                title=f"Server runs local script: {cmd}",
                detail=(
                    f"Server '{spec.name}' runs a local script ({cmd}) rather than "
                    f"a recognized package. Verify this script's provenance and integrity."
                ),
            ))

    return findings


def _check_mcp07_server_level(tools: list[ToolInfo]) -> list[RiskFinding]:
    """Emit a single server-level advisory for MCP07 (no per-tool auth).

    The MCP protocol itself lacks per-tool authentication.  Rather than
    flagging every tool individually, emit one informational finding that
    summarises the scope.
    """
    findings: list[RiskFinding] = []

    dangerous_no_auth = 0
    total_tools = len(tools)

    for tool in tools:
        properties = tool.input_schema.get("properties", {})
        all_param_names = " ".join(properties.keys()).lower()
        all_param_descs = " ".join(
            str(p.get("description", "")) for p in properties.values()
        ).lower()
        has_auth_ref = any(
            kw in all_param_names or kw in all_param_descs
            for kw in ("auth", "token", "credential", "api_key", "apikey", "bearer")
        )
        has_dangerous_param = any(
            _PATH_PARAMS.match(p) or _QUERY_PARAMS.match(p) or _URL_PARAMS.match(p)
            for p in properties
        )
        if not has_auth_ref and has_dangerous_param:
            dangerous_no_auth += 1

    if dangerous_no_auth > 0:
        findings.append(RiskFinding(
            category="auth",
            severity="info",
            owasp_id="MCP07",
            title=f"MCP protocol lacks per-tool authentication ({dangerous_no_auth} of {total_tools} tools affected)",
            detail=(
                f"The MCP protocol does not define a standard per-tool authentication "
                f"mechanism. {dangerous_no_auth} tool(s) operate on files/queries/URLs "
                f"but have no auth-related parameters. This is a protocol limitation, "
                f"not a server bug."
            ),
            advisory=True,
        ))

    return findings


async def scan_server(spec: MCPServerSpec) -> ScanResult:
    """Connect to an MCP server, enumerate capabilities, and assess risk.

    This does NOT call any tools — it only inspects the published schemas.
    """
    async with MCPTestClient() as client:
        await client.connect(spec)

        tools = await client.list_tools()
        try:
            resources = await client.list_resources()
        except Exception:
            resources = []

    # Run risk analysis
    findings: list[RiskFinding] = []

    # Tool/resource schema analysis
    for tool in tools:
        findings.extend(_analyze_tool_schema(tool))
    for resource in resources:
        findings.extend(_analyze_resource(resource))

    # Server-level analysis (MCP04, MCP08, MCP09)
    findings.extend(_analyze_server_spec(spec, tools))

    # Server-level advisory findings
    findings.extend(_check_mcp07_server_level(tools))

    # Collect unique OWASP IDs
    owasp_flags = sorted(set(f.owasp_id for f in findings))

    return ScanResult(
        server_name=spec.name,
        transport=spec.transport,
        tools=tools,
        resources=resources,
        risk_findings=findings,
        owasp_flags=owasp_flags,
    )


__all__ = [
    "RiskFinding",
    "ScanResult",
    "scan_server",
]
