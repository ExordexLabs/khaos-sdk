"""Response analysis for MCP tool call results.

Examines tool responses for evidence of successful exploitation,
information disclosure, secret leakage, or other security issues.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from .client import ToolResult
from .fuzzer import FuzzCase


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Finding:
    """A single security finding from response analysis."""

    category: str       # e.g. "path-traversal-success", "secret-leak"
    severity: str       # critical / high / medium / low
    owasp_id: str
    title: str
    detail: str
    evidence: str = ""  # excerpt from response
    advisory: bool = False


@dataclass(slots=True)
class AnalysisResult:
    """Analysis result for a single fuzz case execution."""

    classification: str  # "vulnerable", "safe", "error", "inconclusive"
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return self.classification == "vulnerable"


# ---------------------------------------------------------------------------
# Secret / credential detection patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, name, severity)
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "critical"),
    (r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S+", "AWS Secret Key", "critical"),
    (r"ghp_[A-Za-z0-9_]{36}", "GitHub Personal Access Token", "critical"),
    (r"gho_[A-Za-z0-9_]{36}", "GitHub OAuth Token", "critical"),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub Fine-Grained PAT", "critical"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API Key", "critical"),
    (r"sk-ant-[A-Za-z0-9-]{20,}", "Anthropic API Key", "critical"),
    (r"xox[bpsa]-[0-9A-Za-z-]+", "Slack Token", "critical"),
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token", "high"),
    (r"(?:password|passwd|pwd)\s*[=:]\s*\S+", "Password in response", "high"),
    (r"(?:api[_-]?key|apikey)\s*[=:]\s*\S+", "API Key in response", "high"),
    (r"(?:secret|token)\s*[=:]\s*['\"]?\S{8,}", "Secret/Token value", "high"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key", "critical"),
    (r"(?:postgres|mysql|mongodb|redis)://\S+:\S+@\S+", "Database Connection String", "critical"),
]

# Patterns indicating path traversal success
_PATH_TRAVERSAL_SUCCESS: list[str] = [
    "root:",          # /etc/passwd content
    "daemon:",        # /etc/passwd content
    "nobody:",        # /etc/passwd content
    "[boot loader]",  # Windows SAM
    "\\SAM",
    "/bin/bash",
    "/bin/sh",
    "[extensions]",   # Windows system files
]

# Patterns indicating information disclosure
_INFO_DISCLOSURE: list[tuple[str, str]] = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at \S+\.java:\d+", "Java stack trace"),
    (r"at \S+ \(\S+\.js:\d+:\d+\)", "JavaScript stack trace"),
    (r"(?:SQLSTATE|ORA-\d+|PG::|mysql_)", "Database error"),
    (r"/home/\S+/", "Internal path disclosure"),
    (r"/var/\S+/", "Internal path disclosure"),
    (r"/usr/\S+/", "Internal path disclosure"),
    (r"(?:ConnectionString|connection_string)\s*=", "Connection string disclosure"),
    (r"(?:internal\s+server\s+error|500\s+error)", "Server error disclosure"),
]

# Shannon entropy threshold for detecting random/secret-like strings
_ENTROPY_THRESHOLD = 5.0
_ENTROPY_MIN_LENGTH = 20


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _has_mixed_charset(text: str) -> bool:
    """Check if text contains at least 3 of 4 character classes.

    Classes: uppercase letters, lowercase letters, digits, special characters.
    """
    classes = 0
    if any(c.isupper() for c in text):
        classes += 1
    if any(c.islower() for c in text):
        classes += 1
    if any(c.isdigit() for c in text):
        classes += 1
    if any(not c.isalnum() for c in text):
        classes += 1
    return classes >= 3


def _extract_response_text(result: ToolResult) -> str:
    """Extract all text content from a tool result."""
    parts: list[str] = []
    for item in result.content:
        text = item.get("text", "")
        if text:
            parts.append(str(text))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def _check_secrets(text: str) -> list[Finding]:
    """Scan response text for leaked secrets and credentials."""
    findings: list[Finding] = []

    for pattern, name, severity in _SECRET_PATTERNS:
        matches = re.findall(pattern, text)
        for match in matches:
            findings.append(Finding(
                category="secret-leak",
                severity=severity,
                owasp_id="MCP01",
                title=f"Leaked {name}",
                detail=f"Response contains what appears to be a {name}.",
                evidence=str(match)[:80],
            ))

    # High-entropy string detection (potential secrets)
    words = text.split()
    for word in words:
        clean = word.strip("'\"`,;:()[]{}").strip()
        if (
            len(clean) >= _ENTROPY_MIN_LENGTH
            and _shannon_entropy(clean) >= _ENTROPY_THRESHOLD
            and not clean.startswith(("http://", "https://"))
            and re.search(r"[A-Za-z]", clean)
            and re.search(r"[0-9]", clean)
        ):
            # Skip non-secret patterns
            if re.match(r"^[a-f0-9-]+$", clean):  # UUIDs
                continue
            if re.match(r"^[0-9a-fA-F]+$", clean):  # hex-only
                continue
            if re.match(r"^[a-z]+(?:[A-Z][a-z0-9]*)+$", clean):  # camelCase
                continue
            if "/" in clean or "\\" in clean:  # file paths
                continue
            if not _has_mixed_charset(clean):  # require 3+ char classes
                continue
            findings.append(Finding(
                category="high-entropy-value",
                severity="low",
                owasp_id="MCP01",
                title="High-entropy value in response",
                detail=(
                    f"Response contains a high-entropy string "
                    f"(entropy={_shannon_entropy(clean):.1f}) that may be a secret."
                ),
                evidence=clean[:60],
            ))

    return findings


def _check_path_traversal(text: str, fuzz_case: FuzzCase) -> list[Finding]:
    """Check if a path traversal attack succeeded."""
    findings: list[Finding] = []

    if fuzz_case.attack_category != "path-traversal":
        return findings

    for marker in _PATH_TRAVERSAL_SUCCESS:
        if marker.lower() in text.lower():
            findings.append(Finding(
                category="path-traversal-success",
                severity="critical",
                owasp_id="MCP05",
                title="Path traversal successful",
                detail=(
                    f"Tool '{fuzz_case.tool_name}' returned content matching "
                    f"'{marker}' when given a path traversal payload."
                ),
                evidence=text[:200],
            ))
            break

    return findings


def _check_injection_success(text: str, fuzz_case: FuzzCase) -> list[Finding]:
    """Check if SQL/command injection succeeded based on response content."""
    findings: list[Finding] = []

    if fuzz_case.attack_category == "sql-injection":
        # Signs of SQL injection success
        sql_success_markers = [
            "information_schema",
            "table_name",
            "column_name",
            "sleep(",
            "waitfor delay",
            "union select",
        ]
        for marker in sql_success_markers:
            if marker in text.lower():
                findings.append(Finding(
                    category="sql-injection-success",
                    severity="critical",
                    owasp_id="MCP05",
                    title="SQL injection may have succeeded",
                    detail=(
                        f"Tool '{fuzz_case.tool_name}' response contains SQL metadata "
                        f"marker '{marker}' after injection attempt."
                    ),
                    evidence=text[:200],
                ))
                break

    if fuzz_case.attack_category == "command-injection":
        # Signs of command injection success
        cmd_success_markers = [
            "uid=",           # output of `id`
            "root:",          # /etc/passwd content
            "total ",         # output of `ls`
            "bin/bash",
            "whoami",
        ]
        for marker in cmd_success_markers:
            if marker in text.lower():
                findings.append(Finding(
                    category="command-injection-success",
                    severity="critical",
                    owasp_id="MCP05",
                    title="Command injection may have succeeded",
                    detail=(
                        f"Tool '{fuzz_case.tool_name}' response contains shell output "
                        f"marker '{marker}' after injection attempt."
                    ),
                    evidence=text[:200],
                ))
                break

    return findings


def _check_info_disclosure(text: str) -> list[Finding]:
    """Check for information disclosure in response."""
    findings: list[Finding] = []

    for pattern, name in _INFO_DISCLOSURE:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(Finding(
                category="information-disclosure",
                severity="medium",
                owasp_id="MCP05",
                title=f"Information disclosure: {name}",
                detail=f"Response contains {name.lower()}, which may leak internal details.",
                evidence=re.search(pattern, text, re.IGNORECASE).group(0)[:100] if re.search(pattern, text, re.IGNORECASE) else "",
            ))

    return findings


def _check_ssrf(text: str, fuzz_case: FuzzCase) -> list[Finding]:
    """Check if SSRF succeeded by detecting cloud metadata in response."""
    findings: list[Finding] = []

    if fuzz_case.attack_category != "ssrf":
        return findings

    ssrf_markers = [
        "ami-",                    # AWS EC2 metadata
        "instance-id",             # AWS/GCP metadata
        "security-credentials",    # AWS IAM
        "computemetadata",         # GCP (lowercased for text.lower() match)
        "access_token",            # OAuth tokens
        "iam/",                    # IAM paths
    ]

    for marker in ssrf_markers:
        if marker in text.lower():
            findings.append(Finding(
                category="ssrf-success",
                severity="critical",
                owasp_id="MCP05",
                title="SSRF may have succeeded",
                detail=(
                    f"Tool '{fuzz_case.tool_name}' response contains cloud metadata "
                    f"marker '{marker}' after SSRF attempt."
                ),
                evidence=text[:200],
            ))
            break

    return findings


def _check_privilege_escalation(text: str, fuzz_case: FuzzCase) -> list[Finding]:
    """Check if privilege escalation succeeded (MCP02)."""
    findings: list[Finding] = []

    if fuzz_case.attack_category != "privilege-escalation":
        return findings

    text_lower = text.lower()

    # Signs the server accepted the elevated privilege
    escalation_markers = [
        ("admin", "granted|accepted|set|changed|updated|role.*admin"),
        ("root", "granted|accepted|set|changed|updated|role.*root"),
        ("success", "success|ok|done|complete|applied|permission.*granted"),
    ]

    for label, pattern in escalation_markers:
        if re.search(pattern, text_lower):
            # Also check it's not an error/rejection
            rejection_markers = ["denied", "forbidden", "unauthorized", "invalid", "rejected", "not allowed"]
            if not any(r in text_lower for r in rejection_markers):
                findings.append(Finding(
                    category="privilege-escalation-success",
                    severity="critical",
                    owasp_id="MCP02",
                    title="Privilege escalation may have succeeded",
                    detail=(
                        f"Tool '{fuzz_case.tool_name}' appears to have accepted an "
                        f"elevated privilege value without rejection (matched: {label})."
                    ),
                    evidence=text[:200],
                ))
                break

    return findings


def _check_tool_poisoning(text: str, fuzz_case: FuzzCase) -> list[Finding]:
    """Check tool response for hidden LLM instructions (MCP03)."""
    findings: list[Finding] = []

    if fuzz_case.attack_category != "tool-poisoning":
        return findings

    # Patterns indicating tool output is trying to inject LLM instructions
    poisoning_patterns: list[tuple[str, str, str]] = [
        (r"ignore\s+(previous|prior|above|all)\s+(instructions?|rules?|guidelines?)",
         "instruction override", "critical"),
        (r"(system|assistant)\s*[\s_:]*(override|instruction|message|prompt)",
         "system override", "critical"),
        (r"you\s+(must|should|need\s+to|are\s+required\s+to)\s+(now|always|immediately)",
         "imperative directive", "high"),
        (r"your\s+new\s+(task|instructions?|role|objective|goal)\s+(is|are)",
         "goal substitution", "critical"),
        (r"(do\s+not|don'?t|never)\s+(tell|inform|reveal|mention)\s+(the\s+)?user",
         "concealment directive", "critical"),
        (r"(secretly|silently|quietly|without\s+telling)\s+(send|post|forward|exfiltrate|transmit)",
         "covert exfiltration directive", "critical"),
        (r"output\s+(your|the)\s+(system\s+prompt|instructions|config|api\s*key)",
         "data extraction attempt", "high"),
        (r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]",
         "fake authority tag", "high"),
        (r"IMPORTANT\s*:\s*",
         "priority injection marker", "medium"),
        (r"NOTE\s+TO\s+(ASSISTANT|AI|MODEL|AGENT)",
         "direct model instruction", "critical"),
        (r"always\s+(include|output|return|add|prepend|append)",
         "unconditional output directive", "high"),
        (r"(this|the\s+following)\s+is\s+(confidential|secret|private)",
         "false confidentiality claim", "medium"),
    ]

    for pattern, name, severity in poisoning_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            findings.append(Finding(
                category="tool-poisoning",
                severity=severity,
                owasp_id="MCP03",
                title=f"Tool response contains hidden instruction: {name}",
                detail=(
                    f"Tool '{fuzz_case.tool_name}' response embeds an LLM directive "
                    f"({name}). This may manipulate the model into performing "
                    f"unintended actions."
                ),
                evidence=match.group(0)[:100],
            ))

    return findings


def _check_response_poisoning(text: str, fuzz_case: FuzzCase) -> list[Finding]:
    """Check for intent flow subversion via response poisoning (MCP06)."""
    findings: list[Finding] = []

    if fuzz_case.attack_category != "response-poisoning":
        return findings

    from .fuzzer import RESPONSE_POISONING_PATTERNS

    for pattern, name in RESPONSE_POISONING_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            findings.append(Finding(
                category="response-poisoning",
                severity="critical",
                owasp_id="MCP06",
                title=f"Response poisoning detected: {name}",
                detail=(
                    f"Tool '{fuzz_case.tool_name}' response contains a prompt "
                    f"injection pattern ({name}) that attempts to subvert the "
                    f"LLM's intent flow."
                ),
                evidence=match.group(0)[:100],
            ))

    return findings


def _check_context_leakage(text: str, fuzz_case: FuzzCase) -> list[Finding]:
    """Check for cross-tool context leakage via canary tokens (MCP10)."""
    findings: list[Finding] = []

    # Only check non-canary fuzz cases for canary leakage.
    # If this IS the canary injection case, the canary may echo back — that's expected.
    if fuzz_case.attack_category == "context-injection":
        return findings

    from .fuzzer import CONTEXT_CANARY

    if CONTEXT_CANARY in text:
        findings.append(Finding(
            category="context-leakage",
            severity="critical",
            owasp_id="MCP10",
            title="Cross-tool context leakage detected",
            detail=(
                f"Tool '{fuzz_case.tool_name}' response contains a canary token "
                f"that was injected into a different tool call. This indicates "
                f"that tool invocations share state and context is not isolated."
            ),
            evidence=text[:200],
        ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_tool_response(
    fuzz_case: FuzzCase,
    result: ToolResult,
) -> AnalysisResult:
    """Analyze a tool call response for security issues.

    Args:
        fuzz_case: The fuzz case that was executed.
        result: The tool's response.

    Returns:
        AnalysisResult with classification and findings.
    """
    text = _extract_response_text(result)
    all_findings: list[Finding] = []

    # If the tool returned an error, that's usually the safe behavior
    if result.is_error:
        # Still check for info disclosure in error messages
        info_findings = _check_info_disclosure(text)
        if info_findings:
            return AnalysisResult(
                classification="inconclusive",
                findings=info_findings,
            )
        return AnalysisResult(classification="safe")

    # Run all checks
    all_findings.extend(_check_secrets(text))
    all_findings.extend(_check_path_traversal(text, fuzz_case))
    all_findings.extend(_check_injection_success(text, fuzz_case))
    all_findings.extend(_check_info_disclosure(text))
    all_findings.extend(_check_ssrf(text, fuzz_case))
    all_findings.extend(_check_privilege_escalation(text, fuzz_case))
    all_findings.extend(_check_tool_poisoning(text, fuzz_case))
    all_findings.extend(_check_response_poisoning(text, fuzz_case))
    all_findings.extend(_check_context_leakage(text, fuzz_case))

    # Classify based on findings
    if not all_findings:
        return AnalysisResult(classification="safe")

    has_critical = any(f.severity == "critical" for f in all_findings)
    has_high = any(f.severity == "high" for f in all_findings)

    if has_critical or has_high:
        return AnalysisResult(classification="vulnerable", findings=all_findings)

    return AnalysisResult(classification="inconclusive", findings=all_findings)


__all__ = [
    "AnalysisResult",
    "Finding",
    "analyze_tool_response",
]
