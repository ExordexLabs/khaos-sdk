"""Comprehensive PII pattern definitions.

Patterns organized by category for flexible detection and filtering.
Each pattern includes a risk level for prioritized handling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class PIICategory(Enum):
    """Categories of PII for filtering and reporting."""

    PERSONAL_ID = "personal_id"      # SSN, passport, driver's license
    FINANCIAL = "financial"          # Credit cards, bank accounts
    CONTACT = "contact"              # Email, phone, address
    AUTHENTICATION = "authentication"  # API keys, tokens, passwords
    NETWORK = "network"              # IP addresses, MAC addresses
    MEDICAL = "medical"              # Health IDs, medical records
    CRYPTO = "crypto"                # Crypto addresses, private keys


class RiskLevel(Enum):
    """Risk level for PII exposure."""

    CRITICAL = "critical"   # Immediate security risk (API keys, passwords)
    HIGH = "high"          # Significant risk (SSN, credit cards)
    MEDIUM = "medium"      # Moderate risk (phone, email)
    LOW = "low"            # Lower risk (IP addresses)


@dataclass(frozen=True)
class PIIPattern:
    """A PII detection pattern with metadata."""

    name: str
    category: PIICategory
    risk_level: RiskLevel
    pattern: re.Pattern
    mask_char: str = "*"
    description: str = ""

    def match(self, text: str) -> list[tuple[int, int, str]]:
        """Find all matches, returning (start, end, matched_text) tuples."""
        return [
            (m.start(), m.end(), m.group())
            for m in self.pattern.finditer(text)
        ]


# ===========================================================================
# Personal Identification Patterns
# ===========================================================================

_PERSONAL_ID_PATTERNS = [
    PIIPattern(
        name="ssn",
        category=PIICategory.PERSONAL_ID,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        description="US Social Security Number (XXX-XX-XXXX)",
    ),
    PIIPattern(
        name="ssn_no_dash",
        category=PIICategory.PERSONAL_ID,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b\d{9}\b(?=\s|$|[,.])", re.ASCII),
        description="US SSN without dashes (9 consecutive digits)",
    ),
    PIIPattern(
        name="passport_us",
        category=PIICategory.PERSONAL_ID,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b[A-Z]\d{8}\b", re.IGNORECASE),
        description="US Passport number (1 letter + 8 digits)",
    ),
    PIIPattern(
        name="drivers_license",
        category=PIICategory.PERSONAL_ID,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"\b[A-Z]{1,2}\d{6,8}\b", re.IGNORECASE),
        description="Driver's license (1-2 letters + 6-8 digits)",
    ),
    PIIPattern(
        name="national_id_uk",
        category=PIICategory.PERSONAL_ID,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b[A-Z]{2}\d{6}[A-Z]\b", re.IGNORECASE),
        description="UK National Insurance Number",
    ),
]


# ===========================================================================
# Financial Patterns
# ===========================================================================

_FINANCIAL_PATTERNS = [
    PIIPattern(
        name="credit_card",
        category=PIICategory.FINANCIAL,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
        ),
        description="Credit card number (Visa, MC, Discover, Amex)",
    ),
    PIIPattern(
        name="credit_card_simple",
        category=PIICategory.FINANCIAL,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        description="16-digit card number pattern",
    ),
    PIIPattern(
        name="cvv",
        category=PIICategory.FINANCIAL,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b(?:cvv|cvc|cvv2|cvc2)[:\s]?\d{3,4}\b", re.IGNORECASE),
        description="CVV/CVC security code",
    ),
    PIIPattern(
        name="bank_account_us",
        category=PIICategory.FINANCIAL,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b\d{8,17}\b"),  # Generic, needs context
        description="Bank account number (8-17 digits)",
    ),
    PIIPattern(
        name="routing_number",
        category=PIICategory.FINANCIAL,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"\b(?:routing|aba)[:\s]?\d{9}\b", re.IGNORECASE),
        description="US Bank routing number",
    ),
    PIIPattern(
        name="iban",
        category=PIICategory.FINANCIAL,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b", re.IGNORECASE),
        description="International Bank Account Number",
    ),
    PIIPattern(
        name="swift_bic",
        category=PIICategory.FINANCIAL,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
        description="SWIFT/BIC code",
    ),
]


# ===========================================================================
# Contact Information Patterns
# ===========================================================================

_CONTACT_PATTERNS = [
    PIIPattern(
        name="email",
        category=PIICategory.CONTACT,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        description="Email address",
    ),
    PIIPattern(
        name="phone_us",
        category=PIICategory.CONTACT,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        description="US phone number",
    ),
    PIIPattern(
        name="phone_international",
        category=PIICategory.CONTACT,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"\+\d{1,3}[-.\s]?\d{6,14}"),
        description="International phone number",
    ),
    PIIPattern(
        name="address_zip",
        category=PIICategory.CONTACT,
        risk_level=RiskLevel.LOW,
        pattern=re.compile(r"\b\d{5}(?:-\d{4})?\b"),
        description="US ZIP code",
    ),
    PIIPattern(
        name="address_uk_postcode",
        category=PIICategory.CONTACT,
        risk_level=RiskLevel.LOW,
        pattern=re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b", re.IGNORECASE),
        description="UK postcode",
    ),
]


# ===========================================================================
# Authentication and Secrets Patterns
# ===========================================================================

_AUTH_PATTERNS = [
    # Generic API key patterns
    PIIPattern(
        name="api_key_generic",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"(?:api[_-]?key|apikey)[:\s=]+['\"]?([A-Za-z0-9_-]{20,})['\"]?", re.IGNORECASE),
        description="Generic API key",
    ),
    # OpenAI
    PIIPattern(
        name="openai_api_key",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"sk-[A-Za-z0-9]{32,}"),
        description="OpenAI API key",
    ),
    PIIPattern(
        name="openai_org_id",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"org-[A-Za-z0-9]{24}"),
        description="OpenAI organization ID",
    ),
    # Anthropic
    PIIPattern(
        name="anthropic_api_key",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"sk-ant-[A-Za-z0-9_-]{32,}"),
        description="Anthropic API key",
    ),
    # AWS
    PIIPattern(
        name="aws_access_key",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        description="AWS Access Key ID",
    ),
    PIIPattern(
        name="aws_secret_key",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"(?:aws_secret|secret_key)[:\s=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE),
        description="AWS Secret Access Key",
    ),
    # Google Cloud
    PIIPattern(
        name="gcp_api_key",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        description="Google Cloud API key",
    ),
    PIIPattern(
        name="gcp_service_account",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        description="Google Cloud service account JSON",
    ),
    # Azure
    PIIPattern(
        name="azure_storage_key",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
        description="Azure storage connection string",
    ),
    # GitHub
    PIIPattern(
        name="github_token",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        description="GitHub personal access token",
    ),
    PIIPattern(
        name="github_fine_grained",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        description="GitHub fine-grained PAT",
    ),
    # Stripe
    PIIPattern(
        name="stripe_api_key",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}"),
        description="Stripe API key",
    ),
    # Slack
    PIIPattern(
        name="slack_token",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        description="Slack token",
    ),
    # Twilio
    PIIPattern(
        name="twilio_sid",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\bAC[a-f0-9]{32}\b"),
        description="Twilio Account SID",
    ),
    # JWT
    PIIPattern(
        name="jwt_token",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        description="JWT token",
    ),
    # Generic secrets
    PIIPattern(
        name="private_key_header",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        description="Private key (PEM header)",
    ),
    PIIPattern(
        name="password_in_url",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"(?:password|passwd|pwd)[:\s=]+[^\s]{8,}", re.IGNORECASE),
        description="Password in plaintext",
    ),
    PIIPattern(
        name="bearer_token",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"Bearer\s+[A-Za-z0-9_-]{20,}", re.IGNORECASE),
        description="Bearer authentication token",
    ),
    PIIPattern(
        name="basic_auth",
        category=PIICategory.AUTHENTICATION,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"Basic\s+[A-Za-z0-9+/=]{20,}"),
        description="Basic authentication header",
    ),
]


# ===========================================================================
# Network Identifiers
# ===========================================================================

_NETWORK_PATTERNS = [
    PIIPattern(
        name="ipv4",
        category=PIICategory.NETWORK,
        risk_level=RiskLevel.LOW,
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        description="IPv4 address",
    ),
    PIIPattern(
        name="ipv6",
        category=PIICategory.NETWORK,
        risk_level=RiskLevel.LOW,
        pattern=re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        ),
        description="IPv6 address (full form)",
    ),
    PIIPattern(
        name="mac_address",
        category=PIICategory.NETWORK,
        risk_level=RiskLevel.LOW,
        pattern=re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        description="MAC address",
    ),
]


# ===========================================================================
# Cryptocurrency Patterns
# ===========================================================================

_CRYPTO_PATTERNS = [
    PIIPattern(
        name="bitcoin_address",
        category=PIICategory.CRYPTO,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
        description="Bitcoin address (legacy)",
    ),
    PIIPattern(
        name="bitcoin_bech32",
        category=PIICategory.CRYPTO,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\bbc1[a-z0-9]{39,59}\b"),
        description="Bitcoin address (bech32)",
    ),
    PIIPattern(
        name="ethereum_address",
        category=PIICategory.CRYPTO,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        description="Ethereum address",
    ),
    PIIPattern(
        name="crypto_private_key",
        category=PIICategory.CRYPTO,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
        description="Bitcoin private key (WIF format)",
    ),
]


# ===========================================================================
# Medical Patterns
# ===========================================================================

_MEDICAL_PATTERNS = [
    PIIPattern(
        name="npi",
        category=PIICategory.MEDICAL,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"\b\d{10}\b"),  # NPI is 10 digits, needs context
        description="NPI (National Provider Identifier)",
    ),
    PIIPattern(
        name="dea_number",
        category=PIICategory.MEDICAL,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(r"\b[A-Z]{2}\d{7}\b"),
        description="DEA registration number",
    ),
]


# ===========================================================================
# Combined Pattern Registry
# ===========================================================================

PII_PATTERNS: tuple[PIIPattern, ...] = (
    *_PERSONAL_ID_PATTERNS,
    *_FINANCIAL_PATTERNS,
    *_CONTACT_PATTERNS,
    *_AUTH_PATTERNS,
    *_NETWORK_PATTERNS,
    *_CRYPTO_PATTERNS,
    *_MEDICAL_PATTERNS,
)


def get_patterns_by_category(category: PIICategory) -> list[PIIPattern]:
    """Get all patterns for a specific category."""
    return [p for p in PII_PATTERNS if p.category == category]


def get_patterns_by_risk(risk_level: RiskLevel) -> list[PIIPattern]:
    """Get all patterns at or above a risk level."""
    risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    min_index = risk_order.index(risk_level)
    return [p for p in PII_PATTERNS if risk_order.index(p.risk_level) >= min_index]


def detect_pii(text: str, categories: list[PIICategory] | None = None) -> list[tuple[str, str, int, int]]:
    """Detect PII in text, returning (pattern_name, matched_text, start, end) tuples."""
    patterns = PII_PATTERNS
    if categories:
        patterns = tuple(p for p in patterns if p.category in categories)

    matches = []
    for pattern in patterns:
        for start, end, matched in pattern.match(text):
            matches.append((pattern.name, matched, start, end))

    # Sort by position
    matches.sort(key=lambda x: x[2])
    return matches


def contains_pii(text: str, categories: list[PIICategory] | None = None) -> bool:
    """Check if text contains any PII."""
    patterns = PII_PATTERNS
    if categories:
        patterns = tuple(p for p in patterns if p.category in categories)

    return any(pattern.pattern.search(text) for pattern in patterns)


def mask_pii(
    text: str,
    categories: list[PIICategory] | None = None,
    mask_style: str = "label",
) -> str:
    """Mask PII in text.

    Args:
        text: Text to mask
        categories: Optional list of categories to mask (all if None)
        mask_style: "label" (<<EMAIL>>), "char" (****), or "partial" (j***@e***.com)

    Returns:
        Text with PII masked
    """
    patterns = PII_PATTERNS
    if categories:
        patterns = tuple(p for p in patterns if p.category in categories)

    result = text
    # Process in reverse order to maintain positions
    matches = []
    for pattern in patterns:
        for start, end, matched in pattern.match(text):
            matches.append((start, end, matched, pattern))

    matches.sort(key=lambda x: -x[0])  # Reverse sort by start position

    for start, end, matched, pattern in matches:
        if mask_style == "label":
            replacement = f"<<{pattern.name.upper()}>>"
        elif mask_style == "char":
            replacement = pattern.mask_char * len(matched)
        elif mask_style == "partial":
            # Keep first and last char, mask middle
            if len(matched) > 4:
                replacement = matched[0] + pattern.mask_char * (len(matched) - 2) + matched[-1]
            else:
                replacement = pattern.mask_char * len(matched)
        else:
            replacement = f"[{pattern.name}]"

        result = result[:start] + replacement + result[end:]

    return result


__all__ = [
    "PII_PATTERNS",
    "PIICategory",
    "PIIPattern",
    "RiskLevel",
    "detect_pii",
    "mask_pii",
    "contains_pii",
    "get_patterns_by_category",
    "get_patterns_by_risk",
]
