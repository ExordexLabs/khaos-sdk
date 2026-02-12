"""PII detection and handling utilities.

Provides comprehensive PII pattern detection for:
- Personal identifiers (SSN, passport, driver's license)
- Financial data (credit cards, bank accounts, crypto)
- Contact information (email, phone, address)
- Authentication secrets (API keys, tokens, passwords)
- Network identifiers (IP addresses, MAC addresses)
"""

from .patterns import (
    PII_PATTERNS,
    PIICategory,
    PIIPattern,
    detect_pii,
    mask_pii,
    contains_pii,
    get_patterns_by_category,
)
from .detector import PIIDetector, PIIMatch, PIIScanResult

__all__ = [
    "PII_PATTERNS",
    "PIICategory",
    "PIIPattern",
    "PIIDetector",
    "PIIMatch",
    "PIIScanResult",
    "detect_pii",
    "mask_pii",
    "contains_pii",
    "get_patterns_by_category",
]
