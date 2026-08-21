from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

from modus_intel.core.models import IndicatorType

_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")

# Practical domain regex
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Common defanging conventions used when sharing IOCs
# (hxxp://evil[.]com, 1.2.3[.]4, evil[at]example.com, ...)
_REFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^hxxps", re.IGNORECASE), "https"),
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
]


def clean_ioc(value: str) -> str:
    """Strip whitespace and surrounding quotes from a raw indicator."""
    return value.strip().strip('"').strip("'").strip()


def refang(value: str) -> str:
    """
    Convert a defanged indicator back to its real form so it can be
    classified and looked up: hxxp://evil[.]com -> http://evil.com
    """
    v = value
    for pattern, replacement in _REFANG_PATTERNS:
        v = pattern.sub(replacement, v)
    return v


def detect_ioc_type(value: str) -> IndicatorType:
    v = value.strip()

    # URL
    parsed = urlparse(v)
    if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
        return "url"

    # IP
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    # Hash
    hv = v.lower()
    if _HASH_RE.match(hv):
        if len(hv) == 32:
            return "md5"
        if len(hv) == 40:
            return "sha1"
        if len(hv) == 64:
            return "sha256"

    # Domain
    dv = v.lower().strip(".")
    if _DOMAIN_RE.match(dv):
        return "domain"

    return "unknown"


def normalize_ioc(value: str, ioc_type: IndicatorType) -> str:
    v = value.strip()

    if ioc_type in ("domain", "md5", "sha1", "sha256"):
        return v.lower().strip(".")

    if ioc_type == "url":
        # Lowercase the scheme and host so equivalent URLs share cache
        # entries; path and query stay untouched (they can be case-sensitive).
        parsed = urlparse(v)
        return urlunparse(
            parsed._replace(
                scheme=parsed.scheme.lower(),
                netloc=parsed.netloc.lower(),
            )
        )

    return v


def prepare_ioc(raw: str) -> tuple[str, IndicatorType]:
    """
    Full input pipeline for a raw indicator: clean, refang, classify,
    normalize. Returns (normalized_value, ioc_type).
    """
    cleaned = refang(clean_ioc(raw))
    ioc_type = detect_ioc_type(cleaned)
    return normalize_ioc(cleaned, ioc_type), ioc_type
