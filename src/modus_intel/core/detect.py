from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from modus_intel.core.models import IndicatorType


_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")

# Practical domain regex: good enough for OSINT tooling without being overly strict.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def detect_ioc_type(value: str) -> IndicatorType:
    v = value.strip()

    # URL
    parsed = urlparse(v)
    if parsed.scheme and parsed.netloc:
        return "url"

    # IP
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    # Hash
    hv = v.lower()
    if _HASH_RE.match(hv) and len(hv) in (32, 40, 64):
        return "hash"

    # Domain
    dv = v.lower().strip(".")
    if _DOMAIN_RE.match(dv):
        return "domain"

    return "unknown"


def normalize_ioc(value: str, ioc_type: IndicatorType) -> str:
    v = value.strip().strip('"').strip("'")

    if ioc_type in ("domain", "hash"):
        return v.lower().strip(".")
    if ioc_type == "url":
        return v.strip()
    if ioc_type == "ip":
        return v
    return v
