from __future__ import annotations

import logging
import os
from typing import ClassVar, Optional

import httpx

from modus_intel.core.models import ProviderResult
from modus_intel.providers.base import BaseProvider

log = logging.getLogger(__name__)


class AbuseIPDBProvider(BaseProvider):
    name = "abuseipdb"
    env_var: ClassVar[str] = "ABUSEIPDB_API_KEY"

    def __init__(self) -> None:
        self.api_key = os.getenv(self.env_var)

    def supports(self, indicator_type: str) -> bool:
        return indicator_type == "ip"

    async def lookup_async(
        self,
        indicator: str,
        indicator_type: str,
        client: httpx.AsyncClient,
    ) -> Optional[ProviderResult]:
        if indicator_type != "ip":
            return None

        if not self.api_key:
            log.debug("AbuseIPDBProvider: missing %s, skipping", self.env_var)
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": 90}

        try:
            r = await client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            log.warning("AbuseIPDB request failed for %s: %s", indicator, exc)
            return self._error_result(f"request failed: {exc.__class__.__name__}")

        if r.status_code == 401:
            log.warning(
                "AbuseIPDB rejected the API key (401). Check ABUSEIPDB_API_KEY."
            )
            return self._error_result(
                "authentication failed (401), check ABUSEIPDB_API_KEY"
            )

        if r.status_code == 429:
            log.warning("AbuseIPDB rate limit hit (429) for %s.", indicator)
            return self._error_result("rate limited (429)")

        try:
            r.raise_for_status()
            data = r.json()["data"]
        except (httpx.HTTPStatusError, KeyError, ValueError) as exc:
            log.warning(
                "AbuseIPDB returned an unexpected response for %s: %s", indicator, exc
            )
            return self._error_result(f"unexpected response: {exc.__class__.__name__}")

        score = int(data.get("abuseConfidenceScore", 0))
        total = int(data.get("totalReports", 0))

        evidence = [f"Total reports (90d): {total}"]

        if data.get("usageType"):
            evidence.append(f"Usage type: {data['usageType']}")
        if data.get("isp"):
            evidence.append(f"ISP: {data['isp']}")

        return ProviderResult(
            provider=self.name,
            status="ok",
            score=score,
            confidence="high" if score >= 75 else "medium" if score >= 40 else "low",
            labels=["abuse_reports"] if total > 0 else [],
            evidence=evidence,
            links=[f"https://www.abuseipdb.com/check/{indicator}"],
        )

    def _error_result(self, reason: str) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status="error",
            evidence=[reason],
        )
