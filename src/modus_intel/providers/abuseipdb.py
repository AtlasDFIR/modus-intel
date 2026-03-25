from __future__ import annotations

import logging
import os
from typing import Optional

import httpx
from dotenv import load_dotenv

from modus_intel.core.models import ProviderResult
from modus_intel.providers.base import BaseProvider

log = logging.getLogger(__name__)
load_dotenv()


class AbuseIPDBProvider(BaseProvider):
    name = "abuseipdb"

    def __init__(self) -> None:
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

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
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": 90}

        try:
            r = await client.get(url, headers=headers, params=params)
            r.raise_for_status()
            data = r.json()["data"]

            score = int(data.get("abuseConfidenceScore", 0))
            total = int(data.get("totalReports", 0))

            evidence = [f"Total reports (90d): {total}"]

            if data.get("usageType"):
                evidence.append(f"Usage type: {data['usageType']}")
            if data.get("isp"):
                evidence.append(f"ISP: {data['isp']}")

            return ProviderResult(
                provider=self.name,
                score=score,
                confidence="high" if score >= 75 else "medium" if score >= 40 else "low",
                labels=["abuse_reports"] if total > 0 else [],
                evidence=evidence,
                links=[f"https://www.abuseipdb.com/check/{indicator}"],
            )
        except Exception as exc:
            log.debug("AbuseIPDB lookup failed for %s: %s", indicator, exc)
            return None