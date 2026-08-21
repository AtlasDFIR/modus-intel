from __future__ import annotations

import base64
import logging
import os
from typing import ClassVar, Optional

import httpx

from modus_intel.core.models import ProviderResult
from modus_intel.providers.base import BaseProvider

log = logging.getLogger(__name__)


class VirusTotalProvider(BaseProvider):
    name = "virustotal"
    env_var: ClassVar[str] = "VT_API_KEY"

    def __init__(self) -> None:
        self.api_key = os.getenv(self.env_var)

    def supports(self, indicator_type: str) -> bool:
        return indicator_type in {"ip", "domain", "url", "md5", "sha1", "sha256"}

    async def lookup_async(
        self,
        indicator: str,
        indicator_type: str,
        client: httpx.AsyncClient,
    ) -> Optional[ProviderResult]:
        if not self.api_key:
            log.debug("VirusTotalProvider: missing %s, skipping", self.env_var)
            return None

        endpoint = self._endpoint(indicator, indicator_type)
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        headers = {"x-apikey": self.api_key}

        try:
            r = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            log.warning("VirusTotal request failed for %s: %s", indicator, exc)
            return self._error_result(f"request failed: {exc.__class__.__name__}")

        # VirusTotal returns 404 for indicators it has never analyzed. That is
        # a meaningful answer (no data), not an error.
        if r.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status="no_data",
                score=0,
                confidence="low",
                evidence=["indicator not found in VirusTotal"],
                links=[f"https://www.virustotal.com/gui/search/{indicator}"],
            )

        if r.status_code == 401:
            log.warning("VirusTotal rejected the API key (401). Check VT_API_KEY.")
            return self._error_result("authentication failed (401), check VT_API_KEY")

        if r.status_code == 429:
            log.warning(
                "VirusTotal rate limit hit (429) for %s. The free tier allows "
                "4 requests/minute; lower --concurrency or retry later.",
                indicator,
            )
            return self._error_result("rate limited (429)")

        try:
            r.raise_for_status()
            data = r.json()["data"]["attributes"]
        except (httpx.HTTPStatusError, KeyError, ValueError) as exc:
            log.warning(
                "VirusTotal returned an unexpected response for %s: %s", indicator, exc
            )
            return self._error_result(f"unexpected response: {exc.__class__.__name__}")

        stats = data.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        raw_score = malicious * 10 + suspicious * 5
        score = min(100, raw_score)

        return ProviderResult(
            provider=self.name,
            status="ok",
            score=score,
            confidence=(
                "high" if malicious > 5 else "medium" if malicious > 0 else "low"
            ),
            labels=["malicious"] if malicious > 0 else [],
            evidence=[
                f"malicious={malicious}, suspicious={suspicious}, raw_score={raw_score}"
            ],
            links=[f"https://www.virustotal.com/gui/search/{indicator}"],
        )

    def _error_result(self, reason: str) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status="error",
            evidence=[reason],
        )

    def _endpoint(self, indicator: str, indicator_type: str) -> str:
        if indicator_type == "ip":
            return f"ip_addresses/{indicator}"

        if indicator_type == "domain":
            return f"domains/{indicator}"

        if indicator_type == "url":
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return f"urls/{url_id}"

        if indicator_type in {"md5", "sha1", "sha256"}:
            return f"files/{indicator}"

        raise ValueError(f"Unsupported indicator type: {indicator_type}")
