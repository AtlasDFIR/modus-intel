from __future__ import annotations

import logging
import os
from typing import ClassVar, Optional

import httpx

from modus_intel.core.models import ProviderResult
from modus_intel.providers.base import BaseProvider

log = logging.getLogger(__name__)


class GreyNoiseProvider(BaseProvider):
    name = "greynoise"
    env_var: ClassVar[str] = "GREYNOISE_API_KEY"
    api_url = "https://api.greynoise.io/v3/community"

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
            log.debug("GreyNoiseProvider: missing %s, skipping", self.env_var)
            return None

        url = f"{self.api_url}/{indicator}"
        headers = {"key": self.api_key}

        try:
            response = await client.get(url, headers=headers, timeout=10)
        except httpx.HTTPError as exc:
            log.warning("GreyNoise request failed for %s: %s", indicator, exc)
            return self._error_result(f"request failed: {exc.__class__.__name__}")

        # GreyNoise returns 404 for IPs it has not observed scanning the
        # internet. That is a meaningful answer (no data), not an error.
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status="no_data",
                score=0,
                confidence="low",
                evidence=["IP not observed by GreyNoise"],
            )

        if response.status_code == 401:
            log.warning(
                "GreyNoise rejected the API key (401). Check GREYNOISE_API_KEY."
            )
            return self._error_result(
                "authentication failed (401), check GREYNOISE_API_KEY"
            )

        if response.status_code == 429:
            log.warning("GreyNoise rate limit hit (429) for %s.", indicator)
            return self._error_result("rate limited (429)")

        if response.status_code != 200:
            log.warning(
                "GreyNoise returned unexpected status %s for %s",
                response.status_code,
                indicator,
            )
            return self._error_result(f"unexpected status {response.status_code}")

        try:
            data = response.json()
        except ValueError:
            log.warning("GreyNoise returned invalid JSON for %s", indicator)
            return self._error_result("invalid JSON response")

        noise = bool(data.get("noise", False))
        riot = bool(data.get("riot", False))
        classification = data.get("classification")
        name = data.get("name")
        link = data.get("link")
        last_seen = data.get("last_seen")
        message = data.get("message")

        score = 0
        confidence = "low"
        labels: list[str] = []
        evidence: list[str] = []
        links: list[str] = []

        if message:
            evidence.append(f"message={message}")

        if classification:
            labels.append(classification)
            evidence.append(f"classification={classification}")

        if name and name != "unknown":
            evidence.append(f"name={name}")

        if last_seen:
            evidence.append(f"last_seen={last_seen}")

        if noise:
            labels.append("internet_scanner")
            evidence.append("noise=true")
            score = max(score, 35)
            confidence = "medium"

        # RIOT (Rule It Out) marks known-benign business services (DNS
        # resolvers, CDNs, ...). It zeroes any noise-based score, but a
        # malicious classification below still wins.
        if riot:
            labels.append("riot")
            evidence.append("riot=true")
            score = 0
            confidence = "medium"

        if classification == "malicious":
            score = max(score, 75)
            confidence = "high"
        elif classification == "benign":
            score = min(score, 10)
            confidence = "medium"

        if link:
            links.append(link)

        labels = list(dict.fromkeys(labels))

        return ProviderResult(
            provider=self.name,
            status="ok",
            score=score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            links=links,
        )

    def _error_result(self, reason: str) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status="error",
            evidence=[reason],
        )
