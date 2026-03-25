from __future__ import annotations

import os
import logging
from typing import Optional

import httpx

from modus_intel.core.models import ProviderResult
from modus_intel.providers.base import BaseProvider

log = logging.getLogger(__name__)


class URLHausProvider(BaseProvider):
    name = "urlhaus"
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self) -> None:
        self.api_key = os.getenv("URLHAUS_AUTH_KEY")

    def supports(self, indicator_type: str) -> bool:
        # This endpoint is for URL lookups, not raw domain lookups.
        return indicator_type == "url"

    async def lookup_async(
        self,
        indicator: str,
        indicator_type: str,
        client: httpx.AsyncClient,
    ) -> Optional[ProviderResult]:
        if indicator_type != "url":
            return None

        if not self.api_key:
            log.debug("URLHausProvider: missing URLHAUS_AUTH_KEY")
            return None

        headers = {"Auth-Key": self.api_key}
        payload = {"url": indicator}

        try:
            response = await client.post(
                self.api_url,
                data=payload,
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("URLHausProvider request failed for %s: %s", indicator, exc)
            return None

        try:
            data = response.json()
        except ValueError:
            log.warning("URLHausProvider returned invalid JSON for %s", indicator)
            return None

        query_status = data.get("query_status")
        if query_status != "ok":
            return ProviderResult(
                provider=self.name,
                score=0,
                confidence="low",
                labels=[],
                evidence=[f"query_status={query_status}"],
                links=[],
            )

        score = 0
        confidence = "low"
        labels: list[str] = []
        evidence: list[str] = []
        links: list[str] = []

        url_status = data.get("url_status")
        threat = data.get("threat")
        reference = data.get("urlhaus_reference")
        host = data.get("host")
        reporter = data.get("reporter")
        tags = data.get("tags") or []

        if url_status:
            evidence.append(f"url_status={url_status}")

        if host:
            evidence.append(f"host={host}")

        if reporter:
            evidence.append(f"reporter={reporter}")

        if url_status == "online":
            score = max(score, 60)
            confidence = "medium"
            labels.append("online_malicious_url")

        if threat:
            labels.append(threat)
            evidence.append(f"threat={threat}")
            score = max(score, 75)
            confidence = "high"

        if tags:
            labels.extend(str(tag) for tag in tags if tag)
            evidence.append(f"tags={','.join(str(tag) for tag in tags if tag)}")

        if reference:
            links.append(reference)

        # Deduplicate while preserving order
        labels = list(dict.fromkeys(labels))

        return ProviderResult(
            provider=self.name,
            score=score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            links=links,
        )