from __future__ import annotations

import os
from typing import Optional

import logging
log = logging.getLogger(__name__)

import base64

import httpx
from dotenv import load_dotenv

from modus_intel.core.models import ProviderResult
from modus_intel.providers.base import BaseProvider

load_dotenv()


class VirusTotalProvider(BaseProvider):
    name = "virustotal"

    def __init__(self) -> None:
        self.api_key = os.getenv("VT_API_KEY")

    def supports(self, indicator_type: str) -> bool:
        return indicator_type in {"ip", "domain", "url", "md5", "sha1", "sha256", "hash"}

    async def lookup_async(self, indicator: str, indicator_type: str, client: httpx.AsyncClient) -> Optional[ProviderResult]:
        if not self.api_key:
            return None

        endpoint = self._endpoint(indicator, indicator_type)
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        headers = {"x-apikey": self.api_key}

        try:
            r = await client.get(url, headers=headers)
            r.raise_for_status()

            data = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))

            raw_score = malicious * 10 + suspicious * 5
            score = min(100, raw_score)

            return ProviderResult(
                provider=self.name,
                score=score,
                confidence="high" if malicious > 5 else "medium" if malicious > 0 else "low",
                labels=["malicious"] if malicious > 0 else [],
                evidence=[f"malicious={malicious}, suspicious={suspicious}, raw_score={raw_score}"],
                links=[f"https://www.virustotal.com/gui/search/{indicator}"],
            )
        except Exception:
            return None

    def _endpoint(self, indicator: str, indicator_type: str) -> str:
        if indicator_type == "ip":
            return f"ip_addresses/{indicator}"

        if indicator_type == "domain":
            return f"domains/{indicator}"

        if indicator_type == "url":
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return f"urls/{url_id}"

        if indicator_type in {"md5", "sha1", "sha256", "hash"}:
            return f"files/{indicator}"

        raise ValueError(f"Unsupported indicator type: {indicator_type}")
