import json

import httpx
import pytest

from modus_intel.providers.abuseipdb import AbuseIPDBProvider
from modus_intel.providers.base import BaseProvider
from modus_intel.providers.greynoise import GreyNoiseProvider
from modus_intel.providers.urlhaus import URLHausProvider
from modus_intel.providers.virustotal import VirusTotalProvider


def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def vt_provider() -> VirusTotalProvider:
    p = VirusTotalProvider()
    p.api_key = "test-key"
    return p


class TestRegistry:
    def test_all_providers_registered(self):
        assert VirusTotalProvider in BaseProvider.registry
        assert AbuseIPDBProvider in BaseProvider.registry
        assert URLHausProvider in BaseProvider.registry
        assert GreyNoiseProvider in BaseProvider.registry

    def test_registry_drives_instantiation(self):
        providers = [cls() for cls in BaseProvider.registry]
        names = {p.name for p in providers}
        assert {"virustotal", "abuseipdb", "urlhaus", "greynoise"} <= names


class TestVirusTotal:
    @pytest.mark.asyncio
    async def test_missing_key_skips(self):
        p = VirusTotalProvider()
        p.api_key = None
        async with mock_client(lambda r: httpx.Response(500)) as client:
            assert await p.lookup_async("8.8.8.8", "ip", client) is None

    @pytest.mark.asyncio
    async def test_detections_scored(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 8, "suspicious": 2}
                    }
                }
            }
            return httpx.Response(200, content=json.dumps(body))

        async with mock_client(handler) as client:
            result = await vt_provider().lookup_async("evil.com", "domain", client)

        assert result is not None
        assert result.status == "ok"
        assert result.score == 90  # 8*10 + 2*5
        assert result.confidence == "high"
        assert "malicious" in result.labels

    @pytest.mark.asyncio
    async def test_404_is_no_data_not_error(self):
        async with mock_client(lambda r: httpx.Response(404)) as client:
            result = await vt_provider().lookup_async(
                "unseen.example", "domain", client
            )

        assert result is not None
        assert result.status == "no_data"
        assert result.score == 0

    @pytest.mark.asyncio
    async def test_401_is_error(self):
        async with mock_client(lambda r: httpx.Response(401)) as client:
            result = await vt_provider().lookup_async("evil.com", "domain", client)

        assert result is not None
        assert result.status == "error"
        assert result.score is None

    @pytest.mark.asyncio
    async def test_429_is_error(self):
        async with mock_client(lambda r: httpx.Response(429)) as client:
            result = await vt_provider().lookup_async("evil.com", "domain", client)

        assert result is not None
        assert result.status == "error"

    @pytest.mark.asyncio
    async def test_network_failure_is_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        async with mock_client(handler) as client:
            result = await vt_provider().lookup_async("evil.com", "domain", client)

        assert result is not None
        assert result.status == "error"

    def test_url_endpoint_is_base64(self):
        endpoint = vt_provider()._endpoint("http://evil.com/a", "url")
        assert endpoint.startswith("urls/")
        assert "=" not in endpoint


class TestAbuseIPDB:
    def test_supports_only_ip(self):
        p = AbuseIPDBProvider()
        assert p.supports("ip")
        assert not p.supports("domain")
        assert not p.supports("url")

    @pytest.mark.asyncio
    async def test_score_and_evidence(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = {
                "data": {
                    "abuseConfidenceScore": 88,
                    "totalReports": 120,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                }
            }
            return httpx.Response(200, content=json.dumps(body))

        p = AbuseIPDBProvider()
        p.api_key = "test-key"
        async with mock_client(handler) as client:
            result = await p.lookup_async("45.155.205.233", "ip", client)

        assert result is not None
        assert result.status == "ok"
        assert result.score == 88
        assert result.confidence == "high"
        assert any("120" in e for e in result.evidence)

    @pytest.mark.asyncio
    async def test_429_is_error(self):
        p = AbuseIPDBProvider()
        p.api_key = "test-key"
        async with mock_client(lambda r: httpx.Response(429)) as client:
            result = await p.lookup_async("8.8.8.8", "ip", client)

        assert result is not None
        assert result.status == "error"


class TestURLHaus:
    def make(self) -> URLHausProvider:
        p = URLHausProvider()
        p.api_key = "test-key"
        return p

    @pytest.mark.asyncio
    async def test_known_malicious_url(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
                "host": "evil.com",
                "reporter": "someone",
                "tags": ["exe", "TA505"],
            }
            return httpx.Response(200, content=json.dumps(body))

        async with mock_client(handler) as client:
            result = await self.make().lookup_async(
                "http://evil.com/payload.exe", "url", client
            )

        assert result is not None
        assert result.status == "ok"
        assert result.score == 75
        assert result.confidence == "high"
        assert "malware_download" in result.labels

    @pytest.mark.asyncio
    async def test_no_results_is_no_data(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=json.dumps({"query_status": "no_results"})
            )

        async with mock_client(handler) as client:
            result = await self.make().lookup_async(
                "http://clean.example/", "url", client
            )

        assert result is not None
        assert result.status == "no_data"
        assert result.score == 0

    @pytest.mark.asyncio
    async def test_invalid_url_is_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=json.dumps({"query_status": "invalid_url"})
            )

        async with mock_client(handler) as client:
            result = await self.make().lookup_async("http://bad", "url", client)

        assert result is not None
        assert result.status == "error"


class TestGreyNoise:
    def make(self) -> GreyNoiseProvider:
        p = GreyNoiseProvider()
        p.api_key = "test-key"
        return p

    def test_supports_only_ip(self):
        p = GreyNoiseProvider()
        assert p.supports("ip")
        assert not p.supports("domain")
        assert not p.supports("url")

    @pytest.mark.asyncio
    async def test_missing_key_skips(self):
        p = GreyNoiseProvider()
        p.api_key = None
        async with mock_client(lambda r: httpx.Response(500)) as client:
            assert await p.lookup_async("8.8.8.8", "ip", client) is None

    @pytest.mark.asyncio
    async def test_malicious_classification(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = {
                "noise": True,
                "riot": False,
                "classification": "malicious",
                "name": "unknown",
                "link": "https://viz.greynoise.io/ip/45.155.205.233",
                "last_seen": "2026-08-20",
                "message": "Success",
            }
            return httpx.Response(200, content=json.dumps(body))

        async with mock_client(handler) as client:
            result = await self.make().lookup_async("45.155.205.233", "ip", client)

        assert result is not None
        assert result.status == "ok"
        assert result.score == 75
        assert result.confidence == "high"
        assert "malicious" in result.labels
        assert "internet_scanner" in result.labels

    @pytest.mark.asyncio
    async def test_riot_zeroes_noise_score(self):
        # A known-benign business service (RIOT) must not score as a
        # scanner even when noise is also set.
        def handler(request: httpx.Request) -> httpx.Response:
            body = {
                "noise": True,
                "riot": True,
                "classification": "benign",
                "name": "Google Public DNS",
                "message": "Success",
            }
            return httpx.Response(200, content=json.dumps(body))

        async with mock_client(handler) as client:
            result = await self.make().lookup_async("8.8.8.8", "ip", client)

        assert result is not None
        assert result.status == "ok"
        assert result.score == 0
        assert "riot" in result.labels

    @pytest.mark.asyncio
    async def test_plain_scanner_scores_35(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = {"noise": True, "riot": False, "message": "Success"}
            return httpx.Response(200, content=json.dumps(body))

        async with mock_client(handler) as client:
            result = await self.make().lookup_async("1.2.3.4", "ip", client)

        assert result is not None
        assert result.score == 35
        assert result.confidence == "medium"

    @pytest.mark.asyncio
    async def test_404_is_no_data(self):
        async with mock_client(lambda r: httpx.Response(404)) as client:
            result = await self.make().lookup_async("10.0.0.1", "ip", client)

        assert result is not None
        assert result.status == "no_data"
        assert result.score == 0

    @pytest.mark.asyncio
    async def test_429_is_error(self):
        async with mock_client(lambda r: httpx.Response(429)) as client:
            result = await self.make().lookup_async("1.2.3.4", "ip", client)

        assert result is not None
        assert result.status == "error"
