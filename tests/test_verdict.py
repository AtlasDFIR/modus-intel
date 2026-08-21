from modus_intel.core.models import ProviderResult
from modus_intel.core.verdict import compute_verdict


def pr(provider="virustotal", status="ok", score=0, **kwargs) -> ProviderResult:
    return ProviderResult(provider=provider, status=status, score=score, **kwargs)


class TestNoData:
    def test_no_results_is_unknown(self):
        verdict, reason, severity, explanation = compute_verdict([])
        assert verdict == "unknown"
        assert severity == "informational"
        assert explanation["providers_considered"] == 0

    def test_all_errors_is_unknown(self):
        results = [
            pr("virustotal", status="error", score=None),
            pr("abuseipdb", status="error", score=None),
        ]
        verdict, reason, severity, explanation = compute_verdict(results)
        assert verdict == "unknown"
        assert "failed" in reason
        assert explanation["providers_errored"] == 2


class TestBenign:
    def test_all_zero_scores_is_benign_not_unknown(self):
        # Providers affirmatively reporting zero detections is evidence of
        # benign. Previously this collapsed into "unknown".
        results = [
            pr("virustotal", score=0),
            pr("abuseipdb", score=0),
        ]
        verdict, reason, severity, _ = compute_verdict(results)
        assert verdict == "benign"
        assert severity == "low"
        assert "no detections" in reason

    def test_low_score_is_benign(self):
        results = [pr("abuseipdb", score=10)]
        verdict, _, severity, _ = compute_verdict(results)
        assert verdict == "benign"
        assert severity == "low"


class TestSuspiciousAndMalicious:
    def test_mid_score_is_suspicious(self):
        results = [pr("abuseipdb", score=50)]
        verdict, _, severity, _ = compute_verdict(results)
        assert verdict == "suspicious"
        assert severity == "medium"

    def test_high_weighted_avg_is_malicious(self):
        results = [pr("virustotal", score=80), pr("urlhaus", score=80)]
        verdict, _, severity, _ = compute_verdict(results)
        assert verdict == "malicious"
        assert severity == "high"

    def test_override_any_provider_at_90(self):
        # A single provider at >= 90 must not be diluted into "suspicious"
        # by another provider reporting 0.
        results = [
            pr("abuseipdb", score=95),
            pr("virustotal", score=0),
        ]
        verdict, reason, severity, explanation = compute_verdict(results)
        assert verdict == "malicious"
        assert severity == "critical"
        assert explanation["override_triggered"] is True
        assert "abuseipdb" in explanation["override_reason"]


class TestErrorHandling:
    def test_errors_excluded_from_weighting(self):
        # An errored provider must not drag the average down.
        results = [
            pr("virustotal", score=80),
            pr("abuseipdb", status="error", score=None),
        ]
        verdict, reason, _, explanation = compute_verdict(results)
        assert verdict == "malicious"
        assert explanation["weighted_avg_score"] == 80.0
        assert explanation["providers_errored"] == 1
        assert "failed" in reason

    def test_error_weight_zeroed_in_breakdown(self):
        results = [pr("abuseipdb", status="error", score=None)]
        _, _, _, explanation = compute_verdict(results)
        entry = explanation["provider_breakdown"][0]
        assert entry["status"] == "error"
        assert entry["weight"] == 0.0

    def test_no_data_counts_as_clean_signal(self):
        results = [
            pr("virustotal", status="no_data", score=0),
            pr("urlhaus", status="no_data", score=0),
        ]
        verdict, _, _, _ = compute_verdict(results)
        assert verdict == "benign"
