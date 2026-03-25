from __future__ import annotations

from typing import Any

from modus_intel.core.models import ProviderResult, Verdict, Severity


# Provider trust weights (tuneable)
PROVIDER_WEIGHTS = {
    "virustotal": 1.5,
    "abuseipdb": 1.0,
    "urlhaus": 1.2,
}


def compute_verdict(
    results: list[ProviderResult],
) -> tuple[Verdict, str, Severity, dict[str, Any]]:
    """
    Returns:
        verdict: malicious | suspicious | benign | unknown
        reason: short summary string
        severity: informational | low | medium | high | critical
        explanation: structured breakdown of decision logic
    """

    if not results:
        return (
            "unknown",
            "no provider results",
            "informational",
            {
                "providers_considered": 0,
                "override_triggered": False,
                "provider_breakdown": [],
            },
        )

    weighted_sum = 0.0
    weight_sum = 0.0
    max_score = 0
    max_provider = None

    breakdown = []

    for r in results:
        weight = PROVIDER_WEIGHTS.get(r.provider, 1.0)
        score = r.score if r.score is not None else 0
        weighted = score * weight

        weighted_sum += weighted
        weight_sum += weight

        if score > max_score:
            max_score = score
            max_provider = r.provider

        breakdown.append(
            {
                "provider": r.provider,
                "score": score,
                "weight": weight,
                "weighted_score": round(weighted, 2),
                "confidence": r.confidence,
                "labels": r.labels,
            }
        )

    weighted_avg = round(weighted_sum / weight_sum, 2) if weight_sum else 0.0

    # -----------------------------
    # Override logic (hard rules)
    # -----------------------------
    override_triggered = False
    override_reason = None

    for r in results:
        score = r.score if r.score is not None else 0
        if r.provider == "virustotal" and score >= 90:
            override_triggered = True
            override_reason = "virustotal score >= 90"
            break

    # -----------------------------
    # Verdict logic
    # -----------------------------
    if override_triggered:
        verdict = "malicious"
        reason = "virustotal high-confidence detection"
    else:
        if weighted_avg >= 75:
            verdict = "malicious"
            reason = f"weighted average score {weighted_avg}"
        elif weighted_avg >= 40:
            verdict = "suspicious"
            reason = f"weighted average score {weighted_avg}"
        elif weighted_avg > 0:
            verdict = "benign"
            reason = f"low weighted score {weighted_avg}"
        else:
            verdict = "unknown"
            reason = "no significant detections"

    # -----------------------------
    # Severity logic
    # -----------------------------
    if verdict == "malicious":
        if max_score >= 90:
            severity = "critical"
        else:
            severity = "high"
    elif verdict == "suspicious":
        severity = "medium"
    elif verdict == "benign":
        severity = "low"
    else:
        severity = "informational"

    explanation = {
        "providers_considered": len(results),
        "override_triggered": override_triggered,
        "override_reason": override_reason,
        "max_provider": max_provider,
        "max_score": max_score,
        "weighted_avg_score": weighted_avg,
        "severity_rules": {
            "critical": "verdict=malicious and max_score >= 90",
            "high": "verdict=malicious",
            "medium": "verdict=suspicious",
            "low": "verdict=benign",
            "informational": "no detections or unknown",
        },
        "provider_breakdown": breakdown,
    }

    return verdict, reason, severity, explanation