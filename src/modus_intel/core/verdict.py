from __future__ import annotations

from typing import Any

from modus_intel.core.models import ProviderResult, Severity, Verdict

# Provider trust weights (tuneable)
PROVIDER_WEIGHTS = {
    "virustotal": 1.5,
    "abuseipdb": 1.0,
    "urlhaus": 1.2,
}

# Any single provider reporting at or above this score forces a malicious
# verdict regardless of the weighted average, so one strong detection cannot
# be diluted by quieter providers.
OVERRIDE_SCORE = 90

MALICIOUS_THRESHOLD = 75
SUSPICIOUS_THRESHOLD = 25


def compute_verdict(
    results: list[ProviderResult],
) -> tuple[Verdict, str, Severity, dict[str, Any]]:
    """
    Returns:
        verdict: malicious | suspicious | benign | unknown
        reason: short summary string
        severity: informational | low | medium | high | critical
        explanation: structured breakdown of decision logic

    Verdict rules, in order:
        1. No results at all -> unknown.
        2. Errored lookups carry no signal and are excluded from scoring.
           If every lookup errored -> unknown.
        3. Any scoring provider at or above OVERRIDE_SCORE -> malicious.
        4. Weighted average >= MALICIOUS_THRESHOLD -> malicious.
        5. Weighted average >= SUSPICIOUS_THRESHOLD -> suspicious.
        6. Otherwise -> benign. Providers affirmatively reporting zero
           detections is evidence of benign, not an unknown.
    """

    if not results:
        return (
            "unknown",
            "no provider results",
            "informational",
            {
                "providers_considered": 0,
                "providers_errored": 0,
                "override_triggered": False,
                "provider_breakdown": [],
            },
        )

    scored = [r for r in results if r.status != "error"]
    errored = [r for r in results if r.status == "error"]

    breakdown = []
    for r in results:
        weight = PROVIDER_WEIGHTS.get(r.provider, 1.0)
        score = r.score if r.score is not None else 0
        breakdown.append(
            {
                "provider": r.provider,
                "status": r.status,
                "score": score,
                "weight": weight if r.status != "error" else 0.0,
                "weighted_score": (
                    round(score * weight, 2) if r.status != "error" else 0.0
                ),
                "confidence": r.confidence,
                "labels": r.labels,
            }
        )

    if not scored:
        return (
            "unknown",
            f"all {len(errored)} provider lookups failed",
            "informational",
            {
                "providers_considered": len(results),
                "providers_errored": len(errored),
                "override_triggered": False,
                "provider_breakdown": breakdown,
            },
        )

    weighted_sum = 0.0
    weight_sum = 0.0
    max_score = 0
    max_provider = None

    for r in scored:
        weight = PROVIDER_WEIGHTS.get(r.provider, 1.0)
        score = r.score if r.score is not None else 0

        weighted_sum += score * weight
        weight_sum += weight

        if max_provider is None or score > max_score:
            max_score = score
            max_provider = r.provider

    weighted_avg = round(weighted_sum / weight_sum, 2) if weight_sum else 0.0

    # -----------------------------
    # Override logic (hard rules)
    # -----------------------------
    override_triggered = False
    override_reason = None

    for r in scored:
        score = r.score if r.score is not None else 0
        if score >= OVERRIDE_SCORE:
            override_triggered = True
            override_reason = f"{r.provider} score {score} >= {OVERRIDE_SCORE}"
            break

    # -----------------------------
    # Verdict logic
    # -----------------------------
    if override_triggered:
        verdict = "malicious"
        reason = f"high-confidence detection ({override_reason})"
    elif weighted_avg >= MALICIOUS_THRESHOLD:
        verdict = "malicious"
        reason = f"weighted average score {weighted_avg}"
    elif weighted_avg >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
        reason = f"weighted average score {weighted_avg}"
    elif weighted_avg > 0:
        verdict = "benign"
        reason = f"low weighted score {weighted_avg}"
    else:
        # Every scoring provider affirmatively reported zero detections.
        verdict = "benign"
        reason = f"no detections across {len(scored)} provider(s)"

    if errored:
        reason += f" ({len(errored)} provider lookup(s) failed)"

    # -----------------------------
    # Severity logic
    # -----------------------------
    if verdict == "malicious":
        severity: Severity = "critical" if max_score >= OVERRIDE_SCORE else "high"
    elif verdict == "suspicious":
        severity = "medium"
    elif verdict == "benign":
        severity = "low"
    else:
        severity = "informational"

    explanation = {
        "providers_considered": len(results),
        "providers_errored": len(errored),
        "override_triggered": override_triggered,
        "override_reason": override_reason,
        "max_provider": max_provider,
        "max_score": max_score,
        "weighted_avg_score": weighted_avg,
        "thresholds": {
            "override_score": OVERRIDE_SCORE,
            "malicious": MALICIOUS_THRESHOLD,
            "suspicious": SUSPICIOUS_THRESHOLD,
        },
        "severity_rules": {
            "critical": f"verdict=malicious and max_score >= {OVERRIDE_SCORE}",
            "high": "verdict=malicious",
            "medium": "verdict=suspicious",
            "low": "verdict=benign",
            "informational": "no usable provider data",
        },
        "provider_breakdown": breakdown,
    }

    return verdict, reason, severity, explanation
