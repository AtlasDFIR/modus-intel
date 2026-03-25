from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


IndicatorType = Literal["ip", "domain", "url", "hash", "md5", "sha1", "sha256", "unknown"]
Verdict = Literal["benign", "suspicious", "malicious", "unknown"]
Severity = Literal["informational", "low", "medium", "high", "critical"]


class Indicator(BaseModel):
    value: str = Field(..., description="Normalized indicator value.")
    type: IndicatorType = Field(..., description="Detected indicator type.")


class ProviderResult(BaseModel):
    provider: str
    score: Optional[int] = Field(None, ge=0, le=100)
    confidence: Optional[Literal["low", "medium", "high"]] = None
    labels: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    indicator: Indicator
    provider_results: list[ProviderResult] = Field(default_factory=list)
    verdict: Verdict
    reason: str
    severity: Severity = "informational"
    explanation: Optional[dict[str, Any]] = None