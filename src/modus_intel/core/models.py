from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


IndicatorType = Literal["ip", "domain", "url", "hash", "unknown"]
Verdict = Literal["benign", "suspicious", "malicious", "unknown"]


class Indicator(BaseModel):
    value: str = Field(..., description="Normalized indicator value.")
    type: IndicatorType = Field(..., description="Detected indicator type.")


class ProviderResult(BaseModel):
    provider: str
    score: Optional[int] = Field(None, ge=0, le=100)
    confidence: Optional[Literal["low", "medium", "high"]] = None
    labels: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    links: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    indicator: Indicator
    provider_results: List[ProviderResult]
    verdict: Verdict