from __future__ import annotations

from modus_intel.core.models import ScanResult

def _hr(char: str = "─", width: int = 58) -> str:
    return char * width


def _color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def _color_verdict(verdict: str) -> str:
    v = verdict.upper()
    if v == "MALICIOUS":
        return _color(v, "31")  # red
    if v == "SUSPICIOUS":
        return _color(v, "33")  # yellow
    if v == "BENIGN":
        return _color(v, "32")  # green
    return _color(v, "36")      # cyan


def _color_severity(severity: str) -> str:
    s = severity.upper()
    if s == "CRITICAL":
        return _color(s, "31")  # red
    if s == "HIGH":
        return _color(s, "91")  # bright red
    if s == "MEDIUM":
        return _color(s, "33")  # yellow
    if s == "LOW":
        return _color(s, "32")  # green
    return _color(s, "36")      # cyan


def render_pretty(result: ScanResult, include_explain: bool = False) -> str:
    lines = []
    hr = _hr

    lines.append("MODUS-INTEL // ENRICHMENT REPORT")
    lines.append(hr())
    lines.append(f"IOC:       {result.indicator.value}")
    lines.append(f"TYPE:      {result.indicator.type.upper()}")
    lines.append("")
    lines.append(f"VERDICT:   {_color_verdict(result.verdict)}")
    lines.append(f"SEVERITY:  {_color_severity(result.severity)}")
    lines.append(f"REASON:    {result.reason}")
    lines.append("")

    if result.provider_results:
        lines.append("PROVIDERS")
        lines.append(hr("·"))
        for pr in sorted(result.provider_results, key=lambda x: x.provider):
            labels = ", ".join(pr.labels) if pr.labels else "-"
            lines.append(
                f"  {pr.provider:<12} score={(pr.score if pr.score is not None else 0):<3} confidence={(pr.confidence or '-'): <6} labels={labels}"
            )
        lines.append("")

        evidence_lines = []
        for pr in sorted(result.provider_results, key=lambda x: x.provider):
            for ev in pr.evidence:
                evidence_lines.append(f"{pr.provider}: {ev}")

        if evidence_lines:
            lines.append("EVIDENCE")
            lines.append(hr("·"))
            for ev in evidence_lines:
                lines.append(f"  • {ev}")
            lines.append("")

        link_lines = []
        for pr in sorted(result.provider_results, key=lambda x: x.provider):
            for link in pr.links:
                link_lines.append(link)

        if link_lines:
            lines.append("LINKS")
            lines.append(hr("·"))
            for link in link_lines:
                lines.append(f"  - {link}")
            lines.append("")

    if include_explain and result.explanation:
        lines.append("EXPLANATION")
        lines.append(hr("·"))
        lines.append(f"  providers_considered={result.explanation.get('providers_considered')}")
        lines.append(f"  override_triggered={result.explanation.get('override_triggered')}")
        if result.explanation.get("override_reason"):
            lines.append(f"  override_reason={result.explanation.get('override_reason')}")
        lines.append(f"  max_provider={result.explanation.get('max_provider') or '-'}")
        lines.append(f"      max_score={result.explanation.get('max_score') if result.explanation.get('max_score') is not None else '-'}")
        if "weighted_avg_score" in result.explanation:
            lines.append(f"  weighted_avg_score={result.explanation.get('weighted_avg_score')}")
        lines.append("")

    lines.append(hr())
    return "\n".join(lines)


def render_batch_pretty(
    results: list[ScanResult],
    summary: dict,
    include_explain: bool = False,
) -> str:
    lines = []
    hr = _hr

    lines.append("MODUS-INTEL // BATCH ENRICHMENT REPORT")
    lines.append(hr())
    lines.append(f"TOTAL IOCs: {summary['total_iocs']}")
    lines.append("")

    lines.append("VERDICTS")
    lines.append(hr("·"))
    for verdict, count in summary["verdict_counts"].items():
        lines.append(f"  {verdict:<14} {count}")
    lines.append("")

    lines.append("SEVERITIES")
    lines.append(hr("·"))
    for severity, count in summary["severity_counts"].items():
        lines.append(f"  {severity:<14} {count}")
    lines.append("")

    lines.append("PROVIDER HITS")
    lines.append(hr("·"))
    for provider, count in summary["provider_hits"].items():
        lines.append(f"  {provider:<14} {count}")
    lines.append("")

    lines.append("IOC RESULTS")
    lines.append(hr())

    for i, result in enumerate(results, start=1):
        lines.append(f"[{i}] {result.indicator.value}")
        lines.append(f"    type:      {result.indicator.type.upper()}")
        lines.append(f"    verdict:   {_color_verdict(result.verdict)}")
        lines.append(f"    severity:  {_color_severity(result.severity)}")
        lines.append(f"    reason:    {result.reason}")

        if result.provider_results:
            lines.append("    providers:")
            for pr in sorted(result.provider_results, key=lambda x: x.provider):
                labels = ", ".join(pr.labels) if pr.labels else "-"
                lines.append(
                    f"      {pr.provider:<12} score={(pr.score if pr.score is not None else 0):<3} confidence={(pr.confidence or '-'): <6} labels={labels}"
                )

        if include_explain and result.explanation:
            lines.append("    explanation:")
            lines.append(f"      max_provider={result.explanation.get('max_provider') or '-'}")
            lines.append(f"      max_score={result.explanation.get('max_score') if result.explanation.get('max_score') is not None else '-'}")
            if "weighted_avg_score" in result.explanation:
                lines.append(
                    f"      weighted_avg_score={result.explanation.get('weighted_avg_score')}"
                )

        lines.append(hr("·"))
        lines.append("")

    return "\n".join(lines)
