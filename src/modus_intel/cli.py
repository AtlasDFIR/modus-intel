from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from typing import Optional

import httpx
import typer
from dotenv import load_dotenv

import modus_intel.providers  # noqa: F401  (import populates the provider registry)
from modus_intel.core.cache import Cache
from modus_intel.core.detect import prepare_ioc
from modus_intel.core.models import Indicator, ProviderResult, ScanResult
from modus_intel.core.render import render_batch_pretty, render_pretty
from modus_intel.core.verdict import compute_verdict
from modus_intel.providers.base import BaseProvider

app = typer.Typer(add_completion=False, no_args_is_help=True)


BANNER = r"""> BOOT SEQUENCE INITIALIZED
> LOADING COGNITIVE SUBROUTINES...
> THREAT INTELLIGENCE MODULE: ACTIVE
> PROVIDER MATRIX: VIRUSTOTAL | ABUSEIPDB | URLHAUS
> OPERATOR: ATLASDFIR

      ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗███████╗
      ████╗ ████║██╔═══██╗██╔══██╗██║   ██║██╔════╝
      ██╔████╔██║██║   ██║██║  ██║██║   ██║███████╗
      ██║╚██╔╝██║██║   ██║██║  ██║██║   ██║╚════██║
      ██║ ╚═╝ ██║╚██████╔╝██████╔╝╚██████╔╝███████║
      ╚═╝     ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝

                 MODUS-INTEL v0.1
           AtlasDFIR | Threat Intelligence Systems

------------------------------------------------------------
       Threat Intelligence & IOC Enrichment Engine
------------------------------------------------------------

  > Scan
  > Enrich
  > Correlate
  > Assess
"""

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def configure_logging(debug: bool, quiet: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
        format="[%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    if quiet and not debug:
        logging.getLogger().setLevel(logging.ERROR)


def get_providers() -> list[BaseProvider]:
    """Instantiate every provider registered on BaseProvider.

    Registration happens automatically in BaseProvider.__init_subclass__
    when the provider modules are imported (see providers/__init__.py).
    """
    return [cls() for cls in BaseProvider.registry]


def warn_unconfigured_providers(providers: list[BaseProvider], quiet: bool) -> None:
    """Tell the user which providers will be skipped and why.

    Without this, a run with no API keys silently returns 'unknown' for
    everything, which looks identical to a clean result.
    """
    missing = [p for p in providers if not p.is_configured()]

    if not missing:
        return

    if len(missing) == len(providers):
        typer.echo(
            "[!] No provider API keys configured. Every lookup will be skipped "
            "and all verdicts will be 'unknown'.",
            err=True,
        )
    elif quiet:
        return

    for p in missing:
        typer.echo(
            f"[!] {p.name}: skipped (set {p.env_var} to enable; see .env.example)",
            err=True,
        )


def hours_to_ttl_seconds(hours: int) -> int:
    return max(1, hours) * 3600


def normalize_output_format(output_format: str) -> str:
    value = output_format.strip().lower()
    if value not in {"json", "pretty"}:
        raise typer.BadParameter("Format must be one of: json, pretty")
    return value


def emit_output(text: str, out: Optional[str]) -> None:
    if out:
        # Never write ANSI color codes into files.
        with open(out, "w", encoding="utf-8") as f:
            f.write(_ANSI_RE.sub("", text) + "\n")
        typer.echo(f"\n[+] Wrote results to: {out}", err=True)
    else:
        if not sys.stdout.isatty():
            text = _ANSI_RE.sub("", text)
        typer.echo(text)


@app.callback()
def main() -> None:
    """MODUS-INTEL CLI."""
    load_dotenv()


async def enrich_providers_async(
    providers: list[BaseProvider],
    ioc_type: str,
    normalized: str,
    cache: Cache,
    ttl_seconds: int,
    no_cache: bool,
    refresh: bool,
) -> list[ProviderResult]:
    async with httpx.AsyncClient(timeout=15.0) as client:

        async def enrich_one(provider: BaseProvider) -> Optional[ProviderResult]:
            if not provider.supports(ioc_type):
                return None

            cache_key = cache.make_key(provider.name, ioc_type, normalized)

            if not no_cache and not refresh:
                cached = cache.get(cache_key)
                if cached:
                    return ProviderResult.model_validate(cached)

            pr = await provider.lookup_async(normalized, ioc_type, client)

            # Failed lookups are never cached; the next run should retry.
            if pr is not None and pr.status != "error" and not no_cache:
                cache.set(
                    cache_key,
                    pr.model_dump(mode="json", exclude_none=True),
                    ttl_seconds,
                )

            return pr

        tasks = [enrich_one(provider) for provider in providers]
        results = await asyncio.gather(*tasks)
        return [result for result in results if result is not None]


async def scan_one_ioc_async(
    indicator_raw: str,
    providers: list[BaseProvider],
    cache: Cache,
    ttl_seconds: int,
    no_cache: bool,
    refresh: bool,
) -> ScanResult:
    normalized, ioc_type = prepare_ioc(indicator_raw)

    if ioc_type == "unknown":
        return ScanResult(
            indicator=Indicator(value=normalized, type=ioc_type),
            provider_results=[],
            verdict="unknown",
            reason="unrecognized indicator format (expected IP, domain, URL, or md5/sha1/sha256 hash)",
            severity="informational",
            explanation=None,
        )

    provider_results = await enrich_providers_async(
        providers=providers,
        ioc_type=ioc_type,
        normalized=normalized,
        cache=cache,
        ttl_seconds=ttl_seconds,
        no_cache=no_cache,
        refresh=refresh,
    )

    verdict, reason, severity, explanation = compute_verdict(provider_results)

    return ScanResult(
        indicator=Indicator(value=normalized, type=ioc_type),
        provider_results=provider_results,
        verdict=verdict,
        reason=reason,
        severity=severity,
        explanation=explanation,
    )


async def run_batch_with_progress(
    iocs: list[str],
    providers: list[BaseProvider],
    cache: Cache,
    ttl_seconds: int,
    no_cache: bool,
    refresh: bool,
    concurrency: int,
    quiet: bool,
) -> list[ScanResult]:
    total = len(iocs)
    completed = 0
    ordered_results: list[ScanResult | None] = [None] * total
    semaphore = asyncio.Semaphore(max(1, concurrency))

    show_progress = not quiet and sys.stderr.isatty()

    def render_progress() -> None:
        if not show_progress:
            return

        width = 24
        filled = int(width * completed / total) if total else width
        bar = "█" * filled + "░" * (width - filled)
        typer.echo(f"\r[{bar}] {completed}/{total} completed", nl=False, err=True)

    async def scan_indexed(idx: int, ioc: str) -> tuple[int, ScanResult]:
        async with semaphore:
            result = await scan_one_ioc_async(
                indicator_raw=ioc,
                providers=providers,
                cache=cache,
                ttl_seconds=ttl_seconds,
                no_cache=no_cache,
                refresh=refresh,
            )
            return idx, result

    tasks = [
        asyncio.create_task(scan_indexed(idx, ioc)) for idx, ioc in enumerate(iocs)
    ]

    render_progress()

    for task in asyncio.as_completed(tasks):
        idx, result = await task
        ordered_results[idx] = result
        completed += 1
        render_progress()

    if show_progress:
        typer.echo("", err=True)

    return [result for result in ordered_results if result is not None]


def load_iocs_from_file(path: str) -> list[str]:
    iocs: list[str] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            value = line.strip()

            if not value:
                continue

            if value.startswith("#"):
                continue

            iocs.append(value)

    return iocs


def build_batch_summary(results: list[ScanResult]) -> dict:
    summary = {
        "total_iocs": len(results),
        "verdict_counts": {},
        "severity_counts": {},
        "provider_hits": {},
        "provider_errors": {},
    }

    for result in results:
        summary["verdict_counts"][result.verdict] = (
            summary["verdict_counts"].get(result.verdict, 0) + 1
        )

        summary["severity_counts"][result.severity] = (
            summary["severity_counts"].get(result.severity, 0) + 1
        )

        for provider_result in result.provider_results:
            summary["provider_hits"][provider_result.provider] = (
                summary["provider_hits"].get(provider_result.provider, 0) + 1
            )
            if provider_result.status == "error":
                summary["provider_errors"][provider_result.provider] = (
                    summary["provider_errors"].get(provider_result.provider, 0) + 1
                )

    return summary


def _setup_run(
    quiet: bool, cache_ttl_hours: int
) -> tuple[Cache, int, list[BaseProvider]]:
    """Shared startup for scan and batch: banner, cache housekeeping,
    provider construction, and missing-key warnings."""
    if not quiet:
        typer.echo(BANNER, err=True)

    cache = Cache()
    cache.purge_expired()

    providers = get_providers()
    warn_unconfigured_providers(providers, quiet=quiet)

    return cache, hours_to_ttl_seconds(cache_ttl_hours), providers


@app.command()
def scan(
    indicator: str = typer.Argument(
        ...,
        help="IP, domain, URL, or hash (md5/sha1/sha256). Defanged forms (hxxp, [.]) are accepted.",
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging."),
    out: Optional[str] = typer.Option(
        None, "--out", "-o", help="Write output to a file (respects --format)."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner output."),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Disable cache reads/writes."
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Ignore cache and fetch fresh results."
    ),
    cache_ttl_hours: int = typer.Option(24, "--cache-ttl", help="Cache TTL in hours."),
    explain: bool = typer.Option(
        False, "--explain", help="Include explainability details in output."
    ),
    format: str = typer.Option(
        "json", "--format", help="Output format: json or pretty"
    ),
) -> None:
    """Scan a single IOC, enrich it with provider data, and emit a verdict."""
    configure_logging(debug=debug, quiet=quiet)

    output_format = normalize_output_format(format)
    cache, ttl_seconds, providers = _setup_run(quiet, cache_ttl_hours)

    result = asyncio.run(
        scan_one_ioc_async(
            indicator_raw=indicator,
            providers=providers,
            cache=cache,
            ttl_seconds=ttl_seconds,
            no_cache=no_cache,
            refresh=refresh,
        )
    )

    if result.indicator.type == "unknown":
        typer.echo(f"[!] {result.reason}: {result.indicator.value!r}", err=True)
        raise typer.Exit(code=2)

    if not explain:
        result.explanation = None

    if output_format == "pretty":
        text = render_pretty(result, include_explain=explain)
    else:
        payload = result.model_dump(mode="json", exclude_none=True)
        text = json.dumps(payload, indent=2)

    emit_output(text, out)


@app.command()
def batch(
    input_file: str = typer.Argument(
        ..., help="Path to a text file containing one IOC per line."
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging."),
    out: Optional[str] = typer.Option(
        None, "--out", "-o", help="Write output to a file (respects --format)."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner output."),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Disable cache reads/writes."
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Ignore cache and fetch fresh results."
    ),
    cache_ttl_hours: int = typer.Option(24, "--cache-ttl", help="Cache TTL in hours."),
    explain: bool = typer.Option(
        False, "--explain", help="Include explainability details in output."
    ),
    format: str = typer.Option(
        "json", "--format", help="Output format: json or pretty"
    ),
    concurrency: int = typer.Option(
        5, "--concurrency", help="Maximum number of concurrent IOC scans."
    ),
) -> None:
    """Scan multiple IOCs from a file and emit batch results with summary."""
    configure_logging(debug=debug, quiet=quiet)

    output_format = normalize_output_format(format)
    iocs = load_iocs_from_file(input_file)

    if not iocs:
        typer.echo(f"[!] No IOCs found in {input_file}", err=True)
        raise typer.Exit(code=2)

    cache, ttl_seconds, providers = _setup_run(quiet, cache_ttl_hours)

    results = asyncio.run(
        run_batch_with_progress(
            iocs=iocs,
            providers=providers,
            cache=cache,
            ttl_seconds=ttl_seconds,
            no_cache=no_cache,
            refresh=refresh,
            concurrency=concurrency,
            quiet=quiet,
        )
    )

    summary = build_batch_summary(results)

    if not explain:
        for result in results:
            result.explanation = None

    if output_format == "pretty":
        text = render_batch_pretty(results, summary, include_explain=explain)
    else:
        payload = {
            "summary": summary,
            "results": [
                result.model_dump(mode="json", exclude_none=True) for result in results
            ],
        }
        text = json.dumps(payload, indent=2)

    emit_output(text, out)


if __name__ == "__main__":
    app()
