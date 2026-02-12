from __future__ import annotations

import json
from typing import Optional

import typer

from modus_intel.core.detect import detect_ioc_type, normalize_ioc
from modus_intel.core.models import Indicator, ScanResult

app = typer.Typer(add_completion=False, no_args_is_help=True)

@app.callback()
def main() -> None:
    """MODUS-INTEL CLI."""
    return


BANNER = r"""> BOOT SEQUENCE INITIALIZED
> LOADING COGNITIVE SUBROUTINES...
> THREAT INTELLIGENCE MODULE: ACTIVE
> PROVIDER MATRIX: VIRUSTOTAL | ABUSEIPDB | OTX
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
  Autonomous Threat Intelligence & IOC Enrichment Engine
------------------------------------------------------------

  > Scan
  > Enrich
  > Correlate
  > Assess
"""


@app.command()
def scan(
    indicator: str = typer.Argument(..., help="IP, domain, URL, or hash (md5/sha1/sha256)."),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Write JSON output to a file."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner output."),
) -> None:
    """Detect indicator type and emit normalized JSON (provider enrichment comes next)."""
    if not quiet:
        typer.echo(BANNER)

    raw = indicator.strip()
    ioc_type = detect_ioc_type(raw)
    normalized = normalize_ioc(raw, ioc_type)

    result = ScanResult(
        indicator=Indicator(value=normalized, type=ioc_type),
        provider_results=[],
        verdict="unknown",
    )

    payload = result.model_dump(mode="json", exclude_none=True)
    output_json = json.dumps(payload, indent=2)

    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(output_json + "\n")
        typer.echo(f"\n[+] Wrote results to: {out}")
    else:
        typer.echo(output_json)


if __name__ == "__main__":
    app()