# MODUS-Intel

[![CI](https://github.com/AtlasDFIR/modus-intel/actions/workflows/ci.yml/badge.svg)](https://github.com/AtlasDFIR/modus-intel/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/github/license/AtlasDFIR/modus-intel)

A threat intelligence CLI (Command Line Interface) that enriches IOCs (Indicators of Compromise) against multiple OSINT (Open Source Intelligence) providers and produces a single weighted verdict with an auditable explanation of how it was reached.

Feed it an IP, domain, URL, or file hash. MODUS-Intel classifies it, fans out async lookups to VirusTotal, AbuseIPDB, URLHaus, and GreyNoise, scores the responses, and tells you whether the indicator is benign, suspicious, or malicious, and why.

```
MODUS-INTEL // ENRICHMENT REPORT
──────────────────────────────────────────────────────────
IOC:       45.155.205.233
TYPE:      IP

VERDICT:   MALICIOUS
SEVERITY:  CRITICAL
REASON:    high-confidence detection (virustotal score 100 >= 90)

PROVIDERS
··························································
  abuseipdb    score=97  confidence=high   labels=abuse_reports
  virustotal   score=100 confidence=high   labels=malicious

EVIDENCE
··························································
  • abuseipdb: Total reports (90d): 214
  • abuseipdb: ISP: Example Hosting
  • virustotal: malicious=14, suspicious=2, raw_score=150
```

## Features

**Multi-provider enrichment.** Async fan-out to VirusTotal, AbuseIPDB, URLHaus, and GreyNoise over a shared HTTP client, with per-provider trust weights. Providers self-register through a plugin registry, so adding a new one is a single subclass plus an import.

**Weighted verdicts with overrides.** Provider scores are combined into a weighted average, but a single high-confidence detection (score 90 or above from any provider) forces a malicious verdict so it cannot be diluted by quieter sources. Run with `--explain` to get the full decision breakdown: every provider's score, weight, and status, the thresholds applied, and whether an override fired.

**Honest failure handling.** Every provider lookup carries a status: `ok`, `no_data` (the provider has never seen the indicator), or `error` (auth failure, rate limit, network). Errors are excluded from scoring, surfaced in the output, and never cached, so a rate-limited batch run cannot masquerade as a clean one. If no API keys are configured, the CLI says so up front instead of silently returning "unknown" for everything.

**Defang-aware input.** Analysts share IOCs defanged; MODUS-Intel accepts them as-is. `hxxps://evil[.]com/payload`, `45.155.205[.]233`, and `evil[dot]com` are automatically refanged before classification and lookup.

**Result caching.** Provider responses are cached in a local SQLite database with a configurable TTL (time to live, default 24 hours), so re-scanning the same indicators does not burn API quota. `--refresh` forces fresh lookups; `--no-cache` bypasses the cache entirely.

**Pipe-friendly output.** JSON goes to stdout; the banner, progress bar, and warnings go to stderr. `modus-intel scan 8.8.8.8 | jq .verdict` just works. Files written with `--out` are stripped of terminal color codes.

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/AtlasDFIR/modus-intel.git
cd modus-intel
pip install -e .
```

## Configuration

Copy `.env.example` to `.env` and add your API keys (or export them as environment variables):

| Variable | Provider | Where to get a key |
|---|---|---|
| `VT_API_KEY` | VirusTotal | https://www.virustotal.com/gui/my-apikey |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | https://www.abuseipdb.com/account/api |
| `URLHAUS_AUTH_KEY` | URLHaus | https://auth.abuse.ch/ |
| `GREYNOISE_API_KEY` | GreyNoise | https://viz.greynoise.io/account/ |

All keys are optional. A provider without a key is skipped, and the CLI warns you which lookups will not run. Note that the VirusTotal free tier allows 4 requests per minute; for large batches, lower `--concurrency` accordingly.

## Usage

Scan a single indicator (JSON by default):

```bash
modus-intel scan 45.155.205.233
modus-intel scan evil-domain.com --format pretty
modus-intel scan "hxxps://evil[.]com/payload.exe" --format pretty
modus-intel scan d41d8cd98f00b204e9800998ecf8427e --explain
```

Scan a file of indicators (one per line, `#` comments allowed):

```bash
modus-intel batch iocs.txt --format pretty
modus-intel batch iocs.txt --out results.json
modus-intel batch iocs.txt --concurrency 2   # be kind to free-tier rate limits
```

Useful flags for both commands:

| Flag | Effect |
|---|---|
| `--format json\|pretty` | Output format (default `json`) |
| `--explain` | Include the full verdict decision breakdown |
| `--out FILE` | Write results to a file (color codes stripped) |
| `--refresh` | Ignore cached results and fetch fresh data |
| `--no-cache` | Disable the cache entirely |
| `--cache-ttl HOURS` | Cache TTL in hours (default 24) |
| `--quiet` | Suppress the banner |
| `--debug` | Verbose logging |

## How verdicts are computed

1. Each provider returns a 0-100 score. Errored lookups are excluded; they carry no signal about the indicator.
2. Scores are combined into a weighted average using per-provider trust weights (VirusTotal 1.5, URLHaus 1.2, AbuseIPDB 1.0, GreyNoise 1.0).
3. Any single provider at score 90 or above forces a **malicious** verdict (override).
4. Otherwise: weighted average >= 75 is **malicious**, >= 25 is **suspicious**, below that is **benign**. Providers affirmatively reporting zero detections count as evidence of benign, not as an unknown.
5. **unknown** is reserved for the cases where there is nothing to go on: no configured providers, no provider supporting the indicator type, or every lookup failing.

Severity follows the verdict: `critical` for overridden malicious, `high` for malicious, `medium` for suspicious, `low` for benign, `informational` for unknown.

## Architecture

```
src/modus_intel/
├── cli.py                # Typer CLI: scan and batch commands, output routing
├── core/
│   ├── detect.py         # IOC classification, defang/refang, normalization
│   ├── verdict.py        # Weighted scoring, overrides, severity mapping
│   ├── cache.py          # SQLite TTL cache for provider responses
│   ├── models.py         # Pydantic models (Indicator, ProviderResult, ScanResult)
│   └── render.py         # Pretty terminal rendering
└── providers/
    ├── base.py           # BaseProvider ABC with self-registration
    ├── virustotal.py
    ├── abuseipdb.py
    ├── urlhaus.py
    └── greynoise.py
```

Adding a provider: subclass `BaseProvider`, set `name` and `env_var`, implement `supports()` and `lookup_async()`, and import the module in `providers/__init__.py`. The registry handles the rest.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
black --check src tests
pytest
```

The test suite mocks all HTTP traffic; no API keys are needed to run it.

## License

MIT. See [LICENSE](LICENSE).
