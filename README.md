# mailshield

Defensive email-security toolkit.

- `mailshield audit <domain>`: audits a domain's SPF and DMARC records and explains fixes in plain English.
- Phishing `.eml` triage: planned (offline, analysis only, synthetic test data).

## Quick start

```bash
pip install -e ".[dev]"
mailshield audit example.com
mailshield audit example.com --format json
pytest
```

## Status

Weekend 1: SPF + DMARC auditing. DKIM, MTA-STS, HTML report and triage are next.

## Limitations

- DMARC lookup checks `_dmarc.<domain>` only (no organizational-domain fallback yet).
- SPF `redirect=` targets are followed for lookup counting, but their `all` policy is not evaluated.
- Macros in SPF terms are not expanded.
