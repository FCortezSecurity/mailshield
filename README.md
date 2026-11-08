# mailshield

![CI](https://github.com/FCortezSecurity/mailshield/actions/workflows/ci.yml/badge.svg)

Defensive email-security toolkit. It audits a domain's email authentication and explains how to fix what it finds.

- `mailshield audit <domain>` checks SPF and DMARC and gives a score, a grade, and plain-English fixes.
- Phishing `.eml` triage is planned: offline, analysis only, synthetic test data.

## Quick start

```bash
git clone https://github.com/FCortezSecurity/mailshield.git
cd mailshield
pip install -e ".[dev]"
mailshield audit example.com
mailshield audit example.com --format json
pytest
```

## Example

```text
(paste the output of: mailshield audit google.com)
```

A weak configuration (a test domain with a missing DMARC record and `+all` in SPF):

```text
(paste the output for a domain you control, or mocked records)
```

## What it checks

- **SPF:** missing or duplicate records, `+all`, `?all`, `~all`, no `all`, `ptr`, unknown mechanisms, include loops, dead includes, and the 10 DNS lookup limit across nested includes.
- **DMARC:** missing, duplicate, or invalid records, `p=none`, partial `pct`, `sp=none`, missing `rua`, and strict alignment.
- **Scoring:** 0 to 100 with an A to F grade. SPF softfail is not penalized when DMARC enforces.
- **Exit codes:** `--fail-on high` returns 1 when a finding at or above that severity exists, so it works in CI.

## Status

SPF and DMARC auditing is done. DKIM, MTA-STS, an HTML report, and phishing triage are next.

## Limitations

- DMARC lookup checks `_dmarc.<domain>` only, with no fallback to the parent domain.
- SPF `redirect=` targets are followed for lookup counting, but their `all` policy is not evaluated.
- SPF macros are not expanded.
- Checks are based on DNS records only. They do not test actual mail delivery.

## License

MIT