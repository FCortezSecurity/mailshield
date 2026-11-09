# mailshield

![CI](https://github.com/FCortezSecurity/mailshield/actions/workflows/ci.yml/badge.svg)

Defensive email-security toolkit. It audits a domain's email authentication and explains how to fix what it finds.

- `mailshield audit <domain>` checks SPF, DMARC and DKIM and gives a score, a grade, and plain-English fixes.
- Phishing `.eml` triage is planned: offline, analysis only, synthetic test data.

## Quick start

```bash
git clone https://github.com/FCortezSecurity/mailshield.git
cd mailshield
pip install -e ".[dev]"
mailshield audit example.com
mailshield audit example.com --format json
mailshield audit example.com --selector myselector
pytest
```

## Example

```text
$ mailshield audit google.com --format markdown

# Email authentication audit: google.com

**Score:** 100/100 (grade A)

- SPF record: `v=spf1 include:_spf.google.com ~all` (1 DNS lookups)
- DMARC record: `v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com`
- DKIM selectors found: none among 20 common selectors

## Findings

### [INFO] SPF uses softfail (~all) (`SPF-SOFTFAIL`)

Unlisted senders are marked suspicious rather than rejected. This is acceptable when DMARC enforces, otherwise it is weak.

**Fix:** No action needed while DMARC enforces.

### [INFO] No DKIM key found among common selectors (`DKIM-NOT-FOUND`)

Probed 20 common selector names. DKIM selectors cannot be listed via DNS, so the domain may still use a custom selector.

**Fix:** Re-run with --selector <name> using the selector from a real message header.
```

A deliberately weak, simulated configuration (see `examples/weak_demo.py`, no real domain is queried):

```text
# Email authentication audit: weak.example

**Score:** 25/100 (grade F)

- SPF record: `v=spf1 +all` (0 DNS lookups)
- DMARC record: `none`
- DKIM selectors found: none among 20 common selectors

## Findings

### [CRITICAL] SPF allows every sender (+all) (`SPF-ALL-PLUS`)

'+all' authorizes any server on the internet to send as this domain.

**Fix:** Replace with -all (or ~all while testing).

### [HIGH] No DMARC record (`DMARC-MISSING`)

_dmarc.weak.example has no DMARC record, so receivers have no policy for spoofed mail and you get no reports about abuse.

**Fix:** Publish a TXT record at _dmarc such as "v=DMARC1; p=none; rua=mailto:you@example.com" and tighten the policy over time.

### [INFO] No DKIM key found among common selectors (`DKIM-NOT-FOUND`)

Probed 20 common selector names. DKIM selectors cannot be listed via DNS, so the domain may still use a custom selector.

**Fix:** Re-run with --selector <name> using the selector from a real message header.
```

## What it checks

- **SPF:** missing or duplicate records, `+all`, `?all`, `~all`, no `all`, `ptr`, unknown mechanisms, include loops, dead includes, and the 10 DNS lookup limit across nested includes.
- **DMARC:** missing, duplicate, or invalid records, `p=none`, partial `pct`, `sp=none`, missing `rua`, and strict alignment.
- **DKIM:** probes 20 common selectors (add your own with `--selector`), reads the RSA key size, and flags keys under 2048 bits, revoked keys, and testing mode (`t=y`).
- **Scoring:** 0 to 100 with an A to F grade. SPF softfail is not penalized when DMARC enforces.
- **Exit codes:** `--fail-on high` returns 1 when a finding at or above that severity exists, so it works in CI.

## Status

SPF, DMARC and DKIM auditing are done. MTA-STS, an HTML report, and phishing triage are next.

## Limitations

- DMARC lookup checks `_dmarc.<domain>` only, with no fallback to the parent domain.
- SPF `redirect=` targets are followed for lookup counting, but their `all` policy is not evaluated.
- SPF macros are not expanded.
- DKIM selectors cannot be listed through DNS, so only common selector names (plus any you pass with `--selector`) are probed. "No DKIM key found" is informational and is not proof that DKIM is missing.
- Checks are based on DNS records only. They do not test actual mail delivery.

## License

MIT
