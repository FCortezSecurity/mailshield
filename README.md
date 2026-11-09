# mailshield

![CI](https://github.com/FCortezSecurity/mailshield/actions/workflows/ci.yml/badge.svg)

Defensive email-security toolkit. It audits a domain's email authentication and transport security and explains how to fix what it finds.

- `mailshield audit <domain>` checks SPF, DMARC, DKIM, MTA-STS and TLS-RPT and gives a score, a grade, and plain-English fixes.
- Phishing `.eml` triage is planned: offline, analysis only, synthetic test data.

## Quick start

```bash
git clone https://github.com/FCortezSecurity/mailshield.git
cd mailshield
pip install -e ".[dev]"
mailshield audit example.com
mailshield audit example.com --format json
mailshield audit example.com --selector myselector
mailshield audit example.com --no-fetch
pytest
```

## Examples

A large, well-configured domain:

```text
$ mailshield audit google.com --format markdown

# Email authentication audit: google.com

**Score:** 95/100 (grade A)

- SPF record: `v=spf1 include:_spf.google.com ~all` (1 DNS lookups)
- DMARC record: `v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com`
- DKIM selectors found: none among 20 common selectors
- MTA-STS: mode=enforce, max_age=86400
- TLS-RPT: v=TLSRPTv1;rua=mailto:sts-reports@google.com

## Findings

### [LOW] MTA-STS max_age is short (`MTA-STS-MAXAGE-SHORT`)

max_age is 86400 seconds; senders cache the policy for that long, so a short value weakens protection.

**Fix:** Use at least 604800 seconds (one week); weeks are typical.

### [INFO] SPF uses softfail (~all) (`SPF-SOFTFAIL`)

Unlisted senders are marked suspicious rather than rejected. This is acceptable when DMARC enforces, otherwise it is weak.

**Fix:** No action needed while DMARC enforces.

### [INFO] No DKIM key found among common selectors (`DKIM-NOT-FOUND`)

Probed 20 common selector names. DKIM selectors cannot be listed via DNS, so the domain may still use a custom selector.

**Fix:** Re-run with --selector <name> using the selector from a real message header.
```

A locked-down domain that sends no mail (`example.com`, run by IANA). The tool recognizes the deliberate no-mail setup and skips checks that do not apply:

```text
$ mailshield audit example.com --format markdown

# Email authentication audit: example.com

**Score:** 100/100 (grade A)

- SPF record: `v=spf1 -all` (0 DNS lookups)
- DMARC record: `v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s`
- DKIM selectors found: none active among 20 common selectors (20 revoked)
- MTA-STS: none
- TLS-RPT: none

## Findings

### [INFO] Domain publishes a no-mail policy (`NULL-SENDER-DOMAIN`)

SPF is '-all' with no authorized senders and DMARC enforces, so this domain declares that it sends no email. Reporting and DKIM checks do not apply.

**Fix:** No action needed. Keep both records in place to prevent spoofing.
```

A deliberately weak, simulated configuration (see `examples/weak_demo.py`; no real domain is queried):

```text
# Email authentication audit: weak.example

**Score:** 25/100 (grade F)

- SPF record: `v=spf1 +all` (0 DNS lookups)
- DMARC record: `none`
- DKIM selectors found: none among 20 common selectors
- MTA-STS: none
- TLS-RPT: none

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

### [INFO] No MTA-STS policy (`MTA-STS-MISSING`)

MTA-STS makes sending servers require TLS when delivering mail to you, which blocks downgrade attacks. It is optional hardening.

**Fix:** Publish a _mta-sts TXT record and a policy file at https://mta-sts.weak.example/.well-known/mta-sts.txt.
```

## What it checks

- **SPF:** missing or duplicate records, `+all`, `?all`, `~all`, no `all`, `ptr`, unknown mechanisms, include loops, dead includes, and the 10 DNS lookup limit across nested includes.
- **DMARC:** missing, duplicate, or invalid records, `p=none`, partial `pct`, `sp=none`, missing `rua`, and strict alignment.
- **DKIM:** probes 20 common selectors (add your own with `--selector`), reads the RSA key size, and flags keys under 2048 bits, revoked keys, and testing mode (`t=y`).
- **MTA-STS:** validates the DNS record and downloads the policy file. Flags unreachable or invalid policies, bad certificates, redirects, wrong content type, `testing` or `none` mode, short `max_age`, and **MX hosts that are missing from the policy**, which would cause mail to be refused in enforce mode.
- **TLS-RPT:** validates the reporting record and flags a missing record when MTA-STS is active.
- **No-mail domains:** recognizes `v=spf1 -all` plus an enforcing DMARC policy (and wildcard-revoked DKIM keys) as a deliberate "this domain sends no email" setup, and skips checks that do not apply.
- **Exit codes:** `--fail-on high` returns 1 when a finding at or above that severity exists, so it works in CI.

## Scoring

Scores run from 0 to 100 with an A to F grade. Severities cost points: critical 50, high 25, medium 15, low 5, info 0. Informational findings never affect the score, and SPF softfail is not penalized when DMARC enforces.

Scoring is opinionated. For example, an MTA-STS `max_age` under one week is a low finding even though some large providers choose short values on purpose. Read the findings, not just the grade.

## Security design

The MTA-STS policy download is the only request that goes beyond DNS, so it is deliberately defensive:

- HTTPS only, with the certificate and hostname always verified.
- Redirects are never followed (RFC 8461 forbids them).
- Hostnames that resolve to loopback, private, link-local or cloud-metadata addresses are refused, so a hostile domain cannot aim the tool at internal services.
- Response size (64 KB) and total time are capped.
- `--no-fetch` disables the download entirely.

The test suite never touches the network: DNS and HTTPS are replaced by fakes.

## Status

SPF, DMARC, DKIM, MTA-STS and TLS-RPT auditing are done. An HTML report and phishing triage are next.

## Limitations

- DMARC lookup checks `_dmarc.<domain>` only, with no fallback to the parent domain.
- SPF `redirect=` targets are followed for lookup counting, but their `all` policy is not evaluated.
- SPF macros are not expanded.
- DKIM selectors cannot be listed through DNS, so only common selector names (plus any you pass with `--selector`) are probed. "No DKIM key found" is informational and is not proof that DKIM is missing.
- The MTA-STS policy fetch makes a live HTTPS request. Use `--no-fetch` for DNS-only mode.
- MX mismatch checking uses the domain's current MX records only.
- There is no DNSSEC or DANE validation.
- Checks are based on DNS and the policy file only. They do not test actual mail delivery.

## License

MIT
