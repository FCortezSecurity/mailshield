# mailshield

![CI](https://github.com/FCortezSecurity/mailshield/actions/workflows/ci.yml/badge.svg)

A defensive email-security toolkit with two parts:

- **`mailshield audit <domain>`** checks a domain's SPF, DMARC, DKIM, MTA-STS and TLS-RPT setup, scores it, and explains each fix in plain English.
- **`mailshield triage <file.eml>`** analyzes a suspicious email **offline** (headers, links, attachments, look-alike domains and wording) and returns a risk score with the specific reasons behind it. It never visits links or opens attachments.

Both parts are built to be safe to point at hostile input: everything they read from DNS, remote servers or email files is treated as untrusted. See [docs/DESIGN.md](docs/DESIGN.md) for the design decisions and the bugs the tests caught along the way.

## Quick start

```bash
git clone https://github.com/FCortezSecurity/mailshield.git
cd mailshield
pip install -e ".[dev]"

mailshield audit example.com
mailshield audit example.com --format html -o report.html
mailshield audit example.com --selector myselector --no-fetch

mailshield triage tests/fixtures/ceo_fraud.eml
mailshield triage suspicious.eml --protected-name "Jane Smith" --trusted-domain example.org

pytest
```

Requires Python 3.10 or newer. Runtime dependencies: `dnspython` and `rich` (nothing else, to keep the supply-chain surface small).

## Audit

`mailshield audit` options: `--format text|json|markdown|html`, `-o FILE`, `--selector NAME` (repeatable), `--no-fetch` (DNS only), `--timeout SECONDS`, and `--fail-on SEVERITY` (exit code 1 if any finding is at or above that level, for use in CI).

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

A deliberately weak, simulated configuration is available offline with `python examples/weak_demo.py` (add a filename to write the HTML report). No real domain is queried.

### What the audit checks

- **SPF:** missing or duplicate records, `+all`, `?all`, `~all`, no `all`, `ptr`, unknown mechanisms, include loops, dead includes, and the 10 DNS lookup limit across nested includes.
- **DMARC:** missing, duplicate or invalid records, `p=none`, partial `pct`, `sp=none`, missing `rua`, strict alignment.
- **DKIM:** probes 20 common selectors (plus any you pass), reads the RSA key size, and flags keys under 2048 bits, revoked keys, and testing mode (`t=y`).
- **MTA-STS:** validates the DNS record and downloads the policy file. Flags unreachable or invalid policies, bad certificates, redirects, wrong content type, `testing` or `none` mode, short `max_age`, and MX hosts missing from the policy, which would cause mail to be refused in enforce mode.
- **TLS-RPT:** validates the reporting record and flags a missing record when MTA-STS is active.
- **No-mail domains:** `v=spf1 -all` plus an enforcing DMARC policy (and wildcard-revoked DKIM keys) is recognized as deliberate, and checks that do not apply are skipped.

Scores run from 0 to 100 with an A to F grade. Severities cost points: critical 50, high 25, medium 15, low 5, info 0. Informational findings never affect the score. Scoring is opinionated (an MTA-STS `max_age` under a week is a low finding even though some large providers choose that on purpose), so read the findings, not just the grade.

## Triage

`mailshield triage` options: `--format text|json|markdown`, `-o FILE`, `--protected-name NAME` (people likely to be impersonated, repeatable), `--trusted-domain DOMAIN` (your own domains, repeatable; used for impersonation and look-alike checks). `--protected-name` requires at least one `--trusted-domain`.

Example, a synthetic message (reserved example domains) that imitates an executive and asks for changed wire instructions:

```text
$ mailshield triage tests/fixtures/wire_change.eml --protected-name "Jane Smith" --trusted-domain example.org --format markdown

# Phishing triage: Urgent - closing funds

**Risk:** 100/100 (likely phishing)

- From: Jane Smith \<jane.smith@example.net\>
- Reply-To: jane.smith.office@gmail.com
- Return-Path: none
- Authentication results: spf=pass, dkim=pass, dmarc=pass
- Received hops: 1
- Links found: 0

## Findings

### [HIGH] Replies go to a free mailbox instead of the sender's domain (`HDR-REPLYTO-FREEMAIL`)

From is example.net but replies go to jane.smith.office@gmail.com. Redirecting replies is how business email compromise keeps the victim talking to the attacker.

**Next step:** Confirm the request through a channel you already trust, not by replying.

### [HIGH] Sender uses the name of Jane Smith from an untrusted domain (`HDR-IMPERSONATION`)

The display name matches a protected person but the mail comes from example.net, which is not one of your trusted domains. Executive impersonation is the usual opening of wire-fraud attempts.

**Next step:** Verify the request with the real person by phone or in person.

### [HIGH] Domain imitates one of your domains (`LOOK-TLD-SWAP`)

example.net (from the sender address) uses the same name with a different ending: it resembles example.org.

**Next step:** Compare the real domain character by character, and report it if unexpected.

### [HIGH] Message asks to change payment or banking details (`TXT-PAYMENT-CHANGE`)

Changing where money is sent is the core move of invoice and vendor fraud. Matched: 'update our wire instructions'; 'new account number'; 'account number and routing number'.

**Next step:** Verify by phoning a number you already have on file, not one from this message.

### [HIGH] Message mixes a closing or escrow with wire details (`TXT-CLOSING-WIRE`)

Fraudulent wire instructions sent just before a property closing are a leading real estate scam. Matched: 'closing funds Hi, I'm in a m ... update our wire instructions'; 'our wire instructions for the closing'.

**Next step:** Confirm wire instructions by phone with the title or escrow company directly.

### [MEDIUM] Message combines urgency with pressure or secrecy (`TXT-URGENCY-SECRECY`)

Pushing for speed and silence keeps victims from checking with anyone. Matched: 'Urgent'; 'immediately'; 'confidential'.

**Next step:** Slow down and verify through another channel before acting.

---

_Heuristic result from headers, links, attachments and wording. Links were never visited and attachments were never opened. A message with no findings can still be malicious, and a finding is a reason to look closer, not proof._
```

### What triage checks

- **Headers:** duplicate or missing From, Reply-To pointing elsewhere (high severity when it goes to a free mailbox), envelope-sender mismatch, SPF/DKIM/DMARC results from the topmost `Authentication-Results` header, display-name spoofing, impersonation of people you name, out-of-order Received timestamps, and a Date far from the first server timestamp.
- **Links:** link text that shows one site while the link goes to another, raw IP addresses (including obfuscated forms), URL shorteners, punycode domains, the `https://good.com@evil.com` trick, and HTML forms.
- **Attachments:** double extensions, executable and script types, macro-enabled Office files, HTML/SVG files, archives, names with hidden or reversing characters, and files whose bytes are a program but whose name says otherwise. SHA-256 hashes are reported for manual lookup.
- **Look-alike domains:** homoglyphs (including punycode), a different ending, small typos, and embedded names, compared against the domains you declare with `--trusted-domain`.
- **Wording:** changed payment details, closing or escrow combined with wire details, gift cards, account-verification lures, and urgency combined with secrecy. Every hit quotes the phrase that matched.

The verdict is `no strong indicators`, `suspicious` (risk 25 or more) or `likely phishing` (60 or more). It never says "safe": a message with no findings can still be malicious.

## Security design

- **Triage is fully offline.** No DNS, no HTTP. Links are parsed but never visited, and every URL in the output is defanged (`hxxps://evil[.]com`). Attachments are decoded in memory only to hash them and are never opened or written to disk. Input files over 10 MB are refused.
- **The MTA-STS download is the only request beyond DNS, and it is defensive.** HTTPS only, certificate and hostname always verified, redirects never followed (RFC 8461 forbids them), response size and total time capped, and hostnames that resolve to loopback, private, link-local or cloud-metadata addresses are refused, so a hostile domain cannot aim the tool at internal services. `--no-fetch` disables it.
- **All untrusted text is sanitized before display.** Control characters are stripped, bidirectional and zero-width characters are shown escaped, terminal markup is neutralized, and HTML reports escape every value and contain no scripts or external resources.
- **Tests never touch the network.** DNS and HTTPS are replaced by fakes, and test data is synthetic, written with reserved domains.

## Limitations

- Triage is a set of heuristics. Expect some false positives and misses, and treat findings as reasons to look closer.
- Authentication results in email headers are written by the receiving server and cannot be verified from the file alone.
- Look-alike checks only run against domains you declare with `--trusted-domain`.
- Domain matching uses a small built-in list of multi-part suffixes, not the full public suffix list.
- Triage does not analyze attachment contents (macros, nested archives) or message language beyond the listed patterns.
- DMARC lookup checks `_dmarc.<domain>` only, with no fallback to the parent domain.
- SPF `redirect=` targets are followed for lookup counting, but their `all` policy is not evaluated. SPF macros are not expanded.
- DKIM selectors cannot be listed through DNS, so only common names (plus `--selector`) are probed. "No DKIM key found" is informational, not proof that DKIM is missing.
- There is no DNSSEC or DANE validation, and nothing tests actual mail delivery.

## Project layout

```text
src/mailshield/
  cli.py  audit.py  models.py  scoring.py  fetch.py  textutil.py
  dns_auth/   resolver, spf, dmarc, dkim, mta_sts, tls_rpt
  report/     render (json, markdown), html
  triage/     parser, body, headers, urls, attachments, lookalike,
              content, domains, verdict, render
tests/        170 tests; fixtures/ holds synthetic .eml files
examples/     weak_demo.py
docs/         DESIGN.md
```

## License

MIT
