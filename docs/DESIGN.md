# Design notes

These notes explain why mailshield is built the way it is, and what testing it against real and hostile input taught.

## Goals

1. Give people **specific, explainable findings**, not a mystery score. Every finding has an ID, a plain-English explanation and a fix.
2. Be **safe to run on hostile input**. The domains and emails a security tool looks at are, by definition, controlled by someone who may be an attacker.
3. Be **honest about uncertainty**. Absence of a finding is not proof of safety, and the tool says so.

Non-goals: replacing a mail gateway, scanning attachments for malware, or testing real mail delivery.

## Architecture

The audit and triage halves share a `Finding` model (ID, severity, title, detail, fix) and a severity scale, but score differently: the audit starts at 100 and deducts, triage accumulates risk up to 100.

All input and output with the outside world goes through two small interfaces:

- `Resolver` (`txt()` and `mx()`), implemented by dnspython for real use and by an in-memory fake in tests.
- `PolicyFetcher` (`fetch(host, path)`), implemented by a hardened HTTPS client and by a fake in tests.

Because of that, the logic that decides what is wrong is pure and can be tested exhaustively without a network. The audit and triage rules (dozens of distinct checks) are exercised this way: most have a test that makes them fire, and the ones that could produce noise also have a test showing they stay quiet on a good configuration.

## Decisions worth explaining

**The HTTPS fetcher assumes the domain is hostile.** MTA-STS requires fetching `https://mta-sts.<domain>/.well-known/mta-sts.txt`. The domain is attacker-controlled input, so a hostile domain could point that hostname at `127.0.0.1` or a cloud metadata address and use the tool as a probe into the operator's network (server-side request forgery). The fetcher resolves the name itself, refuses any non-public address, connects to the checked address while still verifying the certificate against the hostname, never follows redirects, and caps both response size and total time. The address guard is covered by automated tests. During development the real TLS path was also exercised (success, chunked responses, redirect, oversize body, timeout, untrusted certificate, loopback refusal) against a local TLS server; that manual check is not part of the automated suite because it needs a generated certificate.

**Triage cannot do anything dangerous, by construction.** It has no network code at all. Links are classified from their text and are never resolved. Attachments are decoded in memory to a hash and a magic-byte check and are never written out. Anything shown from the message is cleaned first.

**Untrusted text is a vulnerability class, not an edge case.** A review of the code found that DNS record text was being printed through Rich's markup parser. A TXT record containing `[/oops]` crashed the text output with a `MarkupError`, and raw terminal escape sequences in a record would reach the user's terminal. Both were reproduced before they were fixed. The fix has three layers: sanitize at the boundary where data enters (DNS and HTTP), escape again where it is rendered, and show bidirectional and zero-width characters as visible escapes so a file named `invoiceXXXgpj.exe` cannot masquerade as a document. HTML reports escape every value, contain no scripts, and carry a Content-Security-Policy that forbids loading anything.

**Negatives are reported honestly.** DKIM selectors cannot be listed through DNS, so "no DKIM key found" is an informational finding with no score penalty and a note about custom selectors. Triage never returns "safe", only `no strong indicators`, and every report carries a disclaimer.

**Scoring is simple and visible.** Fixed deductions per severity, informational findings are free, and rules that only matter in context are suppressed in that context. For example, SPF softfail costs nothing when DMARC enforces, and a no-mail domain is not nagged about reporting addresses.

## What testing against reality found

- **Running the audit on `example.com`** showed 20 separate "revoked DKIM key" findings. IANA publishes a wildcard revocation, which is the recommended setup for a domain that sends no mail. The first design assumed revoked keys were noteworthy. The fix grouped revoked selectors into one finding and added null-sender detection, which recognizes the whole no-mail pattern and skips checks that do not apply.
- **A fixture-based test** showed the payment-change rules missed "update **our** wire instructions", one of the most natural fraud phrasings, and only matched the account and routing numbers in one order. The patterns were fixed and tests were added for each phrasing.
- **Spot-checking ordinary business mail** showed "The closing dinner is at 7pm. Wire me the photos." tripping the closing-wire rule, because the verb "wire" appeared near "closing". The rule now requires money-wire wording, with a regression test for the benign case.
- **One of the tests was itself wrong** (a "homoglyph" example that actually inserted a letter). The tool correctly reported it as a one-character edit, which is a reminder that a failing test is not always a bug in the code.
- **Adversarial input** (hundreds of thousands of repeated words, tens of thousands of unterminated tags) completes in well under a second, because the patterns use bounded windows and scanned text is capped.

## Known weaknesses and next steps

- Wording rules are keyword patterns. They are explainable and cheap, but easy to evade with paraphrase, and finance mail can match legitimately. They are scored as a reason to verify, and a wording hit alone only reaches `suspicious`.
- Organizational-domain matching uses a short suffix list instead of the public suffix list.
- Look-alike detection needs the operator to declare their own domains.
- Next: an HTML triage report to match the audit report, batch triage of a folder with a summary table, and DNSSEC and DANE checks in the audit.
