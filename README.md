# wp2shell: WordPress Batch RCE

A technical breakdown of CVE-2026-63030, a logic bug in WordPress core's REST API batch endpoint that lets an anonymous request dispatch under a different request's route and permission check, chaining into CVE-2026-60137 (SQL injection) for unauthenticated remote code execution on a stock install. Patched in WordPress 7.0.2 / 6.9.5, July 2026.

> **Disclosure.** This writeup and lab were built after WordPress's public fix and Searchlight Cyber's public advisory. The array-desync mechanism is reproduced in full and safely: it needs only read-shaped requests to observe. The SQL-injection-to-RCE chain is described at a mechanism level only; no working exploit payload is published here.

## The writeup

1. **[The mechanism](./analysis/mechanism.md)**. How `WP_REST_Server::serve_batch_request_v1()` desyncs two parallel arrays, the exact one-line diff between vulnerable 7.0.1 and patched 7.0.2, and a live proof against genuinely vulnerable WordPress.
2. **[Detection](./analysis/detection.md)**. Request fingerprint, access-log hunting queries, the PHP error-log tell.
3. **[Indicators and mitigation](./analysis/IOCs.md)**. WAF rules (nginx/Apache/ModSecurity) and a drop-in mu-plugin.

## The lab

**[`batch-rce-lab/`](./batch-rce-lab/)**. Docker Compose running real, vulnerable WordPress 7.0.1. A safe HTTP proof toggles the running server between vulnerable and patched source and shows the response flip. A standalone PHP model reproduces the desync with no WordPress at all. Full run-through in [`batch-rce-lab/README.md`](./batch-rce-lab/README.md).

## Read online

Published via GitHub Pages: `https://zenithgenius.github.io/wordpress-batch-rce-lab/`

## Credits

Vulnerability discovered by Adam Kues, Assetnote (Searchlight Cyber), reported via WordPress's HackerOne program. Writeup and lab by Isaac Joumessi. For educational and defensive use only.
