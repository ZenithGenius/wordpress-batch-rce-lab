---
title: "Detecting wp2shell exploitation"
description: "Log signatures, request fingerprints, and hunting queries for CVE-2026-63030 batch-endpoint abuse, plus what a benign batch call looks like so you can tell them apart."
---

# Detecting wp2shell exploitation

You cannot see the array desync from outside. What you *can* see is the request
that triggers it: a POST to the batch endpoint whose body contains a sub-request
with an unparseable path. That shape is the fingerprint.

## The request fingerprint

An exploitation attempt is a POST to one of:

- `/wp-json/batch/v1`
- `/?rest_route=/batch/v1`

carrying a JSON body with a `requests` array in which at least one element has a
malformed `path` (for example `http://:`) placed **before** the sub-request the
attacker wants mishandled. A legitimate batch call from WooCommerce or the block
editor never contains a deliberately broken path, and it arrives with a valid
`X-WP-Nonce` header from a logged-in session.

| Signal | Benign batch | wp2shell attempt |
|---|---|---|
| Authentication | Logged-in, valid `X-WP-Nonce` | None, anonymous |
| `path` values | Real routes (`/wp/v2/...`) | Includes a malformed path such as `http://:` |
| Intent of ordering | Independent operations | A broken element positioned to shift the array |
| Source | Admin/editor IPs, browser UA | Scanners, odd UAs, bulk hosts |

## Access-log hunting

The batch route rarely appears in access logs for anonymous visitors. Any anonymous
POST to it deserves a look.

```bash
# Anonymous POSTs to the batch endpoint (both URL shapes)
grep -E 'POST .*(/wp-json/batch/v1|rest_route=/?batch/v1)' access.log

# The query-string form is easy to miss if you only grep /wp-json
grep -E 'rest_route=%2Fbatch%2Fv1|rest_route=/batch/v1' access.log
```

Bodies are not in access logs. If you have a WAF or reverse proxy that captures
request bodies, hunt the malformed-path marker directly:

```
# the trigger: a path that wp_parse_url() rejects
"path":"http://:"
"path":"http:///"
```

## PHP error-log tell

On a vulnerable build, the last sub-request after the desync reads an undefined
`$matches[$i]`, which can surface as a PHP warning around the REST server during a
batch call. An `Undefined array key` or `Trying to access array offset` notice
originating from `class-wp-rest-server.php` during a batch request is worth
correlating with the access-log hit above.

## The SQL injection signature

The second bug, [CVE-2026-60137](./sqli-chain.html), has its own fingerprint. A
legitimate `author__not_in` value is only digits and commas. Anything else in that
parameter, a quote, a parenthesis, a SQL keyword, is an injection attempt.

```bash
# author__not_in carrying non-integer content
grep -E 'author__not_in[^&]*(%27|%28|%29|SELECT|UNION|SLEEP|--)' access.log
```

Plugins often map their own request parameters onto `author__not_in`, so also watch
for SQL metacharacters in any parameter feeding an author filter, not just the raw
query var name.

## Portable detection artifacts

The lab ships ready-to-run rules in [`batch-rce-lab/detect/`](https://github.com/ZenithGenius/wordpress-batch-rce-lab/tree/main/batch-rce-lab/detect):

- **Sigma** (`wp2shell-batch.sigma.yml`, `wp2shell-sqli.sigma.yml`): SIEM-portable log
  rules for the batch-endpoint abuse and the `author__not_in` injection, with a
  body-logging variant and a no-body-logging fallback.
- **Nuclei** (`wp2shell-batch-desync.yaml`): a non-destructive template that confirms
  the batch desync by observing that `/wp/v2/settings` answers with the wrong route's
  error. It sends only read/validation sub-requests and was verified to fire on a
  vulnerable instance and stay silent on a patched one.

## After the fact

wp2shell chains to a SQL injection (CVE-2026-60137) and then code execution, so a
successful intrusion looks like any WordPress compromise downstream: unexpected
admin users, new or modified plugin/theme files, unfamiliar scheduled tasks, and
outbound connections. The [companion webshell campaign writeup](https://zenithgenius.github.io/wordpress-webshell-campaign/)
covers that post-exploitation hunting in depth. The point specific to wp2shell is
the **initial access** signature above: catch the batch request and you catch it
before the shell lands.

## Confirm your own exposure, safely

Check the running version rather than probing yourself with attack traffic:

```bash
wp core version           # vulnerable: 6.9.0-6.9.4, 7.0.0-7.0.1
```

If you cannot run wp-cli, the readme and REST index disclose the version, and the
patched builds are **7.0.2** and **6.9.5**.

Continue with the [mechanism writeup](./mechanism.html) or [indicators and mitigation](./IOCs.html).
