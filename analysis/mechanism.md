---
title: "The mechanism"
description: "How WP_REST_Server::serve_batch_request_v1() desyncs two parallel arrays, the exact one-line diff between vulnerable and patched WordPress, and a live, safe proof against a real vulnerable instance."
---

# The mechanism

wp2shell is two chained CVEs. CVE-2026-63030 is a logic bug in WordPress core's REST API batch endpoint that lets one sub-request dispatch under a different sub-request's route and permission check. CVE-2026-60137 is a SQL injection that becomes reachable, unauthenticated, once the permission check has been bypassed. This piece covers the first bug in full, because it is fully understood, safely reproducible, and the interesting part: a single missing line in an array-building loop.

## What the batch endpoint does

`/wp-json/batch/v1` (or `?rest_route=/batch/v1` on sites without pretty permalinks) lets a client bundle several REST sub-requests into one HTTP call. Send a JSON body shaped like this:

```json
{
  "validation": "normal",
  "requests": [
    { "method": "POST", "path": "/wp/v2/media/123" },
    { "method": "POST", "path": "/wp/v2/comments/456" }
  ]
}
```

and WordPress parses each `path`, resolves it to a route handler, checks permissions, and dispatches all of them in one response. This exists for legitimate bulk operations: the block editor and WooCommerce's Store API both use it.

## The two arrays

Inside `WP_REST_Server::serve_batch_request_v1()`, WordPress processes the parsed sub-requests in a loop that builds two parallel arrays, meant to stay index-aligned with each other and with the `$requests` array they were built from:

- **`$matches`**: the resolved route and handler for each sub-request.
- **`$validation`**: the permission-check / parameter-validation result for each sub-request.

```php
foreach ( $requests as $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        $has_error    = true;
        $validation[] = $single_request;
        continue;                              // <- $matches never gets an entry here
    }

    $match     = $this->match_request_to_handler( $single_request );
    $matches[] = $match;
    // ... permission checks, sanitization ...
    $validation[] = $error ? $error : true;
}
```

A `$single_request` is a `WP_Error` when its `path` failed to parse. That happens earlier, when WordPress calls `wp_parse_url()` on the sub-request's path: a malformed value like `http://:` makes `wp_parse_url()` return `false`, and WordPress records a `parse_path_failed` error in place of a real request object.

Look at the `is_wp_error()` branch above: it appends to `$validation`, sets `$has_error`, and `continue`s. It does **not** append anything to `$matches`. From that request onward, `$matches` has one fewer element than `$validation` and than `$requests`.

## Where the desync gets used

The dispatch loop that actually runs each sub-request reads both arrays by the same numeric index, `$i`, taken from iterating `$requests`:

```php
foreach ( $requests as $i => $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        // handled directly, doesn't touch $matches or $validation
        continue;
    }
    // ...
    $match = $matches[ $i ];        // <- reads by $requests's index
    $error = null;
    if ( is_wp_error( $validation[ $i ] ) ) {
        $error = $validation[ $i ];
    }
    // ... dispatches $single_request against $match's route and handler ...
}
```

`$validation[$i]` still lines up correctly, because every branch appends to `$validation` including the error branch. `$matches[$i]` does not, because the error branch skipped it. So `$matches[$i]` returns the entry that was actually pushed for a **different, later** sub-request; the loop dispatches the current request's body against another request's resolved route and handler, while treating it as though the current request's own permission check applies.

## Attack shape

An attacker sends a batch where the first sub-request has a deliberately unparseable path, followed by the real sub-requests they want mishandled:

```json
{
  "validation": "normal",
  "requests": [
    { "method": "POST", "path": "http://:" },
    { "method": "POST", "path": "<request the attacker wants executed>" },
    { "method": "POST", "path": "<route whose handler/permissions get borrowed>" }
  ]
}
```

Index 0 is discarded as a parse error. Index 1 now runs against the route and handler resolved for index 2's path. If index 2 targets a route with weaker or different permission requirements than index 1's own route, the operation at index 1 executes without its own, correct permission check ever having run against it.

## The live proof

No packaged patched WordPress Docker image existed at the time of writing (Docker Hub had not yet published a `7.0.2` build), so the [lab](https://github.com/ZenithGenius/wordpress-batch-rce-lab/tree/main/batch-rce-lab) proves this on the vulnerable server itself: run a genuinely vulnerable `wordpress:7.0.1` container, observe the desync over HTTP with two harmless, read-shaped requests, then apply the real one-line patch to that same running server's source and watch the identical request answer correctly.

Two fingerprint routes make the desync visible without any write or auth bypass:

| Route | Exists? | Correct standalone answer |
|---|---|---|
| `/wp/v2/settings` | yes, registered | `rest_batch_not_allowed` (400): a real route, batch not enabled for it |
| `/wp/v2/this-route-does-not-exist-zz` | no | `rest_no_route` (404) |

**Control batch** (no malformed element, both routes in order): each index answers for itself.

```json
{"responses":[
  {"body":{"code":"rest_batch_not_allowed"},"status":400},
  {"body":{"code":"rest_no_route"},"status":404}
]}
```

**Attack-shaped batch on the vulnerable server** (malformed path first, then the same two routes): index 1, `/wp/v2/settings`, a route that exists, answers `rest_no_route`, the error that belongs to index 2's nonexistent route.

```json
{"responses":[
  {"body":{"code":"parse_path_failed"},"status":400},
  {"body":{"code":"rest_no_route"},"status":404},
  {"body":{"code":"rest_no_route"},"status":404}
]}
```

**Same request, same server, after applying the real one-line patch to the running source**: index 1 answers for itself again, matching the control run exactly.

```json
{"responses":[
  {"body":{"code":"parse_path_failed"},"status":400},
  {"body":{"code":"rest_batch_not_allowed"},"status":400},
  {"body":{"code":"rest_no_route"},"status":404}
]}
```

No write happened in either state; the desync is entirely visible in which *error code* comes back for index 1. Reproduce this yourself with `batch-rce-lab/probe.sh`, toggled by `apply-fix.sh` and `restore-vuln.sh`; see the [lab README](https://github.com/ZenithGenius/wordpress-batch-rce-lab/tree/main/batch-rce-lab) for exact steps.

## The fix

Comparing the tagged WordPress source for `7.0.1` and `7.0.2` line by line, the entire patch is one added line:

```diff
  if ( is_wp_error( $single_request ) ) {
      $has_error    = true;
+     $matches[]    = $single_request;
      $validation[] = $single_request;
      continue;
  }
```

Appending the error to `$matches` too keeps every array the same length and index-aligned, so `$matches[$i]` and `$validation[$i]` always refer to the same original sub-request again.

## From desync to RCE

The desync alone lets an attacker cause a sub-request to run under the wrong permission result. That is a logic bug, not by itself remote code execution. It becomes CVE-2026-63030-to-RCE by chaining into CVE-2026-60137, a SQL injection in WordPress core reachable through a code path that expects an authenticated or otherwise-checked caller. With the batch desync waving through the permission check, that path becomes reachable anonymously; from an exploitable SQL injection to code execution on a typical WordPress/MySQL stack is a well-understood, previously-documented class of technique, not something specific to this bug. Consistent with the [disclosure note](../index.html#disclosure), the SQLi chain is described here only at this conceptual level; no working payload is published.

## Affected and fixed versions

| | Range |
|---|---|
| Vulnerable | 6.9.0 - 6.9.4, 7.0.0 - 7.0.1 |
| Fixed | 6.9.5, 7.0.2 |

Continue with [detection](./detection.html) or [indicators and mitigation](./IOCs.html).
