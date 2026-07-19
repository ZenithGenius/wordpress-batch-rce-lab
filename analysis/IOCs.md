---
title: "Indicators and mitigation"
description: "Request fingerprints, WAF rules for nginx/Apache/ModSecurity, and a drop-in mu-plugin for CVE-2026-63030, the WordPress REST batch-endpoint array desync."
---

# Indicators and mitigation

There is no malware here, no C2 infrastructure, no attacker-owned domains. This is a WordPress core logic bug; the indicators are request shapes and version numbers, and the mitigations are configuration, not detection signatures for implants.

## The endpoint, two shapes

Both resolve to the same handler. WAF and detection rules that cover only one leave the site exposed through the other.

```
/wp-json/batch/v1
/?rest_route=/batch/v1
```

## Request fingerprint

An exploitation attempt is a **POST**, anonymous, to one of the two paths above, with a JSON body whose `requests` array contains a sub-request with a `path` that fails to parse, positioned before the sub-request the attacker wants mishandled.

```json
{"path": "http://:"}
```

is the simplest such value: `wp_parse_url()` rejects it and WordPress records a `parse_path_failed` error, which is the trigger for the array desync. Any anonymous batch call carrying this shape, or any deliberately malformed `path`, is not routine traffic.

| Signal | Benign batch call | wp2shell attempt |
|---|---|---|
| Auth | Logged-in, valid `X-WP-Nonce` | Anonymous |
| `path` values | Real routes | Includes an unparseable path |
| Source | Editor/admin sessions, browser UA | Scanners, bulk/odd UAs |

## Log hunting

```bash
# Anonymous POSTs to the batch endpoint, either URL shape
grep -E 'POST .*(/wp-json/batch/v1|rest_route=/?batch/v1)' access.log
grep -E 'rest_route=%2Fbatch%2Fv1' access.log   # URL-encoded query-string form

# If your proxy/WAF logs bodies, hunt the trigger value directly
grep -F '"path":"http://:"' waf-body.log
```

A PHP `Undefined array key` or `Trying to access array offset` warning surfacing from `class-wp-rest-server.php` during a batch call is a secondary tell on vulnerable builds, worth correlating with the access-log hit above.

## WAF rules

Block **both** URL shapes. Match on the `rest_route` parameter's value for the query-string form, not only the path.

**Nginx**

```nginx
location ~ ^/wp-json/batch/v1 {
    return 403;
}
if ($arg_rest_route ~* "^/?batch/v1") {
    return 403;
}
```

**Apache (.htaccess)**

```apache
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteRule ^wp-json/batch/v1 - [F,L]
  RewriteCond %{QUERY_STRING} (^|&)rest_route=/?batch/v1 [NC]
  RewriteRule ^ - [F,L]
</IfModule>
```

**ModSecurity**

```
SecRule REQUEST_URI "@rx /wp-json/batch/v1" \
  "id:920920,phase:1,deny,status:403,msg:'wp2shell batch endpoint (path)'"
SecRule ARGS:rest_route "@rx ^/?batch/v1" \
  "id:920921,phase:1,deny,status:403,msg:'wp2shell batch endpoint (rest_route)'"
```

These block all batch traffic, including legitimate WooCommerce/block-editor use. Test log-only first, or use the narrower mu-plugin below.

## Drop-in mitigation (mu-plugin)

Blocks only **anonymous** batch calls, so logged-in editors keep working. A stop-gap ahead of patching, not a substitute for it.

```php
<?php
/**
 * Plugin Name: wp2shell Batch Guard (mitigation)
 * Description: Rejects anonymous calls to the REST batch endpoint (CVE-2026-63030)
 *              until you can update to WordPress 7.0.2 / 6.9.5.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
    $route = $request->get_route();
    if ( is_string( $route ) && 0 === strpos( ltrim( $route, '/' ), 'batch/v1' ) ) {
        if ( ! is_user_logged_in() ) {
            return new WP_Error( 'rest_batch_forbidden', 'Batch requests are not available.', array( 'status' => 401 ) );
        }
    }
    return $result;
}, 1, 3 );
```

Full copy: [`batch-rce-lab/mitigate/mu-batch-guard.php`](https://github.com/ZenithGenius/wordpress-batch-rce-lab/blob/main/batch-rce-lab/mitigate/mu-batch-guard.php). Drop into `wp-content/mu-plugins/`.

## Confirm your own exposure

Check the running version rather than sending attack-shaped traffic at your own site:

```bash
wp core version
```

| | Range |
|---|---|
| Vulnerable | 6.9.0 - 6.9.4, 7.0.0 - 7.0.1 |
| Fixed | 6.9.5, 7.0.2 |

## MITRE ATT&CK

`T1190` Exploit Public-Facing Application ·
`T1078.001` Valid Accounts abuse enabled by permission-check bypass ·
`T1190` -> SQL injection (CVE-2026-60137) -> code execution

## Credit and reference

Discovered by Adam Kues, Assetnote (Searchlight Cyber). Reported through WordPress's HackerOne program. See the [mechanism writeup](./mechanism.html) for the full technical breakdown and a live, safe proof of the desync.
