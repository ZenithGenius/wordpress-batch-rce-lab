# WAF and web-server rules for wp2shell (CVE-2026-63030)

The batch endpoint is reachable by **two** URL shapes. Blocking only `/wp-json/`
leaves the query-string route wide open, which is the single most common mistake.
Block **both**:

- `/wp-json/batch/v1`
- `/?rest_route=/batch/v1` (also `?rest_route=/batch/v1`)

Match on the `rest_route` **parameter value**, not just the path, because the second
form carries the route in the query string.

## Nginx

```nginx
# Deny the pretty-permalink form
location ~ ^/wp-json/batch/v1 {
    return 403;
}
# Deny the query-string form (rest_route=/batch/v1, URL-encoded or not)
if ($arg_rest_route ~* "^/?batch/v1") {
    return 403;
}
```

## Apache (.htaccess)

```apache
<IfModule mod_rewrite.c>
  RewriteEngine On
  # pretty-permalink form
  RewriteRule ^wp-json/batch/v1 - [F,L]
  # query-string form
  RewriteCond %{QUERY_STRING} (^|&)rest_route=/?batch/v1 [NC]
  RewriteRule ^ - [F,L]
</IfModule>
```

## ModSecurity

```
SecRule REQUEST_URI "@rx /wp-json/batch/v1" \
  "id:920920,phase:1,deny,status:403,msg:'wp2shell batch endpoint (path)'"
SecRule ARGS:rest_route "@rx ^/?batch/v1" \
  "id:920921,phase:1,deny,status:403,msg:'wp2shell batch endpoint (rest_route)'"
```

## Caveats

- These rules block **all** batch traffic. If the site uses WooCommerce Store API
  or block-editor batch saves, prefer the `mu-batch-guard.php` drop-in (blocks only
  anonymous callers) or patch. Test in log-only mode first.
- A WAF rule is a shield, not a fix. Update to **7.0.2 / 6.9.5** as the real remedy.
