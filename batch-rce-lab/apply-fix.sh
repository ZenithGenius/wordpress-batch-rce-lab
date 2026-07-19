#!/usr/bin/env bash
# Applies the REAL upstream fixes for BOTH wp2shell CVEs to the live, running
# WordPress container's source. No patched Docker image exists on Docker Hub yet,
# so this lab proves the fixes the honest way: the exact changes WordPress made,
# applied to the exact vulnerable files, on the same running server.
#   CVE-2026-63030  batch array desync   -> wp-includes/rest-api/class-wp-rest-server.php
#   CVE-2026-60137  author__not_in SQLi  -> wp-includes/class-wp-query.php
# Idempotent: safe to run twice. Undo with ./restore-vuln.sh.
set -euo pipefail

REST=/var/www/html/wp-includes/rest-api/class-wp-rest-server.php
QUERY=/var/www/html/wp-includes/class-wp-query.php
WPID="$(docker compose ps -q wp)"

# --- CVE-2026-63030: add the missing $matches[] append in the error branch. ---
# The 4-line block appears exactly once; a bare "$has_error = true;" anchor would
# also hit an unrelated branch further down, so match the whole block.
docker compose exec -T wp perl -0777 -pi -e '
  my $done = 0;
  s/(if \( is_wp_error\( \$single_request \) \) \{\n\t{4}\$has_error    = true;\n)(\t{4}\$validation\[\] = \$single_request;\n\t{4}continue;)/
    $done++;
    $1 . "\t\t\t\t\$matches[]    = \$single_request;\n" . $2
  /e;
  print STDERR ($done ? "patched: batch desync (CVE-2026-63030)\n" : "batch: pattern not found (already patched?)\n");
' "${REST}"

# --- CVE-2026-60137: replace the is_array-gated block with an unconditional ---
# wp_parse_id_list() coercion (upstream 7.0.2 intent). Done host-side in Python
# for an exact, escape-safe block match rather than fragile in-shell regex.
TMP="$(mktemp)"
docker cp "${WPID}:${QUERY}" "${TMP}"
python3 - "${TMP}" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
vuln = (
    "\t\t\tif ( is_array( $query_vars['author__not_in'] ) ) {\n"
    "\t\t\t\t$query_vars['author__not_in'] = array_unique( array_map( 'absint', $query_vars['author__not_in'] ) );\n"
    "\t\t\t\tsort( $query_vars['author__not_in'] );\n"
    "\t\t\t}\n"
    "\t\t\t$author__not_in = implode( ',', (array) $query_vars['author__not_in'] );\n"
)
fixed = "\t\t\t$author__not_in = implode( ',', wp_parse_id_list( $query_vars['author__not_in'] ) );\n"
if vuln in s:
    open(p, "w").write(s.replace(vuln, fixed, 1))
    sys.stderr.write("patched: author__not_in SQLi (CVE-2026-60137)\n")
elif fixed in s:
    sys.stderr.write("sqli: already patched\n")
else:
    sys.stderr.write("sqli: pattern not found (file layout differs)\n")
PY
docker cp "${TMP}" "${WPID}:${QUERY}"
rm -f "${TMP}"

echo "apply-fix: done (both CVEs). Verify with ./probe.sh and ./sqli/probe-sqli.sh"
