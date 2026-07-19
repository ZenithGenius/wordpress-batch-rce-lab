#!/usr/bin/env bash
# Restores the pristine, vulnerable core files (undoes apply-fix.sh) by extracting
# the untouched files straight from the vulnerable Docker image, never by editing
# an already-patched file in place. Covers both wp2shell CVEs.
set -euo pipefail

IMAGE="${WP_IMAGE:-wordpress:7.0.1-php8.3-apache}"
WPID="$(docker compose ps -q wp)"

FILES="
wp-includes/rest-api/class-wp-rest-server.php
wp-includes/class-wp-query.php
"

CID=$(docker create "${IMAGE}")
for f in ${FILES}; do
  TMP="$(mktemp)"
  docker cp "${CID}:/usr/src/wordpress/${f}" "${TMP}"
  docker cp "${TMP}" "${WPID}:/var/www/html/${f}"
  rm -f "${TMP}"
  echo "restored: ${f}"
done
docker rm "${CID}" >/dev/null

echo "restore: done (both CVEs). Verify with ./probe.sh and ./sqli/probe-sqli.sh"
