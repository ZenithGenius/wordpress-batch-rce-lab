#!/usr/bin/env bash
# Restores the pristine, vulnerable class-wp-rest-server.php (undoes apply-fix.sh)
# by extracting the untouched file straight from the vulnerable Docker image,
# never by counting lines in an already-edited file.
set -euo pipefail

IMAGE="${WP_IMAGE:-wordpress:7.0.1-php8.3-apache}"
TARGET=/var/www/html/wp-includes/rest-api/class-wp-rest-server.php
TMP="$(mktemp)"

CID=$(docker create "${IMAGE}")
docker cp "${CID}:/usr/src/wordpress/wp-includes/rest-api/class-wp-rest-server.php" "${TMP}"
docker rm "${CID}" >/dev/null

docker cp "${TMP}" "$(docker compose ps -q wp):${TARGET}"
rm -f "${TMP}"

echo "restored the pristine vulnerable source from ${IMAGE}. Verify with ./probe.sh"
