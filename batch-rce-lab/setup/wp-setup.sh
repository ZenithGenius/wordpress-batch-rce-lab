#!/bin/sh
# Wait for core files + DB, install WordPress once, then idle for exec.
set -e

echo "wp2shell-lab: waiting for WordPress core files..."
until wp core is-installed >/dev/null 2>&1 || [ -f /var/www/html/wp-load.php ]; do
  sleep 2
done

if ! wp core is-installed >/dev/null 2>&1; then
  # Drive install via the PHP mysqli driver in a retry loop. Do NOT use
  # `wp db check` here: it shells out to the mysql client, which fails against
  # mariadb:10.11 with an SSL error and would loop forever.
  echo "wp2shell-lab: installing WordPress (retrying until DB is reachable)..."
  until wp core install \
        --url="http://localhost:${WP_PORT}" \
        --title="wp2shell lab" \
        --admin_user=admin \
        --admin_password=labadmin \
        --admin_email=admin@example.test \
        --skip-email >/dev/null 2>&1; do
    sleep 3
  done
  # Permalinks off (?rest_route= style) so the endpoint is reachable either way.
  wp rewrite structure '' >/dev/null 2>&1 || true
fi

echo "wp2shell-lab: WordPress ready at http://localhost:${WP_PORT}  (admin / labadmin)"
echo "wp2shell-lab: version = $(wp core version)"
# idle
tail -f /dev/null
