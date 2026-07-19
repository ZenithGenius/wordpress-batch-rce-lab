#!/usr/bin/env bash
# Applies the REAL upstream one-line fix (7.0.2 / 6.9.5) to the live, running
# WordPress container's source. No patched Docker image exists on Docker Hub
# yet, so this lab proves the fix the honest way: the exact line WordPress
# added, applied to the exact vulnerable file, on the same running server.
# Idempotent: safe to run twice.
set -euo pipefail

TARGET=/var/www/html/wp-includes/rest-api/class-wp-rest-server.php

# The 4-line block below appears exactly once in the vulnerable file: the
# early-return branch for an unparseable sub-request. A second, unrelated
# "$has_error = true;" exists further down (a different branch that already
# appends to $matches correctly), so a plain single-line anchor would patch
# both spots and corrupt the second. Match the full 4-line block instead.
docker compose exec -T wp perl -0777 -pi -e '
  my $done = 0;
  s/(if \( is_wp_error\( \$single_request \) \) \{\n\t{4}\$has_error    = true;\n)(\t{4}\$validation\[\] = \$single_request;\n\t{4}continue;)/
    $done++;
    $1 . "\t\t\t\t\$matches[]    = \$single_request;\n" . $2
  /e;
  print STDERR ($done ? "patched\n" : "pattern not found (already patched, or file layout differs)\n");
' "${TARGET}"

echo "applied the one-line fix (7.0.2 / 6.9.5 behaviour). Verify with ./probe.sh"
