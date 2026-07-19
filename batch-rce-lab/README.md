# wp2shell lab (CVE-2026-63030)

A safe, local reproduction of the WordPress REST batch-endpoint array desync. Runs genuinely vulnerable WordPress 7.0.1 in Docker, proves the desync over HTTP with two harmless read-shaped requests, then lets you apply the real one-line upstream patch to the same running server and watch the same request answer correctly.

See the [full technical writeup](https://zenithgenius.github.io/wordpress-batch-rce-lab/analysis/mechanism.html) for the mechanism in depth. This README only covers running the lab.

## What is and is not real here

- **The WordPress instance is real and genuinely vulnerable.** `docker-compose.yml` pulls `wordpress:7.0.1-php8.3-apache` from Docker Hub, an unmodified, officially vulnerable build.
- **The proof requests are safe.** `probe.sh` sends two batch calls using only `POST` to two harmless routes (`/wp/v2/settings`, which just refuses batch, and a nonexistent path). No write happens, no auth bypass is exercised, no SQL injection or code execution runs. The desync is visible entirely in which *error code* a route answers with.
- **The fix is the real upstream fix**, applied to the live container's own source (`apply-fix.sh`), not a swapped Docker image, because no patched image existed on Docker Hub at the time this lab was built. `restore-vuln.sh` undoes it by re-extracting the pristine file from the vulnerable image, never by editing the already-patched file in place.
- **Everything binds to `127.0.0.1`.** Nothing here reaches the internet or any real WordPress instance.

## Requirements

Docker with the Compose plugin. First run pulls the WordPress, MariaDB, and wp-cli images.

## Run it, start to finish

```bash
cd batch-rce-lab

# start clean
docker compose up -d
```

Wait for the one-time installer. It's quick, usually under 20 seconds once the DB is reachable:

```bash
docker compose logs -f wpcli    # watch for "WordPress ready", then Ctrl-C
```

```
wpcli-1  | wp2shell-lab: installing WordPress (retrying until DB is reachable)...
wpcli-1  | wp2shell-lab: WordPress ready at http://localhost:8028  (admin / labadmin)
wpcli-1  | wp2shell-lab: version = 7.0.1
```

### 1. The mechanism, offline, no Docker needed

```bash
php demo-desync.php           # reproduces the vulnerable desync
php demo-desync.php fixed     # shows the one-line fix closing it
```

A ~100-line, self-contained model of the exact loop in `WP_REST_Server::serve_batch_request_v1()`. Prints a table of which handler and permission result each request actually got, and asserts the expected outcome either way (exits non-zero if the model's own invariant breaks).

### 2. Exploitation, live, against the running container

```bash
WP_PORT=8028 ./probe.sh
```

This sends a control batch (no malformed element) and an attack-shaped batch (a deliberately malformed path first), then compares. On the vulnerable container, `/wp/v2/settings`, a route that exists, comes back with the error that belongs to the *next* sub-request's nonexistent route, proof the wrong handler answered:

```
== 2. ATTACK-SHAPED: malformed path FIRST, same two routes after. ==
  [0] malformed path 'http://:'    -> parse_path_failed
  [1] /wp/v2/settings              -> rest_no_route          <-- wrong; should be rest_batch_not_allowed
  [2] /wp/v2/this-route-does-not-exist-zz -> rest_no_route

RESULT: DESYNCED. Index [1] (/wp/v2/settings, a real route) answered with
        the error that belongs to index [2] (a route that does not exist).
```

### 3. Correction: apply the real one-line patch, live

```bash
./apply-fix.sh
WP_PORT=8028 ./probe.sh
```

Same server, same request. `/wp/v2/settings` now answers for itself:

```
== 2. ATTACK-SHAPED: malformed path FIRST, same two routes after. ==
  [0] malformed path 'http://:'    -> parse_path_failed
  [1] /wp/v2/settings              -> rest_batch_not_allowed   <-- correct now
  [2] /wp/v2/this-route-does-not-exist-zz -> rest_no_route

RESULT: ALIGNED. Index [1] answered for itself, matching the control run.
```

### 4. The SQL injection half (CVE-2026-60137)

The second bug is a SQL injection in `WP_Query`'s `author__not_in`. The `sqli/` module
deploys a lab-only plugin that forwards a request parameter into that argument, exactly
the precondition a vulnerable plugin or theme creates, and shows unsanitized input
reaching the query:

```bash
WP_PORT=8028 ./sqli/probe-sqli.sh
```

On vulnerable core, a bare-word marker reaches the SQL `WHERE` clause and breaks the
query's syntax, so the database returns an error:

```
== 2. Injection marker: exclude=wp2shell_marker) ==
  SINK: db_error
  unsanitized input reached the SQL WHERE clause.
  error: You have an error in your SQL syntax ... near ')  AND ...

RESULT: VULNERABLE. The marker reached the SQL WHERE clause verbatim ...
```

It only ever triggers a benign syntax error: it runs an ordinary `SELECT` and extracts
no data. After `./apply-fix.sh`, `wp_parse_id_list()` coerces the marker to an integer
and the error disappears.

### 5. Correction and restore (toggles BOTH CVEs)

```bash
./apply-fix.sh      # applies the real upstream fix for BOTH the batch desync and the SQLi
./restore-vuln.sh   # re-extracts pristine vulnerable source for both files from the image
```

`apply-fix.sh` and `restore-vuln.sh` are idempotent and can be run in either order, any
number of times. `apply-fix.sh` patches both `class-wp-rest-server.php` (batch) and
`class-wp-query.php` (SQLi), mirroring what updating to 7.0.2 actually does. Re-run
`./probe.sh` and `./sqli/probe-sqli.sh` to see both flip.

### 6. Portable detections

`detect/` ships Sigma rules and a non-destructive Nuclei template. The Nuclei template
was verified to fire on the vulnerable instance and stay silent once patched:

```bash
nuclei -u "http://localhost:8028" -t detect/wp2shell-batch-desync.yaml
```

### 7. Tear down

```bash
docker compose down -v      # stop everything and remove volumes
```

Every full cycle (`down -v` -> `up -d` -> install -> exploit -> fix -> restore -> `down -v`) was run start to finish while building this lab, so the sequence above is a real, verified transcript, not a description of intended behaviour.

## Mitigations

`mitigate/mu-batch-guard.php` and `mitigate/waf-rules.md` contain the same drop-in mu-plugin and WAF rules covered in [Indicators and mitigation](https://zenithgenius.github.io/wordpress-batch-rce-lab/analysis/IOCs.html). Copy `mu-batch-guard.php` into a live site's `wp-content/mu-plugins/` to test it against this lab's WordPress instance:

```bash
docker compose exec -T wp mkdir -p /var/www/html/wp-content/mu-plugins
docker cp mitigate/mu-batch-guard.php "$(docker compose ps -q wp):/var/www/html/wp-content/mu-plugins/mu-batch-guard.php"
WP_PORT=8028 ./probe.sh
```

`probe.sh` expects a per-sub-request `responses` array, so with the guard active it reports `MISSING` and falls back to printing the raw response, which is the actual proof: the whole batch call is now rejected before WordPress ever parses the sub-requests, regardless of whether the vulnerable or patched source is currently in place.

```json
{"code":"rest_batch_forbidden","message":"Batch requests are not available.","data":{"status":401}}
```

## Files

```
docker-compose.yml   wordpress:7.0.1 (real, vulnerable) + mariadb + wp-cli installer, on 127.0.0.1
.env                 image tag, host port, DB credentials
setup/wp-setup.sh    one-time WordPress install, then idle for exec
demo-desync.php      standalone PHP model of the array desync, no WordPress needed
probe.sh             live HTTP proof of the batch desync, safe (no write, no auth bypass)
sqli/                CVE-2026-60137: lab-only author__not_in sink plugin + safe probe
apply-fix.sh         applies the real upstream fix for BOTH CVEs to the running source
restore-vuln.sh      re-extracts the pristine vulnerable files from the image, undoing apply-fix.sh
detect/              portable Sigma rules + a verified non-destructive Nuclei template
mitigate/            drop-in mu-plugin + WAF rule snippets (nginx/Apache/ModSecurity)
```
