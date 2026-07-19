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

### 4. Restore the vulnerable state (toggle back and forth freely)

```bash
./restore-vuln.sh
WP_PORT=8028 ./probe.sh    # DESYNCED again
```

`apply-fix.sh` and `restore-vuln.sh` are idempotent and can be run in either order, any number of times, to compare before/after as much as you want.

### 5. Tear down

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
probe.sh             live HTTP proof: control vs attack-shaped batch, safe (no write, no auth bypass)
apply-fix.sh         applies the real upstream one-line patch to the running container's source
restore-vuln.sh      re-extracts the pristine vulnerable file from the image, undoing apply-fix.sh
mitigate/            drop-in mu-plugin + WAF rule snippets (nginx/Apache/ModSecurity)
```
