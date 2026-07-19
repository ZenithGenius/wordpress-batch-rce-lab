<?php
/**
 * wp2shell (CVE-2026-63030) - the desync in ~40 lines, no WordPress needed.
 *
 * This is a faithful, self-contained model of the vulnerable loop in
 * WP_REST_Server::serve_batch_request_v1() (WordPress 6.9.0-6.9.4, 7.0.0-7.0.1).
 * It demonstrates WHY a batch sub-request is dispatched against another
 * sub-request's handler. It performs no HTTP, no SQL, and nothing dangerous:
 * it prints two arrays and shows they fall out of alignment.
 *
 * Run:  php demo-desync.php
 *
 * The real fix (7.0.2 / 6.9.5) is a single added line, applied below when
 * you pass "fixed" as an argument:  php demo-desync.php fixed
 */

$fixed = (($argv[1] ?? '') === 'fixed');

// Three sub-requests, exactly like an attacker's JSON body:
//   [0] a deliberately unparseable path  -> becomes a WP_Error
//   [1] a request the attacker wants executed
//   [2] a request whose HANDLER + permission the attacker wants to borrow
$requests = [
    ['path' => 'http://:',                        'kind' => 'ERROR (unparseable path)'],
    ['path' => '/wp/v2/attacker-controlled',      'kind' => 'attacker payload request'],
    ['path' => '/wp/v2/privileged-handler',       'kind' => 'privileged target handler'],
];

// --- First loop: parse. An unparseable path yields a WP_Error placeholder,
//     kept IN $requests so indices line up here. (This part is not the bug.)
$parsed = [];
foreach ($requests as $r) {
    $r['is_error'] = ($r['path'] === 'http://:'); // wp_parse_url() returns false here
    $parsed[] = $r;
}

// --- Second loop: match each request to a route handler + validate perms.
$matches    = [];
$validation = [];
foreach ($parsed as $r) {
    if ($r['is_error']) {
        $validation[] = 'ERROR';
        if ($fixed) {
            $matches[] = 'ERROR';   // <-- THE FIX: 7.0.2 adds this one line
        }
        // vulnerable build: $matches is NOT appended here -> it desyncs
        continue;
    }
    // handler + permission result for THIS request
    $matches[]    = "handler(" . $r['path'] . ")";
    $validation[] = "perm-checked-for(" . $r['path'] . ")";
}

// --- Dispatch loop: reads $matches[$i] and $validation[$i] by the SAME index
//     into $requests. If the arrays are misaligned, a request runs under the
//     wrong handler while carrying another request's permission result.
echo $fixed ? "=== PATCHED (7.0.2 / 6.9.5) ===\n" : "=== VULNERABLE (7.0.1 / 6.9.4) ===\n";
printf("%-3s | %-32s | %-28s | %s\n", "i", "request being dispatched", "handler used (\$matches[i])", "perm used (\$validation[i])");
echo str_repeat('-', 110) . "\n";

$hijacked = false;
foreach ($parsed as $i => $r) {
    if ($r['is_error']) {
        printf("%-3d | %-32s | %-28s | %s\n", $i, $r['kind'], '(error response)', '(error response)');
        continue;
    }
    $handler = $matches[$i]    ?? '(none)';
    $perm    = $validation[$i] ?? '(none)';
    $mismatch = (strpos($handler, $r['path']) === false);
    if ($mismatch) { $hijacked = true; }
    printf("%-3d | %-32s | %-28s | %s%s\n", $i, $r['path'], $handler, $perm,
        $mismatch ? '   <== MISMATCH' : '');
}

echo "\n";
if ($hijacked) {
    echo "RESULT: request index 1 was dispatched against the handler of a DIFFERENT\n";
    echo "        request. The permission check that passed belonged to the wrong\n";
    echo "        request, so an operation is waved through unauthenticated.\n";
} else {
    echo "RESULT: every request ran against its own handler and its own permission\n";
    echo "        check. No hijack. This is the patched behaviour.\n";
}

// ponytail: one runnable check - the whole point is that vuln desyncs and fix doesn't.
// Invariant: in the vulnerable model a mismatch MUST occur; in the fixed one it must NOT.
$assert_expect = $fixed ? false : true;
if ($hijacked !== $assert_expect) {
    fwrite(STDERR, "SELF-CHECK FAILED: expected hijacked=" . var_export($assert_expect, true) . "\n");
    exit(1);
}
