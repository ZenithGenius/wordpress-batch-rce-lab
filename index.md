<div class="hero">
  <div class="hero-in">
    <span class="pill">Severity: Critical</span>
    <h1>wp2shell</h1>
    <p class="lede">A pre-authentication remote-code-execution chain in WordPress core, patched July 2026. No plugin required, no misconfiguration required: a stock install of an affected version was enough. The root cause is a single missing array append in the REST API's batch endpoint.</p>
    <div class="meta">
      <div><span class="k">CVE</span><span class="v amber">2026-63030</span></div>
      <div><span class="k">Chains to</span><span class="v amber">2026-60137</span></div>
      <div><span class="k">Vulnerable</span><span class="v alert">6.9.0-6.9.4, 7.0.0-7.0.1</span></div>
      <div><span class="k">Fixed</span><span class="v ok">6.9.5, 7.0.2</span></div>
      <div><span class="k">Discovered by</span><span class="v">Adam Kues, Assetnote</span></div>
      <div><span class="k">The fix</span><span class="v ok">one line</span></div>
    </div>
  </div>
</div>

*Investigated for educational and defensive purposes. No exploit payload is published. The SQL-injection-to-RCE chain is described at a mechanism level only; see the [disclosure note](#disclosure) below.*

```mermaid
flowchart TB
    A["POST /batch/v1<br/>sub-request 0: malformed path"] --> B["wp_parse_url fails<br/>pushed to $validation only"]
    B --> C["$matches falls one short<br/>of $requests / $validation"]
    C --> D["sub-request 1 dispatches using<br/>$matches[1] = sub-request 2's handler"]
    D --> E["permission check ran for<br/>a DIFFERENT request than the one executed"]
    E --> F["CVE-2026-63030<br/>wrong-handler dispatch"]
    F --> G["chains to CVE-2026-60137<br/>SQL injection, unauthenticated"]
    G --> H["remote code execution"]
```

## Read the writeup

**[The batch mechanism](./analysis/mechanism.html).** How `WP_REST_Server::serve_batch_request_v1()` builds two parallel arrays, how one malformed sub-request desyncs them, and the exact one-line diff between vulnerable 7.0.1 and patched 7.0.2. Includes a live, safe proof against genuinely vulnerable WordPress: the same request, on the same server, answering wrong before the patch and right after it.

**[The SQL injection half](./analysis/sqli-chain.html).** CVE-2026-60137: an `is_array()`-gated sanitization bypass in `WP_Query`'s `author__not_in`, why a string value skips `absint` and lands raw in the query, and how the batch desync lifts it from an authenticated-only bug to an unauthenticated one.

**[Detection](./analysis/detection.html).** The request fingerprints for both bugs, access-log hunting queries, and the PHP error-log tells that distinguish real attack attempts from routine traffic.

**[The bug class](./analysis/bug-class.html).** Why "two arrays that must stay index-aligned" is a recurring defect pattern in request-multiplexing endpoints, and the defensive lesson that generalizes past this one CVE.

**[Indicators and mitigation](./analysis/IOCs.html).** WAF rules for nginx, Apache, and ModSecurity covering both URL shapes of the endpoint, portable Sigma and Nuclei detections, plus a drop-in mu-plugin that blocks anonymous batch calls as a stop-gap ahead of patching.

**[The reproduction lab](https://github.com/ZenithGenius/wordpress-batch-rce-lab/tree/main/batch-rce-lab).** Docker Compose running real, vulnerable WordPress 7.0.1. Safe HTTP proofs of both the batch desync and the SQLi sink toggle between vulnerable and patched source on the same running server. A standalone PHP model reproduces the array desync with no WordPress at all.

## The one-line fix

```diff
  foreach ( $requests as $single_request ) {
      if ( is_wp_error( $single_request ) ) {
          $has_error    = true;
+         $matches[]    = $single_request;
          $validation[] = $single_request;
          continue;
      }
```

That is the entire difference between WordPress 7.0.1 and 7.0.2. Before it, `$matches` and `$validation` fall out of alignment the moment a batch request contains one malformed sub-request, and the dispatch loop reads `$matches[$i]` by index, so every sub-request after the broken one runs against the wrong route and the wrong permission result.

## Who found it, who patched it

Adam Kues, Assetnote (Searchlight Cyber's attack-surface-management arm), discovered the batch-route logic bug and reported it through WordPress's HackerOne program. WordPress shipped 7.0.2 and 6.9.5 with forced automatic updates for affected sites.

## Disclosure

This writeup and lab were built after WordPress's public fix (6.8.6 / 6.9.5 / 7.0.2) and the public advisories. Both bugs are covered at a mechanism level, grounded in the real source diff. The batch desync (CVE-2026-63030) is reproduced in full because it needs only read-shaped requests to observe. The SQL injection (CVE-2026-60137) is demonstrated only far enough to prove that unsanitized input reaches the query, via a benign syntax error, extracting no data; the full SQLi-to-RCE chain is described conceptually only, and no working exploit payload is published here. If you run WordPress, update to 6.8.6, 6.9.5, or 7.0.2, or apply the mitigations linked above, before experimenting with any of this.
