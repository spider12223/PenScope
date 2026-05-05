# PenScope Phase 8 — Self-audit fixes

Applies the 13 confirmed bugs from the self-audit (skipping #9, which was a regex severity question that was actually correct, and #14, the cookie-value race which can't be fixed without a different architecture).

## Files touched

| File | Fixes |
|---|---|
| `src/background.js` | 1, 2, 3, 7, 8, 10, 11, 12, 15 (loader merge, CSP append, postMessage exec-loop, SSRF clause drop, Step 11 gate, request counter, replay world fallback, Symbol shadow, comment) |
| `popup.js` | 4, 13 (network-error verdict, pivot shape) |
| `src/background.js` (IDB handler) | 5, 6 (poll until settled, Accessibility.disable) |

## CRITICAL

### Fix 1 — `regex-pack.json` `respPatterns` now actually scan
`src/background.js` `_loadRegexPack`: after compile, merge `_regexPack.respPatterns` into the inline `RESP_PATTERNS` array (deduplicated by name). The 9 new patterns from Phase 4 (Spring Boot, Rails ActiveRecord, Django DEBUG, ASP.NET YSOD, Express error JSON, Apollo "Did you mean", MSSQL, AWS request ID body, GCP trace ID body, Sentry event ID body) are now consumed by `scanResponseBody()` on every captured response.

```js
if(typeof RESP_PATTERNS!=="undefined"&&Array.isArray(RESP_PATTERNS)){
  const have=new Set(RESP_PATTERNS.map(p=>p.name));
  let added=0;
  _regexPack.respPatterns.forEach(p=>{
    if(have.has(p.name))return;
    RESP_PATTERNS.push({name:p.name,regex:p.regex,sev:p.severity||"medium",desc:p.desc||p.name});
    added++;
  });
  if(added)console.log("[PenScope] regex-pack: merged "+added+" respPatterns into RESP_PATTERNS (total "+RESP_PATTERNS.length+")");
}
```

`SCRIPT_PATTERNS` was not extended in Phase 4, so no merge needed there. Content-script secret scanning was already pulling the pack via `getRegexPack` message, so secrets were never broken.

## HIGH

### Fix 2 — CSP violations now append, not replace
`src/background.js` `reportContentScan` handler: introduced `_APPENDABLE` set containing `cspViolations`. Listed fields are concatenated (cap 200, sliced FIFO) rather than replacing. Phase 2's 10/sec throttle now cooperates correctly with this handler.

### Fix 3 — postMessage origin-check loop uses real match indices
Step 44 (`R.postMessageRiskResults`): replaced `t.match(...).forEach(...)` (which always re-finds the first match) with `regex.exec` in a `while` loop. Each iteration uses `m.index` for the actual match position, so multi-listener scripts get accurate per-listener safety analysis.

### Fix 4 — Unauth-replay verdict guards against network errors
`popup.js` `_runUnauthReplay`: added explicit branch for `cred.status === 0 || omit.status === 0`. Both fetches failing now produces "⚠ Network error — verify manually" with the actual error messages, instead of falsely claiming "auth not enforced". Also surfaces which `world` ran the replay (main vs isolated) in the alert text.

## MEDIUM

### Fix 5 — IDB capture polls until settled
`captureIdb` handler: replaced single 1500ms `setTimeout` with a polling state machine that captures `t.indexedDBData`'s JSON-fingerprint length, polls every 500ms (max 10 attempts = 5s total), and finalizes when the fingerprint hasn't changed for 2 consecutive checks AND differs from the pre-capture state. The final snapshot includes `attempts` and `settledFor` counts so the user can see whether the capture had time to settle. Falls back to "polling timeout — capture may be partial" note after 10 attempts.

### Fix 6 — `Accessibility.disable` after extraction
`extractAriaLabels`: added `_disableAcc()` helper called after `getFullAXTree` resolves (success OR error path). Releases the CDP domain so the SW isn't holding it open for the tab's lifetime.

### Fix 7 — SSRF heuristic clause (b) removed
Step 37: dropped the broken "2xx + body doesn't echo payload prefix" clause. Cloud-metadata responses literally include `169.254.169.254` in their body content, so the inverted check made the most-likely-true-positive case fail to flag. Kept clause (a): the keyword regex match (`instance-id|metadata-flavor|computeMetadata|169\.254\.169\.254|ami-id|iam/security-credentials|access-token`). Findings that match clause (a) are now severity `critical` with note "Cloud metadata content reflected — confirmed SSRF" (was previously a mix of critical and medium based on which clause fired).

### Fix 8 — Step 11 (Content-Type Confusion) tier-gated at step level
Wrapped step 11 in `if(!gate("POST",ctx.aggroLevel).allow){R.errors.push("STEP 11 skipped: ...");}else{...}`. In Careful tier, the step skips entirely instead of pushing 80 gated requests through `sf()`. `R._tierBlocked` and `R.errors` stay clean.

## LOW

### Fix 10 — `R.requests++` counts once per call
Moved increment outside the retry loop so a single `sf()` call counts as 1 request regardless of how many 429-backoff retries happened.

### Fix 11 — `replayUnauth` MAIN→ISOLATED fallback
Hardened the handler to try `world:"MAIN"` first, fall back to default (ISOLATED) on either rejection or empty result. Result includes `_world: "main"` or `_world: "isolated"` for diagnostic visibility. ISOLATED-world fetch still receives session cookies via `credentials:"include"` (cookies are origin-scoped, not world-scoped).

### Fix 12 — `Symbol` shadow added
`var fetch=_F,...,RegExp=_Re,Symbol=_Sym;` — the `_Sym=window.Symbol` snapshot was already captured but never aliased. Now `for...of` loops and `[...arr]` spread inside the IIFE use the captured `Symbol.iterator` instead of the (potentially page-overridden) global.

### Fix 13 — Auto-pivot suggestions accept both string and object subdomains
`_autoPivotSuggestions` now maps `subs` through `typeof s === "string" ? s : (s && s.host) || ""` before filtering. Future-proofed against a refactor that pushes `{host, source}` objects into `tab.subdomains`.

### Fix 15 — Stale `red-attacks.js` comment removed
Updated the comment block above the import to reflect that the standalone mirror file was removed in Phase 6.

## Skipped (with reason)

- **#9 JWT regex permissiveness**: I marked this as "skip" in the audit because empty signatures rarely match anyway, and a forged `alg:none` token IS legitimately critical when paired with admin claims — that's exactly what `_enrichJwt`'s severity bump targets. The "bug" was really a behavior question; the answer is: this is intended.
- **#14 Cookie value precedence**: chrome.cookies.getAll and CDP Network.getCookies can race against actual cookie rotation. Picking one source as canonical is semantically wrong; merging fields from both as I did in Phase 6 is the best available design without rebuilding the cookie pipeline. Documented behavior, not a fixable bug.

## Verification

1. **Pack patterns scan responses.** Visit a Spring-Boot 5xx page (anything `/actuator/*` returning a 500 in dev). Deep mode → trigger the request. Open Secrets / Response Body tab. Expected: a "Spring Boot error" finding appears (was missing before Fix 1).
2. **CSP events accumulate.** On a CSP-chatty page (an embedded YouTube or analytics-heavy SaaS), open the popup, scan, and check `chrome.storage.session.get(null).then(r=>{const k=Object.keys(r).find(x=>x.startsWith("ps:tab:"));console.log(r[k]?.cspViolations?.length);})`. Expected: more than 10 entries; previously capped at the last batch.
3. **postMessage count is accurate.** On a target with 3+ `addEventListener("message")` calls, only some with origin checks: probe → Deep tab → "postMessage Origin-Check Correlation". Expected: `withoutOriginCheck` reflects the actual unsafe count, not just "all unsafe" or "all safe" based on the first listener.
4. **Network-error replay.** Find an endpoint that errors on fetch (e.g. corsblock.example.com). Click `unauth`. Expected: alert reads "⚠ Network error — verify manually" with the actual fetch error string. Was previously "🚨 IDENTICAL — auth not enforced".
5. **IDB diff settles correctly.** Open Slack web. Capture IDB. Send a message. Capture again. Diff. Expected: changes reflect actual store-row deltas. The capture response now includes `attempts` and `settledFor` counts (visible if you copy the snap data).
