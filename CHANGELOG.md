# PenScope Changelog

## v5.8.0 — Stealth, Persistence, HAR Import, Nuclei Export, UX polish

This release addresses every issue I identified in my own 7.5/10 rating. **No features were
removed** — every v5.7 capability is preserved and extended.

### Stealth mode for probing

New checkbox in the probe dropdown. When enabled:
- `delay()` adds 0–80% jitter to every inter-step pause, breaking up the probe's cadence
- Every 10 requests, a 200–800ms random pause is injected
- Persisted to `chrome.storage.local` so it survives across sessions

Result: WAFs that pattern-match rapid sequential scans (e.g. `/admin`, `/.env`, `/.git` HEADs in
sequence) see a much more organic-looking request pattern. Turns a 10-of-10 signature into a 3-of-10.

### Session persistence (chrome.storage.session)

Background state is now periodically serialized to `chrome.storage.session`, which survives
service worker restarts (but clears on browser close, which is the correct lifetime for a recon
tool). The debounced `markDirty()` / `flushDirty()` pipeline trims large arrays before writing to
stay under the quota:

| Field                | Cap  |
|----------------------|------|
| endpoints            | 500  |
| apiResponseBodies    | 60   |
| postBodies           | 100  |
| discoveredRoutes     | 800  |
| scriptSources        | 300  |
| consoleLogs          | 150  |
| perfEntries          | 200  |
| headerIntel          | 150  |

On service worker startup, `restoreStateOnStartup()` reads every `ps:tab:*` key back into the
in-memory `state` object and rebuilds the `endpointIndex` Map from the serialized endpoints.
Previously every 5-minute idle wiped your findings — now they survive.

`chrome.tabs.onRemoved` removes the corresponding session storage entry so closed tabs don't
accumulate.

### Deep tab filter + collapsible sections

The Deep tab (the tab with 40+ data sections) now has:

- **Live filter input**: substring-matches across every rendered section. Hides sections that
  don't contain the query, shows everything when cleared.
- **Clickable section titles**: every `.hs-t` title is now a toggle that collapses/expands its
  section. Collapsed state is tracked in a `_collapsedSections` Set so it survives re-renders.
- **⊕ All / ⊖ All buttons**: one-click expand-all or collapse-all for rapid triage.
- **Visual affordances**: collapsed sections show `▸` instead of `▾` and dim their title.

CSS rules ensure the collapse respects the existing section nesting (source map trees, grouped
headers, etc.) without breaking any existing click handlers (data-copy, data-toggle, data-dlmap,
data-decodeidx). Interactive elements inside titles are explicitly ignored by the collapse click
handler.

### Nuclei template export

New "⚔️ Nuclei Templates (.yaml)" export option generates a multi-document YAML file with one
template per high-severity finding class:

1. **Broken Access Control** — probe BAC hits → access-control templates
2. **Auth Removal** — endpoints returning 200 without credentials → broken-auth templates
3. **IDOR** — auto-test hits with confirmed ID substitution → idor templates
4. **CORS reflection** — reflected origins (especially with credentials) → cors templates
5. **Open Redirects** — redirect parameters that accept `evil.com` → open-redirect templates
6. **CSRF validation gaps** → csrf templates
7. **Method tampering** — endpoints that accept unexpected verbs → method-override templates
8. **Secret exposure** — recursive-probe findings → word-match sensitive-data templates

Output is directly usable with `nuclei -u <target> -t ./penscope_<host>_nuclei.yaml`. Each template
includes the PenScope detection as a reference so findings can be cross-validated.

### HAR import

New "📥 Import HAR..." option. User selects a Burp/ZAP/DevTools HAR capture (`.har` or `.json`),
and the background `importHar` handler replays every entry into state:

- **Endpoints** added with method, status, size, host, tags
- **Query params** extracted
- **POST bodies** captured with content-type detection and JSON body param extraction
- **Auth headers** (Authorization, X-API-Key, X-Auth-Token, Cookie, etc.) captured
- **Response bodies** scanned through the full `scanResponseBody` + `deepScanBody` pipeline
- **JS files** grep'd via `scanScriptViaNetwork` for endpoints and secrets
- **Security headers** analyzed via `analyzeCSP` for the main frame

This decouples PenScope from "must have a live tab" — you can analyze captures from other tools,
share scans between team members, or run post-hoc analysis on historical traffic. File size cap
is 50MB and entry cap is 5000.

### Severity confidence weighting

New `weighSeverity(baseSev, context)` helper + `looksLikeTestValue(v)` heuristic. Findings now get
upgraded or downgraded based on where they were found:

- **+1 severity**: in cookie / auth header / authenticated API response
- **+1 severity**: value looks like a live JWT (three base64 parts)
- **-1 severity**: in a code comment or TODO
- **-1 severity**: stack trace / SQL error on a 2xx response (likely a log, not a real error)
- **-1 severity**: value matches test patterns (`test@`, `example.com`, `john.doe`, `lorem`, etc.)

Applied to `scanResponseBody()` — the noisiest regex scanner in the codebase. Other scanners
retain their existing severity until the next refinement pass.

### Architecture notes

- **No breaking changes**: `runProbe` signature gained a 5th parameter (`stealth`) but remains
  backward compatible — missing args default to false.
- **State restoration**: happens at module load via `restoreStateOnStartup()` which reads
  `chrome.storage.session` and rebuilds `state[tabId]` + `endpointIndex` Maps (which don't
  serialize). Runs before any message handler could be invoked.
- **Debounced persistence**: `markDirty(tabId)` is called from `getData` and probe result merging.
  The 5-second debounce + 5-second timer means a rapid sequence of updates produces at most one
  write per tab per 5 seconds.
- **Deep tab filter scope**: applies to top-level `.hs` sections only. Sub-sections collapsed by
  existing `data-toggle` handlers are respected independently.

## v5.7.0 — Custom Headers + Smart Recursive Probing

### The headline feature: recursive API discovery

PenScope already discovered endpoints from source maps, swagger specs, GraphQL introspection, and
JS grep — but never actually *called* them. v5.7 adds a three-wave recursive probe (`Step 30`) that
closes the loop:

- **Wave 1**: Seeds every unobserved endpoint from swagger paths, source-map endpoints, suffix-brute
  hits, well-known probes, GraphQL introspection, and passively discovered routes. Filters out
  templated paths, static assets, and destructive endpoints (the last gated on `aggroLevel="full"`).
  GETs each one, captures the response, scans for secrets/tokens/PII, and extracts new URLs
  referenced inside the response body.
- **Wave 2**: Takes every URL that Wave 1 extracted from response bodies and probes those. More
  responses → more URL extraction → more findings.
- **Wave 3**: One more pass using URLs discovered in Wave 2. Hard budget caps prevent runaway.

Per-wave budgets scale with aggro level:
| Level   | Wave 1 | Wave 2 | Wave 3 | Total |
|---------|--------|--------|--------|-------|
| careful | 20     | 15     | 10     | 45    |
| medium  | 40     | 25     | 15     | 80    |
| full    | 60     | 40     | 25     | 125   |

Findings inside recursive responses **bubble up into the main Secrets tab**. Discovered URLs
**bubble up into the Discovered Routes list**. The recursive layer isn't a parallel silo — it feeds
everything back into the main data model so the final Claude report and exports include it.

Bonus: **GraphQL query field probing**. When introspection succeeds in Step 1, Wave 1 also POSTs
`{query:"{fieldName{__typename}}"}` for each introspected query field to discover which ones are
reachable without arguments or auth — exposing data that normally requires construction of a full
query body.

### Custom headers

New textarea in the probe dropdown menu. User pastes:

```
Authorization: Bearer eyJhbGc...
X-API-Key: abc123
X-Forwarded-For: 127.0.0.1
```

Parsed on probe start (one header per line, `Name: Value` format, `#` lines are comments), merged
into **every** probe request via a new `mergeCustomHeaders()` helper in the probe eval. User headers
win over any default probe headers (e.g., if the probe sends `Content-Type: application/json` but
the user specifies `Content-Type: application/xml`, the user's value is used).

Headers are persisted to `chrome.storage.local` — type them once, they survive across sessions.
`credentials: "include"` is always set so session cookies + custom `Authorization` headers both
flow through. The "smart recursive probing" toggle is also persisted.

### Stronger findings scanner

New `scanBodyForFindings()` helper inside the probe eval runs on every recursive response with a
20-pattern detector: auth tokens, API keys, passwords, internal IDs, emails, phones, internal URLs,
AWS ARNs, private keys, Stripe/GitHub/AWS/Google keys, hardcoded JWTs, credit cards, SSNs, stack
traces, SQL errors, admin flags, role/scope fields. Findings auto-promote into `tab.secrets` with
proper severity tagging and a `recursive:<path>` source attribution.

### Architecture notes

- **Probe eval function helpers**: `mergeCustomHeaders`, `extractUrlsFromBody`, `scanBodyForFindings`
  are defined near the top of the probe eval IIFE so every step can call them. `sf()` and `probe()`
  both merge custom headers via the new helper.
- **URL extraction regex** matches path-only strings in common API prefixes (`/api/`, `/v1/`,
  `/graphql`, `/rest/`, `/admin/`, `/internal/`, `/app/`, `/auth/`, `/user/`, `/account/`, `/public/`).
  Static assets and templated paths are excluded. Capped at 50 URLs per body to prevent explosion.
- **`shouldProbe()` filter** refuses already-observed paths, static assets, templated paths with
  `{foo}` or `:bar` placeholders, and destructive endpoints outside `full` mode. Prevents wasted
  requests and accidental DoS on the target.
- **Feedback loop**: `runProbe()`'s result merge walks every wave's hits, pushes new discovered
  routes into `tab.discoveredRoutes` (with per-wave source attribution), and pushes findings into
  `tab.secrets` with `recursive:` source. The main Claude export and `/report` naturally include
  everything because they read from the already-enriched state.
- **New `runProbe` signature**: `runProbe(tabId, aggroLevel, customHeaders, recursive)`. Backward
  compatible — missing params default to empty / enabled.

## v5.6.0 — Correctness + Reconstruction

### Critical fixes

- **WASM / binary response body decoding (`Network.loadingFinished`)** — CDP returns non-UTF-8 bodies
  (WASM, images, fonts, protobuf) with `result.base64Encoded = true`. The old handler treated every body
  as plain text, silently corrupting pattern scans on binary content. WASM modules now decode
  server-side via `processWasmBinary()`, extract toolchain signatures (Rust/Emscripten/AssemblyScript/
  Go/LLVM), strings, crypto/mining indicators, magic bytes, and section counts — all without a
  page-context re-fetch. Non-WASM binary bodies are skipped instead of corrupted.

- **`mineMemoryStrings` anchored-regex miss** — the old scanner only matched values that were
  *entirely* a secret (`val === "AKIA..."`). Real secrets almost always live embedded in headers,
  nested JSON, cookie blobs, or stringified config. Rewritten to substring-scan, JSON.stringify
  nested objects in one pass, walk 6 levels deep with a 300-finding cap, and check inline scripts,
  data-* attributes, decoded-cookie values, and hidden inputs. Findings are promoted into the main
  secrets list with proper severity tagging.

- **SPA coverage snapshot never refreshed** — the old flow started `Profiler.startPreciseCoverage` on
  the first `Page.frameNavigated`, took one snapshot at 10s after load, then disabled the profiler.
  Client-side navigations produced zero new coverage data. Now: profiler stays running for the tab
  lifetime; `Page.frameNavigated` (main-frame) triggers a merging snapshot (throttled to 10s) and a
  re-run of runtime extraction (routes, stores, services, secrets) so SPA route changes reflect the
  current state instead of the initial page.

### New passive capabilities

- **GraphQL operation extractor (`extractGraphQLOps`)** — parses every captured POST body for
  `query`/`mutation`/`subscription` definitions, extracts operation name, type, selected fields,
  variables (with sample values), fragments, and fragment definitions. Reconstructs a usable schema
  from normal user traffic without needing `__schema` introspection. Rendered in the Deep tab, sorted
  mutations first. Included in both Claude brief and Full Report exports.

- **Symbol table (`buildSymbolTable`)** — aggregates the `names` array from every parsed source map
  and flags identifiers matching admin/auth/token/secret/debug/bypass/role/privilege/internal
  patterns. Surfaces the real pre-minification function/variable names that ordinarily require
  downloading, parsing, and grepping source maps by hand. Colour-coded by risk category in the UI.

- **Service Worker pattern detection** — added to `SCRIPT_PATTERNS` so any captured JS gets scanned
  for `registerRoute`, cache strategies, fetch/push handlers, `caches.open/match/delete`,
  `skipWaiting`, `clients.claim`, and `precacheAndRoute`. Reveals client-side proxy logic and cache
  surface for stale-auth / cache-poisoning bug classes.

- **Prototype pollution + postMessage wildcard patterns** — new `SCRIPT_PATTERNS` entries detect
  `Object.assign(obj.__proto__)`, bracket-notation `__proto__` assignment, and
  `.postMessage(data, "*")` wildcard targets in captured script sources.

### Architecture notes

- WASM binary analysis moved from a page-context `fetch()` + template-literal URL interpolation
  (which had escaping hazards on URLs containing quotes/backslashes) to a pure server-side decode
  from `Network.getResponseBody`. No page re-fetch, no injection surface.

- `runPassiveAnalysis()` now calls `extractGraphQLOps()` and `buildSymbolTable()` on every `getData`
  invocation so opening the popup picks up new GraphQL traffic + source maps without requiring a
  re-scan.

- `takeCoverageSnapshot()` split out from `runCoverageAnalysis()` so either function can be called
  directly. The snapshot function is idempotent and does not disable the profiler.

- Two new state fields on `T(tabId)`: `graphqlOps` and `symbolTable`. Both flow through `getData`
  automatically and render in the Deep tab.

## v5.5.0

- WASM hex dump + crypto detect, WebGPU, WS hijack, cache poison, timing oracle, COOP/COEP bypass,
  storage partition — 29 probe attack steps total.

## v5.4.0

- gRPC + WebAssembly + WebRTC leaks + BroadcastChannel + WebAuthn + compression oracle.

## v5.3.0

- POST body capture + API response deep scan + coverage analysis + event listeners + Shadow DOM +
  memory mining.

## v5.2.0

- IndexedDB + CacheStorage + JWT decoder + route classification + permission matrix + IDOR test
  generation.

## v5.1.0

- Full endpoint discovery + probe engine (22 attack steps).
