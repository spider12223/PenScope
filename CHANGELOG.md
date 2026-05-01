# PenScope Changelog

## v6.2.2 — Hunt Mode: report quality + false-positive filters

User exported drafts from a real Hunt Mode run on a government LMS and immediately
spotted four bugs that would have made the reports embarrassing to submit. Real
critical findings were buried in noise. Fixed each one.

### Bug 1 (CRITICAL): repro curls used placeholder `https://target.tld`

The chain analyzer's `baseUrl` derivation used a fragile string-split that fell back
to `"https://target.tld"` when `tab.url` was unparseable or empty. Every drafted
report's curl pointed at a domain that doesn't exist — anyone trying to reproduce
would hit `ERR_NAME_NOT_RESOLVED`.

**Fix**: proper URL parsing via `new URL(tab.url).origin`, with a fallback to the
first observed endpoint's host. Final fallback is the obviously-fake string
`https://<TARGET-HOST-NOT-DETECTED>` so the failure is visible rather than silent.

### Bug 2: SPA HTML shells flagged as auth bypass

`/app/dashboard/index.html`, `/app/dashboard/notsubmittedactivities.html`, etc. all
got drafted as Critical auth bypasses because `authRemovalResults` showed they
returned 200 to no-auth requests with `sameBody=true`. **That's normal SPA behavior**
— Angular/React/Vue apps serve the same bootstrap HTML to every visitor and handle
auth client-side after the JS loads. Submitting any of these to a bounty program
would burn reputation.

**Fix**: in the auth-bypass chain pattern, filter out paths where `path` ends with
`.html` AND `sameBody === true`. Real APIs (`/api/*`, `/v1/*`) keep their reportable
status. Out of 12 reports the user got from one hunt, this filter would have removed
7 false positives.

### Bug 3: Azure SAS tokens for media flagged as exposed credentials

The "Azure SAS" pattern matched URLs like `image.jpg?sv=...&sp=r&se=...` and drafted
them as High-severity credential leaks. But these are **short-lived read-only media
delivery URLs** — exactly how SAS tokens are designed to work for serving images
from Azure Blob Storage. Flagging them is a category error.

**Fix**: new `isBenignAzureSas(value, context)` heuristic in `content.js` checks:
- `sp=r` (read-only)
- File extension before `?` matches media (`.jpg`, `.png`, `.svg`, `.webp`, `.mp4`,
  `.woff2`, `.css`, etc.)
- Time window `se - st < 7 days`

If all three match → finding is suppressed. A real leak (long-lived, write-capable,
or pointing to data files) still fires.

### Bug 4: Paths included hash fragments

`/Dashboard#!/` was being treated as a unique server path. Hash fragments are
client-side only — never sent to the server.

**Fix**: `cleanPath()` helper in the chain analyzer strips everything from `#`
onward before pattern matching. The same path with multiple hash variants now
collapses to one entry.

### Improved repro commands

Auth-bypass curl commands now show BOTH the unauthenticated probe AND the
authenticated baseline for direct comparison:

```bash
# Verify unauthenticated access
curl -i "https://lms.moe.gov.ae/api/DashboardApi/getUsefulLinks"

# Compare to authenticated baseline (paste your real cookies):
curl -i "https://lms.moe.gov.ae/api/DashboardApi/getUsefulLinks" -b "session=..."
```

Plus a stronger "Diff the response bodies" step in the next-steps list — `sameBody=false`
isn't always proof of bypass; sometimes the no-auth response is just `401 Unauthorized`
JSON which differs from the auth response without being a vuln.

### Result

The same hunt that previously produced 12 reports (8 false positives, 4 real)
should now produce ~4 reports — only the genuinely reportable ones. Curls will
have the real target host. Users won't burn reputation on noise.

## v6.2.1 — Hunt Mode: auto-Deep + finding fallback

User shipped a hunt on a real target and got `0 reports` despite 3 confirmed
high-severity secrets in the engine. Two real bugs.

### Bug 1: Hunt Mode didn't auto-enable Deep mode

The probe step requires CDP debugger attach. v6.2.0 assumed the user had toggled Deep
in the popup before opening Hunt Mode. Most users won't — they'll click the Hunt
button cold. Without Deep, the probe step bailed with `Probe error: Deep mode
required`, and since the chain analyzer mostly emits chains from probe results, 0
chains formed. 0 chains × `chainOnly: true` = 0 reports.

**Fix**: added a new `deep` step (between `init` and `wait`) that calls `enableDeep`
automatically. The `debugger` permission is granted at install time so attach happens
silently — no user prompt, no friction. If attach fails (chrome:// page, debugger
already held by another extension), Hunt continues with passive findings only and
surfaces the failure clearly in the live feed.

### Bug 2: No fallback to individual findings

Even when 3 critical secrets sat in `tab.secrets`, Hunt Mode reported 0 because the
chain correlator only counts compound chains. v6.2.0 had no path from "individual
high-severity finding" → "drafted report".

**Fix**: new `collectIndividualFindings(state, cfg)` helper synthesizes chain-shaped
objects from passive findings that warrant a bounty report on their own:

- Secrets with `severity: critical | high` → wrapped with full source + value preview
- JWT `alg=none` confirmed accepts → wrapped as critical with forge-PoC repro
- Confirmed SSTI / XXE / CRLF probe results → wrapped at appropriate severity

Each synthesized object passes through the same `composeReport` function as real
chains — produces full HackerOne-format markdown identical in shape to compound-chain
reports.

Scope filter applies to synthesized findings too. Final dedupe by `id` so a real
chain and its corresponding individual finding don't both produce reports.

### UX clarification

Renamed the `chainOnly` checkbox label from "Only draft reports for Critical + High
chains" → "Only Critical + High severity" (with clearer hint). The semantics changed
slightly — now it filters by severity across BOTH chains and individual findings,
which is what users actually want.

### Result

The same hunt that previously produced 0 reports on a target with 3 exposed secrets
now produces 3 drafted reports (one per secret) — plus any chains the analyzer
surfaces from the now-running probe.

## v6.2.0 — Hunt Mode

The category leap. Hunt Mode turns PenScope from "tool you use" into "agent that hunts while you sleep."

Click **🎯 Hunt** in the popup header. Configure scope (in-scope paths, out-of-scope paths, aggression, time budget). Click Start. PenScope autonomously:

1. Settles passive recon
2. Runs the full 36-step probe pipeline + 8 stack-aware attack packs
3. Sweeps the **Authorization Matrix** across saved auth contexts (every endpoint × every user → IDOR/BAC anomalies)
4. Runs the chain correlator, filters chains by your scope rules
5. **Drafts a complete HackerOne-format report for every Critical and High chain** — title, severity with CVSS estimate, summary, steps to reproduce with curl, impact statement specific to the chain, suggested fix from the blue-fixes library, and references
6. Fires a Chrome notification per critical: _"Hunt Mode found a Critical IDOR on /api/users — report draft ready"_
7. Persists drafts to `chrome.storage.local` keyed by host (survive tab close + browser restart)

You wake up to a queue of pre-written bounty reports. Read each, click Copy or Export, paste into your H1/Bugcrowd submission.

### What's in the box

**Hunt UI** (`hunt.html` + `hunt.js`, ~1,200 LOC) — three sub-tabs:

- **Setup** — target URL (auto-filled from active tab), in-scope/out-of-scope glob patterns (Burp-style with `*` and `**`), aggression pill (Careful / Medium / Full Send), time budget (5/15/30/60 min), per-module toggles (probes / stack packs / auth matrix / chain-only filter / notifications)
- **Live** — real-time progress bar, 7-step list with done/live/pending icons, 5 stat cards (endpoints / requests / findings / chains / drafts), live event feed
- **Reports** — list of drafts color-coded by severity, click any to view in modal with Copy / Export `.md` / Delete actions. Bulk Export All as combined Markdown.

**Scope filtering** — glob-based in/out scope rules. A chain is in scope if any finding path matches in-scope AND no finding path matches out-of-scope. Empty in-scope = all paths considered in.

**Report composer** — full HackerOne-format markdown:

```
# [Chain title]

**Severity:** HIGH (CVSS estimate: 7.0–8.9)
**Confidence:** 85%
**Target:** https://...
**Discovered:** [ISO timestamp]
**Detected by:** PenScope v6.2 Hunt Mode (chain pattern: ...)

## Summary
[Chain summary + finding breakdown]

## Steps to reproduce
```bash
[curl from chain.reproCmd]
```
[Additional verification steps]

## Impact
[Severity-appropriate statement + chain-specific specifics
 (privilege escalation, IDOR, RCE, credential exposure, CSRF)]

## Suggested fix
[Pulled from chain-type → fix mapping (10+ patterns covered)]

## Detection methodology
[How PenScope correlated the signals]

## References
[OWASP, CWE, fix-specific links]
```

**Authorization Matrix integration** — when 2+ auth contexts are saved (in the Workbench), Hunt Mode runs the matrix as part of the loop. Anomalies (different status codes per context) get synthesized into chain-shaped findings and feed the report composer. Severity heuristic: anonymous-can-access-but-others-can't, or multi-role-all-200, escalates to High.

**Chrome notifications** — fires on Critical / High chain detection via `chrome.notifications.create`. Uses the existing `notifications` permission. Optional toggle in Setup.

**Persistence** — reports keyed by `ps:hunt:<host>` in `chrome.storage.local`. Capped 100 per host (FIFO). Dedup by `chainId` so re-runs of the same chain replace rather than duplicate.

### Architecture notes

- Orchestrator runs in the foreground hunt page (not in the background SW). Pros: simple, reliable, observable. Cons: aborts if the user closes the tab. Background-driven persistence across tab close planned for v6.2.1.
- Reuses every existing engine piece: `startProbe` for the 36-step pipeline (which auto-fires stack packs in red mode), `wbSendRequest` for matrix cells, `getData` for chain analyzer output. Hunt Mode is pure orchestration over existing primitives — adds ~1,200 LOC of UI + report composition, doesn't fork the engine.
- Reports are pure functions of `(chain, state, config)` — same chain always produces the same report. No randomness. Reproducible.
- Time budget = hard timeout. Hits it → finishHunt('stopped'). Whatever drafts exist persist.

### What this changes for the user

Bug bounty hunting becomes **passive**. Set scope on a target you have permission to test, hit Start Hunt, close the laptop. Wake up to:

- A Chrome notification (or several): _"Hunt Mode found a Critical IDOR on `/api/orders/:id`"_
- A queue of full bounty reports in the Hunt → Reports tab, ready to paste into HackerOne

Burp doesn't ship this. Burp's Active Scanner runs attacks but doesn't compose bounty reports. PenScope owns the entire workflow from scan → exploit → report → submit.

## v6.1.1 — Performance: don't lag YouTube

User reported PenScope made YouTube noticeably laggy. Confirmed two real hot paths
and shipped surgical fixes. No feature regressions; engine still captures everything,
just smarter about what it spends CPU on.

### Hot path 1 — webRequest noisy-host shortcut

YouTube fires hundreds of `googlevideo.com` chunk requests per minute for video
data. The previous webRequest listener ran the full enrichment pipeline on each
(14 AUTH_PATTERN regexes, path-param detection, tag rules, subdomain
classification, API version detection, Swagger lookup) — all on bytes the hunter
never cares about.

Now `onBeforeRequest` and `onHeadersReceived` short-circuit early for ~50 known
noisy host suffixes (video CDNs, ad networks, telemetry endpoints, large static
asset CDNs). Noisy-host requests still get logged as endpoints (one push, minimal
metadata) so they show up in the Site Map — but skip the expensive enrichment.

Same shortcut for "light" resource types (`image`, `media`, `font`, `stylesheet`,
`object`, `ping`, `csp_report`) on any host. These almost never carry
security-relevant URL params; logging them in full was burning CPU for no payoff.

User override: **"Full capture on noisy hosts"** checkbox in the Probe dropdown.
When checked, the noisy-host fast path is bypassed and v6.0 behavior is restored.
Persisted to `chrome.storage.local`. Default off.

### Hot path 2 — content.js MutationObserver

The previous MutationObserver fired `runFullScan` 3 seconds after any DOM mutation.
On YouTube, the DOM mutates constantly (live comments, autoplay queue, time ticks,
chip updates). The 3s debounce kept resetting and the `quickHash` kept changing,
so `runFullScan` ended up firing every few seconds, walking tens of thousands of
nodes via `document.querySelectorAll("*")`.

Three fixes layered together:

1. **Idle-deferred scan**: rescans now run via `requestIdleCallback` (5s timeout
   fallback). The browser only runs them when the page is genuinely idle, so the
   scan never competes with the renderer for cycles.
2. **Hard floor between scans**: `MIN_SCAN_INTERVAL = 15s`. Even on perpetually
   busy pages, runFullScan won't fire more than once per 15 seconds.
3. **Element-only mutation filter**: text-only mutations (timer ticks,
   character-data updates) no longer trigger the observer. Only mutations that
   add Element nodes count.
4. **Skip on hidden tabs**: `document.visibilityState === "hidden"` defers the
   scan until the tab is visible again.

`MUTATION_DEBOUNCE` also bumped from 3s to 5s.

### What this changes for the user

- YouTube, Twitch, X, TikTok, etc. should be smooth again
- Recon-quality on actual targets (the use case PenScope is built for) is unchanged
- Site Map still includes every captured endpoint; only enrichment is light for
  noisy hosts
- If a user IS specifically auditing YouTube/Twitch/etc. as a target, the
  Full-capture toggle restores v6.0 behavior in one click

## v6.1.0 — The Bug Bounty Workbench

PenScope now ships with the same daily-driver tools that hunters pay $449/year for in
Burp Suite Pro. Free, browser-native, faster startup, integrated with the existing
chain correlator and stack-aware probe engine.

The Workbench opens in a new Chrome tab (full-window real estate) and shares state
with the popup via the existing message handler pipeline. Six sub-modules:

### Repeater

Capture any request, edit any field (method/URL/headers/body), resend, see the response.
The single most-used Burp feature, in your browser. Send via Ctrl+Enter from any
field. History rail keeps the last 50 requests; click to reload + re-render the
captured response. **Copy as curl** turns any request into a one-liner you can paste
into a terminal. **Send to Intruder** transfers the request as a fuzz template.
**Send response to Diff** loads the body into the diff viewer.

### Intruder

Wordlist-based fuzzer with payload positions marked by `§...§`. Four attack modes
matching Burp Pro:

- **Sniper** — one position at a time, tries each payload in each marked position
- **Cluster bomb** — cartesian product across all positions
- **Pitchfork** — payloads paired in lockstep with positions (payload[i] → position[i])
- **Battering ram** — same payload in every position

Built-in payload library covering the daily hunter classics:

| Set | Count | Use case |
|---|---|---|
| XSS | 40 | `<script>alert(1)</script>` and 39 modern variants |
| SQLi | 30 | Boolean blind, error-based, time-based, UNION |
| LFI | 28 | Path traversal across encodings + log poisoning |
| SSTI | 18 | Jinja2, Twig, Freemarker, Velocity, Smarty |
| SSRF | 22 | Localhost variants, cloud metadata endpoints, gopher/dict |
| CmdInj | 24 | Bash, PowerShell, IFS bypass |
| IDs 1-100 | 100 | For IDOR enumeration |
| Auth bypass | 25 | `admin'--`, `' OR '1'='1`, role escalation |
| Usernames | 25 | Common admin/test/service accounts |

Or paste your own custom wordlist — overrides the built-in selection. Live result
table with status code, response size, time, and an anomaly flag (★) when status or
size differs from the baseline. Hard cap at 200 requests per attack to prevent
accidental DoS.

### Encoder / Decoder

Round-trippable conversions for everything hunters touch:

- Base64 (standard + URL-safe variants)
- URL encode/decode
- HTML entity encode/decode
- Hex encode/decode
- Hashes: MD5, SHA-1, SHA-256, SHA-512 (via SubtleCrypto, except MD5 which is a
  compact RFC 1321 implementation since SubtleCrypto doesn't expose MD5)

**JWT decoder + forger** as a dedicated card:
- Paste any JWT, decode header + payload to JSON
- Edit either, then **forge** a new token:
  - **alg=none** — the classic JWT auth bypass (server trusts unsigned tokens)
  - **HS256** — sign with a guessed weak secret (`secret`, `key`, `password`, `jwt-secret`)
- Output is a copy-pasteable token

### Diff Viewer

Character-level… actually line-level. Paste two responses or send them from the
Repeater. Click **Compute Diff** for an LCS-based diff (capped at 5000 lines per side
for performance). Shows `+ added`, `- removed`, ` unchanged` lines with color coding
and a summary `+N −M =K` count. Crucial for IDOR confirmation — does endpoint X
return *the same* response for User A and User B?

### Site Map

Hierarchical tree of every observed endpoint, organized by host → path. Method pills,
distinct response status codes shown as colored badges per node. Click any path to
load it into the Repeater. Lets you see the full attack surface at a glance.

### Auth Context Manager + Authorization Matrix

The differentiator. **Save named auth profiles** — Anonymous, User A, User B,
Admin, Internal Service — each with its own cookies + headers. Switch the active
context with one click; every Repeater / Intruder / probe request uses the active
context's credentials.

**Run authorization matrix** kicks off the killer feature: PenScope walks every
observed endpoint × every saved context, builds a color-coded grid:

```
                Anonymous    User A       User B       Admin
GET /api/me     401          200          200          200
GET /api/users  401          403          403          200
GET /api/admin  401          403          403          200
DELETE /users/5 405          403          403   ★      200
```

The ★ icon flags rows where contexts disagree on status code — those are your IDOR
and BAC candidates. Burp doesn't ship this; it's standard-issue PenScope value.

### Architecture

- **Workbench is a standalone Chrome tab** — `chrome.runtime.getURL('workbench.html?source=<tabId>')`
  opens in a new tab with full window real estate. Source tab ID flows through URL
  search params so the workbench knows which tab to operate on.
- **Page-context fetch** — `runWorkbenchRequest` uses `chrome.scripting.executeScript`
  with `world: "MAIN"` to run requests in the source tab's context. `credentials:'include'`
  picks up real session cookies; auth-context cookies are best-effort merged into
  `document.cookie` before the request. HttpOnly cookies stay server-side as expected.
- **Single named-function injection** — `__pageRunOneRequest` is the canonical runner.
  Same pattern as `__pageRunStackAttacks` and `__pageRunClaudeQueue` from v6.0 (see the
  dedicated comment in background.js for the MV3 CSP rationale).
- **State is per-tab** — `repeaterHistory[]`, `authContexts[]`, `authActive` live in
  `state[tabId]` and serialize via the existing `markDirty` pipeline. Snapshots of
  the active tab survive SW restarts.
- **No new dependencies** — all six modules are pure vanilla JS. The MD5 implementation
  is ~50 lines of inlined RFC 1321. The LCS diff is ~30 lines. JWT signing uses
  `crypto.subtle` natively.
- **Permissions unchanged** — the Workbench needs no new permissions beyond what v6.0
  already requested. `web_accessible_resources` added for `workbench.html`/`workbench.js`
  so MV3 will let extension pages load the URL.

### What this replaces in your toolkit

| Burp feature | PenScope equivalent |
|---|---|
| Repeater | Workbench → Repeater |
| Intruder (Sniper/Cluster/Pitchfork/Battering) | Workbench → Intruder (same 4 modes) |
| Decoder | Workbench → Encoder (more codecs) |
| Comparer | Workbench → Diff |
| Target / Site map | Workbench → Site Map |
| Burp Pro session handling rules | Workbench → Auth Contexts (better UX) |
| Burp Pro Authorize-style extension | Workbench → Authorization Matrix (built-in, free) |
| Active scanner | Probe engine (36 attacks + stack packs) |
| Issue prioritization | Chain correlator (13 patterns, severity × confidence) |

What Burp still has that PenScope doesn't (yet): TLS-level proxy interception (browser
extensions can't), Collaborator out-of-band testing service, request smuggling lab,
extension marketplace. Those come in future releases. Everything in a hunter's
day-to-day workflow is now in PenScope.

## v6.0.0 — Red Team / Blue Team / Classic Modes

The biggest release yet. v6.0 adds two new view modes — **Red** for offense, **Blue**
for defense — over the same data engine, while preserving every line of v5.9
functionality byte-for-byte in **Classic** mode. One engine, three views.

### Mode router

A new 3-segment pill in the popup header switches between **Classic**, **Red**, and
**Blue**. Mode is persisted per-tab via `chrome.storage.session` (survives SW
restarts) and via the existing `markDirty` pipeline. Theme swap rides on CSS variable
overrides under `body.mode-red` / `body.mode-blue` — no rule selector changes, so
classic mode is verbatim v5.9.

`tab.mode` defaults to `'classic'`. The data engine is identical across all three
modes; only the renderer changes.

### Red mode — chain-first attacker view

- **Exploit chain rail at top**, sorted by `severity × confidence`. Each chain
  expands in-place to a weaponize panel with five action buttons.
- **Weaponize buttons** — `Copy curl`, `Nuclei YAML`, `Burp request`, `Draft H1
  report`, `Send to Claude queue`. Each copies the right artefact to clipboard
  with a toast.
- **Claude bidirectional sync** — existing `→ Claude` button still pushes findings
  out. New `⟳ Sync from Claude` reads clipboard, parses a fenced
  ```` ```penscope-queue ```` JSON block, validates the shape, and persists to
  `tab.claudeQueue`. A banner appears with `Run queue ▶` to fire each attack via
  page-context fetch with current custom headers + stealth.
- **Stack-aware attack packs** — when `tab.mode === 'red'` and probe runs after step
  36, walks `tab.techStack` and runs matching packs (Laravel, Spring, Rails, ASP.NET,
  Django, Next.js, GraphQL, WordPress). 8 stacks, 40+ steps total. Findings land in
  `tab.stackAttacks` and feed Chain 13 (stack-specific RCE surface).
- **Reference accordion** — the 10 classic tabs render as collapsed sections below
  the chain rail. Expanding moves the actual rendered DOM into the section so click
  handlers and filter inputs continue to work.

### Blue mode — defender health dashboard

- **Health score** — 0-100, computed from severity-weighted finding counts:
  `score = max(0, 100 - (crit*15 + high*7 + med*3 + low*1))`. Live trend arrow
  vs. last snapshot.
- **Top-5 fixes this sprint** — prioritized by `severity × ease`. Each fix has a
  panel with copy-pasteable snippets in language tabs (raw / Nginx / Apache / IIS /
  Express / Django / Laravel / Rails / ASP.NET — only the variants the entry
  defines). 30+ fix entries covering every finding type.
- **Mark as fixed** — finding gets removed from health-score calc and top-5 list
  until the next scan disagrees. Persisted in `tab.markedFixed`.
- **Generate CSP** — observed-traffic CSP builder. Walks `tab.endpoints` by
  resource type, derives source allowlists, adds tight defaults
  (`default-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`,
  `form-action 'self'`, `upgrade-insecure-requests`). Detects inline
  scripts / `eval()` and warns when `'unsafe-inline'` or `'unsafe-eval'` had to be
  kept. Diff against current CSP shows tightened/loosened/added directives.
- **Compliance Audit** — coverage table across **7 frameworks**: PCI-DSS v4, NESA
  UAE IAS, SAMA CSF, DESC ISR, ISO 27001, OWASP Top 10 2021, CWE. Per-framework
  coverage % + drill-down to violating findings. Exports JSON (SIEM-ingestable)
  and PDF (clean print stylesheet via `window.print()`).
- **Snapshot + Compare** — captures current findings + chains under the host's
  `chrome.storage.local` bucket (FIFO, 20 per host). Diff identifies
  `new`/`resolved`/`unchanged` by stable finding ID. Diff Markdown export.
- **Continuous monitor** — toggle uses `chrome.alarms` (5 min interval). Each tick
  re-extracts secrets from the live tab and fires a `chrome.notifications` toast
  when new ones appear. Requires `notifications` + `alarms` permissions added to
  manifest v6.

### New chain pattern (Chain 13)

`analyzeExploitChains` now emits **stack-specific RCE surface** chains when
`tab.stackAttacks` contains critical/high hits. Confidence weights up when admin
endpoints + secrets in scope.

### New files

- `red-attacks.js` — canonical `STACK_ATTACK_PACKS` reference (live copy inlined
  in `background.js`)
- `blue-fixes.js` — canonical `FIX_SNIPPETS` reference (live copy inlined in
  `popup.js`)
- `blue-csp.js` — canonical `generateTightCSP` reference (live copy inlined in
  `popup.js`)
- `blue-compliance.js` — canonical `COMPLIANCE_MAP` reference (live copy inlined
  in `popup.js`)

### Architecture notes

- **Zero new dependencies.** No npm install, no CDN scripts, no build step. All
  new modules are pure vanilla JS; the canonical reference files double as
  external-tooling-readable copies.
- **Mode-router contract**: `setMode(mode)` validates → swaps body class → persists
  to background → calls `rerender()` which dispatches to `renderClassic` /
  `renderRed` / `renderBlue`. Each renderer manages `classicHost` / `modeHost`
  visibility.
- **Reference accordion DOM portage**: Red/Blue mode borrow the actual classic
  rendered nodes (rather than re-rendering or cloning) so listeners stay live.
  Borrowed nodes return to their hidden classic home on collapse.
- **Stack pack fire-and-forget**: runs after probe step 36 finishes; doesn't block
  the probe resolve. `markDirty` fires when packs complete so the popup picks up
  results on the next `getData`.
- **Stable finding hash**: tiny FNV-1a 32-bit. Both `popup.js#stableHash` and
  `background.js#snapStableHash` use the same algorithm so cross-process diffs
  match the same finding to the same ID.
- **No `localStorage`/`sessionStorage` from popup**: snapshots use
  `chrome.storage.local`; mode + queue use the existing `markDirty` →
  `chrome.storage.session` path.
- **Accessibility**: 4.5:1 contrast across all three themes, `:focus-visible`
  outlines on every new interactive element, `role="tablist"` + `aria-selected`
  on the mode toggle, `aria-expanded` on accordions, 44×44 minimum touch
  targets.

## v5.9.0 — Attack Chains + 6 New Attacks + Real Stealth

The release built specifically to push PenScope from "cool but rough" to "best-in-class."

### Attack Chain Correlator — the headline feature

New `analyzeExploitChains()` engine walks the entire tab state looking for **compound findings**
where multiple signals combine into something worse than any individual bug. 12 chain patterns:

1. **Auth bypass on sensitive endpoint** — probe-confirmed missing auth + path name suggests
   admin/user/billing/config
2. **Destructive BAC** — BAC-vulnerable endpoint with destructive naming (delete/remove/purge)
3. **CSRF-vulnerable GraphQL mutation** — confirmed missing CSRF + it's a mutation, not a query
4. **Exposed auth token + live API** — JWT/Bearer in memory + matching /api/ endpoints
5. **Confirmed IDOR with sensitive data** — same-skeleton response after ID substitution
6. **CORS reflection WITH credentials** — full SOP bypass
7. **Open redirect on auth flow** — redirect param on /oauth, /login, /callback
8. **Hidden admin routes** — 3+ admin paths in code never observed in traffic
9. **JWT alg=none accepted** — server trusts unsigned tokens
10. **Source map leaked secrets** — production shipped .map files with hardcoded secrets
11. **WebRTC internal IP leak** — private IPs exposed via STUN
12. **Recursive probe findings cluster** — 3+ sensitive findings across multiple endpoints

Each chain includes a **severity**, **summary**, **reproduction command**, **next steps**, and
**confidence score**. Sorted by severity × confidence. Rendered at the **TOP of the Deep tab**
(the literal first thing you see) and the **TOP of every Claude report**. This is what a
hunter reads first.

### 6 new probe attack vectors (Steps 31-36)

- **Step 31: Parameter Discovery** — brute-forces 38 hidden parameter names (`debug`, `admin`,
  `verbose`, `_method`, `role`, `bypass`, etc.) on observed GET endpoints. Compares response size
  to baseline. If response changes by >50 bytes, flags the parameter as potentially meaningful.
  **This finds debug flags APIs forgot to remove.**
- **Step 32: SSTI Probing** — injects `{{7*7}}`, `${7*7}`, `<%=7*7%>`, `#{7*7}`, `{{7*'7'}}`,
  `${{7*7}}` into query parameters. If the response contains the evaluated result (`49`,
  `7777777`) without the original payload, we have confirmed template injection — critical
  severity, usually RCE.
- **Step 33: XXE Probing** — POSTs XML with external entities to endpoints accepting
  `application/xml`. If the entity is reflected in the response, XXE is confirmed. Also flags
  endpoints that parse XML without error for potential OOB exploitation.
- **Step 34: CRLF Injection** — injects `%0d%0aX-PenScope-Injected:%20true` into redirect
  parameters. Checks response headers for the injected header. Enables response splitting,
  session fixation, and cache poisoning.
- **Step 35: API Version Downgrade** — actively probes older versions (v1, v2) for every
  observed `/vN/` endpoint. Older API versions often lack modern auth/validation.
- **Step 36: Proto Pollution Exploitation** — injects `__proto__` and `constructor.prototype`
  into JSON request bodies. Detects reflection of polluted attributes in responses and flags
  500 responses as potential triggers.

**Total probe attack count: 36 (was 30 in v5.8).**

### Real stealth mode

v5.8's stealth was jitter only. v5.9 adds actual **randomization**:

- `shuf()` Fisher-Yates shuffle helper (stealth-mode only, no-op otherwise)
- **Step 5 path order shuffled** — `/admin, /.env, /.git` are no longer probed in alphabetic
  order. Attacker signature of "sequential scan of admin endpoints" becomes much harder to match.
- **Step 7 prefix × suffix order shuffled** — both arrays randomized. The suffix brute no longer
  produces the same request sequence twice.
- **Per-request micro-jitter** — on top of the per-step delay, every 3rd request gets an
  additional 0-150ms random pause. Breaks timing-based detection.

### Severity weighting extended to more scanners

v5.8 applied `weighSeverity()` to one scanner. v5.9 extends it to `deepScanBody()` — the
heaviest pattern scanner in the codebase, run on every captured API response body. Findings are
now upgraded/downgraded based on:

- **In authenticated API path** → +1 severity
- **In comment/documentation** → -1 severity
- **Value looks like test data** (`john.doe`, `example.com`, `lorem`) → -1 severity
- **Value is a live-looking JWT** (three base64 parts) → +1 severity

### Architecture notes

- `analyzeExploitChains` runs inside `runPassiveAnalysis` on every `getData` call, so chains are
  always fresh. No chain pattern can miss findings added by later pipeline stages.
- The 6 new probe steps share the existing `sf()`, `mergeCustomHeaders()`, and `delay()` helpers.
  Zero new dependencies or helpers needed.
- State additions: `tab.exploitChains` (array). That's it. Everything else piggybacks on existing
  state fields.
- `R.paramDiscovery`, `R.sstiResults`, `R.xxeResults`, `R.crlfResults`, `R.versionDowngrade`,
  `R.protoPollution` added to the probe result object and rendered in the Deep tab under
  "Probe Results."
- `shuf()` is a zero-effect no-op when `ctx.stealth` is false, so non-stealth runs are unchanged.

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
