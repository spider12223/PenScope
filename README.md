<div align="center">

```
██████╗ ███████╗███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗
██╔═══╝ ██╔══╝  ██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
██║     ███████╗██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

### A bug bounty toolkit that lives inside your browser.

![version](https://img.shields.io/badge/version-6.3.0-ff3a5c?style=for-the-badge)
![manifest](https://img.shields.io/badge/manifest-v3%20%E2%80%A2%20ES%20module-9b5aff?style=for-the-badge)
![deps](https://img.shields.io/badge/dependencies-0-3aff8a?style=for-the-badge)
![lines](https://img.shields.io/badge/LOC-17%2C000%2B-3aa8ff?style=for-the-badge)
![probes](https://img.shields.io/badge/probes-45-ff7b3a?style=for-the-badge)
![price](https://img.shields.io/badge/price-free-3addc4?style=for-the-badge)
![license](https://img.shields.io/badge/license-MIT-55556e?style=for-the-badge)

**[Quick start](#quick-start) · [Hunt Mode](#hunt-mode) · [Workbench](#the-workbench) · [Modes](#modes) · [Exports](#exports) · [vs Burp](#vs-burp) · [Under the hood](#under-the-hood)**

</div>

---

## What this is

PenScope is a Chrome extension. Install it, browse a site you have permission to test, and it silently maps the entire attack surface — every endpoint, every secret, every misconfigured header, every hidden parameter. When you give the word, it sends 36 different probe attacks using your real session cookies and reports back which ones hit.

Or you set scope, click **Hunt**, and PenScope does the whole thing autonomously while you do something else — drafting full HackerOne-format bounty reports for every Critical and High finding it lands. You wake up to a queue of submittable drafts.

It's the daily driver for bug bounty hunters who want to skip the "set up a proxy, click around in three windows, alt-tab to a payload list" routine and just **look at a site**. Or stop looking entirely and let the tool hunt for them.

> **Reads everything, sends nothing — until you tell it to.**
> **Set scope, hit Hunt, close the laptop. Wake up to drafted criticals.**

---

## What's new in v6.3

Audit-driven refactor across 8 phases. Headline additions:

- **Probe engine: 36 → 45 attacks.** SSRF param probing, NoSQL operator injection, GraphQL alias/batch DoS, cache deception, subdomain takeover heuristic, TabNabbing, postMessage origin correlation, Service Worker scope abuse.
- **Tier contract is enforced, not described.** Careful = GET only, sequential, 200ms spacing. Medium = +POST for read-shape ops. Full = everything including race-condition bursts. Hover any tier in the Probe menu for the full contract.
- **Coverage: 31 new secret patterns + 9 new response-body patterns.** Mapbox secret keys, Datadog (real format), Algolia admin, Twilio Auth Token, Postmark, Cloudflare API tokens, Heroku, Linear, Notion, Figma, Plaid pair, Snyk, Terraform Cloud, Pinata, SSH public keys, `.env` assignments, Vault `s.`/`b.` prefixes — plus Spring Boot / Rails ActiveRecord / Django DEBUG / ASP.NET YSOD / Express / Apollo / MSSQL response-body detectors.
- **17 new tech fingerprints.** Qwik, SolidStart, Tauri, Strapi, Sanity, Contentful, Hygraph, Clerk, Cognito, Okta, PingIdentity, Workday, ServiceNow, Salesforce Lightning, Adobe AEM, Electron renderer.
- **JWT enrichment.** Every detected JWT auto-decodes (`alg`, `iss`, `sub`, `aud`, `exp`, `iat`, `role`, `scope`...). Severity bumps when `exp` is in the future and the role is admin-shaped.
- **CDP additions.** `Accessibility.getFullAXTree` surfaces sensitive aria-labels (admin/sudo/delete/destroy buttons). `Storage.getCookies` exposes CHIPS partitioned cookies that `chrome.cookies.getAll` doesn't.
- **JSON island parser.** `<script type="application/json">` blocks (Next `__NEXT_DATA__`, Nuxt `__NUXT__`, Remix `__remixContext`, Apollo `__APOLLO_STATE__`) get parsed for endpoints + ID fields, not just regex-scanned.
- **New endpoint-tab UX.** Per-row `curl` button, per-row `unauth` button (replays the request without cookies, shows side-by-side verdict). Route-table view that collapses `/users/123`, `/users/124` into `/users/{id}` with counts. Auto-pivot rail for `admin.*`, `api.*`, `internal.*` subdomains.
- **HAR export + ffuf wordlist.** Mirror exports of the existing HAR import + Burp wordlist. Drop straight into `ffuf -w`.
- **📸 Snap / ↔ Diff buttons in the popup header.** Save a snapshot now, compare any time later. Same machinery Blue mode uses.
- **IndexedDB diff.** Capture client-side state, mutate the app, capture again, diff. Catches state-leak bugs that pure HTTP capture misses.
- **Critical security fixes.** Probe `window.__ps_ctx` no longer leaks user's Authorization headers into page context after probe completes. Chain repro commands redact session cookies by default (Red mode has an opt-in toggle for live values). Probe IIFE snapshots `fetch`/`JSON`/`Promise`/`atob`/`btoa`/etc. at boot so analytics-instrumented pages can't intercept the probe by overriding globals. Local font vendoring — zero outbound requests on popup open.
- **ES module migration.** SW now loads as `"type":"module"`. `src/` directory tree in place; `STACK_ATTACK_PACKS` extracted to `src/probe/stack-packs.js`. Remaining modules are stubs documenting the extraction path.

Full per-phase breakdown in [`CHANGES.md`](./CHANGES.md). Migration notes in [`MIGRATION.md`](./MIGRATION.md).

---

## Quick start

```
1. Download the latest release zip from the Releases page
2. Unzip it
3. Open chrome://extensions, enable Developer mode (top right)
4. Click "Load unpacked" and pick the unzipped folder
```

Pin the extension. Visit any site. Click the **P** icon. PenScope was already watching.

---

## What you can do

PenScope captures 60+ data fields per tab. Here's what that means in practice:

**See the full attack surface.** Every endpoint, including ones referenced in JavaScript but never actually called. API paths buried in source maps, GraphQL operations reconstructed from POST bodies, hidden admin routes inferred from framework introspection.

**Find secrets nobody meant to ship.** API keys hardcoded in `.js` bundles. JWTs in `localStorage`. AWS credentials in environment dumps. Internal IDs in response bodies. The kind of thing that lands in a P1 report.

**Run 36 attack steps in your browser.** Auth bypass, BAC, IDOR, CORS reflection, JWT alg=none, SSTI, XXE, CRLF injection, prototype pollution, parameter discovery, API version downgrade. Three aggression levels — careful, medium, full. Custom headers paste in. Stealth mode shuffles the request order so you don't trip a WAF.

**Chain individual findings into actual exploits.** A JWT in memory is a finding. The same JWT plus an API endpoint that accepts unsigned tokens plus the decoded role being admin is a chain — and PenScope shows you the chain at the top of the report, with confidence score, repro command, and next steps.

**Edit and resend any request.** Right-click style. Repeater opens in a new tab, full window. Change a parameter. Hit Send. See the response. Drop it into Diff to compare against the baseline.

**Fuzz with insertion points.** Mark `§payload§` anywhere in a request, pick a payload set (40 XSS strings, 30 SQLi, 28 LFI, 18 SSTI, 22 SSRF, 24 command injection, IDs 1-100, auth bypass classics, common usernames), pick an attack mode (Sniper / Cluster bomb / Pitchfork / Battering ram), watch the live result table. Anomaly rows are flagged with a star.

**Test as five different users at once.** Save auth contexts (Anonymous, User A, User B, Admin, Internal). One click switches the active context — every Repeater request, every Intruder run, every probe uses those credentials. Then run the **Authorization Matrix**: PenScope walks every endpoint × every context and color-codes a grid. Disagreements between rows are your IDOR / BAC findings, surfaced automatically.

**Generate a CSP that actually fits the site.** Walks every request the page made, classifies each by resource type, builds a tight policy. Adds `default-src 'none'`, `frame-ancestors 'none'`, `upgrade-insecure-requests`. Detects inline scripts and `eval()` and warns when it had to keep `'unsafe-inline'`. Diffs against the existing CSP — green for tightened, red for loosened.

**Talk to Claude both ways.** Click `→ Claude` to push the entire scan into your clipboard as a structured brief. Ask Claude what to test next. Claude responds with a fenced JSON queue. Click `⟳ Sync from Claude` and PenScope parses the queue, runs each attack against the live target, and feeds the results back into the chain analyzer.

**Track your scope over time.** Snapshot a site today, snapshot it again next sprint, click Compare. PenScope tells you which findings are new, which are resolved, which haven't moved. Export the diff as Markdown for the team Slack.

**Map findings to compliance controls.** Click Compliance Audit. Every finding maps to specific controls in PCI-DSS v4, NESA UAE IAS, SAMA CSF, DESC ISR, ISO 27001, OWASP Top 10 2021, and CWE. Export JSON for your SIEM. Export PDF for the auditor.

---

## Hunt Mode

Click `🎯 Hunt` in the popup header. A new tab opens. The **pre-flight panel** at the bottom shows your engine state — endpoints captured, secrets, tech detected, auth contexts saved — so you know whether you have enough surface for a productive hunt before clicking Start. If endpoints < 20, a yellow warning suggests you browse the target first OR rely on the new DOM auto-crawl step. Configure your target scope (in-scope paths, out-of-scope paths, aggression level, time budget). Click `▶ Start Hunt`.

PenScope autonomously:

1. Settles passive recon
2. **Auto-enables Deep mode** (CDP debugger attaches silently — no user prompt)
3. **DOM auto-crawl** — walks every `<a href>`, `<form action>`, `<iframe src>`, `[routerLink]`, `[ng-href]`, `[to]`, `[data-href]` on the current page. Filters to same-origin URLs. Adds new ones to the probe queue. _Pure URL extraction — no clicking, no navigation, no session-changing side effects._
4. Runs the full 36-step probe pipeline + 8 stack-aware attack packs
5. Sweeps the **Authorization Matrix** across saved auth contexts
6. Runs the chain correlator, filters by your scope rules
7. **Drafts a complete HackerOne-format report for every Critical and High finding** — chains *and* individual high-severity findings (exposed secrets, JWT alg=none, confirmed SSTI/XXE/CRLF). Each draft includes title, severity with CVSS estimate, summary, steps to reproduce with two-step curl (no-auth probe + auth baseline for diff), impact statement specific to the finding, suggested fix from the snippet library, and references
8. Fires a Chrome notification per critical: _"Hunt Mode found a Critical IDOR on /api/users — report draft ready"_
9. Persists drafts to `chrome.storage.local` keyed by host (survive tab close + browser restart)

The **Live tab** narrates every filter step in real time — chain count before/after scope filter, severity distribution, what got dropped and why. If the hunt finishes with 0 reports, a "Why no reports?" diagnostic walks you through every filter point with concrete suggestions ("uncheck Critical+High filter," "save 2+ auth contexts," "browse the target more first"). No more wondering why a hunt came up empty.

**You wake up to a queue of pre-written bounty reports.** Read each, click Copy or Export, paste into your HackerOne / Bugcrowd / Intigriti submission.

This is the workflow Burp doesn't even attempt. Burp's Active Scanner runs attacks but you still have to write the report. PenScope owns the entire path from scan → exploit → report → submit.

> Set scope. Hit Start. Close the laptop. Wake up to a queue of drafted Criticals.

### Quality controls — keep your reputation

Hunt Mode actively filters false positives that would burn your reputation if submitted:

- **SPA HTML shells** — Angular/React/Vue bootstrap pages return identical HTML to authenticated and unauthenticated requests because the JS handles auth client-side. Hunt Mode detects this pattern (path ends in `.html` + `sameBody=true`) and suppresses the finding. Real APIs still report.
- **Benign Azure SAS tokens** — short-lived read-only SAS URLs for media (`image.jpg?sv=...&sp=r&se=...`) are legitimate CDN delivery, not credential leaks. Hunt Mode checks `sp=r` + media file extension + `se - st < 7 days` and suppresses. Long-lived, write-capable, or non-media SAS tokens still report as real leaks.
- **Hash fragment normalization** — `/Dashboard#!/` is a client-side route, not a server endpoint. Hunt Mode strips hash fragments before chain analysis so the report shows `/Dashboard` (the actual server path).
- **Real `baseUrl` in every curl** — the chain analyzer derives the target host from `tab.url` (HTTP/HTTPS only) with a fallback to the first observed endpoint. No more `https://target.tld` placeholder URLs in your reports.
- **Transparent diagnostics** — every filter step (scope, severity, dedupe) logs its before/after counts in the live feed. When a hunt finishes with 0 reports, the feed ends with a "Why no reports?" block explaining exactly where every potential finding was dropped, with concrete next-step suggestions adapted to your specific config.

### A real Hunt Mode draft

Here's a redacted excerpt from an actual draft Hunt Mode produced on a government LMS in 4 minutes:

```markdown
# Authentication bypass on sensitive endpoint: /api/DashboardApi/getUsefulLinks

**Severity:** CRITICAL (CVSS estimate: 9.0–10.0)
**Confidence:** 95%
**Target:** https://lms.example.gov/Dashboard
**Discovered:** 2026-05-01T07:31:13.151Z
**Detected by:** PenScope v6.2 Hunt Mode (chain pattern: chain-authbypass)

## Summary
PenScope's probe confirmed that GET /api/DashboardApi/getUsefulLinks returns
the same data whether or not authentication cookies are sent
(auth=200, noauth=200, sameBody=false). The path name strongly suggests this
endpoint should be role-gated — it's returning sensitive data to
unauthenticated callers.

## Steps to reproduce
# Verify unauthenticated access
curl -i "https://lms.example.gov/api/DashboardApi/getUsefulLinks"

# Compare to authenticated baseline (paste your real cookies):
curl -i "https://lms.example.gov/api/DashboardApi/getUsefulLinks" -b "session=..."

## Impact
Successful exploitation enables an attacker to bypass core security controls,
gain unauthorized access to sensitive functionality or data, and pivot to
broader compromise. This is a credible breach path warranting immediate
remediation.

## Suggested fix
Enforce server-side authentication on every endpoint that returns sensitive
data. The fact that PenScope received a 200 with no cookies means the
authorization middleware is missing or disabled for this route.

[ ... full Express/Django/Laravel snippet examples + references ... ]
```

**That's a submittable bounty report.** Drafted while you were doing something else.

---

## The Workbench

The Workbench is what bumps PenScope from "passive recon tool" into "everything you'd open Burp for." Click `⌘ Workbench` in the popup header and a full-window Chrome tab opens with six tools, sharing state with your scan.

### Repeater

Captured a request you want to mess with? Click it in the Site Map. The full request — method, URL, headers, body — loads into the editor. Edit anything. Hit `Send` (or `Ctrl+Enter`). The response renders on the right with status, size, time, and the active auth context that fired it.

The history rail keeps your last 50 sends. Three buttons turn the current request into actionable artifacts: **Copy as curl** (for terminals and reports), **Send to Intruder** (with the same headers and body pre-loaded), **Send response to Diff**.

### Intruder

Take any request. Wrap the value you want to fuzz in `§...§`. Pick a payload set. Hit Start.

Built-in payload library:

| Set | Count | Use case |
|---|---|---|
| **XSS** | 40 | Reflection testing, DOM XSS, SVG/iframe variants |
| **SQLi** | 30 | Boolean blind, error-based, time-based, UNION |
| **LFI / Path Traversal** | 28 | Encoding variants, Windows + Linux, log poisoning |
| **SSTI** | 18 | Jinja2, Twig, Freemarker, Velocity, Smarty |
| **SSRF** | 22 | Localhost variants, AWS/Azure/GCP metadata, gopher/dict |
| **Command Injection** | 24 | Bash, PowerShell, IFS bypass |
| **IDs 1-100** | 100 | For IDOR enumeration |
| **Auth bypass** | 25 | Path tricks, role escalation, SQL auth bypass |
| **Common usernames** | 25 | admin, root, test, support, service... |

Or paste your own list. Four attack modes: **Sniper** (one position at a time), **Cluster bomb** (every combination), **Pitchfork** (positions in lockstep), **Battering ram** (same payload everywhere). Live result table with anomaly detection — rows where status code or response size differs from baseline are flagged.

Hard cap: 200 requests per attack. Don't accidentally DoS your bounty target.

### Encoder

Round-trippable conversions for the formats hunters touch every day:

```
Base64 ↔ B64-URL ↔ URL ↔ HTML ↔ Hex ↔ MD5 / SHA-1 / SHA-256 / SHA-512
```

Plus a dedicated **JWT card**: paste a token, decode the header and payload, edit either, then forge a new one. Two forge modes:

- **alg=none** — the classic JWT auth bypass test (server trusts unsigned tokens)
- **HS256** — sign with a guessed weak secret (`secret`, `key`, `password`, `jwt-secret` are the common ones)

Output is a single token, copy-paste ready.

### Diff

Two text panes. Send responses from Repeater with one click. Hit `Compute Diff`. PenScope runs an LCS line-diff and color-codes the result: `+` for added, `−` for removed. Summary count at the top.

This is the IDOR-confirmation killer. "Is the response for User A *the same* as for User B, or did the server actually return User B's data?" Diff tells you in three seconds.

### Site Map

Hierarchical tree of every endpoint PenScope captured, organized by host → path. Method pills (`GET`, `POST`, `DELETE`...). Status code badges per node, color-coded green/yellow/orange/red. Click any path to load it into Repeater.

The full attack surface, in one view, ready to test.

### Auth Contexts + Authorization Matrix

This is the differentiator. Burp doesn't ship this.

Save named auth profiles. Each profile = a name + a set of cookies + a set of headers. Build them by logging in as each user, copying their session cookies + Authorization header, pasting into the editor. Add notes ("paid plan", "read-only role", "internal staff"). One click switches the active context. Every Repeater / Intruder / probe request now fires with those credentials.

Then click `Run authorization matrix`. PenScope hits every endpoint × every context and renders a grid:

```
                     Anonymous   User A    User B    Admin
GET  /api/me         401         200       200       200
GET  /api/users      401         403       403       200
GET  /api/admin      401         403       403       200
DELETE /api/orders/5 405         403       403  ★    200
PATCH /api/users/42  401         200  ★    403       200
```

Stars flag rows where contexts disagree. Those rows are your **IDOR and BAC findings, automatically surfaced**.

A typical hunter spends an entire afternoon manually testing each endpoint as each user, taking notes in a doc. PenScope does it in 30 seconds and color-codes the results.

---

## Modes

Same data engine, three views. Pick whichever matches what you're doing.

|   | Mode | Built for | What's on screen |
|---|---|---|---|
| 🟣 | **Classic** | Familiar workflow, full data | Every tab, every detail. The original PenScope. |
| 🔴 | **Red** | Offensive testing | Exploit chain rail at the top with weaponize buttons (curl, Nuclei YAML, Burp request, H1 report draft, Claude queue). Stack-aware attack packs auto-fire on detected frameworks (Laravel, Spring Boot, Rails, ASP.NET, Django, Next.js, GraphQL, WordPress). Chain-first, classic tabs collapsed below. |
| 🔵 | **Blue** | Defenders / security review | Health score (0-100, strict — only criticals and highs count). Top 5 fixes prioritized by severity × ease, each with copy-paste snippets in Nginx / Apache / IIS / Express / Django / Laravel / Rails / ASP.NET. Observed-traffic CSP generator. 7-framework compliance audit. Snapshot & regression diff. Continuous monitor with Chrome notifications when new secrets leak. |

Switch modes with the Classic / Red / Blue pill in the popup header. Each tab remembers which mode you were last in. Theme colors swap with the mode.

---

## Exports

Click `Export ▾` in the popup header. Ten formats, two purposes:

| Export | Includes credentials? | Use it for |
|---|---|---|
| **JSON (full data)** | ✅ Yes | Team-share format. Two hunters working the same target need shared auth contexts to reproduce findings. Send via Signal / encrypted channel. |
| **📄 Full Report (.md)** | ❌ Redacted | Bounty submission, customer engagement, anywhere it leaves your team. Auth header values (Authorization, Cookie, X-API-Key, X-Auth-Token, X-CSRF-Token, X-Amz-Security-Token, etc.) replaced with `<redacted, N chars>`. Includes embedded Hunt Mode drafted reports, stack-attack pack hits, continuous monitor alerts, and Marked-as-Fixed triage state. |
| **Burp URL list** | URL list only | Paste into Burp's target scope or feed to ffuf/nuclei |
| **Param wordlist** | Names only | Fuzzing dictionaries — query params + form input names + hidden field names |
| **Param wordlist (ffuf)** | Names only | Same data emitted as `param=FUZZ` lines for `ffuf -w` |
| **Endpoints (txt)** | URL list only | Tab-separated method/status/path/host/tags/size — observed + discovered routes |
| **📤 HAR Export** | Headers + bodies | Full HAR-1.2 capture you can import into Chrome DevTools / a HAR viewer / hand to a teammate |
| **🔧 Swagger Spec (.yaml)** | URL list only | Reconstructed OpenAPI 3.0 spec from observed traffic |
| **🗺️ Source Maps (JSON)** | Source extracts only | Full parsed source maps with file trees, secrets, routes, env vars, dependencies |
| **⚔️ Nuclei Templates (.yaml)** | Probe URLs only | Drop-in `~/.config/nuclei/custom/` for continuous scanning |

The Markdown report is built for sharing — every credential gets redacted, the report header explicitly says so. The JSON is built for syncing with your hunting partner — every credential ships intact.

---

## vs Burp

PenScope and Burp solve the same problem from different sides. PenScope lives in your browser; Burp is an MITM proxy. Both have their place. Here's the honest comparison.

| Feature | PenScope (free) | Burp Suite Pro ($449/yr) |
|---|---|---|
| **Repeater** | ✅ | ✅ |
| **Intruder** (4 attack modes) | ✅ | ✅ |
| **Decoder** (B64/URL/Hex/JWT) | ✅ | ✅ |
| **Comparer / Diff** | ✅ | ✅ |
| **Target / Site Map** | ✅ | ✅ |
| **Active scanner** | ✅ (45 probes + 8 stack packs) | ✅ |
| **Session/auth context handling** | ✅ (saved profiles + matrix) | ✅ (rules-based) |
| **Authorization matrix tester** | ✅ (built-in) | ❌ (paid extension) |
| **Chain correlation** (compound findings) | ✅ (13 patterns) | ❌ |
| **Subdomain takeover heuristic** | ✅ (8 service signatures) | ❌ (paid extension) |
| **GraphQL DoS surface tests** (alias + batch) | ✅ | ❌ |
| **Per-endpoint unauth replay button** | ✅ | ❌ |
| **HAR import + export** | ✅ (round-trip) | ✅ (one-way) |
| **IndexedDB diff** (catch client-state leaks) | ✅ | ❌ |
| **CHIPS partitioned cookie capture** | ✅ | ❌ |
| **JSON island parser** (Next/Nuxt/Remix hydration data) | ✅ | ❌ |
| **Compliance mapping** (PCI/NESA/SAMA/ISO/OWASP) | ✅ (7 frameworks) | ❌ |
| **CSP generator from observed traffic** | ✅ | ❌ |
| **Regression diff** (snapshot + compare) | ✅ | ❌ |
| **AI integration** (Claude bidirectional) | ✅ | ❌ |
| **Autonomous Hunt Mode** (drafts H1 reports while you sleep) | ✅ | ❌ |
| **Setup time** | 60 seconds | ~30 minutes (proxy + cert + browser config) |
| **TLS-level proxy interception** | ❌ (browser limitation) | ✅ |
| **Out-of-band testing** (Collaborator) | ❌ (planned) | ✅ |
| **Extension marketplace** | ❌ | ✅ |
| **Cost** | $0 | $449 / user / year |

**Where PenScope wins**: free, faster setup, browser-native (uses your real session, no cert dance), chain correlation, defender-mode tooling, AI bridge.

**Where Burp wins**: TLS-level interception lets you see and modify requests before they leave the network stack — useful for native apps and websocket smuggling. Collaborator gives you out-of-band callback infrastructure for blind XXE / SSRF.

If you do bug bounty exclusively in your browser on web apps, PenScope replaces Burp for ~95% of your daily workflow. If you reverse-engineer mobile apps or test thick clients, Burp is still your friend.

---

## Privacy

PenScope sends nothing without explicit user action. There is:

- ❌ No analytics
- ❌ No telemetry
- ❌ No remote logging
- ❌ No license server
- ❌ No "phone home" check

Outbound traffic happens only in three cases:
1. You click **Probe** — requests go to the site you're scanning, using your existing session cookies
2. You click **→ Claude** or any **Copy** button — content goes to your local clipboard
3. You click any **Export** option — content saves to your local disk

Zero npm packages. Zero CDN scripts. Zero third-party SDKs. Pure vanilla JavaScript, MV3 manifest, zero supply-chain attack surface.

---
---

# Under the hood

Architecture, the 36 probe attacks, the 13 chain patterns, the file map, and why none of this needs a build step.

---

## Architecture

```
                    ┌──────────────────────────┐
                    │   state[tabId]            │
                    │   60+ fields populated by │
                    │   webRequest / content /  │
                    │   CDP / probe layers      │
                    └──────────┬───────────────┘
                               │
       ┌───────────────────────┼───────────────────────┐
       │                       │                       │
  Classic mode             Red mode               Blue mode
  renderClassic()         renderRed()            renderBlue()
       │                       │                       │
       └───────────────────────┴───────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
         Workbench                          Hunt Mode
   (Repeater · Intruder · Encoder       (autonomous orchestrator
    · Diff · Site Map · Auth Matrix)     drafting H1 reports)
```

**One engine, three modes, three surfaces.** The data engine is mode-agnostic — every state field collects the same way regardless of which view you're in. Modes are theme + renderer choices over the same data. The Workbench and Hunt Mode are standalone Chrome tabs that share `state[tabId]` via background message handlers.

CSS variable overrides (`body.mode-red`, `body.mode-blue`) re-theme everything without touching a single rule selector. That's why Classic mode is byte-for-byte the v5.9 experience.

---

## Performance

PenScope is on every tab, all the time. By default it short-circuits expensive enrichment for ~50 known noisy host suffixes (video CDNs like `googlevideo.com`, ad networks like `doubleclick.net`, telemetry endpoints like `sentry.io`, large static CDNs like `gstatic.com`). Hundreds of `googlevideo.com` chunk requests per minute on YouTube no longer run through 14 AUTH_PATTERN regexes + path-param detection + Swagger lookup — they're logged as endpoints (so the Site Map still includes them) and skipped for the rest.

Same fast path for `image`/`media`/`font`/`stylesheet`/`object`/`ping` resource types on any host. Bugs almost never hide in `.css` URL params.

Content-script DOM rescans run via `requestIdleCallback` (with a hard 15-second floor between scans) and skip entirely when the tab is hidden. MutationObserver filters text-only changes (timer ticks, character-data updates) so YouTube's constant DOM churn doesn't trigger a full rescan every 3 seconds.

Override available: **"Full capture on noisy hosts"** checkbox in the Probe dropdown. When you're specifically auditing YouTube/Twitch/Sentry/etc. AS the target, check it and the fast path is bypassed.

---

## The 45 probe attacks

Run on demand. Three aggression levels with an enforced contract: **Careful** = GET/HEAD/OPTIONS only with 200ms minimum spacing between requests; **Medium** = adds POST for read-shape operations (≤3 parallel); **Full** = all methods including DELETE/PUT/PATCH plus race-condition bursts (≤10 parallel). Custom headers paste into every request. Stealth mode shuffles step order with Fisher-Yates and adds 0–80% jitter to inter-step delays. Every step's expected method is dry-run-checked against the active tier at probe start; blocked steps are listed in the diagnostic log.

| # | Attack | What it does |
|---|---|---|
| 1 | GraphQL introspection | Dumps schema, types, queries, mutations |
| 2 | Source map harvesting | Downloads `.map`, extracts secrets + endpoints |
| 3 | Swagger/OpenAPI fetch | `/swagger.json`, `/openapi.json`, etc. |
| 4 | OPTIONS preflight | CORS preflight on every API path |
| 5 | Recon path probing | `/admin`, `/.env`, `/.git/HEAD`, `/actuator` |
| 6 | API prefix suffix brute | `/api/v1/<word>` |
| 7 | Smart suffix bruteforce | Stealth-shuffled prefix × suffix |
| 8 | BAC (broken access control) | State-changing endpoints unauthenticated |
| 9 | IDOR auto-test | ID substitution + same-body comparison |
| 10 | CORS reflection test | Origin reflection with credentials |
| 11 | Method tampering | GET/POST/PUT/PATCH/DELETE swaps |
| 12 | Open redirect probe | `?redirect=evil.com` variants |
| 13 | Race condition probe | Concurrent requests on idempotency-sensitive endpoints |
| 14 | HTTP parameter pollution | `?id=1&id=2` |
| 15 | Subdomain enumeration | From CT logs + observed traffic |
| 16 | GraphQL field fuzzing | Probes each introspected field for auth |
| 17 | JWT alg=none acceptance | Server trusts unsigned tokens? |
| 18 | Host header injection | `X-Forwarded-Host` variants |
| 19 | Cache poisoning | Unkeyed header injection |
| 20 | IDOR confirmed sameBody | Body-similarity across IDs |
| 21 | Auth removal test | Drop cookies, look for 200s |
| 22 | CSRF validation gap | State-changing endpoints with no token |
| 23 | gRPC reflection | Exposed gRPC reflection service |
| 24 | Compression oracle (BREACH) | Heuristic, doesn't actually exploit |
| 25 | WebSocket hijacking | Cross-origin WS connections |
| 26 | Cache poison probe | Header-based unkeyed input |
| 27 | Timing oracle | Same-endpoint timing variance |
| 28 | COOP/COEP bypass | Cross-origin isolation strength |
| 29 | Storage partition | Cross-site storage isolation |
| 30 | Smart recursive discovery | 3 waves of probing, chained from previous responses |
| 31 | Parameter discovery | 38 hidden param brute (`debug`, `admin`, `_method`, `bypass`...) |
| 32 | SSTI probing | `{{7*7}}`, `${7*7}`, `<%=7*7%>` |
| 33 | XXE probing | XML with external entities |
| 34 | CRLF injection | `%0d%0a` in redirect params |
| 35 | API version downgrade | `/v1/`, `/v2/` for every observed `/vN/` |
| 36 | Prototype pollution | `__proto__` / `constructor.prototype` in JSON bodies |
| 37 | SSRF param probing | 26 SSRF param names with cloud-metadata payloads; flags reflected metadata content |
| 38 | NoSQL operator injection | `{"$ne":null}` / `{"$gt":""}` / `{"$exists":true}` on JSON ID fields |
| 39 | GraphQL alias amplification | 50-alias query → DoS amplification surface (full only) |
| 40 | GraphQL batch amplification | 25-element JSON-array batch → DoS amplification (full only) |
| 41 | Cache deception | `/api/me/avatar.css` style — sensitive content cached behind static extensions |
| 42 | Subdomain takeover | HEAD-style probe of captured subdomains; matches GitHub Pages / S3 / Heroku / Netlify / Vercel / Bitbucket / Shopify takeover signatures |
| 43 | TabNabbing | Cross-origin `<a target="_blank">` without `rel="noopener"` |
| 44 | postMessage origin correlation | `addEventListener("message")` listeners without origin checks |
| 45 | Service Worker scope abuse | Flags broad SW scopes (especially `/`) |

Plus **8 stack-aware attack packs** that fire automatically when Red mode detects the matching framework: Laravel, Spring Boot, Rails, ASP.NET, Django, Next.js, GraphQL, WordPress. Each pack has 4–9 stack-specific tests. Spring Boot's pack alone hits `/actuator/heapdump`, `/actuator/env`, `/jolokia/list`, `/h2-console`.

---

## The 13 chain patterns

Individual findings are noise. Compound findings are exploits. PenScope's chain analyzer walks the full state and emits chains where multiple signals combine into something exploitable.

1. **Auth bypass on sensitive endpoint** — confirmed missing auth + admin/billing/user path
2. **Destructive BAC** — vulnerable endpoint with `delete`/`remove`/`purge` in the path
3. **CSRF-vulnerable GraphQL mutation** — confirmed missing CSRF + it's a mutation
4. **Exposed auth token + live API** — JWT in memory + matching endpoints
5. **Confirmed IDOR with sensitive data** — same-skeleton response across IDs
6. **CORS reflection WITH credentials** — full SOP bypass
7. **Open redirect on auth flow** — redirect param on OAuth callback paths
8. **Hidden admin routes** — 3+ admin paths in code never observed in traffic
9. **JWT alg=none accepted** — server trusts unsigned tokens
10. **Source map leaked secrets** — production shipped `.map` files with hardcoded keys
11. **WebRTC internal IP leak** — private IPs exposed via STUN
12. **Recursive probe findings cluster** — 3+ sensitive findings across multiple endpoints
13. **Stack-specific RCE surface** — stack pack found exposed actuator/Ignition/etc.

Each chain has a severity, summary, repro command, next steps, and confidence score. Sorted by `severity × confidence`. Rendered at the top of Red mode and the top of every Claude report.

---

## Health score (Blue mode)

```
score = max(10, 100 − min(90, crit×22 + high×9))
```

Strict on purpose. Only criticals and highs move the number. Mediums and lows still surface in the count tiles and Top-5 fixes — they're worth fixing — but they don't drag the score.

| State | Score |
|---|---|
| 0 crit, 0 high | **100** (clean) |
| 1 high | 91 |
| 3 highs | 73 |
| 1 critical | 78 |
| 1 critical + 3 highs | 51 |
| 3 criticals | 34 |
| 5+ criticals | **10** (floor) |

Floor at 10 so a catastrophic site reads "10/100", not "0/100" (which the user couldn't distinguish from "scan failed").

---

## File map

```
PenScope/
├── manifest.json              MV3 manifest, v6.3.0, "type":"module" service worker
├── popup.html                 Mode UI shell — three modes, glassmorphism dark theme
├── popup.js                   Renderers, mode router, weaponize panels, fix snippets,
│                              compliance, Hunt + Workbench launchers, exports
├── content.js                 Content script — DOM scanning, secrets, JSON islands,
│                              tech fingerprints, XSS sinks, postMessage scan
│
├── workbench.html / .js       Workbench tab — Repeater / Intruder / Encoder /
│                              Diff / SiteMap / AuthCtx + AuthMatrix
│
├── hunt.html / .js            Hunt Mode tab — autonomous orchestrator
│
├── regex-pack.json            81 secret patterns + 44 response-body patterns
│                              (loaded by SW at boot, merged into RESP_PATTERNS,
│                              fetched by content script via getRegexPack message)
│
├── src/                       Service worker entry + module tree (Phase 7 migration)
│   ├── background.js          Entry — webRequest, CDP, probe orchestrator,
│   │                          chain correlator, message router (~7,000 lines)
│   ├── probe/
│   │   └── stack-packs.js     STACK_ATTACK_PACKS (8 stacks) — extracted module
│   └── (other audit-named files are stubs — see MIGRATION.md)
│
├── fonts/                     Local woff2: JetBrains Mono + Plus Jakarta Sans
│                              (4 + 5 weights, ~590 KB total). Replaces the
│                              Google Fonts beacon that earlier versions hit on
│                              every popup open.
│
├── icons/                     16, 48, 128 px PNG
├── CHANGELOG.md               Full version history v5.1 → v6.3.0
├── CHANGES.md                 v6.3 per-phase fix breakdown
├── MIGRATION.md               Phase 7 module-migration map (real vs stub)
├── LICENSE                    MIT
└── README.md                  You are here
```

The four old reference files (`red-attacks.js`, `blue-fixes.js`, `blue-csp.js`, `blue-compliance.js`) were removed in v6.3 — their content was already inlined into `popup.js` / `background.js` since v6.0; the standalone files were dead code. `STACK_ATTACK_PACKS` is now a real ES-module export from `src/probe/stack-packs.js`.

---

## No build step

```bash
git clone https://github.com/spider12223/PenScope
# That's it.
```

No npm install. No webpack. No babel. No TypeScript. No bundler. Pure vanilla JavaScript. The `popup.html` `<script>` tag points directly at `popup.js`. The service worker loads `background.js` directly. CSS is inlined in `<style>`.

The MD5 implementation is ~50 lines of inlined RFC 1321 reference (because `crypto.subtle` doesn't expose MD5). The LCS diff is ~30 lines. JWT signing uses native `crypto.subtle.sign`. The chain correlator is plain regex + array iteration. Everything you read in this codebase is exactly what runs in the browser.

A recon tool that ships with 200 transitive npm dependencies has 200 packages of supply-chain attack surface. PenScope has zero.

---

## Permissions

| Permission | Why |
|---|---|
| `webRequest` | Capture every request/response without re-fetching |
| `webNavigation` | Detect SPA `pushState`/`replaceState` route changes (v6.3+) so endpoints from `app.com` don't bleed into the new origin's state when the SPA navigates cross-origin |
| `activeTab` | Read the current tab's URL + send content-script messages |
| `scripting` | Inject probe runners, stack packs, and Workbench requests into the page context |
| `tabs` | Map findings to the correct tab; open the Workbench in a new tab |
| `cookies` | Read HttpOnly cookies that `document.cookie` can't see |
| `debugger` | Required for Deep mode — enables CDP for full response bodies, runtime introspection, source extraction, audit issues, accessibility tree, partitioned cookies |
| `notifications` | Continuous monitor alerts on new secret leaks |
| `alarms` | 5-minute interval ticks for continuous monitor |
| `storage` | Persist state (`session`) and snapshots (`local`) across SW restarts |
| `<all_urls>` host permission | Capture is target-agnostic; the user controls which tab is open |

---

## Contributing

Bug reports and PRs welcome. Some guardrails:

- **Zero new dependencies.** No `package.json`. If you need a small utility, write 20 lines.
- **Vanilla JS only.** No React, Vue, TypeScript, build step.
- **State stays in `state[tabId]`.** Don't introduce new global stores.
- **Comments document why, not what.** Inline comments on regex intent, MV3 quirks, mode-router contract.
- **Accessibility.** New interactive elements need `:focus-visible` outlines, ARIA labels, ≥4.5:1 contrast.
- **No `new Function()`.** MV3 service workers ban dynamic code. Use named function declarations + `args` for `chrome.scripting.executeScript`.
- **Audit before pushing.** Verify cookie/state mutations have a restore path. Test custom crypto against vectors. Check edge cases.

---

## License

MIT. Use it, fork it, ship it.

If PenScope finds you a critical, [open an issue](https://github.com/spider12223/PenScope/issues) and tell us. We collect war stories.

---

<div align="center">

**Built by hunters, for hunters.**

[Report a bug](https://github.com/spider12223/PenScope/issues) · [Changelog](./CHANGELOG.md)

</div>
