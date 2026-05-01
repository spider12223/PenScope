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

![version](https://img.shields.io/badge/version-6.2.2-ff3a5c?style=for-the-badge)
![manifest](https://img.shields.io/badge/manifest-v3-9b5aff?style=for-the-badge)
![deps](https://img.shields.io/badge/dependencies-0-3aff8a?style=for-the-badge)
![lines](https://img.shields.io/badge/LOC-14%2C000%2B-3aa8ff?style=for-the-badge)
![price](https://img.shields.io/badge/price-free-3addc4?style=for-the-badge)
![license](https://img.shields.io/badge/license-MIT-55556e?style=for-the-badge)

**[Quick start](#quick-start) · [Hunt Mode](#hunt-mode) · [Workbench](#the-workbench) · [Modes](#modes) · [vs Burp](#vs-burp) · [Under the hood](#under-the-hood)**

</div>

---

## What this is

PenScope is a Chrome extension. Install it, browse a site you have permission to test, and it silently maps the entire attack surface — every endpoint, every secret, every misconfigured header, every hidden parameter. Then, when you give the word, it sends 36 different probe attacks using your real session cookies and reports back which ones hit.

It's the daily driver for bug bounty hunters who want to skip the "set up a proxy, click around in three windows, alt-tab to a payload list" routine and just **look at a site**. It captures everything passively. It tells you what's exploitable. It hands you a working `curl` per finding.

> **Reads everything, sends nothing — until you tell it to.**

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

Click `🎯 Hunt` in the popup header. A new tab opens. Configure your target scope (in-scope paths, out-of-scope paths, aggression level, time budget). Click `▶ Start Hunt`.

PenScope autonomously:

1. Settles passive recon
2. Runs the full 36-step probe pipeline + 8 stack-aware attack packs
3. Sweeps the **Authorization Matrix** across saved auth contexts
4. Runs the chain correlator, filters by your scope rules
5. **Drafts a complete HackerOne-format report for every Critical and High chain** — title, severity with CVSS estimate, summary, steps to reproduce with curl, impact statement, suggested fix, references
6. Fires a Chrome notification per critical: _"Hunt Mode found a Critical IDOR — report draft ready"_
7. Persists drafts to `chrome.storage.local` keyed by host

**You wake up to a queue of pre-written bounty reports.** Read each, click Copy or Export, paste into your HackerOne / Bugcrowd / Intigriti submission.

This is the workflow Burp doesn't even attempt. Burp's Active Scanner runs attacks but you still have to write the report. PenScope owns the entire path from scan → exploit → report → submit.

> Set scope. Hit Start. Close the laptop. Wake up to a queue of drafted Criticals.

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

## vs Burp

PenScope and Burp solve the same problem from different sides. PenScope lives in your browser; Burp is an MITM proxy. Both have their place. Here's the honest comparison.

| Feature | PenScope (free) | Burp Suite Pro ($449/yr) |
|---|---|---|
| **Repeater** | ✅ | ✅ |
| **Intruder** (4 attack modes) | ✅ | ✅ |
| **Decoder** (B64/URL/Hex/JWT) | ✅ | ✅ |
| **Comparer / Diff** | ✅ | ✅ |
| **Target / Site Map** | ✅ | ✅ |
| **Active scanner** | ✅ (36 probes + 8 stack packs) | ✅ |
| **Session/auth context handling** | ✅ (saved profiles + matrix) | ✅ (rules-based) |
| **Authorization matrix tester** | ✅ (built-in) | ❌ (paid extension) |
| **Chain correlation** (compound findings) | ✅ (13 patterns) | ❌ |
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
       ┌───────────────────────┼────────────────────────┐
       │                       │                         │
  Classic mode              Red mode                Blue mode
  renderClassic()          renderRed()             renderBlue()
       │                       │                         │
       └───────────────────────┴─────────────────────────┘
                               │
                          Workbench
                  (separate full-tab UI sharing
                   state via message handlers)
```

**One engine, three modes, two surfaces.** The data engine is mode-agnostic — every state field collects the same way regardless of which view you're in. Modes are theme + renderer choices over the same data. The Workbench is a standalone Chrome tab that talks to the same `state[tabId]`.

CSS variable overrides (`body.mode-red`, `body.mode-blue`) re-theme everything without touching a single rule selector. That's why Classic mode is byte-for-byte the v5.9 experience.

---

## The 36 probe attacks

Run on demand. Three aggression levels. Custom headers paste into every request. Stealth mode shuffles step order with Fisher-Yates and adds 0–80% jitter to inter-step delays.

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
├── manifest.json              MV3 manifest
├── background.js              Service worker — webRequest, CDP, probe engine, chain analyzer (~6,200 lines)
├── popup.html                 Mode UI shell — three modes, glassmorphism dark theme (~340 lines)
├── popup.js                   Renderers, mode router, weaponize panels, fix snippets, compliance (~3,300 lines)
├── content.js                 Content script — DOM scanning, secrets, hidden fields, forms, XSS sinks (~700 lines)
│
├── workbench.html             Workbench full-tab UI shell (~960 lines)
├── workbench.js               Workbench logic — Repeater/Intruder/Encoder/Diff/SiteMap/AuthCtx (~1,200 lines)
│
├── hunt.html                  Hunt Mode full-tab UI shell (~440 lines)
├── hunt.js                    Hunt Mode orchestrator + report composer (~720 lines)
│
├── red-attacks.js             Reference: STACK_ATTACK_PACKS (8 stacks)
├── blue-fixes.js              Reference: FIX_SNIPPETS (30+ remediation snippets)
├── blue-csp.js                Reference: generateTightCSP
├── blue-compliance.js         Reference: COMPLIANCE_MAP (7 frameworks)
│
├── icons/                     16, 48, 128 px PNG
├── CHANGELOG.md               Full version history v5.1 → v6.1
├── LICENSE                    MIT
└── README.md                  You are here
```

The four `*.js` reference files are canonical sources of their dictionaries. The live copies are inlined into `popup.js` / `background.js` because MV3 service workers don't easily import additional scripts and the popup runs as a single bundled script. When you add an entry to a reference file, also paste it into the live copy.

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
| `activeTab` | Read the current tab's URL + send content-script messages |
| `scripting` | Inject probe runners, stack packs, and Workbench requests into the page context |
| `tabs` | Map findings to the correct tab; open the Workbench in a new tab |
| `cookies` | Read HttpOnly cookies that `document.cookie` can't see |
| `debugger` | Required for Deep mode — enables CDP for full response bodies, runtime introspection, source extraction, audit issues |
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
