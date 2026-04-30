<div align="center">

```
██████╗ ███████╗███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗
██╔═══╝ ██╔══╝  ██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
██║     ███████╗██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

### **A Chrome extension that reads everything a website is doing — and tells you what to do about it.**

![version](https://img.shields.io/badge/version-6.1.0-ff3a5c?style=for-the-badge)
![manifest](https://img.shields.io/badge/manifest-v3-9b5aff?style=for-the-badge)
![deps](https://img.shields.io/badge/dependencies-0-3aff8a?style=for-the-badge)
![lines](https://img.shields.io/badge/LOC-10%2C000%2B-3aa8ff?style=for-the-badge)
![license](https://img.shields.io/badge/license-MIT-55556e?style=for-the-badge)

**[Quick start](#quick-start) · [What it does](#what-it-does) · [The Workbench](#the-workbench) · [The three modes](#the-three-modes) · [Under the hood](#under-the-hood)**

</div>

---

## What it does

PenScope is a browser extension. You install it, you visit a website, and it quietly watches every request, response, cookie, script, and storage write that page makes.

Then it shows you, in plain English:

- What endpoints exist (including the hidden ones referenced in JavaScript but never actually called)
- What secrets and tokens are leaking (in headers, in source maps, in localStorage, in JS memory)
- Which security headers and cookie flags are missing
- Which framework is running and what version
- Which third parties the page is talking to
- And — when you give it permission — it sends 36 different probe requests to test for real, exploitable bugs

It's built for **bug bounty hunters**, **pentesters**, and **defenders** who want a fast read on a site without firing up Burp.

> _"Reads everything, sends nothing — until you tell it to."_

**v6.1 added the [Workbench](#the-workbench)** — Repeater, Intruder, Encoder, Diff, Site Map, and an Authorization Matrix tester. Same daily-driver tools you'd pay $449/year for in Burp Pro. Free, browser-native, faster startup.

---

## Quick start

1. Download the latest release zip
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** and select the unzipped `PenScope` folder
5. Pin the extension, visit any site, and click the **P** icon

That's it. PenScope starts capturing the moment the popup opens. Nothing leaves your browser unless you tell it to.

---

## The three modes

This is what's new in v6.0. Same data engine, three different ways to look at it.

|   | Mode | Built for | What you see |
|---|---|---|---|
| 🟣 | **Classic** | Familiar v5.9 workflow | Every tab, every feature, exactly as before. Endpoints, secrets, headers, forms, deep findings — the full data dump. |
| 🔴 | **Red** | Bug bounty / offensive testing | Exploit chains at the top, sorted by how exploitable they actually are. Click any chain to get a working `curl`, a Nuclei template, a Burp request, or a draft H1 report — one click each. |
| 🔵 | **Blue** | Defenders / security engineers | A health score, the top 5 things to fix this sprint with copy-pasteable code snippets, an observed-traffic CSP generator, and a 7-framework compliance audit. |

Switch modes with the **Classic / Red / Blue** pill in the popup header. Each tab remembers which mode you were last in.

> The data engine is identical in every mode. Modes are theme + renderer choices over the same 60+ state fields. Classic mode is byte-for-byte the v5.9 experience.

---

## The Workbench

Click **⌘ Workbench** in the popup header. A new Chrome tab opens with the full hunter toolkit — same daily-driver features Burp charges $449/year for, free and browser-native:

| Tool | What it does |
|---|---|
| **Repeater** | Capture any request, edit any field, resend, see the response. Ctrl+Enter to fire. Copy as `curl`, send to Intruder, send to Diff. History rail keeps the last 50. |
| **Intruder** | Wordlist fuzzer with `§...§` insertion points. 4 attack modes (Sniper / Cluster bomb / Pitchfork / Battering ram). 9 built-in payload sets covering XSS, SQLi, LFI, SSTI, SSRF, CmdInj, IDs, auth bypass, usernames. Live anomaly-flagged result table. |
| **Encoder** | Round-trippable Base64 / URL / HTML / hex / hashes (MD5/SHA-1/SHA-256/SHA-512). Plus a JWT decoder + forger that signs `alg=none` for the classic auth bypass test, or HS256 with a guessed weak secret. |
| **Diff** | Line-level LCS diff between two responses. Crucial for IDOR confirmation — does the endpoint return the same response for User A and User B? Color-coded `+` / `−` / `=` with a summary count. |
| **Site Map** | Hierarchical tree of every observed endpoint, organized by host → path. Method pills, distinct status code badges per node. Click any path to load it into Repeater. |
| **Auth Contexts** | Save named auth profiles (Anonymous, User A, User B, Admin), each with its own cookies + headers. One-click switch. **Run authorization matrix** then probes every endpoint × every context and color-codes the grid — disagreements = IDOR/BAC. |

The Workbench shares state with the popup. Repeater history persists across SW restarts. Auth contexts persist per-tab.

---

## Use cases

**You're hunting on a new program.** Open the site, click PenScope, look at Red mode. The chain rail tells you which combinations of bugs are actually worth chaining. Click "Copy curl" and start testing.

**You just shipped a release.** Open Blue mode, click **Snapshot**. Tomorrow, click **Compare to last** — PenScope shows you exactly which findings are new vs. resolved. Catches regressions before users do.

**Your team is prepping for a SOC 2 audit.** Open Blue mode, click **Compliance Audit**, export the JSON. Each finding is mapped to PCI-DSS v4, ISO 27001, OWASP Top 10, NESA UAE IAS, SAMA CSF, DESC ISR, and CWE controls.

**You want a real CSP for your app.** Open Blue mode, click **Generate CSP**. PenScope walks every request the page actually made, classifies each by resource type, and outputs a tight policy that won't break the site.

**Your team uses Claude.** Click **→ Claude** to dump structured findings into your clipboard. Ask Claude what to test next. Paste Claude's response back. Click **⟳ Sync from Claude** to parse the JSON queue and run those exact attacks.

---

## What's in the box

### Always on (passive)

- Full endpoint discovery from network traffic + JavaScript + source maps + Swagger specs
- 35 response-body patterns (auth tokens, API keys, PII, stack traces, SQL errors, role flags)
- Cookie analysis (HttpOnly, Secure, SameSite, JWT decoding)
- Security header analysis (HSTS, CSP, X-Frame, COOP/COEP, etc.)
- Tech stack detection (frameworks, dependencies, versions)
- Source map harvesting (downloads `.map` files, extracts pre-minification names)
- Hidden form fields, disabled inputs, HTML comments, ASP.NET ViewState
- localStorage, sessionStorage, IndexedDB, CacheStorage
- WebSocket connections + messages
- WebRTC IP leaks, BroadcastChannel messages, WebAuthn capability
- Console logs, Chrome audit issues, network timing anomalies
- Service workers, web workers, WASM modules

### Opt-in: Deep mode

Attaches the Chrome debugger and unlocks:

- Captured response bodies (full pattern scan, not just headers)
- Auth headers from every request
- Runtime introspection (framework routes, services, state stores, prototypes)
- Memory mining (secrets in JS heap, not just DOM)
- TLS certificate details, cookies including HttpOnly ones
- DOM event listeners (real ones, not just `onclick=` attrs)
- Shadow DOM contents
- `eval()` / `new Function()` detection
- API response schema reconstruction

### Opt-in: Probe mode

When you click **Probe**, PenScope runs **36 attack steps** in your browser using your session cookies (and any custom headers you paste). Findings feed back into the chain analyzer.

Three aggression levels:
- **🟢 Careful** — GET only, read-only paths
- **🟡 Medium** — tests auth, no modifications
- **🔴 Full Send** — everything

---

## Privacy

PenScope **does not phone home**. There is no analytics, no telemetry, no remote logging. Every request you see goes only to:

- The site you're scanning (when you click **Probe**)
- Your local clipboard (when you click **→ Claude** or any **Copy** button)
- Your local disk (when you click any **Export** option)

No npm packages, no CDN scripts, no third-party SDKs. Pure vanilla JavaScript, MV3 manifest, zero supply-chain surface.

---
---

# Under the hood

This is where it gets technical. If you're just here to use PenScope, stop here. If you want to know how it actually works, read on.

---

## Architecture

```
                    ┌──────────────────────────┐
                    │   state[tabId]            │
                    │   60+ fields collected by │
                    │   webRequest / content /  │
                    │   CDP / probe layers      │
                    └──────────┬───────────────┘
                               │
                ┌──────────────┴──────────────┐
                │                              │
       tab.mode = 'classic'              tab.mode = 'red' / 'blue'
                │                              │
       renderClassic()                  renderRed() / renderBlue()
       (existing v5.9 UI)               (new layouts, same data)
```

**One engine, three renderers.** State collection is mode-agnostic. The popup picks a renderer based on `tab.mode`. CSS variable overrides (`body.mode-red`, `body.mode-blue`) re-theme everything without touching a single rule selector — that's why classic mode is byte-for-byte v5.9.

---

## The 36 probe attacks

When you click **Probe**, PenScope runs these in order. Each step is gated by aggression level.

| # | Attack | What it does |
|---|---|---|
| 1 | GraphQL introspection | Dumps schema, types, queries, mutations |
| 2 | Source map harvesting | Downloads `.map` files, extracts secrets + endpoints |
| 3 | Swagger/OpenAPI spec fetch | Pulls `/swagger.json`, `/openapi.json`, etc. |
| 4 | OPTIONS preflight | Tests CORS preflight on every API path |
| 5 | Recon path probing | `/admin`, `/.env`, `/.git/HEAD`, `/actuator`, etc. |
| 6 | API prefix suffix brute | `/api/v1/<word>` brute force |
| 7 | Smart suffix bruteforce | Stealth-shuffled prefix × suffix |
| 8 | BAC (broken access control) | Hits state-changing endpoints unauthenticated |
| 9 | IDOR auto-test | Substitutes IDs and compares response bodies |
| 10 | CORS reflection test | Checks if Origin is reflected with credentials |
| 11 | Method tampering | GET/POST/PUT/PATCH/DELETE swaps |
| 12 | Open redirect probe | `?redirect=evil.com` variants |
| 13 | Race condition probe | Concurrent requests on idempotency-sensitive endpoints |
| 14 | HTTP parameter pollution | `?id=1&id=2` |
| 15 | Subdomain enumeration | From CT logs + observed traffic |
| 16 | GraphQL field fuzzing | Uses introspected schema to probe each field |
| 17 | JWT alg=none acceptance | Tests if server trusts unsigned tokens |
| 18 | Host header injection | `Host: evil.com` with `X-Forwarded-Host` variants |
| 19 | Cache poisoning probe | Unkeyed header injection |
| 20 | IDOR with confirmed sameBody | Body-similarity comparison across IDs |
| 21 | Auth removal test | Drops cookies on every endpoint, looks for 200s |
| 22 | CSRF validation gap | Tests state-changing endpoints with no CSRF token |
| 23 | gRPC reflection | Checks for exposed gRPC reflection service |
| 24 | Compression oracle (BREACH) | Heuristic only, doesn't actually exploit |
| 25 | WebSocket hijacking | Tests if WS accepts cross-origin connections |
| 26 | Cache poison probe | Header-based unkeyed input |
| 27 | Timing oracle | Same-endpoint timing variance for IDOR signal |
| 28 | COOP/COEP bypass | Tests cross-origin isolation strength |
| 29 | Storage partition | Cross-site storage isolation check |
| 30 | Smart recursive discovery | 3 waves of GET-based probing chained from previous responses |
| 31 | Parameter discovery | 38 hidden param brute (`debug`, `admin`, `_method`, `bypass`...) |
| 32 | SSTI probing | `{{7*7}}`, `${7*7}`, `<%=7*7%>` injection |
| 33 | XXE probing | XML with external entities |
| 34 | CRLF injection | `%0d%0aX-Injected:%20true` in redirect params |
| 35 | API version downgrade | Probes `/v1/`, `/v2/` for every observed `/vN/` |
| 36 | Prototype pollution | `__proto__` / `constructor.prototype` in JSON bodies |

> **Stealth mode** (checkbox in the probe dropdown) shuffles step order with Fisher-Yates, adds 0–80% jitter to inter-step delays, and inserts micro-pauses every 3 requests. Turns a 10/10 scan signature into a 3/10.

---

## Stack-aware attack packs (Red mode)

When PenScope detects a known framework, Red mode runs a pack of stack-specific attacks after step 36. v6.0 ships **8 packs covering 40+ steps**:

| Stack | Sample steps |
|---|---|
| **Laravel** | `/_ignition/execute-solution`, `/.env`, `/telescope`, `/horizon`, `/_debugbar/open` |
| **Spring Boot** | `/actuator/heapdump`, `/actuator/env`, `/jolokia/list`, `/h2-console` |
| **Rails** | `/config/secrets.yml`, `/rails/info/routes`, `/admin/jobs` |
| **ASP.NET** | `/trace.axd`, `/elmah.axd`, `/web.config`, `/bin/` |
| **Django** | `/?debug=1`, `/admin/`, `/__debug__/` traceback trigger |
| **Next.js** | `/_next/static/development/_buildManifest.js`, `/_next/image` SSRF check |
| **GraphQL** | Introspection, query batching, symbol-table-driven field fuzz |
| **WordPress** | `/wp-json/wp/v2/users`, `/xmlrpc.php`, `/wp-admin/admin-ajax.php` |

Findings feed Chain 13 (stack-specific RCE surface) so a Spring Boot site with exposed actuators surfaces as one consolidated chain rather than five separate findings.

---

## Attack chain correlator (13 patterns)

Individual findings are noise. **Compound findings are exploits.** PenScope's chain analyzer walks the entire state and emits chains where multiple signals combine into something worse than any single bug.

1. **Auth bypass on sensitive endpoint** — probe-confirmed missing auth + admin/billing/user path name
2. **Destructive BAC** — vulnerable endpoint with `delete`/`remove`/`purge` in the path
3. **CSRF-vulnerable GraphQL mutation** — confirmed missing CSRF + it's a mutation, not a query
4. **Exposed auth token + live API** — JWT in memory + matching `/api/` endpoints
5. **Confirmed IDOR with sensitive data** — same-skeleton response after ID substitution
6. **CORS reflection WITH credentials** — full SOP bypass
7. **Open redirect on auth flow** — redirect param on `/oauth`, `/login`, `/callback`
8. **Hidden admin routes** — 3+ admin paths in code never observed in traffic
9. **JWT alg=none accepted** — server trusts unsigned tokens
10. **Source map leaked secrets** — production shipped `.map` files with hardcoded secrets
11. **WebRTC internal IP leak** — private IPs exposed via STUN
12. **Recursive probe findings cluster** — 3+ sensitive findings across multiple endpoints
13. **Stack-specific RCE surface** — _new in v6.0_ — stack pack found exposed `actuator/heapdump`, `_ignition`, etc.

Each chain has a severity, summary, repro command, next steps, and confidence score (0.0–1.0). Sorted by severity × confidence and rendered at the top of Red mode and the top of every Claude report.

---

## Health score (Blue mode)

```
score = max(10, 100 - min(90, crit×22 + high×9))
```

Only criticals and highs count. Mediums and lows are still surfaced in the count tiles and Top-5 fixes (you can still triage them), but they don't drag the score.

| Findings | Score |
|---|---|
| 0 crit, 0 high | **100** (clean) |
| 1 high | 91 |
| 3 highs | 73 |
| 1 critical | 78 |
| 1 critical + 3 highs | 51 |
| 3 criticals | 34 |
| 5+ criticals | **10** (floor) |

The floor at 10 means a catastrophic site doesn't read as literal `0/100` (which would be indistinguishable from "scan failed").

---

## Top-5 fixes — the snippet library

Blue mode prioritizes fixes by `severity × ease-of-fix` and surfaces the top 5 with copy-pasteable snippets. v6.0 ships **30+ fix entries** with framework-specific variants:

```
title:       short imperative — "Add Strict-Transport-Security header"
severity:    expected default severity
ease:        1-5 — ease of fix (5 = trivial config one-liner)
why:         plain-English explanation
snippet_raw: format-agnostic snippet
nginx, apache, iis, cloudflare, express, django, laravel, rails, aspnet, spring
             framework-specific variants
references:  links to authoritative sources
```

Click a fix → expand the panel → switch language tabs → click **Copy** or **Mark as fixed**. Marked-fixed findings drop out of the score and the top-5 list until the next scan disagrees.

---

## CSP generator (Blue mode)

Click **Generate CSP** and PenScope walks every request the page actually made:

```
endpoint type    →    CSP directive
─────────────────────────────────────
script           →    script-src
stylesheet       →    style-src
image            →    img-src
font             →    font-src
xhr / fetch / ws →    connect-src
iframe           →    frame-src
media            →    media-src
worker           →    worker-src + script-src
```

Same-origin sources collapse to `'self'`. Cross-origin sources are listed by full origin. Tight defaults (`default-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`, `upgrade-insecure-requests`) are auto-added.

If the page uses inline scripts or `eval()`, PenScope keeps `'unsafe-inline'` / `'unsafe-eval'` in the policy and surfaces a warning so you know what to migrate.

If the site already serves a CSP, PenScope diffs it directive-by-directive: green = tightened, red = loosened, yellow = newly added.

---

## Compliance audit (Blue mode)

7 frameworks. Every finding type maps to specific controls.

| Framework | Coverage |
|---|---|
| **PCI-DSS v4.0** | Payment card industry |
| **NESA UAE IAS** | UAE National Electronic Security Authority |
| **SAMA CSF** | Saudi Arabian Monetary Authority |
| **DESC ISR** | Dubai Electronic Security Center |
| **ISO 27001** | International standard |
| **OWASP Top 10 2021** | The classic |
| **CWE** | Common Weakness Enumeration IDs |

Click **Compliance Audit** → coverage table per framework → drill into violating findings → export JSON (SIEM-ingestable) or PDF (clean print stylesheet, no popup chrome).

---

## Snapshot + regression diff (Blue mode)

`chrome.storage.local` keyed by hostname. 20 snapshots per host, FIFO eviction.

Each snapshot includes findings (with stable hashes), chains, endpoints, tech stack, and the score at time of capture. **Compare to last** runs a stable-hash diff:

- **Introduced** — findings present now, not in the last snapshot
- **Resolved** — findings in the last snapshot, gone now
- **Unchanged** — same in both

Export the diff as Markdown for the team Slack.

---

## Continuous monitor (Blue mode)

Toggle the **▶ Continuous monitor** button. PenScope sets a `chrome.alarms` entry that fires every 5 minutes while the SW is alive.

On each tick: re-extract secrets from the live tab, compare to `tab.continuousMonitor.lastSnapshot`. New secret → fire a `chrome.notifications` toast.

Useful for long-running pentests where new things show up as developers ship code mid-engagement.

---

## Claude bidirectional bridge (Red mode)

The classic **→ Claude** button has always pushed PenScope's findings into your clipboard, ready to paste into Claude.

v6.0 closes the loop. Ask Claude "what should I test next?" and Claude responds with a fenced JSON block:

````
```penscope-queue
{
  "version": 1,
  "attacks": [
    {
      "type": "actuator",
      "endpoint": "/actuator/heapdump",
      "method": "GET",
      "rationale": "Spring Boot detected via X-Application-Context header",
      "severity_hint": "high"
    },
    {
      "type": "custom",
      "url": "/api/v1/users",
      "method": "PATCH",
      "body": "{\"role\":\"admin\"}",
      "rationale": "Test mass-assignment on user object"
    }
  ]
}
```
````

Click **⟳ Sync from Claude** in Red mode. PenScope reads your clipboard, regex-matches the fence, validates the JSON shape, and stores the queue. A banner appears at the top of Red mode with **Run queue ▶** — runs each attack against the live target with your custom headers + stealth context.

The whole loop: PenScope → clipboard → Claude → clipboard → PenScope → live exploitation.

---

## File structure

```
PenScope/
├── manifest.json          MV3 manifest, v6.1.0
├── background.js          Service worker — webRequest, CDP, probe engine, chain analyzer, workbench runners (~6,200 lines)
├── popup.html             Popup UI — three modes, glassmorphism dark theme (~340 lines)
├── popup.js               Renderers, mode router, weaponize panels, fix snippets, compliance (~3,300 lines)
├── content.js             DOM scanning — secrets, hidden fields, forms, tech, XSS sinks (~684 lines)
│
├── workbench.html         Workbench UI shell — 6 sub-tab full-window app (~430 lines)
├── workbench.js           Workbench logic — Repeater/Intruder/Encoder/Diff/SiteMap/AuthCtx (~830 lines)
│
├── red-attacks.js         Reference copy of STACK_ATTACK_PACKS (8 stacks: Laravel, Spring, Rails, ASP.NET, Django, Next.js, GraphQL, WordPress)
├── blue-fixes.js          Reference copy of FIX_SNIPPETS (30+ remediation snippets)
├── blue-csp.js            Reference copy of generateTightCSP
├── blue-compliance.js     Reference copy of COMPLIANCE_MAP (7 frameworks)
│
├── icons/                 16, 48, 128 px PNG
├── CHANGELOG.md           Full version history v5.1 → v6.1
├── LICENSE                MIT
└── README.md              You are here
```

The `*.js` reference files are the canonical sources of their respective dictionaries. The live copies are inlined into `background.js` / `popup.js` because MV3 service workers don't easily import additional scripts and the popup runs as a single bundled script. Update both when adding entries.

---

## No build step

```bash
git clone <this-repo>
# That's it. There's no install step.
```

Pure vanilla JavaScript. No npm, no webpack, no babel, no TypeScript, no React. The `popup.html` `<script>` tag points directly at `popup.js`. The service worker loads `background.js` directly. CSS is inlined in `<style>`.

Why: a recon tool that ships with 200 transitive npm dependencies is a recon tool with a 200-package supply chain attack surface. PenScope has zero.

---

## Permissions explained

| Permission | Why |
|---|---|
| `webRequest` | Capture every request/response without re-fetching |
| `activeTab` | Read the current tab's URL + send content-script messages |
| `scripting` | Inject runners (probe, stack packs, Claude queue) into the page context |
| `tabs` | Map findings to the correct tab |
| `cookies` | Read HttpOnly cookies that `document.cookie` can't see |
| `debugger` | Required for Deep mode — enables CDP for full response bodies, runtime introspection, source extraction, audit issues |
| `notifications` | Continuous monitor alerts on new secret leaks |
| `alarms` | 5-minute interval ticks for continuous monitor |
| `storage` | Persist state across SW restarts (`session`) and snapshots across browser restarts (`local`) |
| `<all_urls>` host permission | Capture is target-agnostic; the user controls what tab is open |

---

## Contributing

Bug reports and PRs welcome. Some guardrails:

- **Zero new dependencies.** No `package.json`. If you need a small utility, write 20 lines of vanilla JS.
- **Vanilla JS only.** No React, no Vue, no TypeScript, no build step.
- **State stays in `state[tabId]`.** Don't introduce new global stores.
- **Comments document why, not what.** Inline comments on regex intent, MV3 quirks, mode-router contract, and non-obvious algorithm choices.
- **Accessibility.** New interactive elements need `:focus-visible` outlines, ARIA labels, and ≥4.5:1 contrast across all three themes.

---

## License

MIT. Use it, fork it, ship it. If PenScope finds you a critical, tell us about it.

---

<div align="center">

**Made with too much coffee and not enough sleep.**

[Report a bug](https://github.com/your-org/penscope/issues) · [Changelog](./CHANGELOG.md)

</div>
