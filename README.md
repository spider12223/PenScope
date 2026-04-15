<div align="center">

```
██████╗ ███████╗███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗
██╔═══╝ ██╔══╝  ██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
██║     ███████╗██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

### **The browser recon extension that reads everything, sends nothing — until you tell it to.**

![version](https://img.shields.io/badge/version-5.8.0-ff3a5c?style=for-the-badge)
![manifest](https://img.shields.io/badge/manifest-v3-9b5aff?style=for-the-badge)
![deps](https://img.shields.io/badge/dependencies-0-3aff8a?style=for-the-badge)
![lines](https://img.shields.io/badge/LOC-8%2C600%2B-3aa8ff?style=for-the-badge)
![license](https://img.shields.io/badge/license-MIT-55556e?style=for-the-badge)

**[Install](#install) · [Features](#what-it-does) · [Architecture](#architecture) · [Probe Attacks](#probe--30-attack-vectors) · [Why](#why-penscope)**

</div>

---

## v5.8.0 — "Heist Mode"

Three versions in three days. PenScope went from "cool idea" to **the single most dangerous thing a bug bounty hunter can point at a login page.** It lives in your browser, reads the whole attack surface, and — when you give the word — runs **30 probe attacks** + **three waves of recursive API discovery** with custom auth headers and WAF-evading stealth jitter.

> 8,600 lines. Zero dependencies. One button to Claude.

### What's new in 5.8

- ⚔️ **Smart Recursive API Discovery** — 3 waves of GET-based probing that chain findings forward. Wave 1 probes every endpoint discovered in steps 1-29. Wave 2 probes URLs extracted from Wave 1 responses. Wave 3 does it again. Budget-capped, rate-limited, and feeds every finding back into the main Secrets list.
- 🔐 **Custom headers for authenticated testing** — paste `Authorization: Bearer xxx` once, it's merged into every probe request. Persisted across sessions.
- 🥷 **Stealth mode** — jitter + randomized pauses to evade WAF pattern detection. Turns a 10/10 signature scan into a 3/10.
- 💾 **Session persistence** — your findings survive service worker restarts. Close the popup, reopen it 5 minutes later, everything's still there.
- 📥 **HAR import** — load Burp/ZAP/DevTools captures and let PenScope analyze them as if you'd browsed the site live.
- ⚔️ **Nuclei template export** — one click turns BAC/auth-bypass/IDOR/CORS/redirect/CSRF findings into a multi-document YAML for continuous scanning with `nuclei -t ./findings.yaml`.
- 🧬 **GraphQL schema reconstruction** — parses captured POST bodies to rebuild the full operation map without ever touching `__schema`.
- 🔤 **Source-map symbol table** — extracts the `names` array from every parsed source map, flagging any identifier matching `admin|auth|token|secret|bypass|role`.
- 🧠 **WASM binary analysis** — server-side decode of `.wasm` modules from CDP, with toolchain detection (Rust/Emscripten/AssemblyScript/Go/LLVM), crypto/mining signature scanning, and full hex dumps.
- 🎯 **Deep tab filter + collapsible sections** — 40+ sections, one filter input, click-to-collapse titles, ⊕ All / ⊖ All buttons for rapid triage.
- 📐 **Severity confidence weighting** — findings get upgraded when in auth contexts, downgraded when in comments or test data. No more "every stack trace is critical".

---

## What It Does

PenScope runs **four distinct scanning layers** in parallel. Three of them **never send a single request** to the target. The fourth one only sends requests when you click the button.

```
┌──────────────┬──────────────┬──────────────────────┬──────────────────────┐
│ PASSIVE      │ CONTENT      │ DEEP (debugger)      │ PROBE (opt-in)       │
│ ZERO REQUESTS│ ZERO REQUESTS│ ZERO REQUESTS        │ SENDS REQUESTS       │
├──────────────┼──────────────┼──────────────────────┼──────────────────────┤
│ webRequest   │ DOM secrets  │ CDP domains:         │ 30 attack steps      │
│ listeners    │ hidden fields│ Network, Runtime,    │ runs in page context │
│ headers      │ forms/inputs │ Page, Debugger,      │ via Runtime.evaluate │
│ cookies      │ tech detect  │ Log, Audits,         │ session cookies +    │
│ params       │ XSS sinks    │ Profiler, IndexedDB, │ custom headers       │
│ redirects    │ DOM XSS      │ CacheStorage         │ stealth jitter       │
│ subdomains   │ Web workers  │                      │ recursive discovery  │
│ headerIntel  │ Shadow DOM   │ Script grep (60+ pat)│ findings bubble up   │
│ grpc detect  │ COOP/COEP    │ Coverage analysis    │                      │
│              │ WebRTC STUN  │ WASM binary decode   │                      │
│              │ WebAuthn     │ Heap secret scan     │                      │
└──────────────┴──────────────┴──────────────────────┴──────────────────────┘
```

**The cardinal rule:** Passive, Content, and Deep modes read what the browser already has. The probe is the only layer that sends requests — and only when you explicitly enable it.

---

## Feature Matrix

| Category                    | Count | Notes                                                                                    |
|-----------------------------|-------|------------------------------------------------------------------------------------------|
| **Secret patterns**         | 60+   | AWS / GCP / Azure / Stripe / GitHub / GitLab / Slack / OpenAI / Anthropic / Vault / etc. |
| **Tech fingerprints**       | 80+   | React / Next / Nuxt / Vue / Angular / Laravel / Rails / Django / ASP.NET / Blazor / ...  |
| **Probe attack vectors**    | 30    | GraphQL introspection, BAC auto-test, IDOR auto-test, auth removal, CSRF, WS hijack, ... |
| **CDP domains used**        | 10+   | Network, Runtime, Page, Debugger, Log, Audits, Profiler, IndexedDB, CacheStorage, DOMDebugger |
| **Response body patterns**  | 35+   | Stack traces, SQL errors, JWTs, tokens, PII, internal URLs, ARNs, connection strings    |
| **JS source grep patterns** | 50+   | API endpoints, route definitions, hardcoded secrets, dangerous functions, SW handlers   |
| **Export formats**          | 7     | JSON, Markdown report, Burp URL list, param wordlist, endpoints, Swagger YAML, Nuclei YAML |
| **Dependencies**            | **0** | Pure vanilla JS. No npm. No CDN. No supply chain.                                        |

---

## Probe — 30 Attack Vectors

When you click **Probe**, PenScope runs these in sequence (with aggression-level gating):

| #  | Attack                       | What it finds                                                            |
|----|------------------------------|--------------------------------------------------------------------------|
| 1  | **GraphQL Introspection**    | Full schema dump, query/mutation/subscription fields                    |
| 2  | **Source Map Harvesting**    | Parses `.map` files for endpoints, secrets, env vars, TODOs              |
| 3  | **Swagger/OpenAPI Fetch**    | Downloads + parses specs from 8 known paths                              |
| 4  | **Robots + Sitemap**         | Disallowed paths, sitemap URLs                                           |
| 5  | **Well-Known Path Probing**  | `/.env`, `/.git/HEAD`, `/actuator`, `/elmah.axd`, 45+ more                |
| 6  | **OPTIONS Enumeration**      | Allowed methods on every `/api/` endpoint                                |
| 7  | **Smart Suffix Bruteforce**  | Prefix × 90 suffix dict: `/api/users`, `/api/admin`, `/api/config`, etc. |
| 8  | **BAC Auto-Test**            | POST/PUT/DELETE to role-gated routes, checks for 200 from underprivileged |
| 9  | **HTTP Method Tampering**    | Tries all 5 verbs on every observed endpoint                             |
| 10 | **CORS Reflection**          | `evil.com` / `null` origin reflection with/without credentials           |
| 11 | **Content-Type Confusion**   | XML/text/form on JSON endpoints — find parser bypass                     |
| 12 | **Open Redirect**            | `?redirect=evil.com` on every param matching 15+ redirect names          |
| 13 | **Race Conditions**          | 10 parallel requests to `/redeem`, `/purchase`, `/claim` endpoints       |
| 14 | **HTTP Parameter Pollution** | Duplicate params with poisoned values                                    |
| 15 | **Subdomain Mining**         | Scrapes DOM + perf API for same-registrable-domain hosts                 |
| 16 | **GraphQL Field Fuzzing**    | Typo'd field names → "Did you mean...?" introspection leak               |
| 17 | **JWT Algorithm Confusion**  | `alg: none` downgrade on cookies starting with `eyJ`                     |
| 18 | **Host Header Injection**    | `X-Forwarded-Host: evil.com` + 2 more payloads                           |
| 19 | **Cache Poisoning (Passive)** | 4 header tricks tested against `/`                                      |
| 20 | **IDOR Auto-Test**           | URL path IDs + GraphQL variable IDs, substituted with `n+1` / reverse-UUID |
| 21 | **Auth Token Removal**       | Full vs stripped-cookie comparison on every authenticated endpoint       |
| 22 | **CSRF Validation**          | Token removal + credential stripping on state-changing endpoints         |
| 23 | **gRPC Reflection**          | ServerReflection probing on `/grpc/` paths                               |
| 24 | **Compression Oracle (BREACH)** | Ratio variance with injected payloads                                 |
| 25 | **WebSocket Hijack**         | Cross-origin upgrade handshake with `evil.com` origin                    |
| 26 | **Active Cache Poisoning**   | `X-Forwarded-Host`, `X-Original-URL` + 4 more                            |
| 27 | **Timing Oracle**            | Response-time delta on LFI-style payloads                                |
| 28 | **COOP/COEP Bypass**         | Cross-origin-isolated check + iframe-embed testing                       |
| 29 | **Storage Partition Test**   | localStorage / sessionStorage / Cache API / IndexedDB access             |
| 30 | **🔁 Smart Recursive Discovery** | 3 waves: probes discovered URLs, extracts new URLs from responses, probes those, repeat |

---

## Architecture

```
                    ┌──────────────────────────────────┐
                    │       User clicks toolbar         │
                    └─────────────────┬────────────────┘
                                      │
                    ┌─────────────────▼────────────────┐
                    │          popup.html (UI)          │
                    │    10 tabs · Deep filter · ⊕⊖     │
                    └─────────────────┬────────────────┘
                                      │ chrome.runtime
                    ┌─────────────────▼────────────────┐
                    │        background.js (SW)         │
                    │  ┌────────────┐  ┌────────────┐  │
                    │  │ webRequest │  │   CDP      │  │
                    │  │ listeners  │  │ debugger   │  │
                    │  └─────┬──────┘  └─────┬──────┘  │
                    │        └───────┬───────┘         │
                    │         ┌──────▼────────┐        │
                    │         │ state[tabId]  │        │
                    │         │   60+ fields  │        │
                    │         └──────┬────────┘        │
                    └────────────────┼─────────────────┘
                                     │
                    ┌────────────────▼─────────────────┐
                    │  chrome.storage.session (persist) │
                    └────────────────┬─────────────────┘
                                     │
           ┌─────────────────────────┴────────────────────────┐
           │                                                  │
    ┌──────▼──────┐                                   ┌──────▼──────┐
    │  content.js │                                   │   Probe     │
    │ (DOM scan)  │                                   │ (opt-in)    │
    │  60+ regex  │                                   │ 30 attacks  │
    └─────────────┘                                   │ 3 recursive │
                                                      │ waves       │
                                                      └─────────────┘
```

**State lives in `state[tabId]`** — 60+ fields, populated by 4 independent scanning layers. Every field is debounced-persisted to `chrome.storage.session` so service worker restarts don't wipe your work.

**The probe runs as a single async IIFE** injected via `Runtime.evaluate` in page context. It uses session cookies + custom headers + stealth jitter. Findings feed back into `tab.secrets` and `tab.discoveredRoutes` so the final report includes everything.

---

## Install

### From source (until it hits the Chrome Web Store)

```bash
git clone https://github.com/spider12223/PenScope.git
```

1. Open `chrome://extensions/`
2. Toggle **Developer mode** (top-right)
3. Click **Load unpacked**
4. Select the `PenScope` folder
5. Pin the extension to your toolbar
6. Click the **P** badge on any page to start

**You'll need Chrome 116+** (uses `chrome.storage.session`, CDP Profiler coverage, and Network.getCookies).

---

## Usage

### Tier 1 — Passive recon (default)

Open any page. PenScope starts recording immediately. Click the toolbar icon to see:

- Every endpoint the browser has touched
- Secrets detected in scripts + DOM + storage
- Hidden form fields, HTML comments, data attributes
- Missing security headers, CORS issues, cookie flags
- Detected tech stack + dependency versions with known CVEs
- Third-party hosts + subdomains
- Links, forms, iframes

**No requests are sent to the target. The browser already has this data; PenScope just reads it.**

### Tier 2 — Deep mode (click the Deep button)

Attaches Chrome's debugger (CDP) to the current tab. Unlocks:

- Full JS source grep (60+ patterns)
- Response body capture with 35+ finding patterns
- Authorization headers captured
- Runtime framework introspection (React fiber walk, Vue store dump, Redux state, Angular services, Apollo cache)
- IndexedDB + CacheStorage contents
- HttpOnly cookies (invisible to `document.cookie`)
- JS coverage analysis — dead code = hidden features your role can't trigger
- Real event listeners (including ones attached via `addEventListener` in JS)
- WASM binary hex dumps + toolchain identification
- WebRTC STUN leak detection
- BroadcastChannel monitoring
- Shadow DOM piercing
- V8 heap secret scanning
- Source map auto-parse with symbol table + file tree + sensitive-path flagging

Still zero requests to the target. All data comes from the debugger observing what the browser already did.

### Tier 3 — Probe (click the Probe button)

**This is the only layer that sends requests.** Pick your aggression:

- 🟢 **Careful** — GET only, read-only, no state changes
- 🟡 **Medium** — tests auth/CSRF, no destructive operations
- 🔴 **Full Send** — every attack, including DELETE tests

Paste custom headers in the textarea (`Authorization: Bearer ...`) for authenticated testing. They're merged into every probe request and persisted across sessions.

Toggle **Smart recursive probing** to have the probe discover APIs, call them, extract new URLs from responses, call those, and repeat for 3 waves.

Toggle **Stealth mode** to add jitter + random pauses between requests for WAF evasion.

### Tier 4 — Export

Click **Export ▾** for:

- **JSON** — full scan dump (everything the popup shows)
- **📄 Full Report (.md)** — human-readable Markdown with every finding grouped + severity-sorted
- **Burp URL list** — every URL seen, ready to load into Burp's sitemap
- **Param wordlist** — every parameter name observed
- **Endpoints (TSV)** — method, status, path, host, tags, size
- **🔧 Swagger YAML** — reconstructed OpenAPI 3.0 spec from all discovered endpoints
- **🗺️ Source Maps JSON** — parsed source maps with secrets, routes, env vars, file trees
- **⚔️ Nuclei Templates YAML** — weaponized findings ready for `nuclei -t ./...`
- **📥 Import HAR** — load a Burp/ZAP/DevTools HAR capture as seed data

### Tier 5 — → Claude

Click **→ Claude**. A concise pentest brief gets copied to your clipboard. Paste it into Claude and ask:

> analyze these findings and give me a prioritized bug bounty report

You now have a LLM pair-programmer that can reason over 30 attack vectors and 500+ endpoints in a single shot.

---

## Why PenScope

| Feature                           | PenScope v5.8 | Burp Suite Community | OWASP ZAP | Fiddler |
|-----------------------------------|---------------|----------------------|-----------|---------|
| Runs entirely in the browser      | ✅            | ❌                   | ❌        | ❌      |
| Passive (no requests to target)   | ✅            | ⚠️ proxies everything | ⚠️        | ⚠️      |
| Reads browser runtime state       | ✅            | ❌                   | ❌        | ❌      |
| IndexedDB + CacheStorage dump     | ✅            | ❌                   | ❌        | ❌      |
| HttpOnly cookie capture           | ✅            | ✅                   | ✅        | ✅      |
| Source map auto-parse + symbols   | ✅            | ❌                   | ❌        | ❌      |
| WASM binary analysis              | ✅            | ❌                   | ❌        | ❌      |
| JS coverage dead-code detection   | ✅            | ❌                   | ❌        | ❌      |
| GraphQL introspection + schema    | ✅            | ✅ (paid)            | ⚠️        | ❌      |
| IDOR / BAC / auth-removal probes  | ✅ (30 attacks)| ❌                  | ⚠️ (scripts) | ❌   |
| Smart recursive API discovery     | ✅            | ❌                   | ❌        | ❌      |
| Custom auth headers for probe     | ✅            | ✅                   | ✅        | ✅      |
| Stealth mode (jitter + pauses)    | ✅            | ⚠️ (manual)          | ⚠️        | ❌      |
| Export to Nuclei templates        | ✅            | ❌                   | ❌        | ❌      |
| HAR import                        | ✅            | ✅                   | ✅        | ✅      |
| One-click LLM report              | ✅            | ❌                   | ❌        | ❌      |
| Install footprint                 | **~200KB**    | ~200MB               | ~300MB    | ~100MB  |
| External dependencies             | **0**         | JVM + 1000s of libs  | JVM       | .NET    |

---

## Tech Stack

- **Vanilla JavaScript** — no React, no Vue, no build step
- **Manifest V3** — service worker + content script + popup
- **Chrome DevTools Protocol** — via `chrome.debugger` for the Deep layer
- **`chrome.storage.session`** — for cross-restart persistence
- **`chrome.webRequest`** — for passive traffic observation
- **Zero npm dependencies** — every line is one we wrote

### Files

| File            | Lines | Purpose                                                                               |
|-----------------|-------|---------------------------------------------------------------------------------------|
| `background.js` | 4,820 | Service worker: webRequest listeners, CDP integration, probe engine, all extractors  |
| `popup.js`      | 2,840 | UI logic: 10 tabs, all rendering, exports, Claude brief, Nuclei generator, HAR parser |
| `content.js`    |   680 | DOM scanning: secrets, hidden fields, forms, tech, XSS sinks, WebRTC, WebAuthn        |
| `popup.html`    |   280 | Glassmorphism dark UI + inline CSS                                                    |
| `manifest.json` |    15 | MV3 manifest                                                                          |
| **Total**       | **~8,640** | **Zero dependencies. Zero build step. Zero BS.**                                 |

---

## Roadmap

- [ ] Cross-tab correlation (aggregate findings across multiple tabs of the same target)
- [ ] Persistent cross-session scan history
- [ ] More aggressive stealth (User-Agent rotation, random step ordering)
- [ ] MCP server wrapper — let Claude Code drive PenScope directly
- [ ] PCAP export for Wireshark
- [ ] Auto-pivot to discovered subdomains
- [ ] Screenshot capture of findings for bug bounty reports
- [ ] Firefox port (content + background compatibility layer)

---

## Disclaimer

PenScope is built for **authorized security testing only** — bug bounty programs with explicit scope, engagements where you have a written letter of authorization, your own applications, or CTF challenges.

**Do not point it at anything you don't have permission to test.** The Probe layer sends real HTTP requests; the Recursive layer can probe hundreds of endpoints in under a minute. Using it without authorization is illegal in most jurisdictions.

The authors accept no responsibility for misuse. You are responsible for how you use this tool.

---

## License

MIT — do whatever you want, just don't blame me.

---

## Credits

Built by [@spider12223](https://github.com/spider12223) on a quest to make browser-native recon actually good.

v5.6 → v5.8 enhancements co-designed with Claude Opus 4.6 (1M context), who read every line and had opinions about all of them.

---

<div align="center">

**If PenScope found you a bug, star the repo and tell a friend.**

![stars](https://img.shields.io/github/stars/spider12223/PenScope?style=social)

</div>
