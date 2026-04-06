# PenScope v5.5

**Full attack surface mapper — passive recon + 29 probe attacks in one click.**

A Chrome MV3 extension that passively maps every endpoint, secret, hidden field, and route on any website — then optionally probes for real vulnerabilities. Zero dependencies. ~7,200 lines of pure JavaScript.

## What It Captures (Zero Requests)

- **Endpoints** — every URL the page contacts, with method, status, size, tags
- **Secrets** — API keys, tokens, credentials, Azure SAS, AWS keys, Stripe keys, OpenAI/Anthropic/HuggingFace keys
- **Hidden Fields** — form inputs, data attributes, anti-forgery tokens
- **Headers** — missing security headers, CSP analysis, CORS config, 50+ intel headers
- **Tech Stack** — frameworks, libraries, servers, CDNs
- **Route Discovery** — 500+ API routes from JS bundles, classified by intent
- **Runtime Analysis** — framework services, app state, privilege escalation matrix, IDOR targets
- **Deep Extraction** — POST bodies, API response scanning (15 patterns), code coverage, shadow DOM, memory strings, encoded blobs
- **Network Intelligence** — DNS prefetch, iframe scan, perf entries, CSS content URLs, Service Worker routes
- **Console Capture** — dedicated tab with color-coded log levels and filters
- **WASM Analysis** — binary hex dumps, crypto pattern detection, cryptojacking detection, toolchain signatures
- **WebRTC Leak Detection** — actual STUN leak test extracting private/public/IPv6 addresses
- **BroadcastChannel Interception** — constructor patching to capture cross-tab messages
- **WebAuthn/FIDO2 Detection** — passkey support, conditional UI, platform authenticator
- **WebGPU/WASM SIMD Detection** — GPU adapter info, SIMD validation
- **COOP/COEP Analysis** — cross-origin isolation status, Spectre vulnerability assessment
- **SRI Audit** — third-party scripts without Subresource Integrity

## Probe Mode (29 Attack Steps)

Opt-in probing that sends requests with session cookies. For authorized pentesting and bug bounty.

| Step | Attack | What it does |
|------|--------|-------------|
| 1 | GraphQL Introspection | Full schema extraction — types, queries, mutations |
| 2 | Source Map Fetch | Downloads .map files, greps for endpoints and secrets |
| 3 | Swagger Discovery | Tests 8+ common paths for OpenAPI specs |
| 4 | Robots/Sitemap | Parses robots.txt disallows and sitemap URLs |
| 5 | Path Probing | HEAD+GET on 50+ well-known paths |
| 6 | OPTIONS Enumeration | Discovers allowed HTTP methods |
| 7 | Suffix Bruteforce | Smart prefix+suffix combinations on API paths |
| 8 | BAC Auto-Test | Hits permission matrix routes — flags 200 on admin endpoints |
| 9 | Method Tampering | GET→POST/PUT/DELETE on observed endpoints |
| 10 | CORS Reflection | Tests evil.com/attacker.com/null origins |
| 11 | Content-Type Confusion | Replays POST with text/plain, XML, multipart |
| 12 | Open Redirect | Tests redirect params with //evil.com payloads |
| 13 | Race Condition | 10 parallel POSTs to state-changing endpoints |
| 14 | HTTP Parameter Pollution | Duplicate params, checks response diffs |
| 15 | Subdomain Mining | Passive extraction from scripts, CSP, perf entries |
| 16 | GraphQL Field Fuzzing | Typo queries for "Did you mean..." suggestions |
| 17 | JWT Algorithm Confusion | Tests alg:none tokens |
| 18 | Host Header Injection | X-Forwarded-Host reflection testing |
| 19 | Cache Poisoning Detection | Tests X-Original-URL, X-Rewrite-URL |
| 20 | IDOR Auto-Test | Modifies path+body IDs, compares responses |
| 21 | Auth Token Removal | Replays requests without cookies/auth headers |
| 22 | CSRF Validation | Replays state-changing requests without CSRF tokens |
| 23 | gRPC Reflection | Probes gRPC-Web endpoints for service listing |
| 24 | Compression Oracle (BREACH) | Tests compression differentials with injected tokens |
| 25 | WebSocket Hijack | Tests cross-origin WS connections with evil Origin |
| 26 | Active Cache Poisoning | Injects unkeyed headers, compares responses |
| 27 | Timing Oracle | Measures response time deltas for blind injection |
| 28 | COOP/COEP Bypass | Tests cross-origin framing restrictions |
| 29 | Storage Partition Test | Probes storage APIs for partitioning restrictions |

## Architecture

```
┌──────────────┬──────────────┬──────────────────────┬──────────────────────┐
│ Passive      │ Content      │ Deep (debugger)       │ Probe (opt-in)       │
│ (zero reqs)  │ (zero reqs)  │ (zero reqs)           │ (sends requests)     │
├──────────────┼──────────────┼──────────────────────┼──────────────────────┤
│ webRequest   │ DOM secrets  │ CDP: Network, Runtime │ 29 attack steps      │
│ headers/CORS │ hidden fields│ Page, Debugger,       │ GraphQL, CORS, BAC   │
│ cookies      │ forms/inputs │ Log, Audits           │ IDOR, JWT, CSRF      │
│ params       │ tech detect  │ Script grep (50+ pat) │ Race, HPP, BREACH    │
│ redirects    │ storage scan │ Framework extraction  │ gRPC, WS hijack      │
│ subdomains   │ WebRTC STUN  │ Coverage analysis     │ Cache poison, timing │
│ header intel │ WebAuthn     │ WASM hex dump         │ COOP/COEP bypass     │
│              │ COOP/COEP    │ BroadcastChannel hook │ Storage partition    │
└──────────────┴──────────────┴──────────────────────┴──────────────────────┘
```

5 files, ~7,200 lines, zero dependencies:
- `background.js` (~3,950 lines) — service worker, webRequest, CDP, 29 probe steps
- `popup.js` (~2,330 lines) — UI rendering, 10 tabs, exports, Claude report
- `content.js` (~680 lines) — DOM scanning, WebRTC STUN, WASM/WebGPU, COOP/COEP
- `popup.html` (~253 lines) — glassmorphism dark UI with inline CSS
- `manifest.json` — MV3 config

## Exports

| Format | Description |
|--------|-------------|
| **JSON** | Full scan data — every field, every finding |
| **Full Report (.md)** | Complete markdown with all data including probe results |
| **Burp URL list** | All URLs for import into Burp Suite |
| **Param wordlist** | Every parameter name for fuzzing |
| **Endpoints (TSV)** | Tab-separated with headers |
| **Swagger Spec (.yaml)** | Auto-generated OpenAPI 3.0 from all discovered routes |
| **Source Maps JSON** | Parsed maps with secrets, file trees, endpoints |
| **→ Claude** | One-click structured pentest brief to clipboard |

## Installation

1. Clone or download this repo
2. Open `chrome://extensions` → enable **Developer mode**
3. Click **Load unpacked** → select the `penscope/` folder
4. Navigate to any website and click PenScope

## Usage

1. **Navigate** to target — passive scanning starts automatically
2. **Deep** — attaches debugger for response bodies, runtime analysis, coverage, WASM, console
3. **Scan** — triggers content script DOM scan
4. **Probe** — sends authenticated probes (29 attack steps)
5. **Export** — JSON, report, Burp URLs, Swagger spec, or → Claude

## Stealth

Passive and Deep modes send **zero requests**. They only read data your browser already received. The target server cannot detect PenScope is running.

Probe mode sends requests to the target with your existing session. Use only on authorized targets.

## Version History

- **v5.5** — WASM reverse engineering (hex dump, crypto detection, cryptojacking), WebRTC STUN leak, BroadcastChannel interception, WebGPU/SIMD detection, COOP/COEP analysis, gRPC reflection, BREACH compression oracle, WS hijack, active cache poisoning, timing oracle, storage partition testing (29 probe steps, 7,200 lines)
- **v5.3.1** — 30+ bug fixes, coverage fix, 8 new probe attacks, Console tab, AI key detection
- **v5.3** — Aggressive extraction, network intelligence, Swagger Reconstructor
- **v5.2** — IndexedDB/CacheStorage, JWT decode, permission matrix, IDOR tests
- **v5.1** — Endpoint discovery, probe engine foundation
- **v5.0** — CDP stealth domains, glassmorphism UI

## Disclaimer

PenScope is for authorized pentesting, bug bounty, and education. Passive and Deep modes only read data your browser already received. Probe mode sends requests — only use on systems you have authorization to test.

## License

MIT
