# PenScope Changelog

## v5.5 — WASM RE + WebRTC + BroadcastChannel + 29 Probe Steps

### New Probe Attacks (Steps 23-29)
| Step | Attack | What it does |
|------|--------|-------------|
| 23 | gRPC Reflection | Probes gRPC-Web endpoints for service listing |
| 24 | BREACH Compression Oracle | Tests compression differentials with injected tokens |
| 25 | WebSocket Hijack | Tests cross-origin WS with evil.com Origin |
| 26 | Active Cache Poisoning | Injects unkeyed headers, compares responses |
| 27 | Timing Oracle | Measures response deltas for blind injection detection |
| 28 | COOP/COEP Bypass | Tests cross-origin framing restrictions |
| 29 | Storage Partition Test | Probes storage APIs for partitioning |

### New Passive Features
- **WASM Reverse Engineering** — hex dumps, crypto pattern detection (SHA/AES/RSA/HMAC), cryptojacking detection, toolchain signatures (emscripten/rustwasm)
- **WebRTC STUN Leak** — creates RTCPeerConnection to Google STUN, extracts private/public/IPv6 addresses
- **BroadcastChannel Interception** — patches constructor to capture all cross-tab messages, probes 20 common channel names
- **WebGPU Detection** — adapter info (vendor, architecture, features, limits)
- **WASM SIMD Validation** — validates with actual bytecode
- **COOP/COEP Detection** — cross-origin isolation status, SharedArrayBuffer availability, Spectre risk assessment
- **gRPC-Web Detection** — identifies gRPC endpoints via content-type headers
- **SRI Audit** — flags third-party scripts without Subresource Integrity

### Coverage Fix
- Moved `Profiler.startPreciseCoverage` to `Page.frameNavigated` (fires before scripts execute)
- Coverage now captures ALL script execution from the start, not just post-load activity
- Restored: 72 scripts, 76% used, 7,409KB dead code on MOE (was showing 0%)

### File Stats
| File | Lines |
|------|-------|
| background.js | 3,950 |
| popup.js | 2,326 |
| content.js | 683 |
| popup.html | 253 |
| manifest.json | 15 |
| **Total** | **7,227** |

## v5.3.1 — Bug Fixes + 8 New Probe Attacks + Console Tab
- 30+ bug fixes (regex race, escA, semver, timer stacking, sort comparator)
- Probe steps 12-22 (open redirect, race condition, HPP, subdomain mining, GraphQL fuzzing, JWT confusion, host header, cache poisoning, IDOR auto-test, auth removal, CSRF validation)
- Console tab with color-coded log levels and filters
- AI/LLM key detection, CSP analysis, pagination intelligence, Service Worker routes

## v5.3 — Aggressive Extraction + Network Intelligence
- POST body capture, API response deep scan, code coverage analysis
- Shadow DOM, memory strings, encoded blob detection
- DNS prefetch, iframe scan, header intel, perf entries, CSS content
- Swagger Reconstructor, 11 probe steps (BAC, method tampering, CORS, content-type)

## v5.2 — Deep Passive Analysis
- IndexedDB + CacheStorage, JWT decode, route classification, permission matrix, IDOR tests

## v5.1 — Endpoint Discovery + Probe Engine
- Dual-path script analysis, 50+ grep patterns, framework route extraction
- Probe foundation (GraphQL, source maps, Swagger, path probing, suffix bruteforce)

## v5.0 — Stealth CDP Domains
- 6 CDP domains, glassmorphism popup, response body analysis, TLS certs, console capture
