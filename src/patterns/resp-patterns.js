// RESP_PATTERNS — currently loaded from regex-pack.json at SW boot via
// _loadRegexPack() in src/background.js. The hard-coded fallback `RESP_PATTERNS`
// array is also still inline at lines ~440-485. Pending Phase 7b: move both
// the loader and the fallback into this module so callers do
//   import {respPatterns} from "./patterns/resp-patterns.js"
export {};
