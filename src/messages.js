// chrome.runtime.onMessage router (~30 case branches: getData, setMode,
// setClaudeQueue, runClaudeQueue, markFixed, toggleContinuousMonitor,
// saveSnapshot, diffSnapshots, wb*, hunt*, importHar, replayUnauth,
// captureIdb, diffIdb, getRegexPack, etc). Inline in src/background.js.
// Pending Phase 7b extraction. Note: the listener registration MUST stay
// at top-level in the SW entry to fire on every wakeup, so even after
// extraction the registration call stays in src/background.js — only the
// per-action handler bodies move into this module.
export {};
