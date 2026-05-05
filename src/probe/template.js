// The IIFE eval-string template (lines ~1655-3300 of src/background.js). The
// audit's full Phase 7 spec called for converting the 45 inline steps into a
// data-driven PROBE_STEPS array of {id, name, aggro, gate, fn} entries with a
// dispatch loop. That refactor is significantly larger than this phase's
// scope and is queued as a separate task. The current template stays inline
// in src/background.js as a single string template literal so the existing
// behavior is preserved bit-for-bit.
export {};
