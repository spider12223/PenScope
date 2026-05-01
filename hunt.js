// PenScope v6.2 — Hunt Mode (autonomous attacker + report drafter)
//
// Orchestrates the existing PenScope engine pieces (probe, stack packs, auth matrix,
// chain analyzer) into an autonomous "set scope and forget" workflow. When the chain
// analyzer surfaces a Critical or High chain, Hunt Mode composes a full
// HackerOne-format report draft, fires a Chrome notification, and persists the draft
// to chrome.storage.local under the host bucket.
//
// State model:
//   - SOURCE_TAB_ID    — the tab being hunted (passed in URL hash)
//   - hunt config + state lives in the foreground page (this file) for v6.2.
//     If the user closes the tab, the hunt aborts. Background-driven persistence
//     across tab close comes in v6.2.1.
//   - reports persist in chrome.storage.local keyed by host (survive tab close + SW restart)

const params = new URLSearchParams(location.search);
const SOURCE_TAB_ID = parseInt(params.get('source')) || null;

let activeSubtab = 'setup';
let TARGET_URL = '';
let TARGET_HOST = '';
let HUNT_STATE = null;  // null = idle; { running, startTime, config, steps, currentStepIdx, ... } when running
let SAVED_REPORTS = [];
let CURRENT_VIEWING_REPORT = null;

// -------------------------------------------------------------------
// Utility
// -------------------------------------------------------------------
function $(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('show'), 2200);
}
function fmtTime(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ' + (s % 60) + 's';
  return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
}
function copyClip(text, label) {
  navigator.clipboard.writeText(text || '').then(() => toast('Copied' + (label ? ' ' + label : '')), () => toast('Clipboard blocked'));
}

// Glob → RegExp. Supports * (any chars within a path segment) and ** (any chars including /).
// Used to filter endpoints by in/out scope rules.
function globToRegex(pattern) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const withWild = escaped.replace(/\*\*/g, '@@DOUBLEWILD@@').replace(/\*/g, '[^/]*').replace(/@@DOUBLEWILD@@/g, '.*');
  return new RegExp('^' + withWild + '$');
}
function pathMatchesAny(path, patterns) {
  for (const p of patterns) {
    try { if (globToRegex(p).test(path)) return true; } catch (e) {}
  }
  return false;
}

// -------------------------------------------------------------------
// Bootstrap
// -------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.nav-btn').forEach(btn => btn.addEventListener('click', () => switchSubtab(btn.dataset.subtab)));

  if (!SOURCE_TAB_ID) {
    document.querySelector('.main').innerHTML = `
      <div style="padding:80px 24px;text-align:center;color:var(--t2)">
        <div style="font-size:36px;margin-bottom:14px;opacity:.5">⚠</div>
        <div style="font-size:14px">No source tab specified.</div>
        <div style="font-size:11px;color:var(--t3);margin-top:8px">Open Hunt Mode from the PenScope popup.</div>
      </div>`;
    return;
  }

  // Pull the source tab URL for the target pill + auto-fill
  try {
    const tab = await chrome.tabs.get(SOURCE_TAB_ID);
    if (tab && tab.url) {
      TARGET_URL = tab.url;
      try { TARGET_HOST = new URL(tab.url).hostname; } catch (e) {}
      $('targetUrl').textContent = tab.url;
      $('cfgTarget').value = tab.url;
    }
  } catch (e) { /* tab closed */ }

  // Wire setup pills (radio behavior)
  document.querySelectorAll('#cfgAggro .pill-btn').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('#cfgAggro .pill-btn').forEach(x => { x.classList.toggle('active', x === b); x.setAttribute('aria-checked', x === b); });
    });
  });
  document.querySelectorAll('#cfgBudget .pill-btn').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('#cfgBudget .pill-btn').forEach(x => { x.classList.toggle('active', x === b); x.setAttribute('aria-checked', x === b); });
    });
  });

  $('huntStartBtn').addEventListener('click', startHunt);
  $('huntStopBtn').addEventListener('click', stopHunt);
  $('reportsRefresh').addEventListener('click', loadReports);
  $('reportsExportAll').addEventListener('click', exportAllReports);
  $('reportsClearAll').addEventListener('click', clearAllReports);

  // Modal
  $('modalCloseBtn').addEventListener('click', () => $('reportModal').classList.remove('show'));
  $('reportModal').addEventListener('click', e => { if (e.target.id === 'reportModal') $('reportModal').classList.remove('show'); });
  $('modalCopyBtn').addEventListener('click', () => { if (CURRENT_VIEWING_REPORT) copyClip(CURRENT_VIEWING_REPORT.markdown, 'report'); });
  $('modalExportBtn').addEventListener('click', () => { if (CURRENT_VIEWING_REPORT) exportSingleReport(CURRENT_VIEWING_REPORT); });
  $('modalDeleteBtn').addEventListener('click', () => { if (CURRENT_VIEWING_REPORT) deleteReport(CURRENT_VIEWING_REPORT.id); });

  // Initial: load any persisted reports for this host
  await loadReports();

  // If a hunt is already running (e.g. user refreshed the page), refuse to restart;
  // background isn't tracking it (foreground orchestrator), so we just reset to idle.
  setStatus('idle', 'Idle');
});

function switchSubtab(name) {
  activeSubtab = name;
  document.querySelectorAll('.nav-btn').forEach(b => {
    const on = b.dataset.subtab === name;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on);
  });
  document.querySelectorAll('.subtab').forEach(s => s.classList.toggle('active', s.id === 'sub-' + name));
  if (name === 'reports') loadReports();
}

function setStatus(kind, text) {
  const pill = $('statusPill');
  pill.classList.remove('live', 'done', 'error');
  if (kind === 'live') pill.classList.add('live');
  else if (kind === 'done') pill.classList.add('done');
  else if (kind === 'error') pill.classList.add('error');
  $('statusText').textContent = text;
}

// -------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------
function readConfig() {
  const aggroBtn = document.querySelector('#cfgAggro .pill-btn.active');
  const budgetBtn = document.querySelector('#cfgBudget .pill-btn.active');
  return {
    target: $('cfgTarget').value.trim() || TARGET_URL,
    inScope: $('cfgInScope').value.split('\n').map(s => s.trim()).filter(Boolean),
    outScope: $('cfgOutScope').value.split('\n').map(s => s.trim()).filter(Boolean),
    aggro: aggroBtn ? aggroBtn.dataset.aggro : 'medium',
    budgetMin: budgetBtn ? parseInt(budgetBtn.dataset.budget) : 15,
    runProbes: $('cfgProbes').checked,
    runStackPacks: $('cfgStackPacks').checked,
    runAuthMatrix: $('cfgAuthMatrix').checked,
    chainOnly: $('cfgChainOnly').checked,
    notify: $('cfgNotify').checked,
  };
}

// -------------------------------------------------------------------
// Hunt orchestration — runs the engine pieces in sequence
// -------------------------------------------------------------------
const HUNT_STEPS = [
  { id: 'init',     label: 'Bootstrap engine + capture passive state',          weight: 5 },
  { id: 'deep',     label: 'Enable Deep mode (CDP debugger)',                   weight: 3 },
  { id: 'wait',     label: 'Wait for passive scan to settle',                   weight: 5 },
  { id: 'probe',    label: 'Run 36-step probe pipeline',                        weight: 47 },
  { id: 'matrix',   label: 'Run Authorization Matrix sweep',                    weight: 20 },
  { id: 'analyze',  label: 'Run chain correlator + aggregate findings',         weight: 5 },
  { id: 'report',   label: 'Draft HackerOne-format reports for High+ findings', weight: 10 },
  { id: 'finish',   label: 'Save drafts + fire notifications',                  weight: 5 },
];

async function startHunt() {
  const cfg = readConfig();
  if (!cfg.target) { toast('Target URL required'); return; }
  if (HUNT_STATE && HUNT_STATE.running) { toast('Hunt already running'); return; }

  HUNT_STATE = {
    running: true,
    startTime: Date.now(),
    config: cfg,
    currentStepIdx: 0,
    findings: [],
    chains: [],
    reports: [],
    abortRequested: false,
    feed: [],
  };
  $('huntStartBtn').style.display = 'none';
  $('huntStopBtn').style.display = '';
  setStatus('live', 'Hunting');
  switchSubtab('live');
  renderSteps();
  feedLine('info', 'Hunt started · target ' + cfg.target + ' · aggression ' + cfg.aggro + ' · budget ' + cfg.budgetMin + ' min');

  // Time budget timer
  HUNT_STATE.budgetTimer = setTimeout(() => {
    if (HUNT_STATE && HUNT_STATE.running) {
      feedLine('info', 'Time budget reached — stopping hunt');
      stopHunt();
    }
  }, cfg.budgetMin * 60 * 1000);

  // Live progress ticker
  HUNT_STATE.tickInterval = setInterval(updateProgress, 500);

  try {
    await runHuntLoop();
    if (HUNT_STATE && HUNT_STATE.running) {
      finishHunt('done');
    }
  } catch (e) {
    feedLine('crit', 'Hunt error: ' + (e.message || e));
    finishHunt('error');
  }
}

function stopHunt() {
  if (!HUNT_STATE) return;
  HUNT_STATE.abortRequested = true;
  feedLine('info', 'Stop requested — finishing current step then stopping');
  finishHunt('stopped');
}

function finishHunt(reason) {
  if (!HUNT_STATE) return;
  HUNT_STATE.running = false;
  if (HUNT_STATE.budgetTimer) clearTimeout(HUNT_STATE.budgetTimer);
  if (HUNT_STATE.tickInterval) clearInterval(HUNT_STATE.tickInterval);
  $('huntStartBtn').style.display = '';
  $('huntStopBtn').style.display = 'none';
  if (reason === 'done') setStatus('done', 'Done');
  else if (reason === 'error') setStatus('error', 'Error');
  else if (reason === 'stopped') setStatus('done', 'Stopped');
  const elapsed = Date.now() - HUNT_STATE.startTime;
  feedLine('info', 'Hunt finished — ' + fmtTime(elapsed) + ' · ' + (HUNT_STATE.reports || []).length + ' reports drafted');
  loadReports();
}

async function runHuntLoop() {
  const cfg = HUNT_STATE.config;

  // ---- Step 0: init ----
  setStep('init', 'live');
  feedLine('info', 'Connecting to background engine...');
  const initialState = await wbGetTabData();
  setStep('init', 'done', `${initialState.endpoints.length} endpoints captured passively`);
  if (HUNT_STATE.abortRequested) return;

  // ---- Step 0.5: Auto-enable Deep mode (CDP debugger). The probe step requires this;
  // without it the user gets "Probe error: Deep mode required" and the hunt produces
  // zero results. The debugger.attach API is granted at install time via the manifest
  // permission, so enableDeep just works without user interaction. If the source tab
  // is on a chrome:// page or the debugger is already attached by another extension,
  // attach fails — we surface the error but continue (passive findings still useful). ----
  setStep('deep', 'live');
  const deepRes = await new Promise(resolve => {
    chrome.runtime.sendMessage({ action: 'enableDeep', tabId: SOURCE_TAB_ID }, r => {
      void chrome.runtime.lastError;
      resolve(r || {});
    });
  });
  if (deepRes.ok) {
    setStep('deep', 'done', 'CDP attached — probe will run');
    feedLine('info', 'Deep mode auto-enabled. Probe pipeline will have full capabilities.');
  } else {
    setStep('deep', 'done', 'failed — passive only');
    feedLine('crit', 'Deep mode failed to attach (already attached by another extension, or source tab is internal). Probe will be skipped, but passive findings will still be drafted as reports.');
  }
  if (HUNT_STATE.abortRequested) return;

  // ---- Step 1: wait for passive scan to settle ----
  setStep('wait', 'live');
  await chrome.runtime.sendMessage({ action: 'runScan', tabId: SOURCE_TAB_ID }).catch(() => {});
  await delay(4000);  // give the content-script scan time to flush
  const afterScan = await wbGetTabData();
  setStep('wait', 'done', `${afterScan.endpoints.length} endpoints, ${afterScan.secrets.length} secrets, ${afterScan.techStack.length} tech detected`);
  if (HUNT_STATE.abortRequested) return;

  // ---- Step 2: probe pipeline ----
  if (cfg.runProbes) {
    setStep('probe', 'live');
    feedLine('info', 'Firing probe — this is the long step');
    const probeRes = await runProbeViaBackground(cfg);
    if (probeRes && probeRes.ok) {
      const reqs = probeRes.results?.requests || 0;
      setStep('probe', 'done', `${reqs} requests fired`);
      feedLine('info', `Probe complete — ${reqs} requests, results in tab.probeData`);
    } else {
      setStep('probe', 'done', 'failed: ' + (probeRes?.error || 'unknown'));
      feedLine('crit', 'Probe error: ' + (probeRes?.error || 'unknown') + ' (continuing with what we have)');
    }
  } else {
    setStep('probe', 'done', 'skipped (disabled in config)');
  }
  if (HUNT_STATE.abortRequested) return;

  // ---- Step 3: auth matrix ----
  if (cfg.runAuthMatrix) {
    setStep('matrix', 'live');
    const matrixRes = await runAuthMatrixSweep();
    setStep('matrix', 'done', matrixRes.message);
  } else {
    setStep('matrix', 'done', 'skipped (disabled in config)');
  }
  if (HUNT_STATE.abortRequested) return;

  // ---- Step 4: chain analyzer + finding aggregator ----
  // The chain correlator surfaces compound exploit paths (the killer feature). But on
  // sites where Deep mode failed or the probe found nothing, the analyzer might emit
  // 0 chains while we still have legitimate high-severity passive findings (exposed
  // secrets, JWT tokens, etc.) that absolutely warrant a bounty report. Fall back to
  // wrapping those individual findings as chain-shaped objects so the report composer
  // can draft them.
  setStep('analyze', 'live');
  const finalState = await wbGetTabData();
  let chains = filterChainsByScope(finalState.chains || [], cfg);

  // Add HUNT_STATE-internal matrix anomalies (synthesized by runAuthMatrixSweep)
  const matrixChains = (HUNT_STATE.chains || []).filter(c => c && c.findingType === 'authz-matrix');
  matrixChains.forEach(mc => {
    if (!chains.find(x => x.id === mc.id)) chains.push(mc);
  });

  // Fallback: synthesize chain-shaped objects for individual high/critical findings
  // that aren't already represented in a chain. This catches the "Deep mode failed +
  // 3 passive secrets sitting there" case where the chain count is 0 but reportable
  // findings exist. Same scope filter applies.
  const passiveFindings = collectIndividualFindings(finalState, cfg);
  passiveFindings.forEach(f => chains.push(f));

  // Severity filter: when chainOnly is on, restrict to Critical + High. Otherwise
  // include everything (some hunters prefer a full draft queue).
  if (cfg.chainOnly) {
    chains = chains.filter(c => c.severity === 'critical' || c.severity === 'high');
  }

  // Final dedupe by id so a real chain and its corresponding individual finding don't
  // both produce reports.
  const seenIds = new Set();
  chains = chains.filter(c => {
    if (!c.id) return true;
    if (seenIds.has(c.id)) return false;
    seenIds.add(c.id);
    return true;
  });

  HUNT_STATE.chains = chains;
  setStep('analyze', 'done', `${chains.length} reportable items in scope`);
  feedLine('info', `Found ${chains.length} reportable items in scope (chains + individual high/critical findings)`);
  if (HUNT_STATE.abortRequested) return;

  // ---- Step 5: draft reports ----
  setStep('report', 'live');
  const reports = [];
  for (const chain of chains) {
    if (HUNT_STATE.abortRequested) break;
    const report = composeReport(chain, finalState, cfg);
    reports.push(report);
    HUNT_STATE.reports = reports;
    feedLine(severityFeedKind(chain.severity), `Drafted: [${(chain.severity || 'info').toUpperCase()}] ${chain.title}`);
    if (cfg.notify && (chain.severity === 'critical' || chain.severity === 'high')) {
      fireNotification(chain, report);
    }
    updateProgress();
  }
  setStep('report', 'done', `${reports.length} reports composed`);

  // ---- Step 6: persist ----
  setStep('finish', 'live');
  await persistReports(reports);
  setStep('finish', 'done', 'saved to local storage');
  feedLine('info', 'All reports saved · view in Reports tab');
}

// Synthesize chain-shaped objects from individual passive findings. Used as a fallback
// when the chain correlator emits few/no chains (e.g. Deep mode failed and probe didn't
// run). Each returned object has the same shape as a real chain — composeReport doesn't
// have to know the difference.
//
// Sources walked: secrets (high+), exposed-env probe results, JWT findings with weak
// algorithms, source map URLs (medium-severity). Extend conservatively — we don't want
// to draft 200 reports for medium-severity info leaks.
function collectIndividualFindings(state, cfg) {
  const out = [];
  const inP = cfg.inScope || [];
  const outP = cfg.outScope || [];
  function pathInScope(path) {
    if (!path) return true;
    if (outP.length && pathMatchesAny(path, outP)) return false;
    if (inP.length && !pathMatchesAny(path, inP)) return false;
    return true;
  }

  // Secrets — high & critical severity only. The content scan and probe both populate
  // this list. Each becomes a wrapped finding with a real curl repro.
  (state.secrets || []).forEach((s, idx) => {
    if (!s || (s.severity !== 'critical' && s.severity !== 'high')) return;
    if (!pathInScope(s.source || '')) return;
    const valuePreview = String(s.value || '').substring(0, 80);
    out.push({
      id: 'secret-' + (s.type || 'unk').toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + idx,
      severity: s.severity,
      title: `Exposed ${s.type || 'secret'}`,
      summary: `PenScope detected an exposed ${s.type || 'secret'} during recon. Source: \`${s.source || 'unknown source'}\`. Value preview: \`${valuePreview}${(s.value || '').length > 80 ? '…' : ''}\`. ${s.context ? 'Context: ' + s.context.substring(0, 200) : ''} Hardcoded secrets in shipped code/responses are immediately exploitable — assume the credential is compromised the moment it's served.`,
      findings: [{ type: s.type || 'exposed-secret', source: s.source, evidence: valuePreview, path: s.source || '' }],
      reproCmd: s.source && /^https?:/i.test(s.source)
        ? `curl -i "${s.source}" | grep -i "${(s.type || '').split(' ')[0].toLowerCase()}"`
        : `# Verify the exposed secret is reachable\n# Source: ${s.source || '(unknown)'}\n# Value: ${valuePreview}`,
      nextSteps: [
        'Confirm the secret is valid by testing it against the corresponding API',
        'Determine the blast radius (what does this credential authorize?)',
        'Notify the program — exposed secrets are typically high-severity even before exploitation',
      ],
      confidence: 0.85,
      findingType: 'exposed-secret',
    });
  });

  // JWT findings with alg=none or weak algorithms — these are immediately exploitable
  // for auth bypass. Promote to chain-shape for report drafting.
  (state.probeData?.jwtAlgResults || []).forEach((j, idx) => {
    if (!j.confirmed) return;
    if (!pathInScope(j.path || '')) return;
    out.push({
      id: 'jwt-alg-' + idx,
      severity: 'critical',
      title: `JWT alg=none accepted on ${j.path || 'endpoint'}`,
      summary: `The server at \`${j.path}\` accepts JWTs with \`alg=none\` (unsigned). Any attacker can forge a token with arbitrary claims (including \`role: admin\`) and the server will trust it. This is a complete authentication bypass.`,
      findings: [{ type: 'jwt-alg-none', path: j.path, evidence: j.note || 'server accepted unsigned token' }],
      reproCmd: `# Forge an alg=none token (use PenScope Workbench → Encoder → JWT card)\nheader='{"alg":"none","typ":"JWT"}'\npayload='{"sub":"admin","role":"admin","exp":9999999999}'\ntoken="$(echo -n $header|base64|tr '+/' '-_'|tr -d '=').$(echo -n $payload|base64|tr '+/' '-_'|tr -d '=')."\ncurl -i -H "Authorization: Bearer $token" "${j.path}"`,
      nextSteps: ['Verify by sending a forged token to a privileged endpoint', 'Check the impact (what can the forged role do?)', 'Submit immediately — this is critical'],
      confidence: 0.95,
      findingType: 'jwt-alg-none',
    });
  });

  // Confirmed SSTI / XXE / CRLF / IDOR / BAC findings from the probe. The chain
  // correlator usually wraps these into chains, but if the chain analyzer skipped
  // them for some reason, we still want to draft.
  const promote = (results, kind, sev, label, fixHint) => {
    (results || []).forEach((r, idx) => {
      if (!r.confirmed) return;
      if (!pathInScope(r.path || '')) return;
      out.push({
        id: kind + '-' + idx,
        severity: sev,
        title: `${label} on ${r.path || 'endpoint'}`,
        summary: `Confirmed ${label.toLowerCase()} on \`${r.path}\`. ${r.evidence ? 'Evidence: ' + String(r.evidence).substring(0, 200) : ''} ${fixHint}`,
        findings: [{ type: kind, path: r.path, evidence: r.evidence || '' }],
        reproCmd: `# Re-test ${label.toLowerCase()} on the affected endpoint\ncurl -i "${r.path}"`,
        nextSteps: ['Re-verify with a clean session', 'Determine the impact', 'Document for the report'],
        confidence: 0.9,
        findingType: kind,
      });
    });
  };
  promote(state.probeData?.sstiResults, 'ssti', 'critical', 'Server-side template injection', 'SSTI usually means RCE.');
  promote(state.probeData?.xxeResults, 'xxe', 'critical', 'XML External Entity injection', 'XXE allows file disclosure, SSRF, sometimes RCE.');
  promote(state.probeData?.crlfResults, 'crlf', 'high', 'CRLF injection', 'Enables response splitting, cache poisoning, header injection.');

  return out;
}

// Filter chains by scope rules. A chain is in scope if any of its findings'
// paths match the inScope patterns AND none match the outScope patterns.
// If inScope is empty, all paths are considered in (just exclude outScope).
function filterChainsByScope(chains, cfg) {
  const inP = cfg.inScope || [];
  const outP = cfg.outScope || [];
  if (!inP.length && !outP.length) return chains;
  return chains.filter(chain => {
    const findings = chain.findings || [];
    if (!findings.length) return true;  // no path data — don't filter out
    const paths = findings.map(f => f.path || '').filter(Boolean);
    if (!paths.length) return true;
    if (outP.length && paths.every(p => pathMatchesAny(p, outP))) return false;
    if (inP.length && !paths.some(p => pathMatchesAny(p, inP))) return false;
    return true;
  });
}

// -------------------------------------------------------------------
// Sub-step runners (wrap existing background message handlers)
// -------------------------------------------------------------------
function wbGetTabData() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ action: 'getData', tabId: SOURCE_TAB_ID }, data => {
      // Touch lastError to silence channel-closed warnings
      void chrome.runtime.lastError;
      const d = data || {};
      resolve({
        endpoints: d.endpoints || [],
        secrets: d.secrets || [],
        techStack: d.techStack || [],
        chains: d.exploitChains || [],
        probeData: d.probeData || null,
        cookies: d.cookies || [],
        url: d.url || '',
      });
    });
  });
}

function runProbeViaBackground(cfg) {
  // Note: the background's startProbe requires deep mode (debugger). The user must
  // have enabled Deep before launching Hunt. We surface the error if not.
  return new Promise(resolve => {
    chrome.runtime.sendMessage({
      action: 'startProbe',
      tabId: SOURCE_TAB_ID,
      aggroLevel: cfg.aggro,
      customHeaders: {},
      recursive: true,
      stealth: false,
    }, r => {
      void chrome.runtime.lastError;
      resolve(r || { ok: false, error: 'no response' });
    });
  });
}

// Authorization Matrix sweep. Pulls the saved auth contexts from background, then
// runs a bounded matrix scan. We call wbSendRequest per (endpoint, ctx) cell.
async function runAuthMatrixSweep() {
  const state = await new Promise(resolve => {
    chrome.runtime.sendMessage({ action: 'wbGetState', tabId: SOURCE_TAB_ID }, r => {
      void chrome.runtime.lastError;
      resolve(r || {});
    });
  });
  const auth = state.auth || { list: [] };
  const contexts = auth.list || [];
  if (contexts.length < 2) {
    return { message: 'need 2+ auth contexts (set up in Workbench → Auth)' };
  }
  const data = state.data || {};
  // Pick up to 25 unique target endpoints (in-scope only) for the matrix
  const cfg = HUNT_STATE.config;
  const seen = new Set();
  const targets = [];
  for (const ep of (data.endpoints || [])) {
    const key = (ep.method || 'GET') + ' ' + (ep.path || ep.url || '');
    if (seen.has(key)) continue;
    seen.add(key);
    // Filter by scope
    const path = ep.path || '';
    if (cfg.outScope.length && pathMatchesAny(path, cfg.outScope)) continue;
    if (cfg.inScope.length && !pathMatchesAny(path, cfg.inScope)) continue;
    targets.push(ep);
    if (targets.length >= 25) break;
  }
  if (!targets.length) return { message: 'no in-scope endpoints for matrix' };

  feedLine('info', `Authorization Matrix: ${targets.length} endpoints × ${contexts.length} contexts = ${targets.length * contexts.length} requests`);

  let anomalies = 0;
  const grid = {};
  for (const ep of targets) {
    if (HUNT_STATE.abortRequested) break;
    const epKey = (ep.method || 'GET') + ' ' + (ep.path || ep.url);
    grid[epKey] = {};
    const statuses = [];
    for (const ctx of contexts) {
      const resp = await new Promise(resolve => {
        chrome.runtime.sendMessage({
          action: 'wbSendRequest',
          tabId: SOURCE_TAB_ID,
          req: { method: ep.method || 'GET', url: ep.url || ep.path, headers: {}, body: '', ctxName: ctx.name },
        }, r => { void chrome.runtime.lastError; resolve(r || {}); });
      });
      grid[epKey][ctx.name] = { status: resp.status || 0, size: resp.size || 0 };
      statuses.push(resp.status || 0);
    }
    if (new Set(statuses).size > 1) {
      anomalies++;
      // Synthesize a synthetic chain-like object for matrix anomalies and add to chains
      const findingsList = contexts.map(c => ({ ctx: c.name, status: grid[epKey][c.name].status }));
      HUNT_STATE.chains = HUNT_STATE.chains || [];
      HUNT_STATE.chains.push({
        id: 'matrix-' + epKey.replace(/[^a-z0-9]+/gi, '-').substring(0, 60),
        severity: detectMatrixSeverity(grid[epKey], contexts),
        title: `Authorization disagreement: ${ep.method || 'GET'} ${ep.path || ''}`,
        summary: `Different auth contexts return different responses for ${ep.method || 'GET'} ${ep.path || ''}. Statuses: ${contexts.map(c => `${c.name}=${grid[epKey][c.name].status}`).join(', ')}. Likely IDOR or broken access control.`,
        findings: [{ type: 'authz-matrix-anomaly', path: ep.path || ep.url, method: ep.method || 'GET', evidence: JSON.stringify(findingsList) }],
        reproCmd: contexts.slice(0, 2).map(c => `# As ${c.name}\ncurl -i "${ep.url || ep.path}"   # adapt cookies/headers per context`).join('\n'),
        nextSteps: ['Verify the response bodies actually differ', 'Confirm with a burner account', 'Check whether the lower-priv user is seeing the higher-priv user\'s data'],
        confidence: 0.8,
        findingType: 'authz-matrix',
      });
      feedLine('high', `Matrix anomaly: ${ep.method || 'GET'} ${ep.path || ''} → ${contexts.map(c => grid[epKey][c.name].status).join('/')}`);
    }
  }
  return { message: `${targets.length * contexts.length} requests, ${anomalies} anomalies` };
}

// Heuristic severity for matrix anomalies. If a "lower" privilege context (Anonymous
// or named with "guest"/"user") returns 200 and a higher one returns 200 too, that
// might mean lower-priv can access higher-priv data → high. If contexts disagree
// only on 401/403, that's expected → low.
function detectMatrixSeverity(row, contexts) {
  const statuses = contexts.map(c => row[c.name].status);
  const has2xx = statuses.some(s => s >= 200 && s < 300);
  const has4xx = statuses.some(s => s >= 400 && s < 500);
  const anonIdx = contexts.findIndex(c => /anon|public/i.test(c.name));
  if (anonIdx >= 0) {
    const anonStatus = row[contexts[anonIdx].name].status;
    if (anonStatus >= 200 && anonStatus < 300 && contexts.some(c => c !== contexts[anonIdx] && row[c.name].status >= 400)) {
      // Anonymous gets in but other contexts don't — weird but probably not a bug
      return 'medium';
    }
    if (anonStatus >= 400 && contexts.some(c => c !== contexts[anonIdx] && row[c.name].status >= 200 && row[c.name].status < 300)) {
      // Anonymous denied, others allowed — expected. Check for low-priv vs high-priv leak instead
      const others = contexts.filter((_, i) => i !== anonIdx);
      const allOthers200 = others.every(c => row[c.name].status >= 200 && row[c.name].status < 300);
      if (allOthers200 && others.length >= 2) return 'high';  // multiple privilege levels all see same data
      return 'medium';
    }
  }
  if (has2xx && has4xx) return 'high';
  return 'low';
}

// -------------------------------------------------------------------
// Report composer — full HackerOne-format markdown
// -------------------------------------------------------------------
function composeReport(chain, state, cfg) {
  const sev = (chain.severity || 'medium').toLowerCase();
  const sevLabel = sev.toUpperCase();
  const cvssRange = { critical: '9.0–10.0', high: '7.0–8.9', medium: '4.0–6.9', low: '0.1–3.9', info: 'N/A' }[sev] || '4.0–6.9';
  const conf = Math.round((chain.confidence || 0.5) * 100);
  const target = state.url || cfg.target || '';
  let host = '';
  try { host = new URL(target).hostname; } catch (e) {}

  // Suggested fix from blue-fixes mapping (if loaded). Falls back to generic.
  const fix = generateFixHint(chain);

  // Steps to reproduce — derive from chain.reproCmd
  const steps = chain.reproCmd
    ? chain.reproCmd.split('\n').filter(Boolean)
    : [`curl -i "${target}${(chain.findings && chain.findings[0] && chain.findings[0].path) || '/'}"`];

  const md = `# ${chain.title || 'Security finding'}

**Severity:** ${sevLabel} _(CVSS estimate: ${cvssRange})_
**Confidence:** ${conf}%
**Target:** ${target}
**Discovered:** ${new Date().toISOString()}
**Detected by:** PenScope v6.2 Hunt Mode (chain pattern: \`${chain.findingType || chain.id || 'compound'}\`)

---

## Summary

${chain.summary || 'PenScope detected a compound exploit chain combining multiple findings into an exploitable path.'}

${(chain.findings || []).length ? `\nThis chain combines **${(chain.findings || []).length} signal${(chain.findings || []).length === 1 ? '' : 's'}** observed during recon:\n${(chain.findings || []).slice(0, 6).map(f => `- ${f.type || 'finding'}${f.path ? ' on \`' + f.path + '\`' : ''}${f.evidence ? ': ' + String(f.evidence).substring(0, 120) : ''}`).join('\n')}\n` : ''}

## Steps to reproduce

\`\`\`bash
${steps.join('\n')}
\`\`\`

${chain.nextSteps && chain.nextSteps.length ? `Additional verification steps:\n${chain.nextSteps.slice(0, 6).map(s => `1. ${s}`).join('\n')}\n` : ''}

## Impact

${impactStatement(chain, sev)}

${fix.section}

## Detection methodology

PenScope's chain correlator surfaced this compound finding by combining outputs from multiple subsystems:

${(chain.findings || []).slice(0, 4).map(f => `- ${f.type || 'finding'}${f.source ? ' (source: ' + f.source + ')' : ''}`).join('\n') || '- Multiple chain inputs (see attached scan data)'}

The combination meets PenScope's pattern \`${chain.findingType || chain.id || 'compound'}\` with confidence ${conf}%. Severity assigned per the chain analyzer's severity × confidence ranking.

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE List](https://cwe.mitre.org/data/index.html)
${fix.references.map(r => `- ${r}`).join('\n')}

---
_Report drafted automatically by PenScope Hunt Mode. Verify each finding manually before submitting to a bounty program._`;

  return {
    id: 'r-' + Date.now() + '-' + Math.floor(Math.random() * 9999),
    chainId: chain.id || null,
    severity: sev,
    title: chain.title || 'Security finding',
    host,
    target,
    timestamp: Date.now(),
    confidence: conf,
    chain,
    markdown: md,
  };
}

function impactStatement(chain, sev) {
  const sevImpact = {
    critical: "Successful exploitation enables an attacker to bypass core security controls, gain unauthorized access to sensitive functionality or data, and pivot to broader compromise. This is a credible breach path warranting immediate remediation.",
    high: "Successful exploitation bypasses intended access controls and exposes sensitive data or operations to unauthorized actors. Should be remediated as a priority.",
    medium: "Exploitation weakens the security posture and provides a foothold for further attacks. Should be addressed in the next sprint.",
    low: "Minor issue that hardens the security posture if remediated. Low priority but worth tracking.",
  };
  const generic = sevImpact[sev] || sevImpact.medium;
  // If chain summary explicitly mentions specific impact, append context
  const specifics = [];
  if (/admin|privilege|escalat/i.test(chain.summary || '')) specifics.push('privilege escalation to administrator');
  if (/idor|other user|cross.user/i.test(chain.summary || '')) specifics.push('access to other users\' data (IDOR)');
  if (/rce|code execution|shell/i.test(chain.summary || '')) specifics.push('remote code execution');
  if (/data leak|secret|credential|token/i.test(chain.summary || '')) specifics.push('exposure of credentials or sensitive data');
  if (/csrf|forgery/i.test(chain.summary || '')) specifics.push('cross-site request forgery enabling state-changing actions');
  const tail = specifics.length ? `\n\nSpecifically, this chain enables: ${specifics.join(', ')}.` : '';
  return generic + tail;
}

// Pull a remediation hint. If background ever exposes blue-fixes, route through it.
// For now use a small inline mapping covering common chain types.
function generateFixHint(chain) {
  const sec = (key) => '\n## Suggested fix\n\n' + key;
  const findingType = (chain.findingType || chain.id || '').toLowerCase();
  const summary = (chain.summary || '').toLowerCase();
  if (/auth.?bypass|auth.?removal/.test(findingType + summary)) return {
    section: sec("Enforce server-side authentication on every endpoint that returns sensitive data. The fact that PenScope received a 200 with no cookies means the authorization middleware is missing or disabled for this route.\n\n```\n// Express\nfunction requireAuth(req, res, next) { if (!req.user) return res.status(401).end(); next(); }\napp.get('/api/admin/users', requireAuth, handler);\n```"),
    references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
  };
  if (/idor|same.body/.test(findingType + summary)) return {
    section: sec("Scope every database query by the authenticated user, not just by the resource ID. Verify resource ownership before returning data.\n\n```\n// BAD\nconst order = await Order.findById(req.params.id);\n// GOOD\nconst order = await Order.findOne({ _id: req.params.id, userId: req.user.id });\nif (!order) return res.status(404).end();\n```"),
    references: ['https://cwe.mitre.org/data/definitions/639.html']
  };
  if (/jwt.?(none|alg)/.test(findingType + summary)) return {
    section: sec("Pin the allowed JWT algorithm explicitly when verifying tokens. Never let the JWT itself dictate the algorithm.\n\n```\n// jsonwebtoken (Node)\njwt.verify(token, secret, { algorithms: ['HS256'] });\n// PyJWT\njwt.decode(token, secret, algorithms=['HS256'])\n```"),
    references: ['https://cwe.mitre.org/data/definitions/347.html']
  };
  if (/cors/.test(findingType + summary)) return {
    section: sec("Replace any wildcard or reflected `Access-Control-Allow-Origin` with an explicit allowlist. Especially do not combine reflected origin with `Access-Control-Allow-Credentials: true`.\n\n```\nconst ALLOW = new Set(['https://app.example.com']);\napp.use((req, res, next) => {\n  const o = req.headers.origin;\n  if (ALLOW.has(o)) {\n    res.setHeader('Access-Control-Allow-Origin', o);\n    res.setHeader('Access-Control-Allow-Credentials', 'true');\n  }\n  next();\n});\n```"),
    references: ['https://cwe.mitre.org/data/definitions/942.html']
  };
  if (/csrf/.test(findingType + summary)) return {
    section: sec("Add CSRF tokens to every state-changing form. SameSite=Strict cookies help but tokens remain the standard defense.\n\n```\nconst csurf = require('csurf');\napp.use(csurf({ cookie: true }));\n```"),
    references: ['https://cwe.mitre.org/data/definitions/352.html']
  };
  if (/source.?map|sourcemap/.test(findingType + summary)) return {
    section: sec("Remove `.map` files from production deploys. Block at the edge:\n\n```nginx\nlocation ~* \\.map$ { deny all; return 404; }\n```\n\nFix the build config so source maps don't ship in production:\n\n```\n// Webpack\nmodule.exports = { devtool: false };\n// Vite\nbuild: { sourcemap: false }\n```"),
    references: ['https://cwe.mitre.org/data/definitions/540.html']
  };
  if (/secret|exposed.?secret|api.?key|token.?leak/.test(findingType + summary)) return {
    section: sec("Rotate the exposed secret immediately — assume it's compromised. Remove from source, purge from git history, inject from a secrets manager at runtime."),
    references: ['https://cwe.mitre.org/data/definitions/798.html']
  };
  if (/redirect/.test(findingType + summary)) return {
    section: sec("Validate every redirect target against an allowlist. Don't trust user-controlled URLs.\n\n```\nconst ALLOW = ['/dashboard', '/profile'];\nfunction safe(t) { return ALLOW.includes(t) ? t : '/'; }\n```"),
    references: ['https://cwe.mitre.org/data/definitions/601.html']
  };
  if (/ssti/.test(findingType + summary)) return {
    section: sec("Never pass user input into a template engine context. Render via `{{ variable }}` (auto-escaped), not via `render_template_string(user_input)`."),
    references: ['https://cwe.mitre.org/data/definitions/1336.html']
  };
  if (/stack|actuator|ignition|telescope|elmah|trace\.axd/.test(findingType + summary)) return {
    section: sec("Disable the framework's debug/admin endpoints in production. Most stacks have explicit settings:\n\n```\n# Spring Boot\nmanagement.endpoints.web.exposure.include=health,info\n# Laravel: remove /telescope, /horizon middleware in production\n# ASP.NET: remove trace.axd, elmah.axd from web.config\n```"),
    references: ['https://cwe.mitre.org/data/definitions/489.html']
  };
  if (/authz.?matrix|authorization.?disagree/.test(findingType + summary)) return {
    section: sec("The authorization matrix found endpoints where different user roles return different responses. Verify each one — if a lower-privilege role is seeing data intended for a higher-privilege one, that's IDOR/BAC. Enforce role checks server-side at every endpoint."),
    references: ['https://cwe.mitre.org/data/definitions/285.html']
  };
  return {
    section: sec("Apply standard remediation for this finding type. Enforce server-side authorization, validate input, scope queries by authenticated user, and add coverage for this case in your security regression suite."),
    references: []
  };
}

function severityFeedKind(sev) {
  if (sev === 'critical') return 'crit';
  if (sev === 'high') return 'high';
  if (sev === 'medium') return 'med';
  return 'info';
}

// -------------------------------------------------------------------
// Notifications
// -------------------------------------------------------------------
function fireNotification(chain, report) {
  // The chrome.notifications API requires the "notifications" permission (already in
  // manifest as of v6.0). Notification ID is unique so multiple notifications stack.
  try {
    chrome.notifications.create('hunt-' + report.id, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: `Hunt Mode: ${(chain.severity || 'medium').toUpperCase()} chain found`,
      message: `${chain.title} on ${TARGET_HOST || 'target'} — report draft ready`,
      priority: 2,
    }, () => { void chrome.runtime.lastError; });
  } catch (e) { /* notifications API unavailable */ }
}

// -------------------------------------------------------------------
// Persistence — chrome.storage.local keyed by host
// -------------------------------------------------------------------
async function persistReports(reports) {
  if (!reports || !reports.length) return;
  const key = 'ps:hunt:' + (TARGET_HOST || 'unknown');
  try {
    const stored = await chrome.storage.local.get(key);
    const bucket = stored[key] || { reports: [] };
    // Dedupe by chainId — if a hunt re-discovers the same chain, replace the existing
    reports.forEach(r => {
      const existingIdx = bucket.reports.findIndex(x => x.chainId && r.chainId && x.chainId === r.chainId);
      if (existingIdx >= 0) bucket.reports[existingIdx] = r;
      else bucket.reports.push(r);
    });
    // Cap 100 reports per host (FIFO)
    if (bucket.reports.length > 100) bucket.reports = bucket.reports.slice(-100);
    await chrome.storage.local.set({ [key]: bucket });
  } catch (e) { console.warn('persistReports', e); }
}

async function loadReports() {
  if (!TARGET_HOST) {
    SAVED_REPORTS = [];
    renderReports();
    return;
  }
  const key = 'ps:hunt:' + TARGET_HOST;
  try {
    const stored = await chrome.storage.local.get(key);
    SAVED_REPORTS = ((stored[key] || { reports: [] }).reports || []).slice().reverse();  // newest first
  } catch (e) { SAVED_REPORTS = []; }
  renderReports();
}

function renderReports() {
  $('reportCountBadge').textContent = SAVED_REPORTS.length;
  $('reportsHostMeta').textContent = TARGET_HOST ? `host: ${TARGET_HOST} · ${SAVED_REPORTS.length} drafts` : '';
  const list = $('reportsList');
  if (!SAVED_REPORTS.length) {
    list.innerHTML = `<div class="reports-empty"><div class="reports-empty-i">📋</div><div class="reports-empty-t">No reports yet — start a hunt</div></div>`;
    return;
  }
  list.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'report-list';
  SAVED_REPORTS.forEach(r => {
    const card = document.createElement('div');
    card.className = 'report-card ' + (r.severity || 'med');
    const sevClass = (r.severity || 'medium') === 'critical' ? 'crit' : (r.severity || 'medium') === 'high' ? 'high' : (r.severity || 'medium') === 'medium' ? 'med' : 'low';
    card.innerHTML = `
      <div class="report-head">
        <span class="report-sev ${sevClass}">${esc((r.severity || 'medium'))}</span>
        <span class="report-title">${esc(r.title)}</span>
        <span class="report-time">${new Date(r.timestamp).toLocaleString()}</span>
      </div>
      <div class="report-summary">${esc((r.chain && r.chain.summary) ? r.chain.summary.substring(0, 220) : '(no summary)')}${r.chain && r.chain.summary && r.chain.summary.length > 220 ? '…' : ''}</div>`;
    card.addEventListener('click', () => openReportModal(r));
    wrap.appendChild(card);
  });
  list.appendChild(wrap);
}

function openReportModal(report) {
  CURRENT_VIEWING_REPORT = report;
  $('modalTitle').textContent = report.title;
  $('modalBody').textContent = report.markdown;
  $('modalMeta').textContent = `${report.severity.toUpperCase()} · ${new Date(report.timestamp).toLocaleString()} · conf ${report.confidence}%`;
  $('reportModal').classList.add('show');
}

async function deleteReport(id) {
  const key = 'ps:hunt:' + TARGET_HOST;
  try {
    const stored = await chrome.storage.local.get(key);
    const bucket = stored[key] || { reports: [] };
    bucket.reports = bucket.reports.filter(r => r.id !== id);
    await chrome.storage.local.set({ [key]: bucket });
    SAVED_REPORTS = SAVED_REPORTS.filter(r => r.id !== id);
    $('reportModal').classList.remove('show');
    renderReports();
    toast('Draft deleted');
  } catch (e) { toast('Delete failed'); }
}

async function clearAllReports() {
  if (!confirm('Delete ALL drafts for ' + (TARGET_HOST || 'this host') + '?')) return;
  const key = 'ps:hunt:' + TARGET_HOST;
  try {
    await chrome.storage.local.remove(key);
    SAVED_REPORTS = [];
    renderReports();
    toast('All drafts cleared');
  } catch (e) { toast('Clear failed'); }
}

function exportSingleReport(report) {
  const blob = new Blob([report.markdown], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `penscope-${(TARGET_HOST || 'target').replace(/[^a-z0-9]/gi, '_')}-${report.severity}-${report.id}.md`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportAllReports() {
  if (!SAVED_REPORTS.length) { toast('No drafts to export'); return; }
  const combined = SAVED_REPORTS.map(r => r.markdown).join('\n\n---\n\n');
  const blob = new Blob([combined], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `penscope-hunt-${(TARGET_HOST || 'target').replace(/[^a-z0-9]/gi, '_')}-${Date.now()}.md`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(`Exported ${SAVED_REPORTS.length} reports`);
}

// -------------------------------------------------------------------
// Live progress UI
// -------------------------------------------------------------------
function setStep(id, status, meta) {
  if (!HUNT_STATE) return;
  const idx = HUNT_STEPS.findIndex(s => s.id === id);
  if (idx < 0) return;
  HUNT_STATE.currentStepIdx = Math.max(HUNT_STATE.currentStepIdx, idx);
  if (status === 'done' && idx === HUNT_STATE.currentStepIdx) HUNT_STATE.currentStepIdx = idx + 1;
  HUNT_STATE._stepStatus = HUNT_STATE._stepStatus || {};
  HUNT_STATE._stepStatus[id] = { status, meta: meta || '' };
  renderSteps();
  updateProgress();
}

function renderSteps() {
  if (!HUNT_STATE) return;
  const list = $('stepList');
  let html = '';
  HUNT_STEPS.forEach((s, idx) => {
    const ss = HUNT_STATE._stepStatus && HUNT_STATE._stepStatus[s.id];
    const status = ss ? ss.status : (idx < HUNT_STATE.currentStepIdx ? 'done' : 'pending');
    const meta = ss ? ss.meta : '';
    html += `<div class="step ${status}">
      <div class="step-icon">${status === 'done' ? '✓' : status === 'live' ? '●' : (idx + 1)}</div>
      <div class="step-text">${esc(s.label)}</div>
      <div class="step-meta">${esc(meta)}</div>
    </div>`;
  });
  list.innerHTML = html;
}

function updateProgress() {
  if (!HUNT_STATE) return;
  // Compute progress as cumulative weight of completed steps + current step's partial
  let done = 0, total = 0;
  HUNT_STEPS.forEach((s, idx) => {
    total += s.weight;
    const ss = HUNT_STATE._stepStatus && HUNT_STATE._stepStatus[s.id];
    if (ss && ss.status === 'done') done += s.weight;
    else if (ss && ss.status === 'live') done += s.weight * 0.4;
  });
  const pct = total ? Math.round((done / total) * 100) : 0;
  $('progressBar').style.width = pct + '%';
  $('progressPct').textContent = pct + '%';
  $('progressStep').textContent = (HUNT_STATE.currentStepIdx + 1);
  $('progressTotal').textContent = HUNT_STEPS.length;
  const elapsed = Date.now() - HUNT_STATE.startTime;
  $('progressElapsed').textContent = fmtTime(elapsed);
  if (pct > 5 && pct < 100) {
    const eta = Math.round((elapsed / pct) * (100 - pct));
    $('progressEta').textContent = fmtTime(eta);
  } else {
    $('progressEta').textContent = '—';
  }
  // Stats
  $('statEndpoints').textContent = (HUNT_STATE._lastState && HUNT_STATE._lastState.endpoints.length) || '0';
  $('statRequests').textContent = (HUNT_STATE._lastState && HUNT_STATE._lastState.probeData && HUNT_STATE._lastState.probeData.requests) || '0';
  $('statFindings').textContent = (HUNT_STATE._lastState && HUNT_STATE._lastState.secrets.length) || '0';
  $('statChains').textContent = (HUNT_STATE.chains || []).length;
  $('statReports').textContent = (HUNT_STATE.reports || []).length;
}

function feedLine(kind, text) {
  if (!HUNT_STATE) return;
  HUNT_STATE.feed = HUNT_STATE.feed || [];
  HUNT_STATE.feed.push({ kind, text, ts: Date.now() });
  if (HUNT_STATE.feed.length > 200) HUNT_STATE.feed.shift();
  const feed = $('liveFeed');
  const line = document.createElement('div');
  line.className = 'feed-line ' + kind;
  const icon = kind === 'crit' ? '◆' : kind === 'high' ? '◆' : kind === 'med' ? '●' : '·';
  line.innerHTML = `<span class="feed-time">${new Date().toLocaleTimeString()}</span><span class="feed-icon">${icon}</span><span class="feed-text">${esc(text)}</span>`;
  if (feed.firstElementChild && feed.firstElementChild.style && feed.firstElementChild.style.padding) feed.innerHTML = '';
  feed.appendChild(line);
  feed.scrollTop = feed.scrollHeight;
  // Update last-state cache for stats
  wbGetTabData().then(s => { if (HUNT_STATE) HUNT_STATE._lastState = s; updateProgress(); }).catch(() => {});
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
