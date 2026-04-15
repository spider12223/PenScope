// PenScope v5.8 — Popup Logic
let tabId=null,D=null;

// Delegated click handler for all interactive elements (MV3 CSP compliant — no inline onclick)
document.addEventListener("click",e=>{
  const el=e.target.closest("[data-copy]");
  if(el){navigator.clipboard.writeText(el.getAttribute("data-copy"));return;}
  const el2=e.target.closest("[data-copytext]");
  if(el2){navigator.clipboard.writeText(el2.textContent);return;}
  const el3=e.target.closest("[data-toggle]");
  if(el3&&el3.nextElementSibling){el3.nextElementSibling.style.display=el3.nextElementSibling.style.display==="none"?"block":"none";return;}
  const el4=e.target.closest("[data-dlmap]");
  if(el4){downloadSourceMap(el4.getAttribute("data-dlmap"),el4.getAttribute("data-dlfname")||"source.map");return;}
  const el5=e.target.closest("[data-decodeidx]");
  if(el5){decodeBlob(parseInt(el5.getAttribute("data-decodeidx")),el5.getAttribute("data-decodetype"));return;}
});

document.addEventListener("DOMContentLoaded",async()=>{const[tab]=await chrome.tabs.query({active:true,currentWindow:true});if(!tab)return;tabId=tab.id;document.getElementById("tgtUrl").textContent=tab.url||"—";chrome.runtime.sendMessage({action:"runScan",tabId},()=>setTimeout(load,600));chrome.runtime.sendMessage({action:"getCookies",tabId});document.querySelectorAll(".tab").forEach(t=>t.addEventListener("click",()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));document.querySelectorAll(".tc").forEach(x=>x.classList.remove("active"));t.classList.add("active");document.getElementById(`t-${t.dataset.t}`).classList.add("active");}));document.getElementById("btnScan").addEventListener("click",()=>{chrome.runtime.sendMessage({action:"runScan",tabId},()=>setTimeout(load,800));});document.getElementById("btnClear").addEventListener("click",()=>{chrome.runtime.sendMessage({action:"clearData",tabId},()=>load());});document.getElementById("btnClaude").addEventListener("click",sendToClaude);document.getElementById("btnDeep").addEventListener("click",toggleDeep);const expBtn=document.getElementById("btnExport"),expMenu=document.getElementById("exportMenu");expBtn.addEventListener("click",e=>{e.stopPropagation();expMenu.classList.toggle("show");});document.addEventListener("click",()=>expMenu.classList.remove("show"));expMenu.querySelectorAll(".exp-item").forEach(i=>i.addEventListener("click",e=>{e.stopPropagation();exportData(i.dataset.fmt);expMenu.classList.remove("show");}));document.getElementById("fE").addEventListener("input",e=>renderEndpoints(D?.endpoints||[],e.target.value));document.getElementById("fL").addEventListener("input",e=>renderLinks(D?.links||[],e.target.value));document.getElementById("fC").addEventListener("input",e=>renderConsole(e.target.value));document.getElementById("btnProbe").addEventListener("click",toggleProbe);
// Deep dropdown
const deepDropBtn=document.getElementById("btnDeepDrop"),deepMenu=document.getElementById("deepMenu");
deepDropBtn.addEventListener("click",e=>{e.stopPropagation();deepMenu.classList.toggle("show");});
document.addEventListener("click",e=>{if(!e.target.closest(".deep-wrap"))deepMenu.classList.remove("show");});
document.getElementById("deepOptToggle").addEventListener("click",()=>{deepMenu.classList.remove("show");toggleDeep();});
document.getElementById("deepOptSourceMaps").addEventListener("click",()=>{deepMenu.classList.remove("show");startSourceMapScan();});
// Probe dropdown
const activeDropBtn=document.getElementById("btnProbeDrop"),probeMenu=document.getElementById("probeMenu");
activeDropBtn.addEventListener("click",e=>{e.stopPropagation();probeMenu.classList.toggle("show");});
document.addEventListener("click",e=>{if(!e.target.closest("#probeMenu")&&!e.target.closest("#btnProbeDrop"))probeMenu.classList.remove("show");});
probeMenu.querySelectorAll("[data-aggro]").forEach(i=>i.addEventListener("click",e=>{
  e.stopPropagation();probeMenu.classList.remove("show");
  const level=i.getAttribute("data-aggro");
  startProbeWithLevel(level);
}));
document.getElementById("smapClose").addEventListener("click",()=>{document.getElementById("smapOverlay").classList.remove("show");});
document.getElementById("smapOverlay").addEventListener("click",e=>{if(e.target.id==="smapOverlay")e.target.classList.remove("show");});
document.getElementById("smapDownloadAll").addEventListener("click",downloadAllSourceMaps);
// v5.7: Load saved custom headers and probe preferences from chrome.storage.local
try{chrome.storage.local.get(["penscopeCustomHeaders","penscopeRecursive","penscopeStealth"],r=>{
  const hdrEl=document.getElementById("probeHeaders");
  if(hdrEl&&r.penscopeCustomHeaders)hdrEl.value=r.penscopeCustomHeaders;
  const recEl=document.getElementById("probeRecursive");
  if(recEl&&typeof r.penscopeRecursive==="boolean")recEl.checked=r.penscopeRecursive;
  const stlEl=document.getElementById("probeStealth");
  if(stlEl&&typeof r.penscopeStealth==="boolean")stlEl.checked=r.penscopeStealth;
});}catch(e){}
const hdrTextarea=document.getElementById("probeHeaders");
if(hdrTextarea){
  hdrTextarea.addEventListener("click",e=>e.stopPropagation());
  hdrTextarea.addEventListener("input",e=>{
    try{chrome.storage.local.set({penscopeCustomHeaders:e.target.value});}catch(err){}
  });
}
const recCb=document.getElementById("probeRecursive");
if(recCb){
  recCb.addEventListener("click",e=>e.stopPropagation());
  recCb.addEventListener("change",e=>{
    try{chrome.storage.local.set({penscopeRecursive:e.target.checked});}catch(err){}
  });
}
const stCb=document.getElementById("probeStealth");
if(stCb){
  stCb.addEventListener("click",e=>e.stopPropagation());
  stCb.addEventListener("change",e=>{
    try{chrome.storage.local.set({penscopeStealth:e.target.checked});}catch(err){}
  });
}
// v5.8: Deep tab filter — hide/show sections by substring match
const fDeep=document.getElementById("fD");
if(fDeep){
  fDeep.addEventListener("input",e=>{
    const f=(e.target.value||"").toLowerCase();
    const c=document.getElementById("rD");
    if(!c)return;
    const sections=c.querySelectorAll(".hs");
    if(!f){sections.forEach(s=>{s.style.display="";});return;}
    sections.forEach(s=>{
      const text=(s.textContent||"").toLowerCase();
      s.style.display=text.indexOf(f)>-1?"":"none";
    });
  });
}
// v5.8: Deep tab collapse-all / expand-all buttons
document.getElementById("dExpAll")?.addEventListener("click",()=>{
  document.querySelectorAll("#rD .hs").forEach(s=>s.classList.remove("collapsed"));
  _collapsedSections.clear();
});
document.getElementById("dColAll")?.addEventListener("click",()=>{
  document.querySelectorAll("#rD .hs").forEach(s=>{
    s.classList.add("collapsed");
    const t=s.querySelector(".hs-t")?.textContent||"";
    if(t)_collapsedSections.add(t);
  });
});
// v5.8: Deep tab collapsible sections — click title to toggle, persisted within session
document.addEventListener("click",e=>{
  const t=e.target.closest("#rD .hs-t");
  if(!t)return;
  if(e.target.closest("button, input, textarea, a, [data-copy], [data-copytext], [data-toggle], [data-dlmap], [data-decodeidx]"))return;
  const hs=t.parentElement;
  if(hs&&hs.classList.contains("hs")){
    hs.classList.toggle("collapsed");
    const title=t.textContent||"";
    if(hs.classList.contains("collapsed"))_collapsedSections.add(title);
    else _collapsedSections.delete(title);
  }
});
});
// v5.8: Track collapsed section titles so re-renders preserve state
const _collapsedSections=new Set();

function load(){chrome.runtime.sendMessage({action:"getData",tabId},data=>{if(!data)return;D=data;updateDeepUI(data.deepEnabled);updateProbeUI(data.probeData);updateStats();renderEndpoints(data.endpoints||[]);renderSecrets(data.secrets||[]);renderHidden(data.hiddenFields||[]);renderHeaders(data.headers||[]);renderForms(data.forms||[]);renderTech(data.techStack||[]);renderStorage(data.storageData||{});renderLinks(data.links||[]);renderDeep();renderConsole();updateFooter();});}
function toggleDeep(){const btn=document.getElementById("btnDeep");if(btn.classList.contains("active")){chrome.runtime.sendMessage({action:"disableDeep",tabId},()=>{btn.classList.remove("active");document.getElementById("deepBar").classList.remove("show");});}else{chrome.runtime.sendMessage({action:"enableDeep",tabId},r=>{if(r?.ok){btn.classList.add("active");document.getElementById("deepBar").classList.add("show");toast("Deep ON — reload for full capture");}else toast("Debugger failed");});}}
function updateDeepUI(on){if(on){document.getElementById("btnDeep").classList.add("active");document.getElementById("deepBar").classList.add("show");}else{document.getElementById("btnDeep").classList.remove("active");document.getElementById("deepBar").classList.remove("show");}}
function toggleProbe(){startProbeWithLevel("medium");}
// v5.7: Parse custom header textarea into {name: value} object. One header per line,
// "Name: value" format. Lines starting with # are comments. Skips malformed lines silently.
function parseCustomHeaders(text){
  const headers={};
  if(!text||typeof text!=="string")return headers;
  text.split(/\r?\n/).forEach(line=>{
    line=line.trim();
    if(!line||line.charAt(0)==="#")return;
    const colonIdx=line.indexOf(":");
    if(colonIdx<1)return;
    const name=line.substring(0,colonIdx).trim();
    const value=line.substring(colonIdx+1).trim();
    if(name&&value&&name.length<200&&value.length<2000)headers[name]=value;
  });
  return headers;
}
function startProbeWithLevel(level){
  const btn=document.getElementById("btnProbe");
  if(btn.classList.contains("running")){toast("Active recon is running...");return;}
  if(!document.getElementById("btnDeep").classList.contains("active")){toast("Enable Deep mode first");return;}
  btn.classList.add("running");btn.textContent="Active ⏳";
  document.getElementById("probeBar").classList.add("show");
  const levelLabels={careful:"🟢 Careful — GET only",medium:"🟡 Medium — testing auth",full:"🔴 Full Send — testing everything"};
  const hdrEl=document.getElementById("probeHeaders");
  const customHeaders=parseCustomHeaders(hdrEl?.value||"");
  const hdrCount=Object.keys(customHeaders).length;
  const recursiveEl=document.getElementById("probeRecursive");
  const recursive=recursiveEl?recursiveEl.checked:true;
  const stealthEl=document.getElementById("probeStealth");
  const stealth=stealthEl?stealthEl.checked:false;
  document.getElementById("probeStatus").textContent=`Running ${levelLabels[level]||level}${hdrCount?" + "+hdrCount+" custom headers":""}${recursive?" + recursive":""}${stealth?" + stealth":""}...`;
  chrome.runtime.sendMessage({action:"startProbe",tabId,aggroLevel:level,customHeaders,recursive,stealth},r=>{
    btn.classList.remove("running");
    if(r?.ok){
      btn.classList.add("done");btn.textContent="Active ✓";
      const ar=r.results||{};
      const rp=ar.recursiveProbe||{};
      const rpTotal=(rp.wave1?.length||0)+(rp.wave2?.length||0)+(rp.wave3?.length||0);
      document.getElementById("probeStatus").textContent=`Done (${level}) — ${ar.requests||0} requests${rpTotal?`, ${rpTotal} recursive hits`:""}`;
      toast(`Probe done! ${ar.requests||0} requests${rpTotal?` · ${rpTotal} recursive`:""}`);
      setTimeout(load,500);
    }else{
      btn.textContent="Probe ✗";
      const errMsg=r?.error||r?.results?.error||"unknown";
      document.getElementById("probeStatus").textContent=`Error: ${errMsg.substring(0,100)}`;
      toast("Probe error — check Deep tab");
      setTimeout(load,500);
    }
  });
}
function updateProbeUI(ar){
  const btn=document.getElementById("btnProbe");
  if(!ar)return;
  if(ar.status==="running"){btn.classList.add("running");btn.textContent="Active ⏳";document.getElementById("probeBar").classList.add("show");}
  else if(ar.status==="done"){btn.classList.add("done");btn.textContent="Active ✓";document.getElementById("probeBar").classList.add("show");document.getElementById("probeStatus").textContent=`Done — ${ar.requests||0} requests sent`;}
  else if(ar.status==="error"){btn.textContent="Probe ✗";document.getElementById("probeBar").classList.add("show");document.getElementById("probeStatus").textContent=`Error: ${(ar.error||"unknown").substring(0,100)}`;}
}
function updateStats(){
  const ep=D.endpoints?.length||0,se=D.secrets?.length||0,hf=D.hiddenFields?.length||0;
  let issues=0;
  (D.headers||[]).forEach(h=>{
    issues+=(h.missing?.length||0)+(h.leaks?.length||0)+(h.corsIssues?.length||0)+(h.cookieIssues?.length||0);
    if(h.cspAnalysis)issues+=h.cspAnalysis.issues?.length||0;
  });
  // Flatten deep-tab aggregator: sum of every field the Deep tab renders.
  const deepSources=[
    D.responseBodies,D.requestHeaders,D.wsMessages,D.errorBodies,D.redirectChains,
    D.apiVersions,D.swaggerEndpoints,D.xssSinks,D.mixedContent,D.missingSRI,
    D.postMessageListeners,D.pathParams,D.jsonpEndpoints,D.methodSuggestions,
    D.reconSuggestions,D.scriptSources,D.consoleLogs,D.auditIssues,D.executionContexts,
    D.discoveredRoutes,D.jwtFindings,D.permissionMatrix,D.idorTests,D.indexedDBData,
    D.cacheStorageData,D.postBodies,D.apiResponseBodies,D.domListeners,D.shadowDOMData,
    D.memoryStrings,D.encodedBlobs,D.dnsPrefetch,D.iframeScan,D.headerIntel,D.perfEntries,
    D.cssContent,D.grpcEndpoints,D.wasmModules,D.webrtcLeaks,D.broadcastChannels,
    D.compressionResults,D.wsHijackResults,D.cachePoisonProbe,D.timingOracle,
    D.storagePartition,D.realEventListeners,D.httpOnlyCookies,D.responseSchemas,
    D.heapSecrets,D.parsedSourceMaps,D.graphqlOps,D.symbolTable,D.harvestedMaps
  ];
  let deep=0;
  for(let i=0;i<deepSources.length;i++){const s=deepSources[i];if(s&&s.length)deep+=s.length;}
  if(D.certInfo)deep++;
  if(D.coverageData)deep++;
  if(D.webAuthnInfo?.supported)deep++;
  if(D.grpcReflection)deep++;
  if(D.coopCoepInfo)deep++;
  if(D.webgpuInfo?.supported)deep++;
  document.getElementById("sE").textContent=ep;
  document.getElementById("sS").textContent=se;
  document.getElementById("sH").textContent=hf;
  document.getElementById("sI").textContent=issues;
  document.getElementById("sD").textContent=deep;
  document.getElementById("bE").textContent=ep;
  document.getElementById("bS").textContent=se;
  document.getElementById("bH").textContent=hf;
  document.getElementById("bI").textContent=issues;
  document.getElementById("bF").textContent=D.forms?.length||0;
  document.getElementById("bT").textContent=D.techStack?.length||0;
  document.getElementById("bSt").textContent=Object.keys(D.storageData?.local||{}).length+Object.keys(D.storageData?.session||{}).length;
  document.getElementById("bL").textContent=D.links?.length||0;
  document.getElementById("bD").textContent=deep;
  document.getElementById("bC").textContent=D.consoleLogs?.length||0;
}
function fmtSize(b){if(!b||b<0)return"";if(b<1024)return b+"B";if(b<1048576)return(b/1024).toFixed(1)+"K";return(b/1048576).toFixed(1)+"M";}
function statusClass(s){if(!s)return"";if(s<300)return"s2";if(s<400)return"s3";if(s<500)return"s4";return"s5";}

// RENDERERS (endpoints, secrets, hidden, headers, forms, tech, storage, links — same as v3.5)
function renderEndpoints(eps,filter=""){const c=document.getElementById("rE");let list=eps;if(filter){const f=filter.toLowerCase();list=eps.filter(e=>e.path.toLowerCase().includes(f)||e.method.toLowerCase().includes(f)||e.type.toLowerCase().includes(f)||(e.status&&String(e.status).includes(f))||(e.tags&&e.tags.some(t=>t.tag.includes(f))));}if(!list.length){c.innerHTML=empty("📡","No endpoints.");return;}const groups={};list.forEach(e=>{(groups[e.host]=groups[e.host]||[]).push(e);});let h="";for(const[host,es]of Object.entries(groups)){h+=`<div class="ep-grp"><div class="ep-grp-t">${esc(host)} (${es.length})</div>`;es.forEach(e=>{const tags=(e.tags||[]).map(t=>`<span class="ep-tag" style="background:${escA(t.color)}22;color:${escA(t.color)}">${esc(t.tag)}</span>`).join("");h+=`<div class="ep" data-u="${escA(e.url)}"><span class="m m-${escA(e.method)}">${e.method}</span>`;if(e.status)h+=`<span class="ep-status ${statusClass(e.status)}">${e.status}</span>`;h+=`<span class="ep-p">${esc(e.path)}${e.query?`<span style="color:var(--t3)">${esc(e.query.substring(0,40))}</span>`:""}</span>${tags}`;if(e.responseSize)h+=`<span class="ep-size">${fmtSize(e.responseSize)}</span>`;h+=`<span class="ep-t">${e.type}</span></div>`;});h+=`</div>`;}c.innerHTML=h;c.querySelectorAll(".ep").forEach(el=>el.addEventListener("click",()=>copy(el.dataset.u)));}
function renderSecrets(secrets){const c=document.getElementById("rS");if(!secrets.length){c.innerHTML=empty("🔐","No secrets.");return;}const ord={critical:0,high:1,medium:2,low:3,info:4};secrets.sort((a,b)=>(ord[a.severity]||5)-(ord[b.severity]||5));let h="";secrets.forEach(s=>{h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${escA(s.severity)}">${s.severity}</span><span class="fi-t">${esc(s.type)}</span></div><div class="fi-v">${esc(s.value)}</div><div class="fi-m">${esc(s.source)}</div></div>`;});c.innerHTML=h;c.querySelectorAll(".fi-v").forEach(el=>el.addEventListener("click",()=>copy(el.textContent)));}
function renderHidden(fields){const c=document.getElementById("rH");if(!fields.length){c.innerHTML=empty("👁️‍🗨️","No hidden fields.");return;}const colors={"hidden-input":"var(--yellow)","disabled-input":"var(--orange)","data-attribute":"var(--blue)","html-comment":"var(--t3)","noscript":"var(--teal)","template":"var(--purple)","aspnet-state":"var(--coral)"};let h="";fields.forEach(f=>{h+=`<div class="fi"><div class="fi-h"><span style="color:${colors[f.type]||"var(--t2)"};font-size:9px;font-family:monospace;font-weight:600">${esc(f.type)}</span><span class="fi-t">${esc(f.name)}</span></div><div class="fi-v">${esc(f.value)}</div>${f.form?`<div class="fi-m">${esc(f.form)}</div>`:""}${f.element?`<div class="fi-m">${esc(f.element)}</div>`:""}</div>`;});c.innerHTML=h;c.querySelectorAll(".fi-v").forEach(el=>el.addEventListener("click",()=>copy(el.textContent)));}
function renderHeaders(headers){const c=document.getElementById("rI");if(!headers.length){c.innerHTML=empty("📋","No headers.");return;}const mf=headers.find(h=>h.type==="main_frame")||headers[0];let h="";if(mf.missing?.length){h+=`<div class="hs"><div class="hs-t">Missing security headers</div>`;mf.missing.forEach(m=>{h+=`<div class="hi"><span class="sev sev-${escA(m.severity)}">${m.severity}</span><span class="hi-n">${esc(m.header)}</span><span class="hi-d">${esc(m.desc)}</span></div>`;});h+=`</div>`;}if(mf.cspAnalysis?.issues?.length){h+=`<div class="hs"><div class="hs-t">CSP issues</div>`;mf.cspAnalysis.issues.forEach(i=>{h+=`<div class="hi"><span class="sev sev-${escA(i.severity)}">${i.severity}</span><span class="hi-d">${esc(i.desc)}</span></div>`;});h+=`</div>`;}const cors=headers.flatMap(x=>x.corsIssues||[]);if(cors.length){h+=`<div class="hs"><div class="hs-t">CORS</div>`;cors.forEach(c2=>{h+=`<div class="hi"><span class="sev sev-${escA(c2.severity)}">${c2.severity}</span><span class="hi-d">${esc(c2.desc)}</span></div>`;});h+=`</div>`;}const cookies=headers.flatMap(x=>x.cookieIssues||[]);if(cookies.length){h+=`<div class="hs"><div class="hs-t">Cookies</div>`;cookies.forEach(ck=>{h+=`<div class="hi"><span class="sev sev-${escA(ck.severity)}">${ck.severity}</span><span class="hi-n">${esc(ck.cookie)}</span><span class="hi-d">${esc(ck.issue)}</span></div>`;});h+=`</div>`;}const leaks=headers.flatMap(x=>x.leaks||[]);if(leaks.length){h+=`<div class="hs"><div class="hs-t">Info leakage</div>`;leaks.forEach(l=>{h+=`<div class="hi"><span class="sev sev-info">info</span><span class="hi-n">${esc(l.name)}</span><span class="lv">${esc(l.value)}</span></div>`;});h+=`</div>`;}if(!h)h=empty("✅","No issues.");c.innerHTML=h;}
function renderForms(forms){const c=document.getElementById("rF");if(!forms.length){c.innerHTML=empty("📝","No forms.");return;}let h="";forms.forEach(f=>{h+=`<div class="form-card"><div class="form-hdr"><span class="m m-${escA(f.method)}">${f.method}</span><span class="form-action">${esc(f.action)}</span></div><div class="form-tags"><span class="tag tag-low">${f.inputCount} inputs</span>${f.hasCSRF?`<span class="tag tag-high">CSRF: ${esc(f.csrfFieldName)}</span>`:`<span class="tag" style="background:var(--crit-bg);color:var(--crit)">NO CSRF</span>`}${f.hasFileUpload?`<span class="tag tag-med">Upload</span>`:""}${f.hasPasswordField?`<span class="tag tag-med">Password</span>`:""}</div>`;f.inputs?.forEach(inp=>{h+=`<div style="font-family:monospace;font-size:9px;color:var(--t3);padding:1px 0">${esc(inp.type)} → <span style="color:var(--t1)">${esc(inp.name)}</span>${inp.value?` = <span style="color:var(--yellow)">${esc(inp.value)}</span>`:""}</div>`;});h+=`</div>`;});c.innerHTML=h;}
function renderTech(tech){const c=document.getElementById("rT");let h="";if(tech.length){h+=`<div class="hs"><div class="hs-t">Technologies</div>`;tech.forEach(t=>{h+=`<div style="padding:3px 14px"><span class="tag ${t.confidence==="high"?"tag-high":"tag-med"}">${t.confidence}</span> <span style="font-weight:600">${esc(t.name)}</span> <span style="color:var(--t3);font-size:9px">${esc(t.source)}</span></div>`;});h+=`</div>`;}if(D.dependencyVersions?.length){h+=`<div class="hs"><div class="hs-t">Dependency versions</div>`;D.dependencyVersions.forEach(d=>{h+=`<div style="padding:3px 14px;font-family:monospace;font-size:10px"><span style="color:var(--coral);font-weight:600">${esc(d.name)}</span> <span style="color:var(--yellow)">v${esc(d.version)}</span></div>`;});h+=`</div>`;}if(D.jsGlobals?.length){h+=`<div class="hs"><div class="hs-t">JS globals</div></div>`;D.jsGlobals.forEach(g=>{h+=`<div class="glob"><div class="glob-key">window.${esc(g.key)}</div><div class="glob-pre">${esc(g.preview)}</div></div>`;});}if(D.authFlows?.length){h+=`<div class="hs"><div class="hs-t">Auth flows</div>`;D.authFlows.forEach(a=>{h+=`<div class="hi"><span class="m m-${escA(a.method)}" style="font-size:8px">${a.method}</span><span class="hi-n" style="color:var(--pink)">${esc(a.type)}</span><span class="hi-d" style="font-family:monospace">${esc(a.path)}</span></div>`;});h+=`</div>`;}if(D.wsConnections?.length){h+=`<div class="hs"><div class="hs-t">WebSocket</div>`;D.wsConnections.forEach(w=>{h+=`<div style="padding:3px 14px;font-family:monospace;font-size:10px;color:var(--teal)">${esc(w.url)}</div>`;});h+=`</div>`;}if(D.subdomains?.length){h+=`<div class="hs"><div class="hs-t">Subdomains</div>`;D.subdomains.forEach(s=>{h+=`<div style="padding:2px 14px;font-family:monospace;font-size:10px;color:var(--green)">${esc(s)}</div>`;});h+=`</div>`;}if(D.serviceWorkers?.length){h+=`<div class="hs"><div class="hs-t">Service Workers</div>`;D.serviceWorkers.forEach(sw=>{h+=`<div style="padding:3px 14px;font-family:monospace;font-size:10px;color:var(--orange)">${esc(sw.url)}</div>`;});h+=`</div>`;}if(D.sourceMaps?.length){h+=`<div class="hs"><div class="hs-t">Source maps (${D.sourceMaps.length})</div>`;D.sourceMaps.slice(0,15).forEach(s=>{h+=`<div style="padding:2px 14px;font-family:monospace;font-size:9px;color:var(--orange);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.mapUrl)}</div>`;});h+=`</div>`;}if(!h)h=empty("🔧","No tech.");c.innerHTML=h;c.querySelectorAll(".glob-pre").forEach(el=>el.addEventListener("click",()=>copy(el.textContent)));}
function renderStorage(st){const c=document.getElementById("rSt");const lk=Object.keys(st.local||{}),sk=Object.keys(st.session||{});if(!lk.length&&!sk.length&&!(D.cookies?.length)){c.innerHTML=empty("💾","No storage.");return;}let h="";if(lk.length){h+=`<div class="stor-sec"><div class="stor-title">localStorage (${lk.length})</div>`;lk.forEach(k=>{h+=`<div class="stor-row"><span class="stor-k">${esc(k)}</span><span class="stor-v">${esc(st.local[k])}</span></div>`;});h+=`</div>`;}if(sk.length){h+=`<div class="stor-sec"><div class="stor-title">sessionStorage (${sk.length})</div>`;sk.forEach(k=>{h+=`<div class="stor-row"><span class="stor-k">${esc(k)}</span><span class="stor-v">${esc(st.session[k])}</span></div>`;});h+=`</div>`;}if(D.cookies?.length){h+=`<div class="stor-sec"><div class="stor-title">Cookies (${D.cookies.length})</div>`;D.cookies.forEach(ck=>{const flags=[];if(ck.secure)flags.push('<span style="color:var(--green)">Secure</span>');else flags.push('<span style="color:var(--red)">!Secure</span>');if(ck.httpOnly)flags.push('<span style="color:var(--green)">HttpOnly</span>');else flags.push('<span style="color:var(--red)">!HttpOnly</span>');flags.push(`<span style="color:var(--t3)">SameSite=${ck.sameSite||"unset"}</span>`);h+=`<div class="stor-row"><span class="stor-k">${esc(ck.name)}</span><span class="stor-v">${esc(ck.value)}</span></div><div style="padding:0 14px 4px;font-size:9px">${flags.join(" · ")}</div>`;});h+=`</div>`;}c.innerHTML=h;c.querySelectorAll(".stor-v").forEach(el=>el.addEventListener("click",()=>copy(el.textContent)));}
function renderLinks(links,filter=""){const c=document.getElementById("rL");let list=links;if(filter){const f=filter.toLowerCase();list=links.filter(l=>l.url.toLowerCase().includes(f)||l.type.toLowerCase().includes(f));}if(!list.length){c.innerHTML=empty("🔗","No links.");return;}const groups={};list.forEach(l=>{(groups[l.host]=groups[l.host]||[]).push(l);});let h="";if(D.thirdParty?.length){h+=`<div class="ep-grp"><div class="ep-grp-t" style="color:var(--coral)">Third-party (${D.thirdParty.length})</div>`;D.thirdParty.forEach(tp=>{h+=`<div class="link-row"><span class="link-type">${tp.type}</span><span class="link-url" style="color:var(--coral)">${esc(tp.host)}</span></div>`;});h+=`</div>`;}for(const[host,ls]of Object.entries(groups)){h+=`<div class="ep-grp"><div class="ep-grp-t">${esc(host)} (${ls.length})</div>`;ls.slice(0,30).forEach(l=>{h+=`<div class="link-row" data-u="${escA(l.url)}"><span class="link-type">${l.type}</span><span class="link-url">${esc(l.path)}</span></div>`;});if(ls.length>30)h+=`<div style="padding:4px 14px;color:var(--t3);font-size:10px">...${ls.length-30} more</div>`;h+=`</div>`;}c.innerHTML=h;c.querySelectorAll(".link-row[data-u]").forEach(el=>el.addEventListener("click",()=>copy(el.dataset.u)));}

// -------------------------------------------------------
// DEEP TAB — v5: all data + CDP domains
// -------------------------------------------------------
function renderDeep(){const c=document.getElementById("rD");if(!D.deepEnabled&&!D.responseBodies?.length&&!D.xssSinks?.length&&!D.pathParams?.length){c.innerHTML=empty("🔬",'Click <span style="color:var(--purple);font-weight:700">Deep</span> to enable.');return;}try{let h="";
// XSS Sinks
if(D.xssSinks?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">DOM XSS Sinks (${D.xssSinks.length})</div>`;D.xssSinks.slice(0,100).forEach(s=>{h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${escA(s.severity)}">${s.severity}</span><span class="fi-t">${esc(s.name)}</span></div><div style="font-size:10px;color:var(--t2)">${esc(s.description)}</div><div class="fi-v">${esc(s.context)}</div></div>`;});if(D.xssSinks.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.xssSinks.length}</div>`;h+=`</div>`;}
// PostMessage listeners
if(D.postMessageListeners?.length){h+=`<div class="hs"><div class="hs-t">postMessage Listeners (${D.postMessageListeners.length})</div>`;D.postMessageListeners.slice(0,100).forEach(p=>{h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${escA(p.risk)}">${p.risk}</span><span class="fi-t">${esc(p.description)}</span></div><div class="fi-v">${esc(p.context)}</div></div>`;});if(D.postMessageListeners.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.postMessageListeners.length}</div>`;h+=`</div>`;}
// Mixed content
if(D.mixedContent?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">Mixed Content (${D.mixedContent.length})</div>`;D.mixedContent.slice(0,100).forEach(m=>{h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${escA(m.risk)}">${m.risk}</span><span class="fi-t">${esc(m.type)}</span></div><div class="fi-v">${esc(m.url)}</div></div>`;});if(D.mixedContent.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.mixedContent.length}</div>`;h+=`</div>`;}
// Missing SRI
if(D.missingSRI?.length){h+=`<div class="hs"><div class="hs-t">Missing SRI (${D.missingSRI.length})</div>`;D.missingSRI.slice(0,100).forEach(s=>{h+=`<div style="padding:3px 14px;font-family:monospace;font-size:9px;color:var(--orange);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.type)}: ${esc(s.url)}</div>`;});if(D.missingSRI.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.missingSRI.length}</div>`;h+=`</div>`;}
// Path params
if(D.pathParams?.length){h+=`<div class="hs"><div class="hs-t">Path Parameters — IDOR targets (${D.pathParams.length})</div>`;D.pathParams.slice(0,100).forEach(p=>{h+=`<div class="fi"><div class="fi-h"><span class="sev sev-medium">${esc(p.type)}</span><span class="fi-t">${esc(p.pattern)}</span></div><div class="fi-v">${esc(p.value)}</div><div class="fi-m">${esc(p.method)} ${esc(p.path)}</div></div>`;});if(D.pathParams.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.pathParams.length}</div>`;h+=`</div>`;}
// JSONP
if(D.jsonpEndpoints?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">JSONP Endpoints (${D.jsonpEndpoints.length})</div>`;D.jsonpEndpoints.slice(0,100).forEach(j=>{h+=`<div class="fi"><div class="fi-h"><span class="sev sev-high">high</span><span class="fi-t">JSONP: ${esc(j.callbackParam)}</span></div><div class="fi-v">${esc(j.url)}</div></div>`;});if(D.jsonpEndpoints.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.jsonpEndpoints.length}</div>`;h+=`</div>`;}
// Swagger
if(D.swaggerEndpoints?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">Swagger/OpenAPI (${D.swaggerEndpoints.length})</div>`;D.swaggerEndpoints.slice(0,100).forEach(s=>{h+=`<div style="padding:3px 14px;font-family:monospace;font-size:10px;color:var(--coral)">${esc(s.url)}</div>`;});if(D.swaggerEndpoints.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.swaggerEndpoints.length}</div>`;h+=`</div>`;}
// API versions
if(D.apiVersions?.length){h+=`<div class="hs"><div class="hs-t">API Version Downgrades (${D.apiVersions.length})</div>`;D.apiVersions.slice(0,100).forEach(a=>{h+=`<div class="apiver"><div style="font-family:monospace;font-size:10px">${esc(a.path)} (v${a.currentVersion})</div>`;(a.suggestedPaths||[]).slice(0,5).forEach(sp=>{h+=`<div class="apiver-suggest" data-copy="${escA(sp)}">${esc(sp)}</div>`;});h+=`</div>`;});if(D.apiVersions.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.apiVersions.length}</div>`;h+=`</div>`;}
// Method suggestions
if(D.methodSuggestions?.length){h+=`<div class="hs"><div class="hs-t">HTTP Method Tests (${D.methodSuggestions.length})</div>`;D.methodSuggestions.slice(0,100).forEach(m=>{h+=`<div style="padding:3px 14px;font-size:10px"><span style="font-family:monospace;color:var(--t1)">${esc(m.path)}</span> <span style="color:var(--t3)">(${m.currentMethod})</span> → try: <span style="color:var(--yellow)">${(m.suggestedMethods||[]).join(", ")}</span></div>`;});if(D.methodSuggestions.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.methodSuggestions.length}</div>`;h+=`</div>`;}
// Recon suggestions
if(D.reconSuggestions?.length){h+=`<div class="hs"><div class="hs-t">Recon File Suggestions (${D.reconSuggestions.length})</div>`;D.reconSuggestions.slice(0,100).forEach(r=>{h+=`<div style="padding:2px 14px;font-size:10px;cursor:pointer" data-copy="${escA(r.path)}"><span style="font-family:monospace;color:var(--green)">${esc(r.path)}</span> <span style="color:var(--t3)">— ${esc(r.reason)}</span></div>`;});if(D.reconSuggestions.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.reconSuggestions.length}</div>`;h+=`</div>`;}
// Error bodies
if(D.errorBodies?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">Error Responses (${D.errorBodies.length})</div></div>`;D.errorBodies.slice(0,100).forEach(e=>{h+=`<div class="deep-finding"><div class="fi-h"><span class="ep-status ${statusClass(e.status)}" style="font-size:11px;font-weight:700">${e.status}</span><span style="font-family:monospace;font-size:10px;color:var(--t2)">${esc(e.url.substring(0,80))}</span></div><div class="err-body">${esc(e.body)}</div></div>`;});if(D.errorBodies.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.errorBodies.length}</div>`;}
// Redirects
if(D.redirectChains?.length){h+=`<div class="hs"><div class="hs-t">Redirects (${D.redirectChains.length})</div>`;D.redirectChains.slice(0,100).forEach(r=>{h+=`<div class="redir"><span class="ep-status ${statusClass(r.status)}">${r.status}</span><span class="redir-url" style="color:var(--t1)">${esc(r.from.substring(0,50))}</span><span class="redir-arrow">→</span><span class="redir-url" style="color:var(--yellow)">${esc(r.to.substring(0,50))}</span></div>`;});if(D.redirectChains.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.redirectChains.length}</div>`;h+=`</div>`;}
// Response body findings
if(D.responseBodies?.length){const ord={critical:0,high:1,medium:2,low:3,info:4};const sorted=[...D.responseBodies].sort((a,b)=>(ord[a.severity]||5)-(ord[b.severity]||5));h+=`<div class="hs"><div class="hs-t">Response Body Findings (${sorted.length})</div></div>`;sorted.forEach(f=>{h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${escA(f.severity)}">${f.severity}</span><span class="fi-t">${esc(f.pattern)}</span></div><div class="fi-v">${esc(f.value)}</div><div class="deep-url">${esc(f.url.substring(0,80))} (${f.status})</div></div>`;});}
// Auth headers
if(D.requestHeaders?.length){h+=`<div class="hs"><div class="hs-t">Auth Headers (${D.requestHeaders.length})</div></div>`;D.requestHeaders.slice(0,100).forEach(r=>{h+=`<div class="auth-item"><div style="font-family:monospace;font-size:10px;color:var(--t2)">${esc(r.method)} ${esc(r.url.substring(0,80))}</div>`;r.headers.forEach(hdr=>{h+=`<div class="auth-hdr"><span class="auth-name">${esc(hdr.name)}:</span><span class="auth-val">${esc(hdr.value)}</span></div>`;});h+=`</div>`;});if(D.requestHeaders.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.requestHeaders.length}</div>`;}
// WS
if(D.wsMessages?.length){h+=`<div class="hs"><div class="hs-t">WS Messages (${D.wsMessages.length})</div></div>`;D.wsMessages.slice(-30).forEach(m=>{h+=`<div class="ws-msg"><span class="ws-dir ${m.direction==="recv"?"ws-recv":"ws-sent"}">${m.direction==="recv"?"← RECV":"→ SENT"}</span><div class="ws-data">${esc(m.data)}</div></div>`;});}
// TLS cert
if(D.certInfo){h+=`<div class="hs"><div class="hs-t">TLS Certificate</div></div>`;const ci=D.certInfo;if(ci.subjectName)h+=`<div class="cert-row"><span class="cert-k">Subject</span><span class="cert-v">${esc(ci.subjectName)}</span></div>`;if(ci.issuer)h+=`<div class="cert-row"><span class="cert-k">Issuer</span><span class="cert-v">${esc(ci.issuer)}</span></div>`;if(ci.protocol)h+=`<div class="cert-row"><span class="cert-k">Protocol</span><span class="cert-v">${esc(ci.protocol)}</span></div>`;if(ci.sanList?.length)h+=`<div class="cert-row"><span class="cert-k">SANs</span><span class="cert-v">${esc(ci.sanList.join(", "))}</span></div>`;}
// Web workers
if(D.webWorkers?.length){h+=`<div class="hs"><div class="hs-t">Web Workers (${D.webWorkers.length})</div>`;D.webWorkers.slice(0,100).forEach(w=>{h+=`<div style="padding:3px 14px;font-family:monospace;font-size:10px;color:var(--teal)">${esc(w.type)}: ${esc(w.url)}</div>`;});if(D.webWorkers.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.webWorkers.length}</div>`;h+=`</div>`;}

// ---- RUNTIME ANALYSIS ----
const rt=D.runtime||{};

// Framework detection
if(rt.framework){h+=`<div class="hs"><div class="hs-t" style="color:var(--pink)">Runtime: ${esc(rt.framework.name)} ${esc(rt.framework.version||"")}</div></div>`;}

// Framework routes (hidden pages!)
if(rt.routes?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">Framework Routes — ${rt.routes.length} (includes hidden/admin pages)</div>`;rt.routes.forEach(r=>{
  const flags=[];if(r.requiresAuth||r.requireAuth)flags.push('<span style="color:var(--pink);font-size:9px">auth-required</span>');if(r.abstract)flags.push('<span style="color:var(--t3);font-size:9px">abstract</span>');if(/admin|manage|config|settings/i.test(r.path||r.name))flags.push('<span style="color:var(--red);font-size:9px">admin?</span>');
  h+=`<div style="padding:3px 14px;font-family:monospace;font-size:10px"><span style="color:var(--coral)">${esc(r.path||r.name)}</span> ${r.controller?`<span style="color:var(--t3)">→ ${esc(r.controller)}</span>`:""} ${flags.join(" ")}</div>`;
});h+=`</div>`;}

// Framework services + methods
if(rt.services?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--purple)">Framework Services (${rt.services.length})</div>`;rt.services.forEach(s=>{
  h+=`<div style="padding:4px 14px;border-bottom:1px solid var(--brd)"><div style="font-weight:600;color:var(--purple);font-size:11px">${esc(s.name)} <span style="color:var(--t3);font-size:9px">(${s.methods.length} methods)</span></div>`;
  s.methods.slice(0,15).forEach(m=>{h+=`<div style="font-family:monospace;font-size:9px;color:var(--t2);padding:1px 0">.${esc(m.name)}(${esc((m.args||[]).join(", "))})</div>`;});
  h+=`</div>`;
});h+=`</div>`;}

// State stores (Angular scopes, Redux, Vuex, etc)
if(rt.stores?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--teal)">Application State (${rt.stores.length} stores)</div>`;rt.stores.forEach(s=>{
  h+=`<div style="padding:4px 14px;border-bottom:1px solid var(--brd)"><div style="font-weight:600;color:var(--teal);font-size:11px">${esc(s.name)} <span style="color:var(--t3);font-size:9px">${esc(s.type)}</span></div>`;
  const dataStr=typeof s.data==="string"?s.data:JSON.stringify(s.data);
  h+=`<div style="font-family:monospace;font-size:9px;color:var(--t2);background:var(--bg2);padding:4px 6px;border-radius:3px;margin-top:3px;max-height:80px;overflow:auto;white-space:pre-wrap;word-break:break-all;cursor:pointer" data-copytext="1">${esc(dataStr?.substring(0,500))}</div>`;
  h+=`</div>`;
});h+=`</div>`;}

// PostMessage listeners without origin validation
if(rt.eventListeners?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">PostMessage Listeners (${rt.eventListeners.length}) — XSS surface</div>`;rt.eventListeners.forEach(l=>{
  const riskColor=l.risk==="high"?"var(--red)":"var(--green)";
  h+=`<div class="fi"><div class="fi-h"><span class="sev" style="background:${l.risk==="high"?"var(--crit-bg)":"rgba(51,255,136,.1)"};color:${riskColor}">${l.risk==="high"?"NO ORIGIN CHECK":"origin validated"}</span><span class="fi-t">${esc(l.element)}</span></div><div style="font-family:monospace;font-size:9px;color:var(--t3);max-height:60px;overflow:auto">${esc(l.source)}</div></div>`;
});h+=`</div>`;}

// Runtime secrets from memory
if(rt.runtimeSecrets?.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">Secrets in JS Runtime Memory (${rt.runtimeSecrets.length})</div>`;rt.runtimeSecrets.forEach(s=>{
  h+=`<div class="fi"><div class="fi-h"><span class="sev sev-critical">runtime</span><span class="fi-t">${esc(s.type)}</span></div><div class="fi-v">${esc(s.path)}: ${esc(s.value)}</div></div>`;
});h+=`</div>`;}

// Interesting globals
if(rt.interestingGlobals?.length){h+=`<div class="hs"><div class="hs-t">Interesting Global Objects (${rt.interestingGlobals.length})</div>`;rt.interestingGlobals.forEach(g=>{
  h+=`<div style="padding:4px 14px;border-bottom:1px solid var(--brd)"><div style="font-family:monospace;font-size:11px"><span style="color:var(--purple);font-weight:600">window.${esc(g.name)}</span> <span style="color:var(--t3);font-size:9px">${esc(g.type)}</span></div>`;
  if(g.keys&&Array.isArray(g.keys))h+=`<div style="font-size:9px;color:var(--t3)">Keys: ${esc(g.keys.join(", "))}</div>`;
  if(g.preview)h+=`<div style="font-family:monospace;font-size:9px;color:var(--t2);background:var(--bg2);padding:3px 6px;border-radius:3px;margin-top:2px;max-height:60px;overflow:auto;white-space:pre-wrap;word-break:break-all;cursor:pointer" data-copytext="1">${esc(g.preview?.substring(0,500))}</div>`;
  h+=`</div>`;
});h+=`</div>`;}

// Prototype methods (hidden functionality)
if(rt.protoMethods?.length){h+=`<div class="hs"><div class="hs-t">Prototype Chain Methods (hidden functionality)</div>`;rt.protoMethods.forEach(p=>{
  h+=`<div style="padding:4px 14px;border-bottom:1px solid var(--brd)"><div style="font-weight:600;color:var(--orange);font-size:11px">window.${esc(p.object)} <span style="color:var(--t3);font-size:9px">(${p.methods.length} methods)</span></div>`;
  p.methods.slice(0,10).forEach(m=>{h+=`<div style="font-family:monospace;font-size:9px;color:var(--t2);padding:1px 0">.${esc(m.name)}(${esc((m.args||[]).join(", "))})</div>`;});
  h+=`</div>`;
});h+=`</div>`;}

// Ephemeral DOM (elements that appeared and disappeared)
if(rt.ephemeralDOM?.length){h+=`<div class="hs"><div class="hs-t">Ephemeral DOM (appeared then removed)</div>`;rt.ephemeralDOM.forEach(e=>{
  h+=`<div class="fi"><div style="font-size:10px;color:var(--yellow)">${esc(e.tag)}</div><div style="font-family:monospace;font-size:9px;color:var(--t2);max-height:40px;overflow:auto">${esc(e.text)}</div></div>`;
});h+=`</div>`;}

// Network timing anomalies
if(D.networkTiming&&Object.keys(D.networkTiming).length){
  const anomalies=[];
  Object.entries(D.networkTiming).forEach(([path,timings])=>{
    if(timings.length<2)return;
    const times=timings.map(t=>t.time);
    const min=Math.min(...times),max=Math.max(...times);
    if(max>0&&(max-min)/max>0.5&&max>100)anomalies.push({path,min,max,count:timings.length});
  });
  if(anomalies.length){h+=`<div class="hs"><div class="hs-t">Network Timing Anomalies (${anomalies.length})</div>`;anomalies.forEach(a=>{
    h+=`<div style="padding:3px 14px;font-family:monospace;font-size:10px"><span style="color:var(--yellow)">${esc(a.path)}</span> <span style="color:var(--t3)">${a.min}ms-${a.max}ms (${a.count} requests) — timing variance may indicate IDOR</span></div>`;
  });h+=`</div>`;}
}

// Intercepted requests (from monkey-patched XHR/Fetch)
if(D.interceptedRequests?.length){h+=`<div class="hs"><div class="hs-t">Intercepted Requests [Runtime] (${D.interceptedRequests.length})</div>`;D.interceptedRequests.slice(-20).forEach(r=>{
  h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);font-family:var(--mono);font-size:10px"><span class="m m-${escA(r.method)}">${r.method}</span> <span style="color:var(--t1)">${esc((r.url||"").substring(0,80))}</span> <span class="ep-status ${statusClass(r.status)}">${r.status||""}</span> <span class="ep-size">${fmtSize(r.responseSize)}</span>`;
  if(r.requestBody)h+=`<div style="font-size:9px;color:var(--orange);max-height:40px;overflow:auto;margin-top:2px">Body: ${esc(r.requestBody.substring(0,200))}</div>`;
  h+=`</div>`;
});h+=`</div>`;}

// ---- v5: SCRIPT SOURCE GREP ----
if(D.scriptSources?.length){
  // Group by severity
  const crits=D.scriptSources.filter(s=>s.severity==="critical");
  const highs=D.scriptSources.filter(s=>s.severity==="high");
  const meds=D.scriptSources.filter(s=>s.severity==="medium");
  const infos=D.scriptSources.filter(s=>s.severity==="info");
  const endpoints=D.scriptSources.filter(s=>s.pattern==="API Endpoint"||s.pattern==="GraphQL Endpoint");
  const secrets=D.scriptSources.filter(s=>s.severity==="critical"||s.severity==="high");
  const other=D.scriptSources.filter(s=>s.severity!=="critical"&&s.severity!=="high"&&s.pattern!=="API Endpoint"&&s.pattern!=="GraphQL Endpoint");

  if(secrets.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">🔑 Secrets in Script Source (${secrets.length}) [DEBUGGER]</div>`;secrets.forEach(s=>{
    h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${escA(s.severity)}">${s.severity}</span><span class="fi-t">${esc(s.pattern)}</span></div><div class="fi-v">${esc(s.value)}</div><div class="fi-m">Source: ${esc(s.scriptUrl)} | Context: ${esc(s.context)}</div></div>`;
  });h+=`</div>`;}

  if(endpoints.length){h+=`<div class="hs"><div class="hs-t" style="color:var(--blue)">🔗 API Endpoints in Source (${endpoints.length}) [DEBUGGER]</div>`;
    const uniqueEps=[...new Set(endpoints.map(e=>e.value))];
    uniqueEps.slice(0,50).forEach(ep=>{
      h+=`<div style="padding:3px 16px;font-family:var(--mono);font-size:10px;color:var(--blue);cursor:pointer" data-copy="${escA(ep)}">${esc(ep)}</div>`;
    });
  h+=`</div>`;}

  if(other.length){h+=`<div class="hs"><div class="hs-t">📝 Other Findings in Source (${other.length}) [DEBUGGER]</div>`;other.slice(0,30).forEach(s=>{
    h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${escA(s.severity)}">${s.severity}</span><span class="fi-t">${esc(s.pattern)}</span></div><div class="fi-v">${esc(s.value)}</div><div class="fi-m">${esc(s.scriptUrl)}</div></div>`;
  });h+=`</div>`;}
}

// ---- v5: CONSOLE CAPTURE ----
if(D.consoleLogs?.length){
  const errors=D.consoleLogs.filter(l=>l.level==="error");
  const warnings=D.consoleLogs.filter(l=>l.level==="warning");
  const infos2=D.consoleLogs.filter(l=>l.level==="info");
  h+=`<div class="hs"><div class="hs-t" style="color:var(--yellow)">🖥️ Console Capture (${D.consoleLogs.length}: ${errors.length} errors, ${warnings.length} warnings) [LOG]</div>`;
  D.consoleLogs.slice(0,40).forEach(l=>{
    const color=l.level==="error"?"var(--red)":l.level==="warning"?"var(--yellow)":"var(--t2)";
    const bg=l.level==="error"?"rgba(255,58,92,.05)":l.level==="warning"?"rgba(255,197,58,.05)":"transparent";
    h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);background:${bg}"><span style="font-family:var(--mono);font-size:9px;font-weight:700;color:${color};min-width:50px;display:inline-block">[${l.level.toUpperCase()}]</span> <span style="font-family:var(--mono);font-size:10px;color:var(--t2);word-break:break-all">${esc(l.text.substring(0,300))}</span>`;
    if(l.url)h+=`<div style="font-size:8px;color:var(--t3);margin-top:1px">${esc(l.url)}${l.lineNumber?":"+l.lineNumber:""}</div>`;
    h+=`</div>`;
  });
  h+=`</div>`;
}

// ---- v5: CHROME AUDIT ISSUES ----
if(D.auditIssues?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">🛡️ Chrome Audit Issues (${D.auditIssues.length}) [AUDITS]</div>`;
  D.auditIssues.slice(0,100).forEach(a=>{
    h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${escA(a.severity)}">${a.severity}</span><span class="fi-t">${esc(a.type)}</span></div>`;
    if(a.url)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t3)">${esc(a.url)}</div>`;
    if(a.violatedDirective)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--orange)">Directive: ${esc(a.violatedDirective)}</div>`;
    if(a.cookieName)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--teal)">Cookie: ${esc(a.cookieName)} (${esc(a.cookieDomain)})</div>`;
    if(a.cookieWarningReasons)h+=`<div style="font-size:9px;color:var(--yellow)">Warnings: ${esc(a.cookieWarningReasons)}</div>`;
    if(a.reason)h+=`<div style="font-size:9px;color:var(--t2)">${esc(a.reason)}</div>`;
    if(a.raw)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t3);max-height:40px;overflow:auto">${esc(a.raw)}</div>`;
    h+=`</div>`;
  });
  if(D.auditIssues.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.auditIssues.length}</div>`;
  h+=`</div>`;
}

// ---- v5.2: JWT FINDINGS ----
if(D.jwtFindings?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">🔓 JWT Tokens Decoded (${D.jwtFindings.length})</div>`;
  D.jwtFindings.slice(0,100).forEach(j=>{
    const riskColor=j.isExpired?"var(--t3)":j.weakAlgorithm?"var(--red)":"var(--yellow)";
    h+=`<div style="padding:8px 16px;border-bottom:1px solid var(--glassbrd)"><div style="font-size:10px;color:var(--t3)">${esc(j.source)}</div>`;
    h+=`<div style="font-family:var(--mono);font-size:10px;margin:4px 0"><span style="color:${riskColor};font-weight:700">${esc(j.algorithm)}</span>`;
    if(j.isExpired)h+=` <span style="color:var(--t3)">EXPIRED</span>`;
    if(j.weakAlgorithm)h+=` <span style="color:var(--red)">WEAK ALGO</span>`;
    h+=`</div>`;
    if(j.payload){const keys=Object.keys(j.payload).slice(0,12);const payloadStr=JSON.stringify(j.payload,null,2);h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t2);background:var(--glass);padding:4px 8px;border-radius:6px;border:1px solid var(--glassbrd);max-height:80px;overflow:auto;cursor:pointer" data-copy="${escA(payloadStr)}">${keys.map(k=>`<span style="color:var(--teal)">${esc(k)}</span>: <span style="color:var(--yellow)">${esc(String(j.payload[k]).substring(0,60))}</span>`).join(", ")}</div>`;}
    if(j.expiry)h+=`<div style="font-size:9px;color:var(--t3)">Expires: ${esc(j.expiry)}</div>`;
    h+=`</div>`;
  });
  if(D.jwtFindings.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.jwtFindings.length}</div>`;
  h+=`</div>`;
}

// ---- v5.2: PERMISSION MATRIX ----
if(D.permissionMatrix?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">🔐 Permission Escalation Matrix (${D.permissionMatrix.length} routes above your role)</div>`;
  h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">You are: <span style="color:var(--yellow)">${esc(D.permissionMatrix[0]?.currentRole||"?")}</span>. These routes require elevated access — test each for broken access control.</div>`;
  D.permissionMatrix.slice(0,100).forEach(m=>{
    const riskColor=m.risk==="high"?"var(--red)":"var(--orange)";
    h+=`<div style="padding:3px 16px;font-family:var(--mono);font-size:10px;cursor:pointer;display:flex;align-items:center;gap:6px" data-copy="${escA(m.path)}">`;
    h+=`<span style="color:${riskColor};font-size:9px;font-weight:700;min-width:50px">${esc(m.requiredRole)}</span>`;
    h+=`<span style="color:var(--t1)">${esc(m.path)}</span>`;
    h+=`<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:rgba(255,255,255,.05);color:var(--t3)">${esc(m.intent)}</span>`;
    h+=`</div>`;
  });
  if(D.permissionMatrix.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.permissionMatrix.length}</div>`;
  h+=`</div>`;
}

// ---- v5.2: IDOR TESTS ----
if(D.idorTests?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">🎯 IDOR Test Commands (${D.idorTests.length})</div>`;
  D.idorTests.slice(0,100).forEach(t=>{
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="font-size:10px;color:var(--t2)">${esc(t.type)} — ${esc(t.suggestion||"")}</div>`;
    if(t.curl){h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--green);background:var(--glass);padding:4px 8px;border-radius:6px;border:1px solid var(--glassbrd);margin-top:3px;cursor:pointer;overflow-x:auto;white-space:nowrap" data-copytext="1">${esc(t.curl)}</div>`;}
    h+=`</div>`;
  });
  if(D.idorTests.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.idorTests.length}</div>`;
  h+=`</div>`;
}

// ---- v5.2: INDEXEDDB ----
if(D.indexedDBData?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--teal)">💾 IndexedDB (${D.indexedDBData.length} databases)</div>`;
  D.indexedDBData.slice(0,100).forEach(db=>{
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)"><div style="font-weight:600;font-size:11px;color:var(--teal)">${esc(db.name)} <span style="color:var(--t3);font-size:9px">v${db.version} (${db.stores.length} stores)</span></div>`;
    db.stores.forEach(s=>{h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t2);padding:1px 0">📦 ${esc(s.name)} <span style="color:var(--t3)">keyPath=${esc(s.keyPath)}</span></div>`;});
    if(db.data?.length){
      h+=`<div style="margin-top:4px">`;
      db.data.slice(0,15).forEach(d2=>{
        h+=`<div style="font-family:var(--mono);font-size:9px;background:var(--glass);padding:3px 8px;border-radius:4px;border:1px solid var(--glassbrd);margin:2px 0;max-height:40px;overflow:auto;cursor:pointer" data-copytext="1"><span style="color:var(--purple)">${esc(d2.store)}</span>/<span style="color:var(--yellow)">${esc(d2.key)}</span>: <span style="color:var(--t2)">${esc(d2.value.substring(0,300))}</span></div>`;
      });
      if(db.data.length>15)h+=`<div style="font-size:9px;color:var(--t3);padding:2px 0">...${db.data.length-15} more entries</div>`;
      h+=`</div>`;
    }
    h+=`</div>`;
  });
  if(D.indexedDBData.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.indexedDBData.length}</div>`;
  h+=`</div>`;
}

// ---- v5.2: CACHESTORAGE ----
if(D.cacheStorageData?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--blue)">📋 CacheStorage (${D.cacheStorageData.length} caches)</div>`;
  D.cacheStorageData.slice(0,100).forEach(cache=>{
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)"><div style="font-weight:600;font-size:11px;color:var(--blue)">${esc(cache.name)} <span style="color:var(--t3);font-size:9px">(${cache.entryCount} entries)</span></div>`;
    cache.entries.slice(0,20).forEach(e=>{
      const isAPI=/\/api\//i.test(e.url)||/\.json/i.test(e.url);
      h+=`<div style="padding:2px 0;font-family:var(--mono);font-size:9px;color:${isAPI?"var(--coral)":"var(--t2)"};cursor:pointer" data-copy="${escA(e.url)}">${esc(e.method||"GET")} ${e.status} ${esc(e.url.substring(0,100))}</div>`;
    });
    h+=`</div>`;
  });
  if(D.cacheStorageData.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.cacheStorageData.length}</div>`;
  h+=`</div>`;
}

// ---- v5.3: ENCODED/ENCRYPTED BLOB DETECTION ----
if(D.encodedBlobs?.length){
  const jwtValues=new Set((D.jwtFindings||[]).map(j=>j.raw?.substring(0,40)));
  const filteredBlobs=D.encodedBlobs.filter(b=>{
    if((b.type==="jwt"||b.type==="jwt-malformed")&&jwtValues.has(b.value.substring(0,40)))return false;
    return true;
  });
  if(filteredBlobs.length){
  const typeColors={"base64":"var(--yellow)","jwt":"var(--orange)","url":"var(--blue)","hex":"var(--teal)","aes":"var(--red)","bcrypt":"var(--red)","openssl":"var(--red)","possible":"var(--red)","pgp":"var(--red)","encrypted":"var(--red)","double":"var(--orange)","asn1":"var(--purple)"};
  const typeIcons={"base64":"🔤","jwt":"🎫","url":"🔗","hex":"#️⃣","aes":"🔒","bcrypt":"🔒","openssl":"🔒","possible":"🔒","pgp":"🔒","encrypted":"🔒","double":"🔗","asn1":"📜"};
  h+=`<div class="hs"><div class="hs-t" style="color:var(--yellow)">🔐 Encoded/Encrypted Data (${filteredBlobs.length} blobs detected)</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">Click Decode to reveal contents. Encrypted blobs are flagged but cannot be decoded without the key.</div>`;
  filteredBlobs.slice(0,100).forEach((b)=>{
    const idx=D.encodedBlobs.indexOf(b);
    const btype=b.type||"unknown";
    const cat=btype.split("-")[0];
    const color=typeColors[cat]||"var(--t2)";
    const icon=typeIcons[cat]||"❓";
    const isEncrypted=["aes","bcrypt","openssl","pgp","encrypted","possible","asn1"].includes(cat);
    const isHash=["hex-md5","hex-sha1","hex-sha256","hex-sha512","bcrypt-hash"].includes(btype);
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="display:flex;align-items:center;gap:6px">`;
    h+=`<span style="font-size:12px">${icon}</span>`;
    h+=`<span style="color:${color};font-size:10px;font-weight:700">${esc(btype)}</span>`;
    h+=`<span style="color:var(--t3);font-size:9px">from ${esc(b.source)}</span>`;
    h+=`<span style="color:var(--t3);font-size:9px;margin-left:auto">${b.length} chars</span>`;
    if(!isEncrypted&&!isHash)h+=`<button class="smap-dl" data-decodeidx="${idx}" data-decodetype="${esc(btype)}">Decode</button>`;
    if(isEncrypted)h+=`<span style="font-size:9px;color:var(--red);font-weight:600">🔒 ENCRYPTED</span>`;
    if(isHash)h+=`<span style="font-size:9px;color:var(--purple);font-weight:600">HASH</span>`;
    h+=`</div>`;
    h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t2);background:var(--glass);padding:4px 8px;border-radius:6px;border:1px solid var(--glassbrd);margin-top:4px;max-height:40px;overflow:auto;word-break:break-all;cursor:pointer" data-copy="${escA(b.value)}">${esc(b.value.substring(0,200))}${b.value.length>200?"...":""}</div>`;
    if(b.meta?.preview)h+=`<div style="font-size:9px;color:var(--t3);margin-top:2px">Preview: ${esc(b.meta.preview.substring(0,100))}</div>`;
    if(b.meta?.hexPreview)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--purple);margin-top:2px">Hex: ${esc(b.meta.hexPreview)}</div>`;
    if(b.meta?.algorithm)h+=`<div style="font-size:9px;color:var(--orange);margin-top:2px">Algorithm: ${esc(b.meta.algorithm)} | Claims: ${esc((b.meta.claims||[]).join(", "))}</div>`;
    if(b.meta?.note)h+=`<div style="font-size:9px;color:var(--red);margin-top:2px">${esc(b.meta.note)}</div>`;
    h+=`<div id="decoded-${idx}" style="display:none;font-family:var(--mono);font-size:10px;color:var(--green);background:var(--bg2);padding:6px 8px;border-radius:6px;margin-top:4px;max-height:120px;overflow:auto;word-break:break-all;white-space:pre-wrap;cursor:pointer" data-copytext="1"></div>`;
    h+=`</div>`;
  });
  if(filteredBlobs.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${filteredBlobs.length}</div>`;
  h+=`</div>`;
  }
}

// ---- v5.3: MEMORY STRINGS (leaked secrets from V8 runtime) ----
if(D.memoryStrings?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">🧠 Memory Secrets (${D.memoryStrings.length} leaked strings in V8 heap)</div>`;
  D.memoryStrings.slice(0,100).forEach(m=>{
    const sevColor=m.type.includes("Key")||m.type.includes("Token")||m.type.includes("Password")||m.type.includes("Connection")?"var(--red)":"var(--yellow)";
    h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)"><span style="color:${sevColor};font-size:9px;font-weight:700">${esc(m.type)}</span> <span style="color:var(--t3);font-size:9px">from ${esc(m.source)}</span>`;
    h+=`<div style="font-family:var(--mono);font-size:10px;color:var(--t1);cursor:pointer;margin-top:2px" data-copy="${escA(m.value)}">${esc(m.value)}</div></div>`;
  });
  if(D.memoryStrings.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.memoryStrings.length}</div>`;
  h+=`</div>`;
}

// ---- v5.3: POST BODIES ----
if(D.postBodies?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">📤 Captured POST Bodies (${D.postBodies.length})</div>`;
  D.postBodies.slice(0,100).forEach(p=>{
    h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="font-size:10px"><span style="color:var(--orange);font-weight:700">${esc(p.method)}</span> <span style="color:var(--t1)">${esc(p.path)}</span></div>`;
    h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t2);background:var(--glass);padding:4px 8px;border-radius:6px;border:1px solid var(--glassbrd);margin-top:3px;max-height:60px;overflow:auto;cursor:pointer;word-break:break-all" data-copytext="1">${esc(p.body.substring(0,500))}</div></div>`;
  });
  if(D.postBodies.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.postBodies.length}</div>`;
  h+=`</div>`;
}

// ---- v5.3: API RESPONSE FINDINGS ----
if(D.apiResponseBodies?.length){
  const withFindings=D.apiResponseBodies.filter(r=>r.findings?.length>0);
  if(withFindings.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">🔍 API Response Deep Scan (${withFindings.length} responses with findings)</div>`;
    withFindings.forEach(r=>{
      h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
      h+=`<div style="font-size:10px;color:var(--t1)">${r.status} ${esc(r.path)} <span style="color:var(--t3);font-size:9px">${Math.round(r.size/1024)}KB</span></div>`;
      r.findings.forEach(f=>{
        const fColor=f.severity==="critical"?"var(--red)":f.severity==="high"?"var(--orange)":f.severity==="medium"?"var(--yellow)":"var(--t3)";
        h+=`<div style="padding:2px 8px;font-size:9px"><span style="color:${fColor};font-weight:600">${esc(f.pattern)}</span>: <span style="font-family:var(--mono);color:var(--t2);cursor:pointer" data-copy="${escA(f.value)}">${esc(f.value.substring(0,100))}</span></div>`;
      });
      h+=`</div>`;
    });
    h+=`</div>`;
  }
}

// ---- v5.3: COVERAGE ANALYSIS ----
if(D.coverageData){
  const cov=D.coverageData;
  const totalPct=cov.totalBytes>0?Math.round(cov.totalUsed/cov.totalBytes*100):0;
  h+=`<div class="hs"><div class="hs-t" style="color:var(--purple)">📊 Code Coverage — ${totalPct}% used (${Math.round((cov.totalBytes-cov.totalUsed)/1024)}KB dead code)</div>`;
  h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Dead code = hidden features your role can't trigger. ${cov.totalScripts} scripts analyzed.</div>`;
  (cov.scripts||[]).slice(0,20).forEach(s=>{
    const barColor=s.usedPercent<30?"var(--red)":s.usedPercent<60?"var(--orange)":"var(--green)";
    const fname=(s.url||"").split("/").pop()||s.url||"?";
    h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="font-family:var(--mono);font-size:10px;color:var(--t1)">${esc(fname)} <span style="color:var(--t3);font-size:9px">${Math.round(s.totalBytes/1024)}KB</span></div>`;
    h+=`<div style="display:flex;align-items:center;gap:6px;margin-top:3px"><div style="flex:1;height:4px;background:var(--glass);border-radius:2px;overflow:hidden"><div style="width:${s.usedPercent}%;height:100%;background:${barColor}"></div></div><span style="font-size:9px;color:${barColor};min-width:32px">${s.usedPercent}%</span></div>`;
    if(s.unusedFunctions?.length){h+=`<div style="font-size:9px;color:var(--t3);margin-top:2px">Unused: ${esc(s.unusedFunctions.slice(0,8).join(", "))}${s.unusedFunctions.length>8?" +"+( s.unusedFunctions.length-8)+" more":""}</div>`;}
    h+=`</div>`;
  });
  h+=`</div>`;
}

// ---- v5.3: DOM EVENT LISTENERS ----
if(D.domListeners?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--teal)">🎯 DOM Event Listeners (${D.domListeners.length} elements with handlers)</div>`;
  D.domListeners.slice(0,30).forEach(l=>{
    h+=`<div style="padding:3px 16px;border-bottom:1px solid var(--glassbrd)"><span style="font-family:var(--mono);font-size:10px;color:var(--teal)">${esc(l.element)}</span>`;
    l.attrs.forEach(a=>{h+=` <span style="font-size:9px;color:var(--orange)">${esc(a.event)}</span><span style="font-size:9px;color:var(--t3)">=</span><span style="font-family:var(--mono);font-size:9px;color:var(--t2);cursor:pointer" data-copy="${escA(a.handler)}">${esc(a.handler.substring(0,80))}</span>`;});
    h+=`</div>`;
  });
  h+=`</div>`;
}

// ---- v5.3: SHADOW DOM ----
if(D.shadowDOMData?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--pink)">👻 Shadow DOM Content (${D.shadowDOMData.length} shadow roots pierced)</div>`;
  D.shadowDOMData.slice(0,100).forEach(s=>{
    h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)"><div style="font-family:var(--mono);font-size:10px;color:var(--pink)">${esc(s.host)}</div>`;
    if(s.inputs?.length)h+=`<div style="font-size:9px;color:var(--orange)">Inputs: ${s.inputs.map(i=>esc(i.name||i.type)).join(", ")}</div>`;
    if(s.forms?.length)h+=`<div style="font-size:9px;color:var(--red)">Forms: ${s.forms.map(f=>esc(f.method+" "+f.action)).join(", ")}</div>`;
    if(s.links?.length)h+=`<div style="font-size:9px;color:var(--blue)">Links: ${s.links.slice(0,5).map(l=>esc(l.substring(0,60))).join(", ")}</div>`;
    if(s.textPreview)h+=`<div style="font-size:9px;color:var(--t3);max-height:30px;overflow:hidden">${esc(s.textPreview)}</div>`;
    h+=`</div>`;
  });
  if(D.shadowDOMData.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.shadowDOMData.length}</div>`;
  h+=`</div>`;
}

// ---- v5.3.1: DNS PREFETCH / PRECONNECT ----
if(D.dnsPrefetch?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--teal)">🌐 DNS Prefetch / Preconnect (${D.dnsPrefetch.length} infrastructure hints)</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">These reveal backend services the page plans to contact — microservices, CDNs, APIs.</div>`;
  D.dnsPrefetch.slice(0,100).forEach(d=>{
    const relColor=d.rel==="preconnect"?"var(--green)":d.rel==="preload"?"var(--orange)":d.rel==="prefetch"?"var(--blue)":"var(--teal)";
    h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);display:flex;align-items:center;gap:8px">`;
    h+=`<span style="color:${relColor};font-size:9px;font-weight:700;min-width:70px">${esc(d.rel)}</span>`;
    h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer" data-copy="${escA(d.href||d.host)}">${esc(d.host||d.href)}</span>`;
    if(d.as)h+=`<span style="font-size:9px;color:var(--t3)">as=${esc(d.as)}</span>`;
    if(d.crossOrigin)h+=`<span style="font-size:9px;color:var(--yellow)">CORS</span>`;
    h+=`</div>`;
  });
  if(D.dnsPrefetch.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.dnsPrefetch.length}</div>`;
  h+=`</div>`;
}

// ---- v5.3.1: IFRAME DEEP SCAN ----
if(D.iframeScan?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">🖼️ iframe Scan (${D.iframeScan.length} embedded frames)</div>`;
  D.iframeScan.slice(0,100).forEach(f=>{
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="display:flex;align-items:center;gap:6px">`;
    h+=`<span style="font-size:10px;color:var(--orange);font-weight:600">&lt;${esc(f.tag)}&gt;</span>`;
    if(!f.visible)h+=`<span style="font-size:9px;color:var(--red);font-weight:600">HIDDEN (${f.width}×${f.height})</span>`;
    if(f.sameOrigin)h+=`<span style="font-size:9px;color:var(--green)">same-origin</span>`;
    else h+=`<span style="font-size:9px;color:var(--yellow)">cross-origin</span>`;
    h+=`</div>`;
    if(f.src)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t2);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer" data-copy="${escA(f.src)}">${esc(f.src.substring(0,120))}</div>`;
    if(f.sandbox!==null)h+=`<div style="font-size:9px;color:var(--purple);margin-top:2px">sandbox="${esc(f.sandbox||"(empty — full restriction)")}"</div>`;
    if(f.sandbox===null&&f.sameOrigin)h+=`<div style="font-size:9px;color:var(--red);margin-top:2px">⚠️ No sandbox — same-origin iframe has full page access</div>`;
    if(f.allow)h+=`<div style="font-size:9px;color:var(--t3);margin-top:1px">allow="${esc(f.allow)}"</div>`;
    if(f.innerContent){
      const ic=f.innerContent;
      if(ic.forms?.length)h+=`<div style="font-size:9px;color:var(--red);margin-top:2px">Forms: ${ic.forms.map(fm=>esc(fm.method+" "+fm.action)).join(", ")}</div>`;
      if(ic.hiddenInputs?.length)h+=`<div style="font-size:9px;color:var(--yellow);margin-top:1px">Hidden inputs: ${ic.hiddenInputs.map(i=>esc(i.name||i.type)).join(", ")}</div>`;
      if(ic.scripts?.length)h+=`<div style="font-size:9px;color:var(--t3);margin-top:1px">Scripts: ${ic.scripts.length}</div>`;
    }
    h+=`</div>`;
  });
  if(D.iframeScan.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.iframeScan.length}</div>`;
  h+=`</div>`;
}

// ---- v5.3.1: HTTP HEADER INTELLIGENCE ----
if(D.headerIntel?.length){
  const byCategory={};
  D.headerIntel.slice(0,100).forEach(hi=>{
    const cat=hi.label.includes("Trace")||hi.label.includes("Request")||hi.label.includes("Correlation")?"Tracing":
              hi.label.includes("Cache")?"Caching":
              hi.label.includes("Server")||hi.label.includes("Backend")||hi.label.includes("Upstream")||hi.label.includes("Served")?"Infrastructure":
              hi.label.includes("Rate")?"Rate Limiting":
              hi.label.includes("Timing")||hi.label.includes("Runtime")||hi.label.includes("Time")?"Timing":"Other";
    if(!byCategory[cat])byCategory[cat]=[];
    byCategory[cat].push(hi);
  });
  h+=`<div class="hs"><div class="hs-t" style="color:var(--blue)">📡 HTTP Header Intelligence (${D.headerIntel.length} interesting headers)</div>`;
  Object.keys(byCategory).forEach(cat=>{
    h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--t2);border-bottom:1px solid var(--glassbrd)">${esc(cat)}</div>`;
    byCategory[cat].forEach(hi=>{
      h+=`<div style="padding:3px 16px;padding-left:24px;border-bottom:1px solid var(--glassbrd);display:flex;gap:8px;align-items:baseline">`;
      h+=`<span style="font-family:var(--mono);font-size:9px;color:var(--blue);min-width:140px">${esc(hi.header)}</span>`;
      h+=`<span style="font-family:var(--mono);font-size:9px;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer" data-copy="${escA(hi.value)}">${esc(hi.value.substring(0,100))}</span>`;
      h+=`<span style="font-size:8px;color:var(--t3)">${esc(hi.url.substring(0,40))}</span>`;
      h+=`</div>`;
    });
  });
  if(D.headerIntel.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.headerIntel.length}</div>`;
  h+=`</div>`;
}

// ---- v5.3.1: PERFORMANCE ENTRIES ----
if(D.perfEntries?.length){
  const thirdParty=D.perfEntries.filter(e=>e.isThirdParty);
  const byHost={};
  D.perfEntries.forEach(e=>{const h2=e.host||"unknown";if(!byHost[h2])byHost[h2]={count:0,size:0,urls:[]};byHost[h2].count++;byHost[h2].size+=e.transferSize||0;byHost[h2].urls.push(e);});
  const hostList=Object.entries(byHost).sort((a,b)=>b[1].size-a[1].size);
  const totalSize=D.perfEntries.reduce((s,e)=>s+(e.transferSize||0),0);
  h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">⚡ Performance Entries (${D.perfEntries.length} resources, ${Math.round(totalSize/1024)}KB total, ${thirdParty.length} third-party)</div>`;
  hostList.forEach(([host,data])=>{
    const isTP=D.perfEntries.find(e=>e.host===host)?.isThirdParty;
    h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="display:flex;align-items:center;gap:6px;cursor:pointer" data-toggle="next">`;
    h+=`<span style="font-family:var(--mono);font-size:10px;color:${isTP?"var(--yellow)":"var(--green)"}; font-weight:600">${esc(host)}</span>`;
    h+=`<span style="font-size:9px;color:var(--t3)">${data.count} requests</span>`;
    h+=`<span style="font-size:9px;color:var(--t3)">${data.size>1024?Math.round(data.size/1024)+"KB":data.size+"B"}</span>`;
    if(isTP)h+=`<span style="font-size:8px;color:var(--yellow);font-weight:600">3RD PARTY</span>`;
    h+=`</div>`;
    h+=`<div style="display:none">`;
    data.urls.slice(0,15).forEach(u=>{
      const fname=(u.url||"").split("/").pop()?.split("?")[0]||u.url||"?";
      h+=`<div style="padding:2px 8px;font-family:var(--mono);font-size:9px;color:var(--t2);display:flex;gap:6px" data-copy="${escA(u.url)}">`;
      h+=`<span style="color:var(--t3);min-width:35px">${u.initiatorType}</span>`;
      h+=`<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(fname.substring(0,60))}</span>`;
      h+=`<span style="color:var(--t3)">${u.transferSize>0?(u.transferSize>1024?Math.round(u.transferSize/1024)+"KB":u.transferSize+"B"):(u.isThirdParty?"opaque":"0B")}</span>`;
      h+=`<span style="color:var(--t3)">${u.duration}ms</span>`;
      h+=`</div>`;
    });
    if(data.urls.length>15)h+=`<div style="padding:2px 8px;font-size:9px;color:var(--t3)">+${data.urls.length-15} more</div>`;
    h+=`</div></div>`;
  });
  h+=`</div>`;
}

// ---- v5.3.1: CSS CONTENT EXTRACTION ----
if(D.cssContent?.length){
  const apiUrls=D.cssContent.filter(c=>!c.isData&&(c.url.includes("/api/")||c.url.includes("endpoint")||c.url.includes("internal")));
  const dataUris=D.cssContent.filter(c=>c.isData);
  const imports=D.cssContent.filter(c=>c.type==="@import");
  const bgImages=D.cssContent.filter(c=>c.type==="background-image"||c.type==="inline-background");
  h+=`<div class="hs"><div class="hs-t" style="color:var(--pink)">🎨 CSS Content Extraction (${D.cssContent.length} URLs found)</div>`;
  if(imports.length){
    h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--t2)">@import Rules (${imports.length})</div>`;
    imports.forEach(c=>{
      h+=`<div style="padding:2px 16px;padding-left:24px;font-family:var(--mono);font-size:9px;color:var(--blue);cursor:pointer" data-copy="${escA(c.url)}">${esc(c.url.substring(0,120))}</div>`;
    });
  }
  if(apiUrls.length){
    h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--red)">API/Internal URLs in CSS (${apiUrls.length})</div>`;
    apiUrls.forEach(c=>{
      h+=`<div style="padding:2px 16px;padding-left:24px;font-family:var(--mono);font-size:9px;color:var(--red);cursor:pointer" data-copy="${escA(c.url)}">${esc(c.url.substring(0,120))} <span style="color:var(--t3)">via ${esc(c.type)}</span></div>`;
    });
  }
  if(dataUris.length){
    h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--purple)">Data URIs (${dataUris.length})</div>`;
    dataUris.slice(0,20).forEach(c=>{
      h+=`<div style="padding:2px 16px;padding-left:24px;font-size:9px">`;
      h+=`<span style="color:var(--purple)">${esc(c.dataInfo?.mime||"?")}</span> `;
      h+=`<span style="color:var(--t3)">${c.dataInfo?.size||0} chars</span> `;
      h+=`<span style="color:var(--t3)">from ${esc(c.source.substring(0,60))}</span>`;
      h+=`</div>`;
    });
  }
  if(bgImages.length>imports.length+apiUrls.length+dataUris.length){
    const other=bgImages.filter(c=>!c.isData&&!apiUrls.includes(c));
    if(other.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--t2);cursor:pointer" data-toggle="next">Background Images (${other.length}) ▸</div>`;
      h+=`<div style="display:none">`;
      other.slice(0,30).forEach(c=>{
        h+=`<div style="padding:2px 16px;padding-left:24px;font-family:var(--mono);font-size:9px;color:var(--t2);cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" data-copy="${escA(c.url)}">${esc(c.url.substring(0,100))}</div>`;
      });
      h+=`</div>`;
    }
  }
  h+=`</div>`;
}

// ---- v5.1: DISCOVERED ROUTES (upgraded with noise filter + intent) ----
if(D.discoveredRoutes?.length){
  const appRoutes=D.discoveredRoutes.filter(r=>!r.isNoise);
  const noiseCount=D.discoveredRoutes.length-appRoutes.length;
  const bySource={};
  appRoutes.forEach(r=>{(bySource[r.source]=bySource[r.source]||[]).push(r);});
  const sourceOrder=Object.entries(bySource).sort((a,b)=>b[1].length-a[1].length);

  h+=`<div class="hs"><div class="hs-t" style="color:var(--green)">🗺️ Discovered Routes (${appRoutes.length} app routes, ${noiseCount} library noise filtered)</div>`;
  h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Found in ${sourceOrder.length} sources — endpoints in the app code that were never called during your session</div>`;

  sourceOrder.forEach(([source,routes])=>{
    const color=source.includes("webpack")?"var(--orange)":source.includes("react")?"var(--blue)":source.includes("vue")?"var(--green)":source.includes("angular")?"var(--red)":source.includes("next")?"var(--teal)":source.includes("graphql")||source.includes("apollo")?"var(--pink)":source.includes("script")?"var(--yellow)":"var(--purple)";
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)"><div style="font-weight:600;font-size:10px;color:${color};margin-bottom:4px">${esc(source)} (${routes.length})</div>`;
    const uniquePaths=[...new Set(routes.map(r=>r.path))];
    uniquePaths.slice(0,40).forEach(path=>{
      const r=routes.find(x=>x.path===path);
      const intentColors={destructive:"var(--red)",write:"var(--orange)",admin:"var(--red)",auth:"var(--pink)",config:"var(--purple)",payment:"var(--coral)",file:"var(--orange)",read:"var(--blue)"};
      const ic=intentColors[r.intent]||"var(--t3)";
      h+=`<div style="padding:2px 0;font-family:var(--mono);font-size:10px;cursor:pointer;display:flex;align-items:center;gap:4px" data-copy="${escA(path)}">`;
      if(r.intent&&r.intent!=="unknown")h+=`<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:${ic}22;color:${ic}">${esc(r.intent)}</span>`;
      h+=`<span style="color:var(--t1)">${esc(path)}</span>`;
      if(r.observed)h+=`<span style="font-size:8px;color:var(--green)">✓ seen</span>`;
      h+=`</div>`;
    });
    if(uniquePaths.length>40)h+=`<div style="padding:4px 0;color:var(--t3);font-size:10px">...${uniquePaths.length-40} more</div>`;
    h+=`</div>`;
  });
  h+=`</div>`;
}

// ---- v5: EXECUTION CONTEXTS ----
if(D.executionContexts?.length>1){
  h+=`<div class="hs"><div class="hs-t">🌐 Execution Contexts (${D.executionContexts.length}) [RUNTIME]</div>`;
  D.executionContexts.slice(0,100).forEach(ctx=>{
    const isIframe=ctx.type==="iframe"||(!ctx.isDefault&&ctx.origin);
    h+=`<div style="padding:3px 16px;font-family:var(--mono);font-size:10px"><span style="color:${isIframe?"var(--coral)":"var(--teal)"};font-weight:600">${isIframe?"iframe":"main"}</span> <span style="color:var(--t1)">${esc(ctx.origin)}</span> <span style="color:var(--t3);font-size:9px">${esc(ctx.name)}</span></div>`;
  });
  if(D.executionContexts.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.executionContexts.length}</div>`;
  h+=`</div>`;
}

// v5.3.2: Real Event Listeners (DOMDebugger)
if(D.realEventListeners?.length){
  const msgListeners=D.realEventListeners.filter(l=>l.event==="message");
  const interesting=D.realEventListeners.filter(l=>l.isInteresting);
  h+=`<div class="hs"><div class="hs-t" style="color:var(--purple)">🎯 Real Event Listeners (${D.realEventListeners.length} total, ${msgListeners.length} message, ${interesting.length} interesting)</div>`;
  if(msgListeners.length)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--red);font-weight:700">${msgListeners.length} postMessage listeners — test for XSS via window.postMessage()</div>`;
  interesting.slice(0,50).forEach(l=>{
    h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${l.event==="message"?"high":"medium"}">${esc(l.event)}</span><span class="fi-t">on ${esc(l.target)}</span>${l.once?`<span style="font-size:9px;color:var(--t3)">once</span>`:""}</div>`;
    if(l.handler)h+=`<div class="deep-ctx">${esc(l.handler.substring(0,300))}</div>`;
    if(l.lineNumber)h+=`<div class="fi-m">Script ${esc(l.scriptId)} line ${l.lineNumber}:${l.columnNumber}</div>`;
    h+=`</div>`;
  });
  const boring=D.realEventListeners.filter(l=>!l.isInteresting);
  if(boring.length)h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">${boring.length} other listeners (${[...new Set(boring.map(l=>l.event))].join(", ")})</div>`;
  h+=`</div>`;
}

// v5.3.2: HttpOnly Cookies (Network.getCookies)
if(D.httpOnlyCookies?.length){
  const issues=D.httpOnlyCookies.filter(c=>c.issues&&c.issues.length>0);
  const authCookies=D.httpOnlyCookies.filter(c=>c.isAuthCookie);
  h+=`<div class="hs"><div class="hs-t" style="color:var(--teal)">🍪 All Cookies incl. HttpOnly (${D.httpOnlyCookies.length} total, ${authCookies.length} auth, ${issues.length} with issues)</div>`;
  D.httpOnlyCookies.slice(0,50).forEach(c=>{
    const hasIssues=c.issues&&c.issues.length>0;
    h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);font-family:var(--mono);font-size:10px">`;
    h+=`<div style="display:flex;gap:6px;align-items:center">`;
    h+=`<span style="color:${c.isAuthCookie?"var(--coral)":"var(--t1)"}; font-weight:${c.isAuthCookie?"700":"400"}">${esc(c.name)}</span>`;
    if(c.httpOnly)h+=`<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:rgba(58,221,196,.1);color:var(--teal)">HttpOnly</span>`;
    if(c.secure)h+=`<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:rgba(58,255,138,.1);color:var(--green)">Secure</span>`;
    if(hasIssues)h+=`<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:rgba(255,58,92,.1);color:var(--red)">${(c.issues||[]).join(", ")}</span>`;
    h+=`</div>`;
    h+=`<div style="font-size:9px;color:var(--t3)">${esc(c.domain)} ${esc(c.path)} | ${esc(c.sameSite)} | ${esc(c.expires)}</div>`;
    h+=`</div>`;
  });
  h+=`</div>`;
}

// v5.3.2: Response Schemas
if(D.responseSchemas?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--blue)">📐 API Response Schemas (${D.responseSchemas.length} endpoints)</div>`;
  D.responseSchemas.slice(0,20).forEach(s=>{
    const sensitiveFields=s.fields.filter(f=>f.isSensitive);
    const idFields=s.fields.filter(f=>f.isId);
    h+=`<div class="deep-finding"><div class="fi-h"><span class="fi-t">${esc((s.path||"").substring(0,80))}</span><span style="font-size:9px;color:var(--t3)">${s.fields.length} fields</span></div>`;
    if(sensitiveFields.length)h+=`<div style="font-size:9px;color:var(--red);padding:2px 0">Sensitive: ${sensitiveFields.map(f=>esc(f.key)).join(", ")}</div>`;
    if(idFields.length)h+=`<div style="font-size:9px;color:var(--yellow);padding:2px 0">IDs (IDOR targets): ${idFields.map(f=>esc(f.key)+"="+esc(String(f.sample||"?").substring(0,20))).join(", ")}</div>`;
    h+=`<div class="deep-ctx">${s.fields.slice(0,15).map(f=>esc(f.key)+": "+esc(f.type)+(f.sample!==null?" = "+esc(String(f.sample).substring(0,30)):"")).join("\\n")}</div>`;
    h+=`</div>`;
  });
  h+=`</div>`;
}

// v5.3.2: Heap Secrets
if(D.heapSecrets?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">🧠 Heap/Closure Secrets (${D.heapSecrets.length})</div>`;
  D.heapSecrets.slice(0,50).forEach(s=>{
    h+=`<div class="fi"><div class="fi-h"><span class="sev sev-${s.type==="High-Entropy"?"medium":"critical"}">${esc(s.type)}</span><span class="fi-t" style="color:var(--t3)">from ${esc(s.source)}</span></div><div class="fi-v" data-copy="${escA(s.value)}">${esc(s.value)}</div></div>`;
  });
  h+=`</div>`;
}

// v5.3.2: Parsed Source Maps — full intelligence view
if(D.parsedSourceMaps?.length){
  D.parsedSourceMaps.forEach(function(sm,smIdx){
    const totalFindings=(sm.secrets||[]).length+(sm.endpoints||[]).length+(sm.routes||[]).length+(sm.envVars||[]).length;
    h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">🗺️ Source Map: ${esc((sm.url||"").split("/").pop()||sm.url||"?")} (${sm.fileCount} files, ${totalFindings} findings) [${esc(sm.source)}]</div>`;

    // Secrets found in source
    if(sm.secrets?.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--red)">Secrets (${sm.secrets.length}):</div>`;
      sm.secrets.slice(0,20).forEach(function(s){
        h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-critical">${esc(s.type)}</span><span style="font-size:9px;color:var(--t3)">${esc(s.file||"")}</span></div><div class="fi-v" data-copy="${escA(s.value)}">${esc(s.value)}</div></div>`;
      });
      if(sm.secrets.length>20)h+=`<div style="padding:2px 16px;font-size:9px;color:var(--t3)">+${sm.secrets.length-20} more</div>`;
    }

    // Env variables
    if(sm.envVars?.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--yellow)">Environment Variables (${sm.envVars.length}):</div>`;
      sm.envVars.slice(0,30).forEach(function(e){
        h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:10px"><span style="color:var(--yellow)">process.env.${esc(e.name)}</span> <span style="color:var(--t3)">${esc(e.file)}</span></div>`;
      });
    }

    // Routes from router configs
    if(sm.routes?.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--green)">Routes (${sm.routes.length}):</div>`;
      sm.routes.slice(0,40).forEach(function(r){
        h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:10px;cursor:pointer" data-copy="${escA(r.path)}"><span style="color:var(--green)">${esc(r.path)}</span> <span style="color:var(--t3)">${esc(r.file)}</span></div>`;
      });
    }

    // API endpoints from fetch/axios calls
    if(sm.endpoints?.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--blue)">API Endpoints (${sm.endpoints.length}):</div>`;
      var epDedup={};sm.endpoints.forEach(function(e){if(!epDedup[e.path]){epDedup[e.path]=e;}});
      Object.values(epDedup).slice(0,50).forEach(function(e){
        h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:10px;cursor:pointer" data-copy="${escA(e.path)}"><span style="color:var(--blue)">${esc(e.path)}</span> <span style="color:var(--t3);font-size:9px">[${esc(e.type)}] ${esc(e.file)}</span></div>`;
      });
    }

    // Dependencies
    if(sm.dependencies?.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--purple)">Dependencies (${sm.dependencies.length}):</div>`;
      h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:9px;color:var(--t2)">${sm.dependencies.slice(0,50).map(function(d){return esc(d);}).join(", ")}</div>`;
    }

    // TODO/FIXME comments
    if(sm.todos?.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--coral)">TODO/FIXME/HACK (${sm.todos.length}):</div>`;
      sm.todos.slice(0,15).forEach(function(t){
        h+=`<div style="padding:2px 24px;font-size:9px"><span style="color:var(--coral);font-weight:700">${esc(t.marker)}</span> <span style="color:var(--t2)">${esc(t.text.substring(0,150))}</span> <span style="color:var(--t3)">${esc(t.file)}</span></div>`;
      });
    }

    // Sensitive files
    if(sm.sensitiveFiles?.length){
      h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--red)">Sensitive Paths (${sm.sensitiveFiles.length}):</div>`;
      sm.sensitiveFiles.slice(0,20).forEach(function(f){
        h+=`<div style="padding:1px 24px;font-family:var(--mono);font-size:9px;color:var(--red)">${esc(f)}</div>`;
      });
    }

    // File tree (collapsible)
    h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--t2);cursor:pointer" data-toggle="next">Source Tree (${sm.fileCount} files) ▸</div>`;
    h+=`<div style="display:none;padding:2px 16px;max-height:300px;overflow-y:auto">`;
    function renderTree(node,indent){
      var html="";
      var dirs=Object.keys(node).filter(function(k){return k!=="_files"&&typeof node[k]==="object";}).sort();
      dirs.forEach(function(d){
        var isSensitive=sensitiveCheck(d);
        html+='<div style="padding:1px 0;padding-left:'+indent*12+'px;font-family:var(--mono);font-size:9px;color:'+(isSensitive?"var(--red)":"var(--purple)")+'">'+esc(d)+"/</div>";
        html+=renderTree(node[d],indent+1);
      });
      if(node._files){node._files.sort().forEach(function(f){
        var isSens=sensitiveCheck(f);
        var smKey2="sm"+smIdx+":"+f;
        html+='<div style="padding:1px 0;padding-left:'+indent*12+'px;font-family:var(--mono);font-size:9px;color:'+(isSens?"var(--coral)":"var(--t3)")+';cursor:pointer" data-viewsrc="'+smIdx+'" data-viewfile="'+escA(f)+'">'+esc(f)+"</div>";
      });}
      return html;
    }
    function sensitiveCheck(name){var l=name.toLowerCase();return["admin","auth","config","env","secret","key","password","token","credential","private","internal","debug","migration","seed"].some(function(s){return l.indexOf(s)>-1;});}
    h+=renderTree(sm.fileTree,0);
    h+=`</div>`;

    // Source viewer (hidden, shown when clicking a file)
    h+=`<div id="srcview-${smIdx}" style="display:none;padding:8px 16px">`;
    h+=`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span id="srcview-name-${smIdx}" style="font-family:var(--mono);font-size:10px;color:var(--orange)"></span><button class="btn" style="font-size:9px;padding:2px 8px" id="srcview-close-${smIdx}">Close</button></div>`;
    h+=`<pre id="srcview-code-${smIdx}" style="font-family:var(--mono);font-size:9px;color:var(--t2);background:var(--glass);padding:8px;border-radius:6px;border:1px solid var(--glassbrd);max-height:400px;overflow:auto;white-space:pre-wrap;word-break:break-all"></pre>`;
    h+=`</div>`;

    h+=`</div>`; // close .hs
  });
}

// ---- v5.4: gRPC ENDPOINTS ----
if(D.grpcEndpoints?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--teal)">🔌 gRPC Endpoints (${D.grpcEndpoints.length})</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">gRPC/gRPC-Web endpoints detected — test for reflection, unprotected RPCs, and missing auth.</div>`;
  D.grpcEndpoints.slice(0,50).forEach(g=>{
    const typeColor=g.type==="grpc-web"?"var(--green)":g.type==="protobuf-definition"?"var(--orange)":"var(--teal)";
    h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);display:flex;align-items:center;gap:6px">`;
    h+=`<span style="font-size:9px;color:${typeColor};font-weight:700;min-width:80px">${esc(g.type)}</span>`;
    h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer" data-copy="${escA(g.url)}">${esc(g.path)}</span>`;
    if(g.contentType)h+=`<span style="font-size:8px;color:var(--t3)">${esc(g.contentType.substring(0,30))}</span>`;
    if(g.status)h+=`<span class="ep-status ${statusClass(g.status)}">${g.status}</span>`;
    h+=`</div>`;
  });
  h+=`</div>`;
}

// ---- v5.4/5.6: WASM MODULES — now shows toolchain, top strings, crypto/mining flags ----
if(D.wasmModules?.length){
  const wasmFiles=D.wasmModules.filter(w=>w.url);
  const capabilities=D.wasmModules.filter(w=>w.type==="capability");
  h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">⚙️ WebAssembly Modules (${wasmFiles.length} files detected)</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">WASM modules may contain sensitive algorithms, crypto operations, DRM logic, or license checks. Download and decompile with wasm2c or Ghidra.</div>`;
  if(capabilities.length){
    const cap=capabilities[0];
    h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t2)">Runtime: WASM=${cap.wasmSupported?"✓":"✗"} Streaming=${cap.streaming?"✓":"✗"} SIMD=${cap.simd?"✓":"✗"} Threads=${cap.threads?"✓":"✗"} WebGPU=${cap.webgpu?"✓":"✗"}</div>`;
  }
  wasmFiles.forEach(w=>{
    const fname=(w.url||"").split("/").pop()?.split("?")[0]||w.url||"?";
    const hasCrypto=w.patterns?.crypto;const hasMining=w.patterns?.mining;
    const toolchain=w.toolchain&&w.toolchain!=="unknown"?w.toolchain:null;
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10px">`;
    h+=`<span style="color:var(--orange);font-weight:700;font-size:9px;min-width:70px">${esc(w.source||"")}</span>`;
    h+=`<span style="color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer" data-copy="${escA(w.url)}">${esc(fname)}</span>`;
    if(w.fullSize||w.size)h+=`<span style="color:var(--t3);font-size:9px">${fmtSize(w.fullSize||w.size)}</span>`;
    if(w.duration)h+=`<span style="color:var(--t3);font-size:9px">${w.duration}ms</span>`;
    if(hasCrypto)h+=`<span style="font-size:8px;padding:1px 5px;border-radius:3px;background:rgba(255,123,58,.1);color:var(--orange);font-weight:700">CRYPTO</span>`;
    if(hasMining)h+=`<span style="font-size:8px;padding:1px 5px;border-radius:3px;background:rgba(255,58,92,.1);color:var(--red);font-weight:700">MINING</span>`;
    h+=`</div>`;
    if(toolchain)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--purple);margin-top:2px">Toolchain: ${esc(toolchain)}</div>`;
    if(w.magic)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t3);margin-top:2px">Magic: ${esc(w.magic)}</div>`;
    if(w.signatures&&w.signatures.length)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--teal);margin-top:2px">Signatures: ${w.signatures.slice(0,3).map(s=>esc(s)).join(" · ")}</div>`;
    if(w.topStrings&&w.topStrings.length)h+=`<div style="font-family:var(--mono);font-size:8px;color:var(--t3);margin-top:3px;max-height:50px;overflow:auto;cursor:pointer" data-copytext="1">${w.topStrings.slice(0,12).map(s=>esc(s)).join(" · ")}</div>`;
    if(w.hexDump)h+=`<div style="font-family:var(--mono);font-size:8px;color:var(--t3);background:var(--glass);padding:4px 8px;border-radius:6px;border:1px solid var(--glassbrd);margin-top:4px;max-height:80px;overflow:auto;white-space:pre;cursor:pointer" data-copy="${escA(w.hexDump)}">${esc(w.hexDump.substring(0,512))}</div>`;
    h+=`</div>`;
  });
  h+=`</div>`;
}

// ---- v5.4: WEBRTC IP LEAKS ----
if(D.webrtcLeaks?.length){
  const privateIPs=D.webrtcLeaks.filter(l=>l.type==="private");
  const publicIPs=D.webrtcLeaks.filter(l=>l.type==="public");
  const ipv6=D.webrtcLeaks.filter(l=>l.type==="ipv6");
  const sevColor=privateIPs.length?"var(--red)":"var(--yellow)";
  h+=`<div class="hs"><div class="hs-t" style="color:${sevColor}">🌐 WebRTC IP Leaks (${D.webrtcLeaks.length} IPs discovered)</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">WebRTC STUN leaks bypass VPN/proxy — exposes real network topology. Private IPs reveal internal infrastructure.</div>`;
  D.webrtcLeaks.forEach(l=>{
    const typeColor=l.type==="private"?"var(--red)":l.type==="public"?"var(--yellow)":"var(--teal)";
    h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd);display:flex;align-items:center;gap:8px">`;
    h+=`<span style="font-size:9px;font-weight:700;color:${typeColor};min-width:50px;padding:2px 6px;border-radius:4px;background:${typeColor}15">${esc(l.type)}</span>`;
    h+=`<span style="font-family:var(--mono);font-size:11px;color:var(--t1);cursor:pointer" data-copy="${escA(l.ip)}">${esc(l.ip)}</span>`;
    if(l.type==="private")h+=`<span style="font-size:9px;color:var(--red)">⚠️ Internal network — scan for services</span>`;
    h+=`</div>`;
  });
  h+=`</div>`;
}

// ---- v5.4: BROADCASTCHANNEL ----
if(D.broadcastChannels?.length){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--purple)">📡 BroadcastChannel Activity (${D.broadcastChannels.length})</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">BroadcastChannel enables cross-tab communication. If sensitive data is broadcast, it can be intercepted from any same-origin tab.</div>`;
  D.broadcastChannels.forEach(bc=>{
    if(bc.type==="probe"){
      h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t2)">Probed ${bc.channelsProbed} common channel names</div>`;
      if(bc.channelNames?.length)h+=`<div style="padding:2px 16px;font-family:var(--mono);font-size:10px;color:var(--purple)">${bc.channelNames.map(n=>esc(n)).join(", ")}</div>`;
    }
    if(bc.data){
      h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd)"><span style="font-family:var(--mono);font-size:10px;color:var(--purple);font-weight:600">${esc(bc.channel||"?")}</span>`;
      h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t2);background:var(--glass);padding:3px 8px;border-radius:4px;margin-top:2px;max-height:60px;overflow:auto;cursor:pointer" data-copytext="1">${esc(bc.data.substring(0,300))}</div></div>`;
    }
  });
  h+=`</div>`;
}

// ---- v5.4: WEBAUTHN / FIDO2 ----
if(D.webAuthnInfo&&D.webAuthnInfo.supported){
  const wa=D.webAuthnInfo;
  h+=`<div class="hs"><div class="hs-t" style="color:var(--blue)">🔐 WebAuthn / FIDO2 (${wa.features.length} features)</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">Site supports passwordless auth. Test for: resident key enumeration, attestation forgery, missing origin validation, fallback bypass.</div>`;
  h+=`<div style="padding:4px 16px;font-size:10px"><span style="color:var(--green);font-weight:700">WebAuthn Supported</span>`;
  if(wa.platformAuth)h+=` · <span style="color:var(--blue)">Platform Auth</span>`;
  if(wa.conditionalUI)h+=` · <span style="color:var(--purple)">Conditional UI</span>`;
  h+=`</div>`;
  wa.features.forEach(f=>{
    h+=`<div style="padding:2px 16px;font-size:10px;color:var(--t2)">• ${esc(f)}</div>`;
  });
  h+=`</div>`;
}

// ---- v5.5: COOP/COEP STATUS ----
if(D.coopCoepInfo){
  const ci=D.coopCoepInfo;
  const features=ci.features||ci.probeResults?.flatMap(r=>r.note?[r.note]:[])||[];
  const isIsolated=ci.crossOriginIsolated||false;
  const ciColor=isIsolated?"var(--green)":"var(--orange)";
  h+=`<div class="hs"><div class="hs-t" style="color:${ciColor}">🛡️ COOP/COEP Isolation ${isIsolated?"(ISOLATED)":"(NOT ISOLATED)"}</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">Cross-origin isolation status. Non-isolated sites are vulnerable to Spectre side-channels and cross-site data leaks.</div>`;
  h+=`<div style="padding:4px 16px;font-size:10px"><span style="color:${ciColor};font-weight:700">${isIsolated?"Cross-Origin Isolated":"NOT Cross-Origin Isolated"}</span>`;
  if(ci.sharedArrayBuffer)h+=` · <span style="color:var(--teal)">SharedArrayBuffer</span>`;
  if(ci.coop)h+=` · <span style="color:var(--blue)">COOP: ${esc(ci.coop)}</span>`;
  if(ci.coep)h+=` · <span style="color:var(--blue)">COEP: ${esc(ci.coep)}</span>`;
  h+=`</div>`;
  features.forEach(f=>{h+=`<div style="padding:2px 16px;font-size:10px;color:var(--t2)">• ${esc(f)}</div>`;});
  if(ci.probeResults)ci.probeResults.forEach(r=>{
    if(r.type==="iframe-embed")h+=`<div style="padding:3px 16px;font-size:10px;color:var(--orange)">⚠️ ${esc(r.path)} frameable cross-origin (${r.status})</div>`;
  });
  h+=`</div>`;
}

// ---- v5.5: WEBGPU INFO ----
if(D.webgpuInfo?.supported){
  const gpu=D.webgpuInfo;
  h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">🎮 WebGPU Detected</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">WebGPU enables GPU compute. Check for cryptojacking, password cracking, or fingerprinting via GPU capabilities.</div>`;
  if(gpu.adapter){
    const a=gpu.adapter;
    if(a.vendor)h+=`<div style="padding:2px 16px;font-size:10px;color:var(--t2)">Vendor: <span style="color:var(--t1)">${esc(a.vendor)}</span></div>`;
    if(a.architecture)h+=`<div style="padding:2px 16px;font-size:10px;color:var(--t2)">Architecture: <span style="color:var(--t1)">${esc(a.architecture)}</span></div>`;
    if(a.features?.length)h+=`<div style="padding:2px 16px;font-size:10px;color:var(--t2)">Features: <span style="color:var(--teal)">${a.features.slice(0,10).map(f=>esc(f)).join(", ")}</span></div>`;
  }
  h+=`</div>`;
}

// ---- v5.6: GRAPHQL OPERATIONS — reconstructed schema from captured POST bodies ----
if(D.graphqlOps?.length){
  const queries=D.graphqlOps.filter(o=>o.type==="query");
  const mutations=D.graphqlOps.filter(o=>o.type==="mutation");
  const subs=D.graphqlOps.filter(o=>o.type==="subscription");
  h+=`<div class="hs"><div class="hs-t" style="color:var(--pink)">🧬 GraphQL Operations (${D.graphqlOps.length} — ${queries.length}Q / ${mutations.length}M / ${subs.length}S) [PASSIVE]</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">Reconstructed from captured POST bodies without introspection. Mutations are highest priority — test each for missing auth, CSRF, IDOR on input IDs.</div>`;
  const order={mutation:0,subscription:1,query:2};
  [...D.graphqlOps].sort((a,b)=>(order[a.type]||3)-(order[b.type]||3)).slice(0,100).forEach(op=>{
    const typeColor=op.type==="mutation"?"var(--red)":op.type==="subscription"?"var(--orange)":"var(--blue)";
    h+=`<div style="padding:6px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="display:flex;align-items:center;gap:6px">`;
    h+=`<span style="font-size:9px;padding:2px 6px;border-radius:4px;background:${typeColor}22;color:${typeColor};font-weight:700;text-transform:uppercase">${esc(op.type)}</span>`;
    h+=`<span style="font-family:var(--mono);font-size:11px;color:var(--t1);font-weight:600;cursor:pointer" data-copy="${escA(op.name)}">${esc(op.name)}</span>`;
    if(op.path)h+=`<span style="font-family:var(--mono);font-size:9px;color:var(--t3);margin-left:auto">${esc(op.path)}</span>`;
    h+=`</div>`;
    if(op.fields?.length)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--teal);margin-top:3px">Fields: ${op.fields.map(f=>esc(f)).join(", ")}</div>`;
    if(op.variables?.length){
      const varStr=op.variables.map(v=>esc(v)+(op.variableSample&&op.variableSample[v]?"="+esc(op.variableSample[v]):"")).join(", ");
      h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--yellow);margin-top:2px">Variables: ${varStr}</div>`;
    }
    if(op.fragments?.length)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--purple);margin-top:2px">Fragments: ${op.fragments.map(f=>esc(f)).join(", ")}</div>`;
    if(op.queryPreview)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t3);background:var(--glass);padding:4px 8px;border-radius:6px;border:1px solid var(--glassbrd);margin-top:4px;max-height:60px;overflow:auto;cursor:pointer" data-copy="${escA(op.queryPreview)}">${esc(op.queryPreview)}</div>`;
    h+=`</div>`;
  });
  if(D.graphqlOps.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${D.graphqlOps.length}</div>`;
  h+=`</div>`;
}

// ---- v5.6: SYMBOL TABLE — pre-minification identifiers from source map names arrays ----
if(D.symbolTable?.length&&D.symbolTable[0]?.total){
  const st=D.symbolTable[0];
  h+=`<div class="hs"><div class="hs-t" style="color:var(--purple)">🔤 Symbol Table (${st.total} identifiers, ${st.interestingCount} interesting)</div>`;
  h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">Pre-minification function/variable names from source-map <code>names</code> arrays. Interesting matches grep for admin/auth/secret/debug/bypass/role — these are real identifiers you'd otherwise only see by downloading + reading source.</div>`;
  if(st.interesting?.length){
    h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--red)">Interesting (${st.interesting.length}):</div>`;
    h+=`<div style="padding:4px 16px;font-family:var(--mono);font-size:10px;line-height:1.7;display:flex;flex-wrap:wrap;gap:4px">`;
    st.interesting.slice(0,150).forEach(n=>{
      const low=n.toLowerCase();
      const c=/admin|sudo|root|backdoor|bypass|impersonat/.test(low)?"var(--red)":/auth|token|secret|password|credent|key|jwt/.test(low)?"var(--orange)":/debug|intern|hidden|private/.test(low)?"var(--yellow)":/role|permission|privileg/.test(low)?"var(--coral)":"var(--purple)";
      h+=`<span style="padding:2px 6px;background:${c}15;color:${c};border-radius:4px;cursor:pointer" data-copy="${escA(n)}">${esc(n)}</span>`;
    });
    h+=`</div>`;
  }
  if(st.sample?.length>st.interesting?.length){
    h+=`<div style="padding:4px 16px;font-size:10px;font-weight:700;color:var(--t2);cursor:pointer" data-toggle="next">Full sample (${Math.min(st.sample.length,500)} of ${st.total}) ▸</div>`;
    h+=`<div style="display:none;padding:4px 16px;font-family:var(--mono);font-size:9px;color:var(--t2);line-height:1.6;max-height:300px;overflow-y:auto">`;
    h+=st.sample.slice(0,500).map(n=>esc(n)).join(", ");
    h+=`</div>`;
  }
  h+=`</div>`;
}

if(!h)h=empty("🔬",'Click <span style="color:var(--purple);font-weight:700">Deep</span> then <span style="color:var(--orange);font-weight:700">Probe</span> to scan.');

// ---- v5.1: PROBE RESULTS ----
const ar=D.probeData;
if(ar&&ar.status==="done"){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--orange);font-size:13px">⚡ Probe Results (${ar.requests||0} requests sent)</div></div>`;

  // GraphQL introspection
  if(ar.graphql){
    const g=ar.graphql;
    h+=`<div class="hs"><div class="hs-t" style="color:var(--pink)">GraphQL Schema — ${g.endpoint} (${g.typeCount} types)</div>`;
    if(g.queryFields?.length){h+=`<div style="padding:4px 16px;font-weight:600;font-size:10px;color:var(--blue)">Queries (${g.queryFields.length}):</div>`;
      g.queryFields.slice(0,30).forEach(f=>{h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:10px;color:var(--t1);cursor:pointer" data-copy="${escA(f.name)}">${esc(f.name)} <span style="color:var(--t3)">→ ${esc(f.type?.name||f.type?.kind||"?")}</span></div>`;});}
    if(g.mutationFields?.length){h+=`<div style="padding:4px 16px;font-weight:600;font-size:10px;color:var(--red)">Mutations (${g.mutationFields.length}):</div>`;
      g.mutationFields.slice(0,30).forEach(f=>{h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:10px;color:var(--t1);cursor:pointer" data-copy="${escA(f.name)}">${esc(f.name)} <span style="color:var(--t3)">→ ${esc(f.type?.name||f.type?.kind||"?")}</span></div>`;});}
    if(g.types?.length){h+=`<div style="padding:4px 16px;font-weight:600;font-size:10px;color:var(--purple)">Types (${g.types.length}):</div>`;
      g.types.filter(t=>t.kind==="OBJECT"&&!t.name.startsWith("__")).slice(0,20).forEach(t=>{h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:10px"><span style="color:var(--purple);font-weight:600">${esc(t.name)}</span> <span style="color:var(--t3)">${(t.fields||[]).slice(0,5).map(f=>f.name).join(", ")}${t.fields?.length>5?"...":""}</span></div>`;});}
    h+=`</div>`;
  }

  // Swagger specs
  if(ar.swagger?.length){ar.swagger.forEach(sw=>{
    h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">Swagger: ${esc(sw.title)} v${esc(sw.version)} (${sw.pathCount} paths)</div>`;
    if(sw.securitySchemes?.length)h+=`<div style="padding:2px 16px;font-size:9px;color:var(--yellow)">Auth: ${esc(sw.securitySchemes.join(", "))}</div>`;
    sw.paths.slice(0,40).forEach(p=>{
      h+=`<div style="padding:3px 16px;font-family:var(--mono);font-size:10px;cursor:pointer" data-copy="${escA(p.path)}"><span style="color:var(--t1)">${esc(p.path)}</span> <span style="color:var(--green);font-size:9px">${(p.methods||[]).join(" ").toUpperCase()}</span>${p.params.length?` <span style="color:var(--t3);font-size:9px">(${p.params.length} params)</span>`:""}${p.summary?` <span style="color:var(--t3);font-size:9px">— ${esc(p.summary.substring(0,40))}</span>`:""}</div>`;
    });
    h+=`</div>`;
  });}

  // Source map parsed content
  if(ar.sourceMaps?.length){ar.sourceMaps.forEach(sm=>{
    h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">Source Map: ${esc(sm.url.substring(0,60))} (${sm.fileCount} files, ${(sm.size/1024).toFixed(0)}KB)</div>`;
    if(sm.secrets?.length){h+=`<div style="padding:2px 16px;font-size:10px;font-weight:700;color:var(--red)">Secrets in source code (${sm.secrets.length}):</div>`;
      sm.secrets.slice(0,30).forEach(s=>{h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-critical">${esc(s.type)}</span><span class="fi-t" style="font-size:9px;color:var(--t3)">${esc(s.file)}</span></div><div class="fi-v" data-copy="${escA(s.value)}">${esc(s.value)}</div>${s.context?`<div class="fi-m">${esc(s.context)}</div>`:""}</div>`;});}
    if(sm.endpoints?.length){h+=`<div style="padding:2px 16px;font-size:10px;font-weight:600;color:var(--blue)">Endpoints in source (${sm.endpoints.length}):</div>`;
      [...new Set(sm.endpoints.map(e=>e.path))].slice(0,50).forEach(p=>{h+=`<div style="padding:2px 24px;font-family:var(--mono);font-size:10px;color:var(--t1);cursor:pointer" data-copy="${escA(p)}">${esc(p)}</div>`;});}
    if(sm.sources?.length){h+=`<div style="padding:2px 16px;font-size:10px;font-weight:600;color:var(--t2)">Source files (${sm.fileCount}):</div>`;
      sm.sources.slice(0,30).forEach(s=>{h+=`<div style="padding:1px 24px;font-family:var(--mono);font-size:9px;color:var(--t3)">${esc(s)}</div>`;});
      if(sm.sources.length>30)h+=`<div style="padding:1px 24px;font-size:9px;color:var(--t3);font-style:italic">...and ${sm.sources.length-30} more files</div>`;}
    h+=`</div>`;
  });}

  // Probe results
  const interesting=(ar.probes||[]).filter(p=>p.interesting||p.type==="robots"||p.type==="sitemap");
  if(interesting.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--green)">Probe Results (${interesting.length} interesting / ${ar.probes.length} total)</div>`;
    interesting.forEach(p=>{
      const sColor=p.status<300?"var(--green)":p.status<400?"var(--yellow)":p.status<500?"var(--orange)":"var(--red)";
      h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);font-family:var(--mono);font-size:10px"><span style="color:${sColor};font-weight:700;min-width:30px;display:inline-block">${p.status}</span> <span style="color:var(--t1)">${esc(p.path)}</span>`;
      if(p.disallowed?.length)h+=`<div style="font-size:9px;color:var(--yellow);padding:2px 0">Disallowed: ${p.disallowed.slice(0,10).map(d=>esc(d)).join(", ")}</div>`;
      if(p.urls?.length)h+=`<div style="font-size:9px;color:var(--teal);padding:2px 0">${p.urlCount||p.urls.length} URLs in sitemap</div>`;
      if(p.bodyPreview)h+=`<div style="font-size:9px;color:var(--t3);max-height:40px;overflow:auto;padding:2px 0">${esc(p.bodyPreview.substring(0,200))}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // OPTIONS results
  if(ar.options?.length){
    h+=`<div class="hs"><div class="hs-t">OPTIONS Results (${ar.options.length})</div>`;
    ar.options.forEach(o=>{
      h+=`<div style="padding:3px 16px;font-family:var(--mono);font-size:10px"><span style="color:var(--t1)">${esc(o.path)}</span> → <span style="color:var(--green)">${esc(o.allowedMethods)}</span></div>`;
    });
    h+=`</div>`;
  }

  // Suffix bruteforce hits
  if(ar.suffixes?.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--coral)">Suffix Bruteforce Hits (${ar.suffixes.length})</div>`;
    ar.suffixes.forEach(s=>{
      const sColor=s.status<300?"var(--green)":s.status===401||s.status===403?"var(--yellow)":"var(--orange)";
      h+=`<div style="padding:3px 16px;font-family:var(--mono);font-size:10px"><span style="color:${sColor};font-weight:700;min-width:30px;display:inline-block">${s.status}</span> <span style="color:var(--t1)">${esc(s.path)}</span>`;
      if(s.status===401||s.status===403)h+=` <span style="color:var(--yellow);font-size:9px">🔒 auth-required</span>`;
      if(s.bodyPreview)h+=`<div style="font-size:9px;color:var(--t3);max-height:30px;overflow:auto">${esc(s.bodyPreview.substring(0,150))}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // BAC Auto-Test Results
  if(ar.bacResults?.length){
    const vulns=ar.bacResults.filter(b=>b.vulnerable);
    const partials=ar.bacResults.filter(b=>b.partial);
    const bacColor=vulns.length?"var(--red)":"var(--yellow)";
    const bacIcon=vulns.length?"🚨":"⚠️";
    h+=`<div class="hs"><div class="hs-t" style="color:${bacColor};font-size:12px">${bacIcon} Broken Access Control (${vulns.length} VULNERABLE, ${partials.length} partial, ${ar.bacResults.length} tested)</div>`;
    ar.bacResults.sort((a,b)=>(b.vulnerable?1:0)-(a.vulnerable?1:0));
    ar.bacResults.forEach(b=>{
      const color=b.vulnerable?"var(--red)":b.partial?"var(--orange)":"var(--yellow)";
      const icon=b.vulnerable?"🚨":b.partial?"⚠️":"🔍";
      h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
      h+=`<div style="display:flex;align-items:center;gap:6px"><span>${icon}</span>`;
      h+=`<span style="color:var(--orange);font-weight:700;font-size:9px">${esc(b.method)}</span>`;
      h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1);flex:1;cursor:pointer" data-copy="${escA(b.path)}">${esc(b.path)}</span>`;
      h+=`<span style="color:${color};font-weight:700;font-size:11px">${b.status}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">${esc(b.risk||"")} ${esc(b.intent||"")}</span>`;
      h+=`</div>`;
      if(b.vulnerable)h+=`<div style="font-size:9px;color:var(--red);font-weight:700;margin-top:2px">⚡ CONFIRMED — Student accessed ${esc(b.intent||"")} endpoint!</div>`;
      if(b.bodyPreview)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t2);background:var(--glass);padding:3px 6px;border-radius:4px;margin-top:3px;max-height:40px;overflow:auto">${esc(b.bodyPreview.substring(0,200))}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // HTTP Method Tampering Results
  if(ar.methodResults?.length){
    const interesting=ar.methodResults.filter(m=>m.interesting);
    const mtColor=interesting.length?"var(--red)":"var(--blue)";
    h+=`<div class="hs"><div class="hs-t" style="color:${mtColor}">🔀 HTTP Method Tampering (${interesting.length} accepted, ${ar.methodResults.length} tested)</div>`;
    ar.methodResults.sort((a,b)=>(b.interesting?1:0)-(a.interesting?1:0));
    ar.methodResults.forEach(m=>{
      const color=m.interesting?"var(--red)":m.status<400?"var(--yellow)":"var(--t3)";
      h+=`<div style="padding:3px 16px;border-bottom:1px solid var(--glassbrd);font-family:var(--mono);font-size:10px;display:flex;align-items:center;gap:6px">`;
      h+=`<span style="color:var(--t3);min-width:45px">${esc(m.originalMethod)}</span>`;
      h+=`<span style="color:var(--yellow)">→</span>`;
      h+=`<span style="color:var(--orange);font-weight:700;min-width:50px">${esc(m.testedMethod)}</span>`;
      h+=`<span style="color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.path)}</span>`;
      h+=`<span style="color:${color};font-weight:700">${m.status}</span>`;
      if(m.interesting)h+=`<span style="font-size:9px;color:var(--red)">ACCEPTED</span>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // CORS Results
  if(ar.corsResults?.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">🌍 CORS Misconfiguration (${ar.corsResults.length} issues found)</div>`;
    ar.corsResults.forEach(c=>{
      const sevColor=c.severity==="critical"?"var(--red)":c.severity==="high"?"var(--orange)":c.severity==="medium"?"var(--yellow)":"var(--t3)";
      h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
      h+=`<div style="display:flex;align-items:center;gap:6px">`;
      h+=`<span style="font-size:9px;color:${sevColor};font-weight:700;padding:2px 6px;border-radius:4px;background:${sevColor}15">${esc(c.severity.toUpperCase())}</span>`;
      h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1)">${esc(c.path)}</span>`;
      h+=`</div>`;
      h+=`<div style="font-size:9px;color:var(--t2);margin-top:3px">Origin: <span style="color:var(--orange)">${esc(c.origin)}</span> → ACAO: <span style="color:var(--red)">${esc(c.acao)}</span>${c.acac?" | Credentials: <span style='color:var(--red)'>"+esc(c.acac)+"</span>":""}</div>`;
      if(c.reflected)h+=`<div style="font-size:9px;color:var(--red);font-weight:700;margin-top:2px">⚡ Origin REFLECTED — cross-site data theft possible${c.acac==="true"?" WITH CREDENTIALS":""}!</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // Content-Type Confusion Results
  if(ar.contentTypeResults?.length){
    const accepted=ar.contentTypeResults.filter(c=>c.accepted);
    const ctcColor=accepted.length?"var(--orange)":"var(--blue)";
    h+=`<div class="hs"><div class="hs-t" style="color:${ctcColor}">📝 Content-Type Confusion (${accepted.length} bypassed, ${ar.contentTypeResults.length} tested)</div>`;
    ar.contentTypeResults.sort((a,b)=>(b.accepted?1:0)-(a.accepted?1:0));
    ar.contentTypeResults.forEach(c=>{
      const color=c.accepted?"var(--red)":c.serverError?"var(--orange)":"var(--t3)";
      h+=`<div style="padding:3px 16px;border-bottom:1px solid var(--glassbrd);font-size:10px;display:flex;align-items:center;gap:6px">`;
      h+=`<span style="font-family:var(--mono);color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.path)}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">${esc(c.testedCT.substring(0,30))}</span>`;
      h+=`<span style="color:${color};font-weight:700">${c.status}</span>`;
      if(c.accepted)h+=`<span style="font-size:9px;color:var(--red)">BYPASSED</span>`;
      if(c.serverError)h+=`<span style="font-size:9px;color:var(--orange)">500 ERROR</span>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // Open Redirects
  const openRedirects=ar.openRedirects||[];
  if(openRedirects.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">🔀 Open Redirects (${openRedirects.length})</div>`;
    openRedirects.slice(0,100).forEach(r=>{
      h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span><span class="fi-t">${esc(r.path)}</span></div>`;
      h+=`<div class="fi-m">Param: ${esc(r.param)} → Payload: ${esc(r.payload)}</div>`;
      h+=`<div class="deep-ctx">Redirects to: ${esc(r.redirectTo)} (${r.status})</div></div>`;
    });
    if(openRedirects.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${openRedirects.length}</div>`;
    h+=`</div>`;
  }

  // Race Conditions
  const raceResults=ar.raceResults||[];
  if(raceResults.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">⚡ Race Conditions (${raceResults.length})</div>`;
    raceResults.slice(0,100).forEach(r=>{
      h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span><span class="fi-t">${esc(r.method)} ${esc(r.path)}</span></div>`;
      h+=`<div class="fi-m">${r.parallelRequests} parallel → ${r.successCount} success, ${r.uniqueResponses} unique responses</div>`;
      h+=`<div class="deep-ctx">Statuses: ${esc((r.statuses||[]).join(", "))}${r.note?" — "+esc(r.note):""}</div></div>`;
    });
    if(raceResults.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${raceResults.length}</div>`;
    h+=`</div>`;
  }

  // HTTP Parameter Pollution
  const hppResults=ar.hppResults||[];
  if(hppResults.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--yellow)">📋 HTTP Parameter Pollution (${hppResults.length})</div>`;
    hppResults.slice(0,100).forEach(r=>{
      h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span><span class="fi-t">${esc(r.path)}</span></div>`;
      h+=`<div class="fi-m">Param: ${esc(r.param)} — Technique: ${esc(r.technique)}</div>`;
      h+=`<div class="deep-ctx">Original: ${r.originalStatus} → Test: ${r.testStatus}${r.bodyDiffers?" (body differs)":""}</div></div>`;
    });
    if(hppResults.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${hppResults.length}</div>`;
    h+=`</div>`;
  }

  // Subdomains (probe-discovered)
  const probeSubdomains=ar.subdomains||[];
  if(probeSubdomains.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--blue)">🌐 Discovered Subdomains (${probeSubdomains.length})</div>`;
    probeSubdomains.slice(0,100).forEach(r=>{
      h+=`<div style="padding:3px 16px;font-family:var(--mono);font-size:10px;display:flex;align-items:center;gap:8px">`;
      h+=`<span style="color:var(--blue);font-weight:600">${esc(r.host)}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">via ${esc(r.source)}</span>`;
      h+=`</div>`;
    });
    if(probeSubdomains.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${probeSubdomains.length}</div>`;
    h+=`</div>`;
  }

  // GraphQL Fuzz
  const graphqlFuzz=ar.graphqlFuzz||[];
  if(graphqlFuzz.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--purple)">🔮 GraphQL Field Fuzzing (${graphqlFuzz.length})</div>`;
    graphqlFuzz.slice(0,100).forEach(r=>{
      h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-medium">medium</span><span class="fi-t">Typo: ${esc(r.typo)}</span></div>`;
      h+=`<div class="fi-m">Suggestions: ${esc((r.suggestions||[]).join(", "))}${(r.possibleFields||[]).length?" | Possible fields: "+esc(r.possibleFields.join(", ")):""}</div>`;
      if(r.raw)h+=`<div class="deep-ctx" style="font-size:9px;color:var(--t3);max-height:30px;overflow:auto">${esc(r.raw.substring(0,200))}</div>`;
      h+=`</div>`;
    });
    if(graphqlFuzz.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${graphqlFuzz.length}</div>`;
    h+=`</div>`;
  }

  // JWT Algorithm Confusion
  const jwtAlgResults=ar.jwtAlgResults||[];
  if(jwtAlgResults.length){
    const accepted=jwtAlgResults.filter(j=>j.accepted);
    const jwtColor=accepted.length?"var(--red)":"var(--yellow)";
    h+=`<div class="hs"><div class="hs-t" style="color:${jwtColor}">🔑 JWT Algorithm Confusion (${accepted.length} accepted, ${jwtAlgResults.length} tested)</div>`;
    jwtAlgResults.slice(0,100).forEach(r=>{
      const color=r.accepted?"var(--red)":"var(--t3)";
      h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);font-size:10px;display:flex;align-items:center;gap:6px">`;
      h+=`<span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span>`;
      h+=`<span style="font-family:var(--mono);color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.endpoint)}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">${esc(r.originalAlg)} → ${esc(r.testedAlg)}</span>`;
      h+=`<span style="color:${color};font-weight:700">${r.accepted?"ACCEPTED":"rejected"}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">${esc(r.source||"")}</span>`;
      h+=`</div>`;
    });
    if(jwtAlgResults.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${jwtAlgResults.length}</div>`;
    h+=`</div>`;
  }

  // Host Header Injection
  const hostHeaderResults=ar.hostHeaderResults||[];
  if(hostHeaderResults.length){
    const reflected=hostHeaderResults.filter(r=>r.reflected);
    const hhColor=reflected.length?"var(--orange)":"var(--blue)";
    h+=`<div class="hs"><div class="hs-t" style="color:${hhColor}">🏠 Host Header Injection (${reflected.length} reflected, ${hostHeaderResults.length} tested)</div>`;
    hostHeaderResults.slice(0,100).forEach(r=>{
      const color=r.reflected?"var(--red)":"var(--t3)";
      h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);font-size:10px">`;
      h+=`<div style="display:flex;align-items:center;gap:6px"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span>`;
      h+=`<span style="font-family:var(--mono);color:var(--t2)">${esc(r.payload)}</span>`;
      h+=`<span style="color:${color};font-weight:700">${r.reflected?"REFLECTED":"not reflected"}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">${r.status}</span></div>`;
      if(r.bodySnippet)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t3);max-height:30px;overflow:auto;margin-top:2px">${esc(r.bodySnippet.substring(0,200))}</div>`;
      h+=`</div>`;
    });
    if(hostHeaderResults.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${hostHeaderResults.length}</div>`;
    h+=`</div>`;
  }

  // Cache Poisoning
  const cachePoisonResults=ar.cachePoisonResults||[];
  if(cachePoisonResults.length){
    const reflected=cachePoisonResults.filter(r=>r.reflected);
    const cpColor=reflected.length?"var(--orange)":"var(--blue)";
    h+=`<div class="hs"><div class="hs-t" style="color:${cpColor}">💉 Cache Poisoning (${reflected.length} reflected, ${cachePoisonResults.length} tested)</div>`;
    cachePoisonResults.slice(0,100).forEach(r=>{
      const color=r.reflected?"var(--red)":"var(--t3)";
      h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);font-size:10px">`;
      h+=`<div style="display:flex;align-items:center;gap:6px"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span>`;
      h+=`<span style="font-family:var(--mono);color:var(--t2)">${esc(r.url.substring(0,60))}</span>`;
      h+=`<span style="color:${color};font-weight:700">${r.reflected?"REFLECTED":"not reflected"}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">${esc(r.header)}: ${esc(r.value)}</span></div>`;
      if(r.statusChange)h+=`<div style="font-size:9px;color:var(--orange);margin-top:2px">Status changed${r.bodyDiff?" | Body differs":""}</div>`;
      h+=`</div>`;
    });
    if(cachePoisonResults.length>100)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 100 of ${cachePoisonResults.length}</div>`;
    h+=`</div>`;
  }

  // IDOR Auto-Test
  const idorAutoResults=ar.idorAutoResults||[];
  if(idorAutoResults.length){
    const confirmed=idorAutoResults.filter(r=>r.severity==="critical"||r.severity==="high");
    const iColor=confirmed.length?"var(--red)":"var(--green)";
    h+=`<div class="hs"><div class="hs-t" style="color:${iColor}">🔑 IDOR Auto-Test (${confirmed.length} confirmed / ${idorAutoResults.length} tested)</div>`;
    idorAutoResults.filter(r=>r.severity!=="info").slice(0,100).forEach(r=>{
      h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span><span class="fi-t">${esc(r.path)}</span><span style="font-size:9px;color:var(--t3)">${esc(r.paramType)}</span></div>`;
      h+=`<div class="fi-m">Original ID: <span style="color:var(--yellow)">${esc(r.originalId)}</span> → Tested: <span style="color:var(--coral);">${esc(r.testedId)}</span></div>`;
      h+=`<div class="fi-m">Status: ${r.originalStatus} → ${r.testedStatus} | Size: ${r.originalSize||"?"}B → ${r.testedSize||"?"}B${r.sameSkeleton?" | <span style='color:var(--red);font-weight:700'>SAME STRUCTURE, DIFFERENT DATA</span>":""}</div>`;
      if(r.testedPreview)h+=`<div class="deep-ctx" data-copy="${escA(r.testedPreview)}">${esc(r.testedPreview)}</div>`;
      h+=`</div>`;
    });
    var blocked=idorAutoResults.filter(r=>r.severity==="info");
    if(blocked.length)h+=`<div style="padding:4px 16px;font-size:10px;color:var(--green)">${blocked.length} endpoints properly blocked (401/403)</div>`;
    h+=`</div>`;
  }

  // Auth Token Removal
  const authRemovalResults=ar.authRemovalResults||[];
  if(authRemovalResults.length){
    const broken=authRemovalResults.filter(r=>r.severity==="critical"||r.severity==="high");
    const arColor=broken.length?"var(--red)":"var(--green)";
    h+=`<div class="hs"><div class="hs-t" style="color:${arColor}">🔓 Auth Removal Test (${broken.length} broken / ${authRemovalResults.length} tested)</div>`;
    authRemovalResults.slice(0,100).forEach(r=>{
      const rowColor=r.severity==="critical"?"var(--red)":r.severity==="high"?"var(--orange)":"var(--green)";
      h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span><span class="m m-${escA(r.method)}">${esc(r.method)}</span><span class="fi-t">${esc(r.path)}</span></div>`;
      h+=`<div class="fi-m" style="color:${rowColor}">Auth: ${r.authStatus} (${r.authSize||"?"}B) → No Auth: ${r.noAuthStatus} (${r.noAuthSize||"?"}B)${r.sameBody?" — <span style='font-weight:700'>IDENTICAL RESPONSE</span>":""}</div>`;
      if(r.note)h+=`<div class="fi-m">${esc(r.note)}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // CSRF Validation
  const csrfResults=ar.csrfResults||[];
  if(csrfResults.length){
    const vulnerable=csrfResults.filter(r=>r.severity==="critical"||r.severity==="high");
    const csColor=vulnerable.length?"var(--red)":"var(--green)";
    h+=`<div class="hs"><div class="hs-t" style="color:${csColor}">🛡️ CSRF Validation (${vulnerable.length} vulnerable / ${csrfResults.length} tested)</div>`;
    csrfResults.slice(0,100).forEach(r=>{
      h+=`<div class="deep-finding"><div class="fi-h"><span class="sev sev-${escA(r.severity)}">${esc(r.severity)}</span><span class="m m-${escA(r.method)}">${esc(r.method)}</span><span class="fi-t">${esc(r.path)}</span></div>`;
      h+=`<div class="fi-m">${r.isGraphQLMutation?"<span style='color:var(--purple);font-weight:700'>GraphQL mutation</span> | ":""}CSRF token: ${r.hasCSRF?"<span style='color:var(--green)'>present</span> ("+esc(r.csrfField)+")":"<span style='color:var(--red)'>NONE</span>"} | Normal: ${r.normalStatus} | No CSRF: ${r.noCSRFStatus} | No Cookie: ${r.noCookieStatus}</div>`;
      if(r.note)h+=`<div class="fi-m" style="color:${r.severity==="critical"||r.severity==="high"?"var(--red)":"var(--t3)"}">${esc(r.note)}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // v5.4: gRPC Reflection
  if(ar.grpcReflection){
    const gr=ar.grpcReflection;
    const grColor=gr.type==="reflection-enabled"||gr.type==="reflection-v1"?"var(--red)":"var(--yellow)";
    h+=`<div class="hs"><div class="hs-t" style="color:${grColor}">🔌 gRPC Reflection ${gr.type==="health-check-exposed"?"(Health Check)":"(EXPOSED)"}</div>`;
    h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
    h+=`<div style="font-family:var(--mono);font-size:10px;color:var(--t1);cursor:pointer" data-copy="${escA(gr.url)}">${esc(gr.url)}</div>`;
    h+=`<div style="font-size:10px;color:var(--t2);margin-top:3px">Status: <span class="ep-status ${statusClass(gr.status)}">${gr.status}</span> Type: <span style="color:${grColor}">${esc(gr.type)}</span></div>`;
    if(gr.type==="reflection-enabled"||gr.type==="reflection-v1")h+=`<div style="font-size:9px;color:var(--red);font-weight:700;margin-top:2px">⚡ gRPC reflection is enabled — extract all service definitions with grpcurl</div>`;
    if(gr.bodyPreview)h+=`<div style="font-family:var(--mono);font-size:9px;color:var(--t3);background:var(--glass);padding:3px 8px;border-radius:4px;margin-top:3px;max-height:60px;overflow:auto">${esc(gr.bodyPreview)}</div>`;
    h+=`</div></div>`;
  }

  // v5.4: Compression Oracle (BREACH)
  const compResults=ar.compressionResults||[];
  if(compResults.length){
    const vulnerable=compResults.filter(c=>c.severity==="high");
    const cmpColor=vulnerable.length?"var(--red)":"var(--blue)";
    h+=`<div class="hs"><div class="hs-t" style="color:${cmpColor}">🗜️ Compression Oracle / BREACH (${vulnerable.length} vulnerable / ${compResults.length} tested)</div>`;
    compResults.forEach(c=>{
      const sevColor=c.severity==="high"?"var(--red)":c.severity==="medium"?"var(--yellow)":"var(--t3)";
      h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
      h+=`<div style="display:flex;align-items:center;gap:6px">`;
      h+=`<span style="font-size:9px;color:${sevColor};font-weight:700;padding:2px 6px;border-radius:4px;background:${sevColor}15">${esc((c.severity||"info").toUpperCase())}</span>`;
      h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1)">${esc(c.path)}</span>`;
      h+=`</div>`;
      h+=`<div style="font-size:9px;color:var(--t2);margin-top:3px">Compressed: ${fmtSize(c.compressedSize)} | Uncompressed: ${fmtSize(c.uncompressedSize)} | Ratio: ${c.ratio}x</div>`;
      if(c.probeResults?.length){
        h+=`<div style="font-size:9px;color:var(--red);margin-top:2px">⚡ Response size varies with injected content:</div>`;
        c.probeResults.forEach(p=>{
          h+=`<div style="padding:1px 8px;font-family:var(--mono);font-size:9px;color:var(--yellow)">Payload: ${esc(p.payload)} → size delta: ${p.delta}B (${p.payloadSize} vs ${p.randomSize})</div>`;
        });
      }
      h+=`<div style="font-size:9px;color:var(--t3);margin-top:2px">${esc(c.note||"")}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // v5.5: WebSocket Hijack Test
  const wsHijack=ar.wsHijackResults||[];
  if(wsHijack.length){
    const vuln=wsHijack.filter(w=>w.crossOriginAllowed);
    const wsColor=vuln.length?"var(--red)":"var(--green)";
    h+=`<div class="hs"><div class="hs-t" style="color:${wsColor}">🔌 WebSocket Hijack Test (${vuln.length} vulnerable / ${wsHijack.length} tested)</div>`;
    wsHijack.forEach(w=>{
      const sColor=w.crossOriginAllowed?"var(--red)":"var(--green)";
      h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd);display:flex;align-items:center;gap:6px">`;
      h+=`<span class="sev sev-${w.severity}">${esc(w.severity)}</span>`;
      h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer" data-copy="${escA(w.url)}">${esc(w.url)}</span>`;
      h+=`<span style="color:${sColor};font-weight:700;font-size:10px">${w.crossOriginAllowed?"CROSS-ORIGIN OK":"blocked"}</span>`;
      h+=`</div>`;
      if(w.note)h+=`<div style="padding:2px 16px;font-size:9px;color:var(--t3)">${esc(w.note)}</div>`;
    });
    h+=`</div>`;
  }

  // v5.5: Active Cache Poisoning
  const cachePoison=ar.cachePoisonProbe||[];
  if(cachePoison.length){
    const reflected=cachePoison.filter(c=>c.reflected);
    const cpColor=reflected.length?"var(--red)":"var(--yellow)";
    h+=`<div class="hs"><div class="hs-t" style="color:${cpColor}">💉 Active Cache Poisoning (${reflected.length} reflected / ${cachePoison.length} diffs)</div>`;
    cachePoison.forEach(c=>{
      h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
      h+=`<div style="display:flex;align-items:center;gap:6px"><span class="sev sev-${c.severity}">${esc(c.severity)}</span>`;
      h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1)">${esc(c.path)}</span>`;
      if(c.reflected)h+=`<span style="font-size:9px;color:var(--red);font-weight:700">REFLECTED</span>`;
      h+=`</div>`;
      h+=`<div style="font-size:9px;color:var(--t2);margin-top:2px">Headers: ${Object.entries(c.headers||{}).map(([k,v])=>esc(k)+": "+esc(v)).join(", ")}</div>`;
      h+=`<div style="font-size:9px;color:var(--t3);margin-top:1px">Normal: ${c.normalStatus} → Poisoned: ${c.poisonStatus}${c.bodyDiff?" | body differs":""}${c.statusDiff?" | status differs":""}</div>`;
      if(c.note)h+=`<div style="font-size:9px;color:var(--orange);margin-top:1px">${esc(c.note)}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // v5.5: Timing Oracle
  const timingOracle=ar.timingOracle||[];
  if(timingOracle.length){
    const sigTimings=timingOracle.filter(t=>t.maxDelta>200);
    const toColor=sigTimings.length?"var(--orange)":"var(--blue)";
    h+=`<div class="hs"><div class="hs-t" style="color:${toColor}">⏱️ Timing Oracle (${sigTimings.length} significant / ${timingOracle.length} tested)</div>`;
    timingOracle.forEach(t=>{
      h+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
      h+=`<div style="display:flex;align-items:center;gap:6px"><span class="sev sev-${t.severity}">${esc(t.severity)}</span>`;
      h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1)">${esc(t.path)}</span>`;
      h+=`<span style="font-size:9px;color:var(--t3)">baseline: ${t.baselineMs}ms | max delta: ${t.maxDelta}ms</span>`;
      h+=`</div>`;
      if(t.lfiTimings?.length){
        t.lfiTimings.forEach(lt=>{
          const delta=Math.abs(lt.time-t.baselineMs);
          const dColor=delta>200?"var(--red)":delta>100?"var(--yellow)":"var(--t3)";
          h+=`<div style="padding:1px 24px;font-family:var(--mono);font-size:9px"><span style="color:${dColor}">${lt.time}ms</span> <span style="color:var(--t3)">(${delta>0?"+":""}${delta}ms)</span> <span style="color:var(--t2)">${esc(lt.payload.substring(0,40))}</span></div>`;
        });
      }
      if(t.note)h+=`<div style="font-size:9px;color:var(--t3);margin-top:1px">${esc(t.note)}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // v5.5: COOP/COEP Bypass
  const coopBypass=ar.coopCoepBypass||[];
  if(coopBypass.length){
    const notIsolated=coopBypass.filter(c=>!c.crossOriginIsolated);
    const frameables=coopBypass.filter(c=>c.frameable);
    const cbColor=notIsolated.length?"var(--orange)":"var(--green)";
    h+=`<div class="hs"><div class="hs-t" style="color:${cbColor}">🛡️ COOP/COEP Bypass (${frameables.length} frameable endpoints)</div>`;
    coopBypass.forEach(c=>{
      h+=`<div style="padding:4px 16px;border-bottom:1px solid var(--glassbrd)">`;
      h+=`<div style="display:flex;align-items:center;gap:6px"><span class="sev sev-${c.severity}">${esc(c.severity)}</span>`;
      if(c.path)h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1)">${esc(c.path)}</span>`;
      if(c.frameable)h+=`<span style="font-size:9px;color:var(--orange);font-weight:700">FRAMEABLE</span>`;
      if(c.crossOriginIsolated===false)h+=`<span style="font-size:9px;color:var(--red)">NOT ISOLATED</span>`;
      h+=`</div>`;
      if(c.note)h+=`<div style="font-size:9px;color:var(--t3);margin-top:2px">${esc(c.note)}</div>`;
      h+=`</div>`;
    });
    h+=`</div>`;
  }

  // v5.5: Storage Partition Test
  const storPart=ar.storagePartition||[];
  if(storPart.length){
    const partitioned=storPart.filter(s=>s.partitioned);
    const summary=storPart.find(s=>s.type==="summary");
    const spColor=partitioned.length?"var(--yellow)":"var(--green)";
    h+=`<div class="hs"><div class="hs-t" style="color:${spColor}">🔒 Storage Partitioning (${partitioned.length} partitioned / ${storPart.filter(s=>s.type!=="summary").length} tested)</div>`;
    storPart.filter(s=>s.type!=="summary").forEach(s=>{
      const sColor=s.partitioned?"var(--yellow)":"var(--green)";
      h+=`<div style="padding:3px 16px;border-bottom:1px solid var(--glassbrd);display:flex;align-items:center;gap:8px">`;
      h+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1);min-width:100px">${esc(s.type)}</span>`;
      h+=`<span style="color:${sColor};font-weight:700;font-size:10px">${s.partitioned?"PARTITIONED":"accessible"}</span>`;
      if(s.error)h+=`<span style="font-size:9px;color:var(--t3)">${esc(s.error.substring(0,50))}</span>`;
      h+=`</div>`;
    });
    if(summary)h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">${esc(summary.note)}</div>`;
    h+=`</div>`;
  }

  // v5.7: Recursive API Discovery — the wave-by-wave breakdown with inline findings
  const rp=ar.recursiveProbe;
  if(rp&&(rp.wave1?.length||rp.wave2?.length||rp.wave3?.length)){
    const w1=rp.wave1||[],w2=rp.wave2||[],w3=rp.wave3||[];
    const total=w1.length+w2.length+w3.length;
    const allFindings=[...w1,...w2,...w3].flatMap(r=>(r.findings||[]).map(f=>({...f,sourceUrl:r.path})));
    const totalFindings=allFindings.length;
    const critical=allFindings.filter(f=>f.severity==="critical").length;
    const okHits=[...w1,...w2,...w3].filter(r=>r.status>=200&&r.status<300).length;
    const titleColor=critical>0?"var(--red)":okHits>5?"var(--green)":"var(--orange)";
    h+=`<div class="hs"><div class="hs-t" style="color:${titleColor};font-size:13px">🔁 Smart Recursive Probing — ${total} endpoints probed across 3 waves</div>`;
    h+=`<div style="padding:4px 16px;font-size:10px;color:var(--t2)">Seed: ${rp.seedCount||0} URLs · Wave1: ${w1.length} · Wave2: ${w2.length} (from wave1 responses) · Wave3: ${w3.length} (from wave2 responses) · ${rp.newUrlsFound||0} new URLs discovered · ${totalFindings} findings${critical?` · <span style="color:var(--red);font-weight:700">${critical} CRITICAL</span>`:""}</div>`;
    // Render each wave
    const renderWave=(label,waveData,color)=>{
      if(!waveData.length)return "";
      let wh=`<div style="padding:6px 16px;font-size:10px;font-weight:700;color:${color};border-top:1px solid var(--glassbrd);background:${color}08">${label} (${waveData.length} hits)</div>`;
      waveData.sort((a,b)=>(b.findings?.length||0)-(a.findings?.length||0));
      waveData.slice(0,50).forEach(r=>{
        const sColor=r.status>=200&&r.status<300?"var(--green)":r.status===401||r.status===403?"var(--yellow)":r.status>=500?"var(--red)":"var(--t3)";
        const findingCount=(r.findings||[]).length;
        const newUrlCount=(r.newUrls||[]).length;
        const isGql=r.isGraphQL;
        wh+=`<div style="padding:5px 16px;border-bottom:1px solid var(--glassbrd)">`;
        wh+=`<div style="display:flex;align-items:center;gap:6px">`;
        wh+=`<span style="color:${sColor};font-weight:700;font-size:10px;min-width:30px">${r.status}</span>`;
        if(isGql)wh+=`<span style="font-size:8px;padding:1px 5px;border-radius:3px;background:rgba(155,90,255,.15);color:var(--purple);font-weight:700">GQL</span>`;
        wh+=`<span style="font-family:var(--mono);font-size:10px;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer" data-copy="${escA(r.path||r.url||"")}">${esc(r.path||r.url||"")}</span>`;
        wh+=`<span style="font-size:9px;color:var(--t3)">${fmtSize(r.size)}</span>`;
        if(findingCount)wh+=`<span style="font-size:8px;padding:1px 5px;border-radius:3px;background:rgba(255,58,92,.15);color:var(--red);font-weight:700">${findingCount} finding${findingCount>1?"s":""}</span>`;
        if(newUrlCount)wh+=`<span style="font-size:8px;padding:1px 5px;border-radius:3px;background:rgba(58,168,255,.15);color:var(--blue);font-weight:700">+${newUrlCount}</span>`;
        wh+=`</div>`;
        // Findings inline
        if(findingCount){
          r.findings.slice(0,5).forEach(f=>{
            const fColor=f.severity==="critical"?"var(--red)":f.severity==="high"?"var(--orange)":f.severity==="medium"?"var(--yellow)":"var(--t3)";
            wh+=`<div style="padding:2px 0 2px 36px;font-family:var(--mono);font-size:9px"><span style="color:${fColor};font-weight:700">[${esc((f.severity||"").toUpperCase())}]</span> <span style="color:var(--t2)">${esc(f.type)}</span>: <span style="color:var(--yellow);cursor:pointer" data-copy="${escA(f.value)}">${esc(String(f.value).substring(0,120))}</span></div>`;
          });
          if(findingCount>5)wh+=`<div style="padding:1px 0 1px 36px;font-size:9px;color:var(--t3)">+${findingCount-5} more findings</div>`;
        }
        // Body preview (collapsed)
        if(r.bodyPreview&&r.bodyPreview.length>20){
          wh+=`<div style="padding:2px 0 0 36px;font-size:9px;color:var(--t3);cursor:pointer" data-toggle="next">▸ body preview (${r.size}B)</div>`;
          wh+=`<div style="display:none;padding:4px 0 0 36px"><div style="font-family:var(--mono);font-size:9px;color:var(--t3);background:var(--glass);padding:4px 8px;border-radius:6px;border:1px solid var(--glassbrd);max-height:150px;overflow:auto;white-space:pre-wrap;word-break:break-all;cursor:pointer" data-copytext="1">${esc(r.bodyPreview)}</div></div>`;
        }
        // Extracted URLs (collapsed)
        if(newUrlCount){
          wh+=`<div style="padding:2px 0 0 36px;font-size:9px;color:var(--blue);cursor:pointer" data-toggle="next">▸ ${newUrlCount} URLs extracted from response</div>`;
          wh+=`<div style="display:none;padding:4px 0 0 36px">`;
          r.newUrls.slice(0,30).forEach(u=>{
            wh+=`<div style="font-family:var(--mono);font-size:9px;color:var(--blue);padding:1px 0;cursor:pointer" data-copy="${escA(u)}">${esc(u)}</div>`;
          });
          if(newUrlCount>30)wh+=`<div style="font-size:9px;color:var(--t3);padding:1px 0">...+${newUrlCount-30} more</div>`;
          wh+=`</div>`;
        }
        wh+=`</div>`;
      });
      if(waveData.length>50)wh+=`<div style="padding:4px 16px;font-size:10px;color:var(--t3)">Showing 50 of ${waveData.length}</div>`;
      return wh;
    };
    h+=renderWave("Wave 1 — seed URLs from prior steps",w1,"var(--blue)");
    h+=renderWave("Wave 2 — URLs extracted from Wave 1 responses",w2,"var(--orange)");
    h+=renderWave("Wave 3 — URLs extracted from Wave 2 responses",w3,"var(--red)");
    h+=`</div>`;
  }

  // Errors
  if(ar.errors?.length){
    h+=`<div class="hs"><div class="hs-t" style="color:var(--t3)">Probe Log (${ar.errors.length})</div>`;
    ar.errors.forEach(e=>{
      const isStep=/^STEP \d|^ctx loaded/.test(e);
      const isFatal=/^FATAL/.test(e);
      const color=isFatal?"var(--red)":isStep?"var(--t3)":"var(--orange)";
      h+=`<div style="padding:2px 16px;font-size:9px;color:${color}">${esc(e)}</div>`;
    });
    h+=`</div>`;
  }
}
else if(ar&&ar.status==="running"){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--orange)">⚡ Probe Running...</div><div style="padding:8px 16px;color:var(--t2);font-size:11px">Sending requests — GraphQL, source maps, probes, swagger, OPTIONS, suffix brute, BAC testing, method tampering, CORS reflection, content-type confusion...</div></div>`;
}
else if(ar&&ar.status==="error"){
  h+=`<div class="hs"><div class="hs-t" style="color:var(--red)">⚡ Probe FAILED</div>`;
  h+=`<div style="padding:8px 16px;font-family:var(--mono);font-size:10px;color:var(--red);word-break:break-all">${esc(ar.error||"Unknown error")}</div>`;
  if(ar.errors?.length){
    h+=`<div style="padding:4px 16px;font-size:9px;color:var(--t3)">Diagnostic log:</div>`;
    ar.errors.forEach(e=>{h+=`<div style="padding:2px 16px;font-size:9px;color:var(--orange)">${esc(e)}</div>`;});
  }
  h+=`</div>`;
}

c.innerHTML=h;c.querySelectorAll(".fi-v,.auth-val,.ws-data").forEach(el=>el.addEventListener("click",()=>copy(el.textContent)));
// Source viewer click handlers
c.querySelectorAll("[data-viewsrc]").forEach(el=>{el.addEventListener("click",function(){
  const smIdx=parseInt(el.dataset.viewsrc);const fileName=el.dataset.viewfile;
  const sm=D.parsedSourceMaps?.[smIdx];if(!sm||!sm.sourceContents)return;
  // Find the file content — match by filename (last segment)
  let content=null;
  for(const[k,v] of Object.entries(sm.sourceContents)){if(k===fileName||k.endsWith("/"+fileName)){content=v;break;}}
  if(!content){toast("Source not available (file too large or not in sourcesContent)");return;}
  const viewer=document.getElementById("srcview-"+smIdx);
  const nameEl=document.getElementById("srcview-name-"+smIdx);
  const codeEl=document.getElementById("srcview-code-"+smIdx);
  if(viewer&&nameEl&&codeEl){nameEl.textContent=fileName;codeEl.textContent=content;viewer.style.display="block";}
});});
c.querySelectorAll("[id^='srcview-close-']").forEach(btn=>{btn.addEventListener("click",function(){
  const viewer=btn.closest("[id^='srcview-']");if(viewer)viewer.style.display="none";
});});
// v5.8: Restore collapsed section state after re-render + re-apply active filter
c.querySelectorAll(".hs").forEach(hs=>{
  const title=hs.querySelector(".hs-t")?.textContent||"";
  if(title&&_collapsedSections.has(title))hs.classList.add("collapsed");
});
const fVal=document.getElementById("fD")?.value||"";
if(fVal){
  const fLower=fVal.toLowerCase();
  c.querySelectorAll(".hs").forEach(hs=>{
    const text=(hs.textContent||"").toLowerCase();
    hs.style.display=text.indexOf(fLower)>-1?"":"none";
  });
}
}catch(err){c.innerHTML=`<div class="empty"><div class="empty-i">⚠️</div><div class="empty-t">Deep tab render error: ${esc(err.message)}</div></div>`;console.error("renderDeep error:",err);}}

function renderConsole(filter){
  const c=document.getElementById("rC");
  const logs=D.consoleLogs||[];
  if(!logs.length){c.innerHTML=empty("🖥️",'No console logs. Enable <span style="color:var(--purple);font-weight:700">Deep</span> mode and reload the page.');return;}
  const f=filter?filter.toLowerCase():"";
  const filtered=f?logs.filter(l=>(l.text||"").toLowerCase().includes(f)||(l.level||"").includes(f)||(l.url||"").toLowerCase().includes(f)):logs;
  const errors=filtered.filter(l=>l.level==="error");
  const warnings=filtered.filter(l=>l.level==="warning");
  const infos=filtered.filter(l=>l.level==="info"||l.level==="log");
  const verbose=filtered.filter(l=>l.level==="verbose"||l.level==="debug");
  const lvlClass=l=>l==="error"?"con-err":l==="warning"?"con-warn":l==="info"?"con-info":l==="verbose"||l==="debug"?"con-verb":"con-log";
  const lvlLabel=l=>l==="error"?"ERR":l==="warning"?"WARN":l==="info"?"INFO":l==="verbose"?"VERB":l==="debug"?"DBG":"LOG";
  let h=`<div class="con-stats">`;
  h+=`<span style="color:var(--t2);font-weight:600">${filtered.length} logs</span>`;
  if(errors.length)h+=`<div class="con-stat"><span class="con-lvl con-err">${errors.length}</span>errors</div>`;
  if(warnings.length)h+=`<div class="con-stat"><span class="con-lvl con-warn">${warnings.length}</span>warnings</div>`;
  if(infos.length)h+=`<div class="con-stat"><span class="con-lvl con-info">${infos.length}</span>info</div>`;
  if(verbose.length)h+=`<div class="con-stat"><span class="con-lvl con-verb">${verbose.length}</span>verbose</div>`;
  h+=`<button class="btn" id="conCopyAll" style="margin-left:auto;font-size:9px;padding:3px 8px">Copy All</button>`;
  h+=`</div>`;
  filtered.slice(0,200).forEach(l=>{
    const src=(l.url||"").split("/").pop()?.split("?")[0]||"";
    const line=l.lineNumber?":"+l.lineNumber:"";
    const ts=l.timestamp?new Date(l.timestamp).toLocaleTimeString("en",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"}):"";
    h+=`<div class="con-row" data-copy="${escA(l.text||"")}">`;
    h+=`<span class="con-lvl ${lvlClass(l.level)}">${lvlLabel(l.level)}</span>`;
    h+=`<span class="con-text">${esc((l.text||"").substring(0,500))}</span>`;
    if(src)h+=`<span class="con-src" title="${escA((l.url||"")+line)}">${esc(src)}${line}</span>`;
    if(ts)h+=`<span class="con-time">${ts}</span>`;
    h+=`<button class="con-copy" style="flex-shrink:0;background:var(--glass2);border:1px solid var(--glassbrd);border-radius:4px;color:var(--t3);font-size:8px;padding:1px 5px;cursor:pointer;opacity:.5;transition:opacity .15s" title="Copy">CP</button>`;
    h+=`</div>`;
  });
  if(filtered.length>200)h+=`<div style="padding:8px 16px;font-size:10px;color:var(--t3);text-align:center">Showing 200 of ${filtered.length} logs</div>`;
  c.innerHTML=h;
  c.querySelectorAll(".con-row").forEach(el=>{
    el.addEventListener("click",function(e){
      if(e.target.classList.contains("con-copy")){copy(el.dataset.copy);e.target.textContent="OK";setTimeout(()=>{e.target.textContent="CP";},800);return;}
      if(e.target.classList.contains("con-src"))return;
      const txt=el.querySelector(".con-text");
      if(txt)txt.classList.toggle("expanded");
    });
  });
  const copyAllBtn=document.getElementById("conCopyAll");
  if(copyAllBtn)copyAllBtn.addEventListener("click",function(){
    const all=filtered.map(l=>{const src=(l.url||"").split("/").pop()?.split("?")[0]||"";const line=l.lineNumber?":"+l.lineNumber:"";return`[${(l.level||"log").toUpperCase()}] ${l.text||""}${src?" ("+src+line+")":""}`;}).join("\n");
    copy(all);
  });
}
function updateFooter(){if(D?.startTime){const s=Math.floor((Date.now()-D.startTime)/1000);document.getElementById("fTime").textContent=`${Math.floor(s/60)}m ${s%60}s`;}}

// -------------------------------------------------------
// SHARED REPORT BUILDER — used by sendToClaude() and exportData("report")
// opts.format: "claude" (clipboard, concise) or "markdown" (download, verbose)
// -------------------------------------------------------
function buildReport(opts){const v=opts.format==="markdown";const tgtUrl=document.getElementById("tgtUrl").textContent||D.url||"?";const hasDeepData=(D.responseBodies?.length||0)+(D.consoleLogs?.length||0)+(D.auditIssues?.length||0)+(D.scriptSources?.length||0)+(D.executionContexts?.length||0)+(D.discoveredRoutes?.length||0)>0;
let r=`# PenScope v5.8 Recon Report\n**Target:** ${tgtUrl}\n**Time:** ${new Date().toISOString()}\n**Deep:** ${hasDeepData?"ON (data captured)":D.deepEnabled?"ON":"OFF"}\n`;
if(v)r+=`**Endpoints:** ${D.endpoints?.length||0} | **Secrets:** ${D.secrets?.length||0} | **Script Findings:** ${D.scriptSources?.length||0} | **Discovered Routes:** ${D.discoveredRoutes?.length||0} | **Audit Issues:** ${D.auditIssues?.length||0}\n\n---\n\n`;
else r+=`**Discovered Routes:** ${D.discoveredRoutes?.length||0} (endpoints found in code but never called)\n\nAnalyze all findings. Prioritize: XSS sinks, IDOR path params, missing auth, error disclosures, JSONP, mixed content. For discovered routes — identify admin panels, auth endpoints, and destructive actions to test.\n\n---\n\n`;
if(D.techStack?.length){r+=`## Tech Stack\n`;D.techStack.forEach(t=>r+=`- **${t.name}** (${t.source})\n`);r+=`\n`;}
if(D.dependencyVersions?.length){r+=`## Dependency Versions\n`;D.dependencyVersions.forEach(d=>r+=`- **${d.name}** v${d.version}\n`);r+=`\n`;}
if(D.endpoints?.length){r+=`## Endpoints (${D.endpoints.length})\n\`\`\`\n`;D.endpoints.forEach(e=>{const tags=(e.tags||[]).map(t=>`[${t.tag}]`).join("");r+=`${(e.method||"GET").padEnd(v?8:7)}${e.status?(v?e.status+"  ":(" "+e.status).padEnd(5)):v?"     ":""} ${e.path}${e.query?(v?e.query:e.query.substring(0,40)):""} ${tags}${e.responseSize?" "+fmtSize(e.responseSize):""} [${e.type||""}]\n`;});r+=`\`\`\`\n\n`;}
if(D.pathParams?.length){r+=`## ${v?"IDOR Path":"Path"} Parameters${v?"":" — IDOR Targets"} (${D.pathParams.length})\n`;D.pathParams.forEach(p=>{if(v)r+=`- \`${p.value}\` (${p.type}) in ${p.path} — ${p.risk}\n`;else r+=`- ${p.method} \`${p.pattern}\` — found: \`${p.value}\` (${p.type}) in ${p.path}\n`;});r+=`\n`;}
const params=D.params||[];if(params.length){r+=`## Parameters (${params.length})\n\`\`\`\n`;params.forEach(p=>r+=`${(p.method||"GET").padEnd(v?8:7)} ${p.path} → ${p.param}=${p.example} (${p.source})\n`);r+=`\`\`\`\n\n`;}
if(D.xssSinks?.length){r+=`## DOM XSS Sinks (${D.xssSinks.length})\n`;D.xssSinks.forEach(s=>r+=`- [${s.severity.toUpperCase()}] **${s.name}** — ${s.description}\n  \`${s.context.substring(0,120)}\`\n`);r+=`\n`;}
if(D.postMessageListeners?.length){r+=`## postMessage Listeners (${D.postMessageListeners.length})\n`;D.postMessageListeners.forEach(p=>r+=`- [${p.risk.toUpperCase()}] ${p.description}\n  \`${p.context.substring(0,120)}\`\n`);r+=`\n`;}
if(D.mixedContent?.length){r+=`## Mixed Content (${D.mixedContent.length})\n`;D.mixedContent.forEach(m=>r+=`- [${m.risk.toUpperCase()}] ${m.type}: \`${m.url}\`\n`);r+=`\n`;}
if(D.missingSRI?.length){r+=`## Missing SRI (${D.missingSRI.length})\n`;D.missingSRI.slice(0,v?Infinity:15).forEach(s=>r+=`- ${s.type}: \`${s.url}\` (${s.host})\n`);r+=`\n`;}
if(D.jsonpEndpoints?.length){r+=`## JSONP Endpoints (${D.jsonpEndpoints.length})\n`;D.jsonpEndpoints.forEach(j=>r+=`- **${j.callbackParam}** param on \`${j.url}\`\n`);r+=`\n`;}
if(D.swaggerEndpoints?.length){r+=`## Swagger/OpenAPI\n`;D.swaggerEndpoints.forEach(s=>r+=`- \`${s.url}\`\n`);r+=`\n`;}
if(D.apiVersions?.length){r+=`## API Version Downgrades\n`;D.apiVersions.forEach(a=>{r+=`- \`${a.path}\` (v${a.currentVersion}) → try: ${a.suggestedPaths.slice(0,5).map(p=>`\`${p}\``).join(", ")}\n`;});r+=`\n`;}
if(D.methodSuggestions?.length){r+=`## HTTP Method Tests (${D.methodSuggestions.length})\n`;D.methodSuggestions.forEach(m=>r+=`- \`${m.path}\` (${m.currentMethod}) → test: ${(m.suggestedMethods||[]).join(", ")}\n`);r+=`\n`;}
if(D.errorBodies?.length){r+=`## Error Responses (${D.errorBodies.length}) [DEEP]\n`;D.errorBodies.forEach(e=>{r+=`- **${e.status}** ${e.url.substring(0,80)}\n  \`\`\`\n  ${e.body.substring(0,v?500:400)}\n  \`\`\`\n`;});r+=`\n`;}
if(D.redirectChains?.length){r+=`## Redirects (${D.redirectChains.length})\n`;D.redirectChains.forEach(rd=>r+=`- ${rd.status}: \`${rd.from.substring(0,60)}\` → \`${rd.to.substring(0,60)}\`\n`);r+=`\n`;}
if(D.authFlows?.length){r+=`## Auth Flows\n`;D.authFlows.forEach(a=>r+=`- ${a.method} **${a.type}** → \`${a.path}\`\n`);r+=`\n`;}
if(D.secrets?.length){r+=`## Secrets (${D.secrets.length})\n`;D.secrets.forEach(s=>r+=`- [${s.severity.toUpperCase()}] **${s.type}**: \`${s.value}\` (${s.source})\n`);r+=`\n`;}
if(D.responseBodies?.length){r+=`## Response Body Findings (${D.responseBodies.length}) [DEEP]\n`;D.responseBodies.forEach(f=>{r+=`- [${f.severity.toUpperCase()}] **${f.pattern}**: \`${f.value}\` — ${f.description}\n  URL: ${f.url.substring(0,80)} (${f.status})\n`;if(v&&f.context)r+=`  Context: ${f.context}\n`;});r+=`\n`;}
if(D.requestHeaders?.length){r+=`## Request Auth Headers [DEEP]\n`;D.requestHeaders.forEach(rh=>{r+=`- ${rh.method} ${rh.url.substring(0,80)}\n`;rh.headers.forEach(h2=>r+=`  ${h2.name}: \`${h2.value.substring(0,100)}\`\n`);});r+=`\n`;}
if(D.certInfo){r+=`## TLS Cert [DEEP]\n`;if(D.certInfo.subjectName)r+=`- Subject: ${D.certInfo.subjectName}\n`;if(D.certInfo.issuer)r+=`- Issuer: ${D.certInfo.issuer}\n`;if(D.certInfo.sanList?.length)r+=`- SANs: ${D.certInfo.sanList.join(", ")}\n`;r+=`\n`;}
const mf=D.headers?.find(h2=>h2.type==="main_frame");if(mf){const all=[];(mf.missing||[]).forEach(m=>all.push(`[${m.severity.toUpperCase()}] Missing: ${m.header}${v?" — "+m.desc:""}`));(mf.corsIssues||[]).forEach(c2=>all.push(`[${c2.severity.toUpperCase()}] CORS: ${c2.header}${v?" — "+c2.desc:""}`));(mf.cookieIssues||[]).forEach(ck=>all.push(`[${v?ck.severity.toUpperCase():"MEDIUM"}] Cookie ${ck.cookie}: ${ck.issue}`));if(mf.cspAnalysis?.issues)mf.cspAnalysis.issues.forEach(i=>all.push(`[${i.severity.toUpperCase()}] CSP: ${i.desc}`));(mf.leaks||[]).forEach(l=>all.push(`[INFO] ${l.name}: ${l.value}`));if(all.length){r+=`## Header Issues (${all.length})\n`;all.forEach(i=>r+=`- ${i}\n`);r+=`\n`;}}
if(D.forms?.length){r+=`## Forms (${D.forms.length})\n`;D.forms.forEach(f=>r+=`- ${f.method} \`${f.action}\` — ${f.inputCount} inputs, CSRF: ${f.hasCSRF?"YES":"**NO**"}${f.hasFileUpload?", UPLOAD":""}${f.hasPasswordField?", PASSWORD":""}\n`);r+=`\n`;}
if(D.hiddenFields?.length){r+=`## Hidden Fields (${D.hiddenFields.length})\n`;(v?D.hiddenFields:D.hiddenFields.slice(0,30)).forEach(f=>r+=`- [${f.type}] ${f.name} = \`${f.value}\`\n`);r+=`\n`;}
if(D.jsGlobals?.length){r+=`## JS Globals\n`;D.jsGlobals.forEach(g=>r+=`- **window.${g.key}**: \`${g.preview.substring(0,150)}\`\n`);r+=`\n`;}
const lk=Object.keys(D.storageData?.local||{}),sk=Object.keys(D.storageData?.session||{});
if(v){const ls2=Object.entries(D.storageData?.local||{}),ss2=Object.entries(D.storageData?.session||{});if(ls2.length||ss2.length){r+=`## Storage\n`;ls2.forEach(([k,val])=>r+=`- localStorage \`${k}\` = \`${val.substring(0,200)}\`\n`);ss2.forEach(([k,val])=>r+=`- sessionStorage \`${k}\` = \`${val.substring(0,200)}\`\n`);r+=`\n`;}}
else{if(lk.length||sk.length){r+=`## Storage\n`;lk.forEach(k=>r+=`- localStorage \`${k}\` = \`${(D.storageData.local[k]||"").substring(0,80)}\`\n`);sk.forEach(k=>r+=`- sessionStorage \`${k}\` = \`${(D.storageData.session[k]||"").substring(0,80)}\`\n`);r+=`\n`;}}
if(D.cookies?.length){r+=`## Cookies (${D.cookies.length})\n`;D.cookies.forEach(ck=>{const f=[];if(!ck.secure)f.push("!Secure");if(!ck.httpOnly)f.push("!HttpOnly");if(!ck.sameSite||ck.sameSite==="unspecified")f.push("No SameSite");r+=`- \`${ck.name}\` (${ck.domain}) ${f.length?"⚠️ "+f.join(", "):"✓"}\n`;});r+=`\n`;}
if(D.subdomains?.length){r+=`## Subdomains\n`;D.subdomains.forEach(s=>r+=`- ${s}\n`);r+=`\n`;}
if(D.thirdParty?.length){r+=`## Third-Party (${D.thirdParty.length})\n`;D.thirdParty.forEach(tp=>r+=`- ${tp.host}\n`);r+=`\n`;}
if(D.webWorkers?.length){r+=`## Web Workers\n`;D.webWorkers.forEach(w=>r+=`- ${w.type}: \`${w.url}\`\n`);r+=`\n`;}
if(D.reconSuggestions?.length){r+=`## Recon File Checklist (${D.reconSuggestions.length})\n`;D.reconSuggestions.forEach(s=>r+=`- \`${s.path}\` — ${s.reason}\n`);r+=`\n`;}
if(D.wsMessages?.length){r+=`## WS Messages (${D.wsMessages.length})\n`;D.wsMessages.slice(0,15).forEach(m=>r+=`- [${m.direction}] \`${m.data.substring(0,120)}\`\n`);r+=`\n`;}
if(D.inlineHandlers?.length){r+=`## ${v?"Inline Event":"Inline"} Handlers (${D.inlineHandlers.length})\n`;if(v){const unique=[...new Set(D.inlineHandlers.map(h2=>`<${h2.tag}> ${h2.event}="${h2.handler}"`))];unique.slice(0,20).forEach(h2=>r+=`- ${h2}\n`);}else{D.inlineHandlers.slice(0,15).forEach(ih=>r+=`- ${ih.element} ${ih.event}="${ih.handler.substring(0,60)}"\n`);}r+=`\n`;}
// ---- RUNTIME ANALYSIS ----
const rt=D.runtime||{};
if(rt.framework){r+=`## Runtime Framework\n- **${rt.framework.name}** ${rt.framework.version||""}\n\n`;}
if(rt.routes?.length){r+=`## Framework Routes (${rt.routes.length}) [RUNTIME] — includes hidden/admin pages\n`;rt.routes.forEach(route=>{
  const flags=[];if(route.requiresAuth||route.requireAuth)flags.push("[AUTH]");if(route.abstract)flags.push("[ABSTRACT]");if(/admin|manage|config|settings/i.test(route.path||route.name))flags.push("[ADMIN?]");
  r+=`- \`${route.path||route.name}\` ${route.controller?`→ ${route.controller}`:""} ${flags.join(" ")}\n`;
});r+=`\n`;}
if(rt.services?.length){r+=`## Framework Services (${rt.services.length}) [RUNTIME]\n`;rt.services.forEach(s=>{
  r+=`- **${s.name}** (${(s.methods||[]).length} methods): ${(s.methods||[]).slice(0,10).map(m=>`.${m.name}(${(m.args||[]).join(",")})`).join(", ")}\n`;
});r+=`\n`;}
if(rt.stores?.length){r+=`## Application State Dumps (${rt.stores.length}) [RUNTIME]\n`;rt.stores.forEach(s=>{
  const dataStr=typeof s.data==="string"?s.data:JSON.stringify(s.data);
  r+=`- **${s.name}** (${s.type}): \`${(dataStr||"").substring(0,v?500:300)}\`\n`;
});r+=`\n`;}
if(rt.eventListeners?.length){const noOrigin=rt.eventListeners.filter(l=>l.risk==="high");
  r+=`## PostMessage Listeners (${rt.eventListeners.length}) [RUNTIME]\n`;
  if(noOrigin.length)r+=`**${noOrigin.length} listeners WITHOUT origin validation — XSS via postMessage!**\n`;
  rt.eventListeners.forEach(l=>{r+=`- [${l.risk.toUpperCase()}] ${l.element} — ${l.hasOriginCheck?"origin checked":"NO ORIGIN CHECK"}\n  Source: \`${l.source.substring(0,150)}\`\n`;});
  r+=`\n`;}
if(rt.runtimeSecrets?.length){r+=`## Secrets in JS Runtime Memory (${rt.runtimeSecrets.length}) [RUNTIME]\n`;rt.runtimeSecrets.forEach(s=>{
  r+=`- [CRITICAL] **${s.type}** at \`${s.path}\`: \`${s.value}\`\n`;
});r+=`\n`;}
if(rt.interestingGlobals?.length){r+=`## Interesting Global Objects (${rt.interestingGlobals.length}) [RUNTIME]\n`;rt.interestingGlobals.forEach(g=>{
  r+=`- **window.${g.name}** (${g.type})${g.keys&&Array.isArray(g.keys)?` — keys: ${g.keys.slice(0,10).join(", ")}`:""}\n`;
  if(g.preview)r+=`  \`${g.preview.substring(0,v?300:200)}\`\n`;
});r+=`\n`;}
if(rt.protoMethods?.length){r+=`## Hidden Prototype Methods (${rt.protoMethods.length} objects) [RUNTIME]\n`;rt.protoMethods.forEach(p=>{
  r+=`- **window.${p.object}**: ${p.methods.slice(0,10).map(m=>`.${m.name}()`).join(", ")}${p.methods.length>10?` ...+${p.methods.length-10} more`:""}\n`;
});r+=`\n`;}
if(rt.ephemeralDOM?.length){r+=`## Ephemeral DOM Elements (appeared then removed) [RUNTIME]\n`;rt.ephemeralDOM.forEach(e=>{
  r+=`- <${e.tag}> ${e.interesting?"⚠️ ":""}${e.text.substring(0,150)}\n`;
});r+=`\n`;}
if(D.networkTiming&&Object.keys(D.networkTiming).length){
  const anomalies=[];Object.entries(D.networkTiming).forEach(([path,timings])=>{if(timings.length<2)return;const times=timings.map(t=>t.time);const min=Math.min(...times),max=Math.max(...times);if(max>0&&(max-min)/max>0.5&&max>100)anomalies.push({path,min,max,count:timings.length});});
  if(anomalies.length){r+=`## Network Timing Anomalies [DEEP]\n`;anomalies.forEach(a=>{r+=`- \`${a.path}\` — ${a.min}ms to ${a.max}ms (${a.count} requests) — timing variance may reveal IDOR\n`;});r+=`\n`;}
}
if(D.interceptedRequests?.length){r+=`## Intercepted Requests [RUNTIME] (${D.interceptedRequests.length})\nFull request/response bodies captured via XHR/Fetch monkey-patch:\n`;D.interceptedRequests.slice(-15).forEach(req=>{
  r+=`- ${req.method} \`${(req.url||"").substring(0,80)}\` → ${req.status||"?"} (${fmtSize(req.responseSize)})\n`;
  if(req.requestBody)r+=`  Request body: \`${req.requestBody.substring(0,150)}\`\n`;
});r+=`\n`;}
// Script Source Findings
if(D.scriptSources?.length){
  if(v){r+=`## Script Source Findings (${D.scriptSources.length}) [DEBUGGER]\n`;D.scriptSources.forEach(s=>{r+=`- [${s.severity.toUpperCase()}] **${s.pattern}**: \`${s.value}\`\n  Source: ${s.scriptUrl}\n  Context: ${s.context||""}\n`;});r+=`\n`;}
  else{const secrets=D.scriptSources.filter(s=>s.severity==="critical"||s.severity==="high");
  const endpoints=D.scriptSources.filter(s=>s.pattern==="API Endpoint"||s.pattern==="GraphQL Endpoint");
  const other=D.scriptSources.filter(s=>s.severity!=="critical"&&s.severity!=="high"&&s.pattern!=="API Endpoint"&&s.pattern!=="GraphQL Endpoint");
  if(secrets.length){r+=`## Secrets in Script Source (${secrets.length}) [DEBUGGER]\n`;secrets.forEach(s=>{r+=`- [${s.severity.toUpperCase()}] **${s.pattern}**: \`${s.value}\`\n  Source: ${s.scriptUrl}\n`;});r+=`\n`;}
  if(endpoints.length){const uniq=[...new Set(endpoints.map(e=>e.value))];r+=`## API Endpoints in Source Code (${uniq.length}) [DEBUGGER]\n\`\`\`\n`;uniq.slice(0,100).forEach(ep=>{r+=`${ep}\n`;});r+=`\`\`\`\n\n`;}
  if(other.length){r+=`## Other Source Findings (${other.length}) [DEBUGGER]\n`;other.slice(0,30).forEach(s=>{r+=`- [${s.severity.toUpperCase()}] **${s.pattern}**: \`${s.value}\` — ${s.scriptUrl}\n`;});r+=`\n`;}}
}
// JWT Findings
if(D.jwtFindings?.length){
  r+=`## 🔓 Decoded JWT Tokens (${D.jwtFindings.length})\n`;
  D.jwtFindings.forEach(j=>{
    r+=`- **${j.algorithm}**${j.weakAlgorithm?" ⚠️ WEAK":""}${j.isExpired?" (expired)":""} from ${j.source}\n`;
    r+=`  Claims: ${(j.claims||[]).join(", ")}${j.expiry?"\n  Expires: "+j.expiry:""}\n`;
    if(!v){if(j.payload.sub)r+=`  Subject: \`${j.payload.sub}\`\n`;if(j.payload.role||j.payload.roles)r+=`  Role: \`${j.payload.role||JSON.stringify(j.payload.roles)}\`\n`;}
  });
  r+=`\n`;
}
// Permission Matrix
if(D.permissionMatrix?.length){
  r+=`## 🔐 Permission Escalation Matrix (${D.permissionMatrix.length} routes)\nCurrent role: **${D.permissionMatrix[0]?.currentRole||"?"}**${v?"":". These routes require elevated access — test for broken access control."}\n\n`;
  if(v){D.permissionMatrix.forEach(m=>r+=`- [${m.risk.toUpperCase()}] [${m.requiredRole}] \`${m.path}\` (${m.intent})\n`);r+=`\n`;}
  else{const highRisk=D.permissionMatrix.filter(m=>m.risk==="high");const medRisk=D.permissionMatrix.filter(m=>m.risk!=="high");
  if(highRisk.length){r+=`**HIGH RISK (${highRisk.length}):**\n`;highRisk.forEach(m=>r+=`- [${m.requiredRole}] \`${m.path}\` (${m.intent})\n`);r+=`\n`;}
  if(medRisk.length){r+=`**MEDIUM RISK (${medRisk.length}):**\n`;medRisk.forEach(m=>r+=`- [${m.requiredRole}] \`${m.path}\` (${m.intent})\n`);r+=`\n`;}}
}
// IDOR Tests
if(D.idorTests?.length){
  r+=`## 🎯 IDOR Test Commands (${D.idorTests.length})\n`;
  (v?D.idorTests:D.idorTests.slice(0,30)).forEach(t=>{
    r+=`- **${t.type}**: ${t.suggestion||""}\n`;
    if(t.curl)r+=`  \`${t.curl}\`\n`;
  });
  r+=`\n`;
}
// DNS Prefetch
if(D.dnsPrefetch?.length){
  r+=`## 🌐 DNS Prefetch / Preconnect (${D.dnsPrefetch.length} hints)\n`;
  D.dnsPrefetch.forEach(d=>{r+=`- **${d.rel}** → \`${d.host||d.href}\`${d.as?" as="+d.as:""}${d.crossOrigin?" (CORS)":""}\n`;});
  r+=`\n`;
}
// iframe Scan
if(D.iframeScan?.length){
  r+=`## 🖼️ iframe Scan (${D.iframeScan.length} frames)\n`;
  D.iframeScan.forEach(f=>{
    r+=`- **<${f.tag}>** ${f.src?"`"+f.src.substring(0,100)+"`":"(no src)"}${!f.visible?" **HIDDEN**":""}${f.sameOrigin?" same-origin":" cross-origin"}${f.sandbox!==null?" sandbox=\""+f.sandbox+"\"":""}${f.sandbox===null&&f.sameOrigin?" ⚠️ NO SANDBOX":""}\n`;
    if(f.innerContent?.forms?.length)r+=`  Forms: ${f.innerContent.forms.map(fm=>fm.method+" "+fm.action).join(", ")}\n`;
  });
  r+=`\n`;
}
// Header Intelligence
if(D.headerIntel?.length){
  r+=`## 📡 HTTP Header Intelligence (${D.headerIntel.length})\n`;
  D.headerIntel.forEach(hi=>{r+=`- **${hi.header}**: \`${hi.value.substring(0,80)}\` — ${hi.label} (${hi.url})\n`;});
  r+=`\n`;
}
// Performance Entries
if(D.perfEntries?.length){
  const tp=D.perfEntries.filter(e=>e.isThirdParty);
  const totalSize=D.perfEntries.reduce((s,e)=>s+(e.transferSize||0),0);
  r+=`## ⚡ Performance Entries (${D.perfEntries.length} resources, ${Math.round(totalSize/1024)}KB, ${tp.length} third-party)\n`;
  const byHost2={};
  D.perfEntries.forEach(e=>{const h2=e.host||"?";if(!byHost2[h2])byHost2[h2]={count:0,size:0};byHost2[h2].count++;byHost2[h2].size+=e.transferSize||0;});
  Object.entries(byHost2).sort((a,b)=>b[1].size-a[1].size).forEach(([host,data])=>{
    r+=`- **${host}** — ${data.count} requests, ${data.size>1024?Math.round(data.size/1024)+"KB":data.size+"B"}\n`;
  });
  r+=`\n`;
}
// CSS Content
if(D.cssContent?.length){
  r+=`## 🎨 CSS Content Extraction (${D.cssContent.length} URLs)\n`;
  const imports=D.cssContent.filter(c=>c.type==="@import");
  const apiUrls=D.cssContent.filter(c=>!c.isData&&(c.url.includes("/api/")||c.url.includes("internal")));
  if(imports.length){r+=`**@import:** ${imports.map(c=>"`"+c.url+"`").join(", ")}\n`;}
  if(apiUrls.length){r+=`**API/Internal URLs in CSS:**\n`;apiUrls.forEach(c=>{r+=`- \`${c.url}\` via ${c.type}\n`;});}
  r+=`\n`;
}
// Encoded Blobs
if(D.encodedBlobs?.length){
  r+=`## 🔐 Encoded/Encrypted Data (${D.encodedBlobs.length} blobs)\n`;
  D.encodedBlobs.forEach(b=>{
    const isEncrypted=["aes","bcrypt","openssl","pgp","encrypted","possible","asn1"].includes((b.type||"").split("-")[0]);
    r+=`- **${b.type}** from \`${b.source}\` (${b.length} chars)${isEncrypted?" 🔒 ENCRYPTED":""}`;
    if(b.meta?.preview)r+=` — preview: \`${b.meta.preview.substring(0,80)}\``;
    if(b.meta?.algorithm)r+=` — alg: ${b.meta.algorithm}`;
    if(b.meta?.note)r+=` — ${b.meta.note}`;
    r+=`\n`;
  });
  r+=`\n`;
}
// Memory Strings
if(D.memoryStrings?.length){
  r+=`## 🧠 Memory Secrets (${D.memoryStrings.length} leaked strings in V8 heap)\n`;
  D.memoryStrings.forEach(m=>{r+=`- **${m.type}** from \`${m.source}\`: \`${m.value}\`\n`;});
  r+=`\n`;
}
// POST Bodies
if(D.postBodies?.length){
  r+=`## 📤 Captured POST Bodies (${D.postBodies.length})\n`;
  D.postBodies.forEach(p=>{r+=`- **${p.method}** \`${p.path}\` — ${p.contentType}\n  \`${p.body.substring(0,300)}\`\n`;});
  r+=`\n`;
}
// API Response Findings
if(D.apiResponseBodies?.length){
  const withFindings=D.apiResponseBodies.filter(r2=>r2.findings?.length>0);
  if(withFindings.length){
    r+=`## 🔍 API Response Deep Scan (${withFindings.length} responses with findings)\n`;
    withFindings.forEach(r2=>{
      r+=`### ${r2.status} ${r2.path} (${Math.round(r2.size/1024)}KB)\n`;
      r2.findings.forEach(f=>{r+=`- [${f.severity.toUpperCase()}] **${f.pattern}**: \`${f.value.substring(0,100)}\`\n`;});
      r+=`\n`;
    });
  }
}
// Coverage
if(D.coverageData){
  const cov=D.coverageData;
  const totalPct=cov.totalBytes>0?Math.round(cov.totalUsed/cov.totalBytes*100):0;
  r+=`## 📊 Code Coverage — ${totalPct}% used (${Math.round((cov.totalBytes-cov.totalUsed)/1024)}KB dead code)\n`;
  r+=`Dead code = hidden features. ${cov.totalScripts} scripts analyzed.\n\n`;
  (cov.scripts||[]).slice(0,15).forEach(s=>{
    r+=`- **${s.usedPercent}%** used — \`${(s.url||"").split("/").pop()}\` (${Math.round(s.totalBytes/1024)}KB total, ${Math.round(s.unusedBytes/1024)}KB dead)`;
    if(s.unusedFunctions?.length)r+=` — unused: ${s.unusedFunctions.slice(0,5).join(", ")}`;
    r+=`\n`;
  });
  r+=`\n`;
}
// DOM Listeners
if(D.domListeners?.length){
  r+=`## 🎯 DOM Event Listeners (${D.domListeners.length})\n`;
  D.domListeners.slice(0,20).forEach(l=>{r+=`- \`${l.element}\` — ${l.attrs.map(a=>`${a.event}="${a.handler.substring(0,60)}"`).join(", ")}\n`;});
  r+=`\n`;
}
// Shadow DOM
if(D.shadowDOMData?.length){
  r+=`## 👻 Shadow DOM (${D.shadowDOMData.length} shadow roots)\n`;
  D.shadowDOMData.forEach(s=>{r+=`- \`${s.host}\` — ${s.inputCount} inputs, ${s.linkCount} links, ${s.formCount} forms\n`;});
  r+=`\n`;
}
// IndexedDB
if(D.indexedDBData?.length){
  r+=`## 💾 IndexedDB Data (${D.indexedDBData.length} databases)\n`;
  D.indexedDBData.forEach(db=>{
    r+=`- **${db.name}** v${db.version} — ${v?"stores: "+db.stores.map(s=>s.name).join(", "):db.stores.length+" stores: "+db.stores.map(s=>s.name).join(", ")}${db.data?.length?" ("+db.data.length+" entries)":""}\n`;
  });
  r+=`\n`;
}
// CacheStorage
if(D.cacheStorageData?.length){
  r+=`## 📋 CacheStorage (${D.cacheStorageData.length} caches)\n`;
  D.cacheStorageData.forEach(c=>{
    r+=`- **${c.name}** — ${c.entryCount} entries\n`;
    const apiEntries=c.entries.filter(e=>/\/api\//i.test(e.url)||/\.json/i.test(e.url));
    if(apiEntries.length){r+=`  API responses cached:\n`;apiEntries.slice(0,10).forEach(e=>r+=`  - ${e.status} ${e.url.substring(0,80)}\n`);}
  });
  r+=`\n`;
}
// Source Maps
if(v&&D.sourceMaps?.length){r+=`## Source Maps (${D.sourceMaps.length})\n`;D.sourceMaps.forEach(s=>r+=`- ${s.mapUrl} (${s.source})\n`);r+=`\n`;}
// Discovered Routes
if(D.discoveredRoutes?.length){
  const appRoutes=D.discoveredRoutes.filter(r2=>!r2.isNoise);
  const bySource={};appRoutes.forEach(r2=>{(bySource[r2.source]=bySource[r2.source]||[]).push(r2);});
  r+=`## 🗺️ Discovered Routes (${appRoutes.length} app routes, ${D.discoveredRoutes.length-appRoutes.length} noise filtered)\n\n`;
  Object.entries(bySource).sort((a,b)=>b[1].length-a[1].length).forEach(([source,routes])=>{
    const uniquePaths=[...new Set(routes.map(x=>x.path))];
    r+=`### ${source} (${uniquePaths.length})\n\`\`\`\n`;
    uniquePaths.slice(0,v?Infinity:80).forEach(p=>{const route=routes.find(x=>x.path===p);r+=`[${(route?.intent||"?").padEnd(12)}] ${p}\n`;});
    if(!v&&uniquePaths.length>80)r+=`... +${uniquePaths.length-80} more\n`;
    r+=`\`\`\`\n\n`;
  });
}
// Console Capture
if(D.consoleLogs?.length){
  r+=`## Console Capture (${D.consoleLogs.length}) [LOG]\n`;
  (v?D.consoleLogs:D.consoleLogs.slice(0,30)).forEach(l=>{r+=`- [${l.level.toUpperCase()}] ${l.text.substring(0,v?Infinity:200)}${l.url?` (${l.url.substring(0,60)}${l.lineNumber?":"+l.lineNumber:""})`:""}\n`;});
  r+=`\n`;
}
// Chrome Audit Issues
if(D.auditIssues?.length){
  r+=`## Chrome Audit Issues (${D.auditIssues.length}) [AUDITS]\n`;
  D.auditIssues.forEach(a=>{r+=`- [${a.severity.toUpperCase()}] **${a.type}**${a.url?" — "+a.url.substring(0,80):""}${a.violatedDirective?" — directive: "+a.violatedDirective:""}${a.cookieName?" — cookie: "+a.cookieName+(v?" ("+a.cookieDomain+")":""):""}${v&&a.cookieWarningReasons?" — "+a.cookieWarningReasons:""}${a.reason?" — "+a.reason:""}\n`;});
  r+=`\n`;
}
// Execution Contexts
if(D.executionContexts?.length>1){
  r+=`## Execution Contexts (${D.executionContexts.length}) [RUNTIME]\n`;
  D.executionContexts.forEach(ctx=>{r+=`- ${ctx.isDefault?"main":"iframe/worker"}: ${ctx.origin} ${ctx.name?`(${ctx.name})`:""}\n`;});
  r+=`\n`;
}
// Probe Results
const arP=D.probeData;
if(arP&&arP.status==="done"){
  r+=`## ⚡ Probe Results (${arP.requests||0} requests) [PROBE]\n\n`;
  if(arP.graphql){
    const g=arP.graphql;
    r+=`### GraphQL Schema — ${g.endpoint} (${g.typeCount} types)\n`;
    if(g.queryFields?.length){r+=`**Queries (${g.queryFields.length}):**\n`;g.queryFields.slice(0,50).forEach(f=>r+=`- \`${f.name}\` → ${f.type?.name||f.type?.kind||"?"}\n`);r+=`\n`;}
    if(g.mutationFields?.length){r+=`**Mutations (${g.mutationFields.length}):**\n`;g.mutationFields.slice(0,50).forEach(f=>r+=`- \`${f.name}\` → ${f.type?.name||f.type?.kind||"?"}\n`);r+=`\n`;}
    if(v&&g.types?.length){r+=`**Types (${g.types.length}):**\n`;g.types.filter(t=>t.kind==="OBJECT"&&!t.name.startsWith("__")).forEach(t=>{r+=`- **${t.name}**: ${(t.fields||[]).map(f=>f.name).join(", ")}\n`;});r+=`\n`;}
  }
  if(arP.swagger?.length){arP.swagger.forEach(sw=>{
    r+=`### Swagger: ${sw.title} v${sw.version} (${sw.pathCount} paths)\n`;
    if(v&&sw.securitySchemes?.length)r+=`Auth schemes: ${sw.securitySchemes.join(", ")}\n`;
    if(v&&sw.servers?.length)r+=`Servers: ${sw.servers.map(s=>s.url||"").join(", ")}\n`;
    r+=`\`\`\`\n`;(v?sw.paths:sw.paths.slice(0,100)).forEach(p=>r+=`${(p.methods||[]).join(",").toUpperCase().padEnd(20)} ${p.path}${p.params.length?" ("+(v?p.params.map(pr=>pr.name+"["+pr.in+"]").join(","):p.params.length+" params")+")":""}${p.summary?" — "+p.summary:""}\n`);
    r+=`\`\`\`\n\n`;
  });}
  if(arP.sourceMaps?.length){arP.sourceMaps.forEach(sm=>{
    r+=`### Source Map: ${sm.url.substring(0,60)} (${sm.fileCount} files)\n`;
    if(sm.endpoints?.length){const uniq=[...new Set(sm.endpoints.map(e=>e.path))];r+=`${v?"Endpoints found":"**Endpoints in source**"} (${uniq.length})${v?"":":**"}\n\`\`\`\n`;uniq.slice(0,50).forEach(p=>r+=`${p}\n`);r+=`\`\`\`\n\n`;}
    if(v&&sm.sources?.length){r+=`Source tree (${sm.fileCount} files):\n\`\`\`\n`;sm.sources.forEach(s=>r+=`${s}\n`);r+=`\`\`\`\n`;}
    if(v)r+=`\n`;
  });}
  const interestingP=(arP.probes||[]).filter(p=>p.interesting||p.type==="robots"||p.type==="sitemap");
  if(interestingP.length){r+=`### Probe ${v?"Results":"Hits"} (${interestingP.length}${v?" hits":""})\n`;interestingP.forEach(p=>{
    r+=`- **${p.status}** \`${p.path}\`${p.disallowed?" — Disallowed: "+(v?p.disallowed.join(", "):p.disallowed.slice(0,5).join(", ")):""}${p.sitemaps&&v?" — Sitemaps: "+p.sitemaps.join(", "):""}${p.urlCount?" — "+p.urlCount+(v?"":" sitemap")+" URLs":""}\n`;
  });r+=`\n`;}
  if(arP.options?.length){r+=`### OPTIONS ${v?"Allowed Methods":"Results"} (${arP.options.length})\n`;arP.options.forEach(o=>r+=`- \`${o.path}\` → ${o.allowedMethods}\n`);r+=`\n`;}
  if(arP.suffixes?.length){r+=`### Suffix Bruteforce Hits (${arP.suffixes.length})\n`;arP.suffixes.forEach(s=>{
    r+=`- **${s.status}** \`${s.path}\`${s.status===401||s.status===403?" 🔒 auth-required":""}${v&&s.fromPrefix?" (from "+s.fromPrefix+")":""}\n`;
  });r+=`\n`;}
  if(arP.bacResults?.length){const bv=arP.bacResults.filter(b=>b.vulnerable);r+=`### 🚨 Broken Access Control (${bv.length} VULNERABLE / ${arP.bacResults.length} tested)\n`;arP.bacResults.forEach(b=>{r+=`- **${b.status}** ${b.method} \`${b.path}\` ${b.vulnerable?"🚨 CONFIRMED"+(v?"":" VULNERABLE"):b.partial?"⚠️ PARTIAL"+(v?"":" (server processed)"):""}${b.risk?" ["+b.risk+"]":""}${b.intent?" ("+b.intent+")":""}\n`;if(b.bodyPreview)r+=`  Response: \`${b.bodyPreview.substring(0,v?150:100)}\`\n`;});r+=`\n`;}
  if(arP.methodResults?.length){const mi=arP.methodResults.filter(m=>m.interesting);r+=`### 🔀 HTTP Method Tampering (${mi.length} accepted / ${arP.methodResults.length} tested)\n`;arP.methodResults.forEach(m=>{r+=`- **${m.status}** ${m.originalMethod} → ${m.testedMethod} \`${m.path}\`${m.interesting?" 🚨 ACCEPTED":""}\n`;});r+=`\n`;}
  if(arP.corsResults?.length){r+=`### 🌍 CORS Misconfiguration (${arP.corsResults.length})\n`;arP.corsResults.forEach(c=>{r+=`- [${c.severity.toUpperCase()}] \`${c.path}\` — Origin: ${c.origin} → ACAO: ${c.acao}${c.acac?" | Credentials: "+c.acac:""}${c.reflected?" ⚡ REFLECTED":""}${c.severity==="critical"?" 🚨 FULL CORS BYPASS":""}\n`;});r+=`\n`;}
  if(arP.contentTypeResults?.length){const ca=arP.contentTypeResults.filter(c=>c.accepted);r+=`### 📝 Content-Type Confusion (${ca.length} bypassed / ${arP.contentTypeResults.length} tested)\n`;arP.contentTypeResults.forEach(c=>{r+=`- **${c.status}** \`${c.path}\` — ${c.testedCT}${c.accepted?" 🚨 BYPASSED":c.serverError?" ⚠️ 500 ERROR":""}\n`;});r+=`\n`;}
  if(arP.openRedirects?.length){r+=`### 🔀 Open Redirects (${arP.openRedirects.length})\n`;arP.openRedirects.forEach(rd=>{r+=`- [${rd.severity.toUpperCase()}] \`${rd.path}\` — param: ${rd.param}, payload: \`${rd.payload}\` → redirects to \`${rd.redirectTo}\` (${rd.status})\n`;});r+=`\n`;}
  if(arP.raceResults?.length){r+=`### ⚡ Race Conditions (${arP.raceResults.length})\n`;arP.raceResults.forEach(rc=>{r+=`- [${rc.severity.toUpperCase()}] ${rc.method} \`${rc.path}\` — ${rc.parallelRequests} parallel → ${rc.successCount} success, ${rc.uniqueResponses} unique responses — statuses: ${(rc.statuses||[]).join(", ")}${rc.note?" — "+rc.note:""}\n`;});r+=`\n`;}
  if(arP.hppResults?.length){r+=`### 📋 HTTP Parameter Pollution (${arP.hppResults.length})\n`;arP.hppResults.forEach(hp=>{r+=`- [${hp.severity.toUpperCase()}] \`${hp.path}\` — param: ${hp.param}, technique: ${hp.technique} — original: ${hp.originalStatus} → test: ${hp.testStatus}${hp.bodyDiffers?" (body differs)":""}\n`;});r+=`\n`;}
  if(arP.subdomains?.length){r+=`### 🌐 Discovered Subdomains (${arP.subdomains.length})\n`;arP.subdomains.forEach(sd=>{r+=`- \`${sd.host}\` (via ${sd.source})\n`;});r+=`\n`;}
  if(arP.graphqlFuzz?.length){r+=`### 🔮 GraphQL Field Fuzzing (${arP.graphqlFuzz.length})\n`;arP.graphqlFuzz.forEach(gf=>{r+=`- Typo: \`${gf.typo}\` → suggestions: ${(gf.suggestions||[]).join(", ")}${(gf.possibleFields||[]).length?" | possible fields: "+(gf.possibleFields||[]).join(", "):""}\n`;});r+=`\n`;}
  if(arP.jwtAlgResults?.length){const ja=arP.jwtAlgResults.filter(j=>j.accepted);r+=`### 🔑 JWT Algorithm Confusion (${ja.length} accepted / ${arP.jwtAlgResults.length} tested)\n`;arP.jwtAlgResults.forEach(j=>{r+=`- [${j.severity.toUpperCase()}] \`${j.endpoint}\` — ${j.originalAlg} → ${j.testedAlg} ${j.accepted?"🚨 ACCEPTED":"rejected"} (${j.source||""})\n`;});r+=`\n`;}
  if(arP.hostHeaderResults?.length){const hhr=arP.hostHeaderResults.filter(h2=>h2.reflected);r+=`### 🏠 Host Header Injection (${hhr.length} reflected / ${arP.hostHeaderResults.length} tested)\n`;arP.hostHeaderResults.forEach(hh=>{r+=`- [${hh.severity.toUpperCase()}] payload: \`${hh.payload}\` — ${hh.reflected?"REFLECTED":"not reflected"} (${hh.status})${hh.bodySnippet?"\n  Snippet: `"+hh.bodySnippet.substring(0,100)+"`":""}\n`;});r+=`\n`;}
  if(arP.cachePoisonResults?.length){const cpr=arP.cachePoisonResults.filter(c=>c.reflected);r+=`### 💉 Cache Poisoning (${cpr.length} reflected / ${arP.cachePoisonResults.length} tested)\n`;arP.cachePoisonResults.forEach(cp=>{r+=`- [${cp.severity.toUpperCase()}] \`${(cp.url||"").substring(0,80)}\` — header: ${cp.header}: ${cp.value} — ${cp.reflected?"REFLECTED":"not reflected"}${cp.statusChange?" | status changed":""}${cp.bodyDiff?" | body differs":""}\n`;});r+=`\n`;}
  // IDOR Auto-Test
  if(arP.idorAutoResults?.length){const confirmed=arP.idorAutoResults.filter(r2=>r2.severity==="critical"||r2.severity==="high");r+=`### 🔑 IDOR Auto-Test (${confirmed.length} confirmed / ${arP.idorAutoResults.length} tested)\n`;arP.idorAutoResults.filter(r2=>r2.severity!=="info").forEach(ir=>{r+=`- [${ir.severity.toUpperCase()}] \`${ir.path}\` — ${ir.paramType}: ${ir.originalId} → ${ir.testedId} — status ${ir.originalStatus}→${ir.testedStatus}${ir.sameSkeleton?" **SAME STRUCTURE DIFFERENT DATA**":""}${ir.bodyDiffers?" (body differs)":""}\n`;});r+=`\n`;}
  // Auth Token Removal
  if(arP.authRemovalResults?.length){const broken=arP.authRemovalResults.filter(r2=>r2.severity==="critical"||r2.severity==="high");r+=`### 🔓 Auth Removal Test (${broken.length} broken / ${arP.authRemovalResults.length} tested)\n`;arP.authRemovalResults.forEach(ar2=>{r+=`- [${ar2.severity.toUpperCase()}] ${ar2.method} \`${ar2.path}\` — auth: ${ar2.authStatus} (${ar2.authSize||"?"}B) / no auth: ${ar2.noAuthStatus} (${ar2.noAuthSize||"?"}B)${ar2.sameBody?" **IDENTICAL RESPONSE**":""}${ar2.note?" — "+ar2.note:""}\n`;});r+=`\n`;}
  // CSRF Validation
  if(arP.csrfResults?.length){const vuln=arP.csrfResults.filter(r2=>r2.severity==="critical"||r2.severity==="high");r+=`### 🛡️ CSRF Validation (${vuln.length} vulnerable / ${arP.csrfResults.length} tested)\n`;arP.csrfResults.forEach(cs=>{r+=`- [${cs.severity.toUpperCase()}] ${cs.method} \`${cs.path}\` — CSRF: ${cs.hasCSRF?cs.csrfField:"NONE"} | normal: ${cs.normalStatus} | no CSRF: ${cs.noCSRFStatus} | no cookie: ${cs.noCookieStatus}${cs.note?" — "+cs.note:""}\n`;});r+=`\n`;}
  if(arP.grpcReflection){r+=`### 🔌 gRPC Reflection\n- **${arP.grpcReflection.type}** at \`${arP.grpcReflection.url}\` (${arP.grpcReflection.status})\n\n`;}
  if(arP.compressionResults?.length){const vuln=arP.compressionResults.filter(c=>c.severity==="high");r+=`### 🗜️ Compression Oracle / BREACH (${vuln.length} vulnerable / ${arP.compressionResults.length} tested)\n`;arP.compressionResults.forEach(c=>{r+=`- [${(c.severity||"info").toUpperCase()}] \`${c.path}\` — compressed: ${c.compressedSize}B, uncompressed: ${c.uncompressedSize}B, ratio: ${c.ratio}x${c.note?" — "+c.note:""}\n`;});r+=`\n`;}
  if(arP.wsHijackResults?.length){const wv=arP.wsHijackResults.filter(w=>w.crossOriginAllowed);r+=`### 🔌 WebSocket Hijack (${wv.length} vulnerable / ${arP.wsHijackResults.length} tested)\n`;arP.wsHijackResults.forEach(w=>{r+=`- [${w.severity.toUpperCase()}] \`${w.url}\` — cross-origin: ${w.crossOriginStatus}, no-origin: ${w.noOriginStatus}${w.crossOriginAllowed?" **CROSS-ORIGIN ACCEPTED**":""}${w.note?" — "+w.note:""}\n`;});r+=`\n`;}
  if(arP.cachePoisonProbe?.length){const cr=arP.cachePoisonProbe.filter(c=>c.reflected);r+=`### 💉 Active Cache Poisoning (${cr.length} reflected / ${arP.cachePoisonProbe.length} diffs)\n`;arP.cachePoisonProbe.forEach(c=>{r+=`- [${c.severity.toUpperCase()}] \`${c.path}\` — headers: ${Object.entries(c.headers||{}).map(([k,val])=>k+":"+val).join(", ")}${c.reflected?" **REFLECTED**":""}${c.bodyDiff?" body-diff":""}${c.note?" — "+c.note:""}\n`;});r+=`\n`;}
  if(arP.timingOracle?.length){const st=arP.timingOracle.filter(t=>t.maxDelta>200);r+=`### ⏱️ Timing Oracle (${st.length} significant / ${arP.timingOracle.length} tested)\n`;arP.timingOracle.forEach(t=>{r+=`- [${t.severity.toUpperCase()}] \`${t.path}\` — baseline: ${t.baselineMs}ms, max delta: ${t.maxDelta}ms\n`;(t.lfiTimings||[]).forEach(lt=>{r+=`  payload: \`${lt.payload}\` → ${lt.time}ms\n`;});});r+=`\n`;}
  if(arP.coopCoepBypass?.length){r+=`### 🛡️ COOP/COEP Bypass\n`;arP.coopCoepBypass.forEach(c=>{r+=`- [${c.severity.toUpperCase()}] ${c.type||"check"}${c.path?" `"+c.path+"`":""}${c.frameable?" **FRAMEABLE**":""}${c.crossOriginIsolated===false?" NOT ISOLATED":""}${c.note?" — "+c.note:""}\n`;});r+=`\n`;}
  if(arP.storagePartition?.length){const sp=arP.storagePartition.filter(s=>s.partitioned);r+=`### 🔒 Storage Partitioning (${sp.length} partitioned)\n`;arP.storagePartition.forEach(s=>{if(s.type!=="summary")r+=`- **${s.type}**: ${s.partitioned?"PARTITIONED":"accessible"}${s.error?" ("+s.error+")":""}\n`;else r+=`- ${s.note}\n`;});r+=`\n`;}
  // v5.7: Recursive API Discovery — wave-by-wave breakdown with inline findings
  if(arP.recursiveProbe&&(arP.recursiveProbe.wave1?.length||arP.recursiveProbe.wave2?.length||arP.recursiveProbe.wave3?.length)){
    const rp=arP.recursiveProbe;
    const w1=rp.wave1||[],w2=rp.wave2||[],w3=rp.wave3||[];
    const total=w1.length+w2.length+w3.length;
    const allFindings=[...w1,...w2,...w3].flatMap(r2=>(r2.findings||[]).map(f=>({...f,sourceUrl:r2.path})));
    const critical=allFindings.filter(f=>f.severity==="critical").length;
    const high=allFindings.filter(f=>f.severity==="high").length;
    r+=`### 🔁 Smart Recursive Probing (${total} endpoints probed, ${allFindings.length} findings)\n`;
    r+=`Seed: ${rp.seedCount||0} URLs · Wave1: ${w1.length} · Wave2: ${w2.length} · Wave3: ${w3.length} · ${rp.newUrlsFound||0} new URLs discovered${critical?` · **${critical} CRITICAL**`:""}${high?` · ${high} HIGH`:""}\n\n`;
    const renderWave=(label,waveData)=>{
      if(!waveData.length)return "";
      let wr=`**${label} (${waveData.length})**\n`;
      const sorted=[...waveData].sort((a,b)=>(b.findings?.length||0)-(a.findings?.length||0));
      sorted.slice(0,v?Infinity:30).forEach(r2=>{
        wr+=`- **${r2.status}** \`${r2.path||r2.url||""}\``;
        if(r2.size)wr+=` (${r2.size>1024?Math.round(r2.size/1024)+"KB":r2.size+"B"})`;
        if(r2.isGraphQL)wr+=` [GraphQL]`;
        if(r2.findings?.length)wr+=` — **${r2.findings.length} findings**`;
        if(r2.newUrls?.length)wr+=` — ${r2.newUrls.length} new URLs extracted`;
        wr+=`\n`;
        if(r2.findings?.length){
          r2.findings.slice(0,v?Infinity:5).forEach(f=>{
            wr+=`  - [${(f.severity||"").toUpperCase()}] ${f.type}: \`${String(f.value).substring(0,150)}\`\n`;
          });
        }
      });
      wr+=`\n`;
      return wr;
    };
    r+=renderWave("Wave 1 — seed URLs from prior steps",w1);
    r+=renderWave("Wave 2 — URLs extracted from Wave 1 responses",w2);
    r+=renderWave("Wave 3 — URLs extracted from Wave 2 responses",w3);
  }
}
// v5.4: New attack surface
if(D.grpcEndpoints?.length){r+=`## 🔌 gRPC Endpoints (${D.grpcEndpoints.length})\n`;D.grpcEndpoints.forEach(g=>{r+=`- [${g.type}] \`${g.path}\` — ${g.host}${g.contentType?" ("+g.contentType+")":""}\n`;});r+=`\n`;}
if(D.wasmModules?.length){const files=D.wasmModules.filter(w=>w.url);r+=`## ⚙️ WebAssembly Modules (${files.length})\n`;files.forEach(w=>{r+=`- \`${w.url}\` — ${w.source}${w.size?" ("+Math.round(w.size/1024)+"KB)":""}\n`;});r+=`\n`;}
if(D.webrtcLeaks?.length){r+=`## 🌐 WebRTC IP Leaks (${D.webrtcLeaks.length})\n`;D.webrtcLeaks.forEach(l=>{r+=`- **${l.type}** \`${l.ip}\`${l.type==="private"?" — internal network exposure":""}\n`;});r+=`\n`;}
if(D.webAuthnInfo?.supported){r+=`## 🔐 WebAuthn / FIDO2\n`;D.webAuthnInfo.features.forEach(f=>{r+=`- ${f}\n`;});r+=`\n`;}
if(D.coopCoepInfo){r+=`## 🛡️ COOP/COEP Isolation\n`;const ci=D.coopCoepInfo;r+=`- Cross-Origin Isolated: **${ci.crossOriginIsolated?"YES":"NO"}**\n`;if(ci.coop)r+=`- COOP: ${ci.coop}\n`;if(ci.coep)r+=`- COEP: ${ci.coep}\n`;(ci.features||[]).forEach(f=>{r+=`- ${f}\n`;});r+=`\n`;}
if(D.webgpuInfo?.supported){r+=`## 🎮 WebGPU Detected\n`;if(D.webgpuInfo.adapter){const a=D.webgpuInfo.adapter;if(a.vendor)r+=`- Vendor: ${a.vendor}\n`;if(a.architecture)r+=`- Architecture: ${a.architecture}\n`;if(a.features?.length)r+=`- Features: ${a.features.join(", ")}\n`;}r+=`\n`;}
if(D.broadcastChannels?.length){const msgs=D.broadcastChannels.filter(b=>b.type==="message");r+=`## 📡 BroadcastChannel (${D.broadcastChannels.length} entries, ${msgs.length} messages intercepted)\n`;D.broadcastChannels.forEach(b=>{if(b.type==="probe")r+=`- Probed ${b.channelsProbed} channels: ${(b.channelNames||[]).join(", ")}\n`;if(b.type==="message")r+=`- **${b.channel}**: \`${(b.data||"").substring(0,200)}\`\n`;});r+=`\n`;}
// v5.3.2: Real Event Listeners
if(D.realEventListeners?.length){
  const msgL=D.realEventListeners.filter(l=>l.event==="message");
  const intL=D.realEventListeners.filter(l=>l.isInteresting);
  r+=`## 🎯 Event Listeners (${D.realEventListeners.length} total, ${msgL.length} message handlers)\n`;
  if(msgL.length)r+=`**${msgL.length} postMessage listeners — test for XSS via window.postMessage()**\n\n`;
  intL.slice(0,v?50:20).forEach(l=>{r+=`- **${l.event}** on \`${l.target}\` — ${l.handler.substring(0,v?300:100)}${l.lineNumber?" (line "+l.lineNumber+")":""}\n`;});
  r+=`\n`;
}
// v5.3.2: HttpOnly Cookies
if(D.httpOnlyCookies?.length){
  const authC=D.httpOnlyCookies.filter(c=>c.isAuthCookie);
  const issueC=D.httpOnlyCookies.filter(c=>c.issues?.length>0);
  r+=`## 🍪 All Cookies incl. HttpOnly (${D.httpOnlyCookies.length} total, ${authC.length} auth, ${issueC.length} with issues)\n`;
  D.httpOnlyCookies.forEach(c=>{r+=`- \`${c.name}\` (${c.domain}) ${c.httpOnly?"HttpOnly":"!HttpOnly"} ${c.secure?"Secure":"!Secure"} ${c.sameSite}${c.issues?.length?" ⚠️ "+c.issues.join(", "):""}${c.isAuthCookie?" **AUTH**":""}\n`;});
  r+=`\n`;
}
// v5.3.2: Response Schemas
if(D.responseSchemas?.length){
  r+=`## 📐 API Response Schemas (${D.responseSchemas.length} endpoints)\n`;
  D.responseSchemas.slice(0,v?20:10).forEach(s=>{
    const sens=s.fields.filter(f=>f.isSensitive);const ids=s.fields.filter(f=>f.isId);
    r+=`### \`${(s.path||"").substring(0,80)}\` (${s.fields.length} fields)\n`;
    if(sens.length)r+=`**Sensitive fields:** ${sens.map(f=>f.key).join(", ")}\n`;
    if(ids.length)r+=`**ID fields (IDOR targets):** ${ids.map(f=>f.key+"="+String(f.sample||"?").substring(0,20)).join(", ")}\n`;
    r+=`\`\`\`\n${s.fields.slice(0,v?30:15).map(f=>f.key+": "+f.type+(f.sample!==null?" = "+String(f.sample).substring(0,30):"")).join("\n")}\n\`\`\`\n\n`;
  });
}
// v5.3.2: Heap Secrets
if(D.heapSecrets?.length){
  r+=`## 🧠 Heap/Closure Secrets (${D.heapSecrets.length})\n`;
  D.heapSecrets.forEach(s=>{r+=`- **${s.type}**: \`${s.value}\` — from ${s.source}${s.entropy?" (entropy: "+s.entropy+")":""}\n`;});
  r+=`\n`;
}
// v5.3.2: Parsed Source Maps
if(D.parsedSourceMaps?.length){
  D.parsedSourceMaps.forEach(sm=>{
    r+=`## 🗺️ Source Map: ${(sm.url||"").split("/").pop()||"?"} (${sm.fileCount} files) [${sm.source}]\n`;
    if(sm.secrets?.length){r+=`### Secrets (${sm.secrets.length})\n`;sm.secrets.slice(0,v?50:20).forEach(s=>{r+=`- **${s.type}**: \`${s.value}\` — ${s.file}\n`;});r+=`\n`;}
    if(sm.envVars?.length){r+=`### Environment Variables (${sm.envVars.length})\n`;sm.envVars.forEach(e=>{r+=`- \`process.env.${e.name}\` — ${e.file}\n`;});r+=`\n`;}
    if(sm.routes?.length){r+=`### Routes (${sm.routes.length})\n`;sm.routes.forEach(rt=>{r+=`- \`${rt.path}\` — ${rt.file}\n`;});r+=`\n`;}
    if(sm.endpoints?.length){const uniq=[...new Set(sm.endpoints.map(e=>e.path))];r+=`### API Endpoints (${uniq.length})\n\`\`\`\n`;uniq.slice(0,v?100:50).forEach(p=>{r+=`${p}\n`;});r+=`\`\`\`\n\n`;}
    if(sm.dependencies?.length){r+=`### Dependencies (${sm.dependencies.length})\n\`\`\`\n${sm.dependencies.join(", ")}\n\`\`\`\n\n`;}
    if(sm.todos?.length){r+=`### TODO/FIXME (${sm.todos.length})\n`;sm.todos.slice(0,v?30:10).forEach(t=>{r+=`- **${t.marker}** ${t.text.substring(0,150)} — ${t.file}\n`;});r+=`\n`;}
    if(sm.sensitiveFiles?.length){r+=`### Sensitive Paths (${sm.sensitiveFiles.length})\n`;sm.sensitiveFiles.forEach(f=>{r+=`- \`${f}\`\n`;});r+=`\n`;}
  });
}
// v5.6: GraphQL operations (passive — reconstructed from captured POST bodies)
if(D.graphqlOps?.length){
  const queries=D.graphqlOps.filter(o=>o.type==="query");
  const mutations=D.graphqlOps.filter(o=>o.type==="mutation");
  const subs=D.graphqlOps.filter(o=>o.type==="subscription");
  r+=`## 🧬 GraphQL Operations (${D.graphqlOps.length} — ${queries.length}Q / ${mutations.length}M / ${subs.length}S) [PASSIVE]\n`;
  r+=`Reconstructed from captured POST bodies. Mutations are highest priority for auth/CSRF/IDOR testing.\n\n`;
  if(mutations.length){
    r+=`### Mutations (${mutations.length})\n`;
    mutations.slice(0,v?Infinity:30).forEach(op=>{
      r+=`- **${op.name}**`;
      if(op.variables?.length)r+=` — vars: \`${op.variables.join(", ")}\``;
      if(op.fields?.length)r+=` — fields: \`${op.fields.slice(0,10).join(", ")}\``;
      if(op.path)r+=` — ${op.path}`;
      r+=`\n`;
    });
    r+=`\n`;
  }
  if(queries.length){
    r+=`### Queries (${queries.length})\n`;
    queries.slice(0,v?Infinity:30).forEach(op=>{
      r+=`- **${op.name}**`;
      if(op.variables?.length)r+=` — vars: \`${op.variables.join(", ")}\``;
      if(op.fields?.length)r+=` — fields: \`${op.fields.slice(0,10).join(", ")}\``;
      r+=`\n`;
    });
    r+=`\n`;
  }
  if(subs.length){
    r+=`### Subscriptions (${subs.length})\n`;
    subs.forEach(op=>r+=`- **${op.name}**${op.fields?.length?` — \`${op.fields.slice(0,10).join(", ")}\``:""}\n`);
    r+=`\n`;
  }
}
// v5.6: Symbol table (pre-minification identifiers)
if(D.symbolTable?.length&&D.symbolTable[0]?.total){
  const st=D.symbolTable[0];
  r+=`## 🔤 Symbol Table (${st.total} identifiers, ${st.interestingCount} interesting)\n`;
  r+=`Pre-minification identifiers extracted from source-map \`names\` arrays.\n\n`;
  if(st.interesting?.length){
    r+=`### Interesting (${st.interesting.length})\n\`\`\`\n`;
    st.interesting.slice(0,v?Infinity:100).forEach(n=>{r+=`${n}\n`;});
    r+=`\`\`\`\n\n`;
  }
  if(v&&st.sample?.length){
    r+=`### Full sample (${st.sample.length})\n\`\`\`\n${st.sample.join(", ")}\n\`\`\`\n\n`;
  }
}
return r;}

// -------------------------------------------------------
// CLAUDE REPORT v5 — uses shared buildReport()
// -------------------------------------------------------
function sendToClaude(){if(!D)return;const r=buildReport({format:"claude"});
navigator.clipboard.writeText(r).then(()=>{
  if(r.length>15000){toast(`Copied! (${Math.round(r.length/1024)}KB — consider Export → Full Report for large scans)`);}
  else{toast("Pentest brief copied!");}
}).catch(()=>{download("penscope-report.md",r,"text/markdown");toast("Downloaded — too large for clipboard");});}

// EXPORTS
function exportData(fmt){if(!D)return;const host=document.getElementById("tgtUrl").textContent.replace(/https?:\/\//,"").split("/")[0]||"target";const tgtUrl=document.getElementById("tgtUrl").textContent||D.url||"?";const hasDeepData=(D.responseBodies?.length||0)+(D.consoleLogs?.length||0)+(D.auditIssues?.length||0)+(D.scriptSources?.length||0)+(D.executionContexts?.length||0)+(D.discoveredRoutes?.length||0)>0;switch(fmt){case"json":download(`penscope_${host}.json`,JSON.stringify(D,null,2),"application/json");toast("Full JSON downloaded");break;
case"report":{
  const r=buildReport({format:"markdown"});
  // all report sections handled by buildReport()
  download(`penscope_${host}_report.md`,r,"text/markdown");
  toast(`Full report downloaded (${Math.round(r.length/1024)}KB)`);
  break;}
case"burp":{let t="";D.endpoints?.forEach(e=>t+=e.url+"\n");
  // v5.1: Include discovered routes in Burp URL list
  if(D.discoveredRoutes?.length){const baseUrl=document.getElementById("tgtUrl").textContent||"";try{const base=new URL(baseUrl);D.discoveredRoutes.forEach(r=>{if(r.path&&r.path.startsWith("/"))t+=`${base.origin}${r.path}\n`;});}catch{}}
  // v5.1: Include active recon findings
  if(D.probeData?.status==="done"){const baseUrl=document.getElementById("tgtUrl").textContent||"";try{const base=new URL(baseUrl);
    (D.probeData.swagger||[]).forEach(sw=>{(sw.paths||[]).forEach(p=>{t+=`${base.origin}${sw.basePath||""}${p.path}\n`;});});
    (D.probeData.probes||[]).filter(p=>p.interesting).forEach(p=>{t+=`${base.origin}${p.path}\n`;});
    (D.probeData.suffixes||[]).forEach(s=>{t+=`${base.origin}${s.path}\n`;});
    (D.probeData.sourceMaps||[]).forEach(sm=>{(sm.endpoints||[]).forEach(ep=>{if(ep.path.startsWith("/"))t+=`${base.origin}${ep.path}\n`;});});
    // Include IDOR-confirmed and auth-broken endpoints
    (D.probeData.idorAutoResults||[]).filter(r=>r.severity==="critical"||r.severity==="high").forEach(r=>{t+=`${base.origin}${r.path}\n`;});
    (D.probeData.authRemovalResults||[]).filter(r=>r.severity==="critical"||r.severity==="high").forEach(r=>{t+=`${base.origin}${r.path}\n`;});
  }catch{}}
  download(`penscope_${host}_urls.txt`,t,"text/plain");break;}case"wordlist":{const w=new Set();(D.params||[]).forEach(p=>w.add(p.param));D.forms?.forEach(f=>f.inputs?.forEach(i=>{if(i.name)w.add(i.name);}));D.hiddenFields?.forEach(f=>{if(f.name&&f.name!=="<!-- -->")w.add(f.name);});download(`penscope_${host}_params.txt`,[...w].sort().join("\n"),"text/plain");break;}case"endpoints":{let t="Method\tStatus\tPath\tHost\tTags\tSize\n";D.endpoints?.forEach(e=>{const tags=(e.tags||[]).map(t=>t.tag).join(",");t+=`${e.method}\t${e.status||""}\t${e.path}${e.query||""}\t${e.host}\t${tags}\t${e.responseSize||""}\n`;});
  // v5.1: Append discovered routes
  if(D.discoveredRoutes?.length){t+=`\n# --- DISCOVERED (not observed in traffic) ---\n`;D.discoveredRoutes.forEach(r=>{t+=`DISCOVERED\t\t${r.path}\t${r.source}\t${r.type}\n`;});}
  download(`penscope_${host}_endpoints.txt`,t,"text/plain");break;}
  case"swagger":{generateSwaggerSpec(host);break;}
  case"sourcemaps":{
    const maps=D.parsedSourceMaps||D.harvestedMaps||[];
    if(!maps.length){toast("No source maps found — enable Deep mode or run Probe");break;}
    const exportData={exportedAt:new Date().toISOString(),target:host,mapCount:maps.length,
      totalFiles:maps.reduce((s,m)=>s+(m.fileCount||0),0),
      totalEndpoints:maps.reduce((s,m)=>s+(m.endpoints||[]).length,0),
      totalSecrets:maps.reduce((s,m)=>s+(m.secrets||[]).length,0),
      totalRoutes:maps.reduce((s,m)=>s+(m.routes||[]).length,0),
      totalEnvVars:maps.reduce((s,m)=>s+(m.envVars||[]).length,0),
      totalDeps:maps.reduce((s,m)=>s+(m.dependencies||[]).length,0),
      maps:maps.map(m=>({url:m.url,source:m.source||"probe",fileCount:m.fileCount,size:m.size,version:m.version,sourceRoot:m.sourceRoot,
        files:m.files||m.sources||[],endpoints:m.endpoints||[],secrets:m.secrets||[],routes:m.routes||[],envVars:m.envVars||[],
        dependencies:m.dependencies||[],todos:m.todos||[],sensitiveFiles:m.sensitiveFiles||[],fileTree:m.fileTree||{}})),
      csvIndex:"URL,Source,Files,Endpoints,Secrets,Routes,EnvVars,Deps\n"+maps.map(m=>`"${(m.url||"").substring(0,200)}","${m.source||""}",${m.fileCount||0},${(m.endpoints||[]).length},${(m.secrets||[]).length},${(m.routes||[]).length},${(m.envVars||[]).length},${(m.dependencies||[]).length}`).join("\n")
    };
    download(`penscope_${host}_sourcemaps.json`,JSON.stringify(exportData,null,2),"application/json");break;}
  case"nuclei":{generateNucleiTemplates(host);break;}
  case"har-import":{openHarImportDialog();break;}
}}

// v5.8: HAR import — load a Burp/ZAP/Chrome DevTools HAR capture and replay it into state so
// PenScope can analyze traffic that was captured elsewhere. Fills endpoints, params, auth headers,
// POST bodies, and response bodies just as if the user had loaded the page in the current tab.
function openHarImportDialog(){
  const input=document.createElement("input");
  input.type="file";
  input.accept=".har,application/json";
  input.onchange=(e)=>{
    const file=e.target.files&&e.target.files[0];
    if(!file){toast("No file selected");return;}
    if(file.size>50*1024*1024){toast("HAR too large (>50MB)");return;}
    const reader=new FileReader();
    reader.onload=(evt)=>{
      try{
        const har=JSON.parse(evt.target.result);
        const entries=har?.log?.entries||[];
        if(!entries.length){toast("HAR has no entries");return;}
        chrome.runtime.sendMessage({action:"importHar",tabId,entries:entries.slice(0,5000)},r=>{
          if(r?.ok){
            toast(`Imported ${r.imported} entries · ${r.endpoints} endpoints, ${r.params} params`);
            setTimeout(load,500);
          }else{
            toast("Import failed: "+(r?.error||"unknown"));
          }
        });
      }catch(err){toast("HAR parse error: "+err.message);}
    };
    reader.onerror=()=>toast("Failed to read file");
    reader.readAsText(file);
  };
  input.click();
}

// v5.8: Nuclei template export — weaponize PenScope findings as YAML templates for continuous
// scanning with ProjectDiscovery's nuclei. Generates one template per class of finding with
// matchers derived from actual observed responses. Output is a multi-document YAML file so it
// can be dropped directly into ~/.config/nuclei/custom/ and scanned with `nuclei -t ./custom/`.
function generateNucleiTemplates(host){
  const tgtUrl=document.getElementById("tgtUrl").textContent||D.url||"";
  let baseUrl="https://"+host;
  try{const u=new URL(tgtUrl);baseUrl=u.origin;}catch(e){}
  const ye=s=>(s||"").toString().replace(/'/g,"''").replace(/[\r\n]/g," ");
  const slug=s=>(s||"").toString().replace(/[^a-z0-9]/gi,"-").replace(/-+/g,"-").replace(/^-|-$/g,"").substring(0,50).toLowerCase()||"finding";
  const docs=[];
  function docHeader(id,name,severity,desc,tags){
    return "id: "+id+"\n"+
      "info:\n"+
      "  name: '"+ye(name)+"'\n"+
      "  author: penscope\n"+
      "  severity: "+severity+"\n"+
      "  description: '"+ye(desc||name)+"'\n"+
      "  tags: "+tags+"\n"+
      "  reference:\n"+
      "    - https://penscope.local/v"+"5.8\n";
  }
  // 1. Broken Access Control hits from the probe
  const bac=(D.probeData?.bacResults||[]).filter(b=>b.vulnerable);
  bac.forEach((b,i)=>{
    docs.push(docHeader("penscope-bac-"+slug(b.path)+"-"+i,"Broken Access Control: "+b.path,"high","Endpoint accepts "+b.method+" without role enforcement (detected by PenScope)","access-control,bac,penscope")+
      "\nhttp:\n"+
      "  - method: "+b.method+"\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(b.path)+"'\n"+
      (["POST","PUT","PATCH"].indexOf(b.method)>-1?"    headers:\n      Content-Type: application/json\n    body: '{}'\n":"")+
      "    matchers-condition: and\n"+
      "    matchers:\n"+
      "      - type: status\n        status:\n          - 200\n          - 201\n          - 204\n"+
      "      - type: word\n        part: body\n        negative: true\n        words:\n          - 'unauthorized'\n          - 'forbidden'\n          - 'login required'\n");
  });
  // 2. Auth Removal — endpoints that return 200 without credentials
  const ar=(D.probeData?.authRemovalResults||[]).filter(r=>r.severity==="critical"||r.severity==="high");
  ar.forEach((r,i)=>{
    docs.push(docHeader("penscope-auth-removal-"+slug(r.path)+"-"+i,"Missing auth enforcement: "+r.path,r.severity,"Endpoint returns same data without any authentication (detected by PenScope)","auth,broken-auth,penscope")+
      "\nhttp:\n"+
      "  - method: "+r.method+"\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(r.path)+"'\n"+
      "    matchers-condition: and\n"+
      "    matchers:\n"+
      "      - type: status\n        status:\n          - 200\n"+
      "      - type: dsl\n        dsl:\n          - 'len(body) > 50'\n");
  });
  // 3. IDOR — auto-test hits that returned critical/high
  const idor=(D.probeData?.idorAutoResults||[]).filter(r=>r.severity==="critical"||r.severity==="high");
  idor.forEach((r,i)=>{
    if(!r.path||r.path.indexOf("GraphQL")>-1)return;
    docs.push(docHeader("penscope-idor-"+slug(r.path)+"-"+i,"IDOR on "+r.path,r.severity,"Path parameter "+r.originalId+" can be substituted with "+r.testedId+" (detected by PenScope)","idor,access-control,penscope")+
      "\nhttp:\n"+
      "  - method: GET\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(String(r.path).replace(r.originalId,r.testedId))+"'\n"+
      "    matchers:\n"+
      "      - type: status\n        status:\n          - 200\n");
  });
  // 4. CORS misconfiguration — reflected origins
  const cors=(D.probeData?.corsResults||[]).filter(c=>c.severity==="critical"||c.severity==="high");
  cors.forEach((c,i)=>{
    docs.push(docHeader("penscope-cors-"+slug(c.path)+"-"+i,"CORS reflection on "+c.path,c.severity,"Origin "+c.origin+" reflected in ACAO"+(c.acac==="true"?" with credentials":"")+" (detected by PenScope)","cors,penscope")+
      "\nhttp:\n"+
      "  - method: GET\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(c.path)+"'\n"+
      "    headers:\n"+
      "      Origin: '"+ye(c.origin)+"'\n"+
      "    matchers:\n"+
      "      - type: word\n        part: header\n        words:\n          - 'Access-Control-Allow-Origin: "+ye(c.origin)+"'\n");
  });
  // 5. Open redirects
  const redir=(D.probeData?.openRedirects||[]);
  redir.forEach((r,i)=>{
    docs.push(docHeader("penscope-open-redirect-"+slug(r.path)+"-"+i,"Open Redirect on "+r.path,r.severity||"high","Parameter "+r.param+" accepts attacker-controlled redirect target (detected by PenScope)","redirect,open-redirect,penscope")+
      "\nhttp:\n"+
      "  - method: GET\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(r.path)+"?"+ye(r.param)+"=https://evil.com'\n"+
      "    matchers:\n"+
      "      - type: regex\n        part: header\n        regex:\n          - 'Location: https?://evil\\.com'\n");
  });
  // 6. Missing CSRF on state-changing endpoints
  const csrf=(D.probeData?.csrfResults||[]).filter(r=>r.severity==="critical"||r.severity==="high");
  csrf.forEach((r,i)=>{
    docs.push(docHeader("penscope-csrf-"+slug(r.path)+"-"+i,"Missing CSRF on "+r.path,r.severity,r.note||"State-changing endpoint lacks CSRF token validation","csrf,penscope")+
      "\nhttp:\n"+
      "  - method: "+r.method+"\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(r.path)+"'\n"+
      "    headers:\n"+
      "      Content-Type: application/json\n"+
      "    body: '{}'\n"+
      "    matchers:\n"+
      "      - type: status\n        status:\n          - 200\n          - 201\n          - 204\n");
  });
  // 7. HTTP method tampering
  const mt=(D.probeData?.methodResults||[]).filter(m=>m.interesting);
  mt.forEach((m,i)=>{
    docs.push(docHeader("penscope-method-override-"+slug(m.path)+"-"+i,"Method tampering on "+m.path,"medium","Endpoint accepts "+m.testedMethod+" when "+m.originalMethod+" was observed","method-override,penscope")+
      "\nhttp:\n"+
      "  - method: "+m.testedMethod+"\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(m.path)+"'\n"+
      "    matchers:\n"+
      "      - type: status\n        status:\n          - 200\n          - 201\n          - 204\n");
  });
  // 8. Exposed secrets from recursive probe findings — turned into simple word-match templates
  const secrets=(D.secrets||[]).filter(s=>(s.severity==="critical"||s.severity==="high")&&s.source&&s.source.indexOf("recursive:")===0);
  secrets.slice(0,30).forEach((s,i)=>{
    const path=s.source.substring(10);
    if(!path||path.charAt(0)!=="/")return;
    docs.push(docHeader("penscope-secret-"+slug(s.type)+"-"+i,"Secret exposure ("+s.type+") on "+path,s.severity,"Response body contains a "+s.type+" matching PenScope pattern","secret-exposure,sensitive-data,penscope")+
      "\nhttp:\n"+
      "  - method: GET\n"+
      "    path:\n"+
      "      - '{{BaseURL}}"+ye(path)+"'\n"+
      "    matchers:\n"+
      "      - type: word\n        part: body\n        words:\n          - '"+ye(s.type.toLowerCase().split(" ")[0])+"'\n");
  });
  if(!docs.length){
    toast("No actionable findings to export as Nuclei templates");
    return;
  }
  // Multi-document YAML: separate with ---
  const yaml="# PenScope v5.8 — Nuclei templates auto-generated from scan of "+host+"\n"+
    "# Generated: "+new Date().toISOString()+"\n"+
    "# Total templates: "+docs.length+"\n"+
    "# Usage: nuclei -u "+baseUrl+" -t ./penscope_"+host+"_nuclei.yaml\n\n"+
    docs.join("\n---\n\n");
  download("penscope_"+host+"_nuclei.yaml",yaml,"text/yaml");
  toast("Generated "+docs.length+" Nuclei templates");
}
function download(n,c,t){const b=new Blob([c],{type:t}),u=URL.createObjectURL(b),a=document.createElement("a");a.href=u;a.download=n;a.style.display="none";document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(u);document.body.removeChild(a);},500);}
function generateSwaggerSpec(host){
  const tgtUrl=document.getElementById("tgtUrl").textContent||D.url||"";
  let baseUrl="";
  try{const u=new URL(tgtUrl);baseUrl=u.origin;}catch{baseUrl="https://"+host;}
  
  const methodPatterns=[
    {re:/^(?:Get|Fetch|List|Search|Find|Load|Read|Check|Allow|Is|Has|Count)/i,method:"get"},
    {re:/^(?:Add|Create|Insert|New|Register|Submit|Save|Send|Upload|Generate|Book|Activate|Approve)/i,method:"post"},
    {re:/^(?:Update|Edit|Modify|Change|Set|Replace|Patch|Rename|Mark|Pin|UnPin)/i,method:"put"},
    {re:/^(?:Delete|Remove|Destroy|Purge|Revoke|Deactivate|Cancel|Reject|Ban)/i,method:"delete"},
  ];
  
  const tagPatterns=[
    {re:/\/api\/(\w+Api)\//,extract:1},
    {re:/\/api\/(\w+)\//,extract:1},
    {re:/\/api\/v\d+\/(\w+)/,extract:1},
  ];
  
  function inferMethod(path){
    const lastSeg=path.split("/").pop()||"";
    for(const p of methodPatterns){if(p.re.test(lastSeg))return p.method;}
    if(/\?/.test(path))return "get";
    return "get";
  }
  
  function inferTag(path){
    for(const p of tagPatterns){const m=path.match(p.re);if(m)return m[p.extract];}
    return "default";
  }
  
  function inferParams(path){
    const params=[];
    const cleanPath=path.split("?")[0];
    const query=path.includes("?")?path.split("?")[1]:"";
    // Path params from :param or {param} patterns
    const pathParams=cleanPath.match(/[:{}](\w+)/g);
    if(pathParams)pathParams.forEach(p=>{
      const name=p.replace(/[:{}]/g,"");
      params.push({in:"path",name,required:true,schema:{type:name.toLowerCase().includes("id")?"integer":"string"},example:name.toLowerCase().includes("id")?"1":name});
    });
    // Query params from known patterns
    if(query){query.split("&").forEach(q=>{
      const[k,v]=q.split("=");
      if(k)params.push({in:"query",name:k,required:false,schema:{type:v&&/^\d+$/.test(v)?"integer":"string"},example:v||""});
    });}
    // If path ends with numeric-looking segment, add id param
    const segs=cleanPath.split("/");
    const lastSeg=segs[segs.length-1];
    if(/^\d+$/.test(lastSeg)){
      segs[segs.length-1]="{id}";
      params.push({in:"path",name:"id",required:true,schema:{type:"integer"},example:lastSeg});
    }
    return {cleanPath:segs.join("/"),params};
  }
  
  function inferRequestBody(method,path){
    if(method==="get"||method==="delete")return null;
    const lastSeg=(path.split("?")[0].split("/").pop()||"").toLowerCase();
    const props={};
    // Infer fields from endpoint name
    if(/user|profile|account/i.test(lastSeg)){props.userId={type:"string"};props.email={type:"string"};}
    if(/course/i.test(lastSeg)){props.courseId={type:"string"};props.title={type:"string"};}
    if(/session/i.test(lastSeg)){props.sessionId={type:"string"};}
    if(/survey|question/i.test(lastSeg)){props.surveyId={type:"string"};}
    if(/assessment|grade/i.test(lastSeg)){props.assessmentId={type:"string"};props.score={type:"number"};}
    if(/announcement|post|comment/i.test(lastSeg)){props.content={type:"string"};props.title={type:"string"};}
    if(/file|upload/i.test(lastSeg)){props.file={type:"string",format:"binary"};}
    if(/badge/i.test(lastSeg)){props.badgeId={type:"string"};props.userId={type:"string"};}
    if(/invitation/i.test(lastSeg)){props.invitationId={type:"string"};}
    if(Object.keys(props).length===0){props.id={type:"string"};}
    return {required:true,content:{"application/json":{schema:{type:"object",properties:props}}}};
  }
  
  // Collect all routes
  const allRoutes=new Set();
  const routeMeta={};
  const staticAssetRe=/\.(?:js|css|png|jpg|svg|woff|ico|map)(?:\?|$)/i;

  // From discovered routes
  (D.discoveredRoutes||[]).forEach(r=>{
    if(!r.path||!r.path.startsWith("/")||staticAssetRe.test(r.path))return;
    allRoutes.add(r.path);
    routeMeta[r.path]={source:"discovered",intent:r.intent||"unknown"};
  });

  // From observed endpoints
  (D.endpoints||[]).forEach(e=>{
    if(!e.path||!e.path.startsWith("/")||staticAssetRe.test(e.path))return;
    const full=e.path+(e.query||"");
    allRoutes.add(full);
    if(!routeMeta[full])routeMeta[full]={source:"observed",status:e.status,method:e.method?.toLowerCase()};
    else{routeMeta[full].status=e.status;routeMeta[full].observedMethod=e.method?.toLowerCase();}
  });

  // From script source endpoints
  (D.scriptSources||[]).forEach(s=>{
    if(s.type==="api-endpoint"&&s.path?.startsWith("/")&&!staticAssetRe.test(s.path)){
      allRoutes.add(s.path);
      if(!routeMeta[s.path])routeMeta[s.path]={source:"script"};
    }
  });
  
  // Build paths object
  const paths={};
  const tags=new Set();
  
  [...allRoutes].sort().forEach(route=>{
    const meta=routeMeta[route]||{};
    const method=meta.observedMethod||inferMethod(route);
    const tag=inferTag(route);
    tags.add(tag);
    const {cleanPath,params}=inferParams(route);
    const pathKey=cleanPath.split("?")[0];
    
    if(!paths[pathKey])paths[pathKey]={};
    
    const lastSeg=pathKey.split("/").pop()||"";
    const opId=tag.replace(/Api$/,"")+"_"+lastSeg;
    
    const operation={
      tags:[tag],
      operationId:opId,
      summary:lastSeg.replace(/([A-Z])/g," $1").trim(),
    };
    
    if(meta.source)operation["x-penscope-source"]=meta.source;
    if(meta.intent)operation["x-penscope-intent"]=meta.intent;
    if(meta.status)operation["x-observed-status"]=meta.status;
    if(params.length)operation.parameters=params;
    
    const body=inferRequestBody(method,route);
    if(body)operation.requestBody=body;
    
    operation.responses={"200":{description:"Success"},"401":{description:"Unauthorized"},"403":{description:"Forbidden"},"404":{description:"Not Found"}};
    
    paths[pathKey][method]=operation;
  });
  
  // Build YAML manually (no library needed)
  const yesc=s=>(s||"").replace(/'/g,"''");
  let yaml="openapi: '3.0.3'\n";
  yaml+="info:\n";
  yaml+=`  title: '${yesc(host)} — PenScope Reconstructed API'\n`;
  yaml+=`  description: '${yesc("Auto-generated from "+allRoutes.size+" discovered endpoints by PenScope v5.8. NOT an official spec — reconstructed from client-side JavaScript analysis.")}'\n`;
  yaml+="  version: 'penscope-recon'\n";
  yaml+=`  x-generated-at: '${yesc(new Date().toISOString())}'\n`;
  yaml+=`  x-generated-by: 'PenScope v5.8'\n`;
  yaml+=`  x-total-routes: ${allRoutes.size}\n`;
  yaml+="servers:\n";
  yaml+=`  - url: '${yesc(baseUrl)}'\n`;
  yaml+=`    description: 'Target'\n`;
  yaml+="tags:\n";
  [...tags].sort().forEach(t=>{yaml+=`  - name: '${yesc(t)}'\n`;});
  yaml+="paths:\n";
  
  Object.keys(paths).sort().forEach(path=>{
    yaml+=`  '${yesc(path)}':\n`;
    Object.keys(paths[path]).forEach(method=>{
      const op=paths[path][method];
      yaml+=`    ${method}:\n`;
      yaml+=`      tags:\n        - '${yesc(op.tags[0])}'\n`;
      yaml+=`      operationId: '${yesc(op.operationId)}'\n`;
      yaml+=`      summary: '${yesc(op.summary)}'\n`;
      if(op["x-penscope-source"])yaml+=`      x-penscope-source: '${yesc(op["x-penscope-source"])}'\n`;
      if(op["x-penscope-intent"])yaml+=`      x-penscope-intent: '${yesc(op["x-penscope-intent"])}'\n`;
      if(op["x-observed-status"])yaml+=`      x-observed-status: ${op["x-observed-status"]}\n`;
      if(op.parameters?.length){
        yaml+=`      parameters:\n`;
        op.parameters.forEach(p=>{
          yaml+=`        - in: '${yesc(p.in)}'\n          name: '${yesc(p.name)}'\n          required: ${p.required}\n          schema:\n            type: '${yesc(p.schema.type)}'\n`;
          if(p.example)yaml+=`          example: '${yesc(p.example)}'\n`;
        });
      }
      if(op.requestBody){
        yaml+=`      requestBody:\n        required: true\n        content:\n          application/json:\n            schema:\n              type: object\n              properties:\n`;
        const props=op.requestBody.content["application/json"].schema.properties;
        Object.keys(props).forEach(k=>{
          yaml+=`                ${yesc(k)}:\n                  type: '${yesc(props[k].type)}'\n`;
          if(props[k].format)yaml+=`                  format: '${yesc(props[k].format)}'\n`;
        });
      }
      yaml+=`      responses:\n`;
      Object.keys(op.responses).forEach(code=>{
        yaml+=`        '${yesc(code)}':\n          description: '${yesc(op.responses[code].description)}'\n`;
      });
    });
  });
  
  // Security schemes
  yaml+=`security:\n  - cookieAuth: []\ncomponents:\n  securitySchemes:\n    cookieAuth:\n      type: apiKey\n      in: cookie\n      name: '.AspNet.Cookies'\n    xsrfToken:\n      type: apiKey\n      in: header\n      name: 'X-XSRF-TOKEN'\n`;
  
  download(`penscope_${host}_swagger.yaml`,yaml,"text/yaml");
  toast(`Swagger spec: ${allRoutes.size} routes → ${Object.keys(paths).length} paths exported`);
}
function copy(t){navigator.clipboard.writeText(t).then(()=>toast("Copied!"));}
function toast(m){const e=document.getElementById("toast");e.textContent=m;e.style.display="block";setTimeout(()=>e.style.display="none",1800);}
function empty(i,t){return`<div class="empty"><div class="empty-i">${i}</div><div class="empty-t">${t}</div></div>`;}
function esc(s){return(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function escA(s){return(s||"").replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/'/g,"&#39;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
// -------------------------------------------------------
// v5.2: SOURCE MAP SCANNER
// -------------------------------------------------------
let _smapResults=[];

function startSourceMapScan(){
  const overlay=document.getElementById("smapOverlay");
  const status=document.getElementById("smapStatus");
  const results=document.getElementById("smapResults");
  const dlAllBtn=document.getElementById("smapDownloadAll");
  overlay.classList.add("show");
  status.textContent="Scanning for source map files...";
  results.innerHTML="";
  dlAllBtn.style.display="none";
  _smapResults=[];

  chrome.runtime.sendMessage({action:"scanSourceMaps",tabId},r=>{
    if(!r||!r.ok){
      status.textContent="Error: "+(r?.error||"scan failed");
      return;
    }
    const all=r.results||[];
    if(!all.length&&r.skipped){
      status.textContent=`No source maps found for ${r.targetDomain||"target"}. ${r.skipped} third-party CDN URLs filtered out.`;
      return;
    }
    if(!all.length){
      status.textContent="No script source map URLs found on this page.";
      return;
    }
    const found=all.filter(x=>x.status===200);
    const notFound=all.filter(x=>x.status!==200&&x.status!==0);
    const errors=all.filter(x=>x.status===0);
    _smapResults=found;

    status.textContent=`Found ${found.length} source maps out of ${all.length} URLs on ${r.targetDomain||"target"}${r.skipped?" ("+r.skipped+" CDN filtered)":""}${errors.length?" ("+errors.length+" errors)":""}`;
    let h="";
    // Show found maps first, sorted by size (biggest first)
    found.sort((a,b)=>(b.size||0)-(a.size||0));
    found.forEach((m,i)=>{
      const fname=(m.url||"").split("/").pop()||"source.map";
      const sizeStr=m.size>0?(m.size>1048576?Math.round(m.size/1048576*10)/10+"MB":m.size>1024?Math.round(m.size/1024)+"KB":m.size+"B"):"unknown size";
      const sizeColor=m.size>100000?"var(--green)":m.size>10000?"var(--yellow)":"var(--t3)";
      h+=`<div class="smap-row">`;
      h+=`<span class="smap-status" style="background:rgba(58,255,138,.1);color:var(--green)">200</span>`;
      h+=`<span class="smap-url" title="${escA(m.url)}">${esc(fname)}</span>`;
      h+=`<span style="color:${sizeColor};font-size:9px;font-weight:600;min-width:50px;text-align:right">${sizeStr}</span>`;
      h+=`<button class="smap-dl" data-dlmap="${escA(m.url)}" data-dlfname="${escA(fname)}">Download</button>`;
      h+=`</div>`;
    });
    // Show 404s collapsed
    if(notFound.length){
      h+=`<div style="margin-top:8px;padding:6px 8px;font-size:10px;color:var(--t3);cursor:pointer" data-toggle="next">▸ ${notFound.length} not found (404) — click to expand</div>`;
      h+=`<div style="display:none">`;
      notFound.forEach(m=>{
        const fname=(m.url||"").split("/").pop()||"?";
        h+=`<div class="smap-row" style="opacity:.4">`;
        h+=`<span class="smap-status" style="background:rgba(255,70,102,.1);color:var(--red)">${m.status}</span>`;
        h+=`<span class="smap-url" title="${escA(m.url)}">${esc(fname)}</span>`;
        h+=`</div>`;
      });
      h+=`</div>`;
    }

    results.innerHTML=h;
    if(found.length>0)dlAllBtn.style.display="inline-flex";
  });
}

function downloadSourceMap(url,filename){
  chrome.runtime.sendMessage({action:"downloadSourceMap",tabId,url},r=>{
    if(!r||!r.ok){toast("Failed to download: "+(r?.error||r?.status||"?"));return;}
    download(filename,r.body,"application/json");
    toast("Downloaded "+filename);
  });
}

function downloadAllSourceMaps(){
  if(!_smapResults.length)return;
  const btn=document.getElementById("smapDownloadAll");
  btn.textContent="Downloading...";
  let completed=0;
  const total=_smapResults.length;

  _smapResults.forEach(m=>{
    const fname=(m.url||"").split("/").pop()||"source.map";
    chrome.runtime.sendMessage({action:"downloadSourceMap",tabId,url:m.url},r=>{
      completed++;
      if(r&&r.ok)download(fname,r.body,"application/json");
      if(completed>=total){
        btn.textContent=`📥 Downloaded ${total} files`;
        toast(`Downloaded ${total} source maps`);
      }
    });
  });
}

// -------------------------------------------------------
// v5.3: BLOB DECODER
// -------------------------------------------------------
function decodeBlob(idx,type){
  if(!D||!D.encodedBlobs||!D.encodedBlobs[idx])return;
  const blob=D.encodedBlobs[idx];
  const el=document.getElementById("decoded-"+idx);
  if(!el)return;
  if(el.style.display!=="none"){el.style.display="none";return;}
  let decoded="";
  try{
    if(type.startsWith("base64")){
      const raw=atob(blob.value);
      if(type==="base64-binary"){
        let hex="";
        for(let i=0;i<Math.min(raw.length,256);i++){
          hex+=("0"+raw.charCodeAt(i).toString(16)).slice(-2)+" ";
          if((i+1)%16===0)hex+="\n";
        }
        decoded="=== HEX DUMP ("+raw.length+" bytes) ===\n"+hex;
        if(raw.length>256)decoded+="\n... +"+(raw.length-256)+" more bytes";
      }else if(type==="base64-json"){
        try{decoded=JSON.stringify(JSON.parse(raw),null,2);}
        catch(e){decoded=raw;}
      }else{decoded=raw;}
    }
    else if(type==="jwt"||type==="jwt-malformed"){
      const parts=blob.value.split(".");
      const header=JSON.parse(atob(parts[0].replace(/-/g,"+").replace(/_/g,"/")));
      const payload=JSON.parse(atob(parts[1].replace(/-/g,"+").replace(/_/g,"/")));
      decoded="=== JWT HEADER ===\n"+JSON.stringify(header,null,2)+"\n\n=== JWT PAYLOAD ===\n"+JSON.stringify(payload,null,2);
      if(payload.exp){const d=new Date(payload.exp*1000);decoded+="\n\nExpires: "+d.toISOString()+(d<new Date()?" (EXPIRED)":" (VALID)");}
      if(payload.iat){decoded+="\nIssued: "+new Date(payload.iat*1000).toISOString();}
      if(header.alg==="none"||header.alg==="HS256")decoded+="\n\n⚠️ WEAK ALGORITHM: "+header.alg;
    }
    else if(type.startsWith("url-encoded")||type.startsWith("double-url")){
      decoded=decodeURIComponent(blob.value);
      if(/%[0-9A-Fa-f]{2}/.test(decoded))decoded="=== FIRST DECODE ===\n"+decoded+"\n\n=== SECOND DECODE ===\n"+decodeURIComponent(decoded);
    }
    else if(type.startsWith("hex")){
      const clean=blob.value.replace(/^0x/,"");
      let ascii="";
      for(let i=0;i<Math.min(clean.length,500);i+=2)ascii+=String.fromCharCode(parseInt(clean.substr(i,2),16));
      decoded=ascii;
    }
    else{decoded="[Cannot decode — type: "+type+"]";}
  }catch(e){decoded="[Decode error: "+e.message+"]";}
  el.textContent=decoded||"[empty]";
  el.style.display="block";
}
