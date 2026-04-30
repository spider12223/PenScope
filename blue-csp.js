// PenScope v6.0 — Observed-Traffic CSP Generator (reference copy)
//
// Builds a Content-Security-Policy header from the data engine's observed sources.
// "Observed" is the load-bearing word: every src in the policy was actually requested
// by this page, so the policy will not break the page if applied.
//
// The live copy is inlined into popup.js (generateTightCSP). Treat this file as
// canonical; update both when changing the algorithm.
//
// Output:
//   {
//     header:    string — full single-line CSP value
//     directives: { 'script-src': [...], 'style-src': [...], ... }
//     warnings:   string[] — any unsafe sources we had to keep (inline scripts, eval)
//     diff:       { tightened:[], loosened:[], same:[], added:[] } when oldCsp present
//   }

function generateTightCSP(tabData,oldCsp){
  // Build a target-origin reference so same-origin sources collapse to 'self'
  let origin="";try{if(tabData&&tabData.url)origin=new URL(tabData.url).origin;}catch(e){}
  function srcOf(url){
    try{
      const u=new URL(url);
      if(origin&&u.origin===origin)return "'self'";
      return u.origin;
    }catch(e){return null;}
  }

  // CSP directives we'll fill from observed traffic. Sets dedupe automatically.
  const D={
    "default-src":new Set(["'none'"]),
    "script-src":new Set(),
    "style-src":new Set(),
    "img-src":new Set(),
    "font-src":new Set(),
    "connect-src":new Set(),
    "frame-src":new Set(),
    "media-src":new Set(),
    "manifest-src":new Set(),
    "worker-src":new Set(),
    "frame-ancestors":new Set(["'none'"]),
    "base-uri":new Set(["'self'"]),
    "form-action":new Set(["'self'"]),
  };
  const warnings=[];

  // Map endpoint resource type → CSP directive(s)
  const TYPE_MAP={
    "script":["script-src"],
    "stylesheet":["style-src"],
    "image":["img-src"],
    "font":["font-src"],
    "xhr":["connect-src"],
    "fetch":["connect-src"],
    "websocket":["connect-src"],
    "iframe":["frame-src"],
    "media":["media-src"],
    "manifest":["manifest-src"],
    "worker":["worker-src","script-src"],
  };

  (tabData.endpoints||[]).forEach(e=>{
    if(!e||!e.url)return;
    const dirs=TYPE_MAP[String(e.type||"").toLowerCase()];
    if(!dirs)return;
    const s=srcOf(e.url);
    if(!s)return;
    dirs.forEach(d=>D[d].add(s));
  });

  // Iframes from content-script scan
  (tabData.iframeScan||[]).forEach(i=>{
    if(!i||!i.url)return;
    const s=srcOf(i.url);if(s)D["frame-src"].add(s);
  });

  // WebSocket connections — connect-src
  (tabData.wsConnections||[]).forEach(w=>{
    if(!w||!w.url)return;
    try{const u=new URL(w.url);D["connect-src"].add(u.origin);}catch(e){}
  });

  // Inline-script detection. The runtime extractor + content script flag any <script>
  // without a src as inline. If found, `'unsafe-inline'` must be allowed in script-src
  // — but we surface a warning so the user knows this loosens the policy.
  const scriptSources=tabData.scriptSources||[];
  const hasInlineScript=scriptSources.some(s=>s&&s.scriptUrl&&/^inline-script/i.test(s.scriptUrl));
  if(hasInlineScript){
    D["script-src"].add("'unsafe-inline'");
    warnings.push("Inline <script> tags detected — kept 'unsafe-inline' in script-src. Consider migrating to nonces or hashes for a tighter policy.");
  }

  // eval() detection. PenScope's source-map analysis surfaces eval-using scripts.
  const hasEval=scriptSources.some(s=>s&&s.pattern&&/eval|new Function/i.test(s.pattern));
  if(hasEval){
    D["script-src"].add("'unsafe-eval'");
    warnings.push("eval()/new Function() usage detected — kept 'unsafe-eval' in script-src. Replace with safer alternatives where possible.");
  }

  // Default to 'self' for anything that has zero observed sources but is required for
  // common use (otherwise default-src 'none' would block them entirely).
  ["script-src","style-src","img-src","font-src","connect-src"].forEach(d=>{
    if(D[d].size===0)D[d].add("'self'");
  });

  // Allow inline data: URIs for images (very common, low risk).
  if(D["img-src"].size)D["img-src"].add("data:");

  // Build the final header. Order matters for readability, not security.
  const order=["default-src","script-src","style-src","img-src","font-src","connect-src","frame-src","media-src","manifest-src","worker-src","frame-ancestors","base-uri","form-action"];
  const parts=[];
  order.forEach(d=>{
    if(D[d].size===0)return;
    parts.push(d+" "+[...D[d]].join(" "));
  });
  parts.push("upgrade-insecure-requests");
  const header=parts.join("; ");

  // Diff against the old CSP if present. We compare per-directive: each directive in
  // oldCsp is parsed; "tightened" means we have FEWER sources than the old CSP for
  // that directive; "loosened" means MORE; "same" means identical sets; "added" means
  // we added a new directive not present before.
  let diff=null;
  if(oldCsp&&typeof oldCsp==="string"){
    const oldD=parseCspString(oldCsp);
    diff={tightened:[],loosened:[],same:[],added:[]};
    Object.keys(D).forEach(d=>{
      const newSet=[...D[d]].sort();
      const oldSet=oldD[d]?[...oldD[d]].sort():null;
      if(!oldSet){diff.added.push({directive:d,sources:newSet});return;}
      if(JSON.stringify(newSet)===JSON.stringify(oldSet)){diff.same.push({directive:d,sources:newSet});return;}
      if(newSet.length<oldSet.length)diff.tightened.push({directive:d,from:oldSet,to:newSet});
      else if(newSet.length>oldSet.length)diff.loosened.push({directive:d,from:oldSet,to:newSet});
      else diff.tightened.push({directive:d,from:oldSet,to:newSet});// same count, different content — treat as a change (could be tighter or wider, user decides)
    });
  }

  return {header,directives:Object.fromEntries(Object.entries(D).map(([k,v])=>[k,[...v]])),warnings,diff};
}

// Tolerant CSP parser. Splits on ; , per-directive splits on whitespace. Returns
// a {directive: Set<source>} map. Tolerates leading/trailing whitespace and quoted vs
// unquoted keywords.
function parseCspString(csp){
  const out={};
  if(!csp||typeof csp!=="string")return out;
  csp.split(";").forEach(part=>{
    const p=part.trim();if(!p)return;
    const tokens=p.split(/\s+/);
    const dir=tokens.shift().toLowerCase();
    if(!dir)return;
    out[dir]=new Set(tokens);
  });
  return out;
}

if(typeof module!=='undefined'&&module.exports){module.exports={generateTightCSP,parseCspString};}
if(typeof globalThis!=='undefined'){globalThis.PENSCOPE_CSP_GEN=generateTightCSP;}
