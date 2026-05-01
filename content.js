// PenScope v5.9 — Content Script
// 60+ secret patterns, 80+ tech fingerprints, 11 contextual scanners:
//   Path param extraction, mixed content, SRI check,
//   postMessage listeners, dependency versions, web workers,
//   DOM XSS sinks, JSONP detection, cookie value scan,
//   recon file suggestions, HTTP method suggestions,
//   WebAuthn/FIDO2, WebRTC leaks, WASM modules, COOP/COEP
(() => {

// ============================================================
// CONFIGURATION CONSTANTS
// ============================================================
const PS_CONFIG = {
  HTML_SCAN_LIMIT: 200000,
  STORAGE_ITEM_LIMIT: 100,
  COMMENT_LIMIT: 50,
  INITIAL_SCAN_DELAY: 1500,
  // v6.1.1 — Performance: bumped debounce 3000 → 5000ms. On YouTube/Twitch/etc.
  // the DOM mutates constantly (live comments, autoplay, timer ticks) and any
  // shorter window means runFullScan fires every few seconds, walking thousands of
  // nodes and tanking the renderer. The MIN_SCAN_INTERVAL is a hard floor — even if
  // mutations keep streaming in, we never scan more than once per 15s.
  MUTATION_DEBOUNCE: 5000,
  MIN_SCAN_INTERVAL: 15000,
  SECRET_MATCH_LIMIT: 5,
  INLINE_TEXT_LIMIT: 100000,
  XSS_MATCH_LIMIT: 3,
  PERF_ENTRY_LIMIT: 500,
  ELEMENT_SAMPLE_SIZE: 50,
};

function semverCompare(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0, nb = pb[i] || 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

// ============================================================
// SECRET PATTERNS (60+)
// ============================================================
const SECRETS = [
  {name:"AWS Access Key",regex:/AKIA[0-9A-Z]{16}/g,sev:"critical"},
  {name:"AWS Secret Key",regex:/(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,sev:"critical"},
  {name:"AWS ARN",regex:/arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/_-]+/g,sev:"medium"},
  {name:"Google API Key",regex:/AIza[0-9A-Za-z_-]{35}/g,sev:"high"},
  {name:"Google OAuth ID",regex:/[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,sev:"high"},
  {name:"Google OAuth Secret",regex:/GOCSPX-[A-Za-z0-9_-]{28}/g,sev:"critical"},
  {name:"Firebase Config",regex:/firebaseConfig\s*=\s*\{[^}]+\}/gs,sev:"medium"},
  {name:"Firebase URL",regex:/https:\/\/[a-z0-9-]+\.firebaseio\.com/g,sev:"medium"},
  {name:"Slack Token",regex:/xox[bpors]-[0-9A-Za-z-]{10,}/g,sev:"critical"},
  {name:"Slack Webhook",regex:/https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,sev:"high"},
  {name:"GitHub Token",regex:/gh[ps]_[A-Za-z0-9_]{36,}/g,sev:"critical"},
  {name:"GitHub Fine-grained",regex:/github_pat_[A-Za-z0-9_]{22,}/g,sev:"critical"},
  {name:"GitLab Token",regex:/glpat-[A-Za-z0-9_-]{20,}/g,sev:"critical"},
  {name:"Azure Key",regex:/(?:AccountKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/=]{40,})/g,sev:"critical"},
  {name:"Azure SAS",regex:/(?:sv=\d{4}-\d{2}-\d{2}&[^'"\s]{20,}|sig=[A-Za-z0-9%+/=]{20,})/g,sev:"high"},
  {name:"DigitalOcean Token",regex:/dop_v1_[a-f0-9]{64}/g,sev:"critical"},
  {name:"Cloudflare Token",regex:/v1\.0-[a-f0-9]{40}/g,sev:"critical"},
  {name:"Stripe Key",regex:/(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g,sev:"critical"},
  {name:"Square Token",regex:/sq0atp-[A-Za-z0-9_-]{22,}/g,sev:"critical"},
  {name:"PayPal Braintree",regex:/access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}/g,sev:"critical"},
  {name:"SendGrid Key",regex:/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,sev:"critical"},
  {name:"Mailgun Key",regex:/key-[0-9a-zA-Z]{32}/g,sev:"high"},
  {name:"Mailchimp Key",regex:/[a-f0-9]{32}-us\d{1,2}/g,sev:"high"},
  {name:"Twilio SID",regex:/AC[a-f0-9]{32}/g,sev:"high"},
  {name:"Telegram Bot",regex:/\d{8,10}:AA[A-Za-z0-9_-]{33,}/g,sev:"critical"},
  {name:"Discord Webhook",regex:/https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g,sev:"high"},
  {name:"Discord Token",regex:/[MN][A-Za-z0-9]{23,}\.[\w-]{6}\.[\w-]{27,}/g,sev:"critical"},
  {name:"Sentry DSN",regex:/https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io\/[0-9]+/g,sev:"medium"},
  {name:"Datadog API",regex:/dd[a-f0-9]{32,}/g,sev:"high"},
  {name:"New Relic Key",regex:/NRAK-[A-Z0-9]{27}/g,sev:"high"},
  {name:"MapBox Token",regex:/pk\.[A-Za-z0-9]{60,}/g,sev:"medium"},
  {name:"Shopify Token",regex:/shpat_[a-fA-F0-9]{32}/g,sev:"critical"},
  {name:"JWT",regex:/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,sev:"high"},
  {name:"Private Key",regex:/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\sBLOCK)?-----/g,sev:"critical"},
  {name:"Bearer Token",regex:/[Bb]earer\s+[A-Za-z0-9_\-./+=]{20,}/g,sev:"high"},
  {name:"Basic Auth",regex:/[Bb]asic\s+[A-Za-z0-9+/=]{15,}/g,sev:"high"},
  {name:"Generic API Key",regex:/(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]?/gi,sev:"high"},
  {name:"Generic Secret",regex:/(?:secret_key|client_secret|app_secret|private_key)\s*[:=]\s*['"]([^'"]{8,64})['"]?/gi,sev:"high"},
  {name:"Generic Password",regex:/(?:password|passwd|pwd|pass)\s*[:=]\s*['"]([^'"]{4,64})['"]?/gi,sev:"high"},
  {name:"Auth Token",regex:/(?:auth_token|access_token|bearer_token|refresh_token)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{16,})['"]?/gi,sev:"high"},
  {name:"MongoDB URI",regex:/mongodb(?:\+srv)?:\/\/[^\s'"<]{10,}/g,sev:"critical"},
  {name:"PostgreSQL URI",regex:/postgres(?:ql)?:\/\/[^\s'"<]{10,}/g,sev:"critical"},
  {name:"MySQL URI",regex:/mysql:\/\/[^\s'"<]{10,}/g,sev:"critical"},
  {name:"Redis URI",regex:/redis(?:s)?:\/\/[^\s'"<]{10,}/g,sev:"critical"},
  {name:"Internal IP",regex:/(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:\/[^\s'"<]*)?/g,sev:"medium"},
  {name:"S3 Bucket",regex:/[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com|s3:\/\/[a-z0-9.-]+/g,sev:"medium"},
  {name:"GCS Bucket",regex:/storage\.googleapis\.com\/[a-z0-9._-]+|gs:\/\/[a-z0-9._-]+/g,sev:"medium"},
  {name:"GraphQL Endpoint",regex:/['"](?:\/graphql|\/gql|\/api\/graphql)['"]/gi,sev:"medium"},
  {name:"Debug Mode",regex:/(?:debug|dev_mode|development|DEBUG|NODE_ENV)\s*[:=]\s*(?:true|1|'true'|"true"|'development'|"development")/gi,sev:"medium"},
  {name:"Hardcoded Email",regex:/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,sev:"info"},
  {name:"Supabase Key",regex:/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,sev:"high"},
  {name:"npm Token",regex:/npm_[A-Za-z0-9]{36}/g,sev:"critical"},
  {name:"OpenAI API Key",regex:/sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/g,sev:"critical",context:"OpenAI GPT API key"},
  {name:"Anthropic API Key",regex:/sk-ant-api03-[a-zA-Z0-9_-]{90,}/g,sev:"critical",context:"Anthropic Claude API key"},
  {name:"Google AI Key",regex:/AIza[A-Za-z0-9_-]{35}/g,sev:"high",context:"Google AI/Maps API key"},
  {name:"HuggingFace Token",regex:/hf_[a-zA-Z0-9]{34,}/g,sev:"high",context:"HuggingFace access token"},
  {name:"Hashicorp Vault Token",regex:/hvs\.[a-zA-Z0-9_-]{24,}/g,sev:"critical",context:"Hashicorp Vault service token"},
];

// ============================================================
// TECH FINGERPRINTS (80+)
// ============================================================
const TECH_FP = [
  {name:"React",check:()=>!!document.querySelector("[data-reactroot],[data-reactid]")||!!window.__REACT_DEVTOOLS_GLOBAL_HOOK__||!!document.getElementById("__next")},
  {name:"Next.js",check:()=>!!document.getElementById("__next")||!!window.__NEXT_DATA__},
  {name:"Nuxt.js",check:()=>!!document.getElementById("__nuxt")||!!window.__NUXT__},
  {name:"Vue.js",check:()=>!!document.querySelector("[data-v-]")||!!window.__VUE__},
  {name:"Angular",check:()=>!!document.querySelector("[ng-version],[_ngcontent],[ng-app],.ng-scope,[ng-controller]")},
  {name:"AngularJS (1.x)",check:()=>!!window.angular},
  {name:"Svelte",check:()=>!!document.querySelector("[class*='svelte-']")},
  {name:"SvelteKit",check:()=>!!document.querySelector('[data-sveltekit-hydrate],[data-sveltekit]')},
  {name:"Solid.js",check:()=>!!document.querySelector("[data-hk]")},
  {name:"Preact",check:()=>!!window.__PREACT_DEVTOOLS__},
  {name:"Ember.js",check:()=>!!window.Ember||!!document.querySelector("[id*='ember'],.ember-view")},
  {name:"Backbone.js",check:()=>!!window.Backbone},
  {name:"Alpine.js",check:()=>!!document.querySelector("[x-data],[x-bind],[x-on]")},
  {name:"HTMX",check:()=>!!document.querySelector("[hx-get],[hx-post],[hx-trigger]")||!!window.htmx},
  {name:"Stimulus",check:()=>!!document.querySelector("[data-controller]")},
  {name:"Turbo",check:()=>!!document.querySelector("turbo-frame,turbo-stream")||!!window.Turbo},
  {name:"Lit",check:()=>!!document.querySelector("[lit-node-index]")},
  {name:"Astro",check:()=>!!document.querySelector("astro-island,[data-astro-cid]")},
  {name:"Remix",check:()=>!!window.__remixContext},
  {name:"Gatsby",check:()=>!!document.getElementById("___gatsby")},
  {name:"jQuery",check:()=>!!window.jQuery||!!window.$?.fn?.jquery},
  {name:"Bootstrap",check:()=>!!document.querySelector('link[href*="bootstrap"],.navbar-toggler,.btn-primary')},
  {name:"Tailwind CSS",check:()=>{const els=document.querySelectorAll('[class]');let twCount=0;for(let i=0;i<Math.min(els.length,PS_CONFIG.ELEMENT_SAMPLE_SIZE);i++){if(/\b(?:flex|grid|p-\d|m-\d|text-\w+-\d|bg-\w+-\d|rounded|shadow|hover:|focus:)\b/.test(els[i].className))twCount++;}return twCount>=3;}},
  {name:"Material UI",check:()=>!!document.querySelector("[class*='MuiButton'],[class*='MuiPaper']")},
  {name:"Ant Design",check:()=>!!document.querySelector("[class*='ant-btn'],[class*='ant-layout']")},
  {name:"WordPress",check:()=>!!document.querySelector('meta[name="generator"][content*="WordPress"],link[href*="wp-content"]')},
  {name:"Drupal",check:()=>!!document.querySelector('meta[name="generator"][content*="Drupal"]')||!!window.Drupal},
  {name:"Shopify",check:()=>!!window.Shopify||!!document.querySelector('[href*="cdn.shopify.com"]')},
  {name:"WooCommerce",check:()=>!!document.querySelector('link[href*="woocommerce"],.woocommerce')},
  {name:"Magento",check:()=>!!document.querySelector('script[src*="mage/"]')},
  {name:"Google Analytics",check:()=>!!window.ga||!!window.gtag||!!window.dataLayer},
  {name:"Google Tag Manager",check:()=>!!window.google_tag_manager},
  {name:"Hotjar",check:()=>!!window.hj||!!window._hjSettings},
  {name:"Mixpanel",check:()=>!!window.mixpanel},
  {name:"Segment",check:()=>!!window.analytics?.identify},
  {name:"Amplitude",check:()=>!!window.amplitude},
  {name:"FullStory",check:()=>!!window.FS||!!window._fs_initialized},
  {name:"PostHog",check:()=>!!window.posthog},
  {name:"Datadog RUM",check:()=>!!window.DD_RUM},
  {name:"New Relic",check:()=>!!window.NREUM||!!window.newrelic},
  {name:"Intercom",check:()=>!!window.Intercom||!!document.getElementById("intercom-frame")},
  {name:"Zendesk",check:()=>!!window.zE||!!document.querySelector('script[src*="zendesk"]')},
  {name:"Crisp",check:()=>!!window.$crisp||!!window.CRISP_WEBSITE_ID},
  {name:"Drift",check:()=>!!window.drift},
  {name:"HubSpot",check:()=>!!window._hsq||!!document.querySelector('script[src*="hubspot"]')},
  {name:"LaunchDarkly",check:()=>!!window.ldclient},
  {name:"Optimizely",check:()=>!!window.optimizely},
  {name:"Webpack",check:()=>!!window.webpackJsonp||!!window.webpackChunk},
  {name:"Vite",check:()=>!!document.querySelector('script[type="module"][src*="@vite"]')},
  {name:"Socket.io",check:()=>!!window.io},
  {name:"Cloudflare",check:()=>!!document.querySelector('script[src*="cloudflare"],script[src*="cf-beacon"]')},
  {name:"reCAPTCHA",check:()=>!!document.querySelector('script[src*="recaptcha"],.g-recaptcha')},
  {name:"hCaptcha",check:()=>!!document.querySelector('script[src*="hcaptcha"],.h-captcha')},
  {name:"Turnstile",check:()=>!!document.querySelector('.cf-turnstile')},
  {name:"Stripe.js",check:()=>!!window.Stripe||!!document.querySelector('script[src*="js.stripe.com"]')},
  {name:"Firebase",check:()=>!!window.firebase||!!document.querySelector('script[src*="firebase"]')},
  {name:"Supabase",check:()=>!!window.supabase},
  {name:"Sentry",check:()=>!!window.__SENTRY__||!!window.Sentry},
  {name:"LogRocket",check:()=>!!window._lr_loaded},
  {name:"Laravel",check:()=>!!document.querySelector('meta[name="csrf-token"]')&&!!document.querySelector('input[name="_token"]')},
  {name:"Django",check:()=>!!document.querySelector('input[name="csrfmiddlewaretoken"]')},
  {name:"Rails",check:()=>!!document.querySelector('meta[name="csrf-param"][content="authenticity_token"]')},
  {name:"ASP.NET",check:()=>!!document.querySelector('input[name="__VIEWSTATE"],input[name="__EVENTVALIDATION"]')},
  {name:"Blazor",check:()=>!!document.querySelector('script[src*="_framework/blazor"]')},
];

const GLOBAL_KEYS=["__NEXT_DATA__","__NUXT__","__INITIAL_STATE__","__PRELOADED_STATE__","__APP_CONFIG__","__CONFIG__","__ENV__","ENV","APP_CONFIG","config","appConfig","settings","featureFlags","__APOLLO_STATE__","__RELAY_STORE__","graphqlEndpoint","API_URL","API_BASE","API_ENDPOINT","BASE_URL","SENTRY_DSN","STRIPE_KEY","FIREBASE_CONFIG","SUPABASE_KEY","__RUNTIME_CONFIG__","__remixContext","process","dataLayer","intercomSettings","DD_RUM","NREUM","amplitude","mixpanel","posthog"];

// ============================================================
// EXISTING SCANNERS (from MAXED)
// ============================================================
// v6.2.2 — Heuristic for benign Azure SAS tokens. Real-world SAS tokens used for
// short-lived read-only media delivery (image/video/font CDN URLs in Azure Blob
// Storage) are NOT vulnerabilities — they're how SAS tokens are designed to work.
// A leak only matters when the SAS is long-lived OR write-capable OR points to
// non-media data. Returns true if the finding looks benign and should be filtered out.
function isBenignAzureSas(value, context){
  const blob = ((value || '') + ' ' + (context || '')).toLowerCase();
  // Read-only check — `sp=r` (or `sp=rl`, `sp=rt`) means the holder can only read.
  const readOnly = /[?&]sp=r[^a-z]|[?&]sp=rl|[?&]sp=rt/.test(blob);
  if (!readOnly) return false;
  // Media file extension immediately before the `?`
  const mediaExt = /\.(?:jpg|jpeg|png|gif|svg|webp|bmp|ico|mp4|m4a|mp3|webm|mov|wav|ogg|flac|woff2?|ttf|otf|eot|pdf|css)\?/.test(blob);
  if (!mediaExt) return false;
  // Time window check — extract `st=...&se=...` and compute duration
  const stMatch = /[?&]st=([0-9t:%a-z\-]+)/i.exec(blob);
  const seMatch = /[?&]se=([0-9t:%a-z\-]+)/i.exec(blob);
  if (stMatch && seMatch) {
    try {
      const st = new Date(decodeURIComponent(stMatch[1])).getTime();
      const se = new Date(decodeURIComponent(seMatch[1])).getTime();
      const hours = (se - st) / 3600000;
      // Less than 7 days = legitimate short-lived delivery URL. Longer = probably a leak.
      if (hours > 0 && hours < 24 * 7) return true;
    } catch (e) { return true; }  // unparseable date — be conservative, treat as benign
  } else {
    // No time bounds and read-only media — still likely benign (just no-expiry CDN)
    return true;
  }
  return false;
}

function scanSecrets(){
  const results=[],seen=new Set(),texts=[];
  document.querySelectorAll("script:not([src])").forEach(s=>{if(s.textContent.trim().length>0)texts.push({source:"inline-script",content:s.textContent});});
  texts.push({source:"page-html",content:(document.body?document.body.innerHTML:"").substring(0,PS_CONFIG.HTML_SCAN_LIMIT)});
  document.querySelectorAll("meta").forEach(m=>{const c=m.getAttribute("content")||"",n=m.getAttribute("name")||m.getAttribute("property")||"";if(c.length>8)texts.push({source:`meta[${n}]`,content:c});});
  document.querySelectorAll("noscript").forEach(ns=>{if(ns.textContent.trim().length>10)texts.push({source:"noscript",content:ns.textContent});});
  document.querySelectorAll("template").forEach(tpl=>{if(tpl.innerHTML.trim().length>10)texts.push({source:"template",content:tpl.innerHTML});});
  texts.forEach(({source,content})=>{
    SECRETS.forEach(pat=>{
      pat.regex.lastIndex=0;
      let match,count=0;
      while((match=pat.regex.exec(content))!==null&&count<PS_CONFIG.SECRET_MATCH_LIMIT){
        count++;
        const val=match[1]||match[0],key=`${pat.name}:${val.substring(0,40)}`;
        if(seen.has(key))continue;
        seen.add(key);
        const s=Math.max(0,match.index-40),e=Math.min(content.length,match.index+match[0].length+40);
        const ctx=content.substring(s,e).replace(/[\n\r]/g," ").substring(0,200);
        // v6.2.2 — Filter benign Azure SAS (short-lived read-only media URLs)
        if(pat.name==="Azure SAS"&&isBenignAzureSas(val,ctx))continue;
        results.push({type:pat.name,value:val.substring(0,150),severity:pat.sev,source,context:ctx});
      }
    });
  });
  return results;
}

function scanDOMElements(){const allElements=document.querySelectorAll("*");const hiddenFields=[];const inlineHandlers=[];const events=["onclick","onmouseover","onerror","onload","onfocus","onblur","onsubmit","onchange","oninput","onkeyup","onkeydown","onkeypress","ondblclick","oncontextmenu","onmouseenter","onmouseleave","ondrag","ondrop","onpaste","oncopy","onmessage"];const skip=["data-reactid","data-react-","data-v-","data-ng-","data-bs-","data-toggle","data-target","data-dismiss","data-slide","data-ride","data-svelte-h","data-astro-cid","data-lit-","data-testid","data-cy","data-qa","data-emotion","data-styled","data-radix","data-reactroot","data-placement","data-original-title"];allElements.forEach(el=>{Array.from(el.attributes).filter(a=>a.name.startsWith("data-")&&a.value&&a.value.length>15).forEach(a=>{if(!skip.some(s=>a.name.startsWith(s))){hiddenFields.push({name:a.name,value:a.value.substring(0,300),element:el.tagName.toLowerCase(),source:"data-attr"});}});events.forEach(attr=>{const val=el.getAttribute(attr);if(val)inlineHandlers.push({event:attr,element:el.tagName.toLowerCase(),code:val.substring(0,200),id:el.id||""});});});return{hiddenFields,inlineHandlers};}

function scanHiddenFields(domScanResults){const fields=[];document.querySelectorAll('input[type="hidden"]').forEach(el=>{fields.push({type:"hidden-input",name:el.name||el.id||"(unnamed)",value:el.value?el.value.substring(0,150):"(empty)",form:el.closest("form")?.action||""});});document.querySelectorAll("input[disabled],input[readonly]").forEach(el=>{if(el.value)fields.push({type:"disabled-input",name:el.name||el.id||"(unnamed)",value:el.value.substring(0,150)});});if(domScanResults){domScanResults.hiddenFields.forEach(f=>{fields.push({type:"data-attribute",name:f.name,value:f.value.substring(0,200),element:`<${f.element}>`});});}const walker=document.createTreeWalker(document.documentElement,NodeFilter.SHOW_COMMENT);let cc=0;while(walker.nextNode()&&cc<PS_CONFIG.COMMENT_LIMIT){const t=walker.currentNode.textContent.trim();if(t.length>3){cc++;fields.push({type:"html-comment",name:"<!-- -->",value:t.substring(0,300)});}}document.querySelectorAll("noscript").forEach(ns=>{const t=ns.textContent.trim();if(t.length>10)fields.push({type:"noscript",name:"<noscript>",value:t.substring(0,200)});});document.querySelectorAll("template").forEach(tpl=>{const h=tpl.innerHTML.trim();if(h.length>10)fields.push({type:"template",name:"<template>",value:h.substring(0,200)});});document.querySelectorAll('input[name="__VIEWSTATE"],input[name="__VIEWSTATEGENERATOR"],input[name="__EVENTVALIDATION"]').forEach(el=>{if(el.value)fields.push({type:"aspnet-state",name:el.name,value:el.value.substring(0,200)});});return fields;}

function scanForms(){const forms=[];document.querySelectorAll("form").forEach((form,idx)=>{const inputs=[];form.querySelectorAll("input,select,textarea").forEach(el=>{inputs.push({tag:el.tagName.toLowerCase(),type:el.type||"text",name:el.name||el.id||"(unnamed)",value:el.type==="hidden"?el.value.substring(0,100):"",required:el.required,autocomplete:el.autocomplete||""});});const csrf=form.querySelector('input[name*="csrf"],input[name*="token"],input[name*="_token"],input[name*="authenticity"],input[name*="__RequestVerification"],input[name*="antiforgery"]');forms.push({index:idx,id:form.id||"",action:form.action||"(none)",method:(form.method||"GET").toUpperCase(),enctype:form.enctype||"",hasCSRF:!!csrf,csrfFieldName:csrf?.name||"",hasFileUpload:!!form.querySelector('input[type="file"]'),hasPasswordField:!!form.querySelector('input[type="password"]'),inputCount:inputs.length,inputs});});return forms;}

function scanTech(){const tech=[];TECH_FP.forEach(fp=>{try{if(fp.check())tech.push({name:fp.name,source:"dom",confidence:"high"});}catch{}});document.querySelectorAll("script[src]").forEach(s=>{const src=s.src.toLowerCase();const m={"react":"React","angular":"Angular","vue":"Vue.js","jquery":"jQuery","lodash":"Lodash","axios":"Axios","socket.io":"Socket.io","d3.js":"D3.js","chart.js":"Chart.js","moment":"Moment.js","leaflet":"Leaflet","highcharts":"Highcharts"};for(const[k,n]of Object.entries(m)){if(src.includes(k)&&!tech.find(t=>t.name===n))tech.push({name:n,source:"script-src",confidence:"medium"});}});document.querySelectorAll('meta[name="generator"]').forEach(m=>{const c=m.getAttribute("content")||"";if(c&&!tech.find(t=>t.name===c.split(" ")[0]))tech.push({name:c,source:"meta-generator",confidence:"high"});});return tech;}

function scanGlobals(){const globals=[],allKeys=new Set(GLOBAL_KEYS);try{Object.keys(window).forEach(key=>{if(/^(?:__[A-Z_]+__|[A-Z][A-Z_]*(?:CONFIG|KEY|SECRET|TOKEN|URL|ENDPOINT|ENV|API|STATE|STORE|DATA|SETTINGS|FLAGS))$/i.test(key))allKeys.add(key);});}catch{}allKeys.forEach(key=>{try{const val=window[key];if(val!==undefined&&val!==null&&!["chrome","document","window","self","top","parent","frames","location","navigator","performance","screen","history","length","name"].includes(key)){let s;try{s=JSON.stringify(val,null,0);}catch{s=String(val);}if(s&&s.length>2&&s.length<50000)globals.push({key,type:typeof val,preview:s.substring(0,800),size:s.length});}}catch{}});return globals;}

function scanStorage(){const d={local:{},session:{}};try{for(let i=0;i<localStorage.length&&i<PS_CONFIG.STORAGE_ITEM_LIMIT;i++){const k=localStorage.key(i);d.local[k]=localStorage.getItem(k)?.substring(0,500)||"";}}catch{}try{for(let i=0;i<sessionStorage.length&&i<PS_CONFIG.STORAGE_ITEM_LIMIT;i++){const k=sessionStorage.key(i);d.session[k]=sessionStorage.getItem(k)?.substring(0,500)||"";}}catch{}return d;}

function scanLinks(){const links=[],seen=new Set();const add=(url,type,text)=>{if(url&&!seen.has(url)&&!url.startsWith("javascript:")&&!url.startsWith("#")&&!url.startsWith("data:")){seen.add(url);try{new URL(url);}catch{try{url=new URL(url,location.href).href;}catch{return;}}try{const u=new URL(url);links.push({url,host:u.hostname,path:u.pathname,type,text:text||""});}catch{}}};document.querySelectorAll("a[href]").forEach(a=>add(a.href,"anchor",a.textContent.trim().substring(0,60)));document.querySelectorAll("script[src]").forEach(s=>add(s.src,"script"));document.querySelectorAll("link[href]").forEach(l=>add(l.href,l.rel||"link"));document.querySelectorAll("img[src]").forEach(i=>add(i.src,"image"));document.querySelectorAll("iframe[src]").forEach(f=>add(f.src,"iframe"));document.querySelectorAll("form[action]").forEach(f=>{if(f.action&&f.action!==window.location.href)add(f.action,"form-action");});return links;}

function scanSourceMaps(){const maps=[],seen=new Set();document.querySelectorAll("script[src]").forEach(s=>{if(s.src&&!seen.has(s.src)){seen.add(s.src);const clean=s.src.split("?")[0];maps.push({url:s.src,mapUrl:clean+".map",source:"script-tag"});}});document.querySelectorAll('link[rel="stylesheet"]').forEach(l=>{if(l.href&&!seen.has(l.href)){seen.add(l.href);const clean=l.href.split("?")[0];maps.push({url:l.href,mapUrl:clean+".map",source:"stylesheet"});}});document.querySelectorAll("script:not([src])").forEach(s=>{const m=(s.textContent||"").match(/\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)/);if(m&&!seen.has(m[1])){seen.add(m[1]);maps.push({url:"inline",mapUrl:m[1],source:"inline-comment"});}});return maps;}

function scanInlineHandlers(domScanResults){const handlers=[];if(domScanResults){domScanResults.inlineHandlers.forEach(h=>{handlers.push({element:`<${h.element}>`,id:h.id||"",event:h.event,handler:h.code});});}document.querySelectorAll('a[href^="javascript:"]').forEach(a=>{handlers.push({element:"<a>",id:a.id||"",event:"href",handler:a.getAttribute("href").substring(0,200)});});return handlers;}

function scanMetaTags(){const tags=[];document.querySelectorAll("meta").forEach(m=>{const n=m.getAttribute("name")||m.getAttribute("property")||m.getAttribute("http-equiv")||"",c=m.getAttribute("content")||"";if(n||c)tags.push({name:n,content:c.substring(0,300)});});return tags;}

function scanServiceWorkers(){const sws=[];try{if("serviceWorker" in navigator&&navigator.serviceWorker.controller)sws.push({url:navigator.serviceWorker.controller.scriptURL,state:navigator.serviceWorker.controller.state});}catch{}document.querySelectorAll("script:not([src])").forEach(s=>{const match=(s.textContent||"").match(/navigator\.serviceWorker\.register\s*\(\s*['"]([^'"]+)['"]/);if(match)sws.push({url:match[1],state:"in-source"});});return sws;}

// ============================================================
// 11 NEW SCANNERS
// ============================================================

// 1. MIXED CONTENT — HTTP resources on HTTPS page
function scanMixedContent(){
  const mixed=[];
  if(location.protocol!=="https:")return mixed;
  const check=(el,attr)=>{const val=el.getAttribute(attr);if(val&&val.startsWith("http://"))mixed.push({element:`<${el.tagName.toLowerCase()}>`,attribute:attr,url:val.substring(0,200),risk:el.tagName==="SCRIPT"?"high":"medium"});};
  document.querySelectorAll("script[src]").forEach(el=>check(el,"src"));
  document.querySelectorAll("link[href]").forEach(el=>check(el,"href"));
  document.querySelectorAll("img[src]").forEach(el=>check(el,"src"));
  document.querySelectorAll("iframe[src]").forEach(el=>check(el,"src"));
  document.querySelectorAll("form[action]").forEach(el=>check(el,"action"));
  document.querySelectorAll("object[data]").forEach(el=>check(el,"data"));
  document.querySelectorAll("video[src],audio[src],source[src]").forEach(el=>check(el,"src"));
  return mixed;
}

// 2. SRI CHECK — third-party scripts without integrity attribute
function scanSRI(){
  const missing=[];
  const mainHost=location.hostname;
  document.querySelectorAll("script[src]").forEach(s=>{
    try{
      const u=new URL(s.src);
      if(u.hostname!==mainHost&&!s.hasAttribute("integrity")){
        missing.push({url:s.src.substring(0,200),host:u.hostname,hasIntegrity:false,hasCrossorigin:s.hasAttribute("crossorigin")});
      }
    }catch{}
  });
  document.querySelectorAll('link[rel="stylesheet"][href]').forEach(l=>{
    try{
      const u=new URL(l.href);
      if(u.hostname!==mainHost&&!l.hasAttribute("integrity")){
        missing.push({url:l.href.substring(0,200),host:u.hostname,hasIntegrity:false,type:"stylesheet"});
      }
    }catch{}
  });
  return missing;
}

// 3. POSTMESSAGE LISTENER DETECTION
function scanPostMessageListeners(){
  const listeners=[];
  // Scan inline scripts for addEventListener('message') patterns
  document.querySelectorAll("script:not([src])").forEach(s=>{
    const text=s.textContent||"";
    // Look for message event listeners
    const patterns=[
      /addEventListener\s*\(\s*['"]message['"]/g,
      /\.on\s*\(\s*['"]message['"]/g,
      /onmessage\s*=/g,
      /window\.onmessage/g,
    ];
    patterns.forEach(pat=>{
      pat.lastIndex=0;
      let match;
      while((match=pat.exec(text))!==null){
        const start=Math.max(0,match.index-20);
        const end=Math.min(text.length,match.index+match[0].length+80);
        const ctx=text.substring(start,end).replace(/[\n\r]/g," ").trim();
        // Check if origin validation exists nearby
        const nearby=text.substring(Math.max(0,match.index-200),Math.min(text.length,match.index+500));
        const hasOriginCheck=/(?:\.origin|event\.origin|e\.origin|msg\.origin)\s*[!=]==?\s*['"]/.test(nearby);
        listeners.push({
          pattern:match[0],
          context:ctx.substring(0,200),
          hasOriginCheck,
          risk:hasOriginCheck?"low":"high"
        });
      }
    });
  });
  return listeners;
}

// 4. DEPENDENCY VERSION EXTRACTION + KNOWN CVE FLAGGING
function scanDependencyVersions(){
  const deps=[];
  const seen=new Set();
  // From script src URLs
  const verPatterns=[
    {regex:/jquery[.-](\d+\.\d+\.\d+)/i,name:"jQuery"},
    {regex:/bootstrap[.-](\d+\.\d+\.\d+)/i,name:"Bootstrap"},
    {regex:/angular[.-](\d+\.\d+\.\d+)/i,name:"Angular"},
    {regex:/vue[.-](\d+\.\d+\.\d+)/i,name:"Vue.js"},
    {regex:/react[.-](\d+\.\d+\.\d+)/i,name:"React"},
    {regex:/lodash[.-](\d+\.\d+\.\d+)/i,name:"Lodash"},
    {regex:/moment[.-](\d+\.\d+\.\d+)/i,name:"Moment.js"},
    {regex:/axios[/@](\d+\.\d+\.\d+)/i,name:"Axios"},
    {regex:/socket\.io[.-](\d+\.\d+\.\d+)/i,name:"Socket.io"},
    {regex:/d3[.-]v?(\d+\.\d+\.\d+)/i,name:"D3.js"},
    {regex:/ckeditor[/-](\d+\.\d+)/i,name:"CKEditor"},
    {regex:/tinymce[/-](\d+\.\d+)/i,name:"TinyMCE"},
  ];
  // Known vulnerable versions (subset of critical ones)
  const knownVulns={
    "jQuery":[[{max:"1.12.4"},["XSS via cross-domain ajax (CVE-2015-9251)"]],[{max:"3.4.1"},["XSS in htmlPrefilter (CVE-2020-11022)"]]],
    "Bootstrap":[[{max:"3.4.0"},["XSS in tooltip/popover (CVE-2019-8331)"]]],
    "Angular":[[{max:"1.6.9"},["Sandbox escape / template injection (multiple CVEs)"]]],
    "CKEditor":[[{max:"4.24"},["XSS via paste (CVE-2024-24816)"]]],
    "Lodash":[[{max:"4.17.20"},["Prototype pollution (CVE-2021-23337)"]]],
  };

  document.querySelectorAll("script[src]").forEach(s=>{
    verPatterns.forEach(vp=>{
      const match=s.src.match(vp.regex);
      if(match&&!seen.has(vp.name)){
        seen.add(vp.name);
        const ver=match[1];
        const vulns=[];
        if(knownVulns[vp.name]){
          knownVulns[vp.name].forEach(([range,cves])=>{
            if(range.min?semverCompare(ver,range.min)>=0&&semverCompare(ver,range.max)<=0:semverCompare(ver,range.max)<=0)vulns.push(...cves);
          });
        }
        deps.push({name:vp.name,version:ver,source:s.src.substring(0,150),vulns});
      }
    });
  });

  // Also check inline version declarations
  const inlineText=Array.from(document.querySelectorAll("script:not([src])")).map(s=>s.textContent).join("\n").substring(0,PS_CONFIG.INLINE_TEXT_LIMIT);
  verPatterns.forEach(vp=>{
    if(seen.has(vp.name))return;
    const match=inlineText.match(vp.regex);
    if(match){
      seen.add(vp.name);
      deps.push({name:vp.name,version:match[1],source:"inline-script",vulns:[]});
    }
  });

  // jQuery specific: check window.jQuery.fn.jquery
  if(!seen.has("jQuery")&&window.jQuery){
    try{
      const ver=window.jQuery.fn.jquery;
      if(ver){
        const vulns=[];
        if(knownVulns["jQuery"])knownVulns["jQuery"].forEach(([range,cves])=>{if(range.min?semverCompare(ver,range.min)>=0&&semverCompare(ver,range.max)<=0:semverCompare(ver,range.max)<=0)vulns.push(...cves);});
        deps.push({name:"jQuery",version:ver,source:"window.jQuery.fn.jquery",vulns});
      }
    }catch{}
  }

  return deps;
}

// 5. WEB WORKER DETECTION
function scanWebWorkers(){
  const workers=[];
  // Scan inline scripts for Worker/SharedWorker construction
  document.querySelectorAll("script:not([src])").forEach(s=>{
    const text=s.textContent||"";
    const patterns=[
      /new\s+Worker\s*\(\s*['"]([^'"]+)['"]/g,
      /new\s+SharedWorker\s*\(\s*['"]([^'"]+)['"]/g,
      /new\s+Worker\s*\(\s*URL\.createObjectURL/g,
    ];
    patterns.forEach(pat=>{
      pat.lastIndex=0;
      let match;
      while((match=pat.exec(text))!==null){
        workers.push({type:pat.source.includes("Shared")?"SharedWorker":"Worker",url:match[1]||"blob URL",source:"inline-script"});
      }
    });
  });
  return workers;
}

// 6. DOM XSS SINK DETECTION
function scanDOMXSSSinks(){
  const sinks=[];
  const sinkPatterns=[
    {pattern:/\.innerHTML\s*=/g,name:"innerHTML",risk:"high",desc:"Direct HTML injection sink"},
    {pattern:/\.outerHTML\s*=/g,name:"outerHTML",risk:"high",desc:"Direct HTML injection sink"},
    {pattern:/document\.write\s*\(/g,name:"document.write",risk:"high",desc:"Document write sink"},
    {pattern:/document\.writeln\s*\(/g,name:"document.writeln",risk:"high",desc:"Document writeln sink"},
    {pattern:/\.insertAdjacentHTML\s*\(/g,name:"insertAdjacentHTML",risk:"high",desc:"HTML injection sink"},
    {pattern:/eval\s*\(/g,name:"eval()",risk:"critical",desc:"Code execution sink"},
    {pattern:/setTimeout\s*\(\s*['"`]/g,name:"setTimeout(string)",risk:"high",desc:"String-based setTimeout"},
    {pattern:/setInterval\s*\(\s*['"`]/g,name:"setInterval(string)",risk:"high",desc:"String-based setInterval"},
    {pattern:/new\s+Function\s*\(/g,name:"new Function()",risk:"critical",desc:"Dynamic function creation"},
    {pattern:/\.html\s*\([^)]*[\$+]/g,name:"jQuery .html()",risk:"high",desc:"jQuery HTML injection"},
    {pattern:/\.append\s*\([^)]*[\$+]/g,name:"jQuery .append()",risk:"medium",desc:"jQuery append with dynamic content"},
    {pattern:/\$\s*\(\s*[^'"][^)]*\)/g,name:"jQuery selector injection",risk:"medium",desc:"Dynamic jQuery selector"},
    {pattern:/location\s*[.=]\s*[^;]*(?:search|hash|href)/g,name:"location manipulation",risk:"medium",desc:"URL-based DOM manipulation"},
    {pattern:/window\.open\s*\(/g,name:"window.open",risk:"medium",desc:"Window open — potential open redirect"},
    {pattern:/postMessage\s*\(/g,name:"postMessage",risk:"low",desc:"Cross-origin message sending"},
  ];

  document.querySelectorAll("script:not([src])").forEach(s=>{
    const text=s.textContent||"";
    if(text.length<10)return;
    sinkPatterns.forEach(sp=>{
      sp.pattern.lastIndex=0;
      let match,count=0;
      while((match=sp.pattern.exec(text))!==null&&count<PS_CONFIG.XSS_MATCH_LIMIT){
        count++;
        const start=Math.max(0,match.index-30);
        const end=Math.min(text.length,match.index+match[0].length+50);
        sinks.push({
          sink:sp.name,
          risk:sp.risk,
          description:sp.desc,
          context:text.substring(start,end).replace(/[\n\r]/g," ").trim().substring(0,200)
        });
      }
    });
  });
  return sinks;
}

// 7. JSONP DETECTION — callback parameters in script tags
function scanJSONP(){
  const jsonp=[];
  document.querySelectorAll("script[src]").forEach(s=>{
    try{
      const u=new URL(s.src);
      const cbParams=["callback","jsonp","cb","jsonpcallback","_callback","jsonpCallback"];
      cbParams.forEach(p=>{
        const val=u.searchParams.get(p);
        if(val)jsonp.push({url:s.src.substring(0,200),param:p,value:val,host:u.hostname});
      });
    }catch{}
  });
  // Also check inline scripts for JSONP patterns
  document.querySelectorAll("script:not([src])").forEach(s=>{
    const text=s.textContent||"";
    const match=text.match(/[?&]callback=([^&'"]+)/);
    if(match)jsonp.push({url:"inline-script",param:"callback",value:match[1],host:location.hostname});
  });
  return jsonp;
}

// 8. COOKIE VALUE ANALYSIS — run secret patterns on cookie values
function scanCookieValues(){
  const findings=[];
  try{
    const cookies=document.cookie.split(";");
    cookies.forEach(c=>{
      const parts=c.trim().split("=");
      const name=parts[0];
      const value=parts.slice(1).join("=");
      if(!value||value.length<10)return;
      // Check for JWT
      if(/^eyJ[A-Za-z0-9_-]+\.eyJ/.test(value))findings.push({cookie:name,type:"JWT in cookie",value:value.substring(0,100),risk:"high"});
      // Check for base64 encoded data
      else if(/^[A-Za-z0-9+/]{30,}={0,2}$/.test(value)){
        try{const decoded=atob(value);if(/[{"\w]/.test(decoded))findings.push({cookie:name,type:"Base64 data",value:decoded.substring(0,100),risk:"medium"});}catch{}
      }
      // Check for sequential/numeric IDs
      else if(/^\d{3,10}$/.test(value))findings.push({cookie:name,type:"Sequential ID",value,risk:"medium"});
      // Check for plaintext username/email patterns
      else if(/^[a-zA-Z0-9._-]+@/.test(value))findings.push({cookie:name,type:"Email in cookie",value:value.substring(0,60),risk:"low"});
    });
  }catch{}
  return findings;
}

// 9. RECON FILE SUGGESTIONS — based on detected tech stack
function generateReconSuggestions(techStack){
  const suggestions=[];
  const always=[
    {path:"/robots.txt",reason:"Disallowed paths reveal hidden endpoints"},
    {path:"/sitemap.xml",reason:"Full URL map of the site"},
    {path:"/.well-known/security.txt",reason:"Security contact and scope info"},
    {path:"/crossdomain.xml",reason:"Flash crossdomain policy"},
    {path:"/clientaccesspolicy.xml",reason:"Silverlight access policy"},
    {path:"/.git/HEAD",reason:"Exposed git repository"},
    {path:"/.env",reason:"Environment variables / secrets"},
    {path:"/web.config",reason:"IIS configuration"},
    {path:"/server-info",reason:"Apache server info"},
    {path:"/server-status",reason:"Apache server status"},
    {path:"/.htaccess",reason:"Apache configuration"},
    {path:"/wp-login.php",reason:"WordPress admin login"},
  ];
  suggestions.push(...always);
  const techNames=techStack.map(t=>t.name.toLowerCase());
  if(techNames.some(t=>t.includes("wordpress"))){suggestions.push({path:"/wp-json/wp/v2/users",reason:"WordPress user enumeration"},{path:"/xmlrpc.php",reason:"WordPress XML-RPC (brute force)"},{path:"/wp-content/debug.log",reason:"WordPress debug log"});}
  if(techNames.some(t=>t.includes("laravel"))){suggestions.push({path:"/.env",reason:"Laravel environment config"},{path:"/storage/logs/laravel.log",reason:"Laravel error log"},{path:"/telescope",reason:"Laravel Telescope debug"});}
  if(techNames.some(t=>t.includes("django"))){suggestions.push({path:"/admin/",reason:"Django admin panel"},{path:"/__debug__/",reason:"Django debug toolbar"},{path:"/api/schema/",reason:"Django REST schema"});}
  if(techNames.some(t=>t.includes("rails"))){suggestions.push({path:"/rails/info",reason:"Rails info page"},{path:"/rails/mailers",reason:"Rails mailer previews"});}
  if(techNames.some(t=>t.includes("asp.net")||t.includes("iis"))){suggestions.push({path:"/elmah.axd",reason:"ASP.NET ELMAH error log"},{path:"/trace.axd",reason:"ASP.NET trace"},{path:"/web.config",reason:"IIS config file"});}
  if(techNames.some(t=>t.includes("graphql"))){suggestions.push({path:"/graphql",reason:"GraphQL endpoint"},{path:"/graphiql",reason:"GraphQL IDE"},{path:"/graphql/schema",reason:"GraphQL schema"});}
  if(techNames.some(t=>t.includes("node")||t.includes("express")||t.includes("next"))){suggestions.push({path:"/package.json",reason:"Node.js dependencies"},{path:"/.env",reason:"Environment config"});}
  return suggestions;
}


// ============================================================
// v5.4: WEBAUTHN / FIDO2 FINGERPRINTING
// ============================================================
function scanWebAuthn() {
  const info = { supported: false, conditionalUI: false, platformAuth: false, features: [] };
  try {
    if (!window.PublicKeyCredential) return info;
    info.supported = true;
    info.features.push("WebAuthn API present");
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
      info.features.push("Platform authenticator check available");
      info.platformAuth = true;
    }
    if (typeof PublicKeyCredential.isConditionalMediationAvailable === "function") {
      info.features.push("Conditional UI (autofill passkeys) available");
      info.conditionalUI = true;
    }
    const credForms = document.querySelectorAll('form[action*="login"], form[action*="auth"], form[action*="signin"], form[action*="webauthn"], form[action*="fido"], form[action*="passkey"]');
    if (credForms.length) info.features.push(credForms.length + " auth-related forms detected");
    const passkeyHints = document.querySelectorAll('[autocomplete*="webauthn"], [data-webauthn], [data-passkey], [data-fido], .webauthn, .passkey, .fido2');
    if (passkeyHints.length) info.features.push(passkeyHints.length + " passkey/WebAuthn DOM hints");
    const scripts = document.querySelectorAll("script");
    let webauthnInScript = false;
    scripts.forEach(s => {
      const txt = (s.textContent || "").substring(0, 50000);
      if (/navigator\.credentials\.(create|get)\s*\(/i.test(txt) || /PublicKeyCredential/i.test(txt) || /webauthn|fido2?|passkey/i.test(txt)) webauthnInScript = true;
    });
    if (webauthnInScript) info.features.push("WebAuthn/FIDO2 references in inline scripts");
    if (typeof navigator.credentials !== "undefined" && typeof navigator.credentials.create === "function") info.features.push("CredentialsContainer.create available");
  } catch (e) {}
  return info.features.length > 1 ? info : info;
}

// ============================================================
// v5.4: WEBRTC IP LEAK DETECTION (content script fallback)
// ============================================================
function scanWebRTC() {
  const results = [];
  try {
    if (typeof RTCPeerConnection === "undefined" && typeof webkitRTCPeerConnection === "undefined") return results;
    results.push({ type: "capability", rtcSupported: true, source: "content-script" });
    try {
      const RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
      const pc = new RTC({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      pc.createDataChannel("");
      pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(() => {});
      pc.onicecandidate = ice => {
        if (!ice || !ice.candidate || !ice.candidate.candidate) { try { pc.close(); } catch (e2) {} return; }
        const parts = ice.candidate.candidate.split(" ");
        for (let i = 0; i < parts.length; i++) {
          const p = parts[i];
          if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(p)) {
            const isPrivate = /^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.)/.test(p);
            if (!results.find(r => r.ip === p)) results.push({ ip: p, type: isPrivate ? "private" : "public", source: "content-stun" });
          }
          if (p.includes(":")) {
            const v6 = p.match(/([0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7})/i);
            if (v6 && !results.find(r => r.ip === v6[1])) results.push({ ip: v6[1], type: "ipv6", source: "content-stun" });
          }
        }
      };
      setTimeout(() => { try { pc.close(); } catch (e2) {} }, 5000);
    } catch (e) {}
  } catch (e) {}
  return results;
}

// ============================================================
// v5.4: WASM MODULE DETECTION
// ============================================================
function scanWasmModules() {
  const results = [];
  try {
    const entries = performance.getEntriesByType("resource");
    entries.forEach(e => {
      if (e.name && (e.name.endsWith(".wasm") || e.name.includes(".wasm?")))
        results.push({ url: e.name, size: e.transferSize || 0, duration: Math.round(e.duration), source: "content-perf" });
    });
    document.querySelectorAll('script[src*=".wasm"], link[href*=".wasm"]').forEach(el => {
      const url = el.src || el.href;
      if (url && !results.find(r => r.url === url))
        results.push({ url, source: "content-dom", size: 0 });
    });
    const html = (document.documentElement?.innerHTML || "").substring(0, PS_CONFIG.INLINE_TEXT_LIMIT);
    const wasmRefs = html.match(/['"]([^'"]*\.wasm(?:\?[^'"]*)?)['"]/gi);
    if (wasmRefs) {
      wasmRefs.slice(0, 10).forEach(ref => {
        const url = ref.replace(/['"]/g, "");
        if (url.length > 5 && !results.find(r => r.url === url))
          results.push({ url, source: "content-html", size: 0 });
      });
    }
    try {
      if (navigator.gpu) {
        results.push({ type: "webgpu", supported: true, source: "content-detect" });
      }
    } catch (e) {}
    try {
      if (typeof SharedArrayBuffer !== "undefined") {
        results.push({ type: "shared-array-buffer", supported: true, source: "content-detect" });
      }
    } catch (e) {}
    try {
      if (typeof WebAssembly !== "undefined") {
        const simdValid = WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11]));
        if (simdValid) results.push({ type: "wasm-simd", supported: true, source: "content-detect" });
      }
    } catch (e) {}
  } catch (e) {}
  return results;
}

// ============================================================
// CSP VIOLATION LISTENER
// ============================================================
function scanCoopCoep() {
  const info = { crossOriginIsolated: false, sharedArrayBuffer: false, features: [] };
  try {
    info.crossOriginIsolated = !!self.crossOriginIsolated;
    info.sharedArrayBuffer = typeof SharedArrayBuffer !== "undefined";
    if (info.crossOriginIsolated) info.features.push("Cross-origin isolated");
    if (info.sharedArrayBuffer) info.features.push("SharedArrayBuffer available");
    if (!info.crossOriginIsolated) info.features.push("NOT cross-origin isolated — Spectre side-channels possible");
    const metas = document.querySelectorAll("meta[http-equiv]");
    metas.forEach(m => {
      const equiv = (m.getAttribute("http-equiv") || "").toLowerCase();
      if (equiv === "cross-origin-opener-policy") { info.coop = m.content; info.features.push("COOP: " + m.content); }
      if (equiv === "cross-origin-embedder-policy") { info.coep = m.content; info.features.push("COEP: " + m.content); }
      if (equiv === "cross-origin-resource-policy") { info.corp = m.content; info.features.push("CORP: " + m.content); }
    });
  } catch (e) {}
  return info.features.length ? info : null;
}

function setupCSPViolationListener(){document.addEventListener("securitypolicyviolation",e=>{try{chrome.runtime.sendMessage({action:"reportContentScan",cspViolations:[{directive:e.violatedDirective,blockedUri:e.blockedURI,sourceFile:e.sourceFile,lineNumber:e.lineNumber}]});}catch{}});}

// ============================================================
// MASTER SCAN
// ============================================================
function runFullScan(){
  // Single DOM pass for hidden fields + inline handlers
  let domScanResults;
  try { domScanResults = scanDOMElements(); } catch(e) { console.warn('[PenScope] scanDOMElements failed:', e); domScanResults = {hiddenFields:[], inlineHandlers:[]}; }

  let secrets; try { secrets = scanSecrets(); } catch(e) { console.warn('[PenScope] scanSecrets failed:', e); secrets = []; }
  let hiddenFields; try { hiddenFields = scanHiddenFields(domScanResults); } catch(e) { console.warn('[PenScope] scanHiddenFields failed:', e); hiddenFields = []; }
  let forms; try { forms = scanForms(); } catch(e) { console.warn('[PenScope] scanForms failed:', e); forms = []; }
  let techStack; try { techStack = scanTech(); } catch(e) { console.warn('[PenScope] scanTech failed:', e); techStack = []; }
  let jsGlobals; try { jsGlobals = scanGlobals(); } catch(e) { console.warn('[PenScope] scanGlobals failed:', e); jsGlobals = []; }
  let storageData; try { storageData = scanStorage(); } catch(e) { console.warn('[PenScope] scanStorage failed:', e); storageData = {local:{},session:{}}; }
  let links; try { links = scanLinks(); } catch(e) { console.warn('[PenScope] scanLinks failed:', e); links = []; }
  let sourceMaps; try { sourceMaps = scanSourceMaps(); } catch(e) { console.warn('[PenScope] scanSourceMaps failed:', e); sourceMaps = []; }
  let inlineHandlers; try { inlineHandlers = scanInlineHandlers(domScanResults); } catch(e) { console.warn('[PenScope] scanInlineHandlers failed:', e); inlineHandlers = []; }
  let metaTags; try { metaTags = scanMetaTags(); } catch(e) { console.warn('[PenScope] scanMetaTags failed:', e); metaTags = []; }
  let serviceWorkers; try { serviceWorkers = scanServiceWorkers(); } catch(e) { console.warn('[PenScope] scanServiceWorkers failed:', e); serviceWorkers = []; }
  let mixedContent; try { mixedContent = scanMixedContent(); } catch(e) { console.warn('[PenScope] scanMixedContent failed:', e); mixedContent = []; }
  let sriIssues; try { sriIssues = scanSRI(); } catch(e) { console.warn('[PenScope] scanSRI failed:', e); sriIssues = []; }
  let postMessageListeners; try { postMessageListeners = scanPostMessageListeners(); } catch(e) { console.warn('[PenScope] scanPostMessageListeners failed:', e); postMessageListeners = []; }
  let dependencyVersions; try { dependencyVersions = scanDependencyVersions(); } catch(e) { console.warn('[PenScope] scanDependencyVersions failed:', e); dependencyVersions = []; }
  let webWorkers; try { webWorkers = scanWebWorkers(); } catch(e) { console.warn('[PenScope] scanWebWorkers failed:', e); webWorkers = []; }
  let domXSSSinks; try { domXSSSinks = scanDOMXSSSinks(); } catch(e) { console.warn('[PenScope] scanDOMXSSSinks failed:', e); domXSSSinks = []; }
  let jsonpEndpoints; try { jsonpEndpoints = scanJSONP(); } catch(e) { console.warn('[PenScope] scanJSONP failed:', e); jsonpEndpoints = []; }
  let cookieFindings; try { cookieFindings = scanCookieValues(); } catch(e) { console.warn('[PenScope] scanCookieValues failed:', e); cookieFindings = []; }
  let reconSuggestions; try { reconSuggestions = generateReconSuggestions(techStack); } catch(e) { console.warn('[PenScope] generateReconSuggestions failed:', e); reconSuggestions = []; }
  // v5.4: New attack surface scanners
  let webAuthnInfo; try { webAuthnInfo = scanWebAuthn(); } catch(e) { console.warn('[PenScope] scanWebAuthn failed:', e); webAuthnInfo = null; }
  let webrtcLeaks; try { webrtcLeaks = scanWebRTC(); } catch(e) { console.warn('[PenScope] scanWebRTC failed:', e); webrtcLeaks = []; }
  let wasmModules; try { wasmModules = scanWasmModules(); } catch(e) { console.warn('[PenScope] scanWasmModules failed:', e); wasmModules = []; }
  let coopCoepInfo; try { coopCoepInfo = scanCoopCoep(); } catch(e) { console.warn('[PenScope] scanCoopCoep failed:', e); coopCoepInfo = null; }

  let perfEntries=[];
  try{perfEntries=performance.getEntriesByType("resource").slice(0,PS_CONFIG.PERF_ENTRY_LIMIT).map(r=>({name:r.name,type:r.initiatorType,duration:Math.round(r.duration),size:r.transferSize||0}));}catch{}

  const data={secrets,hiddenFields,forms,techStack,jsGlobals,storageData,links,sourceMaps,inlineHandlers,metaTags,serviceWorkers,perfEntries,
    mixedContent,sriIssues,postMessageListeners,dependencyVersions,webWorkers,domXSSSinks,jsonpEndpoints,cookieFindings,reconSuggestions,
    webAuthnInfo,webrtcLeaks,wasmModules,coopCoepInfo
  };
  chrome.runtime.sendMessage({action:"reportContentScan",...data});
  return data;
}

chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{
  if(msg.action==="scan"){
    try{runFullScan();}catch(e){console.warn('[PenScope]',e);}
    sendResponse({ok:true});
  }
  return true;
});
setupCSPViolationListener();

let _lastScanHash="";
function quickHash(){const sample=(document.body?document.body.innerHTML.substring(0,5000):"")+document.querySelectorAll("*").length;let h=0;for(let i=0;i<sample.length;i++)h=((h<<5)-h+sample.charCodeAt(i))|0;return h.toString(36);}

setTimeout(runFullScan,PS_CONFIG.INITIAL_SCAN_DELAY);

// v6.1.1 — Smarter rescan scheduling. The previous version called runFullScan
// directly from a 3-second debounce, which on busy pages (YouTube, Twitch, etc.)
// caused the scan to fire every few seconds, walking tens of thousands of nodes
// and competing with the renderer. New behavior:
//   - Defer to requestIdleCallback (only run when the page isn't busy)
//   - Hard-cap rescans to once per MIN_SCAN_INTERVAL (15s)
//   - Skip entirely when the tab is hidden — defer until visible
//   - Filter mutations to only those that add Element nodes (text-only mutations
//     like timer ticks, character-data updates, are ignored)
let _lastFullScan=0;let _scanScheduled=false;
function scheduleFullScan(){
  if(_scanScheduled)return;
  _scanScheduled=true;
  const now=Date.now();
  const wait=Math.max(0,PS_CONFIG.MIN_SCAN_INTERVAL-(now-_lastFullScan));
  setTimeout(()=>{
    const runIt=()=>{
      _scanScheduled=false;
      // Tab is hidden — no rush. Wait for it to come back.
      if(typeof document.visibilityState==="string"&&document.visibilityState==="hidden"){
        const onShow=()=>{
          document.removeEventListener("visibilitychange",onShow);
          if(document.visibilityState==="visible")scheduleFullScan();
        };
        document.addEventListener("visibilitychange",onShow);
        return;
      }
      const h=quickHash();
      if(h!==_lastScanHash){
        _lastScanHash=h;
        _lastFullScan=Date.now();
        try{runFullScan();}catch(e){console.warn('[PenScope]',e);}
      }
    };
    // requestIdleCallback runs when the page is idle. timeout:5s ensures we
    // eventually run even on perpetually-busy pages.
    if(typeof requestIdleCallback==="function"){
      requestIdleCallback(runIt,{timeout:5000});
    }else{
      runIt();
    }
  },wait);
}

let st;
const obs=new MutationObserver(muts=>{
  // Quick-reject: ignore mutations that didn't add any Element nodes. Text-only
  // changes (timer ticks, character data updates) shouldn't trigger a rescan.
  let elementAdded=false;
  for(let i=0;i<muts.length;i++){
    const m=muts[i];
    if(!m.addedNodes||!m.addedNodes.length)continue;
    for(let j=0;j<m.addedNodes.length;j++){
      if(m.addedNodes[j].nodeType===1){elementAdded=true;break;}
    }
    if(elementAdded)break;
  }
  if(!elementAdded)return;
  clearTimeout(st);
  st=setTimeout(scheduleFullScan,PS_CONFIG.MUTATION_DEBOUNCE);
});
const target=document.body||document.documentElement;
if(target)obs.observe(target,{childList:true,subtree:true});
})();
