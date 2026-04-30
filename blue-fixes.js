// PenScope v6.0 — Blue Mode Fix Snippets (reference copy)
//
// Map every finding type PenScope produces to a remediation snippet. The live copy is
// inlined into popup.js (FIX_SNIPPETS) so the popup can render fixes without a module
// import. Treat this file as the canonical source: when adding entries, paste the same
// shape into popup.js's FIX_SNIPPETS const.
//
// Schema:
//   key (lower-case finding identifier; matches what mapFindingToFixKey() in popup.js
//        returns when normalizing a finding object)
//   →  {
//        title:       short imperative — "Add Strict-Transport-Security header"
//        severity:    expected default severity for this finding
//        ease:        1-5 — ease of fix (5 = trivial, one-line config)
//        why:         plain-English explanation; appears in the fix panel
//        snippet_raw: format-agnostic snippet (e.g. raw HTTP header)
//        nginx?, apache?, iis?, cloudflare?, express?, django?, laravel?, rails?,
//        aspnet?, spring?, fastify?, koa?, csp?    framework-specific snippet variants
//        references?: array of URL strings; rendered as "References" footer in panel
//      }
//
// The fix panel UX exposes language tabs only for the snippet keys that exist on the
// matching entry — so a finding that has only `nginx` and `cloudflare` won't show
// "Apache" / "Express" tabs at all.

const FIX_SNIPPETS={
  "missing-hsts":{
    title:"Add Strict-Transport-Security header",
    severity:"high",ease:5,
    why:"Prevents protocol downgrade attacks. Forces HTTPS for the configured max-age. Combined with `preload` submission, also protects first-time visitors.",
    snippet_raw:"Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    nginx:'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
    apache:'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
    iis:'<add name="Strict-Transport-Security" value="max-age=63072000; includeSubDomains; preload" />',
    cloudflare:"Cloudflare → SSL/TLS → Edge Certificates → HTTP Strict Transport Security: enable with max-age=2y, includeSubDomains, preload.",
    express:"app.use((req,res,next)=>{ res.setHeader('Strict-Transport-Security','max-age=63072000; includeSubDomains; preload'); next(); });",
    references:["https://hstspreload.org/","https://owasp.org/www-project-secure-headers/#strict-transport-security"]
  },
  "missing-csp":{
    title:"Add Content-Security-Policy header",
    severity:"high",ease:3,
    why:"CSP is the strongest defense against XSS. A tight CSP blocks inline scripts and limits where scripts/styles can come from. Use Blue mode's CSP Generator to produce one from observed traffic.",
    snippet_raw:"Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests",
    nginx:`add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests" always;`,
    apache:`Header always set Content-Security-Policy "default-src 'none'; script-src 'self'; ..."`,
    express:"const helmet=require('helmet'); app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc:[\"'none'\"], scriptSrc:[\"'self'\"], styleSrc:[\"'self'\"], imgSrc:[\"'self'\",\"data:\"], connectSrc:[\"'self'\"], fontSrc:[\"'self'\"], frameAncestors:[\"'none'\"], baseUri:[\"'self'\"], formAction:[\"'self'\"] } }));",
    references:["https://content-security-policy.com/","https://csp-evaluator.withgoogle.com/"]
  },
  "missing-xframe":{
    title:"Add X-Frame-Options or CSP frame-ancestors",
    severity:"medium",ease:5,
    why:"Prevents clickjacking by disallowing the page from being embedded in an iframe by other origins. CSP frame-ancestors supersedes X-Frame-Options where supported.",
    snippet_raw:"X-Frame-Options: DENY\n# or, preferred:\nContent-Security-Policy: frame-ancestors 'none'",
    nginx:'add_header X-Frame-Options "DENY" always;\nadd_header Content-Security-Policy "frame-ancestors \'none\'" always;',
    apache:'Header always set X-Frame-Options "DENY"',
    iis:'<add name="X-Frame-Options" value="DENY" />',
    express:"app.use((req,res,next)=>{ res.setHeader('X-Frame-Options','DENY'); next(); });",
  },
  "missing-xcto":{
    title:"Add X-Content-Type-Options: nosniff",
    severity:"low",ease:5,
    why:"Prevents the browser from MIME-sniffing the response away from the declared Content-Type. Stops attacks that upload .jpg.html and trick browsers into executing them as HTML.",
    snippet_raw:"X-Content-Type-Options: nosniff",
    nginx:'add_header X-Content-Type-Options "nosniff" always;',
    apache:'Header always set X-Content-Type-Options "nosniff"',
    iis:'<add name="X-Content-Type-Options" value="nosniff" />',
    express:"res.setHeader('X-Content-Type-Options','nosniff');",
  },
  "missing-referrer":{
    title:"Add Referrer-Policy header",
    severity:"low",ease:5,
    why:"Controls how much referrer information is sent with cross-origin requests. `strict-origin-when-cross-origin` is the modern default — full referrer to same-origin, only origin to cross-origin HTTPS, nothing on downgrade.",
    snippet_raw:"Referrer-Policy: strict-origin-when-cross-origin",
    nginx:'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    apache:'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    express:"res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');",
  },
  "missing-permissions-policy":{
    title:"Add Permissions-Policy header",
    severity:"low",ease:4,
    why:"Disables browser APIs the page doesn't need (camera, microphone, geolocation, etc.) so a successful XSS can't pivot into hardware access. Start tight; loosen per-feature only as needed.",
    snippet_raw:"Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    nginx:'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;',
  },
  "missing-coop":{
    title:"Add Cross-Origin-Opener-Policy header",
    severity:"low",ease:4,
    why:"Isolates the browsing context from cross-origin windows so XS-Leaks and Spectre-class attacks can't read your origin's memory.",
    snippet_raw:"Cross-Origin-Opener-Policy: same-origin",
    nginx:'add_header Cross-Origin-Opener-Policy "same-origin" always;',
  },
  "cookie-no-httponly":{
    title:"Add HttpOnly to session cookie",
    severity:"medium",ease:5,
    why:"Prevents document.cookie from reading the cookie. Combined with Secure + SameSite=Strict, this eliminates the vast majority of session-stealing XSS payloads.",
    snippet_raw:"Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
    express:"res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });",
    django:"SESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_SAMESITE = 'Strict'",
    laravel:"// config/session.php\n'http_only' => true,\n'secure' => true,\n'same_site' => 'strict',",
    rails:"# config/initializers/session_store.rb\nRails.application.config.session_store :cookie_store, key:'_app_session', httponly:true, secure:Rails.env.production?, same_site::strict",
    aspnet:"options.Cookie.HttpOnly = true;\noptions.Cookie.SecurePolicy = CookieSecurePolicy.Always;\noptions.Cookie.SameSite = SameSiteMode.Strict;",
  },
  "cookie-no-secure":{
    title:"Add Secure flag to cookie",
    severity:"medium",ease:5,
    why:"Without Secure, the cookie is sent over plaintext HTTP — any network attacker (open Wi-Fi, compromised router) can read the session.",
    snippet_raw:"Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
    express:"res.cookie('session', token, { secure: true });",
  },
  "cookie-no-samesite":{
    title:"Set SameSite on cookie",
    severity:"medium",ease:5,
    why:"SameSite=Strict prevents the cookie from being sent on cross-site requests, blocking CSRF on most flows. Use Lax if you need top-level GET cross-site (e.g. SSO redirects). Never Default-None without Secure.",
    snippet_raw:"Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly",
    express:"res.cookie('session', token, { sameSite: 'strict' });",
  },
  "sourcemap-leak":{
    title:"Remove .map files from production",
    severity:"medium",ease:5,
    why:"Source maps deobfuscate minified code, exposing original variable names, comments, and sometimes hardcoded secrets. They are useful in dev, leaked in prod.",
    snippet_raw:"# Webpack: in production config\nmodule.exports={ devtool:false, ...}\n# Vite: vite.config.js\nbuild:{ sourcemap:false }\n# Rollup: rollup.config.js\noutput:{ sourcemap:false }",
    nginx:"# Block .map fetches at the edge:\nlocation ~* \\.map$ { deny all; return 404; }",
    apache:"<FilesMatch \"\\.map$\"> Require all denied </FilesMatch>",
  },
  "exposed-secret":{
    title:"Rotate the exposed secret and remove from source",
    severity:"critical",ease:2,
    why:"Once a secret is committed/served, assume it's compromised. Rotate immediately. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager, Doppler) and inject at runtime. Never commit `.env` files.",
    snippet_raw:"# 1. Rotate the secret upstream (AWS console, Stripe dashboard, etc.)\n# 2. Remove from code: git rm <file>; commit; push\n# 3. Purge from history: git filter-repo --path <file> --invert-paths\n# 4. Force-push and notify all collaborators to re-clone\n# 5. Update CI/CD to inject the new secret from your secrets manager",
    references:["https://docs.github.com/en/code-security/secret-scanning"]
  },
  "sql-injection-confirmed":{
    title:"Use parameterized queries — never concatenate input into SQL",
    severity:"critical",ease:3,
    why:"SQL injection lets an attacker read, modify, or destroy your entire database. Parameterized queries (prepared statements) are the only correct fix. ORMs do this for you when used correctly.",
    snippet_raw:"// BAD\ndb.query('SELECT * FROM users WHERE id='+id)\n// GOOD\ndb.query('SELECT * FROM users WHERE id=?', [id])",
    express:"const [rows]=await pool.query('SELECT * FROM users WHERE id=?',[req.params.id]);",
    django:"User.objects.get(id=request.GET.get('id'))  # Django ORM parameterizes automatically",
    laravel:"DB::select('SELECT * FROM users WHERE id=?',[$id]);  // or use Eloquent",
  },
  "ssti-confirmed":{
    title:"Don't pass user input into template engine context",
    severity:"critical",ease:2,
    why:"Server-side template injection lets an attacker execute arbitrary code in the template engine's context — usually full RCE. Treat user input as data: render it via `{{ value }}` (auto-escaped), never via `render_template_string(user_input)`.",
    snippet_raw:"# BAD (Flask)\nreturn render_template_string('Hello '+name)\n# GOOD\nreturn render_template('hello.html', name=name)",
    references:["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection"]
  },
  "xxe-confirmed":{
    title:"Disable external entities in XML parser",
    severity:"critical",ease:4,
    why:"XXE allows file disclosure, SSRF, and sometimes RCE. The fix is parser-config: disable DOCTYPE, external entities, and external DTDs.",
    snippet_raw:"// Java (DocumentBuilderFactory)\ndbf.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true);\ndbf.setFeature('http://xml.org/sax/features/external-general-entities', false);\ndbf.setFeature('http://xml.org/sax/features/external-parameter-entities', false);\n// Python (lxml)\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\n// PHP (libxml)\nlibxml_disable_entity_loader(true);"
  },
  "crlf-injection":{
    title:"Strip \\r and \\n from values used in headers/redirects",
    severity:"high",ease:5,
    why:"CRLF injection enables response splitting, session fixation, and cache poisoning by sneaking newlines into headers. Most modern frameworks strip these automatically — but check Location headers and any code that builds raw HTTP responses.",
    snippet_raw:"const safe = String(input).replace(/[\\r\\n]/g, '');\nres.setHeader('Location', safe);",
  },
  "open-redirect":{
    title:"Validate redirect targets against an allowlist",
    severity:"medium",ease:4,
    why:"Open redirects are commonly chained into phishing and OAuth code-stealing. Don't trust user-controlled URLs. Either compare against an allowlist of paths/origins, or require the redirect to be same-origin.",
    snippet_raw:"const ALLOW=['/dashboard','/profile','/settings'];\nfunction safeRedirect(target){\n  if(!ALLOW.includes(target))return '/';\n  return target;\n}",
  },
  "cors-wildcard-credentials":{
    title:"Replace Access-Control-Allow-Origin '*' with explicit allowlist",
    severity:"high",ease:4,
    why:"Wildcard origin combined with credentials:'include' (which browsers actually block in this exact combo) — but more commonly, a server reflecting the request Origin while sending Allow-Credentials:true breaks SOP entirely. Maintain a strict allowlist.",
    snippet_raw:"const ALLOW=new Set(['https://app.example.com','https://admin.example.com']);\napp.use((req,res,next)=>{\n  const o=req.headers.origin;\n  if(ALLOW.has(o)){ res.setHeader('Access-Control-Allow-Origin',o); res.setHeader('Access-Control-Allow-Credentials','true'); }\n  next();\n});"
  },
  "missing-csrf":{
    title:"Add CSRF tokens to state-changing forms",
    severity:"medium",ease:4,
    why:"Without CSRF tokens, an attacker can trick a logged-in user into submitting a malicious form from another site. SameSite=Strict cookies help but tokens are still recommended.",
    snippet_raw:"// Express + csurf middleware\nconst csurf=require('csurf');\napp.use(csurf({ cookie: true }));\n// In template: <input type=\"hidden\" name=\"_csrf\" value=\"{{csrfToken}}\">",
    django:"# Django enables CSRF by default. Ensure {% csrf_token %} is in every <form>.",
    laravel:"<!-- Blade: -->\n@csrf",
  },
  "jwt-alg-none":{
    title:"Reject JWT alg=none and weak algorithms",
    severity:"critical",ease:4,
    why:"alg=none means the server trusts unsigned tokens — anyone can forge an admin token. Pin the algorithm explicitly when verifying; never let the JWT itself dictate it.",
    snippet_raw:"// jsonwebtoken (Node)\njwt.verify(token, secret, { algorithms: ['HS256'] }); // pin allowed algos\n// PyJWT\njwt.decode(token, secret, algorithms=['HS256'])"
  },
  "graphql-introspection":{
    title:"Disable GraphQL introspection in production",
    severity:"low",ease:5,
    why:"Introspection lets anyone query your full schema — every field, type, mutation, deprecated marker. Useful in dev; in prod it just helps attackers map your data model.",
    snippet_raw:"// Apollo Server\nconst server = new ApolloServer({\n  typeDefs, resolvers,\n  introspection: process.env.NODE_ENV !== 'production'\n});",
  },
  "exposed-debug":{
    title:"Disable debug/trace/admin endpoints in production",
    severity:"high",ease:4,
    why:"Endpoints like /debug, /trace.axd, /actuator, /_debugbar, /telescope expose internals — env vars, heap dumps, request bodies, sometimes RCE. They should not exist on production deploys.",
    snippet_raw:"# Spring Boot\nmanagement.endpoints.web.exposure.include=health,info\nmanagement.endpoints.web.base-path=/internal-only-vpn-required\n# Laravel\n# Remove or restrict middleware on /telescope, /horizon\n# ASP.NET\n# Remove trace.axd and elmah.axd from web.config in production builds"
  },
  "directory-listing":{
    title:"Disable directory listing",
    severity:"medium",ease:5,
    why:"Auto-generated directory indexes expose file names and structure that the app didn't intend to surface — old backups, .git, .env, source maps, etc.",
    snippet_raw:"# Apache\n<Directory /var/www/html>\n  Options -Indexes\n</Directory>\n# Nginx\nautoindex off;",
  },
  "weak-tls":{
    title:"Disable TLS 1.0/1.1 and weak ciphers",
    severity:"high",ease:3,
    why:"TLS 1.0 and 1.1 have known cryptographic weaknesses and are deprecated. Modern ciphers (AEAD only, forward secrecy) are required for compliance and security.",
    snippet_raw:"# Nginx — modern TLS only\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers off;\nssl_session_cache shared:SSL:50m;\nssl_session_timeout 1d;",
    references:["https://ssl-config.mozilla.org/"]
  },
  "mixed-content":{
    title:"Upgrade all subresources to HTTPS",
    severity:"medium",ease:4,
    why:"A page served over HTTPS that loads HTTP subresources (scripts, iframes) leaks data and is MITM-able. Modern browsers block active mixed content but warn for passive — fix both.",
    snippet_raw:"Content-Security-Policy: upgrade-insecure-requests"
  },
  "missing-sri":{
    title:"Add Subresource Integrity to CDN scripts",
    severity:"low",ease:4,
    why:"If you load JavaScript from a third-party CDN without SRI and the CDN is compromised, the attacker runs code in your origin. SRI lets the browser verify the script content matches a known hash.",
    snippet_raw:'<script src="https://cdn.example.com/lib.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>'
  },
  "verbose-error":{
    title:"Hide stack traces and database errors in production",
    severity:"medium",ease:4,
    why:"Stack traces leak file paths, framework versions, sometimes user data. Database error messages leak schema. Show generic 500 pages externally; log details server-side only.",
    snippet_raw:"// Express\napp.use((err,req,res,next)=>{\n  console.error(err);\n  res.status(500).json({ error: 'Internal error' }); // no stack to client\n});\n// Django: DEBUG = False in production"
  },
  "exposed-env":{
    title:"Block access to /.env, /.git, dotfiles",
    severity:"critical",ease:5,
    why:"Many deploys accidentally serve dotfiles. /.env contains DB credentials, API keys, JWT secrets. /.git/ leaks the entire source tree. Block at the edge.",
    snippet_raw:"# Nginx\nlocation ~ /\\. { deny all; return 404; }\n# Apache\nRedirectMatch 404 /\\..*$"
  },
  "broken-access-control":{
    title:"Enforce server-side authorization on every endpoint",
    severity:"critical",ease:3,
    why:"Hidden UI buttons aren't security. Every endpoint must verify the caller's role and resource ownership server-side. The classic pattern: middleware + decorator + per-route policy.",
    snippet_raw:"// Express\nfunction requireRole(role){ return (req,res,next)=>{ if(req.user?.role!==role) return res.status(403).end(); next(); }; }\napp.delete('/api/users/:id', requireRole('admin'), handler);"
  },
  "idor-confirmed":{
    title:"Verify resource ownership before returning data",
    severity:"high",ease:3,
    why:"IDOR (broken object-level authorization) means /api/orders/42 returns order 42 even when the caller doesn't own it. Always scope queries by the authenticated user, not just by ID.",
    snippet_raw:"// BAD\nconst order=await Order.findById(req.params.id);\n// GOOD\nconst order=await Order.findOne({ _id: req.params.id, userId: req.user.id });\nif(!order) return res.status(404).end();"
  },
  "rate-limit":{
    title:"Add rate limiting to auth endpoints",
    severity:"medium",ease:4,
    why:"Without rate limits, password endpoints, OTP send, and APIs are wide open to enumeration and brute force. Limit per-IP and per-user. Use a sliding window.",
    snippet_raw:"// Express + rate-limiter-flexible\nconst { RateLimiterMemory } = require('rate-limiter-flexible');\nconst limiter = new RateLimiterMemory({ points: 5, duration: 60 });\napp.post('/login', async (req,res)=>{\n  try{ await limiter.consume(req.ip); }\n  catch(e){ return res.status(429).end(); }\n  // ... auth\n});"
  },
};

// Map a finding object to a FIX_SNIPPETS key. Findings come from many subsystems with
// inconsistent naming — this is the single normalization point. Update both this file
// and popup.js's mapFindingToFixKey when adding a new fix entry.
function mapFindingToFixKey(f){
  if(!f)return null;
  const t=String(f.type||f.id||"").toLowerCase();
  const h=String(f.header||"").toLowerCase();
  const cat=String(f.category||f.pattern||"").toLowerCase();
  if(/strict-transport/.test(h)||/hsts/.test(t))return "missing-hsts";
  if(/content-security-policy/.test(h)||(h==="csp")||/^csp-/.test(t)||/csp/.test(cat))return "missing-csp";
  if(/x-frame/.test(h)||/clickjack/.test(t))return "missing-xframe";
  if(/x-content-type/.test(h)||/nosniff/.test(t))return "missing-xcto";
  if(/referrer/.test(h)||/referrer/.test(t))return "missing-referrer";
  if(/permissions-policy/.test(h)||/feature-policy/.test(t))return "missing-permissions-policy";
  if(/coop|cross-origin-opener/.test(h+t))return "missing-coop";
  if(/httponly/.test(t))return "cookie-no-httponly";
  if(/samesite/.test(t))return "cookie-no-samesite";
  if(/cookie.*secure|!secure/.test(t))return "cookie-no-secure";
  if(/source ?map|\.map\b/.test(t))return "sourcemap-leak";
  if(/sql.*injection|sqli\b/.test(t))return "sql-injection-confirmed";
  if(/ssti/.test(t))return "ssti-confirmed";
  if(/xxe/.test(t))return "xxe-confirmed";
  if(/crlf/.test(t))return "crlf-injection";
  if(/open ?redirect/.test(t))return "open-redirect";
  if(/cors/.test(t))return "cors-wildcard-credentials";
  if(/csrf/.test(t))return "missing-csrf";
  if(/jwt.*alg|alg.*none/.test(t))return "jwt-alg-none";
  if(/graphql.*introspect/.test(t))return "graphql-introspection";
  if(/debug|trace|actuator|telescope|elmah/.test(t))return "exposed-debug";
  if(/directory.*listing|autoindex/.test(t))return "directory-listing";
  if(/tls|cipher|ssl/.test(t))return "weak-tls";
  if(/mixed.*content/.test(t))return "mixed-content";
  if(/sri|integrity/.test(t))return "missing-sri";
  if(/stack.*trace|verbose.*error/.test(t))return "verbose-error";
  if(/\.env|dotfile|exposed.*env/.test(t))return "exposed-env";
  if(/idor/.test(t))return "idor-confirmed";
  if(/bac\b|broken access/.test(t))return "broken-access-control";
  if(/rate.*limit|brute/.test(t))return "rate-limit";
  if(/secret|api ?key|token|password|credential/.test(t))return "exposed-secret";
  return null;
}

function getFixForFinding(f){
  const k=mapFindingToFixKey(f);
  return k?FIX_SNIPPETS[k]:null;
}

if(typeof module!=='undefined'&&module.exports){module.exports={FIX_SNIPPETS,mapFindingToFixKey,getFixForFinding};}
if(typeof globalThis!=='undefined'){globalThis.PENSCOPE_FIX_SNIPPETS=FIX_SNIPPETS;globalThis.PENSCOPE_GET_FIX=getFixForFinding;}
