// PenScope v6.0 — Compliance Mapping (reference copy)
//
// Maps every finding type PenScope produces to the controls it violates across 7
// compliance frameworks (PCI-DSS v4, NESA UAE IAS, SAMA CSF, DESC ISR, ISO 27001,
// OWASP Top 10 2021, CWE). The Compliance Audit panel in Blue mode renders a coverage
// table and exports JSON / PDF.
//
// The live copy is inlined into popup.js (COMPLIANCE_MAP). Treat this file as the
// canonical source: when adding entries, paste the same shape into popup.js.
//
// Schema:
//   key (lower-case finding identifier — same key space as blue-fixes.js)
//   →  array of { framework, control, desc }
//
// Frameworks covered:
//   - PCI-DSS-v4         Payment Card Industry Data Security Standard v4.0
//   - NESA-UAE-IAS       National Electronic Security Authority (UAE) IAS
//   - SAMA-CSF           Saudi Arabian Monetary Authority Cybersecurity Framework
//   - DESC-ISR           Dubai Electronic Security Center Information Security Regulation
//   - ISO-27001          International standard
//   - OWASP-Top10        OWASP Top 10 (2021 edition)
//   - CWE                Common Weakness Enumeration

const COMPLIANCE_MAP={
  "missing-hsts":[
    {framework:"PCI-DSS-v4",  control:"4.2.1",   desc:"Strong cryptography for data in transit"},
    {framework:"NESA-UAE-IAS",control:"T2.3.5",  desc:"Secure communications"},
    {framework:"SAMA-CSF",    control:"3.3.14",  desc:"Cryptography"},
    {framework:"DESC-ISR",    control:"CO.2.1",  desc:"Cryptographic protection"},
    {framework:"ISO-27001",   control:"A.13.2.1",desc:"Information transfer policies and procedures"},
    {framework:"OWASP-Top10", control:"A02:2021",desc:"Cryptographic Failures"},
    {framework:"CWE",         control:"CWE-319", desc:"Cleartext Transmission of Sensitive Information"},
  ],
  "missing-csp":[
    {framework:"PCI-DSS-v4",  control:"6.4.2",   desc:"Web application protection"},
    {framework:"NESA-UAE-IAS",control:"T7.4.3",  desc:"Web application security"},
    {framework:"SAMA-CSF",    control:"3.3.5",   desc:"Application security"},
    {framework:"ISO-27001",   control:"A.14.2.5",desc:"Secure system engineering principles"},
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-693", desc:"Protection Mechanism Failure"},
  ],
  "missing-xframe":[
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-1021",desc:"Improper Restriction of Rendered UI Layers (clickjacking)"},
  ],
  "missing-xcto":[
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-430", desc:"Deployment of Wrong Handler"},
  ],
  "cookie-no-httponly":[
    {framework:"PCI-DSS-v4",  control:"6.2.4",   desc:"Bespoke and custom software protected against attacks"},
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"ISO-27001",   control:"A.14.1.3",desc:"Protecting application services transactions"},
    {framework:"CWE",         control:"CWE-1004",desc:"Sensitive Cookie Without HttpOnly Flag"},
  ],
  "cookie-no-secure":[
    {framework:"PCI-DSS-v4",  control:"4.2.1",   desc:"Strong cryptography for data in transit"},
    {framework:"OWASP-Top10", control:"A02:2021",desc:"Cryptographic Failures"},
    {framework:"CWE",         control:"CWE-614", desc:"Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"},
  ],
  "cookie-no-samesite":[
    {framework:"PCI-DSS-v4",  control:"6.4.2",   desc:"Web application protection"},
    {framework:"OWASP-Top10", control:"A01:2021",desc:"Broken Access Control"},
    {framework:"CWE",         control:"CWE-1275",desc:"Sensitive Cookie with Improper SameSite Attribute"},
  ],
  "sourcemap-leak":[
    {framework:"PCI-DSS-v4",  control:"3.5.1",   desc:"Cryptographic keys protection / no exposure of internals"},
    {framework:"NESA-UAE-IAS",control:"T6.1.7",  desc:"Information leakage prevention"},
    {framework:"SAMA-CSF",    control:"3.3.5",   desc:"Application security"},
    {framework:"ISO-27001",   control:"A.14.2.7",desc:"Outsourced development"},
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-540", desc:"Inclusion of Sensitive Information in Source Code"},
  ],
  "exposed-secret":[
    {framework:"PCI-DSS-v4",  control:"6.5.1",   desc:"Application secrets protection"},
    {framework:"NESA-UAE-IAS",control:"T1.2.4",  desc:"Credential management"},
    {framework:"SAMA-CSF",    control:"3.3.10",  desc:"Identity and access management"},
    {framework:"DESC-ISR",    control:"AM.2.4",  desc:"Privileged access controls"},
    {framework:"ISO-27001",   control:"A.9.4.3", desc:"Password management system"},
    {framework:"OWASP-Top10", control:"A07:2021",desc:"Identification and Authentication Failures"},
    {framework:"CWE",         control:"CWE-798", desc:"Use of Hard-coded Credentials"},
  ],
  "sql-injection-confirmed":[
    {framework:"PCI-DSS-v4",  control:"6.2.4",   desc:"Bespoke and custom software protected against attacks"},
    {framework:"NESA-UAE-IAS",control:"T6.1.2",  desc:"Input validation"},
    {framework:"SAMA-CSF",    control:"3.3.5",   desc:"Application security"},
    {framework:"DESC-ISR",    control:"AC.1.2",  desc:"Application controls"},
    {framework:"ISO-27001",   control:"A.14.2.5",desc:"Secure system engineering principles"},
    {framework:"OWASP-Top10", control:"A03:2021",desc:"Injection"},
    {framework:"CWE",         control:"CWE-89",  desc:"SQL Injection"},
  ],
  "ssti-confirmed":[
    {framework:"OWASP-Top10", control:"A03:2021",desc:"Injection"},
    {framework:"PCI-DSS-v4",  control:"6.2.4",   desc:"Bespoke and custom software protected against attacks"},
    {framework:"NESA-UAE-IAS",control:"T6.1.2",  desc:"Input validation"},
    {framework:"CWE",         control:"CWE-1336",desc:"Improper Neutralization of Special Elements Used in a Template Engine"},
  ],
  "xxe-confirmed":[
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration (and Injection)"},
    {framework:"NESA-UAE-IAS",control:"T6.1.2",  desc:"Input validation"},
    {framework:"CWE",         control:"CWE-611", desc:"Improper Restriction of XML External Entity Reference"},
  ],
  "crlf-injection":[
    {framework:"OWASP-Top10", control:"A03:2021",desc:"Injection"},
    {framework:"CWE",         control:"CWE-93",  desc:"Improper Neutralization of CRLF Sequences"},
  ],
  "open-redirect":[
    {framework:"OWASP-Top10", control:"A01:2021",desc:"Broken Access Control"},
    {framework:"NESA-UAE-IAS",control:"T6.1.5",  desc:"Output encoding / redirect validation"},
    {framework:"CWE",         control:"CWE-601", desc:"URL Redirection to Untrusted Site"},
  ],
  "cors-wildcard-credentials":[
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"PCI-DSS-v4",  control:"6.4.2",   desc:"Web application protection"},
    {framework:"NESA-UAE-IAS",control:"T7.4.3",  desc:"Web application security"},
    {framework:"CWE",         control:"CWE-942", desc:"Permissive Cross-domain Policy with Untrusted Domains"},
  ],
  "missing-csrf":[
    {framework:"OWASP-Top10", control:"A01:2021",desc:"Broken Access Control"},
    {framework:"PCI-DSS-v4",  control:"6.2.4",   desc:"Bespoke and custom software protected against attacks"},
    {framework:"CWE",         control:"CWE-352", desc:"Cross-Site Request Forgery"},
  ],
  "jwt-alg-none":[
    {framework:"OWASP-Top10", control:"A02:2021",desc:"Cryptographic Failures"},
    {framework:"PCI-DSS-v4",  control:"4.2.1",   desc:"Strong cryptography"},
    {framework:"SAMA-CSF",    control:"3.3.14",  desc:"Cryptography"},
    {framework:"CWE",         control:"CWE-347", desc:"Improper Verification of Cryptographic Signature"},
  ],
  "graphql-introspection":[
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-200", desc:"Exposure of Sensitive Information to an Unauthorized Actor"},
  ],
  "exposed-debug":[
    {framework:"PCI-DSS-v4",  control:"2.2.4",   desc:"Only necessary services enabled"},
    {framework:"NESA-UAE-IAS",control:"T7.4.3",  desc:"Web application security"},
    {framework:"SAMA-CSF",    control:"3.3.5",   desc:"Application security"},
    {framework:"ISO-27001",   control:"A.12.1.4",desc:"Separation of development, testing and operational environments"},
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-489", desc:"Active Debug Code"},
  ],
  "directory-listing":[
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-548", desc:"Exposure of Information Through Directory Listing"},
  ],
  "weak-tls":[
    {framework:"PCI-DSS-v4",  control:"4.2.1",   desc:"Strong cryptography for data in transit"},
    {framework:"NESA-UAE-IAS",control:"T2.3.5",  desc:"Secure communications"},
    {framework:"SAMA-CSF",    control:"3.3.14",  desc:"Cryptography"},
    {framework:"DESC-ISR",    control:"CO.2.1",  desc:"Cryptographic protection"},
    {framework:"ISO-27001",   control:"A.10.1.1",desc:"Policy on the use of cryptographic controls"},
    {framework:"OWASP-Top10", control:"A02:2021",desc:"Cryptographic Failures"},
    {framework:"CWE",         control:"CWE-326", desc:"Inadequate Encryption Strength"},
  ],
  "mixed-content":[
    {framework:"OWASP-Top10", control:"A02:2021",desc:"Cryptographic Failures"},
    {framework:"CWE",         control:"CWE-311", desc:"Missing Encryption of Sensitive Data"},
  ],
  "missing-sri":[
    {framework:"OWASP-Top10", control:"A06:2021",desc:"Vulnerable and Outdated Components"},
    {framework:"CWE",         control:"CWE-353", desc:"Missing Support for Integrity Check"},
  ],
  "verbose-error":[
    {framework:"OWASP-Top10", control:"A04:2021",desc:"Insecure Design"},
    {framework:"PCI-DSS-v4",  control:"6.2.4",   desc:"Bespoke and custom software protected against attacks"},
    {framework:"CWE",         control:"CWE-209", desc:"Generation of Error Message Containing Sensitive Information"},
  ],
  "exposed-env":[
    {framework:"PCI-DSS-v4",  control:"3.3.1",   desc:"Sensitive authentication data not retained"},
    {framework:"NESA-UAE-IAS",control:"T6.1.7",  desc:"Information leakage prevention"},
    {framework:"SAMA-CSF",    control:"3.3.10",  desc:"Identity and access management"},
    {framework:"ISO-27001",   control:"A.9.4.3", desc:"Password management system"},
    {framework:"OWASP-Top10", control:"A05:2021",desc:"Security Misconfiguration"},
    {framework:"CWE",         control:"CWE-200", desc:"Exposure of Sensitive Information"},
  ],
  "broken-access-control":[
    {framework:"PCI-DSS-v4",  control:"7.2.1",   desc:"Access controls enforce least privilege"},
    {framework:"NESA-UAE-IAS",control:"T1.3.5",  desc:"Authorization controls"},
    {framework:"SAMA-CSF",    control:"3.3.10",  desc:"Identity and access management"},
    {framework:"DESC-ISR",    control:"AM.2.1",  desc:"Access management"},
    {framework:"ISO-27001",   control:"A.9.4.1", desc:"Information access restriction"},
    {framework:"OWASP-Top10", control:"A01:2021",desc:"Broken Access Control"},
    {framework:"CWE",         control:"CWE-285", desc:"Improper Authorization"},
  ],
  "idor-confirmed":[
    {framework:"OWASP-Top10", control:"A01:2021",desc:"Broken Access Control"},
    {framework:"PCI-DSS-v4",  control:"7.2.1",   desc:"Access controls enforce least privilege"},
    {framework:"CWE",         control:"CWE-639", desc:"Authorization Bypass Through User-Controlled Key"},
  ],
  "rate-limit":[
    {framework:"OWASP-Top10", control:"A04:2021",desc:"Insecure Design"},
    {framework:"PCI-DSS-v4",  control:"8.3.6",   desc:"Account lockout / rate limit"},
    {framework:"CWE",         control:"CWE-307", desc:"Improper Restriction of Excessive Authentication Attempts"},
  ],
};

const COMPLIANCE_FRAMEWORKS=[
  {key:"PCI-DSS-v4",   label:"PCI-DSS v4.0",   color:"#ff3a5c"},
  {key:"NESA-UAE-IAS", label:"NESA UAE IAS",   color:"#ffc53a"},
  {key:"SAMA-CSF",     label:"SAMA CSF",       color:"#3aff8a"},
  {key:"DESC-ISR",     label:"DESC ISR",       color:"#3addc4"},
  {key:"ISO-27001",    label:"ISO 27001",      color:"#3aa8ff"},
  {key:"OWASP-Top10",  label:"OWASP Top 10",   color:"#9b5aff"},
  {key:"CWE",          label:"CWE IDs",        color:"#ff5aaa"},
];

function getComplianceForFinding(f){
  if(!f)return [];
  // Re-use the same key normalization as blue-fixes.js. Caller has already done it.
  const key=f._fixKey||f.type;
  return COMPLIANCE_MAP[key]||[];
}

if(typeof module!=='undefined'&&module.exports){module.exports={COMPLIANCE_MAP,COMPLIANCE_FRAMEWORKS,getComplianceForFinding};}
if(typeof globalThis!=='undefined'){globalThis.PENSCOPE_COMPLIANCE_MAP=COMPLIANCE_MAP;}
