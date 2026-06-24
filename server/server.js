import 'dotenv/config';
/**
 * HHTTPS v4.1 — Role Identity API (PostgreSQL persistence)
 * iamhmn Initiative · daniel.hannuschka@tweakz.de
 * https://github.com/dhannus/HHTTPS
 *
 * v4.1 changes from v4:
 *   ✓ PostgreSQL persistence (sessions, tokens, credentials, etc.)
 *   ✓ Server restarts no longer wipe user state
 *   ✓ All v4 live bugs fixed and consolidated:
 *     - trust proxy 1 (express-rate-limit + nginx)
 *     - CSP allows inline event handlers (Helmet)
 *     - WebAuthn v9 API syntax (startRegistration/Authentication w/o optionsJSON)
 *     - Buffer.from(credentialId, 'base64url') for excludeCredentials/allowCredentials
 *     - authenticatorAttachment removed (allows YubiKey, cross-platform)
 *     - /hhttps/role/declare (no /v2 suffix)
 *   ✓ 14 roles (citizen, journalist, student, teacher, researcher, creative,
 *               developer, medical_professional, caregiver, lawyer, notary,
 *               civil_servant, politician, business, craftsman)
 */

import express           from 'express';
import cors              from 'cors';
import helmet            from 'helmet';
import rateLimit         from 'express-rate-limit';
import { v4 as uuid }    from 'uuid';
import crypto            from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

import {
  generateRegistrationOptions,  verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';

import { ROLES, VERIFICATION_LEVELS, AGE_GROUPS, AGE_VERIFICATION_METHODS,
         VERIFICATION_CHECKS, resolveVerification, ageGroupFromEudiClaims,
         VERIFICATION_METHODS, computeVerification,
         TRUST_BANDS, trustBand, HUMAN_CONFIRMED_THRESHOLD } from './roles.js';
import {
  sendVerificationEmail, verifyEmailToken, verifyEmailCode, classifyDomain,
  sendPlatformRegistrationEmail, sendPlatformVerifiedEmail, sendPlatformRejectedEmail
} from './email.js';
import { loadOrCreateKeys, signToken, verifyToken, getJWKS } from './keys.js';
import { registerWebhook, removeWebhook, listWebhooks, fireEvent } from './webhooks.js';
import * as db from './db.js';

// Role assurance (RAL) + ESCO-only taxonomy + the iamhmn-card issuance bridge.
import {
  resolveRole, resolveEsco, buildRoleClaim, sanitizeCustomRole,
  guardReservedRole, RESERVED_REGISTRY, roleAssuranceDiscovery, CUSTOM_ROLE_ID
} from './roles.taxonomy.js';
import { issueIamhmnCard } from './eudi-verifier/backend-client.js';

// Privacy Pass module (additive, RFC 9576-9578)
import { initPrivacyPass, privacyPassRouter, privacyPassWellKnownRouter }
  from './privacy-pass/index.js';
import { createEudiVerifierRouter } from './eudi-verifier/index.js';

// External provider verification (GitHub for now; extends to ORCID, LinkedIn)
import {
  isGithubConfigured, startGithubVerify, handleGithubCallback,
  getGithubStatus, startGithubVerifyCleanup
} from './external-verify.js';

// ─── Bootstrap ────────────────────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT     = process.env.PORT    || 3000;
const RP_ID    = process.env.RP_ID   || 'hhttps.org';
const ORIGIN   = process.env.ORIGIN  || `https://${RP_ID}`;
const BASE_URL = process.env.BASE_URL || ORIGIN;
const RP_NAME  = 'iamhmn HHTTPS';

// Token TTLs
const ACCESS_TTL  = 3600;          // 1 hour
const REFRESH_TTL = 7 * 86400;     // 7 days
const MACHINE_TTL = 86400;         // 24 hours

// ─── Express setup ────────────────────────────────────────────────────────────
const app = express();

// CRITICAL: trust the Nginx reverse proxy. Without this, express-rate-limit
// crashes on X-Forwarded-For and the entire request fails.
app.set('trust proxy', 1);

// Pretty-print all JSON responses (2-space indent) — much more readable
// both in browsers and in curl/CLI tools. Negligible bandwidth cost.
app.set('json spaces', 2);

/**
 * Smart JSON sender: when a request comes from a browser (Accept: text/html
 * preferred), render the JSON inside a pretty syntax-highlighted HTML page
 * that matches the HHTTPS brand palette. API clients (curl, fetch, JSON.parse-
 * based libraries) get plain JSON as before.
 *
 * Usage:   sendJson(req, res, { ... });
 */
function sendJson(req, res, data, opts = {}) {
  // Negotiate: if Accept explicitly prefers JSON, OR no Accept header at all,
  // OR the request is from curl / a typical API client, return JSON.
  const accept = (req.headers.accept || '').toLowerCase();
  const ua     = (req.headers['user-agent'] || '').toLowerCase();
  const wantsJson =
    accept.includes('application/json') && !accept.includes('text/html') ||
    /curl|wget|httpie|postman|insomnia|fetch/i.test(ua) ||
    req.query.format === 'json';

  // If client clearly wants HTML and isn't an API tool, give them the viewer.
  const wantsHtml =
    !wantsJson && (
      accept.includes('text/html') ||
      req.query.format === 'html'
    );

  if (!wantsHtml) {
    return res.json(data);
  }

  const title = opts.title || 'HHTTPS API';
  const json  = JSON.stringify(data, null, 2);
  // Server-side syntax highlight: wrap keys, strings, numbers, booleans, null
  const highlighted = json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/("(?:[^"\\]|\\.)*")(\s*:)/g, '<span class="k">$1</span>$2')
    .replace(/:\s*("(?:[^"\\]|\\.)*")/g, ': <span class="s">$1</span>')
    .replace(/\b(true|false|null)\b/g, '<span class="b">$1</span>')
    .replace(/(:\s*)(-?\d+(?:\.\d+)?)/g, '$1<span class="n">$2</span>');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} — HHTTPS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT,WONK@9..144,400..600,30..100,0..1&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --cream:   #F8F1E4;  --paper:    #FCFAF5;  --sand: #EDE0C8;
    --terra:   #C97D5B;  --terra-dp: #A86246;  --apricot: #F2B894;
    --sage:    #A8B89E;  --sage-dp:  #889982;  --lavender: #B5A8D9;
    --ink:     #2D2823;  --ink-soft: #4A413A;  --ink-mute: #7A6F62;
    --line:    rgba(45, 40, 35, 0.1);
    --code-bg: #2D2823;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    background: var(--cream);
    color: var(--ink);
    line-height: 1.6;
    min-height: 100vh;
    padding: 32px 20px 80px;
  }
  .wrap { max-width: 980px; margin: 0 auto; }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
    margin-bottom: 24px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--line);
  }
  .logo {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    text-decoration: none;
    color: var(--ink);
  }
  .logo-mark {
    width: 32px; height: 32px;
    border-radius: 9px;
    background: linear-gradient(135deg, var(--terra), var(--apricot));
    position: relative;
  }
  .logo-mark::after {
    content: 'H';
    position: absolute; inset: 0;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Fraunces', serif; font-weight: 600; font-size: 18px;
    color: var(--paper);
  }
  .logo-text {
    font-family: 'Fraunces', serif;
    font-variation-settings: "SOFT" 100, "WONK" 1;
    font-weight: 500;
    font-size: 20px;
  }
  .meta {
    display: inline-flex; gap: 8px; flex-wrap: wrap;
  }
  .badge {
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 100px;
    padding: 6px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--ink-soft);
  }
  .badge .dot {
    display: inline-block; width: 6px; height: 6px;
    border-radius: 50%; background: var(--sage-dp);
    margin-right: 6px; vertical-align: middle;
  }
  h1 {
    font-family: 'Fraunces', serif;
    font-variation-settings: "SOFT" 50, "WONK" 1;
    font-weight: 400;
    font-size: 36px;
    letter-spacing: -0.02em;
    margin-bottom: 4px;
  }
  h1 em {
    font-style: italic;
    color: var(--terra);
    font-variation-settings: "SOFT" 100, "WONK" 1;
  }
  .sub {
    color: var(--ink-mute);
    font-size: 14px;
    margin-bottom: 28px;
    font-family: 'JetBrains Mono', monospace;
  }
  .toolbar {
    display: flex; gap: 8px; flex-wrap: wrap;
    margin-bottom: 16px;
  }
  .btn {
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 100px;
    padding: 8px 16px;
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 500;
    color: var(--ink-soft);
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.15s;
  }
  .btn:hover {
    background: var(--sand);
    color: var(--ink);
    transform: translateY(-1px);
  }
  .btn.primary {
    background: var(--ink);
    color: var(--cream);
    border-color: var(--ink);
  }
  .btn.primary:hover {
    background: var(--terra-dp);
    border-color: var(--terra-dp);
    color: var(--cream);
  }
  pre {
    background: var(--code-bg);
    color: #F2E8D5;
    border-radius: 14px;
    padding: 24px 28px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    line-height: 1.7;
    overflow-x: auto;
    box-shadow: 0 4px 20px rgba(45, 40, 35, 0.08);
    tab-size: 2;
  }
  .k { color: #F2B894; }     /* keys */
  .s { color: #B8C9A8; }     /* strings */
  .n { color: #DDB4B0; }     /* numbers */
  .b { color: #B5A8D9; font-style: italic; } /* booleans / null */
  footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--line);
    color: var(--ink-mute);
    font-size: 12px;
    font-family: 'JetBrains Mono', monospace;
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
  }
  footer a { color: var(--ink-soft); text-decoration: none; }
  footer a:hover { color: var(--terra-dp); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <a class="logo" href="/">
      <div class="logo-mark"></div>
      <span class="logo-text">HHTTPS</span>
    </a>
    <div class="meta">
      <span class="badge"><span class="dot"></span>v0.5.0</span>
      <span class="badge">${req.path}</span>
    </div>
  </header>

  <h1>${title}</h1>
  <p class="sub">${opts.subtitle || 'Open protocol — open API. JSON below, formatted for humans.'}</p>

  <div class="toolbar">
    <a class="btn primary" href="${req.path}?format=json" target="_blank">
      <span>↓</span> Raw JSON
    </a>
    <button class="btn" id="copyBtn" onclick="copyJson()">
      <span>⎘</span> <span id="copyLabel">Kopieren</span>
    </button>
    <a class="btn" href="/spec">Spec</a>
    <a class="btn" href="https://iamhmn.org" target="_blank">iamhmn.org →</a>
  </div>

  <pre id="json">${highlighted}</pre>

  <footer>
    <span>iamhmn Initiative</span>
    <a href="https://github.com/dhannus/HHTTPS">GitHub</a>
    <a href="/.well-known/jwks.json">JWKS</a>
    <a href="/.well-known/hhttps-configuration">Discovery</a>
    <a href="/hhttps/info">Info</a>
    <a href="/hhttps/roles">Roles</a>
  </footer>
</div>
<script>
async function copyJson() {
  try {
    const r = await fetch('${req.path}?format=json');
    const t = await r.text();
    await navigator.clipboard.writeText(t);
    document.getElementById('copyLabel').textContent = 'Kopiert!';
    setTimeout(() => { document.getElementById('copyLabel').textContent = 'Kopieren'; }, 1500);
  } catch (e) {
    alert('Kopieren fehlgeschlagen: ' + e.message);
  }
}
</script>
</body>
</html>`);
}

app.use(express.json({ limit: '2mb' }));

app.use(cors({
  exposedHeaders: [
    'HHTTPS-Protocol-Version','HHTTPS-Status','HHTTPS-Human',
    'HHTTPS-Actor-Type','HHTTPS-Role','HHTTPS-Role-Label',
    'HHTTPS-Role-Level','HHTTPS-Trust-Score',
    'HHTTPS-Issuer','HHTTPS-Method',
    'HHTTPS-Machine-Operator','HHTTPS-Machine-Purpose',
    'HHTTPS-Age-Group','HHTTPS-Age-Verified','HHTTPS-Age-Method'
  ]
}));

// CRITICAL: scriptSrcAttr must allow 'unsafe-inline' so the existing onclick=
// handlers in index.html keep working. Without this, all buttons silently fail.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", 'unpkg.com', 'fonts.googleapis.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      fontSrc:    ["'self'", 'fonts.gstatic.com'],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", 'data:']
    }
  },
  crossOriginEmbedderPolicy: false  // required for WebAuthn
}));

// Rate limiters
const rl = (max, windowMs = 60000) => rateLimit({
  max, windowMs, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({
    error: 'Rate limit exceeded.', retryAfter: Math.ceil(windowMs / 1000)
  })
});

const limit = {
  global:   rl(300),
  check:    rl(120),
  // webauthn: 40 attempts / 15 min — covers normal registration retry, lost
  // typo-fingerprint attempts, and re-auth roundtrips without being stingy.
  webauthn: rl(40, 15 * 60_000),
  // email: 30 sends / 60 min per IP. Generous on purpose: a single user
  // who triggers session/start + send + confirm + retries can easily hit
  // 5-8 requests; 30 leaves ample headroom for normal demos and dev work.
  email:    rl(30, 60 * 60_000),
  revoke:   rl(30),
  webhooks: rl(20, 60 * 60_000),
  machine:  rl(60)
};

app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/hhttps/info') return next();
  limit.global(req, res, next);
});

// ─── HHTTPS identity cookie (additive convenience feature) ────────────────────
//
// The protocol is and remains client-driven: the authoritative identity is the
// token the browser holds (localStorage) and presents to platforms. This cookie
// changes nothing about that.
//
// What it adds: after the user authenticates on hhttps.org, we ALSO mirror the
// freshly issued token into an HttpOnly cookie scoped to hhttps.org. That lets
// the issuer's own pages surface the logged-in identity as HHTTPS-* response
// headers on the document request itself — so a developer can read their live
// role/trust straight from the Network tab (or `curl --cookie`) without wiring
// up a token-echo call. It is a developer-experience feature of the website,
// not a change to the wire protocol: platforms never rely on this cookie, and
// it is scoped to hhttps.org only (SameSite=Lax, HttpOnly, Secure).
const ID_COOKIE = 'hhttps_identity';

function setIdentityCookie(res, token) {
  res.cookie(ID_COOKIE, token, {
    httpOnly: true,
    secure:   true,
    sameSite: 'lax',
    maxAge:   ACCESS_TTL * 1000,
    path:     '/'
  });
}
function clearIdentityCookie(res) {
  res.clearCookie(ID_COOKIE, { path: '/' });
}
// Minimal single-cookie reader (avoids adding the cookie-parser dependency).
function readIdentityCookie(req) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    if (part.slice(0, i).trim() === ID_COOKIE) {
      return decodeURIComponent(part.slice(i + 1).trim());
    }
  }
  return null;
}

// Advertise HHTTPS on every static/landing response. If the visitor carries a
// valid identity cookie (i.e. they logged in on hhttps.org), surface their real
// identity in the headers; otherwise emit the issuer-level headers. We never
// invent identity — headers reflect a verified token or nothing.
app.use((req, res, next) => {
  res.setHeader('HHTTPS-Protocol-Version', '0.5.0');

  const cookieToken = readIdentityCookie(req);
  if (cookieToken) {
    try {
      const d = verifyToken(cookieToken);
      if (d.sub !== 'refresh' && !(d.actorType === 'bot')) {
        setHHTPPS(res, {
          status:     'verified',
          human:      true,
          actorType:  'human',
          role:       d.role,
          roleLevel:  d.roleLevel,
          trustScore: d.trustScore ?? 0,
          method:     d.method || 'webauthn-passkey',
          ageGroup:              d.age_group || null,
          ageVerified:           d.age_group ? (d.age_verified ?? false) : null,
          ageVerificationMethod: d.age_verification_method || null
        });
        return next();
      }
    } catch {
      // Expired/invalid cookie token → fall through to issuer headers and clear it.
      clearIdentityCookie(res);
    }
  }

  // No (valid) identity cookie: state that this origin is an HHTTPS issuer.
  res.setHeader('HHTTPS-Status', 'issuer');
  res.setHeader('HHTTPS-Issuer', `hhttps://${RP_ID}`);
  next();
});

app.use(express.static(join(__dirname, 'public')));

// Privacy Pass routes (additive, see privacy-pass/index.js)
app.use(privacyPassWellKnownRouter);
app.use('/privacy-pass', privacyPassRouter);

// EUDI verification orchestrator (age + eID identity, additive, see eudi-verifier/index.js).
// setIdentityCookie is injected so the browser-facing /eudi/*/status handlers can
// mirror the upgraded token into the httpOnly identity cookie (fixes the bug where
// EUDI claims never reached the browser cookie — the upgrade runs server-to-server).
app.use('/eudi', createEudiVerifierRouter({ setIdentityCookie }));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function setHHTPPS(res, opts = {}) {
  const { status = 'unverified', human = false, actorType = 'unknown',
          role = null, roleLevel = null, trustScore = 0, token = null,
          method = 'none', machineOperator = null, machinePurpose = null,
          ageGroup = null, ageVerified = null, ageVerificationMethod = null,
          verifiedMethods = null, domainValue = null } = opts;

  // HTTP header values must be ASCII (Latin-1). German role labels contain
  // umlauts (Bürger, Schüler, Pädagoge), which make res.setHeader throw
  // ERR_INVALID_CHAR. Transliterate umlauts and strip any remaining non-ASCII
  // and control chars so no header value can ever crash the response.
  const hdrSafe = (v) => String(v)
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue')
    .replace(/Ä/g, 'Ae').replace(/Ö/g, 'Oe').replace(/Ü/g, 'Ue')
    .replace(/ß/g, 'ss')
    .replace(/[^\x20-\x7E]/g, '')   // drop any remaining non-ASCII / control chars
    .trim();

  res.setHeader('HHTTPS-Protocol-Version', '0.5.0');
  res.setHeader('HHTTPS-Status',           hdrSafe(status));
  res.setHeader('HHTTPS-Human',            String(human));
  res.setHeader('HHTTPS-Actor-Type',       hdrSafe(actorType));
  res.setHeader('HHTTPS-Method',           hdrSafe(method));
  res.setHeader('HHTTPS-Trust-Score',      String(trustScore));
  res.setHeader('HHTTPS-Issuer',           `hhttps://${RP_ID}`);
  if (role)            { res.setHeader('HHTTPS-Role', hdrSafe(role)); res.setHeader('HHTTPS-Role-Label', hdrSafe(ROLES[role]?.label || role)); }
  if (roleLevel)         res.setHeader('HHTTPS-Role-Level', hdrSafe(roleLevel));
  // NOTE: the access token is intentionally NOT exposed as an HHTTPS-Token
  // response header. A full ES256 JWT (now carrying role + age_group +
  // verification_status + claimed_as) is several KB and overflows nginx's
  // default proxy header buffer ("upstream sent too big header" → 502).
  // The token travels in the JSON body (hhttps.token) and the identity cookie,
  // which is the correct transport. Keeping it out of headers keeps responses
  // small and within proxy limits.
  if (machineOperator)   res.setHeader('HHTTPS-Machine-Operator', hdrSafe(machineOperator));
  if (machinePurpose)    res.setHeader('HHTTPS-Machine-Purpose',  hdrSafe(machinePurpose));
  // Age group is an orthogonal, optional claim — surface it only when present.
  if (ageGroup)              res.setHeader('HHTTPS-Age-Group', hdrSafe(ageGroup));
  if (ageVerified !== null)  res.setHeader('HHTTPS-Age-Verified', String(ageVerified));
  if (ageVerificationMethod) res.setHeader('HHTTPS-Age-Method', hdrSafe(ageVerificationMethod));

  // Verification methods (v0.5) — the trademark "HHTTPS fields in headers/cookie".
  // Each confirmed method appears as its own official HHTTPS-<Method>-Verified
  // header plus a comma-separated roll-up, exactly mirroring the age-group fields.
  // The trust SCORE stays in HHTTPS-Trust-Score (API only); the UI shows methods,
  // never the number. Adding a method needs nothing here — it derives from the
  // VERIFICATION_METHODS registry in roles.js.
  if (Array.isArray(verifiedMethods) && verifiedMethods.length) {
    res.setHeader('HHTTPS-Verified-Methods', hdrSafe(verifiedMethods.join(',')));
    for (const id of verifiedMethods) {
      const m = VERIFICATION_METHODS[id];
      if (!m || !m.header) continue;
      res.setHeader(m.header, 'true');
      // Methods that carry a value (domain → the domain name) expose it too.
      if (m.valueHeader && id === 'domain' && domainValue) {
        res.setHeader(m.valueHeader, hdrSafe(domainValue));
      }
    }
  }
}

// ─── Signature helpers (Phase 2.5: Domain-bound slugs) ───────────────────────

// Normalize a hostname to its "apex" form for binding purposes.
// reddit.com, www.reddit.com, old.reddit.com, np.reddit.com → "reddit.com"
// This is heuristic and uses a small public-suffix list for the common cases.
// Not as bulletproof as the full PSL but covers 99% of real domains.
const TWO_PART_TLDS = new Set([
  'co.uk', 'co.jp', 'co.kr', 'co.nz', 'co.za', 'co.in', 'co.il',
  'com.au', 'com.br', 'com.cn', 'com.mx', 'com.tr', 'com.tw', 'com.ar',
  'org.uk', 'org.au', 'net.au', 'gov.uk', 'gov.au', 'ac.uk', 'ac.jp',
  'or.jp', 'ne.jp'
]);

function normalizeApexDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return null;
  let h = hostname.toLowerCase().trim();
  // Strip protocol and path if accidentally included
  h = h.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  if (!/^[a-z0-9.\-]+$/.test(h)) return null;
  const parts = h.split('.').filter(Boolean);
  if (parts.length < 2) return parts.join('.') || null;
  // Check two-part TLD
  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join('.');
    if (TWO_PART_TLDS.has(lastTwo)) {
      return parts.slice(-3).join('.');
    }
  }
  return parts.slice(-2).join('.');
}

// Slug generator: 12-char Crockford Base32 with prefix "hp-" (HHTTPS signature).
// Avoids 0/O/1/I confusion. Example: "hp-7K2-XQ9NMR-3F"
const SLUG_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
function generateSlug() {
  const bytes = crypto.randomBytes(12);
  let out = 'hp-';
  for (let i = 0; i < 10; i++) {
    out += SLUG_ALPHABET[bytes[i] % SLUG_ALPHABET.length];
    if (i === 2 || i === 6) out += '-';
  }
  return out;
}

// Text hashing: strict (byte-exact) vs loose (normalized)
function hashTextStrict(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}
function hashTextLoose(text) {
  const normalized = (text || '').trim().replace(/\s+/g, ' ').toLowerCase();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

async function issueAccessToken(payload) {
  const jti = uuid();
  const tok = signToken({
    jti, iss: `https://${RP_ID}`, hhttps_iss: `hhttps://${RP_ID}`,
    sub: 'human-verified', human: true, actorType: 'human',
    // `iat` is set automatically by jsonwebtoken (RFC 7519 standard claim).
    ...payload
  }, { expiresIn: ACCESS_TTL });

  await db.tokens.create({
    jti, type: 'access',
    userId:     payload.userId,
    role:       payload.role,
    roleLevel:  payload.roleLevel,
    trustScore: payload.trustScore,
    method:     payload.method,
    deviceType: payload.deviceType,
    ttlMs:      ACCESS_TTL * 1000
  });
  await db.stats.increment('tokens_issued');
  return { token: tok, jti };
}

async function issueRefreshToken(userId, credId, role, surface = {}) {
  const jti = uuid();
  const tok = signToken({
    jti, iss: `https://${RP_ID}`, hhttps_iss: `hhttps://${RP_ID}`,
    sub: 'refresh', userId, credId, role,
    // v0.5: the verification surface rides inside the SIGNED refresh token, so the
    // session may expire and the identity still rehydrates statelessly on refresh.
    // Nothing is persisted server-side (zero-PII) — the signature is the integrity.
    ...(Array.isArray(surface.verifiedMethods) ? { verified_methods: surface.verifiedMethods } : {}),
    ...(surface.trustScore != null ? { trustScore: surface.trustScore } : {}),
    ...(surface.emailDomain ? { emailDomain: surface.emailDomain } : {})
    // `iat` is set automatically by jsonwebtoken (RFC 7519 standard claim).
  }, { expiresIn: REFRESH_TTL });
  await db.refreshTokens.create({
    jti, userId, credentialId: credId, role, ttlMs: REFRESH_TTL * 1000
  });
  return tok;
}

async function checkTokenValid(token) {
  const decoded = verifyToken(token);
  if (await db.revokedTokens.has(decoded.jti)) throw new Error('Token revoked');
  if (decoded.sub === 'refresh') {
    if (!await db.refreshTokens.get(decoded.jti)) throw new Error('Refresh-Token nicht aktiv');
  } else {
    if (!await db.tokens.exists(decoded.jti)) throw new Error('Token nicht aktiv');
  }
  return decoded;
}

// Periodic cleanup (every 5 minutes)
setInterval(async () => {
  try {
    const r = await db.cleanupExpired();
    const total = (r.deleted_tokens || 0) + (r.deleted_refresh || 0) +
                  (r.deleted_sessions || 0) + (r.deleted_challenges || 0) +
                  (r.deleted_emails || 0);
    if (total > 0) console.log(`[CLEANUP] removed ${total} expired records`);
  } catch (err) {
    console.error('[CLEANUP] failed:', err.message);
  }
}, 5 * 60 * 1000);

// ─── .well-known ─────────────────────────────────────────────────────────────

app.get('/.well-known/hhttps-configuration', (req, res) => {
  sendJson(req, res, {
    issuer:                  `https://${RP_ID}`,
    hhttps_issuer:           `hhttps://${RP_ID}`,
    protocol_version:        '0.5.0',
    base_url:                BASE_URL,
    jwks_uri:                `${BASE_URL}/.well-known/jwks.json`,
    check_endpoint:          `${BASE_URL}/hhttps/check`,
    registration_endpoint:   `${BASE_URL}/hhttps/webauthn/register/start`,
    authentication_endpoint: `${BASE_URL}/hhttps/webauthn/auth/start`,
    token_refresh_endpoint:  `${BASE_URL}/hhttps/token/refresh`,
    revocation_endpoint:     `${BASE_URL}/hhttps/revoke`,
    roles_endpoint:          `${BASE_URL}/hhttps/roles`,
    machine_endpoint:        `${BASE_URL}/hhttps/machine/register`,
    webhooks_endpoint:       `${BASE_URL}/hhttps/webhooks`,
    stats_endpoint:          `${BASE_URL}/hhttps/stats`,
    token_ttl:               ACCESS_TTL,
    refresh_ttl:             REFRESH_TTL,
    supported_algorithms:    ['ES256'],
    supported_roles:         'esco-dynamic (no fixed catalogue)',
    roles_model:             { base_identity: ROLES.citizen.id,
                               esco_suggest: `${BASE_URL}/hhttps/esco/suggest`,
                               discovery:    `${BASE_URL}/.well-known/hhttps-role-assurance` },
    supported_verification:  Object.keys(VERIFICATION_LEVELS)
  }, {
    title:    'Discovery',
    subtitle: 'Service-discovery endpoint — gives clients all URLs they need to interact with this issuer.'
  });
});

app.get('/.well-known/jwks.json', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  sendJson(req, res, getJWKS(), {
    title:    'JWKS — Public Keys',
    subtitle: 'Public keys used to verify HHTTPS tokens issued by this server (RFC 7517).'
  });
});

// Role-assurance discovery: RAL tiers, claim format, reserved registry.
app.get('/.well-known/hhttps-role-assurance', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json(roleAssuranceDiscovery(RP_ID));
});

// ESCO occupation typeahead (server-side proxy → avoids CORS, keeps the browser
// dependency-free). Returns up to 8 { label, isco08, escoUri, reserved } hits.
app.get('/hhttps/esco/suggest', async (req, res) => {
  const q = String(req.query.q || '').trim();
  const lang = (String(req.query.lang || 'de') === 'en') ? 'en' : 'de';
  if (q.length < 2) return res.json({ results: [] });
  try {
    const url = `https://ec.europa.eu/esco/api/search?type=occupation&language=${lang}` +
                `&text=${encodeURIComponent(q)}&full=false&limit=8`;
    const r = await fetch(url, { headers: { accept: 'application/json' } });
    if (!r.ok) return res.json({ results: [] });
    const j = await r.json();
    const hits = j?._embedded?.results || [];
    const results = hits.map(h => {
      const label = h.title || h.preferredLabel || '';
      const isco08 = h.code || null;
      const g = guardReservedRole(label, isco08);
      return { label, isco08, escoUri: h.uri || null, reserved: g.reserved, reservedKey: g.key || null };
    }).filter(x => x.label);
    res.json({ results });
  } catch (e) {
    res.json({ results: [], error: 'esco_unreachable' });
  }
});

// ─── Info ─────────────────────────────────────────────────────────────────────

app.get('/hhttps/info', async (req, res) => {
  setHHTPPS(res, { status: 'info', actorType: 'api' });

  const counts = await Promise.all([
    db.credentials.count(), db.tokens.count(), db.refreshTokens.count(),
    db.sessions.count(), db.revokedTokens.count(), db.machineOperators.count()
  ]);

  sendJson(req, res, {
    protocol: 'HHTTPS — Human-verified HTTPS', version: '0.5.0',
    initiative: 'iamhmn', contact: 'daniel.hannuschka@tweakz.de',
    github: 'github.com/dhannus/HHTTPS', demo: 'https://hhttps.org',
    features: ['webauthn', 'roles-esco-dynamic', 'email-verification', 'refresh-tokens',
               'token-revocation', 'machine-tokens', 'webhooks', 'jwks',
               'discovery', 'postgres-persistence'],
    security: { algorithm: 'ES256', helmet: true, rateLimiting: true,
                revocation: true, persistence: 'postgres' },
    stats: {
      registeredPasskeys:  counts[0],
      activeTokens:        counts[1],
      activeRefreshTokens: counts[2],
      activeSessions:      counts[3],
      revokedTokens:       counts[4],
      machineOperators:    counts[5]
    },
    roles_model: 'esco-dynamic',
    base_identity: { id: ROLES.citizen.id, label: ROLES.citizen.label, icon: ROLES.citizen.icon },
    endpoints: {
      'GET  /.well-known/hhttps-configuration': 'Discovery',
      'GET  /.well-known/jwks.json':            'Public key (JWKS)',
      'POST /hhttps/check':                     '★ Human/machine + role check',
      'GET  /hhttps/roles':                     'Role registry (15 roles)',
      'POST /hhttps/webauthn/register/{start,finish}': 'Passkey registration',
      'POST /hhttps/webauthn/auth/{start,finish}':     'Passkey authentication',
      'POST /hhttps/token/refresh':             'Refresh access token',
      'POST /hhttps/session/email/start':       'Create email-only session (no WebAuthn required)',
      'POST /hhttps/email/send':                'Send email verification',
      'GET  /hhttps/email/verify':              'Confirm email',
      'POST /hhttps/role/declare':              'Declare role → token',
      'POST /hhttps/revoke':                    'Revoke token',
      'POST /hhttps/validate':                  'Validate token',
      'POST /hhttps/machine/{register,token}':  'Machine token issuance',
      'GET/POST/DELETE /hhttps/webhooks':       'Webhook management',
      'GET  /hhttps/stats':                     'Public aggregated stats'
    }
  }, {
    title:    'API Info',
    subtitle: 'Current server state, available features, statistics, and endpoint catalog.'
  });
});

// ─── Core Check ──────────────────────────────────────────────────────────────

app.post('/hhttps/check', limit.check, async (req, res) => {
  await db.stats.increment('check_calls');
  const token = req.headers['hhttps-token'] ||
                req.headers['authorization']?.replace('Bearer ', '') ||
                req.body?.token;

  if (!token) {
    setHHTPPS(res, { status: 'unverified', human: false, actorType: 'unknown' });
    return res.json({
      hhttps: { version: '0.5.0', human: false, actorType: 'unknown',
                status: 'unverified', message: 'No HHTTPS token. Please verify.' }
    });
  }

  try {
    const d = await checkTokenValid(token);

    if (d.sub === 'machine') {
      await db.stats.increment('machine_checks');
      setHHTPPS(res, { status: 'verified', human: false, actorType: 'bot',
                       method: 'machine-token', machineOperator: d.operatorId,
                       machinePurpose: d.purpose });
      return res.json({
        hhttps: { version: '0.5.0', human: false, actorType: 'bot',
                  status: 'verified', trustScore: 0, method: 'machine-token' },
        machine: { operatorId: d.operatorId, operatorName: d.operatorName,
                   purpose: d.purpose, issuedAt: new Date(d.iat * 1000).toISOString() }
      });
    }

    const methods = Array.isArray(d.verified_methods) ? d.verified_methods : [];

    setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                     role: d.role || null, roleLevel: d.roleLevel || null, trustScore: d.trustScore,
                     token, method: d.method,
                     verifiedMethods: methods.length ? methods : null,
                     domainValue: d.domain_name || null,
                     ageGroup:              d.age_group || null,
                     ageVerified:           d.age_group ? (d.age_verified ?? false) : null,
                     ageVerificationMethod: d.age_verification_method || null });

    return res.json({
      hhttps: { version: '0.5.0', status: 'verified', human: true, actorType: 'human',
                method: d.method, trustScore: d.trustScore,
                verifiedMethods: methods,
                issuedAt: new Date(d.iat * 1000).toISOString(),
                expiresAt: new Date(d.exp * 1000).toISOString(), issuer: d.iss },
      verification: {
        methods: methods.map(id => ({
          id, label: VERIFICATION_METHODS[id]?.label || id, verified: true,
          value: id === 'domain' ? (d.domain_name || null)
               : id === 'age'    ? (d.age_group || null) : null
        }))
      },
      // A professional role is present ONLY when it arrived via an EUDI (Q)EAA.
      ...(d.role ? {
        role: { id: d.role, label: ROLES[d.role]?.label, icon: ROLES[d.role]?.icon,
                description: ROLES[d.role]?.description, level: d.roleLevel,
                levelLabel: (VERIFICATION_LEVELS[d.roleLevel]?.label) || null,
                trustScore: d.trustScore, privileges: ROLES[d.role]?.privileges }
      } : {}),
      ...(d.age_group ? {
        ageGroup: {
          id:          d.age_group,
          label:       (AGE_GROUPS[d.age_group]?.label) || d.age_group,
          verified:    d.age_verified ?? false,
          method:      d.age_verification_method || null,
          methodLabel: AGE_VERIFICATION_METHODS[d.age_verification_method]?.label || null
        }
      } : {})
    });
  } catch (e) {
    setHHTPPS(res, { status: 'invalid', human: false, actorType: 'unknown' });
    return res.status(401).json({ hhttps: { status: 'invalid', human: false }, error: e.message });
  }
});

// ─── Sign-Text / Verify-Text (Beta mode: bind token to specific text) ────────
// These endpoints allow a verified user to cryptographically bind a HHTTPS
// token to a specific piece of text. The result is a short signature that,
// when later combined with the same text, proves: "this exact text was
// approved by the holder of this token". Used by the browser extension's
// Beta signing mode for sensitive content (contracts, formal statements).

app.post('/hhttps/sign-text', limit.check, async (req, res) => {
  const token = req.headers['hhttps-token'] ||
                req.headers['authorization']?.replace('Bearer ', '') ||
                req.body?.token;
  const text = req.body?.text;

  if (!token) return res.status(400).json({ error: 'token required' });
  if (typeof text !== 'string' || text.length === 0) {
    return res.status(400).json({ error: 'text required' });
  }
  if (text.length > 100_000) {
    return res.status(400).json({ error: 'text too long (max 100k chars)' });
  }

  try {
    // First, verify the token is currently valid (signature + revocation + expiry)
    const d = await checkTokenValid(token);
    if (d.sub === 'machine') {
      return res.status(403).json({ error: 'machine tokens cannot sign text' });
    }

    // Build a deterministic content hash
    const textHash = crypto.createHash('sha256').update(text, 'utf8').digest('hex');

    // Issue a separate small JWT that binds the user's token JTI to the text hash.
    // We keep this short-lived and refer to the original token via its jti.
    const signature = signToken({
      sub:        'text-signature',
      tokenJti:   d.jti,
      textHash,
      role:       d.role,
      roleLevel:  d.roleLevel,
      trustScore: d.trustScore,
      // `iat` is set automatically by jsonwebtoken (RFC 7519 standard claim).
      exp:        d.exp,    // matches the underlying token's expiry
      iss:        d.iss,
      hhttps_iss: d.hhttps_iss
    });

    return res.json({
      hhttps:    { version: '0.5.0', mode: 'beta-text-bound' },
      signature,                       // the JWT that proves text + identity
      textHash,                        // sha256 hex of the signed text
      role: {
        id: d.role,
        label: (ROLES[d.role] || ROLES.citizen).label,
        icon:  (ROLES[d.role] || ROLES.citizen).icon,
        level: d.roleLevel,
        trustScore: d.trustScore
      },
      validUntil: new Date(d.exp * 1000).toISOString()
    });
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }
});

app.post('/hhttps/verify-text', limit.check, async (req, res) => {
  const { signature, text } = req.body || {};
  if (!signature || typeof text !== 'string') {
    return res.status(400).json({ error: 'signature and text required' });
  }

  try {
    const d = verifyToken(signature);
    if (d.sub !== 'text-signature') {
      return res.status(400).json({ error: 'not a text signature' });
    }

    // Recompute the hash and compare
    const actualHash = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
    const hashMatches = actualHash === d.textHash;

    // Also verify the original token has not been revoked (lookup via jti)
    const revoked = await db.revokedTokens.has(d.tokenJti);

    if (!hashMatches) {
      return res.json({
        hhttps: { status: 'invalid', reason: 'text-modified' },
        match:  false,
        message: 'The text was modified after signing.'
      });
    }
    if (revoked) {
      return res.json({
        hhttps: { status: 'revoked' },
        match:  true,
        message: 'Signature was revoked.'
      });
    }
    if (d.exp * 1000 < Date.now()) {
      return res.json({
        hhttps: { status: 'expired', match: true },
        match:  true,
        message: 'Signature expired (text unchanged).'
      });
    }

    const roleDef = ROLES[d.role] || ROLES.citizen;
    return res.json({
      hhttps: { version: '0.5.0', status: 'verified', mode: 'beta-text-bound', match: true },
      match: true,
      role: {
        id: d.role,
        label: roleDef.label,
        icon:  roleDef.icon,
        level: d.roleLevel,
        trustScore: d.trustScore
      },
      signedAt:   new Date(d.iat  * 1000).toISOString(),
      validUntil: new Date(d.exp * 1000).toISOString()
    });
  } catch (e) {
    return res.status(401).json({ hhttps: { status: 'invalid' }, error: e.message });
  }
});

// ─── Signatures (Phase 2.5: domain-bound, slug-based) ───────────────────────
// Replaces the v0.5.0 raw-token-in-marker approach. Now:
//   - Marker is a short slug (e.g. #hhttps:s:hp-7K2-XQ9NMR-3F)
//   - Slug references a DB record, never reveals the access token
//   - Each signature is single-use creation, but verifiable forever
//   - Binding to apex domain prevents cross-site copy/paste theft
//   - Two text hashes (strict + loose) catch tampering with different tolerance

const VALID_BINDING_TYPES = new Set(['web', 'email', 'document']);

app.post('/hhttps/signatures', limit.check, async (req, res) => {
  const token = req.headers['hhttps-token'] ||
                req.headers['authorization']?.replace('Bearer ', '') ||
                req.body?.token;
  const { text, mode, bindingType, domain } = req.body || {};

  if (!token) return res.status(400).json({ error: 'token required' });
  if (typeof text !== 'string' || text.length === 0) {
    return res.status(400).json({ error: 'text required' });
  }
  if (text.length > 100_000) {
    return res.status(400).json({ error: 'text too long (max 100k chars)' });
  }
  const bType = VALID_BINDING_TYPES.has(bindingType) ? bindingType : 'web';
  if (bType === 'web' && (!domain || typeof domain !== 'string')) {
    return res.status(400).json({ error: 'domain required for web binding' });
  }

  try {
    const d = await checkTokenValid(token);
    if (d.sub === 'machine') {
      return res.status(403).json({ error: 'machine tokens cannot create signatures' });
    }

    const apex = bType === 'web' ? normalizeApexDomain(domain) : null;
    if (bType === 'web' && !apex) {
      return res.status(400).json({ error: 'invalid domain format' });
    }

    // Generate unique slug (retry if collision — extremely rare with 32^10 space)
    let slug, attempts = 0;
    do {
      slug = generateSlug();
      attempts++;
      if (attempts > 5) {
        return res.status(500).json({ error: 'slug generation failed; please retry' });
      }
    } while (await db.signatures.slugExists(slug) || await db.signatures.isReservedSlug(slug));

    const roleDef = ROLES[d.role] || ROLES.citizen;
    const vlevel  = VERIFICATION_LEVELS[d.roleLevel] || {};

    const textPreview = text.length <= 120 ? text : text.slice(0, 117) + '…';

    await db.signatures.create({
      id:              slug,
      signerId:        d.uid || d.userId || d.sub,   // pseudonymous user id
      role:            d.role,
      roleLabel:       roleDef.label,
      roleIcon:        roleDef.icon,
      trustScore:      d.trustScore,
      level:           d.roleLevel,
      levelLabel:      vlevel.label,
      bindingType:     bType,
      boundDomain:     apex,
      textHashStrict:  hashTextStrict(text),
      textHashLoose:   hashTextLoose(text),
      textLength:      text.length,
      textPreview,
      issuer:          `hhttps://${RP_ID}`
    });

    await db.stats.increment('signatures_created');

    return res.json({
      hhttps: { version: '0.5.0', mode: 'slug' },
      id:      slug,
      marker:  `#hhttps:s:${slug}`,
      url:     `${BASE_URL}/s/${slug}`,
      role: {
        id:    d.role,
        label: roleDef.label,
        icon:  roleDef.icon,
        trustScore: d.trustScore
      },
      binding: {
        type:   bType,
        domain: apex
      },
      createdAt: new Date().toISOString()
    });
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }
});

// Public verify endpoint — anyone can check a slug.
// Optional ?domain= and ?textPreview= for binding + tamper-detection.
app.get('/hhttps/s/:slug', async (req, res) => {
  const slug = (req.params.slug || '').trim();
  if (!/^hp-[A-Z0-9\-]+$/i.test(slug)) {
    return res.status(400).json({ error: 'invalid slug format' });
  }
  const sig = await db.signatures.get(slug);
  if (!sig) {
    return res.status(404).json({
      hhttps: { status: 'unknown' },
      error:  'signature not found'
    });
  }

  await db.signatures.incrementVerify(slug).catch(() => {});
  await db.stats.increment('signatures_verified').catch(() => {});

  const reqDomain = req.query.domain ? normalizeApexDomain(req.query.domain) : null;

  // First-seen-lock: only record on first valid verification with a domain
  if (!sig.first_seen_at && reqDomain) {
    await db.signatures.setFirstSeen(slug, reqDomain).catch(() => {});
  }

  // Build response
  const out = {
    hhttps:    { version: '0.5.0', status: 'verified' },
    id:        sig.id,
    role: {
      id:    sig.role,
      label: sig.role_label,
      icon:  sig.role_icon,
      level: sig.level,
      levelLabel: sig.level_label,
      trustScore: sig.trust_score
    },
    binding: {
      type:   sig.binding_type,
      domain: sig.bound_domain
    },
    textPreview: sig.text_preview,
    textLength:  sig.text_length,
    firstSeen:   sig.first_seen_at ? {
      domain: sig.first_seen_domain,
      at:     sig.first_seen_at
    } : null,
    createdAt:   sig.created_at,
    issuer:      sig.issuer,
    verifyCount: sig.verify_count + 1   // include this call
  };

  // Revocation check
  if (sig.revoked_at) {
    out.hhttps.status = 'revoked';
    out.revokedAt     = sig.revoked_at;
    out.revokeReason  = sig.revoke_reason;
    return sendJson(req, res, out, {
      title: 'Signature revoked',
      subtitle: 'This signature was revoked by the signer.'
    });
  }

  // Domain binding check
  if (sig.binding_type === 'web' && reqDomain && sig.bound_domain &&
      reqDomain !== sig.bound_domain) {
    out.hhttps.status      = 'wrong-domain';
    out.hhttps.expected    = sig.bound_domain;
    out.hhttps.observed    = reqDomain;
    out.warning            = `This signature was issued for ${sig.bound_domain} but used on ${reqDomain}. Possible theft.`;
    return sendJson(req, res, out, {
      title: 'Wrong domain',
      subtitle: out.warning
    });
  }

  // Text-tampering check — ONLY for `document` binding (Beta mode).
  // Alpha mode (web binding) is by design an identity stamp, not a text seal:
  // the user signs "as themselves on this domain"; edits to the surrounding
  // text are permitted (typo fixes, additions, etc.). Forcing a hash match
  // here produces false positives because mail clients / forums normalize
  // whitespace, decode entities, hard-wrap lines, and so on.
  if (sig.binding_type === 'document' && req.query.textPreview) {
    try {
      const preview = Buffer.from(req.query.textPreview, 'base64').toString('utf8');
      // Strict hash for document binding — every byte counts.
      const expectedStrict = sig.text_hash_strict;
      const actualStrict   = hashTextStrict(preview);
      if (expectedStrict !== actualStrict) {
        out.hhttps.status = 'text-modified';
        out.warning       = 'The text was modified after signing.';
      }
    } catch (e) {
      // Ignore preview parse errors
    }
  }

  return sendJson(req, res, out, {
    title: `Signature ${slug}`,
    subtitle: `${sig.role_icon || ''} ${sig.role_label} · Trust ${sig.trust_score}/100`
  });
});

// Batch verify (Performance: 1 request for N slugs on a page)
app.post('/hhttps/signatures/batch', async (req, res) => {
  const { slugs, domain, textPreviews } = req.body || {};
  if (!Array.isArray(slugs) || slugs.length === 0) {
    return res.status(400).json({ error: 'slugs array required' });
  }
  if (slugs.length > 100) {
    return res.status(400).json({ error: 'too many slugs (max 100)' });
  }

  const cleanSlugs = slugs.filter(s => /^hp-[A-Z0-9\-]+$/i.test(s));
  const sigs = await db.signatures.getMany(cleanSlugs);
  const reqDomain = domain ? normalizeApexDomain(domain) : null;

  const out = {};
  for (const sig of sigs) {
    const entry = {
      id: sig.id,
      role: {
        id: sig.role, label: sig.role_label, icon: sig.role_icon,
        level: sig.level, levelLabel: sig.level_label,
        trustScore: sig.trust_score
      },
      binding: { type: sig.binding_type, domain: sig.bound_domain },
      textPreview: sig.text_preview,
      createdAt:   sig.created_at,
      status:      'verified'
    };

    if (sig.revoked_at) {
      entry.status = 'revoked';
      entry.revokedAt = sig.revoked_at;
    } else if (sig.binding_type === 'web' && reqDomain &&
               sig.bound_domain && reqDomain !== sig.bound_domain) {
      entry.status   = 'wrong-domain';
      entry.expected = sig.bound_domain;
      entry.observed = reqDomain;
    } else if (sig.binding_type === 'document' && textPreviews && textPreviews[sig.id]) {
      // Strict text check only for Beta/document bindings (see single-slug
      // endpoint above for rationale).
      try {
        const preview = Buffer.from(textPreviews[sig.id], 'base64').toString('utf8');
        if (hashTextStrict(preview) !== sig.text_hash_strict) {
          entry.status = 'text-modified';
        }
      } catch (e) {}
    }
    out[sig.id] = entry;
  }

  // Missing slugs
  for (const slug of cleanSlugs) {
    if (!out[slug]) out[slug] = { id: slug, status: 'unknown' };
  }

  await db.stats.increment('signatures_verified', Object.keys(out).length).catch(() => {});

  return res.json({ hhttps: { version: '0.5.0' }, results: out });
});

// Revoke a signature (only by original signer)
app.post('/hhttps/signatures/:slug/revoke', async (req, res) => {
  const slug = (req.params.slug || '').trim();
  const token = req.headers['hhttps-token'] ||
                req.headers['authorization']?.replace('Bearer ', '') ||
                req.body?.token;
  const reason = req.body?.reason;

  if (!token) return res.status(401).json({ error: 'token required' });
  if (!/^hp-[A-Z0-9\-]+$/i.test(slug)) {
    return res.status(400).json({ error: 'invalid slug' });
  }

  try {
    const d = await checkTokenValid(token);
    const signerId = d.uid || d.userId || d.sub;
    const ok = await db.signatures.revoke(slug, signerId, reason);
    if (!ok) {
      return res.status(403).json({ error: 'not authorized or already revoked' });
    }
    await db.stats.increment('signatures_revoked').catch(() => {});
    return res.json({
      hhttps: { version: '0.5.0', status: 'revoked' },
      id:     slug,
      revokedAt: new Date().toISOString()
    });
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }
});

// Short-link redirect: /s/:slug → /hhttps/s/:slug (HTML-friendly)
app.get('/s/:slug', (req, res) => {
  const slug = (req.params.slug || '').trim();
  if (!/^hp-[A-Z0-9\-]+$/i.test(slug)) return res.status(400).send('Invalid slug');
  res.redirect(`/hhttps/s/${slug}`);
});

// ─── OAuth 2.0 / OpenID Connect Provider (Phase 3a) ──────────────────────────
// Standards-compliant authorization-code flow with PKCE. Pairwise subject IDs
// by default (each client sees a different pseudonymous user ID, no
// cross-platform tracking).

const OAUTH_CODE_TTL  = 60;         // seconds
const OAUTH_TOKEN_TTL = 5 * 60;     // 5 min for third-party access tokens
const SCOPES_KNOWN    = new Set(['openid', 'role', 'verification_method', 'age_group']);

// Discovery (RFC 8414 / OpenID Connect Discovery 1.0)
app.get('/.well-known/openid-configuration', (req, res) => {
  sendJson(req, res, {
    issuer:                          `https://${RP_ID}`,
    authorization_endpoint:          `${BASE_URL}/hhttps/oauth/authorize`,
    token_endpoint:                  `${BASE_URL}/hhttps/oauth/token`,
    userinfo_endpoint:               `${BASE_URL}/hhttps/oauth/userinfo`,
    revocation_endpoint:              `${BASE_URL}/hhttps/oauth/revoke`,
    jwks_uri:                         `${BASE_URL}/.well-known/jwks.json`,
    scopes_supported:                 ['openid', 'role', 'verification_method', 'age_group'],
    response_types_supported:         ['code'],
    grant_types_supported:            ['authorization_code'],
    subject_types_supported:          ['pairwise', 'public'],
    id_token_signing_alg_values_supported: ['ES256'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    claims_supported: [
      'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time',
      'role', 'role_label', 'role_icon', 'trust_score',
      'verification_method', 'verification_method_label',
      'age_group', 'age_verified', 'age_verification_method'
    ]
  }, {
    title: 'OpenID Connect Discovery',
    subtitle: 'Endpoint metadata for OAuth 2.0 + OIDC clients.'
  });
});

// Compute a pairwise subject identifier: stable per (user, client) but
// different across clients. Uses HMAC with a per-issuer secret.
function pairwiseSubjectId(userId, clientId, subjectType) {
  if (subjectType === 'public') {
    // Returns the user_id as-is (with a hash prefix to make it opaque)
    return crypto.createHash('sha256').update(`public:${userId}`).digest('hex').slice(0, 32);
  }
  // pairwise (default): HMAC(userId + clientId, server-secret)
  const secret = process.env.PAIRWISE_SECRET || 'hhttps-pairwise-' + RP_ID;
  return crypto.createHmac('sha256', secret)
    .update(`${userId}|${clientId}`)
    .digest('hex')
    .slice(0, 32);
}

// Authorize endpoint: shows consent page or auto-approves with active session
app.get('/hhttps/oauth/authorize', async (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    code_challenge,
    code_challenge_method
  } = req.query;

  // Step 1: validate the request
  if (response_type !== 'code') {
    return res.status(400).send(renderOAuthError('Only response_type=code is supported.', 400));
  }
  if (!client_id) {
    return res.status(400).send(renderOAuthError('client_id is required.', 400));
  }
  const client = await db.oauthClients.get(client_id);
  if (!client) {
    return res.status(400).send(renderOAuthError('Unknown client_id. Platform is not registered.', 400));
  }
  if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send(renderOAuthError(
      'redirect_uri does not match the registered value. Rejected for security reasons.', 400
    ));
  }

  // PKCE: required for public clients (no client_secret_hash)
  const isPublicClient = !client.client_secret_hash;
  if (isPublicClient && !code_challenge) {
    return redirectWithError(redirect_uri, state, 'invalid_request',
      'PKCE code_challenge is required for public clients.');
  }

  // Scope validation
  const requestedScopes = (scope || 'openid').split(/\s+/).filter(Boolean);
  if (!requestedScopes.includes('openid')) {
    return redirectWithError(redirect_uri, state, 'invalid_scope',
      'The "openid" scope is required.');
  }
  const unknownScopes = requestedScopes.filter(s => !SCOPES_KNOWN.has(s));
  if (unknownScopes.length > 0) {
    return redirectWithError(redirect_uri, state, 'invalid_scope',
      `Unknown scopes: ${unknownScopes.join(', ')}`);
  }
  const deniedScopes = requestedScopes.filter(s => !client.allowed_scopes.includes(s));
  if (deniedScopes.length > 0) {
    return redirectWithError(redirect_uri, state, 'invalid_scope',
      `Platform may not request these scopes: ${deniedScopes.join(', ')}`);
  }

  // Step 2: render the consent page. The user's session/identity will be
  // picked up from a cookie OR (when the browser extension is installed)
  // from localStorage published by hhttps.org itself.
  // For now we render a server-side consent page that asks the user to
  // identify (passkey) and approve.

  const params = new URLSearchParams({
    client_id, redirect_uri,
    scope:  requestedScopes.join(' '),
    state:  state || '',
    nonce:  nonce || '',
    code_challenge:        code_challenge || '',
    code_challenge_method: code_challenge_method || ''
  });

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderConsentPage({ client, scopes: requestedScopes, params: params.toString() }));
});

// Approve endpoint: called from the consent page after the user has
// authenticated (passkey) and confirmed. Exchanges the user's session for a
// short-lived authorization code.
app.post('/hhttps/oauth/approve', async (req, res) => {
  const { token, client_id, redirect_uri, scope, state, nonce,
          code_challenge, code_challenge_method } = req.body || {};

  if (!token) return res.status(401).json({ error: 'token required' });

  try {
    const d = await checkTokenValid(token);
    if (d.sub === 'machine') {
      return res.status(403).json({ error: 'machine tokens cannot authorize' });
    }

    const client = await db.oauthClients.get(client_id);
    if (!client) return res.status(400).json({ error: 'unknown client' });
    if (!client.redirect_uris.includes(redirect_uri)) {
      return res.status(400).json({ error: 'redirect_uri mismatch' });
    }
    const scopes = (scope || 'openid').split(/\s+/).filter(Boolean);
    if (!scopes.includes('openid')) {
      return res.status(400).json({ error: 'openid scope required' });
    }

    // Generate authorization code
    const code = 'hp-' + crypto.randomBytes(24).toString('base64url');

    await db.authCodes.create({
      code,
      clientId:           client_id,
      userId:             d.uid || d.userId || d.sub,
      redirectUri:        redirect_uri,
      scopes,
      pkceChallenge:      code_challenge,
      pkceMethod:         code_challenge_method || 'plain',
      state, nonce,
      role:               d.role,
      trustScore:         d.trustScore,
      verificationMethod: d.roleLevel,
      ageGroup:               d.age_group || null,
      ageVerified:            d.age_verified ?? null,
      ageVerificationMethod:  d.age_verification_method || null,
      ttlSec:             OAUTH_CODE_TTL
    });

    await db.oauthClients.touchLastUsed(client_id);
    await db.stats.increment('oauth_authorizations');

    // Build redirect URL with code (and state if provided)
    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);

    return res.json({ redirect: url.toString() });
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }
});

// Token endpoint: exchange code for access_token + id_token
app.post('/hhttps/oauth/token', async (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret,
    code_verifier
  } = req.body || {};

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (!code || !client_id) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const client = await db.oauthClients.get(client_id);
  if (!client) return res.status(401).json({ error: 'invalid_client' });

  // Authenticate client (secret OR PKCE)
  const isPublicClient = !client.client_secret_hash;
  if (!isPublicClient) {
    if (!client_secret) return res.status(401).json({ error: 'invalid_client' });
    const expected = crypto.createHash('sha256').update(client_secret).digest('hex');
    if (expected !== client.client_secret_hash) {
      return res.status(401).json({ error: 'invalid_client' });
    }
  }

  // Claim the code (single-use, atomic)
  const claimed = await db.authCodes.claim(code);
  if (!claimed) return res.status(400).json({ error: 'invalid_grant', error_description: 'code expired or already used' });
  if (claimed.client_id !== client_id) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'client mismatch' });
  }
  if (claimed.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
  }

  // PKCE verification
  if (claimed.pkce_challenge) {
    if (!code_verifier) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier required' });
    }
    let computed;
    if (claimed.pkce_method === 'S256') {
      computed = crypto.createHash('sha256').update(code_verifier).digest('base64url');
    } else {
      computed = code_verifier;
    }
    if (computed !== claimed.pkce_challenge) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }
  }

  // Generate pairwise subject ID
  const pairwiseId = pairwiseSubjectId(claimed.user_id, client_id, client.subject_type);

  // Record the connection (for "my logins" UI later)
  await db.connectedPlatforms.record({
    userId:             claimed.user_id,
    clientId:           client_id,
    pairwiseSubjectId:  pairwiseId,
    scopesGranted:      claimed.scopes
  });

  // Build the access token (a JWT with limited scope, short TTL)
  const roleDef = ROLES[claimed.role] || ROLES.citizen;
  const vMethod = VERIFICATION_LEVELS[claimed.verification_method] || {};

  const accessToken = signToken({
    iss:        `https://${RP_ID}`,
    hhttps_iss: `hhttps://${RP_ID}`,
    sub:        pairwiseId,
    aud:        client_id,
    client_id,
    scope:      claimed.scopes.join(' '),
    role:       claimed.role,
    trustScore: claimed.trust_score,
    // age_group travels with the access token only when the scope was granted,
    // so /userinfo can echo it. Orthogonal to role; self-declared in Phase 1.
    ...(claimed.scopes.includes('age_group') && claimed.age_group ? {
      age_group:               claimed.age_group,
      age_verified:            claimed.age_verified ?? false,
      age_verification_method: claimed.age_verification_method || 'self-declared'
    } : {})
  }, { expiresIn: OAUTH_TOKEN_TTL });

  // ID token (OIDC) — claims based on requested scopes
  const idTokenClaims = {
    iss:       `https://${RP_ID}`,
    sub:       pairwiseId,
    aud:       client_id,
    nonce:     claimed.nonce || undefined,
    auth_time: Math.floor(Date.now() / 1000)
  };
  if (claimed.scopes.includes('role')) {
    idTokenClaims.role        = claimed.role;
    idTokenClaims.role_label  = roleDef.label;
    idTokenClaims.role_icon   = roleDef.icon;
    idTokenClaims.trust_score = claimed.trust_score;
  }
  if (claimed.scopes.includes('verification_method')) {
    idTokenClaims.verification_method       = claimed.verification_method;
    idTokenClaims.verification_method_label = vMethod.label || null;
  }
  if (claimed.scopes.includes('age_group') && claimed.age_group) {
    idTokenClaims.age_group               = claimed.age_group;
    idTokenClaims.age_verified            = claimed.age_verified ?? false;
    idTokenClaims.age_verification_method = claimed.age_verification_method || 'self-declared';
  }
  const idToken = signToken(idTokenClaims, { expiresIn: OAUTH_TOKEN_TTL });

  await db.stats.increment('oauth_tokens_issued');
  await db.stats.increment('oauth_logins');

  // Phase 3b: per-client privacy-preserving daily stats
  // (no user IDs, just role/trust buckets)
  try {
    await db.clientStats.recordLogin(
      client_id,
      idTokenClaims.role || 'unknown',
      idTokenClaims.trust_score || 0
    );
  } catch (err) {
    console.warn('[STATS] recordLogin failed:', err.message);
  }

  return res.json({
    access_token: accessToken,
    token_type:   'Bearer',
    expires_in:   OAUTH_TOKEN_TTL,
    id_token:     idToken,
    scope:        claimed.scopes.join(' ')
  });
});

// UserInfo endpoint: returns claims for the bearer token
app.get('/hhttps/oauth/userinfo', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });

  try {
    const d = verifyToken(token);
    if (!d.client_id) {
      return res.status(403).json({ error: 'not an oauth access token' });
    }
    const scopes = (d.scope || '').split(/\s+/).filter(Boolean);
    const out = {
      sub: d.sub,
      iss: d.iss
    };
    if (scopes.includes('role')) {
      const roleDef = ROLES[d.role] || ROLES.citizen;
      out.role        = d.role;
      out.role_label  = roleDef.label;
      out.role_icon   = roleDef.icon;
      out.trust_score = d.trustScore;
    }
    if (scopes.includes('age_group') && d.age_group) {
      out.age_group               = d.age_group;
      out.age_verified            = d.age_verified ?? false;
      out.age_verification_method = d.age_verification_method || 'self-declared';
    }
    return res.json(out);
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// Revoke endpoint: user disconnects a platform
app.post('/hhttps/oauth/revoke', async (req, res) => {
  const { token, client_id } = req.body || {};
  if (!token || !client_id) return res.status(400).json({ error: 'token + client_id required' });

  try {
    const d = await checkTokenValid(token);
    await db.connectedPlatforms.revoke(d.uid || d.userId || d.sub, client_id);
    return res.json({ status: 'revoked', client_id });
  } catch (e) {
    return res.status(401).json({ error: e.message });
  }
});

// ─── OAuth helper rendering ──────────────────────────────────────────────────

function redirectWithError(redirectUri, state, errorCode, errorDescription) {
  try {
    const url = new URL(redirectUri);
    url.searchParams.set('error', errorCode);
    if (errorDescription) url.searchParams.set('error_description', errorDescription);
    if (state) url.searchParams.set('state', state);
    return { redirect: url.toString() };
  } catch (e) {
    return null;
  }
}

function renderOAuthError(message, status) {
  return `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8">
<title>OAuth error · HHTTPS</title>
<style>body{font-family:system-ui;background:#F8F1E4;color:#2D2823;padding:60px 20px;text-align:center}
.box{max-width:520px;margin:0 auto;background:#FCFAF5;border-radius:14px;padding:32px;box-shadow:0 4px 20px rgba(45,40,35,.08)}
h1{font-family:'Fraunces',serif;color:#C97D5B;margin-bottom:16px}
p{line-height:1.6;color:#4A413A}
a{color:#A86246;text-decoration:none}
</style></head><body><div class="box"><h1>OAuth error ${status}</h1><p>${message}</p>
<p><a href="https://hhttps.org">← back to hhttps.org</a></p></div></body></html>`;
}

function renderConsentPage({ client, scopes, params }) {
  const verifiedBadge = client.verified
    ? `<span class="badge badge-verified" data-i18n="consent.verified">✓ Verifizierte Plattform</span>`
    : `<span class="badge badge-unverified" data-i18n="consent.unverified">⚠ Nicht verifiziert</span>`;

  const unverifiedWarning = client.verified ? '' : `
    <div class="warning">
      <strong data-i18n="consent.warnStrong">Achtung — Diese Plattform ist nicht von hhttps.org geprüft.</strong>
      <span data-i18n="consent.warnB1">Klicke nur auf "Erlauben", wenn du der Plattform</span> <em>${escapeHtml(client.name)}</em> <span data-i18n="consent.warnB2">wirklich vertraust. Prüfe besonders, ob die URL in der Adressleiste mit</span> <code>${escapeHtml(client.homepage_url || '?')}</code> <span data-i18n="consent.warnB3">übereinstimmt.</span>
    </div>
  `;

  const scopeRows = scopes.map(s => {
    const label = {
      'openid':              { icon: '🆔', title: 'Anonyme Identität',  desc: 'Eine pseudonyme Kennung, die nur diese Plattform sieht.' },
      'role':                { icon: '🎭', title: 'Rolle + Trust-Score', desc: 'Deine gesellschaftliche Rolle (z. B. Entwickler) und dein Vertrauenswert.' },
      'verification_method': { icon: '🔐', title: 'Verifikationsmethode', desc: 'Wie deine Rolle verifiziert wurde (z. B. ORCID, Presseausweis).' },
      'age_group':           { icon: '🔞', title: 'Altersgruppe', desc: 'Deine grobe Altersgruppe (z. B. 18+), nicht dein Geburtsdatum. Aktuell Eigenangabe.' }
    }[s] || { icon: '?', title: s, desc: 'Unbekannter Scope.' };
    return `<div class="scope-row">
      <span class="scope-icon">${label.icon}</span>
      <div><div class="scope-title" data-i18n="scope.${s}.title">${label.title}</div>
           <div class="scope-desc" data-i18n="scope.${s}.desc">${label.desc}</div></div>
    </div>`;
  }).join('');

  return `<!DOCTYPE html><html lang="de"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login bei ${escapeHtml(client.name)} · HHTTPS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT,WONK@9..144,400..600,30..100,0..1&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --cream:#F8F1E4; --paper:#FCFAF5; --sand:#EDE0C8;
    --terra:#C97D5B; --terra-dp:#A86246; --apricot:#F2B894;
    --sage:#A8B89E; --green-v:#5BAF6B;
    --ink:#2D2823; --ink-soft:#4A413A; --ink-mute:#7A6F62;
    --line:rgba(45,40,35,0.1);
    --red:#C97D5B;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--cream); color: var(--ink); min-height: 100vh; display:flex; align-items:center; justify-content:center; padding: 40px 16px; line-height:1.55; }
  .wrap { max-width: 540px; width:100%; }
  .header { text-align: center; margin-bottom: 24px; }
  .logo { display:inline-flex; align-items:center; gap:10px; }
  .logo-mark { width:40px; height:40px; border-radius:11px; background: linear-gradient(135deg, var(--terra), var(--apricot)); position:relative; }
  .logo-mark::after { content:'H'; position:absolute; inset:0; display:flex; align-items:center; justify-content:center; font-family:'Fraunces',serif; font-weight:600; font-size:22px; color: var(--paper); }
  .logo-text { font-family:'Fraunces',serif; font-variation-settings:"SOFT" 100,"WONK" 1; font-weight:500; font-size:22px; }
  .card { background: var(--paper); border-radius: 18px; box-shadow: 0 8px 28px rgba(45,40,35,0.1); border: 1px solid var(--line); overflow:hidden; }
  .card-head { padding: 28px 28px 20px; border-bottom: 1px solid var(--line); text-align: center; }
  .client-logo { width:64px; height:64px; border-radius:14px; background: var(--sand); margin: 0 auto 14px; display:flex; align-items:center; justify-content:center; font-size:32px; color: var(--ink-soft); }
  h1 { font-family:'Fraunces',serif; font-variation-settings:"SOFT" 50,"WONK" 1; font-size:24px; font-weight:500; letter-spacing:-0.01em; margin-bottom:6px; }
  h1 em { color: var(--terra); font-style:italic; font-variation-settings:"SOFT" 100,"WONK" 1; }
  .client-url { font-family:'JetBrains Mono',monospace; font-size:12px; color: var(--ink-mute); margin-top: 8px; }
  .badge { display:inline-block; font-size: 11px; padding: 4px 10px; border-radius: 100px; margin-top: 10px; font-family:'JetBrains Mono',monospace; letter-spacing:0.5px; }
  .badge-verified { background: rgba(91,175,107,0.15); color: var(--green-v); }
  .badge-unverified { background: rgba(201,125,91,0.15); color: var(--terra-dp); }
  .warning { background: rgba(201,125,91,0.08); border-left: 4px solid var(--terra); padding: 14px 18px; margin: 0; font-size:13px; color: var(--ink-soft); }
  .warning strong { color: var(--terra-dp); display:block; margin-bottom:4px; }
  .warning code { background: var(--sand); padding: 2px 6px; border-radius: 4px; font-family:'JetBrains Mono',monospace; font-size: 11px; }
  .scope-list { padding: 20px 28px; }
  .scope-list-head { font-family:'JetBrains Mono',monospace; font-size:10px; color: var(--ink-mute); letter-spacing:1.5px; text-transform:uppercase; margin-bottom: 14px; }
  .scope-row { display:flex; gap:14px; padding:10px 0; align-items:flex-start; border-bottom: 1px solid var(--line); }
  .scope-row:last-child { border-bottom:none; }
  .scope-icon { font-size:24px; line-height:1; }
  .scope-title { font-weight:600; margin-bottom:2px; }
  .scope-desc { font-size: 12px; color: var(--ink-mute); }
  .actions { padding: 20px 28px 28px; display:flex; gap:10px; }
  .btn { flex:1; padding: 14px; border-radius: 100px; border: none; font-family:inherit; font-size:14px; font-weight:500; cursor:pointer; transition: all 0.2s; }
  .btn-allow { background: var(--ink); color: var(--paper); }
  .btn-allow:hover { background: var(--terra-dp); transform: translateY(-1px); }
  .btn-allow:disabled { background: var(--ink-mute); cursor: not-allowed; transform: none; }
  .btn-deny { background: var(--paper); color: var(--ink-soft); border: 1px solid var(--line); }
  .btn-deny:hover { background: var(--sand); }
  .footer-note { padding: 14px 28px; background: var(--cream); border-top: 1px solid var(--line); text-align:center; font-size: 11px; color: var(--ink-mute); font-family:'JetBrains Mono',monospace; }
  .status { padding: 14px 28px; font-size: 13px; text-align:center; display:none; }
  .status.error { background: rgba(201,125,91,0.1); color: var(--terra-dp); display:block; }
  .lang-toggle { display:inline-flex; gap:2px; background:var(--sand); border-radius:100px; padding:2px; margin-top:12px; }
  .lang-toggle button { border:none; background:transparent; color:var(--ink-mute); font:600 11px/1 'JetBrains Mono',monospace; letter-spacing:.5px; padding:5px 9px; border-radius:100px; cursor:pointer; transition:all .15s; }
  .lang-toggle button:hover { color:var(--ink); }
  .lang-toggle button.active { background:var(--paper); color:var(--terra-dp); box-shadow:0 1px 3px rgba(45,40,35,.12); }
</style></head><body>
<div class="wrap">
  <div class="header">
    <a class="logo" href="https://hhttps.org" style="text-decoration:none;color:inherit">
      <div class="logo-mark"></div>
      <div class="logo-text">HHTTPS</div>
    </a>
    <div class="lang-toggle" role="group" aria-label="Language">
      <button type="button" data-lang="de" class="active">DE</button>
      <button type="button" data-lang="en">EN</button>
    </div>
  </div>
  <div class="card">
    <div class="card-head">
      <div class="client-logo">${client.logo_url ? `<img src="${escapeHtml(client.logo_url)}" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:14px">` : '🏛️'}</div>
      <h1><em>${escapeHtml(client.name)}</em> <span data-i18n="consent.heading">möchte deine Identität sehen</span></h1>
      ${client.homepage_url ? `<div class="client-url">${escapeHtml(client.homepage_url)}</div>` : ''}
      ${verifiedBadge}
    </div>
    ${unverifiedWarning}
    <div class="scope-list">
      <div class="scope-list-head" data-i18n="consent.scopeHead">Folgende Daten werden geteilt</div>
      ${scopeRows}
    </div>
    <div class="status" id="status"></div>
    <div class="actions">
      <button class="btn btn-deny" id="denyBtn" data-i18n="consent.deny">Ablehnen</button>
      <button class="btn btn-allow" id="allowBtn" data-i18n="consent.allow">Erlauben</button>
    </div>
    <div class="footer-note"><span data-i18n="consent.footPre">Nur Rolle und Trust-Score werden geteilt. Keine PII. Du kannst die Verbindung jederzeit auf</span> <a href="https://hhttps.org" style="color:var(--terra-dp);text-decoration:none">hhttps.org</a> <span data-i18n="consent.footPost">widerrufen.</span></div>
  </div>
</div>
<script>
const params = new URLSearchParams(${JSON.stringify(params)});

document.getElementById('denyBtn').addEventListener('click', () => {
  const redirectUri = params.get('redirect_uri');
  const state = params.get('state') || '';
  const url = new URL(redirectUri);
  url.searchParams.set('error', 'access_denied');
  url.searchParams.set('error_description', 'User denied the request');
  if (state) url.searchParams.set('state', state);
  window.location = url.toString();
});

document.getElementById('allowBtn').addEventListener('click', async () => {
  const allow = document.getElementById('allowBtn');
  const status = document.getElementById('status');
  allow.disabled = true;
  allow.textContent = t('consent.processing');

  // Look for an identity in localStorage (published by hhttps.org main page)
  // or in browser extension storage. For Phase 3a we use localStorage.
  let identity = null;
  try {
    const raw = localStorage.getItem('hhttps_identity');
    if (raw) identity = JSON.parse(raw);
  } catch (e) {}

  if (!identity || !identity.token) {
    status.className = 'status error';
    status.textContent = t('consent.noIdentity');
    setTimeout(() => {
      window.location = 'https://hhttps.org/?returnTo=' + encodeURIComponent(window.location.href);
    }, 2000);
    return;
  }

  try {
    const r = await fetch('/hhttps/oauth/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: identity.token,
        client_id:             params.get('client_id'),
        redirect_uri:          params.get('redirect_uri'),
        scope:                 params.get('scope'),
        state:                 params.get('state'),
        nonce:                 params.get('nonce'),
        code_challenge:        params.get('code_challenge'),
        code_challenge_method: params.get('code_challenge_method')
      })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'OAuth error');
    window.location = d.redirect;
  } catch (e) {
    status.className = 'status error';
    status.textContent = t('consent.errorPrefix') + e.message;
    allow.disabled = false;
    allow.textContent = t('consent.allow');
  }
});

// ─── Consent page i18n (DE/EN toggle, shared storage key) ──────────────────
const CONSENT_I18N = {
  de: {
    "consent.verified":"✓ Verifizierte Plattform","consent.unverified":"⚠ Nicht verifiziert",
    "consent.warnStrong":"Achtung — Diese Plattform ist nicht von hhttps.org geprüft.",
    "consent.warnB1":"Klicke nur auf „Erlauben“, wenn du der Plattform",
    "consent.warnB2":"wirklich vertraust. Prüfe besonders, ob die URL in der Adressleiste mit",
    "consent.warnB3":"übereinstimmt.","consent.heading":"möchte deine Identität sehen",
    "consent.scopeHead":"Folgende Daten werden geteilt","consent.deny":"Ablehnen","consent.allow":"Erlauben",
    "consent.footPre":"Nur Rolle und Trust-Score werden geteilt. Keine PII. Du kannst die Verbindung jederzeit auf",
    "consent.footPost":"widerrufen.","consent.processing":"Wird verarbeitet…",
    "consent.noIdentity":"Keine HHTTPS-Identität gefunden. Bitte zuerst auf hhttps.org einloggen.",
    "consent.errorPrefix":"Fehler: ",
    "scope.openid.title":"Anonyme Identität","scope.openid.desc":"Eine pseudonyme Kennung, die nur diese Plattform sieht.",
    "scope.role.title":"Rolle + Trust-Score","scope.role.desc":"Deine gesellschaftliche Rolle (z. B. Entwickler) und dein Vertrauenswert.",
    "scope.verification_method.title":"Verifikationsmethode","scope.verification_method.desc":"Wie deine Rolle verifiziert wurde (z. B. ORCID, Presseausweis).",
    "scope.age_group.title":"Altersgruppe","scope.age_group.desc":"Deine grobe Altersgruppe (z. B. 18+), nicht dein Geburtsdatum. Aktuell Eigenangabe."
  },
  en: {
    "consent.verified":"✓ Verified platform","consent.unverified":"⚠ Not verified",
    "consent.warnStrong":"Caution — this platform has not been checked by hhttps.org.",
    "consent.warnB1":"Only click “Allow” if you really trust the platform",
    "consent.warnB2":". Check in particular that the URL in the address bar matches",
    "consent.warnB3":".","consent.heading":"wants to see your identity",
    "consent.scopeHead":"The following data will be shared","consent.deny":"Deny","consent.allow":"Allow",
    "consent.footPre":"Only role and trust score are shared. No PII. You can revoke the connection any time at",
    "consent.footPost":".","consent.processing":"Processing…",
    "consent.noIdentity":"No HHTTPS identity found. Please log in at hhttps.org first.",
    "consent.errorPrefix":"Error: ",
    "scope.openid.title":"Anonymous identity","scope.openid.desc":"A pseudonymous identifier that only this platform sees.",
    "scope.role.title":"Role + trust score","scope.role.desc":"Your societal role (e.g. developer) and your trust value.",
    "scope.verification_method.title":"Verification method","scope.verification_method.desc":"How your role was verified (e.g. ORCID, press card).",
    "scope.age_group.title":"Age group","scope.age_group.desc":"Your rough age group (e.g. 18+), not your date of birth. Currently self-declared."
  }
};
let CONSENT_LANG = 'de';
function t(k){ return (CONSENT_I18N[CONSENT_LANG]||CONSENT_I18N.de)[k] ?? (CONSENT_I18N.de[k] ?? k); }
function applyConsentLang(lang){
  CONSENT_LANG = CONSENT_I18N[lang] ? lang : 'de';
  document.documentElement.lang = CONSENT_LANG;
  document.querySelectorAll('[data-i18n]').forEach(function(e){ var v = t(e.getAttribute('data-i18n')); if (v != null) e.textContent = v; });
  document.querySelectorAll('.lang-toggle button').forEach(function(b){ b.classList.toggle('active', b.dataset.lang === CONSENT_LANG); });
  try { localStorage.setItem('iamhmn-lang', CONSENT_LANG); } catch(e){}
}
function detectConsentLang(){
  try { var sv = localStorage.getItem('iamhmn-lang'); if (sv && CONSENT_I18N[sv]) return sv; } catch(e){}
  var n = (navigator.language || 'de').slice(0,2).toLowerCase();
  return CONSENT_I18N[n] ? n : 'de';
}
document.querySelectorAll('.lang-toggle button').forEach(function(b){
  b.addEventListener('click', function(){ applyConsentLang(b.dataset.lang); });
});
applyConsentLang(detectConsentLang());
</script>
</body></html>`;
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── Roles registry ───────────────────────────────────────────────────────────

app.get('/hhttps/roles', (req, res) => {
  sendJson(req, res, {
    hhttps: { version: '0.5.0' },
    model: 'esco-dynamic',
    note: 'v0.5: roles are no longer a fixed catalogue. Occupations resolve dynamically against ESCO; a professional role arrives only as an EUDI (Q)EAA or an HHTTPS-issued iamhmn-card. Use /hhttps/esco/suggest to look up occupations.',
    base_identity: { id: ROLES.citizen.id, label: ROLES.citizen.label, icon: ROLES.citizen.icon },
    reserved_registry: RESERVED_REGISTRY,
    ralLevels: roleAssuranceDiscovery().ral_levels,
    esco_suggest: '/hhttps/esco/suggest?q=',
    discovery: '/.well-known/hhttps-role-assurance',
    verificationLevels: VERIFICATION_LEVELS
  }, {
    title:    'Role Registry (ESCO-dynamic)',
    subtitle: 'v0.5: no fixed role list — occupations resolve via ESCO; roles arrive as EUDI (Q)EAA or iamhmn-card.'
  });
});

// ─── WebAuthn Registration ────────────────────────────────────────────────────

app.post('/hhttps/webauthn/register/start', limit.webauthn, async (req, res) => {
  try {
    const userId    = req.body.userId || uuid();
    const userIdBuf = Buffer.from(userId);
    const existingCreds = await db.credentials.findByUserId(userId);

    // CRITICAL: convert credentialId from base64url string to Buffer for the library
    const excludeCredentials = existingCreds.map(c => ({
      id:         Buffer.from(c.credentialId, 'base64url'),
      type:       'public-key',
      transports: c.transports
    }));

    const options = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: RP_ID, userID: userIdBuf,
      userName: `human-${userId.slice(0, 8)}`, userDisplayName: 'iamhmn Nutzer',
      attestationType: 'none',
      excludeCredentials,
      // CRITICAL: NO authenticatorAttachment — allows YubiKey, smartphone, platform auth
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257]
    });

    await db.challenges.create(userId, options.challenge, userId, 'registration', 120_000);
    res.json({ userId, options });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/hhttps/webauthn/register/finish', async (req, res) => {
  const { userId, response } = req.body;
  const stored = await db.challenges.get(userId);
  if (!stored) return res.status(400).json({ error: 'Challenge expired.' });

  try {
    const v = await verifyRegistrationResponse({
      response, expectedChallenge: stored.challenge,
      expectedOrigin: ORIGIN, expectedRPID: RP_ID,
      requireUserVerification: true
    });
    if (!v.verified || !v.registrationInfo)
      return res.status(400).json({ error: 'Verifikation fehlgeschlagen.' });

    const { credentialID, credentialPublicKey, counter,
            credentialDeviceType, credentialBackedUp } = v.registrationInfo;
    const credId = Buffer.from(credentialID).toString('base64url');

    await db.credentials.create({
      credentialId: credId,
      userId,
      publicKey:    Buffer.from(credentialPublicKey),
      counter,
      transports:   response.response.transports || [],
      deviceType:   credentialDeviceType,
      backedUp:     credentialBackedUp
    });
    await db.challenges.delete(userId);
    await db.stats.increment('verifications');

    res.json({
      status: 'registered', credentialId: credId,
      deviceType: credentialDeviceType, backedUp: credentialBackedUp
    });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ─── WebAuthn Authentication ──────────────────────────────────────────────────

app.post('/hhttps/webauthn/auth/start', limit.webauthn, async (req, res) => {
  try {
    const { userId } = req.body;
    const userCreds = userId ? await db.credentials.findByUserId(userId) : [];

    // CRITICAL: convert credentialId from base64url string to Buffer
    const allowCredentials = userCreds.map(c => ({
      id:         Buffer.from(c.credentialId, 'base64url'),
      type:       'public-key',
      transports: c.transports
    }));

    const sessionId = uuid();
    const options   = await generateAuthenticationOptions({
      rpID: RP_ID, userVerification: 'required',
      allowCredentials, timeout: 60_000
    });
    await db.challenges.create(sessionId, options.challenge, userId, 'authentication', 90_000);
    res.json({ sessionId, options });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/hhttps/webauthn/auth/finish', async (req, res) => {
  // emailSessionId (optional): when present, an existing email-verified session
  // is merged into the new passkey session. Email-flow continues uninterrupted,
  // and the final session carries BOTH the passkey credential and the email
  // verification info, so /role/declare sees the full picture.
  const { sessionId, response, emailSessionId, priorSessionId } = req.body;
  const stored = await db.challenges.get(sessionId);
  if (!stored) return res.status(400).json({ error: 'Session expired.' });

  const cred = await db.credentials.get(response.id);
  if (!cred) return res.status(400).json({ error: 'Passkey nicht registriert.' });

  try {
    const v = await verifyAuthenticationResponse({
      response, expectedChallenge: stored.challenge,
      expectedOrigin: ORIGIN, expectedRPID: RP_ID,
      authenticator: {
        credentialID:        Buffer.from(cred.credentialId, 'base64url'),
        credentialPublicKey: cred.credentialPublicKey,
        counter:             cred.counter,
        transports:          cred.transports
      },
      requireUserVerification: true
    });
    if (!v.verified) return res.status(401).json({ error: 'WebAuthn fehlgeschlagen.' });

    await db.credentials.updateCounter(cred.credentialId, v.authenticationInfo.newCounter);
    await db.challenges.delete(sessionId);

    // ── Merge in the PRIOR session, if the client passed one. ──────────────
    // v0.5 (method-neutral): passkey can be added after email, GitHub OR EUDI in
    // any order. We carry over EVERY verified method from the prior session into
    // the new passkey session so none of those confirmations are lost, then
    // delete the old session so the user keeps exactly ONE active session.
    // `emailSessionId` is kept as a backward-compatible alias for `priorSessionId`.
    let priorMerge = {};
    const priorId = priorSessionId || emailSessionId;
    if (priorId) {
      const prior = await db.sessions.get(priorId);
      if (prior) {
        priorMerge = {
          ...(prior.emailVerified ? {
            emailVerified:   true,
            emailDomain:     prior.emailDomain     || null,
            emailLevel:      prior.emailLevel      || null,
            emailTrustBonus: prior.emailTrustBonus || 0,
          } : {}),
          ...(prior.githubVerified ? { githubVerified: true } : {}),
          ...(prior.eudiVerified   ? { eudiVerified:   true } : {}),
          ...(prior.pseudonym      ? { pseudonym: prior.pseudonym } : {}),
        };
        if (Object.keys(priorMerge).length) {
          try { await db.sessions.delete(priorId); } catch (e) {}
        }
      }
    }

    // Create the (merged) verified session. TTL 30 min — long enough for the
    // user to think about pseudonym / role selection / age group.
    const sid = uuid();
    await db.sessions.create(sid, {
      userId:       stored.userId || cred.userId,
      credentialId: cred.credentialId,
      deviceType:   cred.deviceType,
      backedUp:     cred.backedUp,
      verified:     true,
      hasPasskey:   true,
      // Initial trust placeholder. The final trust is computed in /role/declare
      // via computeVerification (email 20 + passkey 30 + domain + …, capped 100).
      // We seed with 50 — the human-confirmed threshold (email+passkey) — so a
      // caller that reads the session before /role/declare sees a sane number.
      trustScore:   50,
      ...priorMerge,
    }, 1800_000); // 30 min
    await db.stats.increment('verifications');

    res.json({
      verified:  true,
      sessionId: sid,
      merged:    Object.keys(priorMerge).length > 0,
      message:   'WebAuthn OK. Please declare a role.'
    });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ─── Token Refresh ────────────────────────────────────────────────────────────

app.post('/hhttps/token/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });

  try {
    const d = verifyToken(refreshToken);
    if (d.sub !== 'refresh')              throw new Error('Kein Refresh-Token');
    if (await db.revokedTokens.has(d.jti)) throw new Error('Refresh token revoked');

    const stored = await db.refreshTokens.get(d.jti);
    if (!stored) throw new Error('Refresh-Token nicht aktiv');

    const cred = stored.credential_id ? await db.credentials.get(stored.credential_id) : null;

    // v0.5: rehydrate the verification surface STATELESSLY from the signed refresh
    // token (zero-PII — nothing is read from a per-user table). verified_methods,
    // trust and the domain value were embedded into the refresh token at issuance.
    const methods    = Array.isArray(d.verified_methods) ? d.verified_methods : [];
    const trustScore = (typeof d.trustScore === 'number') ? d.trustScore : 20;  // email floor
    const domainVal  = d.emailDomain || null;

    const { token: newAccess } = await issueAccessToken({
      userId:     stored.user_id,
      role:       null,
      roleLabel:  null,
      roleLevel:  null,
      trustScore,
      method:     'verification-methods',
      deviceType: cred?.deviceType || 'unknown',
      verified_methods:    methods,
      verification_status: 'verified',
      ...(domainVal ? { domain_name: domainVal } : {})
    });

    setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                     role: null, trustScore, token: newAccess,
                     method: 'verification-methods',
                     verifiedMethods: methods, domainValue: domainVal });
    setIdentityCookie(res, newAccess);  // refresh the hhttps.org-scoped cookie too

    res.json({
      hhttps:    { version: '0.5.0', status: 'refreshed', human: true, actorType: 'human',
                   trustScore, verifiedMethods: methods },
      token:     newAccess,
      expiresAt: new Date(Date.now() + ACCESS_TTL * 1000).toISOString(),
      role:      null,
      message:   '✓ New access token issued — no re-authentication needed.'
    });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// ─── Email-First Session ─────────────────────────────────────────────────────
//
// POST /hhttps/session/email/start
//
// Erstellt eine verified Session ohne WebAuthn-Credential.
// Passkey bleibt optional und kann nachträglich den trust_score erhöhen.
//
// Motivation: Ermöglicht Email-first-Flow auf der Landing Page ohne
// vorherige Passkey-Registrierung. Sessions werden mit trust_score: 30
// erstellt (Baseline E-Mail). Nach erfolgreicher E-Mail-Verifikation
// wertet /hhttps/role/declare den emailTrustBonus aus wie gehabt.
//
// Rate-limit: identisch mit limit.email (5 Req / 60 min pro IP).
// Kein DB-Schema-Change: credential_id, device_type, backed_up sind nullable.
//
// Body:     { pseudonym?: string }
// Response: { sessionId, userId, trustScore: 30, method: "email-pending" }
//
app.post('/hhttps/session/email/start', limit.email, async (req, res) => {
  try {
    const { pseudonym } = req.body || {};

    // Pseudonym: max 32 Zeichen, nur sichere Zeichen
    const cleanPseudo = pseudonym
      ? String(pseudonym)
          .replace(/[^\w\-. äöüÄÖÜß]/gu, '')
          .slice(0, 32)
          .trim() || null
      : null;

    const userId = uuid();
    const sid    = uuid();

    // credential_id, device_type, backed_up sind in der DB nullable —
    // kein ALTER TABLE nötig.
    await db.sessions.create(sid, {
      userId,
      credentialId: null,
      deviceType:   'email-only',
      backedUp:     false,
      verified:     true,   // session gilt als verified für /hhttps/email/send
      trustScore:   0,      // email pending — 0 until the email is confirmed (then 20)
    }, 900_000); // 15 min — ausreichend für E-Mail-Zustellung und Bestätigung

    await db.stats.increment('verifications');

    res.json({
      sessionId:  sid,
      userId,
      trustScore: 0,        // email pending — not yet a verified method
      method:     'email-pending',
      pseudonym:  cleanPseudo,
      message:    'Session erstellt. Bitte E-Mail verifizieren.',
    });
  } catch (e) {
    console.error('[session/email/start]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Method-neutral session bootstrap (v0.5) ────────────────────────────────
// Any of the equal entry methods (email, passkey, EUDI Wallet, GitHub) may open
// a session FIRST and then run its own real verification against it. Same
// primitive as /hhttps/session/email/start, but without the email label: the
// session carries NO verified method yet (trust 0) until one really lands. The
// token gate in /hhttps/role/declare requires ≥1 genuinely verified method, so
// an empty bootstrap session can never mint a token on its own.
app.post('/hhttps/session/start', limit.email, async (req, res) => {
  try {
    const { pseudonym } = req.body || {};
    const cleanPseudo = pseudonym
      ? String(pseudonym).replace(/[^\w\-. äöüÄÖÜß]/gu, '').slice(0, 32).trim() || null
      : null;

    const userId = uuid();
    const sid    = uuid();

    await db.sessions.create(sid, {
      userId,
      credentialId: null,
      deviceType:   'pending',   // neutral: the confirmed method(s) describe the identity
      backedUp:     false,
      verified:     true,        // "session exists" — NOT a trust statement (trust stays 0)
      trustScore:   0,
    }, 900_000); // 15 min

    await db.stats.increment('verifications');

    res.json({
      sessionId:  sid,
      userId,
      trustScore: 0,
      method:     'session-pending',
      pseudonym:  cleanPseudo,
      message:    'Session created. Verify with any method.',
    });
  } catch (e) {
    console.error('[session/start]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Email Verification ───────────────────────────────────────────────────────

app.post('/hhttps/email/send', limit.email, async (req, res) => {
  const { sessionId, email, role } = req.body;
  const session = await db.sessions.get(sessionId);
  if (!session?.verified) return res.status(401).json({ error: 'Invalid session.' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address.' });

  const sentCount = await db.sessions.incrementEmailsSent(sessionId);
  if (sentCount > 3)
    return res.status(429).json({ error: 'Zu viele E-Mail-Anfragen pro Session.' });

  const classification = classifyDomain(email);

  try {
    const result = await sendVerificationEmail({ email, role, sessionId, baseUrl: BASE_URL });
    const resp   = {
      sent: result.sent || result.devMode, devMode: result.devMode || false,
      domain: classification.domain, expectedLevel: classification.level,
      expectedTrustScore: classification.trustBonus, category: classification.category,
      expiresIn: '15 Minuten'
    };
    if (result.devMode) {
      // In dev mode (no SMTP), surface the code so the page can show it.
      if (result.code)     resp.devCode      = result.code;
      if (result.rawToken) resp.devToken     = result.rawToken;
      if (result.verifyUrl) resp.devVerifyUrl = result.verifyUrl;
    }
    res.json(resp);
  } catch (err) { res.status(500).json({ error: 'E-Mail-Fehler: ' + err.message }); }
});

app.get('/hhttps/email/verify', async (req, res) => {
  const { token, session: sessionId } = req.query;
  if (!token || !sessionId) return res.redirect('/?email_verify=error&reason=missing_params');

  const result = await verifyEmailToken(token);
  if (!result.valid) return res.redirect(`/?email_verify=error&reason=${encodeURIComponent(result.error)}`);

  const session = await db.sessions.get(sessionId);
  if (!session) return res.redirect('/?email_verify=error&reason=session_expired');

  await db.sessions.update(sessionId, {
    emailVerified:   true,
    emailLevel:      result.level,
    emailDomain:     result.domain,
    emailTrustBonus: result.trustBonus,
    emailCategory:   result.category
  });

  res.redirect(
    `/?email_verify=success&level=${encodeURIComponent(result.level)}` +
    `&score=${result.trustBonus}&domain=${encodeURIComponent(result.domain)}&session=${sessionId}`
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /hhttps/email/confirm-code
//
// Same-tab verification path: the user types the 6-digit code they received
// in the email into the page where they started, and we mark THIS session as
// emailVerified. No tab-switching, no cross-tab session glue.
//
// Body:     { sessionId, code }
// Response: { verified: true, level, domain, trustBonus, category, accountTrust }
//
app.post('/hhttps/email/confirm-code', limit.email, async (req, res) => {
  const { sessionId, code } = req.body || {};
  if (!sessionId || !code) return res.status(400).json({ error: 'sessionId and code required.' });

  const result = await verifyEmailCode(code, sessionId);
  if (!result.valid) return res.status(400).json({ error: result.error });

  const session = await db.sessions.get(sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found or expired.' });

  await db.sessions.update(sessionId, {
    emailVerified:   true,
    emailLevel:      result.level,
    emailDomain:     result.domain,
    emailTrustBonus: result.trustBonus,
    emailCategory:   result.category,
  });

  // Report the verification surface the user has RIGHT NOW (before adding more
  // methods), so the UI can immediately show the confirmed method badges. Trust
  // is internal/API-only; the UI renders `methods`, never the number.
  const v = computeVerification({
    email:       true,
    passkey:     !!(session.hasPasskey || session.credentialId),
    domain:      !!result.domain,
    domainTrust: result.trustBonus || 0,
    domainValue: result.domain || null,
    github:      !!session.githubVerified,
    eudi:        !!session.eudiVerified
  });

  res.json({
    verified:     true,
    level:        result.level,
    domain:       result.domain,
    trustBonus:   result.trustBonus,
    category:     result.category,
    methods:      v.methods,        // confirmed verification methods (UI shows these)
    accountTrust: v.trust,          // API only — the UI must not render this number
  });
});

app.post('/hhttps/email/status', async (req, res) => {
  const session = await db.sessions.get(req.body.sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found.' });
  res.json({
    emailVerified: session.emailVerified || false,
    emailLevel:    session.emailLevel    || null,
    emailDomain:   session.emailDomain   || null,
    trustBonus:    session.emailTrustBonus || null
  });
});

// ─── GitHub Verification (for `developer` role) ───────────────────────────────
// Pseudonymity-preserving: GitHub username/ID/repo-count/follower-count are
// NEVER persisted. Only sha256(github:id:pepper) and the resulting trust
// score survive. See external-verify.js for the full contract.

app.get('/hhttps/verify/github/start', async (req, res) => {
  const { session: sessionId } = req.query;
  if (!sessionId) return res.status(400).send('session parameter required');

  const session = await db.sessions.get(sessionId);
  if (!session?.verified) return res.status(401).send('Invalid session.');

  if (!isGithubConfigured()) {
    return res.status(503).json({
      error: 'github_not_configured',
      detail: 'This HHTTPS issuer has no GitHub OAuth app configured. Please contact the operator.'
    });
  }

  try {
    const authUrl = await startGithubVerify({ sessionId, redirectBase: BASE_URL });
    res.redirect(authUrl);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/hhttps/verify/github/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`/?github_verify=error&reason=${encodeURIComponent(error)}`);
  if (!code || !state) return res.redirect('/?github_verify=error&reason=missing_params');

  try {
    const result = await handleGithubCallback({ code, state, redirectBase: BASE_URL });
    const warn = result.alreadyOwnedBy ? ' (warning: anchor collision)' : '';
    // Render a self-closing landing page instead of redirecting the popup back
    // to the SPA. The original tab is already polling /hhttps/verify/github/status
    // and will pick up the verification on its own — we just need this tab to
    // get out of the way without dragging fresh JS state into the user's flow.
    res.send(renderGithubReturnPage({
      ok: true,
      title: 'GitHub verified',
      message: 'You can close this tab and return to hhttps.org.' + warn
    }));
  } catch (e) {
    res.send(renderGithubReturnPage({
      ok: false,
      title: 'GitHub verification failed',
      message: e.message
    }));
  }
});

// ─── Static landing page for the GitHub OAuth popup tab ─────────────────────
// Bilingual (EN/DE stacked), self-closes after 2 s. Inline CSS keeps it tiny.
function renderGithubReturnPage({ ok, title, message }) {
  const color = ok ? '#34d399' : '#f87171';
  const icon  = ok ? '✓'  : '✗';
  // v0.5: the trust score is API-only and is NEVER shown to the user — no score line.
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><title>${title}</title>
<style>
  body{margin:0;background:#0d1421;color:#e2f0fa;font:14px/1.6 system-ui,sans-serif;
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
  .card{max-width:420px;text-align:center;background:#161e30;border:1px solid #2a3550;
        border-radius:12px;padding:32px 28px;}
  .icon{font-size:48px;color:${color};margin-bottom:8px;line-height:1;}
  h1{font-size:18px;margin:0 0 12px;color:#e2f0fa;}
  .msg{color:#a0b8d8;font-size:14px;line-height:1.5;margin:0 0 6px;}
  .lang-de{color:#7a8aa0;font-size:13px;margin-top:14px;border-top:1px solid #2a3550;padding-top:12px;}
  button{margin-top:18px;background:#00e5ff;color:#0d1421;border:0;border-radius:6px;
         padding:10px 22px;font:600 13px/1 system-ui,sans-serif;cursor:pointer;}
</style></head><body>
  <div class="card">
    <div class="icon">${icon}</div>
    <h1>${title}</h1>
    <p class="msg">${escapeHtml(message)}</p>
    <p class="lang-de">Du kannst diesen Tab schließen und zu hhttps.org zurückkehren.</p>
    <button onclick="window.close()">Close tab / Tab schließen</button>
  </div>
  <script>
    // Best-effort: try to close after 2 s. Some browsers refuse to close tabs
    // that weren't opened via window.open() — the button is the manual fallback.
    setTimeout(() => { try { window.close(); } catch(e){} }, 2000);
  </script>
</body></html>`;
}

app.post('/hhttps/verify/github/status', async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  res.json(await getGithubStatus(sessionId));
});

// ─── Role Declaration ─────────────────────────────────────────────────────────

app.post('/hhttps/role/declare', async (req, res) => {
  const { sessionId, role, verificationMethod, verificationData, ageGroup } = req.body;
  const session = await db.sessions.get(sessionId);
  if (!session?.verified) return res.status(401).json({ error: 'Invalid or expired session.' });

  // Pseudonym is optional and human-readable. It travels two paths:
  //   1) via the email-first flow's session-merge (already on the session), or
  //   2) directly in verificationData when the user typed it on the role page.
  // We sanitize aggressively (letters/digits/dash/dot/space + German umlauts,
  // max 32 chars) and prefer the request-fresh value over the session copy.
  let pseudonym = (verificationData && verificationData.pseudonym) || session.pseudonym || null;
  if (pseudonym) {
    pseudonym = String(pseudonym)
      .replace(/[^\w\-. äöüÄÖÜß]/gu, '')
      .slice(0, 32)
      .trim() || null;
  }

  // v0.5: roles are no longer self-declared. The base identity is simply "human".
  // A professional role arrives ONLY via an EUDI (Q)EAA (handled by eudi-verifier),
  // so we do not take a role from the request. The sign-in gate is no longer email-
  // specific: ANY one genuinely verified method (email, passkey, EUDI Wallet, GitHub)
  // establishes a human identity. It is enforced below, after the verification
  // surface is computed (see "Sign-in gate" near computeVerification).

  // Optional age_group (orthogonal to role). Phase 1: self-declared only —
  // honestly labelled, low trust, age_verified:false. Phase 3 will set this
  // from an EUDI Wallet PID presentation (age_over_NN) with method 'eudi-wallet'.
  let ageClaims = null;
  if (ageGroup) {
    const ag = AGE_GROUPS[ageGroup];
    if (!ag) return res.status(400).json({
      error: `Unknown age group: ${ageGroup}`, available: Object.keys(AGE_GROUPS)
    });
    const ageMethod = AGE_VERIFICATION_METHODS['self-declared'];
    ageClaims = {
      age_group:                ag.id,
      age_verified:             ageMethod.verified,        // false in Phase 1
      age_verification_method:  ageMethod.id               // 'self-declared'
    };
  }

  // ─── Verification surface (v0.5) ────────────────────────────────────────────
  // Build the method flag-bag from the session and let roles.js compute the
  // additive, API-only trust + the official HHTTPS method headers + the badges.
  // Self-declared role picking and the typed-in role-ID honesty gate are gone;
  // the only role path is an EUDI (Q)EAA (handled by the eudi-verifier).
  const ageVerifiedFlag = !!(ageClaims && ageClaims.age_verified === true);
  const flags = {
    email:       !!session.emailVerified,
    passkey:     !!(session.hasPasskey || session.credentialId),
    domain:      !!session.emailDomain,
    domainTrust: session.emailTrustBonus || 0,
    domainValue: session.emailDomain || null,
    github:      !!session.githubVerified,
    eudi:        !!session.eudiVerified,           // set by the EUDI eID flow (eudi-verifier)
    age:         ageVerifiedFlag                   // self-declared age is trust-neutral, not a "method"
  };
  const v = computeVerification(flags);
  const trustScore = v.trust;

  // Sign-in gate (v0.5, method-neutral): at least ONE genuinely verified method
  // must be present. Age is self-declared / trust-neutral and never counts; the
  // honesty gate lives in computeVerification (only real checks add trust), so a
  // trust-bearing method == a real method. An empty bootstrap session is refused.
  const realMethods = v.methods.filter(m => m !== 'age');
  if (realMethods.length === 0) {
    return res.status(403).json({
      error: 'At least one verified method (email, passkey, EUDI Wallet or GitHub) is required.'
    });
  }

  // Issue access + refresh token. The access token carries the human identity,
  // the verified_methods[] array and (optional, orthogonal) age claims. No role.
  const { token } = await issueAccessToken({
    userId:     session.userId,
    role:       null,
    roleLabel:  null,
    roleLevel:  null,
    trustScore,
    method:     'verification-methods',
    deviceType: session.deviceType,
    verified_methods:    v.methods,
    verification_status: 'verified',
    ...(session.emailDomain ? { domain_name: session.emailDomain } : {}),
    ...(pseudonym ? { pseudonym } : {}),
    ...(ageClaims || {})   // age_group / age_verified / age_verification_method (optional)
  });
  const refresh = await issueRefreshToken(session.userId, session.credentialId, null, {
    verifiedMethods: v.methods, trustScore, emailDomain: session.emailDomain || null
  });

  // Zero-PII: role / methods / trust are NOT persisted against the user. The
  // session keeps only the transient trust for in-flow display; the durable
  // identity lives in the signed tokens (client-held), never in the database.
  await db.sessions.update(sessionId, { trustScore });

  fireEvent('identity.verified', { trustScore, methods: v.methods });
  fireEvent('token.issued',      { trustScore, methods: v.methods });

  setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                   role: null, trustScore, token, method: 'verification-methods',
                   verifiedMethods: v.methods, domainValue: session.emailDomain || null,
                   ageGroup:              ageClaims?.age_group || null,
                   ageVerified:           ageClaims ? ageClaims.age_verified : null,
                   ageVerificationMethod: ageClaims?.age_verification_method || null });
  setIdentityCookie(res, token);  // trademark: the HHTTPS fields mirrored into the cookie

  // Human-readable badge list for the UI (the UI shows methods, never the score).
  const badges = v.badges.map(id => ({
    id, label: VERIFICATION_METHODS[id]?.label || id, verified: true,
    value: id === 'domain' ? (session.emailDomain || null)
         : id === 'age'    ? (ageClaims?.age_group || null) : null
  }));

  res.json({
    hhttps: {
      version: '0.5.0', status: 'verified', human: true, actorType: 'human',
      token, refreshToken: refresh,
      expiresAt:        new Date(Date.now() + ACCESS_TTL  * 1000).toISOString(),
      refreshExpiresAt: new Date(Date.now() + REFRESH_TTL * 1000).toISOString(),
      trustScore,                 // API only — the UI must not render this number
      verifiedMethods: v.methods
    },
    verification: {
      methods:       badges,      // confirmed methods (what the UI renders)
      pseudonym:     pseudonym || null,
      emailVerified: session.emailVerified || false,
      emailDomain:   session.emailDomain   || null
    },
    role: null,                    // no self-declared role (EUDI EAA only)
    ageGroup: ageClaims ? {
      id:        ageClaims.age_group,
      label:     AGE_GROUPS[ageClaims.age_group].label,
      verified:  ageClaims.age_verified,
      method:    ageClaims.age_verification_method,
      methodLabel: AGE_VERIFICATION_METHODS[ageClaims.age_verification_method]?.label,
      note:      'Self-declared — verifiable via EUDI Wallet.'
    } : null,
    message: `✓ Human verified · ${badges.length} method(s) · Access (1h) + Refresh (7d)`
  });
});

// ─── EUDI age upgrade (Phase 3) ───────────────────────────────────────────────
//
// INTERNAL endpoint. Called only by the eudi-verifier service (port 3002) after a
// successful OpenID4VP age presentation. Lifts a self-declared age_group to a
// cryptographically verified one (age_verified:true, method:eudi-wallet, trust 99)
// by reissuing the holder's token with the verified age claims.
//
// SECURITY — defence in depth (single-server setup, no mTLS needed):
//   1. nginx MUST NOT expose this path externally (allow 127.0.0.1; deny all).
//   2. The request MUST carry a valid HMAC-SHA256 assertion signed with the
//      shared EUDI_VERIFIER_SECRET. Without the secret, a caller cannot forge an
//      upgrade — so even if the path were reachable, age_over_18:true can't be
//      injected. The assertion binds {sessionId, ageOver, nonce, iat} so it
//      can't be replayed onto another session.
//
// Body: {
//   sessionId,                       // the holder's active hhttps session
//   ageOver: { age_over_14?, age_over_16?, age_over_18? },  // disclosed booleans
//   assertion                        // HMAC-SHA256 hex over the canonical payload
// }
app.post('/hhttps/age/upgrade', async (req, res) => {
  try {
    const { sessionId, ageOver, assertion, nonce, iat, currentToken } = req.body || {};

    if (!sessionId || typeof ageOver !== 'object' || ageOver === null || !assertion) {
      return res.status(400).json({ error: 'sessionId, ageOver and assertion are required.' });
    }

    const secret = process.env.EUDI_VERIFIER_SECRET;
    if (!secret) {
      console.error('[AGE-UPGRADE] EUDI_VERIFIER_SECRET not configured — refusing.');
      return res.status(503).json({ error: 'Age verification not configured.' });
    }

    // Recompute the HMAC over a canonical, sorted representation and compare in
    // constant time. The verifier must sign exactly this structure.
    const canonical = JSON.stringify({
      sessionId,
      ageOver: {
        age_over_14: ageOver.age_over_14 === true,
        age_over_16: ageOver.age_over_16 === true,
        age_over_18: ageOver.age_over_18 === true
      },
      nonce: nonce || null,
      iat:   iat   || null
    });
    const expected = crypto.createHmac('sha256', secret).update(canonical).digest('hex');

    const a = Buffer.from(String(assertion), 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      console.warn(`[AGE-UPGRADE] invalid assertion for session ${String(sessionId).slice(0,8)}…`);
      return res.status(401).json({ error: 'Invalid verifier assertion.' });
    }

    // Reject stale assertions (replay window: 5 min) when iat is provided.
    if (iat) {
      const ageMs = Date.now() - Number(iat);
      if (!Number.isFinite(ageMs) || ageMs < -60_000 || ageMs > 300_000) {
        return res.status(401).json({ error: 'Assertion expired or clock skew too large.' });
      }
    }

    // Session must exist and be a verified human session.
    const session = await db.sessions.get(sessionId);
    if (!session?.verified) {
      return res.status(404).json({ error: 'Unknown or expired session.' });
    }

    // Map the disclosed EUDI booleans to the narrowest age band (Phase 3 bridge).
    const ageGroupId = ageGroupFromEudiClaims(ageOver);
    const ag = AGE_GROUPS[ageGroupId];
    const eudiMethod = AGE_VERIFICATION_METHODS['eudi-wallet'];

    // Carry forward EUDI identity from the holder's current signed token (eID
    // lives in the token, not the session), so verifying age after eID does not
    // drop the +40 eudi method.
    let priorEudi = false;
    if (currentToken) {
      try {
        const prev = verifyToken(currentToken);
        priorEudi = prev?.eudi_verified === true ||
                    (Array.isArray(prev?.verified_methods) && prev.verified_methods.includes('eudi'));
      } catch (_) { /* invalid/expired — ignore */ }
    }

    // Reissue the holder's token with VERIFIED age claims. age_group lives in the
    // token (client-driven design); no session schema change is needed.
    // Recompute the verification surface, now with age cryptographically verified.
    // Age is TRUST-NEUTRAL (contributesToTrust:false): this flips HHTTPS-Age-Verified
    // to true and adds 'age' to verified_methods, but the trust score is UNCHANGED.
    // No role (EUDI EAA only). No age_trust / no "99".
    const flags = {
      email:       !!session.emailVerified,
      passkey:     !!(session.hasPasskey || session.credentialId),
      domain:      !!session.emailDomain,
      domainTrust: session.emailTrustBonus || 0,
      domainValue: session.emailDomain || null,
      github:      !!session.githubVerified,
      eudi:        priorEudi,
      age:         true
    };
    const v = computeVerification(flags);

    const { token } = await issueAccessToken({
      userId:     session.userId,
      role:       null,
      roleLabel:  null,
      roleLevel:  null,
      trustScore: v.trust,                          // age added 0 — trust UNCHANGED by design
      method:     'verification-methods',
      deviceType: session.deviceType,
      verified_methods:        v.methods,
      verification_status:     'verified',
      ...(session.emailDomain ? { domain_name: session.emailDomain } : {}),
      ...(priorEudi ? { eudi_verified: true } : {}),
      // verified age claims (orthogonal, trust-neutral):
      age_group:               ag.id,
      age_verified:            true,                 // cryptographically verified now
      age_verification_method: eudiMethod.id         // 'eudi-wallet'
    });
    // Reissue the refresh token too, so the upgraded surface survives the 1h
    // access-token expiry (zero-PII — the surface rides in the signed token).
    const refresh = await issueRefreshToken(session.userId, session.credentialId, null, {
      verifiedMethods: v.methods, trustScore: v.trust, emailDomain: session.emailDomain || null
    });

    // Mirror the verified age into the identity cookie. NOTE: this endpoint is
    // called server-side by the eudi-verifier, so this Set-Cookie reaches that
    // internal response — NOT the browser. The browser cookie is (re)set by the
    // browser-facing /eudi/age/status handler, which adopts this same token.
    setIdentityCookie(res, token);

    console.log(`[AGE-UPGRADE] session ${String(sessionId).slice(0,8)}… → ${ag.id} (eudi-wallet, verified)`);
    await db.stats.increment('age_verifications');
    fireEvent('age.verified', { ageGroup: ag.id, method: 'eudi-wallet' });

    res.json({
      hhttps: { version: '0.5.0', token, refreshToken: refresh, trustScore: v.trust, verifiedMethods: v.methods },
      ageGroup: {
        id:       ag.id,
        label:    ag.label,
        verified: true,
        method:   eudiMethod.id
      },
      message: `✓ Age verified: ${ag.label} (EUDI Wallet)`
    });
  } catch (e) {
    console.error('[AGE-UPGRADE] error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── EUDI eID identity upgrade (v0.5) ─────────────────────────────────────────
//
// INTERNAL endpoint (127.0.0.1 only, like /hhttps/age/upgrade). Called by the
// eudi-verifier after a VALID PID presentation. Establishes "EUDI verified" on
// the session (the +40 `eudi` method) and reissues the holder's token. ZERO-PII:
// no PID attribute is read or stored — the proof is the validated presentation.
//
// Orthogonal age claims (which live in the token, not the session) are carried
// forward from the holder's current signed token if it is supplied.
//
// Body: { sessionId, currentToken?, nonce, iat, assertion }
//   assertion = HMAC-SHA256 over canonical { sessionId, eidVerified:true, nonce, iat }
app.post('/hhttps/eid/upgrade', async (req, res) => {
  try {
    const { sessionId, currentToken, nonce, iat, assertion } = req.body || {};
    if (!sessionId || !assertion) {
      return res.status(400).json({ error: 'sessionId and assertion are required.' });
    }

    const secret = process.env.EUDI_VERIFIER_SECRET;
    if (!secret) {
      console.error('[EID-UPGRADE] EUDI_VERIFIER_SECRET not configured — refusing.');
      return res.status(503).json({ error: 'EUDI verification not configured.' });
    }

    const canonical = JSON.stringify({
      sessionId, eidVerified: true, nonce: nonce || null, iat: iat || null
    });
    const expected = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
    const a = Buffer.from(String(assertion), 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      console.warn(`[EID-UPGRADE] invalid assertion for session ${String(sessionId).slice(0,8)}…`);
      return res.status(401).json({ error: 'Invalid verifier assertion.' });
    }

    if (iat) {
      const ageMs = Date.now() - Number(iat);
      if (!Number.isFinite(ageMs) || ageMs < -60_000 || ageMs > 300_000) {
        return res.status(401).json({ error: 'Assertion expired or clock skew too large.' });
      }
    }

    const session = await db.sessions.get(sessionId);
    if (!session?.verified) {
      return res.status(404).json({ error: 'Unknown or expired session.' });
    }

    // eID lives in the TOKEN, not the session (like age) — no session column and
    // no DB migration. The +40 rides in the reissued access + refresh tokens.

    // Carry forward any orthogonal age claims from the holder's current signed
    // token (age lives in the token, not the session, by design).
    let ageCarry = {};
    if (currentToken) {
      try {
        const prev = verifyToken(currentToken);
        if (prev && prev.age_group) {
          ageCarry = {
            age_group:               prev.age_group,
            age_verified:            prev.age_verified === true,
            age_verification_method: prev.age_verification_method || null
          };
        }
      } catch (_) { /* invalid/expired token — reissue without age */ }
    }

    // Recompute the verification surface with eudi now true → +40.
    const flags = {
      email:       !!session.emailVerified,
      passkey:     !!(session.hasPasskey || session.credentialId),
      domain:      !!session.emailDomain,
      domainTrust: session.emailTrustBonus || 0,
      domainValue: session.emailDomain || null,
      github:      !!session.githubVerified,
      eudi:        true,
      age:         ageCarry.age_verified === true
    };
    const v = computeVerification(flags);

    const { token } = await issueAccessToken({
      userId:     session.userId,
      role:       null,
      roleLabel:  null,
      roleLevel:  null,
      trustScore: v.trust,
      method:     'verification-methods',
      deviceType: session.deviceType,
      verified_methods:    v.methods,
      verification_status: 'verified',
      eudi_verified:       true,
      ...(session.emailDomain ? { domain_name: session.emailDomain } : {}),
      ...ageCarry
    });
    // Reissue the refresh token so the +40 survives the 1h access-token expiry.
    const refresh = await issueRefreshToken(session.userId, session.credentialId, null, {
      verifiedMethods: v.methods, trustScore: v.trust, emailDomain: session.emailDomain || null
    });

    // NOTE: server-to-server call — this Set-Cookie reaches the eudi-verifier, not
    // the browser. The browser cookie is (re)set by the browser-facing
    // /eudi/eid/status handler, which adopts this same token.
    setIdentityCookie(res, token);

    console.log(`[EID-UPGRADE] session ${String(sessionId).slice(0,8)}… → eudi-verified (+40)`);
    await db.stats.increment('eudi_verifications');
    fireEvent('eudi.verified', { trustScore: v.trust });

    res.json({
      hhttps: { version: '0.5.0', token, refreshToken: refresh, trustScore: v.trust, verifiedMethods: v.methods },
      eudi:   { verified: true, method: 'eudi-eid' },
      message: '✓ EUDI verified (eID)'
    });
  } catch (e) {
    console.error('[EID-UPGRADE] error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── iamhmn-card issuance (HHTTPS as issuer → role INTO the wallet) ───────────
//
// The "create a role yourself" path. The user defines a role (ESCO dropdown or
// free text) and optionally provides a document; HHTTPS issues an iamhmn-card
// EAA into their wallet via EUDIPLO with an HONEST RAL:
//   • no document            → RAL0 (self-declared)
//   • document provided       → RAL1 (accredited; pilot: self-asserted, live: reviewed)
//   • reserved profession     → RAL0 is REFUSED (needs document or external (Q)EAA).
//
// Returns an offer URI the frontend renders as a QR / deep-link. Zero-PII: no
// document is persisted; the role + RAL travel inside the issued card only.
//
// Body: { sessionId, esco?:{label,isco08,escoUri}, customRole?, documentProvided?, locale? }
app.post('/hhttps/role/card', async (req, res) => {
  try {
    const { sessionId, esco = null, customRole = null, documentProvided = false } = req.body || {};
    const session = await db.sessions.get(sessionId);
    if (!session?.verified) return res.status(401).json({ error: 'Invalid or expired session.' });
    // Method-neutral human gate (v0.5): any one genuinely verified method qualifies,
    // not email specifically (consistent with /hhttps/role/declare).
    const hasMethod = !!(session.emailVerified || session.hasPasskey || session.credentialId
                         || session.githubVerified || session.eudiVerified);
    if (!hasMethod) return res.status(403).json({ error: 'At least one verified method is required first.' });

    let roleInput = null, custom = false, customLabel = null, reservedKey = null;
    if (customRole) {
      const c = sanitizeCustomRole(customRole);
      if (!c.ok) return res.status(400).json({
        error: c.reason === 'reserved'
          ? 'This profession is protected and cannot be self-declared. Provide a document or present a qualified attestation.'
          : 'Please provide a job title.',
        reason: c.reason, matched: c.matched || null, reservedKey: c.key || null
      });
      custom = true; customLabel = c.label;
    } else if (esco && (esco.label || esco.isco08 || esco.escoUri)) {
      roleInput = { label: esco.label || null, isco08: esco.isco08 || null, escoUri: esco.escoUri || null };
      const g = guardReservedRole(esco.label || '', esco.isco08 || null);
      reservedKey = g.key;
      if (g.reserved && !documentProvided) {
        const hint = reservedKey && RESERVED_REGISTRY[reservedKey] ? RESERVED_REGISTRY[reservedKey].sourceHint : 'a qualified source';
        return res.status(400).json({
          error: `"${esco.label || esco.isco08}" is a protected profession. Self-declaration (RAL0) is not allowed.`,
          reason: 'reserved', reservedKey,
          remedy: `Upload a document for RAL1, or present a qualified attestation from ${hint} (RAL2).`
        });
      }
    } else {
      return res.status(400).json({ error: 'Provide either an ESCO role or a customRole.' });
    }

    const method = documentProvided ? 'document-checked' : 'self-declared';
    const verificationStatus = documentProvided ? 'verified' : 'self-declared';
    const humanVerified = !!(session.hasPasskey || session.credentialId);

    const built = buildRoleClaim({ roleInput, custom, customLabel, verificationStatus, method, humanVerified });

    const cardClaims = {
      userId:     session.userId,
      role:       built.role.id,
      roleLabel:  built.role.label,
      ral:        built.ral,
      human:      humanVerified,
      method,
      issuer:     `hhttps://${RP_ID}`,
      ...(built.role.taxonomy?.isco08  ? { isco08:  built.role.taxonomy.isco08 }  : {}),
      ...(built.role.taxonomy?.uri     ? { escoUri: built.role.taxonomy.uri }     : {}),
      ...(built.role.reserved          ? { reserved: 'true' }                     : {})
    };

    const offer = await issueIamhmnCard(cardClaims);

    fireEvent('card.issued', { ral: built.ral, role: built.role.id, reserved: !!built.role.reserved });

    res.json({
      hhttps: { version: '0.5.0' },
      card: {
        role: built.role, ral: built.ral,
        ...(built.verification ? { verification: built.verification } : {}),
        note: documentProvided
          ? 'Document accepted (pilot: self-asserted, verified against registers in live operation) → RAL1.'
          : 'Self-declared role → RAL0.'
      },
      offer: { uri: offer.uri, crossDeviceUri: offer.crossDeviceUri || offer.uri },
      message: `iamhmn-card ready to load into the wallet · RAL ${built.ral}`
    });
  } catch (e) {
    console.error('[ROLE-CARD] error:', e.message);
    res.status(502).json({ error: 'Card issuance failed.', detail: e.message });
  }
});

// ─── Token Revocation ─────────────────────────────────────────────────────────

app.post('/hhttps/revoke', limit.revoke, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });

  try {
    const decoded = verifyToken(token);
    await db.revokedTokens.add(decoded.jti, decoded.role, 'user-requested');
    await db.tokens.delete(decoded.jti);
    await db.refreshTokens.delete(decoded.jti);
    await db.stats.increment('tokens_revoked');

    console.log(`[REVOKE] jti=${decoded.jti.slice(0, 8)}... role=${decoded.role}`);
    fireEvent('token.revoked', { role: decoded.role });

    setHHTPPS(res, { status: 'revoked', human: false, actorType: 'unknown' });
    clearIdentityCookie(res);  // drop the hhttps.org-scoped convenience cookie
    res.json({ hhttps: { status: 'revoked' }, revoked: true, jti: decoded.jti });
  } catch (e) {
    // Allow revoking expired tokens by extracting jti from payload
    try {
      const raw = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      if (raw.jti) {
        await db.revokedTokens.add(raw.jti, raw.role, 'user-requested-expired');
        await db.tokens.delete(raw.jti);
        await db.refreshTokens.delete(raw.jti);
      }
    } catch {}
    res.status(401).json({ error: e.message });
  }
});

app.get('/hhttps/revoke/status', async (req, res) => {
  const { jti } = req.query;
  if (!jti) return res.status(400).json({ error: 'jti required' });
  const revoked = await db.revokedTokens.has(jti);
  const active  = await db.tokens.exists(jti);
  res.json({ jti, revoked, active: active && !revoked });
});

// ─── Token Validate ──────────────────────────────────────────────────────────

app.post('/hhttps/validate', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token required' });
  try {
    const d       = await checkTokenValid(token);
    const roleDef = ROLES[d.role] || ROLES.citizen;
    setHHTPPS(res, { status: 'valid', human: true, actorType: 'human', role: d.role,
                     roleLevel: d.roleLevel, trustScore: d.trustScore,
                     token, method: d.method });
    res.json({
      hhttps: { status: 'valid', human: true, actorType: 'human', version: '0.5.0' },
      claims: { role: d.role, roleLabel: roleDef.label, roleIcon: roleDef.icon,
                roleLevel: d.roleLevel, trustScore: d.trustScore,
                issuedAt: new Date(d.iat * 1000).toISOString(),
                expiresAt: new Date(d.exp * 1000).toISOString(),
                method: d.method, issuer: d.iss, kid: d.kid }
    });
  } catch (e) {
    setHHTPPS(res, { status: 'invalid', human: false, actorType: 'unknown' });
    res.status(401).json({ hhttps: { status: 'invalid', human: false }, error: e.message });
  }
});

// ─── Protected example ────────────────────────────────────────────────────────

app.get('/hhttps/protected', async (req, res) => {
  const token = req.headers['hhttps-token'] || req.headers['authorization']?.replace('Bearer ', '');
  if (!token) {
    setHHTPPS(res, { status: 'required' });
    res.setHeader('HHTTPS-Challenge-Endpoint', '/hhttps/webauthn/auth/start');
    return res.status(401).json({ hhttps: { status: 'token-required' },
                                   authEndpoint: '/hhttps/webauthn/auth/start' });
  }
  try {
    const d = await checkTokenValid(token);
    setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                     role: d.role, trustScore: d.trustScore, token, method: d.method });
    res.json({
      hhttps:  { status: 'verified', method: d.method },
      message: '🎉 Human-verified access granted.',
      resource: { title: 'HHTTPS-protected content',
                  content: 'For humans only. Cryptographically proven without personal data.',
                  verifiedAt: new Date().toISOString(), role: d.role }
    });
  } catch (e) { res.status(401).json({ hhttps: { status: 'invalid' }, error: e.message }); }
});

// ─── Machine Tokens ───────────────────────────────────────────────────────────

app.post('/hhttps/machine/register', limit.machine, async (req, res) => {
  const { operatorName, operatorUrl, purpose, contactEmail, role } = req.body;
  if (!operatorName || !purpose)
    return res.status(400).json({ error: 'operatorName and purpose are required.' });

  // Optional self-declared role for the bot. v0.5: roles are ESCO-dynamic, so a
  // bot may declare a free-form role — EXCEPT a reserved profession (doctor/
  // lawyer/notary/police/…), which a machine can never self-declare.
  let normalizedRole = null;
  let roleLabel = null;
  let roleIcon = null;
  if (role) {
    const g = guardReservedRole(role);
    if (g.reserved) {
      return res.status(400).json({
        error: 'invalid_role',
        detail: `"${role}" is a protected profession and cannot be self-declared by a machine.`,
        reservedKey: g.key || null
      });
    }
    const desc = resolveRole({ label: role });
    normalizedRole = desc.id;
    roleLabel      = desc.label;
    roleIcon       = '🤖';
  }

  const operatorId = 'op-' + crypto.randomBytes(8).toString('hex');
  const apiKey     = 'mk-' + crypto.randomBytes(24).toString('hex');
  const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

  await db.machineOperators.create({
    operatorId, operatorName, operatorUrl, purpose, contactEmail, apiKeyHash,
    role: normalizedRole, roleLabel, roleIcon,
  });

  res.status(201).json({
    hhttps: { version: '0.5.0' },
    operatorId, apiKey,
    role: normalizedRole,
    roleLabel,
    warning: 'Store the API key securely — it is shown only once.',
    tokenEndpoint: `${BASE_URL}/hhttps/machine/token`,
    message: `Operator "${operatorName}"${normalizedRole ? ` (role: ${roleLabel})` : ''} registered. Issue machine tokens with apiKey.`
  });
});

app.post('/hhttps/machine/token', limit.machine, async (req, res) => {
  const { operatorId, apiKey } = req.body;
  if (!operatorId || !apiKey)
    return res.status(400).json({ error: 'operatorId and apiKey are required.' });

  const op = await db.machineOperators.get(operatorId);
  if (!op) return res.status(404).json({ error: 'Operator not found.' });

  const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  if (keyHash !== op.api_key_hash)
    return res.status(401).json({ error: 'Invalid API key.' });

  const jti   = uuid();
  const tokenPayload = {
    jti, sub: 'machine', iss: `https://${RP_ID}`, hhttps_iss: `hhttps://${RP_ID}`,
    human: false, actorType: 'bot',
    operatorId, operatorName: op.operator_name, purpose: op.purpose
    // `iat` is set automatically by jsonwebtoken (RFC 7519 standard claim).
  };
  // If the operator self-declared a role at /machine/register, propagate it
  // into the token claims. Origins (like ask.iamhmn.org) can use this for
  // role-based logic just as they do for human OAuth tokens.
  if (op.role) {
    tokenPayload.role       = op.role;
    tokenPayload.role_label = op.role_label;
    tokenPayload.role_icon  = op.role_icon;
  }
  const token = signToken(tokenPayload, { expiresIn: MACHINE_TTL });

  await db.tokens.create({
    jti, type: 'machine', operatorId, ttlMs: MACHINE_TTL * 1000
  });
  await db.machineOperators.incrementTokensIssued(operatorId);

  setHHTPPS(res, { status: 'verified', human: false, actorType: 'bot',
                   method: 'machine-token', machineOperator: operatorId,
                   machinePurpose: op.purpose });
  res.json({
    hhttps: { version: '0.5.0', human: false, actorType: 'bot' },
    token, expiresAt: new Date(Date.now() + MACHINE_TTL * 1000).toISOString(),
    operator: { id: operatorId, name: op.operator_name, purpose: op.purpose }
  });
});

// ─── Webhooks ────────────────────────────────────────────────────────────────

app.get('/hhttps/webhooks', limit.webhooks, async (req, res) => {
  res.json({ hhttps: { version: '0.5.0' }, webhooks: await listWebhooks() });
});

app.post('/hhttps/webhooks', limit.webhooks, async (req, res) => {
  const { url, events = ['*'], secret } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required.' });
  try {
    const wh = await registerWebhook({ url, events, secret });
    res.status(201).json({
      hhttps: { version: '0.5.0' },
      webhook: { id: wh.id, url: wh.url, events: wh.events, secret: wh.secret },
      note: 'Speichere das Secret — Requests werden mit HMAC-SHA256 signiert (HHTTPS-Webhook-Sig).'
    });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/hhttps/webhooks/:id', limit.webhooks, async (req, res) => {
  const ok = await removeWebhook(req.params.id);
  ok ? res.json({ deleted: true, id: req.params.id })
     : res.status(404).json({ error: 'Webhook not found.' });
});

app.post('/hhttps/webhooks/verify', (req, res) => {
  const { payload, signature, secret } = req.body;
  if (!payload || !signature || !secret)
    return res.status(400).json({ error: 'payload, signature, secret are required.' });
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
  res.json({ valid: expected === signature, expected, received: signature });
});

// ─── Phase 3b: Developer Self-Service + Admin ─────────────────────────────
//
// Endpoints for platform operators to register their OAuth clients
// without manual admin intervention, and for admins (operator of this
// HHTTPS issuer) to verify, reject, and suspend platforms.
//
// State machine for oauth_clients.verification_status:
//   draft → email_pending → unverified → pending_review → verified
//                                                       ↘ rejected
//                              ↑
//                              └── (after email change, drops back)
// Plus: verified/unverified/pending_review → suspended (admin action)
//
// Hard requirements for `verified`:
//   1. email_verified_at IS NOT NULL    (user clicked confirmation link)
//   2. domain_email_match = TRUE        (email's apex matches platform's apex)
//   3. dns_verified_at IS NOT NULL      (TXT record at _hhttps-verify.<apex>)
//   4. Admin clicked Approve            (verification_status='verified')

/** Resolve apex domain (last two parts, with two-part TLDs like co.uk handled). */
function apexDomainFromUrl(urlOrHost) {
  if (!urlOrHost) return null;
  let host;
  try {
    host = (urlOrHost.includes('://') ? new URL(urlOrHost).hostname : urlOrHost).toLowerCase();
  } catch (e) {
    return null;
  }
  return normalizeApexDomain(host);
}
function apexDomainFromEmail(email) {
  if (!email || !email.includes('@')) return null;
  return normalizeApexDomain(email.split('@')[1].toLowerCase());
}

/** Variant A: email's apex must equal platform's apex.
 *  Subdomain mail is accepted (e.g. admin@team.example.com for example.com). */
function emailMatchesPlatform(email, homepageUrl) {
  const e = apexDomainFromEmail(email);
  const h = apexDomainFromUrl(homepageUrl);
  return !!(e && h && e === h);
}

/** Generate a short random hex token (URL-safe). */
function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Resolve current user from request (Authorization header). Returns null
 *  if no token, throws if token invalid/expired. */
async function authenticatedUser(req) {
  const token = req.headers['hhttps-token'] ||
                req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return null;
  const d = await checkTokenValid(token);  // throws on invalid/revoked
  return {
    userId:     d.uid || d.userId || d.sub,
    role:       d.role,
    trustScore: d.trustScore || 0
  };
}

/** Convenience wrapper for routes requiring authentication. */
async function requireUser(req, res) {
  try {
    const u = await authenticatedUser(req);
    if (!u || !u.userId) {
      res.status(401).json({ error: 'unauthorized', message: 'Authentication required' });
      return null;
    }
    return u;
  } catch (err) {
    res.status(401).json({ error: 'invalid_token', message: err.message });
    return null;
  }
}

async function requireAdmin(req, res) {
  const u = await requireUser(req, res);
  if (!u) return null;
  if (!await db.admins.isAdmin(u.userId)) {
    res.status(403).json({ error: 'forbidden', message: 'Admin privileges required' });
    return null;
  }
  return u;
}

/** Validate redirect URI format. Must be a syntactically valid HTTPS URL
 *  (or http://localhost for dev). */
function isValidRedirectUri(uri) {
  if (typeof uri !== 'string' || uri.length > 500) return false;
  try {
    const u = new URL(uri);
    if (u.protocol === 'https:') return true;
    if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) return true;
    return false;
  } catch (e) {
    return false;
  }
}

/** Slug-ify a platform name for client_id generation.
 *  Returns something like "my-platform-x4z7". */
function generateClientId(name) {
  const slug = (name || 'platform')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
  const tail = crypto.randomBytes(2).toString('hex');
  return `${slug || 'platform'}-${tail}`;
}

// ─── POST /hhttps/developers/clients — Register a new platform ─────────────
app.post('/hhttps/developers/clients', limit.check, async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;

  const { name, description, homepage_url, redirect_uris, contact_email,
          impressum_url, logo_url } = req.body || {};

  // Validation
  if (!name || typeof name !== 'string' || name.length < 2 || name.length > 120) {
    return res.status(400).json({ error: 'invalid_name',
      message: 'Name must be 2-120 characters' });
  }
  if (!homepage_url || !apexDomainFromUrl(homepage_url)) {
    return res.status(400).json({ error: 'invalid_homepage',
      message: 'homepage_url must be a valid HTTPS URL' });
  }
  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || redirect_uris.length > 10) {
    return res.status(400).json({ error: 'invalid_redirect_uris',
      message: 'Provide 1-10 redirect URIs' });
  }
  for (const uri of redirect_uris) {
    if (!isValidRedirectUri(uri)) {
      return res.status(400).json({ error: 'invalid_redirect_uri',
        message: `Not a valid redirect URI: ${uri}` });
    }
  }
  if (!contact_email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(contact_email)) {
    return res.status(400).json({ error: 'invalid_email',
      message: 'Valid contact_email required' });
  }
  if (description && description.length > 2000) {
    return res.status(400).json({ error: 'description_too_long',
      message: 'Description must be ≤ 2000 chars' });
  }

  // Rate limit: max 3 new clients per user per 24h
  const recent = await db.oauthClients.countRecentByOwner(u.userId, 24);
  if (recent >= 3) {
    return res.status(429).json({ error: 'rate_limited',
      message: 'You may only register 3 platforms per day' });
  }

  // Compute domain match + generate tokens
  const domainMatch  = emailMatchesPlatform(contact_email, homepage_url);
  const emailToken   = randomToken(24);
  const emailExpires = new Date(Date.now() + 48 * 3600 * 1000); // 48h
  const dnsToken     = `hhttps-verify=${randomToken(20)}`;
  const clientId     = generateClientId(name);

  try {
    await db.oauthClients.createDraft({
      clientId,
      name, description, homepageUrl: homepage_url,
      redirectUris: redirect_uris,
      contactEmail: contact_email,
      impressumUrl: impressum_url,
      logoUrl: logo_url,
      ownerUserId: u.userId,
      domainEmailMatch: domainMatch,
      emailToken, emailTokenExpiresAt: emailExpires,
      dnsToken
    });
  } catch (err) {
    console.error('[DEVELOPERS] createDraft failed:', err.message);
    return res.status(500).json({ error: 'creation_failed', message: err.message });
  }

  // Send confirmation email
  try {
    const confirmUrl = `${BASE_URL}/hhttps/developers/confirm-email?token=${emailToken}`;
    await sendPlatformRegistrationEmail({
      to:           contact_email,
      platformName: name,
      homepageUrl:  homepage_url,
      confirmUrl,
      kind:         'registration'
    });
  } catch (err) {
    console.warn('[DEVELOPERS] platform registration email failed:', err.message);
    // Continue — user can request resend later
  }

  res.json({
    success: true,
    client_id: clientId,
    verification_status: 'email_pending',
    domain_email_match: domainMatch,
    warnings: domainMatch ? [] : [{
      code: 'email_domain_mismatch',
      message: 'Contact email domain does not match platform domain. ' +
               'Platform can be created and used as "unverified", but cannot be promoted ' +
               'to "verified" status until you set an email at the platform domain.'
    }],
    next_steps: [
      'Check your inbox and click the confirmation link.',
      domainMatch
        ? 'Add a DNS TXT record at _hhttps-verify.<your-domain> with the value shown in your dashboard.'
        : 'Change your contact email to an address at the platform domain.',
      'Submit for review once email confirmed, domain matches, and DNS verified.'
    ]
  });
});

// ─── GET /hhttps/developers/confirm-email?token=... ────────────────────────
// User clicks this link in their email. Returns HTML for visual feedback.
app.get('/hhttps/developers/confirm-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Missing token');

  const client = await db.oauthClients.getByEmailToken(token);
  if (!client) {
    return res.status(404).type('html').send(renderSimplePage(
      'Link invalid or expired · Link ungültig oder abgelaufen',
      'The confirmation link is invalid or has already expired. Please request a new link in the dashboard.'
      + '<br><br><span lang="de">Der Bestätigungslink ist ungültig oder bereits abgelaufen. Bitte fordere im Dashboard einen neuen Link an.</span>'
    ));
  }

  await db.oauthClients.confirmEmail(client.client_id);
  res.type('html').send(renderSimplePage(
    'Email confirmed ✓ · Email bestätigt ✓',
    `Your platform <strong>${escapeHtml(client.name)}</strong> is now in status <code>unverified</code>. ` +
    `You can now log in at <a href="${BASE_URL}/developers">developers</a> and set the DNS TXT record to request verification.` +
    `<br><br><span lang="de">Deine Plattform <strong>${escapeHtml(client.name)}</strong> ist jetzt im Status <code>unverified</code>. ` +
    `Du kannst dich jetzt einloggen unter <a href="${BASE_URL}/developers">developers</a> und ` +
    `den DNS-TXT-Record setzen, um die Verifikation zu beantragen.</span>`
  ));
});

// ─── GET /hhttps/developers/clients — List my platforms ────────────────────
app.get('/hhttps/developers/clients', async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;
  const clients = await db.oauthClients.listAllByOwner(u.userId);
  res.json({
    success: true,
    clients: clients.map(serializeClientForOwner)
  });
});

// ─── GET /hhttps/developers/clients/:id — Detail ───────────────────────────
app.get('/hhttps/developers/clients/:id', async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;
  const client = await db.oauthClients.get(req.params.id);
  if (!client || client.owner_user_id !== u.userId) {
    return res.status(404).json({ error: 'not_found' });
  }
  res.json({ success: true, client: serializeClientForOwner(client) });
});

// ─── PATCH /hhttps/developers/clients/:id — Update metadata ────────────────
app.patch('/hhttps/developers/clients/:id', async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;

  const client = await db.oauthClients.get(req.params.id);
  if (!client || client.owner_user_id !== u.userId) {
    return res.status(404).json({ error: 'not_found' });
  }

  const { name, description, redirect_uris, logo_url, impressum_url, contact_email } = req.body || {};

  // Validate updates
  if (name !== undefined && (typeof name !== 'string' || name.length < 2 || name.length > 120)) {
    return res.status(400).json({ error: 'invalid_name' });
  }
  if (description !== undefined && description !== null && description.length > 2000) {
    return res.status(400).json({ error: 'description_too_long' });
  }
  if (redirect_uris !== undefined) {
    if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || redirect_uris.length > 10) {
      return res.status(400).json({ error: 'invalid_redirect_uris' });
    }
    for (const uri of redirect_uris) {
      if (!isValidRedirectUri(uri)) {
        return res.status(400).json({ error: 'invalid_redirect_uri', uri });
      }
    }
  }

  // Email change → reset verification
  if (contact_email !== undefined && contact_email !== client.contact_email) {
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(contact_email)) {
      return res.status(400).json({ error: 'invalid_email' });
    }
    const newMatch = emailMatchesPlatform(contact_email, client.homepage_url);
    const newToken = randomToken(24);
    const newExp   = new Date(Date.now() + 48 * 3600 * 1000);
    await db.oauthClients.updateContactEmail(client.client_id, contact_email, newMatch, newToken, newExp);
    try {
      const confirmUrl = `${BASE_URL}/hhttps/developers/confirm-email?token=${newToken}`;
      await sendPlatformRegistrationEmail({
        to:           contact_email,
        platformName: client.name,
        homepageUrl:  client.homepage_url,
        confirmUrl,
        kind:         'email_change'
      });
    } catch (err) { console.warn('[DEVELOPERS] email change email failed:', err.message); }
  }

  // Metadata updates
  await db.oauthClients.updateMetadata(client.client_id, {
    name, description, redirectUris: redirect_uris, logoUrl: logo_url, impressumUrl: impressum_url
  });

  const updated = await db.oauthClients.get(client.client_id);
  res.json({ success: true, client: serializeClientForOwner(updated) });
});

// ─── DELETE /hhttps/developers/clients/:id — Delete draft ──────────────────
app.delete('/hhttps/developers/clients/:id', async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;
  const deleted = await db.oauthClients.deleteIfDraft(req.params.id, u.userId);
  if (!deleted) return res.status(409).json({ error: 'cannot_delete',
    message: 'Only draft/email_pending clients can be deleted. Use suspend instead.' });
  res.json({ success: true });
});

// ─── POST /hhttps/developers/clients/:id/dns-check ────────────────────────
// Triggers a DNS lookup for _hhttps-verify.<apex> and matches against dns_token.
app.post('/hhttps/developers/clients/:id/dns-check', async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;

  const client = await db.oauthClients.get(req.params.id);
  if (!client || client.owner_user_id !== u.userId) {
    return res.status(404).json({ error: 'not_found' });
  }
  if (!client.dns_token) {
    return res.status(400).json({ error: 'no_dns_token',
      message: 'This client does not have a DNS token. Internal inconsistency.' });
  }

  const apex = apexDomainFromUrl(client.homepage_url);
  if (!apex) {
    return res.status(400).json({ error: 'no_apex',
      message: 'Cannot resolve apex domain from homepage_url' });
  }

  // DNS lookup via Node's dns/promises
  const { Resolver } = await import('dns/promises');
  const resolver = new Resolver();
  resolver.setServers(['1.1.1.1', '8.8.8.8']);

  let found = false;
  let records = [];
  try {
    records = await resolver.resolveTxt(`_hhttps-verify.${apex}`);
    // records is array of arrays of strings (TXT can have multiple chunks)
    for (const recordChunks of records) {
      const joined = recordChunks.join('');
      if (joined.trim() === client.dns_token.trim()) {
        found = true;
        break;
      }
    }
  } catch (err) {
    await db.oauthClients.touchDnsCheck(client.client_id);
    return res.json({
      success: false,
      dns_verified: false,
      error: 'dns_lookup_failed',
      message: `Could not resolve _hhttps-verify.${apex}: ${err.code || err.message}`,
      expected_record: client.dns_token,
      expected_host: `_hhttps-verify.${apex}`
    });
  }

  await db.oauthClients.touchDnsCheck(client.client_id);
  if (found) {
    await db.oauthClients.setDnsVerified(client.client_id);
    return res.json({ success: true, dns_verified: true });
  }

  return res.json({
    success: false,
    dns_verified: false,
    error: 'record_not_found',
    message: 'TXT record exists but value does not match. Make sure the value is exactly the dns_token.',
    expected_record: client.dns_token,
    expected_host: `_hhttps-verify.${apex}`,
    found_records: records.map(r => r.join(''))
  });
});

// ─── POST /hhttps/developers/clients/:id/submit-review ─────────────────────
// Owner asks for admin verification. Checks all hard requirements first.
app.post('/hhttps/developers/clients/:id/submit-review', async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;

  const client = await db.oauthClients.get(req.params.id);
  if (!client || client.owner_user_id !== u.userId) {
    return res.status(404).json({ error: 'not_found' });
  }
  if (client.verification_status !== 'unverified') {
    return res.status(409).json({ error: 'wrong_state',
      message: `Cannot submit for review from state '${client.verification_status}'. ` +
               `Must be 'unverified' (email confirmed, ready for DNS+admin).` });
  }

  // Hard checks
  const failures = [];
  if (!client.email_verified_at) failures.push('Email not confirmed');
  if (!client.domain_email_match) failures.push('Contact email does not match platform domain');
  if (!client.dns_verified_at)    failures.push('DNS TXT record not verified');
  if (!client.impressum_url)      failures.push('Impressum URL missing');

  if (failures.length > 0) {
    return res.status(412).json({ error: 'preconditions_failed',
      message: 'The following requirements must be met before submitting for review:',
      failures });
  }

  await db.oauthClients.submitForReview(client.client_id, {
    ownerRole: u.role, ownerTrust: u.trustScore
  });
  res.json({ success: true, verification_status: 'pending_review' });
});

// ─── GET /hhttps/developers/clients/:id/stats ─────────────────────────────
app.get('/hhttps/developers/clients/:id/stats', async (req, res) => {
  const u = await requireUser(req, res);
  if (!u) return;
  const client = await db.oauthClients.get(req.params.id);
  if (!client || client.owner_user_id !== u.userId) {
    return res.status(404).json({ error: 'not_found' });
  }
  const days = Math.min(parseInt(req.query.days || '30', 10), 90);
  const [daily, total] = await Promise.all([
    db.clientStats.getDaily(client.client_id, days),
    db.clientStats.getTotal(client.client_id)
  ]);
  res.json({ success: true, client_id: client.client_id, days, total, daily });
});

// ─── Admin endpoints ──────────────────────────────────────────────────────

// GET /hhttps/admin/clients/pending — admin queue
app.get('/hhttps/admin/clients/pending', async (req, res) => {
  const a = await requireAdmin(req, res);
  if (!a) return;
  const clients = await db.oauthClients.listPendingReview();
  res.json({ success: true, clients: clients.map(serializeClientForAdmin) });
});

// POST /hhttps/admin/clients/:id/approve
app.post('/hhttps/admin/clients/:id/approve', async (req, res) => {
  const a = await requireAdmin(req, res);
  if (!a) return;
  const client = await db.oauthClients.get(req.params.id);
  if (!client) return res.status(404).json({ error: 'not_found' });
  if (client.verification_status !== 'pending_review') {
    return res.status(409).json({ error: 'wrong_state',
      message: `Can only approve clients in 'pending_review' state. Current: ${client.verification_status}` });
  }
  await db.oauthClients.adminApprove(client.client_id, a.userId);
  await db.adminActions.log('verify_client', 'oauth_client', client.client_id, a.userId,
    { previous_status: 'pending_review' });
  // Notify platform owner by email (fire-and-forget — never block the response)
  if (client.contact_email) {
    sendPlatformVerifiedEmail({
      to:           client.contact_email,
      platformName: client.name,
      homepageUrl:  client.homepage_url
    }).catch(err => console.warn('[ADMIN] verified email failed:', err.message));
  }
  res.json({ success: true });
});

// POST /hhttps/admin/clients/:id/reject  body: { reason }
app.post('/hhttps/admin/clients/:id/reject', async (req, res) => {
  const a = await requireAdmin(req, res);
  if (!a) return;
  const reason = (req.body?.reason || '').toString().slice(0, 1000).trim();
  if (!reason) return res.status(400).json({ error: 'reason_required' });
  const client = await db.oauthClients.get(req.params.id);
  if (!client) return res.status(404).json({ error: 'not_found' });
  await db.oauthClients.adminReject(client.client_id, a.userId, reason);
  await db.adminActions.log('reject_client', 'oauth_client', client.client_id, a.userId,
    { previous_status: client.verification_status, reason });
  if (client.contact_email) {
    sendPlatformRejectedEmail({
      to:           client.contact_email,
      platformName: client.name,
      reason
    }).catch(err => console.warn('[ADMIN] rejected email failed:', err.message));
  }
  res.json({ success: true });
});

// POST /hhttps/admin/clients/:id/suspend  body: { reason }
app.post('/hhttps/admin/clients/:id/suspend', async (req, res) => {
  const a = await requireAdmin(req, res);
  if (!a) return;
  const reason = (req.body?.reason || '').toString().slice(0, 1000).trim();
  if (!reason) return res.status(400).json({ error: 'reason_required' });
  const client = await db.oauthClients.get(req.params.id);
  if (!client) return res.status(404).json({ error: 'not_found' });
  await db.oauthClients.adminSuspend(client.client_id, a.userId, reason);
  await db.adminActions.log('suspend_client', 'oauth_client', client.client_id, a.userId,
    { previous_status: client.verification_status, reason });
  res.json({ success: true });
});

// GET /hhttps/admin/clients — list all (with filter)
app.get('/hhttps/admin/clients', async (req, res) => {
  const a = await requireAdmin(req, res);
  if (!a) return;
  const status = req.query.status;
  const { rows } = await db.pool().query(
    status
      ? `SELECT * FROM oauth_clients WHERE verification_status = $1 ORDER BY created_at DESC LIMIT 200`
      : `SELECT * FROM oauth_clients ORDER BY created_at DESC LIMIT 200`,
    status ? [status] : []
  );
  const clients = rows.map(r => {
    try { r.redirect_uris  = JSON.parse(r.redirect_uris); } catch (e) { r.redirect_uris = []; }
    try { r.allowed_scopes = JSON.parse(r.allowed_scopes); } catch (e) { r.allowed_scopes = []; }
    return serializeClientForAdmin(r);
  });
  res.json({ success: true, clients });
});

// GET /hhttps/admin/stats — system overview
app.get('/hhttps/admin/stats', async (req, res) => {
  const a = await requireAdmin(req, res);
  if (!a) return;
  const { rows } = await db.pool().query(
    `SELECT verification_status, COUNT(*)::int AS n
       FROM oauth_clients
       GROUP BY verification_status`
  );
  const recentActions = await db.adminActions.listRecent(20);
  res.json({
    success: true,
    clients_by_status: rows,
    recent_admin_actions: recentActions
  });
});

// ─── Helpers used by Phase 3b endpoints ────────────────────────────────────

/** Serialize a client for owner-facing dashboard. Includes sensitive metadata
 *  (DNS token, contact email) but never the client_secret_hash. */
function serializeClientForOwner(c) {
  if (!c) return null;
  const apex = apexDomainFromUrl(c.homepage_url);
  return {
    client_id:              c.client_id,
    name:                   c.name,
    description:            c.description,
    homepage_url:           c.homepage_url,
    redirect_uris:          c.redirect_uris,
    contact_email:          c.contact_email,
    impressum_url:          c.impressum_url,
    logo_url:               c.logo_url,
    verification_status:    c.verification_status,
    verified:               c.verified,
    domain_email_match:     c.domain_email_match,
    email_verified_at:      c.email_verified_at,
    dns_verified_at:        c.dns_verified_at,
    dns_last_checked_at:    c.dns_last_checked_at,
    dns_token:              c.dns_token,
    dns_record_host:        apex ? `_hhttps-verify.${apex}` : null,
    submitted_for_review_at:c.submitted_for_review_at,
    reviewed_at:            c.reviewed_at,
    rejection_reason:       c.rejection_reason,
    created_at:             c.created_at,
    last_used_at:            c.last_used_at,
    // Eligibility for next step
    eligible_for_review: !!(c.verification_status === 'unverified' &&
                            c.email_verified_at &&
                            c.domain_email_match &&
                            c.dns_verified_at &&
                            c.impressum_url),
    blockers: [
      !c.email_verified_at      && 'email_not_verified',
      !c.domain_email_match     && 'email_domain_mismatch',
      !c.dns_verified_at        && 'dns_not_verified',
      !c.impressum_url          && 'impressum_missing'
    ].filter(Boolean)
  };
}

/** Serialize a client for admin queue. Includes everything plus owner_role hints. */
function serializeClientForAdmin(c) {
  if (!c) return null;
  return {
    ...serializeClientForOwner(c),
    owner_user_id:          c.owner_user_id,
    owner_role_at_submit:   c.owner_role_at_submit,
    owner_trust_at_submit:  c.owner_trust_at_submit
  };
}

/** Tiny HTML response template — used by the email confirm callback. */
function renderSimplePage(title, body) {
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>${escapeHtml(title)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{margin:0;font-family:system-ui,sans-serif;background:#03050a;color:#dfe7ea;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
  .card{max-width:520px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
        border-radius:14px;padding:36px 32px;}
  h1{font-size:24px;margin:0 0 16px;color:#00e5ff;font-weight:600;}
  p{line-height:1.6;}
  a{color:#00e5ff;text-decoration:none;border-bottom:1px dashed rgba(0,229,255,.4);}
  a:hover{border-bottom-color:#00e5ff;}
  code{font-family:'JetBrains Mono',monospace;background:rgba(0,0,0,.3);padding:2px 6px;border-radius:4px;font-size:13px;}
</style></head><body>
<div class="card"><h1>${escapeHtml(title)}</h1><p>${body}</p>
<p style="margin-top:24px;font-size:13px;opacity:.6;">— HHTTPS Issuer · hhttps.org</p>
</div></body></html>`;
}

// ─── Public Stats ─────────────────────────────────────────────────────────────

app.get('/hhttps/stats', async (req, res) => {
  const [s, dist, c] = await Promise.all([
    db.stats.getAll(),
    db.rolesDeclared.distribution(),
    Promise.all([
      db.tokens.count(), db.refreshTokens.count(),
      db.credentials.count(), db.revokedTokens.count(),
      db.machineOperators.count(),
      listWebhooks().then(w => w.length)
    ])
  ]);

  const total = dist.reduce((sum, r) => sum + r.n, 0);

  sendJson(req, res, {
    hhttps: { version: '0.5.0' },
    stats: {
      verifications:       s.verifications      || 0,
      tokensIssued:        s.tokens_issued      || 0,
      tokensRevoked:       s.tokens_revoked     || 0,
      checkCalls:          s.check_calls        || 0,
      machineChecks:       s.machine_checks     || 0,
      activeTokens:        c[0],
      activeRefreshTokens: c[1],
      registeredPasskeys:  c[2],
      revokedTokens:       c[3],
      machineOperators:    c[4],
      registeredWebhooks:  c[5],
      roleDistribution:    Object.fromEntries(
        dist.map(r => [r.role, total > 0 ? `${Math.round(r.n / total * 100)}%` : '0%'])
      ),
      uptime: Math.floor(process.uptime()) + 's'
    }
  }, {
    title:    'Public Stats',
    subtitle: 'Aggregated server statistics — no personal data, no individual user info.'
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

async function main() {
  // 1. Init keys
  loadOrCreateKeys();

  // 1b. Init Privacy Pass module (loads VOPRF keys + runs migrations)
  await initPrivacyPass();

  // 1c. Start cleanup of expired pending OAuth states (GitHub verify)
  startGithubVerifyCleanup();

  // 2. Init database
  db.init();
  const dbOk = await db.ping();
  if (!dbOk) {
    console.error('\n❌ Database connection failed. Check DB_* environment variables.\n');
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`\n🔐 HHTTPS v4.1 · Port ${PORT}`);
    console.log(`   RP_ID:   ${RP_ID}`);
    console.log(`   ORIGIN:  ${ORIGIN}`);
    console.log(`   Signing: ES256 (asymmetric)`);
    console.log(`   Storage: PostgreSQL (persistent)`);
    console.log(`   Roles:   ESCO-dynamic (base: citizen; professions via ESCO + reserved registry)`);
    console.log(`\n   ✓ All v4 live bugs fixed   ✓ trust proxy + Helmet CSP`);
    console.log(`   ✓ JWKS / .well-known       ✓ Refresh + Machine Tokens`);
    console.log(`   ✓ Token Revocation         ✓ Webhooks (DB-backed)\n`);
  });
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
