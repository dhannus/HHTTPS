import 'dotenv/config';
/**
 * HHTTPS v4.1 — Role Identity API (PostgreSQL persistence)
 * HumanProof Initiative · daniel.hannuschka@tweakz.de
 * https://github.com/dhannus/HumanProof
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

import { ROLES, VERIFICATION_LEVELS } from './roles.js';
import {
  sendVerificationEmail, verifyEmailToken, classifyDomain,
  sendPlatformRegistrationEmail, sendPlatformVerifiedEmail, sendPlatformRejectedEmail
} from './email.js';
import { loadOrCreateKeys, signToken, verifyToken, getJWKS } from './keys.js';
import { registerWebhook, removeWebhook, listWebhooks, fireEvent } from './webhooks.js';
import * as db from './db.js';

// Privacy Pass module (additive, RFC 9576-9578)
import { initPrivacyPass, privacyPassRouter, privacyPassWellKnownRouter }
  from './privacy-pass/index.js';

// External provider verification (GitHub for now; extends to ORCID, LinkedIn)
import {
  isGithubConfigured, startGithubVerify, handleGithubCallback,
  getGithubStatus, startGithubVerifyCleanup
} from './external-verify.js';

// ─── Bootstrap ────────────────────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));

const PORT     = process.env.PORT    || 3000;
const RP_ID    = process.env.RP_ID   || 'funnysearch.eu';
const ORIGIN   = process.env.ORIGIN  || `https://${RP_ID}`;
const BASE_URL = process.env.BASE_URL || ORIGIN;
const RP_NAME  = 'HumanProof HHTTPS';

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
      <span class="badge"><span class="dot"></span>v0.4.1</span>
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
    <span>HumanProof Initiative</span>
    <a href="https://github.com/dhannus/HumanProof">GitHub</a>
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
    'HHTTPS-Role-Level','HHTTPS-Trust-Score','HHTTPS-Token',
    'HHTTPS-Issuer','HHTTPS-Method','HHTTPS-Refresh-Token',
    'HHTTPS-Machine-Operator','HHTTPS-Machine-Purpose'
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
    error: 'Rate limit erreicht.', retryAfter: Math.ceil(windowMs / 1000)
  })
});

const limit = {
  global:   rl(300),
  check:    rl(120),
  webauthn: rl(20, 15 * 60_000),
  email:    rl(5,  60 * 60_000),
  revoke:   rl(30),
  webhooks: rl(20, 60 * 60_000),
  machine:  rl(60)
};

app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/hhttps/info') return next();
  limit.global(req, res, next);
});

app.use(express.static(join(__dirname, 'public')));

// Privacy Pass routes (additive, see privacy-pass/index.js)
app.use(privacyPassWellKnownRouter);
app.use('/privacy-pass', privacyPassRouter);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function setHHTPPS(res, opts = {}) {
  const { status = 'unverified', human = false, actorType = 'unknown',
          role = null, roleLevel = null, trustScore = 0, token = null,
          method = 'none', machineOperator = null, machinePurpose = null } = opts;

  res.setHeader('HHTTPS-Protocol-Version', '0.4.1');
  res.setHeader('HHTTPS-Status',           status);
  res.setHeader('HHTTPS-Human',            String(human));
  res.setHeader('HHTTPS-Actor-Type',       actorType);
  res.setHeader('HHTTPS-Method',           method);
  res.setHeader('HHTTPS-Trust-Score',      String(trustScore));
  res.setHeader('HHTTPS-Issuer',           `hhttps://${RP_ID}`);
  if (role)            { res.setHeader('HHTTPS-Role', role); res.setHeader('HHTTPS-Role-Label', ROLES[role]?.label || role); }
  if (roleLevel)         res.setHeader('HHTTPS-Role-Level', roleLevel);
  if (token)             res.setHeader('HHTTPS-Token',      token);
  if (machineOperator)   res.setHeader('HHTTPS-Machine-Operator', machineOperator);
  if (machinePurpose)    res.setHeader('HHTTPS-Machine-Purpose',  machinePurpose);
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

// Slug generator: 12-char Crockford Base32 with prefix "hp-" for "HumanProof"
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
    jti, iss: `hhttps://${RP_ID}`, sub: 'human-verified',
    human: true, actorType: 'human', ia: Math.floor(Date.now() / 1000),
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

async function issueRefreshToken(userId, credId, role) {
  const jti = uuid();
  const tok = signToken({
    jti, sub: 'refresh', userId, credId, role,
    ia: Math.floor(Date.now() / 1000)
  }, { expiresIn: REFRESH_TTL });
  await db.refreshTokens.create({
    jti, userId, credentialId: credId, role, ttlMs: REFRESH_TTL * 1000
  });
  return tok;
}

async function checkTokenValid(token) {
  const decoded = verifyToken(token);
  if (await db.revokedTokens.has(decoded.jti)) throw new Error('Token widerrufen');
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
    issuer:                  `hhttps://${RP_ID}`,
    protocol_version:        '0.4.1',
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
    supported_roles:         Object.keys(ROLES),
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

// ─── Info ─────────────────────────────────────────────────────────────────────

app.get('/hhttps/info', async (req, res) => {
  setHHTPPS(res, { status: 'info', actorType: 'api' });

  const counts = await Promise.all([
    db.credentials.count(), db.tokens.count(), db.refreshTokens.count(),
    db.sessions.count(), db.revokedTokens.count(), db.machineOperators.count()
  ]);

  sendJson(req, res, {
    protocol: 'HHTTPS — Human-verified HTTPS', version: '0.4.1',
    initiative: 'HumanProof', contact: 'daniel.hannuschka@tweakz.de',
    github: 'github.com/dhannus/HumanProof', demo: 'https://hhttps.org',
    features: ['webauthn', 'roles-15', 'email-verification', 'refresh-tokens',
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
    roles: Object.values(ROLES).map(r => ({ id: r.id, label: r.label, icon: r.icon })),
    endpoints: {
      'GET  /.well-known/hhttps-configuration': 'Discovery',
      'GET  /.well-known/jwks.json':            'Public key (JWKS)',
      'POST /hhttps/check':                     '★ Human/machine + role check',
      'GET  /hhttps/roles':                     'Role registry (15 roles)',
      'POST /hhttps/webauthn/register/{start,finish}': 'Passkey registration',
      'POST /hhttps/webauthn/auth/{start,finish}':     'Passkey authentication',
      'POST /hhttps/token/refresh':             'Refresh access token',
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
      hhttps: { version: '0.4.1', human: false, actorType: 'unknown',
                status: 'unverified', message: 'Kein HHTTPS-Token. Bitte verifizieren.' }
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
        hhttps: { version: '0.4.1', human: false, actorType: 'bot',
                  status: 'verified', trustScore: 0, method: 'machine-token' },
        machine: { operatorId: d.operatorId, operatorName: d.operatorName,
                   purpose: d.purpose, issuedAt: new Date(d.ia * 1000).toISOString() }
      });
    }

    const roleDef = ROLES[d.role] || ROLES.citizen;
    const vlevel  = VERIFICATION_LEVELS[d.roleLevel] || VERIFICATION_LEVELS['self-declared'];

    setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                     role: d.role, roleLevel: d.roleLevel, trustScore: d.trustScore,
                     token, method: d.method });

    return res.json({
      hhttps: { version: '0.4.1', status: 'verified', human: true, actorType: 'human',
                method: d.method, trustScore: d.trustScore,
                issuedAt: new Date(d.ia * 1000).toISOString(),
                expiresAt: new Date(d.exp * 1000).toISOString(), issuer: d.iss },
      role: { id: d.role, label: roleDef.label, labelEn: roleDef.labelEn, icon: roleDef.icon,
              description: roleDef.description, level: d.roleLevel,
              levelLabel: vlevel.label, trustScore: d.trustScore,
              privileges: roleDef.privileges, userStory: roleDef.userStory }
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
      ia:         Math.floor(Date.now() / 1000),
      exp:        d.exp,    // matches the underlying token's expiry
      iss:        d.iss
    });

    return res.json({
      hhttps:    { version: '0.4.1', mode: 'beta-text-bound' },
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
        message: 'Der Text wurde nach dem Signieren verändert.'
      });
    }
    if (revoked) {
      return res.json({
        hhttps: { status: 'revoked' },
        match:  true,
        message: 'Signatur wurde widerrufen.'
      });
    }
    if (d.exp * 1000 < Date.now()) {
      return res.json({
        hhttps: { status: 'expired', match: true },
        match:  true,
        message: 'Signatur abgelaufen (Text aber unverändert).'
      });
    }

    const roleDef = ROLES[d.role] || ROLES.citizen;
    return res.json({
      hhttps: { version: '0.4.1', status: 'verified', mode: 'beta-text-bound', match: true },
      match: true,
      role: {
        id: d.role,
        label: roleDef.label,
        icon:  roleDef.icon,
        level: d.roleLevel,
        trustScore: d.trustScore
      },
      signedAt:   new Date(d.ia  * 1000).toISOString(),
      validUntil: new Date(d.exp * 1000).toISOString()
    });
  } catch (e) {
    return res.status(401).json({ hhttps: { status: 'invalid' }, error: e.message });
  }
});

// ─── Signatures (Phase 2.5: domain-bound, slug-based) ───────────────────────
// Replaces the v0.4.1 raw-token-in-marker approach. Now:
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
      hhttps: { version: '0.4.1', mode: 'slug' },
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
    hhttps:    { version: '0.4.1', status: 'verified' },
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
      title: 'Signatur widerrufen',
      subtitle: 'Diese Signatur wurde vom Unterzeichner widerrufen.'
    });
  }

  // Domain binding check
  if (sig.binding_type === 'web' && reqDomain && sig.bound_domain &&
      reqDomain !== sig.bound_domain) {
    out.hhttps.status      = 'wrong-domain';
    out.hhttps.expected    = sig.bound_domain;
    out.hhttps.observed    = reqDomain;
    out.warning            = `Diese Signatur wurde für ${sig.bound_domain} ausgestellt, aber auf ${reqDomain} verwendet. Möglicher Diebstahl.`;
    return sendJson(req, res, out, {
      title: 'Falsche Domain',
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
        out.warning       = 'Der Text wurde nach dem Signieren verändert.';
      }
    } catch (e) {
      // Ignore preview parse errors
    }
  }

  return sendJson(req, res, out, {
    title: `Signatur ${slug}`,
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

  return res.json({ hhttps: { version: '0.4.1' }, results: out });
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
      hhttps: { version: '0.4.1', status: 'revoked' },
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
const SCOPES_KNOWN    = new Set(['openid', 'role', 'verification_method']);

// Discovery (RFC 8414 / OpenID Connect Discovery 1.0)
app.get('/.well-known/openid-configuration', (req, res) => {
  sendJson(req, res, {
    issuer:                          `https://${RP_ID}`,
    authorization_endpoint:          `${BASE_URL}/hhttps/oauth/authorize`,
    token_endpoint:                  `${BASE_URL}/hhttps/oauth/token`,
    userinfo_endpoint:               `${BASE_URL}/hhttps/oauth/userinfo`,
    revocation_endpoint:              `${BASE_URL}/hhttps/oauth/revoke`,
    jwks_uri:                         `${BASE_URL}/.well-known/jwks.json`,
    scopes_supported:                 ['openid', 'role', 'verification_method'],
    response_types_supported:         ['code'],
    grant_types_supported:            ['authorization_code'],
    subject_types_supported:          ['pairwise', 'public'],
    id_token_signing_alg_values_supported: ['ES256'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    claims_supported: [
      'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time',
      'role', 'role_label', 'role_icon', 'trust_score',
      'verification_method', 'verification_method_label'
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
    return res.status(400).send(renderOAuthError('Nur response_type=code wird unterstützt.', 400));
  }
  if (!client_id) {
    return res.status(400).send(renderOAuthError('client_id ist erforderlich.', 400));
  }
  const client = await db.oauthClients.get(client_id);
  if (!client) {
    return res.status(400).send(renderOAuthError('Unbekannte client_id. Plattform ist nicht registriert.', 400));
  }
  if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send(renderOAuthError(
      'redirect_uri stimmt nicht mit dem registrierten Wert überein. Aus Sicherheitsgründen abgelehnt.', 400
    ));
  }

  // PKCE: required for public clients (no client_secret_hash)
  const isPublicClient = !client.client_secret_hash;
  if (isPublicClient && !code_challenge) {
    return redirectWithError(redirect_uri, state, 'invalid_request',
      'PKCE code_challenge ist für public clients erforderlich.');
  }

  // Scope validation
  const requestedScopes = (scope || 'openid').split(/\s+/).filter(Boolean);
  if (!requestedScopes.includes('openid')) {
    return redirectWithError(redirect_uri, state, 'invalid_scope',
      'Der Scope "openid" ist erforderlich.');
  }
  const unknownScopes = requestedScopes.filter(s => !SCOPES_KNOWN.has(s));
  if (unknownScopes.length > 0) {
    return redirectWithError(redirect_uri, state, 'invalid_scope',
      `Unbekannte Scopes: ${unknownScopes.join(', ')}`);
  }
  const deniedScopes = requestedScopes.filter(s => !client.allowed_scopes.includes(s));
  if (deniedScopes.length > 0) {
    return redirectWithError(redirect_uri, state, 'invalid_scope',
      `Plattform darf diese Scopes nicht anfragen: ${deniedScopes.join(', ')}`);
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
    sub:        pairwiseId,
    aud:        client_id,
    client_id,
    scope:      claimed.scopes.join(' '),
    role:       claimed.role,
    trustScore: claimed.trust_score
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
<title>OAuth-Fehler · HHTTPS</title>
<style>body{font-family:system-ui;background:#F8F1E4;color:#2D2823;padding:60px 20px;text-align:center}
.box{max-width:520px;margin:0 auto;background:#FCFAF5;border-radius:14px;padding:32px;box-shadow:0 4px 20px rgba(45,40,35,.08)}
h1{font-family:'Fraunces',serif;color:#C97D5B;margin-bottom:16px}
p{line-height:1.6;color:#4A413A}
a{color:#A86246;text-decoration:none}
</style></head><body><div class="box"><h1>OAuth-Fehler ${status}</h1><p>${message}</p>
<p><a href="https://hhttps.org">← zurück zu hhttps.org</a></p></div></body></html>`;
}

function renderConsentPage({ client, scopes, params }) {
  const verifiedBadge = client.verified
    ? `<span class="badge badge-verified">✓ Verifizierte Plattform</span>`
    : `<span class="badge badge-unverified">⚠ Nicht verifiziert</span>`;

  const unverifiedWarning = client.verified ? '' : `
    <div class="warning">
      <strong>Achtung — Diese Plattform ist nicht von hhttps.org geprüft.</strong>
      Klicke nur auf "Erlauben", wenn du der Plattform <em>${escapeHtml(client.name)}</em> wirklich vertraust.
      Prüfe besonders, ob die URL in der Adressleiste mit <code>${escapeHtml(client.homepage_url || '?')}</code> übereinstimmt.
    </div>
  `;

  const scopeRows = scopes.map(s => {
    const label = {
      'openid':              { icon: '🆔', title: 'Anonyme Identität',  desc: 'Eine pseudonyme Kennung, die nur diese Plattform sieht.' },
      'role':                { icon: '🎭', title: 'Rolle + Trust-Score', desc: 'Deine gesellschaftliche Rolle (z. B. Entwickler) und dein Vertrauenswert.' },
      'verification_method': { icon: '🔐', title: 'Verifikationsmethode', desc: 'Wie deine Rolle verifiziert wurde (z. B. ORCID, Presseausweis).' }
    }[s] || { icon: '?', title: s, desc: 'Unbekannter Scope.' };
    return `<div class="scope-row">
      <span class="scope-icon">${label.icon}</span>
      <div><div class="scope-title">${label.title}</div>
           <div class="scope-desc">${label.desc}</div></div>
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
</style></head><body>
<div class="wrap">
  <div class="header">
    <a class="logo" href="https://hhttps.org" style="text-decoration:none;color:inherit">
      <div class="logo-mark"></div>
      <div class="logo-text">HHTTPS</div>
    </a>
  </div>
  <div class="card">
    <div class="card-head">
      <div class="client-logo">${client.logo_url ? `<img src="${escapeHtml(client.logo_url)}" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:14px">` : '🏛️'}</div>
      <h1><em>${escapeHtml(client.name)}</em> möchte deine Identität sehen</h1>
      ${client.homepage_url ? `<div class="client-url">${escapeHtml(client.homepage_url)}</div>` : ''}
      ${verifiedBadge}
    </div>
    ${unverifiedWarning}
    <div class="scope-list">
      <div class="scope-list-head">Folgende Daten werden geteilt</div>
      ${scopeRows}
    </div>
    <div class="status" id="status"></div>
    <div class="actions">
      <button class="btn btn-deny" id="denyBtn">Ablehnen</button>
      <button class="btn btn-allow" id="allowBtn">Erlauben</button>
    </div>
    <div class="footer-note">Nur Rolle und Trust-Score werden geteilt. Keine PII. Du kannst die Verbindung jederzeit auf <a href="https://hhttps.org" style="color:var(--terra-dp);text-decoration:none">hhttps.org</a> widerrufen.</div>
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
  allow.textContent = 'Wird verarbeitet…';

  // Look for an identity in localStorage (published by hhttps.org main page)
  // or in browser extension storage. For Phase 3a we use localStorage.
  let identity = null;
  try {
    const raw = localStorage.getItem('hhttps_identity');
    if (raw) identity = JSON.parse(raw);
  } catch (e) {}

  if (!identity || !identity.token) {
    status.className = 'status error';
    status.textContent = 'Keine HHTTPS-Identität gefunden. Bitte zuerst auf hhttps.org einloggen.';
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
    if (!r.ok) throw new Error(d.error || 'OAuth-Fehler');
    window.location = d.redirect;
  } catch (e) {
    status.className = 'status error';
    status.textContent = 'Fehler: ' + e.message;
    allow.disabled = false;
    allow.textContent = 'Erlauben';
  }
});
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
    hhttps: { version: '0.4.1' },
    roles: Object.values(ROLES).map(r => ({
      id: r.id, label: r.label, labelEn: r.labelEn, icon: r.icon,
      description: r.description, verificationMethods: r.verificationMethods,
      verificationHints: r.verificationHints || {},
      privileges: r.privileges, userStory: r.userStory
    })),
    verificationLevels: VERIFICATION_LEVELS
  }, {
    title:    'Role Registry',
    subtitle: '15 supported roles with verification methods, trust levels, and user stories.'
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
      userName: `human-${userId.slice(0, 8)}`, userDisplayName: 'HumanProof Nutzer',
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
  if (!stored) return res.status(400).json({ error: 'Challenge abgelaufen.' });

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
  const { sessionId, response } = req.body;
  const stored = await db.challenges.get(sessionId);
  if (!stored) return res.status(400).json({ error: 'Session abgelaufen.' });

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

    // Create verified session (role declaration follows)
    const sid = uuid();
    await db.sessions.create(sid, {
      userId:       stored.userId || cred.userId,
      credentialId: cred.credentialId,
      deviceType:   cred.deviceType,
      backedUp:     cred.backedUp,
      verified:     true,
      trustScore:   60
    }, 600_000);
    await db.stats.increment('verifications');

    res.json({ verified: true, sessionId: sid, message: 'WebAuthn OK. Bitte Rolle deklarieren.' });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ─── Token Refresh ────────────────────────────────────────────────────────────

app.post('/hhttps/token/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });

  try {
    const d = verifyToken(refreshToken);
    if (d.sub !== 'refresh')              throw new Error('Kein Refresh-Token');
    if (await db.revokedTokens.has(d.jti)) throw new Error('Refresh-Token widerrufen');

    const stored = await db.refreshTokens.get(d.jti);
    if (!stored) throw new Error('Refresh-Token nicht aktiv');

    const cred       = stored.credential_id ? await db.credentials.get(stored.credential_id) : null;
    const role       = stored.role || d.role;
    const roleDef    = ROLES[role] || ROLES.citizen;
    const savedRole  = await db.rolesDeclared.get(stored.user_id);

    const { token: newAccess } = await issueAccessToken({
      userId:     stored.user_id,
      role,
      roleLabel:  roleDef.label,
      roleLevel:  savedRole?.role_level  || 'self-declared',
      trustScore: savedRole?.trust_score || 60,
      method:     'webauthn-passkey',
      deviceType: cred?.deviceType || 'unknown'
    });

    setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                     role, roleLevel: savedRole?.role_level,
                     trustScore: savedRole?.trust_score || 60,
                     token: newAccess, method: 'webauthn-passkey' });

    res.json({
      hhttps:    { version: '0.4.1', status: 'refreshed', human: true, actorType: 'human' },
      token:     newAccess,
      expiresAt: new Date(Date.now() + ACCESS_TTL * 1000).toISOString(),
      role:      { id: role, label: roleDef.label, trustScore: savedRole?.trust_score || 60 },
      message:   '✓ Neuer Access-Token ausgestellt — kein erneuter Fingerabdruck nötig.'
    });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// ─── Email Verification ───────────────────────────────────────────────────────

app.post('/hhttps/email/send', limit.email, async (req, res) => {
  const { sessionId, email, role } = req.body;
  const session = await db.sessions.get(sessionId);
  if (!session?.verified) return res.status(401).json({ error: 'Ungültige Session.' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Ungültige E-Mail-Adresse.' });

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
    if (result.devMode && result.rawToken) {
      resp.devToken     = result.rawToken;
      resp.devVerifyUrl = result.verifyUrl;
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

app.post('/hhttps/email/status', async (req, res) => {
  const session = await db.sessions.get(req.body.sessionId);
  if (!session) return res.status(404).json({ error: 'Session nicht gefunden.' });
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
  if (!session?.verified) return res.status(401).send('Ungültige Session.');

  if (!isGithubConfigured()) {
    return res.status(503).json({
      error: 'github_not_configured',
      detail: 'Dieser HHTTPS-Issuer hat keine GitHub-OAuth-App konfiguriert. Bitte den Betreiber kontaktieren.'
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
    const warn = result.alreadyOwnedBy ? '&warning=anchor_collision' : '';
    res.redirect(
      `/?github_verify=success&score=${result.trustScore}&session=${result.sessionId}${warn}`
    );
  } catch (e) {
    res.redirect(`/?github_verify=error&reason=${encodeURIComponent(e.message)}`);
  }
});

app.post('/hhttps/verify/github/status', async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  res.json(await getGithubStatus(sessionId));
});

// ─── Role Declaration ─────────────────────────────────────────────────────────

app.post('/hhttps/role/declare', async (req, res) => {
  const { sessionId, role, verificationMethod, verificationData } = req.body;
  const session = await db.sessions.get(sessionId);
  if (!session?.verified) return res.status(401).json({ error: 'Ungültige oder abgelaufene Session.' });

  const roleDef = ROLES[role];
  if (!roleDef) return res.status(400).json({
    error: `Unbekannte Rolle: ${role}`, available: Object.keys(ROLES)
  });

  let vMethod    = verificationMethod || 'self-declared';
  let trustScore = 60;
  let note       = null;

  // GitHub takes precedence for developer if both are set, since it's a
  // stronger pseudonymous signal than mere email-domain classification.
  if (session.githubVerified && session.githubTrustBonus && role === 'developer') {
    vMethod    = 'github-verified';
    trustScore = Math.max(trustScore, session.githubTrustBonus);
    note       = `GitHub-Konto verifiziert (Trust ${session.githubTrustBonus}).`;
  } else if (session.emailVerified && session.emailTrustBonus) {
    vMethod    = session.emailLevel || 'email-verified';
    trustScore = Math.max(trustScore, session.emailTrustBonus);
    note = `E-Mail-Domain "${session.emailDomain}" automatisch verifiziert.`;
  } else {
    const vlevel = VERIFICATION_LEVELS[vMethod] || VERIFICATION_LEVELS['self-declared'];
    trustScore   = Math.max(trustScore, vlevel.trustScore);

    // Optional: validate ID format for various verification methods
    if (vMethod === 'press-card'         && verificationData?.pressCardId)
      note = `Presseausweis-Nr. ${verificationData.pressCardId} eingereicht.`;
    if (vMethod === 'student-id'         && verificationData?.studentId)
      note = `Matrikelnummer "${verificationData.studentId}" eingereicht.`;
    if (vMethod === 'association-member' && verificationData?.memberId)
      note = `Verbandsmitglied-Nr. "${verificationData.memberId}" eingereicht.`;
    if (vMethod === 'bar-association-id' && verificationData?.barId)
      note = `RAK-Eintrag "${verificationData.barId}" eingereicht.`;
    if (vMethod === 'craft-chamber-id'   && verificationData?.craftId)
      note = `Handwerksrolle-Eintrag "${verificationData.craftId}" eingereicht.`;
    if (vMethod === 'orcid'              && verificationData?.orcid) {
      const ok = /^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/.test(verificationData.orcid);
      if (!ok) { vMethod = 'self-declared'; trustScore = 30; note = 'ORCID-Format ungültig.'; }
      else note = `ORCID ${verificationData.orcid} eingereicht.`;
    }
  }

  const cred = session.credentialId ? await db.credentials.get(session.credentialId) : null;

  // Issue access + refresh token
  // Note: `method` is the verification method that lifted the trust score
  // (github-verified, email-verified, orcid, ...). 'webauthn-passkey' is
  // the baseline assertion that there is a real human; vMethod tells you
  // WHAT was additionally verified about that human.
  const { token } = await issueAccessToken({
    userId:     session.userId,
    role,
    roleLabel:  roleDef.label,
    roleLevel:  vMethod,
    trustScore,
    method:     vMethod,
    deviceType: session.deviceType
  });
  const refresh = await issueRefreshToken(session.userId, session.credentialId, role);

  await db.rolesDeclared.upsert(session.userId, role, vMethod, trustScore);
  await db.sessions.update(sessionId, { role, roleLevel: vMethod, trustScore });

  // Webhooks (fire-and-forget)
  fireEvent('role.declared', { role, roleLevel: vMethod, trustScore });
  fireEvent('token.issued',  { role, trustScore, method: vMethod });

  setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                   role, roleLevel: vMethod, trustScore,
                   token, method: vMethod });
  res.setHeader('HHTTPS-Refresh-Token', refresh);

  res.json({
    hhttps: {
      version: '0.4.1', status: 'verified', human: true, actorType: 'human',
      token, refreshToken: refresh,
      expiresAt:        new Date(Date.now() + ACCESS_TTL  * 1000).toISOString(),
      refreshExpiresAt: new Date(Date.now() + REFRESH_TTL * 1000).toISOString(),
      trustScore
    },
    role: {
      id: role, label: roleDef.label, icon: roleDef.icon, level: vMethod,
      levelLabel: VERIFICATION_LEVELS[vMethod]?.label, trustScore,
      verificationNote: note, privileges: roleDef.privileges,
      emailVerified: session.emailVerified || false,
      emailDomain:   session.emailDomain   || null
    },
    message: `✓ "${roleDef.label}" · Trust ${trustScore}/100 · Access (1h) + Refresh (7d)`
  });
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
      hhttps: { status: 'valid', human: true, actorType: 'human', version: '0.4.1' },
      claims: { role: d.role, roleLabel: roleDef.label, roleIcon: roleDef.icon,
                roleLevel: d.roleLevel, trustScore: d.trustScore,
                issuedAt: new Date(d.ia * 1000).toISOString(),
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
      message: '🎉 Menschlich verifizierter Zugang gewährt.',
      resource: { title: 'HHTTPS-geschützter Inhalt',
                  content: 'Nur für Menschen. Kryptografisch bewiesen ohne persönliche Daten.',
                  verifiedAt: new Date().toISOString(), role: d.role }
    });
  } catch (e) { res.status(401).json({ hhttps: { status: 'invalid' }, error: e.message }); }
});

// ─── Machine Tokens ───────────────────────────────────────────────────────────

app.post('/hhttps/machine/register', limit.machine, async (req, res) => {
  const { operatorName, operatorUrl, purpose, contactEmail, role } = req.body;
  if (!operatorName || !purpose)
    return res.status(400).json({ error: 'operatorName und purpose sind erforderlich.' });

  // Optional self-declared role for the bot. Must be one of the existing
  // HHTTPS roles. No verification — pilot mode (see migration-phase-4 docs).
  let normalizedRole = null;
  let roleLabel = null;
  let roleIcon = null;
  if (role) {
    if (!ROLES[role]) {
      return res.status(400).json({
        error: 'invalid_role',
        detail: `Unbekannte Rolle "${role}". Erlaubte Rollen: ${Object.keys(ROLES).join(', ')}.`,
      });
    }
    normalizedRole = role;
    roleLabel      = ROLES[role].label;
    roleIcon       = ROLES[role].icon;
  }

  const operatorId = 'op-' + crypto.randomBytes(8).toString('hex');
  const apiKey     = 'mk-' + crypto.randomBytes(24).toString('hex');
  const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

  await db.machineOperators.create({
    operatorId, operatorName, operatorUrl, purpose, contactEmail, apiKeyHash,
    role: normalizedRole, roleLabel, roleIcon,
  });

  res.status(201).json({
    hhttps: { version: '0.4.1' },
    operatorId, apiKey,
    role: normalizedRole,
    roleLabel,
    warning: 'Speichere den API-Key sicher — er wird nur einmal angezeigt.',
    tokenEndpoint: `${BASE_URL}/hhttps/machine/token`,
    message: `Operator "${operatorName}"${normalizedRole ? ` (Rolle: ${roleLabel})` : ''} registriert. Mit apiKey Maschinen-Token ausstellen.`
  });
});

app.post('/hhttps/machine/token', limit.machine, async (req, res) => {
  const { operatorId, apiKey } = req.body;
  if (!operatorId || !apiKey)
    return res.status(400).json({ error: 'operatorId und apiKey erforderlich.' });

  const op = await db.machineOperators.get(operatorId);
  if (!op) return res.status(404).json({ error: 'Operator nicht gefunden.' });

  const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  if (keyHash !== op.api_key_hash)
    return res.status(401).json({ error: 'Ungültiger API-Key.' });

  const jti   = uuid();
  const tokenPayload = {
    jti, sub: 'machine', iss: `hhttps://${RP_ID}`,
    human: false, actorType: 'bot',
    operatorId, operatorName: op.operator_name, purpose: op.purpose,
    ia: Math.floor(Date.now() / 1000)
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
    hhttps: { version: '0.4.1', human: false, actorType: 'bot' },
    token, expiresAt: new Date(Date.now() + MACHINE_TTL * 1000).toISOString(),
    operator: { id: operatorId, name: op.operator_name, purpose: op.purpose }
  });
});

// ─── Webhooks ────────────────────────────────────────────────────────────────

app.get('/hhttps/webhooks', limit.webhooks, async (req, res) => {
  res.json({ hhttps: { version: '0.4.1' }, webhooks: await listWebhooks() });
});

app.post('/hhttps/webhooks', limit.webhooks, async (req, res) => {
  const { url, events = ['*'], secret } = req.body;
  if (!url) return res.status(400).json({ error: 'url erforderlich.' });
  try {
    const wh = await registerWebhook({ url, events, secret });
    res.status(201).json({
      hhttps: { version: '0.4.1' },
      webhook: { id: wh.id, url: wh.url, events: wh.events, secret: wh.secret },
      note: 'Speichere das Secret — Requests werden mit HMAC-SHA256 signiert (HHTTPS-Webhook-Sig).'
    });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/hhttps/webhooks/:id', limit.webhooks, async (req, res) => {
  const ok = await removeWebhook(req.params.id);
  ok ? res.json({ deleted: true, id: req.params.id })
     : res.status(404).json({ error: 'Webhook nicht gefunden.' });
});

app.post('/hhttps/webhooks/verify', (req, res) => {
  const { payload, signature, secret } = req.body;
  if (!payload || !signature || !secret)
    return res.status(400).json({ error: 'payload, signature, secret erforderlich.' });
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
      'Link ungültig oder abgelaufen',
      'Der Bestätigungslink ist ungültig oder bereits abgelaufen. Bitte fordere im Dashboard einen neuen Link an.'
    ));
  }

  await db.oauthClients.confirmEmail(client.client_id);
  res.type('html').send(renderSimplePage(
    'Email bestätigt ✓',
    `Deine Plattform <strong>${escapeHtml(client.name)}</strong> ist jetzt im Status <code>unverified</code>. ` +
    `Du kannst dich jetzt einloggen unter <a href="${BASE_URL}/developers">developers</a> und ` +
    `den DNS-TXT-Record setzen, um die Verifikation zu beantragen.`
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
  return `<!doctype html><html lang="de"><head>
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
    hhttps: { version: '0.4.1' },
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
    console.log(`   Roles:   ${Object.keys(ROLES).length} (citizen, ..., craftsman)`);
    console.log(`\n   ✓ All v4 live bugs fixed   ✓ trust proxy + Helmet CSP`);
    console.log(`   ✓ JWKS / .well-known       ✓ Refresh + Machine Tokens`);
    console.log(`   ✓ Token Revocation         ✓ Webhooks (DB-backed)\n`);
  });
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
