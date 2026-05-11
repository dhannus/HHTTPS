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
import { sendVerificationEmail, verifyEmailToken, classifyDomain } from './email.js';
import { loadOrCreateKeys, signToken, verifyToken, getJWKS } from './keys.js';
import { registerWebhook, removeWebhook, listWebhooks, fireEvent } from './webhooks.js';
import * as db from './db.js';

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

  if (session.emailVerified && session.emailTrustBonus) {
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
  const { token } = await issueAccessToken({
    userId:     session.userId,
    role,
    roleLabel:  roleDef.label,
    roleLevel:  vMethod,
    trustScore,
    method:     'webauthn-passkey',
    deviceType: session.deviceType
  });
  const refresh = await issueRefreshToken(session.userId, session.credentialId, role);

  await db.rolesDeclared.upsert(session.userId, role, vMethod, trustScore);
  await db.sessions.update(sessionId, { role, roleLevel: vMethod, trustScore });

  // Webhooks (fire-and-forget)
  fireEvent('role.declared', { role, roleLevel: vMethod, trustScore });
  fireEvent('token.issued',  { role, trustScore, method: 'webauthn-passkey' });

  setHHTPPS(res, { status: 'verified', human: true, actorType: 'human',
                   role, roleLevel: vMethod, trustScore,
                   token, method: 'webauthn-passkey' });
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
  const { operatorName, operatorUrl, purpose, contactEmail } = req.body;
  if (!operatorName || !purpose)
    return res.status(400).json({ error: 'operatorName und purpose sind erforderlich.' });

  const operatorId = 'op-' + crypto.randomBytes(8).toString('hex');
  const apiKey     = 'mk-' + crypto.randomBytes(24).toString('hex');
  const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

  await db.machineOperators.create({
    operatorId, operatorName, operatorUrl, purpose, contactEmail, apiKeyHash
  });

  res.status(201).json({
    hhttps: { version: '0.4.1' },
    operatorId, apiKey,
    warning: 'Speichere den API-Key sicher — er wird nur einmal angezeigt.',
    tokenEndpoint: `${BASE_URL}/hhttps/machine/token`,
    message: `Operator "${operatorName}" registriert. Mit apiKey Maschinen-Token ausstellen.`
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
  const token = signToken({
    jti, sub: 'machine', iss: `hhttps://${RP_ID}`,
    human: false, actorType: 'bot',
    operatorId, operatorName: op.operator_name, purpose: op.purpose,
    ia: Math.floor(Date.now() / 1000)
  }, { expiresIn: MACHINE_TTL });

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
