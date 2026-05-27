/**
 * Privacy Pass attribute / verification HTTP API
 *
 * Endpoints (all mounted under /privacy-pass/):
 *
 *   GET  /eligibility?sessionId=&role=         what's missing for this role?
 *   POST /email/start         { sessionId, role, email }   → sends verify link
 *   GET  /email/verify?token=                   completes email verification
 *   GET  /credentials?sessionId=               list user's registered credentials
 *   POST /recovery/generate { sessionId }       generate 10 codes (first time only)
 *   POST /recovery/use      { code, userId }    consume code, returns auth status
 *
 * The /issue endpoint in issuance.js is updated separately to enforce
 * eligibility before issuing tokens.
 */

import express from 'express';

import { ROLES }                       from './keys.js';
import {
  eligibilityFor,
  createEmailPending,
  consumeEmailPending,
  recordVerification,
  hashEmail,
  emailDomain,
  generateRecoveryCodesForUser,
  consumeRecoveryCode,
  countRemainingRecoveryCodes,
  isAdminCredential,
  adminCredentialCount,
} from './verifications.js';
import { ROLE_REQUIREMENTS, emailDomainMatchesRole } from './role-requirements.js';

export const verificationsRouter = express.Router();
verificationsRouter.use(express.json({ limit: '8kb' }));

// ─── GET /eligibility ────────────────────────────────────────────────────────

verificationsRouter.get('/eligibility', async (req, res) => {
  try {
    const { sessionId, role } = req.query;
    if (!sessionId) return res.status(400).json({ error: 'missing_session' });
    if (!role || !ROLES.includes(role)) return res.status(400).json({ error: 'invalid_role' });

    const db = await import('../db.js');
    const session = await db.sessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'invalid_session' });

    const result = await eligibilityFor(session.credentialId, role);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'eligibility_failed', detail: err.message });
  }
});

// ─── POST /email/start ───────────────────────────────────────────────────────

verificationsRouter.post('/email/start', async (req, res) => {
  try {
    const { sessionId, role, email, method } = req.body || {};

    if (!sessionId)                      return res.status(400).json({ error: 'missing_session' });
    if (!role || !ROLES.includes(role))  return res.status(400).json({ error: 'invalid_role' });
    if (typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'invalid_email' });
    }

    // Normalize method
    const verificationMethod = method || 'email-verified';

    const db = await import('../db.js');
    const session = await db.sessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'invalid_session' });
    if (session.role && session.role !== role) {
      return res.status(403).json({
        error: 'role_mismatch',
        detail: `session role is ${session.role}, requested ${role}`,
      });
    }

    // For strict roles, the email domain must match
    if (!emailDomainMatchesRole(email, role)) {
      const req = ROLE_REQUIREMENTS[role];
      return res.status(400).json({
        error: 'domain_does_not_match',
        detail: req.emailDomainHint || 'The email domain does not match the selected role.',
        hint: req.emailDomainHint,
      });
    }

    const domain = emailDomain(email);

    // Create pending verification
    const { rawToken } = await createEmailPending({
      credentialId: session.credentialId,
      role,
      email,
      method: verificationMethod,
      domain,
    });

    // Send the email using the existing email infrastructure.
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const link    = `${baseUrl}/privacy-pass/email/verify?token=${rawToken}`;

    try {
      const emailMod = await import('../email.js');
      const result = await emailMod.sendPrivacyPassVerification({ to: email, role, link });
      if (result.devMode) {
        console.warn(`[PP] email transport not configured — dev mode. Link: ${link}`);
      }
    } catch (sendErr) {
      console.error('[PP] email send failed:', sendErr.message);
      return res.status(500).json({
        error: 'email_send_failed',
        detail: sendErr.message,
      });
    }

    res.json({
      ok: true,
      message: 'Verifikations-E-Mail wurde versandt.',
      domain,
      expires_in_seconds: 15 * 60,
    });

  } catch (err) {
    console.error('[PP] /email/start error:', err);
    res.status(500).json({ error: 'email_start_failed', detail: err.message });
  }
});

// ─── GET /email/verify?token=… ───────────────────────────────────────────────

verificationsRouter.get('/email/verify', async (req, res) => {
  const { token } = req.query;
  if (!token || typeof token !== 'string') {
    return res.status(400).send(renderEmailResult({
      ok: false,
      title: 'Link invalid · Link ungültig',
      message: 'No token found in the link.<br><br><span lang="de">Kein Token im Link gefunden.</span>',
    }));
  }

  try {
    const pending = await consumeEmailPending(token);
    if (!pending) {
      return res.status(410).send(renderEmailResult({
        ok: false,
        title: 'Link expired or already used · Link abgelaufen oder bereits benutzt',
        message: 'The confirmation link is no longer valid. Please request a new one.<br><br><span lang="de">Der Bestätigungslink ist nicht mehr gültig. Fordere bitte einen neuen an.</span>',
      }));
    }

    await recordVerification(pending.credential_id, pending.role, pending.method, {
      emailHash:   pending.email_hash,
      emailDomain: pending.email_domain,
    });

    res.send(renderEmailResult({
      ok:        true,
      title:     'Email confirmed · E-Mail bestätigt',
      message:   `Your email was verified for the role "${pending.role}". You can close this window and fetch your tokens in the wallet.<br><br><span lang="de">Deine E-Mail wurde für die Rolle "${pending.role}" verifiziert. Du kannst dieses Fenster schließen und in der Wallet die Tokens holen.</span>`,
      role:      pending.role,
      domain:    pending.email_domain,
    }));
  } catch (err) {
    res.status(500).send(renderEmailResult({
      ok: false,
      title: 'Verification error · Fehler bei der Verifikation',
      message: err.message,
    }));
  }
});

function renderEmailResult({ ok, title, message, role, domain }) {
  const icon = ok ? '✓' : '✗';
  const color = ok ? '#00e676' : '#ff5252';
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} — HHTTPS</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#03050a;color:#e0ecff;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 60% 50% at 50% 30%,rgba(0,229,255,0.06) 0%,transparent 60%);pointer-events:none;}
.card{position:relative;max-width:480px;width:100%;background:#070d18;border:1px solid #132035;border-radius:16px;padding:40px 32px;text-align:center;animation:pop .5s cubic-bezier(.175,.885,.32,1.275);}
@keyframes pop{from{opacity:0;transform:scale(.92)}to{opacity:1;transform:scale(1)}}
.icon{font-size:64px;color:${color};margin-bottom:18px;}
h1{font-family:'Syne',sans-serif;font-size:24px;font-weight:800;color:${color};margin-bottom:14px;}
p{font-size:13px;color:#4a6080;line-height:1.6;margin-bottom:18px;}
.meta{font-size:12px;color:#00e5ff;margin:18px 0;font-family:'JetBrains Mono',monospace;}
.btn{display:inline-block;margin-top:14px;padding:12px 28px;background:linear-gradient(135deg,#1a4dcc,#2979ff);color:white;text-decoration:none;border-radius:8px;font-size:13px;font-weight:700;}
</style></head><body>
<div class="card">
  <div class="icon">${icon}</div>
  <h1>${title}</h1>
  <p>${message}</p>
  ${role ? `<div class="meta">Role: <strong>${role}</strong>${domain ? ` · ${domain}` : ''}</div>` : ''}
  <a href="/privacy-pass" class="btn">To the wallet →</a>
</div>
</body></html>`;
}

// ─── GET /credentials?sessionId=… ────────────────────────────────────────────

verificationsRouter.get('/credentials', async (req, res) => {
  try {
    const { sessionId } = req.query;
    if (!sessionId) return res.status(400).json({ error: 'missing_session' });

    const db = await import('../db.js');
    const session = await db.sessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'invalid_session' });

    const { rows } = await db.pool().query(
      `SELECT credential_id, device_type, backed_up,
              registered_at, last_used_at, transports
         FROM credentials
        WHERE user_id = $1
        ORDER BY registered_at ASC`,
      [session.userId]
    );

    res.json({
      userId:        session.userId,
      currentCredentialId: session.credentialId,
      isAdmin:       isAdminCredential(session.credentialId),
      adminCount:    adminCredentialCount(),
      credentials:   rows.map(r => ({
        credentialId:  r.credential_id,
        deviceType:    r.device_type,
        backedUp:      r.backed_up,
        transports:    r.transports || [],
        registeredAt:  r.registered_at,
        lastUsedAt:    r.last_used_at,
        isCurrent:     r.credential_id === session.credentialId,
        isAdmin:       isAdminCredential(r.credential_id),
      })),
    });
  } catch (err) {
    res.status(500).json({ error: 'credentials_failed', detail: err.message });
  }
});

// ─── POST /recovery/generate ─────────────────────────────────────────────────

verificationsRouter.post('/recovery/generate', async (req, res) => {
  try {
    const { sessionId } = req.body || {};
    if (!sessionId) return res.status(400).json({ error: 'missing_session' });

    const db = await import('../db.js');
    const session = await db.sessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'invalid_session' });

    const codes = await generateRecoveryCodesForUser(session.userId);
    res.json({
      ok: true,
      userId: session.userId,
      codes,
      message: 'Diese Codes werden DIR EINMALIG ANGEZEIGT. Speichere sie offline. Jeder Code ist nur einmal verwendbar.',
    });
  } catch (err) {
    res.status(500).json({ error: 'recovery_generate_failed', detail: err.message });
  }
});

// ─── GET /recovery/status?sessionId=… ────────────────────────────────────────

verificationsRouter.get('/recovery/status', async (req, res) => {
  try {
    const { sessionId } = req.query;
    if (!sessionId) return res.status(400).json({ error: 'missing_session' });

    const db = await import('../db.js');
    const session = await db.sessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'invalid_session' });

    const remaining = await countRemainingRecoveryCodes(session.userId);
    res.json({
      userId: session.userId,
      remaining,
      hasCodes: remaining > 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'recovery_status_failed', detail: err.message });
  }
});

// ─── POST /recovery/use ──────────────────────────────────────────────────────

verificationsRouter.post('/recovery/use', async (req, res) => {
  try {
    const { code } = req.body || {};
    if (typeof code !== 'string' || code.length < 8) {
      return res.status(400).json({ error: 'invalid_code' });
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const userId = await consumeRecoveryCode(code, ip);

    if (!userId) {
      return res.status(401).json({
        error: 'invalid_or_used_code',
        detail: 'The code is invalid or has already been used.',
      });
    }

    res.json({
      ok: true,
      userId,
      message: 'Code accepted. You can now add a new security key to your account.',
    });
  } catch (err) {
    res.status(500).json({ error: 'recovery_use_failed', detail: err.message });
  }
});
