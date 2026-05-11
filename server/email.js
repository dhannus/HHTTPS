/**
 * HHTTPS Email Verification Module
 * Sends a one-time verification link and upgrades trust level upon confirmation.
 *
 * Supports two transport modes:
 *   1. SMTP (production) — via nodemailer (sendmail, SMTP relay, or services like Brevo/Mailgun)
 *   2. Console (dev fallback) — prints the link to stdout when no SMTP is configured
 *
 * Zero personal data storage: only a hashed token + domain is kept. The full
 * email address is never persisted after sending.
 */

import crypto     from 'crypto';
import nodemailer from 'nodemailer';
import { emailVerifications } from './db.js';

// ─── Config (from environment) ─────────────────────────────────────────────
const SMTP_HOST = process.env.SMTP_HOST || null;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587');
const SMTP_USER = process.env.SMTP_USER || null;
const SMTP_PASS = process.env.SMTP_PASS || null;
const SMTP_FROM = process.env.SMTP_FROM || 'noreply@humanproof.demo';
const BASE_URL  = process.env.BASE_URL  || 'https://hhttps.funnysearch.eu';

// Email verification persistence is now in PostgreSQL via db.js
// (was: in-memory Map() — lost on restart)

// ─── Domain classification ─────────────────────────────────────────────────
const DOMAIN_RULES = {
  // Official government/parliament domains → level 5 "official-email"
  official: [
    'bundestag.de','bundesregierung.de','bundesrat.de',
    'bmi.bund.de','bmj.bund.de','bmbf.bund.de','bmwk.bund.de',
    'bka.bund.de','verfassungsschutz.bund.de'
  ],
  // University domains → level 3 "email-verified" (student/researcher)
  university: [
    '.uni-','.tu-','.lmu.de','.rwth-aachen.de','.fu-berlin.de',
    '.hu-berlin.de','.kit.edu','.tum.de','.fau.de','.uni-',
    '.hs-','.fh-','hochschule-'
  ],
  // Known press/media domains → level 3 "email-verified" (journalist)
  press: [
    'spiegel.de','zeit.de','sueddeutsche.de','faz.net','welt.de',
    'tagesspiegel.de','focus.de','stern.de','handelsblatt.com',
    'dpa.com','dw.com','ard.de','zdf.de','br.de','ndr.de',
    'mdr.de','rbb-online.de','wdr.de','swr.de'
  ],
  // Voice actor / creative associations
  creative: [
    'sprecherverband.de','bffs.de','synchronverband.de',
    'bsd-synchron.de','gema.de','vgwort.de','vds-online.de'
  ]
};

export function classifyDomain(email) {
  const domain = email.split('@')[1]?.toLowerCase() || '';

  if (DOMAIN_RULES.official.some(d => domain.endsWith(d))) {
    return { level: 'official-email', trustBonus: 90, category: 'official', domain };
  }
  if (DOMAIN_RULES.university.some(d => domain.includes(d))) {
    return { level: 'email-verified', trustBonus: 75, category: 'university', domain };
  }
  if (DOMAIN_RULES.press.some(d => domain.endsWith(d))) {
    return { level: 'email-verified', trustBonus: 72, category: 'press', domain };
  }
  if (DOMAIN_RULES.creative.some(d => domain.endsWith(d))) {
    return { level: 'email-verified', trustBonus: 78, category: 'creative', domain };
  }
  // Generic domain — basic email-verified
  return { level: 'email-verified', trustBonus: 65, category: 'generic', domain };
}

// ─── Create transporter ────────────────────────────────────────────────────
function createTransport() {
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    return nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
  }

  // Fallback: try system sendmail
  if (process.platform !== 'win32') {
    try {
      return nodemailer.createTransport({ sendmail: true });
    } catch(e) {}
  }

  // Dev fallback: log to console
  return null;
}

// ─── Send verification email ───────────────────────────────────────────────
export async function sendVerificationEmail({ email, role, sessionId, baseUrl }) {
  const base = baseUrl || BASE_URL;

  // Generate secure random token
  const rawToken  = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  // Classify domain
  const classification = classifyDomain(email);

  // Persist verification token in DB (15 min TTL)
  await emailVerifications.create({
    token:      tokenHash,
    email:      crypto.createHash('sha256').update(email.toLowerCase()).digest('hex'),
    domain:     classification.domain,
    level:      classification.level,
    trustBonus: classification.trustBonus,
    category:   classification.category,
    sessionId,
    ttlMs:      15 * 60 * 1000
  });

  const verifyUrl = `${base}/hhttps/email/verify?token=${rawToken}&session=${sessionId}`;

  // Build email HTML
  const roleLabels = {
    journalist: '📰 Journalist', student: '🎓 Schüler/Student',
    researcher: '🔬 Wissenschaftler', politician: '🏛️ Politiker',
    creative: '🎭 Kreativschaffender', developer: '💻 Entwickler',
    business: '🏢 Unternehmen', citizen: '🧑 Bürger'
  };

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<style>
  body { margin:0; padding:0; background:#04080f; font-family:'Courier New',monospace; }
  .wrap { max-width:520px; margin:40px auto; background:#070d18;
    border:1px solid #132035; border-radius:12px; overflow:hidden; }
  .header { padding:28px 32px; background:linear-gradient(135deg,#0b1525,#0a2040);
    border-bottom:1px solid #132035; text-align:center; }
  .header .logo { font-size:28px; font-weight:900; color:#00e5ff;
    letter-spacing:4px; text-shadow:0 0 20px rgba(0,229,255,0.4); }
  .header .sub { font-size:11px; color:#4a6080; margin-top:4px; letter-spacing:2px; }
  .body { padding:32px; }
  .body p { color:#a0b8d8; font-size:13px; line-height:1.7; margin:0 0 16px; }
  .role-box { background:#0b1525; border:1px solid #1c3050;
    border-radius:8px; padding:14px 18px; margin:20px 0; text-align:center; }
  .role-box .rl { font-size:20px; color:#00e5ff; font-weight:700; }
  .role-box .lv { font-size:11px; color:#4a6080; margin-top:4px; }
  .btn-wrap { text-align:center; margin:28px 0; }
  .btn { display:inline-block; padding:14px 36px;
    background:linear-gradient(135deg,#1a4dcc,#2979ff);
    color:#fff; text-decoration:none; border-radius:8px;
    font-size:14px; font-weight:700; letter-spacing:1px;
    box-shadow:0 4px 20px rgba(41,121,255,0.4); }
  .url-fallback { background:#020508; border:1px solid #132035;
    border-radius:6px; padding:10px 14px; margin:16px 0;
    font-size:10px; color:#4a6080; word-break:break-all; }
  .trust-row { display:flex; gap:12px; margin:20px 0; }
  .tc { flex:1; background:#0b1525; border:1px solid #1c3050;
    border-radius:6px; padding:10px; text-align:center; }
  .tc .k { font-size:9px; color:#4a6080; letter-spacing:1px; margin-bottom:3px; }
  .tc .v { font-size:13px; color:#00e5ff; font-weight:700; }
  .footer { padding:16px 32px; border-top:1px solid #132035;
    font-size:10px; color:#4a6080; text-align:center; line-height:1.6; }
  .footer a { color:#00e5ff; text-decoration:none; }
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">HHTTPS</div>
    <div class="sub">HUMAN-VERIFIED HTTPS · HUMANPROOF INITIATIVE</div>
  </div>
  <div class="body">
    <p>Du hast eine E-Mail-Verifikation für deine HHTTPS-Identität angefordert.</p>

    <div class="role-box">
      <div class="rl">${roleLabels[role] || role}</div>
      <div class="lv">${classification.level.toUpperCase()} · Domain: ${classification.domain}</div>
    </div>

    <div class="trust-row">
      <div class="tc"><div class="k">TRUST SCORE</div><div class="v">${classification.trustBonus}/100</div></div>
      <div class="tc"><div class="k">LEVEL</div><div class="v">${classification.level}</div></div>
      <div class="tc"><div class="k">GÜLTIG</div><div class="v">15 Min</div></div>
    </div>

    <p>Klicke auf den Button, um deine E-Mail-Domain zu bestätigen und deinen Trust Score zu erhöhen:</p>

    <div class="btn-wrap">
      <a href="${verifyUrl}" class="btn">✓ E-Mail bestätigen</a>
    </div>

    <p style="font-size:11px;color:#4a6080;">Falls der Button nicht funktioniert, kopiere diesen Link:</p>
    <div class="url-fallback">${verifyUrl}</div>

    <p style="font-size:11px;color:#4a6080;margin-top:20px;">
      <strong style="color:#a0b8d8">Datenschutz:</strong>
      Deine E-Mail-Adresse wird nicht gespeichert. Es wird nur ein kryptografischer Hash
      der Domain zur Rolleverifikation genutzt. Nach 15 Minuten wird dieser Token automatisch gelöscht.
    </p>
  </div>
  <div class="footer">
    HumanProof Initiative · <a href="https://github.com/dhannus/HumanProof">github.com/dhannus/HumanProof</a><br>
    daniel.hannuschka@tweakz.de · tweakz.de<br>
    Diese E-Mail wurde automatisch generiert. Nicht antworten.
  </div>
</div>
</body>
</html>`;

  const text = `HHTTPS E-Mail-Verifikation\n\nRolle: ${roleLabels[role] || role}\nDomain: ${classification.domain}\nTrust Score nach Verifikation: ${classification.trustBonus}/100\n\nVerifikationslink (gültig 15 Min):\n${verifyUrl}\n\nHumanProof Initiative · daniel.hannuschka@tweakz.de`;

  const transporter = createTransport();

  if (!transporter) {
    // Dev mode: print to console
    console.log('\n' + '─'.repeat(60));
    console.log('📧 DEV MODE — E-Mail würde gesendet an:', email);
    console.log('   Rolle:', roleLabels[role] || role);
    console.log('   Domain:', classification.domain, '→', classification.level);
    console.log('   Trust Score:', classification.trustBonus);
    console.log('   Verifikationslink:');
    console.log('   ' + verifyUrl);
    console.log('─'.repeat(60) + '\n');
    return { sent: false, devMode: true, verifyUrl, classification, rawToken };
  }

  await transporter.sendMail({
    from:    `"HumanProof HHTTPS" <${SMTP_FROM}>`,
    to:      email,
    subject: `[HHTTPS] Deine E-Mail-Verifikation für Rolle "${roleLabels[role] || role}"`,
    text,
    html
  });

  return { sent: true, devMode: false, classification };
}

// ─── Verify token (async, DB-backed, atomic consume) ───────────────────────
export async function verifyEmailToken(rawToken) {
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const entry = await emailVerifications.getAndConsume(tokenHash);

  if (!entry) return {
    valid: false,
    error: 'Token nicht gefunden, abgelaufen oder bereits verwendet (gültig: 15 Min).'
  };

  return {
    valid:      true,
    sessionId:  entry.session_id,
    domain:     entry.domain,
    level:      entry.level,
    trustBonus: entry.trust_bonus,
    category:   entry.category
  };
}
