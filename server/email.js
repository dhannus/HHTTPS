/**
 * HHTTPS Email Module
 *
 * Two purposes:
 *   1. User email verification — legacy flow during role declaration.
 *      Function: sendVerificationEmail({ email, role, sessionId, baseUrl })
 *
 *   2. Platform registration confirmation (Phase 3b).
 *      Function: sendPlatformRegistrationEmail({ to, platformName, homepageUrl,
 *                                                 confirmUrl, kind })
 *
 * Transport modes:
 *   - SMTP (production) — via nodemailer (Strato, Brevo, Mailgun, ...)
 *   - sendmail fallback (system MTA)
 *   - Console (dev fallback) — prints to stdout if no SMTP configured
 *
 * Zero personal data storage. Token persisted as hash only, never the raw email.
 */

import crypto     from 'crypto';
import nodemailer from 'nodemailer';
import { emailVerifications } from './db.js';

// ─── Config (from environment) ─────────────────────────────────────────────
const SMTP_HOST = process.env.SMTP_HOST || null;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587');
const SMTP_USER = process.env.SMTP_USER || null;
const SMTP_PASS = process.env.SMTP_PASS || null;
const SMTP_FROM = process.env.SMTP_FROM || 'noreply@hhttps.org';
const BASE_URL  = process.env.BASE_URL  || 'https://hhttps.org';
const FROM_NAME = process.env.SMTP_FROM_NAME || 'HHTTPS Issuer';
const REPLY_TO  = process.env.SMTP_REPLY_TO || null;  // optional: separate reply address

// ─── Domain classification (for user email verification, legacy flow) ──────
const DOMAIN_RULES = {
  official: [
    'bundestag.de','bundesregierung.de','bundesrat.de',
    'bmi.bund.de','bmj.bund.de','bmbf.bund.de','bmwk.bund.de',
    'bka.bund.de','verfassungsschutz.bund.de'
  ],
  university: [
    '.uni-','.tu-','.lmu.de','.rwth-aachen.de','.fu-berlin.de',
    '.hu-berlin.de','.kit.edu','.tum.de','.fau.de','.uni-',
    '.hs-','.fh-','hochschule-'
  ],
  press: [
    'spiegel.de','zeit.de','sueddeutsche.de','faz.net','welt.de',
    'tagesspiegel.de','focus.de','stern.de','handelsblatt.com',
    'dpa.com','dw.com','ard.de','zdf.de','br.de','ndr.de',
    'mdr.de','rbb-online.de','wdr.de','swr.de'
  ],
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
  return { level: 'email-verified', trustBonus: 65, category: 'generic', domain };
}

// ─── Transport factory ─────────────────────────────────────────────────────
function createTransport() {
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    return nodemailer.createTransport({
      host:   SMTP_HOST,
      port:   SMTP_PORT,
      secure: SMTP_PORT === 465,         // SMTPS on 465, STARTTLS on 587
      auth:   { user: SMTP_USER, pass: SMTP_PASS },
      tls:    { rejectUnauthorized: true }
    });
  }
  if (process.platform !== 'win32') {
    try { return nodemailer.createTransport({ sendmail: true }); } catch(e) {}
  }
  return null;
}

function buildMailOptions(extra) {
  const opts = {
    from: `"${FROM_NAME}" <${SMTP_FROM}>`,
    ...extra
  };
  if (REPLY_TO) opts.replyTo = REPLY_TO;
  return opts;
}

// ─── Shared email shell (DRY for both purposes) ────────────────────────────
function emailShell({ title, subtitle, bodyHtml, ctaUrl, ctaLabel, footerNote }) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
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
  .body strong { color:#dfe7ea; }
  .body code { background:rgba(0,0,0,.3); padding:2px 6px; border-radius:4px;
    font-size:12px; color:#00e5ff; }
  .info-box { background:#0b1525; border:1px solid #1c3050;
    border-radius:8px; padding:14px 18px; margin:20px 0; }
  .info-box .ib-key { font-size:10px; color:#4a6080; letter-spacing:1.5px;
    text-transform:uppercase; margin-bottom:4px; }
  .info-box .ib-val { font-size:14px; color:#00e5ff; font-weight:600; word-break:break-all; }
  .btn-wrap { text-align:center; margin:28px 0; }
  .btn { display:inline-block; padding:14px 36px;
    background:linear-gradient(135deg,#1a4dcc,#2979ff);
    color:#fff !important; text-decoration:none; border-radius:8px;
    font-size:14px; font-weight:700; letter-spacing:1px;
    box-shadow:0 4px 20px rgba(41,121,255,0.4); }
  .url-fallback { background:#020508; border:1px solid #132035;
    border-radius:6px; padding:10px 14px; margin:16px 0;
    font-size:10px; color:#4a6080; word-break:break-all; }
  .footer { padding:16px 32px; border-top:1px solid #132035;
    font-size:10px; color:#4a6080; text-align:center; line-height:1.6; }
  .footer a { color:#00e5ff; text-decoration:none; }
</style></head><body>
<div class="wrap">
  <div class="header">
    <div class="logo">HHTTPS</div>
    <div class="sub">${subtitle || 'HUMAN-VERIFIED HTTPS'}</div>
  </div>
  <div class="body">
    ${bodyHtml}
    <div class="btn-wrap">
      <a href="${ctaUrl}" class="btn">${ctaLabel}</a>
    </div>
    <p style="font-size:11px;color:#4a6080;">Falls der Button nicht funktioniert, kopiere diesen Link in deinen Browser:</p>
    <div class="url-fallback">${ctaUrl}</div>
    ${footerNote ? `<p style="font-size:11px;color:#4a6080;margin-top:20px;">${footerNote}</p>` : ''}
  </div>
  <div class="footer">
    HHTTPS Project · <a href="https://github.com/dhannus/HHTTPS">github.com/dhannus/HHTTPS</a><br>
    <a href="https://hhttps.org">hhttps.org</a> · <a href="https://iamhmn.org">iamhmn.org</a><br>
    Diese E-Mail wurde automatisch generiert. Bitte nicht antworten.
  </div>
</div>
</body></html>`;
}

// ═══════════════════════════════════════════════════════════════════════════
// LEGACY: User email verification (role declaration flow)
// ═══════════════════════════════════════════════════════════════════════════

export async function sendVerificationEmail({ email, role, sessionId, baseUrl }) {
  const base = baseUrl || BASE_URL;

  const rawToken  = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const classification = classifyDomain(email);

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

  const roleLabels = {
    journalist: '📰 Journalist', student: '🎓 Schüler/Student',
    researcher: '🔬 Wissenschaftler', politician: '🏛️ Politiker',
    creative: '🎭 Kreativschaffender', developer: '💻 Entwickler',
    business: '🏢 Unternehmen', citizen: '🧑 Bürger'
  };

  const bodyHtml = `
    <p>Du hast eine E-Mail-Verifikation für deine HHTTPS-Identität angefordert.</p>
    <div class="info-box">
      <div class="ib-key">Rolle</div>
      <div class="ib-val">${roleLabels[role] || role}</div>
    </div>
    <div class="info-box">
      <div class="ib-key">Domain · Level · Trust-Bonus</div>
      <div class="ib-val">${classification.domain} · ${classification.level} · +${classification.trustBonus}</div>
    </div>
    <p>Klicke auf den Button, um deine E-Mail-Domain zu bestätigen und deinen Trust Score zu erhöhen. Der Link ist <strong>15 Minuten</strong> gültig.</p>
  `;

  const html = emailShell({
    title:     'E-Mail-Verifikation',
    subtitle:  'HUMAN-VERIFIED HTTPS · ROLE VERIFICATION',
    bodyHtml,
    ctaUrl:    verifyUrl,
    ctaLabel:  '✓ E-Mail bestätigen',
    footerNote: '<strong style="color:#a0b8d8">Datenschutz:</strong> Deine E-Mail-Adresse wird nicht gespeichert. Nur ein Hash der Domain wird für die Rollenverifikation genutzt. Der Token verfällt automatisch nach 15 Minuten.'
  });

  const text = `HHTTPS — E-Mail-Verifikation\n\nRolle: ${roleLabels[role] || role}\nDomain: ${classification.domain}\nTrust-Bonus: +${classification.trustBonus}\n\nLink (15 Min gültig):\n${verifyUrl}\n\n— HHTTPS Project · hhttps.org`;

  const transporter = createTransport();
  if (!transporter) {
    devLog('User email verification', email, verifyUrl, { role, classification });
    return { sent: false, devMode: true, verifyUrl, classification, rawToken };
  }

  await transporter.sendMail(buildMailOptions({
    to:      email,
    subject: `[HHTTPS] E-Mail-Verifikation für Rolle "${roleLabels[role] || role}"`,
    text,
    html
  }));

  return { sent: true, devMode: false, classification };
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 3b: Platform registration confirmation
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Send the platform registration confirmation email.
 * Called from /hhttps/developers/clients (POST) and from email change handlers.
 *
 * @param {object} opts
 * @param {string} opts.to            Recipient email
 * @param {string} opts.platformName  Display name of the platform
 * @param {string} opts.homepageUrl   Platform's homepage URL
 * @param {string} opts.confirmUrl    Full URL with email_token to confirm
 * @param {string} [opts.kind]        'registration' | 'email_change' (default: 'registration')
 * @returns {Promise<{sent: boolean, devMode: boolean}>}
 */
export async function sendPlatformRegistrationEmail({
  to, platformName, homepageUrl, confirmUrl, kind = 'registration'
}) {
  const isChange = kind === 'email_change';

  const titleDe = isChange
    ? 'Neue Kontakt-Email bestätigen'
    : 'Plattform-Anmeldung bestätigen';

  const intro = isChange
    ? `<p>Du hast für deine HHTTPS-Plattform <strong>${escapeHtml(platformName)}</strong> eine neue Kontakt-Email hinterlegt. Bitte bestätige diese E-Mail-Adresse, indem du auf den Button klickst.</p>`
    : `<p>Du hast eine neue Plattform bei HHTTPS angemeldet. Bitte bestätige deine Kontakt-Email, damit die Plattform aktiviert wird.</p>`;

  const bodyHtml = `
    ${intro}
    <div class="info-box">
      <div class="ib-key">Plattform</div>
      <div class="ib-val">${escapeHtml(platformName)}</div>
    </div>
    <div class="info-box">
      <div class="ib-key">Homepage</div>
      <div class="ib-val">${escapeHtml(homepageUrl)}</div>
    </div>
    <p>Nach der Bestätigung wechselt deine Plattform in den Status <code>unverified</code> und kann sofort von Usern für den Login genutzt werden. Für den <code>verified</code>-Status (grüner Badge auf der Consent-Seite) musst du zusätzlich einen DNS-TXT-Record setzen und einen Review beantragen.</p>
    <p style="font-size:11px;color:#4a6080;">Der Link ist <strong style="color:#a0b8d8">48 Stunden</strong> gültig.</p>
  `;

  const html = emailShell({
    title:     titleDe,
    subtitle:  'HUMAN-VERIFIED HTTPS · PLATFORM REGISTRATION',
    bodyHtml,
    ctaUrl:    confirmUrl,
    ctaLabel:  '✓ Email bestätigen',
    footerNote: 'Du erhältst diese E-Mail, weil sich jemand mit dieser Adresse als Kontakt für die genannte Plattform angemeldet hat. Falls das nicht du warst, ignoriere diese E-Mail einfach — ohne Bestätigung wird die Plattform automatisch nach 48 Stunden gelöscht.'
  });

  const text = [
    `HHTTPS — ${titleDe}`,
    '',
    `Plattform: ${platformName}`,
    `Homepage:  ${homepageUrl}`,
    '',
    `Bestätigungslink (48 Stunden gültig):`,
    confirmUrl,
    '',
    `— HHTTPS Project · hhttps.org`
  ].join('\n');

  const subject = isChange
    ? `[HHTTPS] Neue Email für Plattform "${platformName}" bestätigen`
    : `[HHTTPS] Bestätige deine Plattform-Anmeldung: ${platformName}`;

  const transporter = createTransport();
  if (!transporter) {
    devLog('Platform registration', to, confirmUrl, { platformName, homepageUrl, kind });
    return { sent: false, devMode: true };
  }

  await transporter.sendMail(buildMailOptions({
    to,
    subject,
    text,
    html
  }));

  return { sent: true, devMode: false };
}

/**
 * Notify the platform owner that their submission was verified by admin.
 */
export async function sendPlatformVerifiedEmail({ to, platformName, homepageUrl }) {
  const bodyHtml = `
    <p>Glückwunsch! Deine Plattform <strong>${escapeHtml(platformName)}</strong> ist jetzt offiziell <strong style="color:#00e5ff">verifiziert</strong>.</p>
    <div class="info-box">
      <div class="ib-key">Plattform</div>
      <div class="ib-val">${escapeHtml(platformName)}</div>
    </div>
    <p>Was sich ab jetzt ändert:</p>
    <ul style="color:#a0b8d8;font-size:13px;line-height:1.7;padding-left:20px;">
      <li>Auf der Consent-Seite zeigt deine Plattform einen grünen <strong>Verified</strong>-Badge</li>
      <li>User-Trust beim Login steigt — keine Warnbanner mehr</li>
      <li>Deine Plattform erscheint in der Liste der Connected Platforms auf hhttps.org</li>
    </ul>
    <p>Schau dir dein Dashboard an, um Stats und Status zu sehen.</p>
  `;

  const html = emailShell({
    title:     'Plattform verifiziert',
    subtitle:  'HUMAN-VERIFIED HTTPS · VERIFICATION APPROVED',
    bodyHtml,
    ctaUrl:    `${BASE_URL}/developers`,
    ctaLabel:  '→ Zum Dashboard',
    footerNote: null
  });

  const text = [
    `HHTTPS — Plattform verifiziert`,
    '',
    `${platformName} wurde vom HHTTPS-Admin verifiziert.`,
    `Sie erscheint ab sofort mit grünem Badge auf der Consent-Seite.`,
    '',
    `Dashboard: ${BASE_URL}/developers`,
    '',
    `— HHTTPS Project · hhttps.org`
  ].join('\n');

  const transporter = createTransport();
  if (!transporter) {
    devLog('Platform verified', to, `${BASE_URL}/developers`, { platformName });
    return { sent: false, devMode: true };
  }

  await transporter.sendMail(buildMailOptions({
    to,
    subject: `[HHTTPS] ✓ ${platformName} ist jetzt verifiziert`,
    text, html
  }));

  return { sent: true };
}

/**
 * Notify the platform owner that their submission was rejected.
 */
export async function sendPlatformRejectedEmail({ to, platformName, reason }) {
  const bodyHtml = `
    <p>Wir haben deinen Antrag zur Verifikation der Plattform <strong>${escapeHtml(platformName)}</strong> geprüft und müssen ihn leider ablehnen.</p>
    <div class="info-box">
      <div class="ib-key">Grund</div>
      <div class="ib-val" style="font-weight:400;">${escapeHtml(reason || '(kein Grund angegeben)')}</div>
    </div>
    <p>Deine Plattform bleibt im Status <code>unverified</code> und kann weiterhin von Usern genutzt werden — sie zeigt nur einen Warnbanner auf der Consent-Seite. Wenn du die Punkte oben behoben hast, kannst du den Antrag im Dashboard erneut einreichen.</p>
  `;

  const html = emailShell({
    title:     'Antrag abgelehnt',
    subtitle:  'HUMAN-VERIFIED HTTPS · VERIFICATION REJECTED',
    bodyHtml,
    ctaUrl:    `${BASE_URL}/developers`,
    ctaLabel:  '→ Zum Dashboard',
    footerNote: 'Falls du die Begründung nicht nachvollziehen kannst oder Fragen hast, antworte gerne auf diese E-Mail — wir helfen weiter.'
  });

  const text = [
    `HHTTPS — Verifikations-Antrag abgelehnt`,
    '',
    `Plattform: ${platformName}`,
    `Grund: ${reason || '(kein Grund angegeben)'}`,
    '',
    `Dashboard: ${BASE_URL}/developers`,
    '',
    `— HHTTPS Project · hhttps.org`
  ].join('\n');

  const transporter = createTransport();
  if (!transporter) {
    devLog('Platform rejected', to, `${BASE_URL}/developers`, { platformName, reason });
    return { sent: false, devMode: true };
  }

  await transporter.sendMail(buildMailOptions({
    to,
    subject: `[HHTTPS] Antrag für "${platformName}" abgelehnt`,
    text, html
  }));

  return { sent: true };
}

// ─── Verify token (used by /hhttps/email/verify, legacy user flow) ─────────

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

// ─── Helpers ───────────────────────────────────────────────────────────────

function devLog(kind, to, link, meta) {
  console.log('\n' + '─'.repeat(60));
  console.log(`📧 [DEV MODE — ${kind}]`);
  console.log(`   To:    ${to}`);
  if (meta) {
    for (const [k, v] of Object.entries(meta)) {
      console.log(`   ${k.padEnd(8)}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
    }
  }
  console.log(`   Link:  ${link}`);
  console.log('─'.repeat(60) + '\n');
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
