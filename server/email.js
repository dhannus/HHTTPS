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
 * LANGUAGE: transactional emails are BILINGUAL (English first as the canonical
 * text, German second), because the recipient's locale is generally unknown at
 * send time. Role labels come from the i18n catalog (roles.i18n.js) so there is
 * a single source of truth — no hardcoded role-name maps in this file.
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
import { ROLES } from './roles.js';
import { roleLabel } from './roles.i18n.js';

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

// Classify the user's email domain. The returned `trustBonus` is the **bonus
// added on top** of the email-verified baseline (30), NOT an absolute score.
//
// Final account trust is computed in /role/declare:
//   base 30 + domainBonus + (passkey ? 30 : 0), capped at 100.
//
// Bonus values:
//   generic     → +0   (free webmail like gmail, gmx)
//   university  → +15  (.uni-*, .edu, hochschule-*)
//   press       → +15  (verlage, redaktionen)
//   creative    → +15  (associations like VDS, GEMA, BFFS)
//   official    → +40  (bund.de, bundestag.de, official authorities)
//
export function classifyDomain(email) {
  const domain = email.split('@')[1]?.toLowerCase() || '';

  if (DOMAIN_RULES.official.some(d => domain.endsWith(d))) {
    return { level: 'official-email', trustBonus: 40, category: 'official', domain };
  }
  if (DOMAIN_RULES.university.some(d => domain.includes(d))) {
    return { level: 'school-email', trustBonus: 15, category: 'university', domain };
  }
  if (DOMAIN_RULES.press.some(d => domain.endsWith(d))) {
    return { level: 'email-verified', trustBonus: 15, category: 'press', domain };
  }
  if (DOMAIN_RULES.creative.some(d => domain.endsWith(d))) {
    return { level: 'email-verified', trustBonus: 15, category: 'creative', domain };
  }
  return { level: 'email-verified', trustBonus: 0, category: 'generic', domain };
}

// ─── Bilingual helpers ──────────────────────────────────────────────────────
// HTML: English block, a thin divider, then the German block.
function biHtml(en, de) {
  return `${en}
    <div style="height:1px;background:#132035;margin:22px 0"></div>
    <div lang="de">${de}</div>`;
}
// Plain text: English block, divider, German block.
function biText(en, de) {
  return `${en}\n\n— — —\n\n${de}`;
}
// Role display label for emails: icon + English / German (single source: catalog).
function roleDisplay(role) {
  const icon = ROLES[role]?.icon || '';
  const en = roleLabel(role, 'en');
  const de = roleLabel(role, 'de');
  return `${icon} ${en} / ${de}`.trim();
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
    <p style="font-size:11px;color:#4a6080;">If the button does not work, copy this link into your browser:<br>Falls der Button nicht funktioniert, kopiere diesen Link in deinen Browser:</p>
    <div class="url-fallback">${ctaUrl}</div>
    ${footerNote ? `<p style="font-size:11px;color:#4a6080;margin-top:20px;">${footerNote}</p>` : ''}
  </div>
  <div class="footer">
    HHTTPS Project · <a href="https://github.com/dhannus/HHTTPS">github.com/dhannus/HHTTPS</a><br>
    <a href="https://hhttps.org">hhttps.org</a> · <a href="https://iamhmn.org">iamhmn.org</a><br>
    This email was generated automatically. Please do not reply.<br>
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
  const label = roleDisplay(role);

  const bodyHtml = biHtml(
    `<p>You requested email verification for your HHTTPS identity.</p>
    <div class="info-box">
      <div class="ib-key">Role</div>
      <div class="ib-val">${label}</div>
    </div>
    <div class="info-box">
      <div class="ib-key">Domain · Level · Trust bonus</div>
      <div class="ib-val">${classification.domain} · ${classification.level} · +${classification.trustBonus}</div>
    </div>
    <p>Click the button to confirm your email domain and raise your trust score. The link is valid for <strong>15 minutes</strong>.</p>`,
    `<p>Du hast eine E-Mail-Verifikation für deine HHTTPS-Identität angefordert.</p>
    <p>Klicke auf den Button, um deine E-Mail-Domain zu bestätigen und deinen Trust Score zu erhöhen. Der Link ist <strong>15 Minuten</strong> gültig.</p>`
  );

  const html = emailShell({
    title:     'Email verification',
    subtitle:  'HUMAN-VERIFIED HTTPS · ROLE VERIFICATION',
    bodyHtml,
    ctaUrl:    verifyUrl,
    ctaLabel:  '✓ Confirm email / E-Mail bestätigen',
    footerNote: '<strong style="color:#a0b8d8">Privacy:</strong> your email address is not stored. Only a hash of the domain is used for role verification; the token expires automatically after 15 minutes. — <strong style="color:#a0b8d8">Datenschutz:</strong> Deine E-Mail-Adresse wird nicht gespeichert. Nur ein Hash der Domain wird für die Rollenverifikation genutzt. Der Token verfällt automatisch nach 15 Minuten.'
  });

  const text = biText(
    `HHTTPS — Email verification\n\nRole: ${label}\nDomain: ${classification.domain}\nTrust bonus: +${classification.trustBonus}\n\nLink (valid 15 min):\n${verifyUrl}\n\n— HHTTPS Project · hhttps.org`,
    `HHTTPS — E-Mail-Verifikation\n\nRolle: ${label}\nDomain: ${classification.domain}\nTrust-Bonus: +${classification.trustBonus}\n\nLink (15 Min gültig):\n${verifyUrl}\n\n— HHTTPS Project · hhttps.org`
  );

  const transporter = createTransport();
  if (!transporter) {
    devLog('User email verification', email, verifyUrl, { role, classification });
    return { sent: false, devMode: true, verifyUrl, classification, rawToken };
  }

  await transporter.sendMail(buildMailOptions({
    to:      email,
    subject: `[HHTTPS] Verify email for role "${roleLabel(role,'en')}" / E-Mail-Verifikation`,
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

  const titleEn = isChange ? 'Confirm new contact email' : 'Confirm platform registration';
  const titleDe = isChange ? 'Neue Kontakt-Email bestätigen' : 'Plattform-Anmeldung bestätigen';

  const introEn = isChange
    ? `<p>You set a new contact email for your HHTTPS platform <strong>${escapeHtml(platformName)}</strong>. Please confirm this email address by clicking the button.</p>`
    : `<p>You registered a new platform with HHTTPS. Please confirm your contact email so the platform is activated.</p>`;
  const introDe = isChange
    ? `<p>Du hast für deine HHTTPS-Plattform <strong>${escapeHtml(platformName)}</strong> eine neue Kontakt-Email hinterlegt. Bitte bestätige diese E-Mail-Adresse, indem du auf den Button klickst.</p>`
    : `<p>Du hast eine neue Plattform bei HHTTPS angemeldet. Bitte bestätige deine Kontakt-Email, damit die Plattform aktiviert wird.</p>`;

  const bodyHtml = biHtml(
    `${introEn}
    <div class="info-box">
      <div class="ib-key">Platform</div>
      <div class="ib-val">${escapeHtml(platformName)}</div>
    </div>
    <div class="info-box">
      <div class="ib-key">Homepage</div>
      <div class="ib-val">${escapeHtml(homepageUrl)}</div>
    </div>
    <p>After confirmation your platform moves to status <code>unverified</code> and can immediately be used by users for login. For <code>verified</code> status (green badge on the consent screen) you additionally need to set a DNS TXT record and request a review.</p>
    <p style="font-size:11px;color:#4a6080;">The link is valid for <strong style="color:#a0b8d8">48 hours</strong>.</p>`,
    `${introDe}
    <p>Nach der Bestätigung wechselt deine Plattform in den Status <code>unverified</code> und kann sofort von Usern für den Login genutzt werden. Für den <code>verified</code>-Status (grüner Badge auf der Consent-Seite) musst du zusätzlich einen DNS-TXT-Record setzen und einen Review beantragen.</p>
    <p style="font-size:11px;color:#4a6080;">Der Link ist <strong style="color:#a0b8d8">48 Stunden</strong> gültig.</p>`
  );

  const html = emailShell({
    title:     titleEn,
    subtitle:  'HUMAN-VERIFIED HTTPS · PLATFORM REGISTRATION',
    bodyHtml,
    ctaUrl:    confirmUrl,
    ctaLabel:  '✓ Confirm email / Email bestätigen',
    footerNote: 'You received this email because someone registered this address as the contact for the named platform. If that was not you, simply ignore this email — without confirmation the platform is deleted automatically after 48 hours. — Du erhältst diese E-Mail, weil sich jemand mit dieser Adresse als Kontakt für die genannte Plattform angemeldet hat. Falls das nicht du warst, ignoriere diese E-Mail einfach — ohne Bestätigung wird die Plattform automatisch nach 48 Stunden gelöscht.'
  });

  const text = biText(
    [`HHTTPS — ${titleEn}`, '', `Platform: ${platformName}`, `Homepage:  ${homepageUrl}`, '',
     `Confirmation link (valid 48 hours):`, confirmUrl, '', `— HHTTPS Project · hhttps.org`].join('\n'),
    [`HHTTPS — ${titleDe}`, '', `Plattform: ${platformName}`, `Homepage:  ${homepageUrl}`, '',
     `Bestätigungslink (48 Stunden gültig):`, confirmUrl, '', `— HHTTPS Project · hhttps.org`].join('\n')
  );

  const subject = isChange
    ? `[HHTTPS] Confirm new email for platform "${platformName}" / Neue Email bestätigen`
    : `[HHTTPS] Confirm your platform registration: ${platformName}`;

  const transporter = createTransport();
  if (!transporter) {
    devLog('Platform registration', to, confirmUrl, { platformName, homepageUrl, kind });
    return { sent: false, devMode: true };
  }

  await transporter.sendMail(buildMailOptions({ to, subject, text, html }));
  return { sent: true, devMode: false };
}

/**
 * Notify the platform owner that their submission was verified by admin.
 */
export async function sendPlatformVerifiedEmail({ to, platformName, homepageUrl }) {
  const bodyHtml = biHtml(
    `<p>Congratulations! Your platform <strong>${escapeHtml(platformName)}</strong> is now officially <strong style="color:#00e5ff">verified</strong>.</p>
    <div class="info-box">
      <div class="ib-key">Platform</div>
      <div class="ib-val">${escapeHtml(platformName)}</div>
    </div>
    <p>What changes from now on:</p>
    <ul style="color:#a0b8d8;font-size:13px;line-height:1.7;padding-left:20px;">
      <li>On the consent screen your platform shows a green <strong>Verified</strong> badge</li>
      <li>User trust at login rises — no more warning banners</li>
      <li>Your platform appears in the Connected Platforms list on hhttps.org</li>
    </ul>
    <p>Check your dashboard to see stats and status.</p>`,
    `<p>Glückwunsch! Deine Plattform <strong>${escapeHtml(platformName)}</strong> ist jetzt offiziell <strong style="color:#00e5ff">verifiziert</strong>.</p>
    <p>Was sich ab jetzt ändert:</p>
    <ul style="color:#a0b8d8;font-size:13px;line-height:1.7;padding-left:20px;">
      <li>Auf der Consent-Seite zeigt deine Plattform einen grünen <strong>Verified</strong>-Badge</li>
      <li>User-Trust beim Login steigt — keine Warnbanner mehr</li>
      <li>Deine Plattform erscheint in der Liste der Connected Platforms auf hhttps.org</li>
    </ul>
    <p>Schau dir dein Dashboard an, um Stats und Status zu sehen.</p>`
  );

  const html = emailShell({
    title:     'Platform verified',
    subtitle:  'HUMAN-VERIFIED HTTPS · VERIFICATION APPROVED',
    bodyHtml,
    ctaUrl:    `${BASE_URL}/developers`,
    ctaLabel:  '→ To the dashboard / Zum Dashboard',
    footerNote: null
  });

  const text = biText(
    [`HHTTPS — Platform verified`, '', `${platformName} was verified by the HHTTPS admin.`,
     `It now appears with a green badge on the consent screen.`, '',
     `Dashboard: ${BASE_URL}/developers`, '', `— HHTTPS Project · hhttps.org`].join('\n'),
    [`HHTTPS — Plattform verifiziert`, '', `${platformName} wurde vom HHTTPS-Admin verifiziert.`,
     `Sie erscheint ab sofort mit grünem Badge auf der Consent-Seite.`, '',
     `Dashboard: ${BASE_URL}/developers`, '', `— HHTTPS Project · hhttps.org`].join('\n')
  );

  const transporter = createTransport();
  if (!transporter) {
    devLog('Platform verified', to, `${BASE_URL}/developers`, { platformName });
    return { sent: false, devMode: true };
  }

  await transporter.sendMail(buildMailOptions({
    to,
    subject: `[HHTTPS] ✓ ${platformName} is now verified / ist jetzt verifiziert`,
    text, html
  }));

  return { sent: true };
}

/**
 * Notify the platform owner that their submission was rejected.
 */
export async function sendPlatformRejectedEmail({ to, platformName, reason }) {
  const reasonEn = escapeHtml(reason || '(no reason given)');
  const reasonDe = escapeHtml(reason || '(kein Grund angegeben)');

  const bodyHtml = biHtml(
    `<p>We reviewed your request to verify the platform <strong>${escapeHtml(platformName)}</strong> and unfortunately have to reject it.</p>
    <div class="info-box">
      <div class="ib-key">Reason</div>
      <div class="ib-val" style="font-weight:400;">${reasonEn}</div>
    </div>
    <p>Your platform stays in status <code>unverified</code> and can still be used by users — it only shows a warning banner on the consent screen. Once you have addressed the points above, you can resubmit the request from the dashboard.</p>`,
    `<p>Wir haben deinen Antrag zur Verifikation der Plattform <strong>${escapeHtml(platformName)}</strong> geprüft und müssen ihn leider ablehnen.</p>
    <p>Deine Plattform bleibt im Status <code>unverified</code> und kann weiterhin von Usern genutzt werden — sie zeigt nur einen Warnbanner auf der Consent-Seite. Wenn du die Punkte oben behoben hast, kannst du den Antrag im Dashboard erneut einreichen.</p>`
  );

  const html = emailShell({
    title:     'Request rejected',
    subtitle:  'HUMAN-VERIFIED HTTPS · VERIFICATION REJECTED',
    bodyHtml,
    ctaUrl:    `${BASE_URL}/developers`,
    ctaLabel:  '→ To the dashboard / Zum Dashboard',
    footerNote: 'If you cannot follow the reasoning or have questions, feel free to reply to this email — we are happy to help. — Falls du die Begründung nicht nachvollziehen kannst oder Fragen hast, antworte gerne auf diese E-Mail — wir helfen weiter.'
  });

  const text = biText(
    [`HHTTPS — Verification request rejected`, '', `Platform: ${platformName}`, `Reason: ${reason || '(no reason given)'}`,
     '', `Dashboard: ${BASE_URL}/developers`, '', `— HHTTPS Project · hhttps.org`].join('\n'),
    [`HHTTPS — Verifikations-Antrag abgelehnt`, '', `Plattform: ${platformName}`, `Grund: ${reason || '(kein Grund angegeben)'}`,
     '', `Dashboard: ${BASE_URL}/developers`, '', `— HHTTPS Project · hhttps.org`].join('\n')
  );

  const transporter = createTransport();
  if (!transporter) {
    devLog('Platform rejected', to, `${BASE_URL}/developers`, { platformName, reason });
    return { sent: false, devMode: true };
  }

  await transporter.sendMail(buildMailOptions({
    to,
    subject: `[HHTTPS] Request for "${platformName}" rejected / Antrag abgelehnt`,
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
    error: 'Token not found, expired, or already used (valid: 15 min).'
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

// ═══════════════════════════════════════════════════════════════════════════
// PRIVACY PASS: anonymous wallet email verification
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Send the Privacy Pass wallet's email verification link.
 *
 * Separate code path from sendVerificationEmail (the legacy HHTTPS role
 * declaration flow) because the verify link points to a different endpoint
 * (/privacy-pass/email/verify), the wallet has its own role concept and trust
 * model, and the body is shorter and wallet-specific.
 *
 * Hash-only: the email plaintext is NEVER stored. The caller stores only the
 * SHA-256 hash. We use the plaintext here just for sending and then discard it.
 *
 * @param {object} opts
 * @param {string} opts.to     Recipient email
 * @param {string} opts.role   Role identifier (e.g. 'journalist')
 * @param {string} opts.link   Absolute URL of the verification link
 * @returns {Promise<{sent: boolean, devMode: boolean}>}
 */
export async function sendPrivacyPassVerification({ to, role, link }) {
  const label = roleDisplay(role);

  const bodyHtml = biHtml(
    `<p>You requested email verification for your <strong>Privacy Pass wallet</strong>.</p>
    <div class="info-box">
      <div class="ib-key">Role</div>
      <div class="ib-val">${label}</div>
    </div>
    <p>Click the button to confirm your email address. Afterwards you can fetch anonymous tokens in the wallet.</p>
    <p style="color:#a0b8d8;font-size:12px;margin-top:18px">The link is valid for <strong>15 minutes</strong>.</p>`,
    `<p>Du hast eine E-Mail-Verifikation für deine <strong>Privacy Pass Wallet</strong> angefordert.</p>
    <p>Klicke auf den Button, um deine E-Mail-Adresse zu bestätigen. Danach kannst du anonyme Tokens in der Wallet abrufen.</p>
    <p style="color:#a0b8d8;font-size:12px;margin-top:18px">Der Link ist <strong>15 Minuten</strong> gültig.</p>`
  );

  const html = emailShell({
    title:    'Privacy Pass — email verification',
    subtitle: 'HHTTPS · ANONYMOUS WALLET',
    bodyHtml,
    ctaUrl:   link,
    ctaLabel: '✓ Confirm email / E-Mail bestätigen',
    footerNote: '<strong style="color:#a0b8d8">Privacy:</strong> your email address is stored only as a hash, never in plaintext. The anonymous tokens issued later cannot be traced back to you. — <strong style="color:#a0b8d8">Datenschutz:</strong> Deine E-Mail-Adresse wird nur als Hash gespeichert, niemals im Klartext. Die später ausgestellten anonymen Tokens lassen sich nicht zu dir zurückverfolgen.'
  });

  const text = biText(
    `HHTTPS Privacy Pass — email verification\n\nRole: ${label}\n\nConfirm your email address:\n${link}\n\nThe link is valid for 15 minutes.\n\n— HHTTPS · hhttps.org`,
    `HHTTPS Privacy Pass — E-Mail-Verifikation\n\nRolle: ${label}\n\nBestätige deine E-Mail-Adresse:\n${link}\n\nDer Link ist 15 Minuten gültig.\n\n— HHTTPS · hhttps.org`
  );

  const transporter = createTransport();
  if (!transporter) {
    devLog('Privacy Pass verification', to, link, { role });
    return { sent: false, devMode: true };
  }

  await transporter.sendMail(buildMailOptions({
    to,
    subject: `[HHTTPS Privacy Pass] Email verification / E-Mail-Verifikation — ${roleLabel(role,'en')}`,
    text,
    html,
  }));

  return { sent: true, devMode: false };
}
