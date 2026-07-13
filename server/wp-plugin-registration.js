// server/wp-plugin-registration.js
//
// Self-service OAuth-client registration for CMS plugins (WordPress first).
//
// WHY: The developer-portal flow (/hhttps/developers/clients) requires an
// authenticated HHTTPS user — right for developers, wrong for a site admin who
// just installed the WordPress plugin. This module adds a lightweight,
// bot-resistant registration path with the SAME hard security checks:
//
//   1. contact e-mail must be confirmed (link click), AND
//   2. e-mail apex must match the platform apex (domain_email_match), AND
//   3. DNS TXT record `_hhttps-verify.<apex>` must carry the issued token.
//
// When ALL THREE hold, the client is AUTO-APPROVED to `verified` — no manual
// admin click (verified_by = 'auto:plugin-dns'). Admins can still filter/
// suspend in the portal; last_used_at keeps tracking activity as usual.
//
// Endpoints (mounted by mountWpPluginRegistration(app, deps)):
//   POST /hhttps/plugin/register            { site_name, homepage_url,
//                                             redirect_uri, contact_email }
//        → { client_id, verification_status, expected_host, dns_token, … }
//   GET  /hhttps/plugin/status/:clientId    → progress for the setup wizard
//   POST /hhttps/plugin/dns-check/:clientId → runs the TXT check;
//        on success + email confirmed + domain match → auto-verify.
//
// Zero-PII stance: stores only what the developer flow already stores
// (contact e-mail, domain, tokens). No end-user data is involved.

import crypto from 'crypto';
import { Resolver } from 'dns/promises';

// ── small local helpers (server.js keeps its own copies; duplicated here so
//    this module stays self-contained and server.js untouched) ──────────────

const TWO_PART_TLDS = new Set(['co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au',
  'co.nz', 'co.jp', 'com.br', 'com.mx', 'co.in']);

function apexDomainFromUrl(urlOrHost) {
  if (!urlOrHost) return null;
  let host;
  try {
    host = new URL(urlOrHost.includes('://') ? urlOrHost : `https://${urlOrHost}`).hostname;
  } catch { return null; }
  const parts = host.toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return null;
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

function emailMatchesPlatform(email, homepageUrl) {
  const at = (email || '').split('@')[1];
  if (!at) return false;
  const emailApex = apexDomainFromUrl(at);
  const siteApex  = apexDomainFromUrl(homepageUrl);
  return !!emailApex && !!siteApex && emailApex === siteApex;
}

function randomToken(len) {
  return crypto.randomBytes(len).toString('base64url').slice(0, len);
}

function generateClientId(name) {
  const slug = String(name || 'site').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24) || 'site';
  return `wp-${slug}-${randomToken(8)}`;
}

function isValidRedirectUri(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol !== 'https:' && u.hostname !== 'localhost') return false;
    if (u.hash) return false;
    return true;
  } catch { return false; }
}

// naive in-memory rate limit: 5 registrations per IP per hour
const regHits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (regHits.get(ip) || []).filter(t => now - t < 3600_000);
  if (arr.length >= 5) { regHits.set(ip, arr); return true; }
  arr.push(now); regHits.set(ip, arr);
  return false;
}

/**
 * Mount the plugin-registration endpoints.
 *
 * @param app  Express app
 * @param deps { db, sendPlatformRegistrationEmail, BASE_URL }
 *             — pass the SAME instances server.js already imports, so this
 *             module reuses the existing DB pool and mailer.
 */
export function mountWpPluginRegistration(app, deps) {
  const { db, sendPlatformRegistrationEmail, BASE_URL } = deps;

  // ── POST /hhttps/plugin/register ───────────────────────────────────────
  app.post('/hhttps/plugin/register', async (req, res) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    if (rateLimited(ip)) {
      return res.status(429).json({ error: 'rate_limited',
        message: 'Too many registrations from this address. Try again later.' });
    }

    const { site_name, homepage_url, redirect_uri, contact_email } = req.body || {};

    if (!site_name || typeof site_name !== 'string'
        || site_name.length < 2 || site_name.length > 120) {
      return res.status(400).json({ error: 'invalid_name',
        message: 'site_name must be 2-120 characters' });
    }
    const apex = apexDomainFromUrl(homepage_url);
    if (!apex) {
      return res.status(400).json({ error: 'invalid_homepage',
        message: 'homepage_url must be a valid HTTPS URL' });
    }
    if (!redirect_uri || !isValidRedirectUri(redirect_uri)) {
      return res.status(400).json({ error: 'invalid_redirect_uri',
        message: 'redirect_uri must be a valid HTTPS URL without fragment' });
    }
    // The redirect must live on the SAME apex as the homepage — a WordPress
    // plugin always redirects back to its own site. Blocks token exfiltration
    // to foreign hosts at registration time.
    if (apexDomainFromUrl(redirect_uri) !== apex) {
      return res.status(400).json({ error: 'redirect_apex_mismatch',
        message: 'redirect_uri must be on the same domain as homepage_url' });
    }
    if (!contact_email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(contact_email)) {
      return res.status(400).json({ error: 'invalid_email',
        message: 'Valid contact_email required' });
    }

    const domainMatch  = emailMatchesPlatform(contact_email, homepage_url);
    const emailToken   = randomToken(24);
    const emailExpires = new Date(Date.now() + 48 * 3600 * 1000);
    const dnsToken     = `hhttps-verify=${randomToken(20)}`;
    const clientId     = generateClientId(site_name);

    try {
      await db.oauthClients.createDraft({
        clientId,
        name: site_name,
        description: 'Registered via WordPress plugin setup',
        homepageUrl: homepage_url,
        redirectUris: [redirect_uri],
        contactEmail: contact_email,
        impressumUrl: null,
        logoUrl: null,
        ownerUserId: 'wp-plugin',
        domainEmailMatch: domainMatch,
        emailToken, emailTokenExpiresAt: emailExpires,
        dnsToken
      });
    } catch (err) {
      console.error('[WP-PLUGIN] createDraft failed:', err.message);
      return res.status(500).json({ error: 'creation_failed', message: err.message });
    }

    try {
      const confirmUrl = `${BASE_URL}/hhttps/developers/confirm-email?token=${emailToken}`;
      const setupUrl = String(homepage_url).replace(/\/+$/, '') +
        '/wp-admin/options-general.php?page=iamhmn-verify-setup';
      await sendPlatformRegistrationEmail({
        to:           contact_email,
        platformName: site_name,
        homepageUrl:  homepage_url,
        confirmUrl,
        kind:         'registration',
        setupUrl
      });
    } catch (err) {
      console.warn('[WP-PLUGIN] registration email failed:', err.message);
    }

    return res.json({
      success: true,
      client_id: clientId,
      verification_status: 'email_pending',
      domain_email_match: domainMatch,
      expected_host: `_hhttps-verify.${apex}`,
      dns_token: dnsToken,
      warnings: domainMatch ? [] : [{
        code: 'email_domain_mismatch',
        message: 'Contact e-mail domain does not match the site domain. ' +
                 'Auto-approval requires an e-mail address at the site domain.'
      }]
    });
  });

  // ── GET /hhttps/plugin/status/:clientId ────────────────────────────────
  app.get('/hhttps/plugin/status/:clientId', async (req, res) => {
    const client = await db.oauthClients.get(req.params.clientId);
    if (!client || client.owner_user_id !== 'wp-plugin') {
      return res.status(404).json({ error: 'not_found' });
    }
    const apex = apexDomainFromUrl(client.homepage_url);
    return res.json({
      client_id:           client.client_id,
      verification_status: client.verification_status,
      email_verified:      !!client.email_verified_at,
      domain_email_match:  !!client.domain_email_match,
      dns_verified:        !!client.dns_verified_at,
      expected_host:       apex ? `_hhttps-verify.${apex}` : null,
      // The TXT token is only revealed until the client is verified; after
      // that it is no longer needed by the wizard.
      dns_token: client.verification_status === 'verified' ? null : client.dns_token
    });
  });

  // ── POST /hhttps/plugin/dns-check/:clientId ────────────────────────────
  app.post('/hhttps/plugin/dns-check/:clientId', async (req, res) => {
    const client = await db.oauthClients.get(req.params.clientId);
    if (!client || client.owner_user_id !== 'wp-plugin') {
      return res.status(404).json({ error: 'not_found' });
    }
    if (!client.dns_token) {
      return res.status(400).json({ error: 'no_dns_token' });
    }
    const apex = apexDomainFromUrl(client.homepage_url);
    if (!apex) {
      return res.status(400).json({ error: 'no_apex' });
    }

    const resolver = new Resolver();
    let records = [];
    try {
      records = await resolver.resolveTxt(`_hhttps-verify.${apex}`);
    } catch (err) {
      await db.oauthClients.touchDnsCheck(client.client_id);
      return res.json({
        success: false, dns_verified: false,
        error: 'dns_lookup_failed',
        message: `Could not resolve _hhttps-verify.${apex}: ${err.code || err.message}`,
        expected_record: client.dns_token,
        expected_host: `_hhttps-verify.${apex}`
      });
    }

    let found = false;
    for (const parts of records) {
      if (parts.join('').trim() === client.dns_token.trim()) { found = true; break; }
    }
    await db.oauthClients.touchDnsCheck(client.client_id);

    if (!found) {
      return res.json({
        success: false, dns_verified: false,
        error: 'record_not_found',
        message: 'TXT record not found or value does not match.',
        expected_record: client.dns_token,
        expected_host: `_hhttps-verify.${apex}`,
        found_records: records.map(r => r.join(''))
      });
    }

    await db.oauthClients.setDnsVerified(client.client_id);

    // AUTO-APPROVAL: all three hard requirements met → verified, no admin
    // click. verified_by records the automatic path for auditability.
    const fresh = await db.oauthClients.get(client.client_id);
    let autoVerified = false;
    if (fresh.email_verified_at && fresh.domain_email_match && fresh.dns_verified_at
        && fresh.verification_status !== 'verified'
        && fresh.verification_status !== 'suspended'
        && fresh.verification_status !== 'rejected') {
      await db.oauthClients.adminApprove(client.client_id, 'auto:plugin-dns');
      autoVerified = true;
      console.log(`[WP-PLUGIN] auto-verified client ${client.client_id} (email+domain+dns)`);
    }

    return res.json({
      success: true,
      dns_verified: true,
      auto_verified: autoVerified,
      verification_status: autoVerified ? 'verified' : fresh.verification_status
    });
  });
}
