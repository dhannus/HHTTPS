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

import rateLimit from 'express-rate-limit';
import { isValidEmail, normalizeEmail } from './identity.js';
import {
  apexDomainFromUrl, emailMatchesPlatform, expectedDnsHost,
  generateClientId, isValidHomepageUrl, isValidRedirectUri, randomToken,
  WP_PLUGIN_OWNER_ID, PLATFORM_EMAIL_TOKEN_TTL_MS
} from './client-registration.js';
import { dnsCheckTooSoon, maybeAutoVerify, verifyDnsToken, DNS_MIN_INTERVAL_MS }
  from './dns-verify.js';

// AP5-38 / AP5-39 (Welle 3): apex resolution, redirect validation, client-id
// generation and the DNS-TXT check used to be private copies here, with
// semantics that quietly differed from the developer portal's. They now live
// in ./client-registration.js and ./dns-verify.js — one rule, both doors.

// AP5-17: 5 registrations per IP per hour via express-rate-limit (keyed on
// req.ip, which honours the app's `trust proxy` setting — the previous
// hand-rolled map trusted a client-supplied X-Forwarded-For and never evicted).
const registrationLimiter = rateLimit({
  windowMs: 3600_000, limit: 5, standardHeaders: true, legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'rate_limited',
    message: 'Too many registrations from this address. Try again later.' })
});

// AP5-31: the DNS check is unauthenticated (client_id only) and used to run
// an unbounded lookup per call — now 10 calls / min per IP, plus the resolver
// timeout, hard deadline and per-client minimum interval from dns-verify.js.
const dnsCheckLimiter = rateLimit({
  windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'rate_limited',
    message: 'Too many DNS checks from this address. Try again later.' })
});

// AP5-29: an unauthenticated registration writes a row and sends a mail per
// call. Besides the IP limiter, at most this many UNCONFIRMED (email_pending,
// token not yet expired) plugin drafts may exist per site apex.
const MAX_OPEN_DRAFTS_PER_APEX = 3;
async function countOpenDraftsForApex(db, apex) {
  const { rows } = await db.q(
    `SELECT homepage_url FROM oauth_clients
      WHERE owner_user_id = $1
        AND verification_status = 'email_pending'
        AND email_token_expires_at > NOW()`,
    [WP_PLUGIN_OWNER_ID]
  );
  return rows.filter(r => apexDomainFromUrl(r.homepage_url) === apex).length;
}

// AP5-09: forward async rejections to the app's central error handler.
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

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
  app.post('/hhttps/plugin/register', registrationLimiter, wrap(async (req, res) => {

    const { site_name, homepage_url, redirect_uri, contact_email } = req.body || {};

    if (!site_name || typeof site_name !== 'string'
        || site_name.length < 2 || site_name.length > 120) {
      return res.status(400).json({ error: 'invalid_name',
        message: 'site_name must be 2-120 characters' });
    }
    if (!isValidHomepageUrl(homepage_url)) {                   // AP5-14
      return res.status(400).json({ error: 'invalid_homepage',
        message: 'homepage_url must be a valid HTTPS URL' });
    }
    const apex = apexDomainFromUrl(homepage_url);
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
    if (!isValidEmail(normalizeEmail(contact_email))) {
      return res.status(400).json({ error: 'invalid_email',
        message: 'Valid contact_email required' });
    }

    if (await countOpenDraftsForApex(db, apex) >= MAX_OPEN_DRAFTS_PER_APEX) {
      return res.status(429).json({ error: 'too_many_pending',
        message: `There are already ${MAX_OPEN_DRAFTS_PER_APEX} unconfirmed registrations for ${apex}. ` +
                 'Confirm one of them via the e-mail link (or wait until they expire).' });
    }

    const domainMatch  = emailMatchesPlatform(contact_email, homepage_url);
    const emailToken   = randomToken(24);
    const emailExpires = new Date(Date.now() + PLATFORM_EMAIL_TOKEN_TTL_MS);
    const dnsToken     = `hhttps-verify=${randomToken(20)}`;
    const clientId     = generateClientId(site_name, { prefix: 'wp-', fallback: 'site' });

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
        ownerUserId: WP_PLUGIN_OWNER_ID,
        domainEmailMatch: domainMatch,
        emailToken, emailTokenExpiresAt: emailExpires,
        dnsToken
      });
    } catch (err) {
      // AP5-24: a Postgres error text names columns, constraints and values.
      console.error('[WP-PLUGIN] createDraft failed:', err);
      return res.status(500).json({ error: 'creation_failed',
        message: 'The site could not be registered. Please try again.' });
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
      expected_host: expectedDnsHost(apex),
      dns_token: dnsToken,
      warnings: domainMatch ? [] : [{
        code: 'email_domain_mismatch',
        message: 'Contact e-mail domain does not match the site domain. ' +
                 'Auto-approval requires an e-mail address at the site domain.'
      }]
    });
  }));

  // ── GET /hhttps/plugin/status/:clientId ────────────────────────────────
  app.get('/hhttps/plugin/status/:clientId', wrap(async (req, res) => {
    const client = await db.oauthClients.get(req.params.clientId);
    if (!client || client.owner_user_id !== WP_PLUGIN_OWNER_ID) {
      return res.status(404).json({ error: 'not_found' });
    }
    const apex = apexDomainFromUrl(client.homepage_url);
    return res.json({
      client_id:           client.client_id,
      verification_status: client.verification_status,
      email_verified:      !!client.email_verified_at,
      domain_email_match:  !!client.domain_email_match,
      dns_verified:        !!client.dns_verified_at,
      expected_host:       expectedDnsHost(apex),
      // The TXT token is only revealed until the client is verified; after
      // that it is no longer needed by the wizard.
      dns_token: client.verification_status === 'verified' ? null : client.dns_token
    });
  }));

  // ── POST /hhttps/plugin/dns-check/:clientId ────────────────────────────
  app.post('/hhttps/plugin/dns-check/:clientId', dnsCheckLimiter, wrap(async (req, res) => {
    const client = await db.oauthClients.get(req.params.clientId);
    if (!client || client.owner_user_id !== WP_PLUGIN_OWNER_ID) {
      return res.status(404).json({ error: 'not_found' });
    }
    if (!client.dns_token) {
      return res.status(400).json({ error: 'no_dns_token' });
    }
    if (dnsCheckTooSoon(client)) {
      return res.status(429).json({ error: 'dns_check_too_soon',
        message: `Wait ${Math.ceil(DNS_MIN_INTERVAL_MS / 1000)} s between DNS checks.`,
        retry_after: Math.ceil(DNS_MIN_INTERVAL_MS / 1000) });
    }
    const apex = apexDomainFromUrl(client.homepage_url);
    if (!apex) {
      return res.status(400).json({ error: 'no_apex' });
    }

    const result = await verifyDnsToken(db, client);
    if (!result.dns_verified) return res.json(result);

    // AUTO-APPROVAL: all three hard requirements met → verified, no admin click.
    const { autoVerified, client: fresh } = await maybeAutoVerify(db, client.client_id);

    return res.json({
      success: true,
      dns_verified: true,
      auto_verified: autoVerified,
      verification_status: autoVerified ? 'verified' : fresh.verification_status
    });
  }));
}
