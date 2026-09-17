// server/dns-verify.js
//
// AP5-39 / AP5-32 (Review 2026-09, Welle 3): the domain-ownership check
// (`_hhttps-verify.<apex>` TXT == the client's dns_token) used to exist twice,
// nearly line for line — once in the developer portal
// (POST /hhttps/developers/clients/:id/dns-check) and once in the WordPress
// plugin flow (POST /hhttps/plugin/dns-check/:clientId). The copies differed
// in exactly one place that mattered: the portal asked 1.1.1.1 / 8.8.8.8, the
// plugin asked whatever resolver the host happened to be configured with, so
// the same domain could verify through one door and not the other.
//
// This module is the single implementation. The resolver is created ONCE per
// process (AP5-32: the portal handler used to `await import('dns/promises')`,
// build a Resolver and call setServers() on every single request) and the
// nameservers are pinned to public resolvers by default — a site's own
// split-horizon DNS must not be able to answer an ownership challenge about
// itself. DNS_VERIFY_SERVERS overrides them for closed deployments.

import { Resolver } from 'node:dns/promises';
import { apexDomainFromUrl, expectedDnsHost } from './client-registration.js';

export const DNS_TIMEOUT_MS      = 3000;
export const DNS_MIN_INTERVAL_MS = 15_000;

const DEFAULT_SERVERS = ['1.1.1.1', '8.8.8.8'];

const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
{
  const configured = String(process.env.DNS_VERIFY_SERVERS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  try { resolver.setServers(configured.length ? configured : DEFAULT_SERVERS); }
  catch (err) { console.warn('[dns-verify] invalid DNS_VERIFY_SERVERS:', err.message); }
}

/** The resolver timeout is per attempt / per server — add a hard deadline. */
function resolveTxtWithDeadline(host) {
  return Promise.race([
    resolver.resolveTxt(host),
    new Promise((_, reject) => setTimeout(() => {
      const e = new Error('DNS lookup timed out'); e.code = 'ETIMEOUT'; reject(e);
    }, DNS_TIMEOUT_MS * 2 + 500).unref())
  ]);
}

/** AP5-31: at most one lookup per client per DNS_MIN_INTERVAL_MS. */
export function dnsCheckTooSoon(client) {
  const last = client?.dns_last_checked_at ? new Date(client.dns_last_checked_at).getTime() : 0;
  return !!last && (Date.now() - last) < DNS_MIN_INTERVAL_MS;
}

/**
 * Run the TXT check for `client` and record the attempt.
 *
 * Always resolves (a lookup failure is a result, not an exception) and always
 * calls touchDnsCheck, so the per-client interval applies to failures too.
 *
 * @returns the JSON response body; `dns_verified` says whether it matched.
 */
export async function verifyDnsToken(db, client) {
  const apex = apexDomainFromUrl(client.homepage_url);
  const host = expectedDnsHost(apex);

  let records;
  try {
    records = await resolveTxtWithDeadline(host);
  } catch (err) {
    await db.oauthClients.touchDnsCheck(client.client_id);
    return {
      success: false, dns_verified: false,
      error: 'dns_lookup_failed',
      message: `Could not resolve ${host}: ${err.code || err.message}`,
      expected_record: client.dns_token,
      expected_host: host
    };
  }

  // A TXT record can arrive in several chunks — join them before comparing.
  const wanted = String(client.dns_token).trim();
  const found  = records.some(chunks => chunks.join('').trim() === wanted);
  await db.oauthClients.touchDnsCheck(client.client_id);

  if (!found) {
    return {
      success: false, dns_verified: false,
      error: 'record_not_found',
      message: 'TXT record not found, or its value does not match. ' +
               'The value must be exactly the dns_token.',
      expected_record: client.dns_token,
      expected_host: host,
      found_records: records.map(r => r.join(''))
    };
  }

  await db.oauthClients.setDnsVerified(client.client_id);
  return { success: true, dns_verified: true };
}

/**
 * Auto-approval (plugin flow only): e-mail confirmed AND e-mail apex ==
 * platform apex AND DNS proven → `verified`, without an admin click.
 * verified_by records the automatic path for auditability.
 *
 * @returns {{ autoVerified: boolean, client: object }} the reloaded row
 */
export async function maybeAutoVerify(db, clientId) {
  const fresh = await db.oauthClients.get(clientId);
  const blocked = ['verified', 'suspended', 'rejected'];
  if (fresh?.email_verified_at && fresh.domain_email_match && fresh.dns_verified_at
      && !blocked.includes(fresh.verification_status)) {
    await db.oauthClients.adminApprove(clientId, 'auto:plugin-dns');
    console.log(`[WP-PLUGIN] auto-verified client ${clientId} (email+domain+dns)`);
    return { autoVerified: true, client: fresh };
  }
  return { autoVerified: false, client: fresh };
}
