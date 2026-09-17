/**
 * HHTTPS Webhook System v4.1
 *
 * Now backed by PostgreSQL via db.js — webhooks survive server restarts,
 * delivery audit log persists, retry state is durable.
 *
 * Events: see WEBHOOK_EVENTS (the single source of truth for what can be
 * subscribed AND what fireEvent may emit).
 * Delivery: HTTP POST with HMAC-SHA256 signature.
 */

import crypto from 'crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import { webhooks as dbWebhooks } from './db.js';

// AP1-04: the event catalogue. Everything server.js fires is listed here,
// registration validates against it, '*' expands to it, and fireEvent refuses
// anything not in it — so the catalogue and the emitted events cannot drift.
export const WEBHOOK_EVENTS = Object.freeze([
  'identity.verified',   // e-mail-first flow completed, identity established
  'token.issued',        // HHTTPS access token issued
  'token.revoked',       // HHTTPS access token revoked
  'age.verified',        // age group confirmed (EUDI Wallet)
  'eudi.verified',       // eID identity confirmed (EUDI Wallet)
  'card.issued',         // iamhmn-card (role EAA) issued
]);
const VALID_EVENTS = [...WEBHOOK_EVENTS, '*'];

// ─── SSRF guard (AP1-21, Review 2026-09) ──────────────────────────────────────
// Webhook targets are attacker-supplied URLs that the server POSTs to. Only
// https (http outside production), no credentials, no loopback / private /
// link-local / ULA / metadata addresses — checked on the resolved addresses,
// and redirects are not followed (fetch `redirect: 'error'`).
// WEBHOOK_ALLOW_PRIVATE=1 lifts the address check for local integration tests.
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127
      || (a === 100 && b >= 64 && b <= 127)          // CGNAT
      || (a === 169 && b === 254)                    // link-local / cloud metadata
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || a >= 224;                                   // multicast / reserved
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v === '::' || v === '::1') return true;
    if (v.startsWith('::ffff:')) return isPrivateAddress(v.slice(7));
    return v.startsWith('fc') || v.startsWith('fd')  // ULA
      || v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb') // link-local
      || v.startsWith('ff');                          // multicast
  }
  return true;
}

export async function assertSafeWebhookUrl(url, env = process.env) {
  let u;
  try { u = new URL(url); } catch { throw new Error('Invalid webhook URL.'); }
  const allowHttp = env.NODE_ENV !== 'production';
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:'))
    throw new Error('Webhook URL must use https.');
  if (u.username || u.password) throw new Error('Webhook URL must not contain credentials.');
  if (env.WEBHOOK_ALLOW_PRIVATE === '1') return u;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal'))
    throw new Error('Webhook URL must point to a public host.');
  let addrs;
  if (net.isIP(host)) addrs = [{ address: host }];
  else {
    try { addrs = await dns.lookup(host, { all: true }); }
    catch { throw new Error('Webhook host does not resolve.'); }
  }
  if (!addrs.length || addrs.some(a => isPrivateAddress(a.address)))
    throw new Error('Webhook URL must point to a public host.');
  return u;
}

// ─── Register ─────────────────────────────────────────────────────────────────
export async function registerWebhook({ url, events, secret, ownerUserId }) {
  if (!ownerUserId) throw new Error('Webhook owner is required.');
  await assertSafeWebhookUrl(url);

  const invalid = events.find(e => !VALID_EVENTS.includes(e));
  if (invalid) throw new Error(`Unbekanntes Event: ${invalid}`);

  const expanded = events.includes('*')
    ? [...WEBHOOK_EVENTS]
    : [...new Set(events)];

  const id        = crypto.randomBytes(12).toString('hex');
  const secretVal = secret || crypto.randomBytes(32).toString('hex');

  await dbWebhooks.create({ id, url, events: expanded, secret: secretVal, ownerUserId });

  // The secret is returned exactly once — here. list() never exposes it (AP1-22).
  return { id, url, events: expanded, secret: secretVal };
}

// ─── Deregister (own webhooks only, AP5-16) ───────────────────────────────────
export async function removeWebhook(id, ownerUserId) {
  return await dbWebhooks.delete(id, ownerUserId);
}

// ─── List (own webhooks only, without secrets) ────────────────────────────────
export async function listWebhooks(ownerUserId) {
  return await dbWebhooks.list(ownerUserId);
}

// ─── Fire event ───────────────────────────────────────────────────────────────
export async function fireEvent(eventType, payload) {
  if (!WEBHOOK_EVENTS.includes(eventType)) {
    // A programming error, not a runtime condition: surface it loudly in the
    // log, never deliver an event nobody could have subscribed to.
    console.error(`[WEBHOOK] fireEvent: unknown event "${eventType}" (not in WEBHOOK_EVENTS)`);
    return;
  }
  const matching = await dbWebhooks.findForEvent(eventType);
  if (!matching.length) return;

  const body = JSON.stringify({
    event:     eventType,
    timestamp: new Date().toISOString(),
    data:      payload
  });

  // fire-and-forget — webhook failures shouldn't block the originating request
  Promise.allSettled(matching.map(wh => deliverWithRetry(wh, body, eventType)))
    .catch(err => console.error('[WEBHOOK] dispatch error:', err));
}

// ─── Delivery with retry ──────────────────────────────────────────────────────
async function deliverWithRetry(wh, body, event, attempt = 1) {
  const sig = 'sha256=' + crypto.createHmac('sha256', wh.secret).update(body).digest('hex');
  const MAX = 3;

  try {
    const res = await fetch(wh.url, {
      method:  'POST',
      headers: {
        'Content-Type':         'application/json',
        'HHTTPS-Webhook-Sig':   sig,
        'HHTTPS-Webhook-Event': event,
        'User-Agent':           'HHTTPS-Webhook/4.1'
      },
      body,
      redirect: 'error',                 // AP1-21: never follow to an internal target
      signal: AbortSignal.timeout(8000)
    });

    if (res.ok) {
      await dbWebhooks.recordDelivery(wh.id, event, 'success', res.status, attempt);
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    console.warn(`[WEBHOOK] Delivery failed (attempt ${attempt}/${MAX}): ${wh.url} — ${err.message}`);
    await dbWebhooks.recordDelivery(wh.id, event, 'failed', null, attempt);

    if (attempt < MAX) {
      const delay = 1000 * Math.pow(2, attempt); // 2s, 4s
      await new Promise(r => setTimeout(r, delay));
      return deliverWithRetry(wh, body, event, attempt + 1);
    }

    // Disable webhook after too many consecutive failures
    const disabled = await dbWebhooks.deactivateIfFailing(wh.id, 10);
    if (disabled) console.warn(`[WEBHOOK] Disabled after 10 failures: ${wh.url}`);
  }
}
