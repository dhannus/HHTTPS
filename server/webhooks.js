/**
 * HHTTPS Webhook System v4.1
 *
 * Now backed by PostgreSQL via db.js — webhooks survive server restarts,
 * delivery audit log persists, retry state is durable.
 *
 * Events: token.issued, token.revoked, role.declared
 * Delivery: HTTP POST with HMAC-SHA256 signature.
 */

import crypto from 'crypto';
import { webhooks as dbWebhooks } from './db.js';

const VALID_EVENTS = ['token.issued', 'token.revoked', 'role.declared', '*'];

// ─── Register ─────────────────────────────────────────────────────────────────
export async function registerWebhook({ url, events, secret }) {
  try { new URL(url); } catch { throw new Error('Invalid webhook URL.'); }

  const invalid = events.find(e => !VALID_EVENTS.includes(e));
  if (invalid) throw new Error(`Unbekanntes Event: ${invalid}`);

  const expanded = events.includes('*')
    ? ['token.issued', 'token.revoked', 'role.declared']
    : events;

  const id        = crypto.randomBytes(12).toString('hex');
  const secretVal = secret || crypto.randomBytes(32).toString('hex');

  await dbWebhooks.create({ id, url, events: expanded, secret: secretVal });

  return { id, url, events: expanded, secret: secretVal };
}

// ─── Deregister ───────────────────────────────────────────────────────────────
export async function removeWebhook(id) {
  return await dbWebhooks.delete(id);
}

// ─── List ─────────────────────────────────────────────────────────────────────
export async function listWebhooks() {
  return await dbWebhooks.list();
}

// ─── Fire event ───────────────────────────────────────────────────────────────
export async function fireEvent(eventType, payload) {
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
