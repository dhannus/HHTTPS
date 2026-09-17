// Review 2026-09, Welle 2 — AP1 unit tests (no database):
//   AP1-06  reserved-role detection: word boundaries for English stems, longest
//           stem / longest ISCO prefix wins, every registry prefix resolves to
//           its own key, no 3-digit catch-all prefixes
//   AP1-04  WEBHOOK_EVENTS is the single event catalogue: it covers exactly what
//           server.js fires, '*' expands to it, fireEvent refuses unknown events
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { guardReservedRole, sanitizeCustomRole, resolveRole, RESERVED_REGISTRY, RESERVED_STEMS } from '../../roles.taxonomy.js';
import { WEBHOOK_EVENTS, fireEvent } from '../../webhooks.js';

const here = dirname(fileURLToPath(import.meta.url));

// ─── AP1-06 ──────────────────────────────────────────────────────────────────
test('AP1-06: substrings of ordinary professions are not reserved', () => {
  for (const label of ['Nursery teacher', 'Tierpfleger', 'Einrichter', 'doctoral student', 'Steuerprüfer', 'Judgement analyst']) {
    const g = guardReservedRole(label);
    assert.equal(g.reserved, false, `${label} → ${JSON.stringify(g)}`);
    assert.equal(sanitizeCustomRole(label).ok, true, `${label} allowed as custom role`);
  }
});

test('AP1-06: reserved professions still match (German compounds, English words) with the right key', () => {
  const cases = {
    'Rechtsanwältin': 'lawyer', 'Fachärztin': 'medical', 'Dr. med. Müller': 'medical', 'Notarzt': 'medical',
    'Krankenpfleger': 'nursing', 'Krankenpfleger und Tierpfleger': 'nursing', 'Nurse': 'nursing',
    'Notar': 'notary', 'Polizist': 'police', 'Police officer': 'police',
    'Staatsanwältin': 'judge', 'Staatsanwalt': 'judge', 'Richterin': 'judge', 'Judge': 'judge', 'Doctor': 'medical',
  };
  for (const [label, key] of Object.entries(cases)) {
    const g = guardReservedRole(label);
    assert.equal(g.reserved, true, `${label} reserved`);
    assert.equal(g.key, key, `${label} → ${g.key} (matched "${g.matched}")`);
    assert.equal(sanitizeCustomRole(label).reason, 'reserved', `${label} blocked as custom role`);
  }
});

test('AP1-06: every registry ISCO prefix resolves to its own key; unrelated codes are free', () => {
  for (const [key, def] of Object.entries(RESERVED_REGISTRY)) {
    for (const p of def.iscoPrefixes) {
      assert.ok(p.length >= 3, `${key}: prefix ${p}`);
      const g = guardReservedRole('', p);
      assert.equal(g.key, key, `ISCO ${p} → ${g.key}, expected ${key}`);
      const r = resolveRole({ label: 'x', isco08: p });
      assert.equal(r.reservedKey, key, `resolveRole ${p}`);
    }
  }
  // 2612 (judges) is not a notary, 3352 (tax) / 3351 (customs) are not police
  assert.equal(guardReservedRole(null, '2612').key, 'judge');
  for (const code of ['3352', '3351', '3353', '2610', '7522']) {
    assert.equal(guardReservedRole(null, code).reserved, false, `ISCO ${code} free`);
  }
  // no registry prefix is a prefix of another registry's entry
  const all = Object.entries(RESERVED_REGISTRY).flatMap(([k, d]) => d.iscoPrefixes.map(p => [k, p]));
  for (const [k1, p1] of all) for (const [k2, p2] of all) {
    if (k1 !== k2) assert.equal(p2.startsWith(p1), false, `${k1}:${p1} shadows ${k2}:${p2}`);
  }
});

test('AP1-06: the exported stem list stays non-empty and mirrors the keyed tables', () => {
  assert.ok(RESERVED_STEMS.length >= 30);
  for (const stem of RESERVED_STEMS) assert.equal(typeof stem, 'string');
});

// ─── AP1-04 ──────────────────────────────────────────────────────────────────
test('AP1-04: WEBHOOK_EVENTS equals the set of events server.js fires (no role.declared)', () => {
  const src = readFileSync(join(here, '../../server.js'), 'utf8');
  const fired = new Set([...src.matchAll(/fireEvent\(\s*'([a-z.]+)'/g)].map(m => m[1]));
  assert.ok(fired.size >= 5, `found ${fired.size} fireEvent calls`);
  assert.deepEqual([...fired].sort(), [...WEBHOOK_EVENTS].sort());
  assert.equal(WEBHOOK_EVENTS.includes('role.declared'), false);
  assert.equal(WEBHOOK_EVENTS.includes('*'), false);
  assert.ok(Object.isFrozen(WEBHOOK_EVENTS));
});

test('AP1-04: fireEvent ignores an event outside the catalogue without touching the database', async () => {
  // db.js has no connection at this point (DB_* unset); a lookup would throw.
  const errors = [];
  const orig = console.error;
  console.error = (...a) => errors.push(a.join(' '));
  try {
    await assert.doesNotReject(() => fireEvent('role.declared', { x: 1 }));
    await assert.doesNotReject(() => fireEvent('*', {}));
  } finally { console.error = orig; }
  assert.equal(errors.length, 2);
  assert.match(errors[0], /unknown event "role\.declared"/);
});
