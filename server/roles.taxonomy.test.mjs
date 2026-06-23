/**
 * roles.taxonomy.test.mjs — runnable sanity tests (no framework, enum-free model).
 * Run: node roles.taxonomy.test.mjs
 */
import assert from 'node:assert/strict';
import {
  deriveRAL, resolveRole, buildRoleClaim, sanitizeCustomRole, guardReservedRole,
  RESERVED_REGISTRY, RAL_LEVELS, CUSTOM_ROLE_ID
} from './roles.taxonomy.js';
import { buildRoleEaaClaims, guardRoleEaa } from './roles.eaa.js';

let n = 0; const ok = (s) => { n++; console.log(`  ✓ ${s}`); };

// RAL derivation
assert.equal(deriveRAL({ verificationStatus: 'self-declared' }), 0);
assert.equal(deriveRAL({ method: 'document-checked' }), 1);
assert.equal(deriveRAL({ method: 'email-verified' }), 1);
assert.equal(deriveRAL({ method: 'eudi-wallet-role' }), 2);
ok('deriveRAL: self=0, document/domain=1, eudi=2');

// Dynamic resolver — no fixed list
const dev = resolveRole({ label: 'Drohnen-Choreograf' });
assert.equal(dev.reserved, false);
assert.equal(dev.group, 'B');
const docByIsco = resolveRole({ label: 'Internistin', isco08: '2212' });
assert.equal(docByIsco.reserved, true);          // reserved via ISCO prefix, no keyword
assert.equal(docByIsco.reservedKey, 'medical');
assert.equal(docByIsco.group, 'A');
ok('resolveRole is dynamic; reserved detected by ISCO prefix and by keyword');

// Custom free-text → always RAL0
const custom = buildRoleClaim({ custom: true, customLabel: 'Barista', humanVerified: true });
assert.equal(custom.ral, 0);
assert.equal(custom.role.self_declared, true);
assert.equal(custom.role.custom, true);
ok('custom free-text role is always RAL0');

// Document-checked self-issued card → RAL1
const card1 = buildRoleClaim({ roleInput: { label: 'Tischler', isco08: '7522' }, method: 'document-checked', humanVerified: true });
assert.equal(card1.ral, 1);
assert.equal(card1.verification.evidence_type, 'document');
ok('document-checked card → RAL1 (evidence: document)');

// External qualified → RAL2
const ext = buildRoleEaaClaims({ roleInput: { label: 'Ärztin', isco08: '2212' }, ral: 2, authoritativeSource: 'Ärztekammer Berlin' });
assert.equal(ext.claims.ral, 2);
assert.equal(ext.claims.role_verification.trust_framework, 'eidas');
ok('external (Q)EAA → RAL2 (eidas/high)');

// Reserved governance: cannot self-declare a reserved profession
for (const bad of ['Dr. med. Müller', 'Rechtsanwältin', 'Notarzt', 'Polizist', 'Krankenpfleger']) {
  const c = sanitizeCustomRole(bad);
  assert.equal(c.ok, false, `expected "${bad}" rejected`);
  assert.equal(c.reason, 'reserved');
}
for (const good of ['Drohnen-Choreograf', 'Barista', 'Game Designer', 'Sommelier']) {
  assert.equal(sanitizeCustomRole(good).ok, true, `expected "${good}" allowed`);
}
ok('reserved professions blocked as custom; legit free-text passes');

// Reserved EAA guard: blocked at RAL0, allowed at RAL2+source / RAL1
assert.equal(guardRoleEaa({ roleInput: { label: 'Ärztin', isco08: '2212' }, ral: 0 }).allowed, false);
assert.equal(guardRoleEaa({ roleInput: { label: 'Ärztin', isco08: '2212' }, ral: 1 }).allowed, true);
assert.equal(guardRoleEaa({ roleInput: { label: 'Ärztin', isco08: '2212' }, ral: 2, authoritativeSource: 'ÄK' }).allowed, true);
ok('reserved EAA: blocked at RAL0, allowed at RAL1 (doc) / RAL2 (qualified)');

// RAL levels well-formed; RAL0 never "verified"
for (const k of [0, 1, 2]) { assert.ok(RAL_LEVELS[k]); assert.equal(RAL_LEVELS[k].ral, k); }
assert.equal(RAL_LEVELS[0].badge.verifiedWording, false);
ok('RAL levels well-formed; RAL0 badge never claims "verified"');

// Reserved registry shape
for (const [key, def] of Object.entries(RESERVED_REGISTRY)) {
  assert.ok(def.label && Array.isArray(def.iscoPrefixes) && def.sourceHint, `registry ${key} malformed`);
}
ok('reserved registry well-formed');

console.log(`\n✅ ${n} checks passed. Reserved keys: ${Object.keys(RESERVED_REGISTRY).join(', ')}`);
