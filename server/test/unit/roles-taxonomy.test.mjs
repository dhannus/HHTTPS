// Role taxonomy & assurance — RAL derivation, the dynamic (enum-free) resolver,
// custom-role sanitation, the reserved-profession governance layer and the
// role-EAA bridge.
//
// AP1-10 (#220): this used to be server/roles.taxonomy.test.mjs — a hand-rolled
// script with bare `assert` calls that had to be run by hand and was outside the
// `npm test` glob, so nothing here was ever checked in CI. Same assertions,
// converted to node:test.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveRAL, resolveRole, buildRoleClaim, sanitizeCustomRole,
  RESERVED_REGISTRY, RAL_LEVELS
} from '../../roles.taxonomy.js';
import { buildRoleEaaClaims, guardRoleEaa } from '../../roles.eaa.js';

test('deriveRAL: self-declared = 0, document/email = 1, EUDI = 2', () => {
  assert.equal(deriveRAL({ verificationStatus: 'self-declared' }), 0);
  assert.equal(deriveRAL({ method: 'document-checked' }), 1);
  assert.equal(deriveRAL({ method: 'email-verified' }), 1);
  assert.equal(deriveRAL({ method: 'eudi-wallet-role' }), 2);
});

test('resolveRole is dynamic; reserved detected by ISCO prefix and by keyword', () => {
  const free = resolveRole({ label: 'Drohnen-Choreograf' });
  assert.equal(free.reserved, false);
  assert.equal(free.group, 'B');

  const docByIsco = resolveRole({ label: 'Internistin', isco08: '2212' });
  assert.equal(docByIsco.reserved, true);   // reserved via ISCO prefix, no keyword
  assert.equal(docByIsco.reservedKey, 'medical');
  assert.equal(docByIsco.group, 'A');
});

test('a custom free-text role is always RAL0', () => {
  const custom = buildRoleClaim({ custom: true, customLabel: 'Barista', humanVerified: true });
  assert.equal(custom.ral, 0);
  assert.equal(custom.role.self_declared, true);
  assert.equal(custom.role.custom, true);
});

test('a document-checked self-issued card is RAL1 with document evidence', () => {
  const card = buildRoleClaim({
    roleInput: { label: 'Tischler', isco08: '7522' },
    method: 'document-checked', humanVerified: true
  });
  assert.equal(card.ral, 1);
  assert.equal(card.verification.evidence_type, 'document');
});

test('an external qualified (Q)EAA is RAL2 under the eidas trust framework', () => {
  const ext = buildRoleEaaClaims({
    roleInput: { label: 'Ärztin', isco08: '2212' },
    ral: 2, authoritativeSource: 'Ärztekammer Berlin'
  });
  assert.equal(ext.ok, true);
  assert.equal(ext.claims.ral, 2);
  assert.equal(ext.claims.role_verification.trust_framework, 'eidas');
});

test('buildRoleEaaClaims refuses an empty roleInput', () => {
  const bad = buildRoleEaaClaims({ roleInput: {} });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /roleInput/);
});

test('reserved professions are blocked as custom roles; legitimate free text passes', () => {
  for (const bad of ['Dr. med. Müller', 'Rechtsanwältin', 'Notarzt', 'Polizist', 'Krankenpfleger']) {
    const c = sanitizeCustomRole(bad);
    assert.equal(c.ok, false, `expected "${bad}" rejected`);
    assert.equal(c.reason, 'reserved');
  }
  for (const good of ['Drohnen-Choreograf', 'Barista', 'Game Designer', 'Sommelier']) {
    assert.equal(sanitizeCustomRole(good).ok, true, `expected "${good}" allowed`);
  }
});

test('reserved EAA: blocked at RAL0, allowed at RAL1 (document) and RAL2 (qualified)', () => {
  const role = { label: 'Ärztin', isco08: '2212' };
  assert.equal(guardRoleEaa({ roleInput: role, ral: 0 }).allowed, false);
  assert.equal(guardRoleEaa({ roleInput: role, ral: 1 }).allowed, true);
  assert.equal(guardRoleEaa({ roleInput: role, ral: 2, authoritativeSource: 'ÄK' }).allowed, true);
  // an unreserved role passes at any level
  assert.equal(guardRoleEaa({ roleInput: { label: 'Barista' }, ral: 0 }).allowed, true);
});

test('RAL levels are well-formed and RAL0 never claims "verified"', () => {
  for (const k of [0, 1, 2]) {
    assert.ok(RAL_LEVELS[k]);
    assert.equal(RAL_LEVELS[k].ral, k);
  }
  assert.equal(RAL_LEVELS[0].badge.verifiedWording, false);
});

test('the reserved registry is well-formed', () => {
  assert.ok(Object.keys(RESERVED_REGISTRY).length > 0);
  for (const [key, def] of Object.entries(RESERVED_REGISTRY)) {
    assert.ok(def.label, `registry ${key}: label`);
    assert.ok(Array.isArray(def.iscoPrefixes) && def.iscoPrefixes.length, `registry ${key}: iscoPrefixes`);
    assert.ok(def.sourceHint, `registry ${key}: sourceHint`);
  }
});
