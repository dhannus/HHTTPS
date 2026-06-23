/**
 * HHTTPS Role Taxonomy & Assurance — v0.5 (ESCO-only, enum-free)
 *
 * CANONICAL LANGUAGE: English. German display strings live in
 * ./roles.taxonomy.i18n.js (one-way import).
 *
 * MODEL (v0.5, corrected): there is NO fixed list of professions. A role is
 * whatever (a) an EUDI (Q)EAA attests, or (b) the user defines and HHTTPS issues
 * as an iamhmn-card into the wallet. Occupations are resolved against ESCO at
 * runtime. The ONLY hard-coded role knowledge is the RESERVED_REGISTRY — the
 * small governance layer of professions that must not be freely self-declared.
 *
 * THE TWO ROLE PATHS (a closed loop):
 *   1. ISSUE  — user picks/defines a role (ESCO) + optionally uploads a document
 *               → HHTTPS issues an iamhmn-card EAA into the wallet with an honest
 *               RAL: 0 (self-declared) or 1 (document-checked).
 *   2. READ   — present any (Q)EAA (the iamhmn-card, or an external one such as
 *               an Ärztekammer attestation) → role + RAL is read back. An
 *               external qualified source is RAL2.
 *
 * RAL: 0 = self-declared · 1 = accredited (document / domain authority) ·
 *      2 = qualified eIDAS source (external (Q)EAA / PuB-EAA).
 *
 * RESERVED_REGISTRY — what it is and the case it governs:
 *   Some professions can cause real harm when impersonated (physician, lawyer,
 *   notary, police, nurse, judge). ESCO knows them as WORDS but not as RISKS.
 *   The registry is the credibility gate: a reserved profession may NOT be
 *   self-declared into an iamhmn-card at RAL0. It requires either a checked
 *   document (RAL1) or an external qualified (Q)EAA (RAL2). Non-reserved roles
 *   (developer, barista, drone choreographer …) are never blocked.
 *
 * CREDIBILITY: self-declared data is NEVER presented as verified. A free-text or
 * self-picked role tops out at RAL0/1; only a presented qualified attestation is
 * RAL2. ESCO URIs are NEVER fabricated — resolveEsco() fetches them live; ISCO-08
 * codes are provided only where unambiguous.
 */

// ─── Role Assurance Level (RAL) ───────────────────────────────────────────────
export const RAL_LEVELS = {
  0: { ral: 0, key: 'self-declared',
       label: 'Self-declared', short: 'self-declared',
       badge: { tone: 'neutral', icon: 'circle', verifiedWording: false },
       note: 'Role chosen by the user. Not checked by any authority.' },
  1: { ral: 1, key: 'accredited',
       label: 'Confirmed by an accredited authority (document/domain)', short: 'accredited',
       badge: { tone: 'info', icon: 'shield', verifiedWording: true },
       note: 'Backed by a checked document or a verified domain/account.' },
  2: { ral: 2, key: 'qualified',
       label: 'Confirmed by a qualified eIDAS source', short: 'qualified',
       badge: { tone: 'official', icon: 'seal', verifiedWording: true },
       note: 'Confirmed via EUDI Wallet (QEAA/PuB-EAA) from a qualified source.' }
};

// Methods that, when actually verified, count as a QUALIFIED (RAL2) source.
const RAL2_METHODS = new Set(['eudi-wallet-role', 'eudi-wallet', 'eudi', 'qeaa', 'pub-eaa']);
// Methods that count as RAL1 (accredited — real automated/document check).
const RAL1_METHODS = new Set(['document-checked', 'email-verified', 'github-verified',
  'domain-verified', 'school-email', 'official-email', 'medical-email', 'lawyer-email']);

/**
 * Derive the Role Assurance Level. Pure function.
 * @returns {0|1|2}
 */
export function deriveRAL({ verificationStatus, method } = {}) {
  if (method && RAL2_METHODS.has(method)) return 2;
  if (method && RAL1_METHODS.has(method)) return 1;
  if (verificationStatus === 'verified') return 1;
  return 0;
}

// ─── Reserved registry (governance layer) ─────────────────────────────────────
//
// The small, curated set of professions that may NOT be self-declared at RAL0.
// `iscoPrefixes` lets an incoming ESCO/ISCO occupation be recognised as reserved
// even when it arrives only as a code. `sourceHint` tells the UI which kind of
// authoritative source can legitimately attest it (RAL2).
export const RESERVED_REGISTRY = {
  medical: { label: 'Medical professional', iscoPrefixes: ['221', '2212', '2211'],
             sourceHint: 'Ärztekammer / medical chamber' },
  nursing: { label: 'Nurse / care professional', iscoPrefixes: ['2221', '3221', '532'],
             sourceHint: 'Pflegekammer / care chamber' },
  lawyer:  { label: 'Attorney', iscoPrefixes: ['2611'],
             sourceHint: 'Rechtsanwaltskammer / bar association' },
  notary:  { label: 'Notary', iscoPrefixes: ['2619', '261'],
             sourceHint: 'Notarkammer / notary chamber' },
  police:  { label: 'Police / law enforcement', iscoPrefixes: ['5412', '335'],
             sourceHint: 'state police authority' },
  judge:   { label: 'Judge / prosecutor', iscoPrefixes: ['2612'],
             sourceHint: 'state judicial authority' }
};

export const RESERVED_STEMS = [
  'arzt', 'aerztin', 'dr. med', 'dr.med', 'drmed', 'physician', 'doctor',
  'mediziner', 'chirurg', 'psychiater', 'approbation',
  'anwalt', 'anwaelt', 'attorney', 'lawyer', 'advokat',
  'notar', 'notary',
  'polizei', 'polizist', 'police', 'kriminalbeamt', 'staatsanwalt', 'prosecutor',
  'pfleger', 'pflegerin', 'pflegekraft', 'krankenpfleg', 'krankenschwester',
  'nurse', 'altenpfleg',
  'richter', 'judge'
];

function normalize(s) {
  return String(s || '').toLowerCase()
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/\s+/g, ' ').trim();
}

/**
 * Is this free-text label / ISCO code a reserved profession?
 * @returns {{ reserved:boolean, matched:string|null, key:string|null }}
 */
export function guardReservedRole(freeText, isco08 = null) {
  const n = normalize(freeText);
  if (n) {
    for (const stem of RESERVED_STEMS) {
      if (n.includes(stem)) return { reserved: true, matched: stem, key: stemToKey(stem) };
    }
  }
  if (isco08) {
    for (const [key, def] of Object.entries(RESERVED_REGISTRY)) {
      if (def.iscoPrefixes.some(p => String(isco08).startsWith(p))) {
        return { reserved: true, matched: isco08, key };
      }
    }
  }
  return { reserved: false, matched: null, key: null };
}

function stemToKey(stem) {
  if (/arzt|aerzt|med|physician|doctor|chirurg|psychiater|approbation/.test(stem)) return 'medical';
  if (/anwalt|anwaelt|attorney|lawyer|advokat/.test(stem)) return 'lawyer';
  if (/notar/.test(stem)) return 'notary';
  if (/polizei|polizist|police|kriminal|staatsanwalt|prosecutor/.test(stem)) return 'police';
  if (/pfleg|kranken|nurse/.test(stem)) return 'nursing';
  if (/richter|judge/.test(stem)) return 'judge';
  return null;
}

// ─── Custom (free-text) role sanitation ───────────────────────────────────────
export const CUSTOM_ROLE_ID = 'custom';
const CUSTOM_LABEL_MAX = 48;

export function sanitizeCustomRole(freeText) {
  let label = String(freeText || '')
    .replace(/[^\p{L}\p{N}\-./& ]/gu, '').replace(/\s+/g, ' ').trim().slice(0, CUSTOM_LABEL_MAX);
  if (!label) return { ok: false, label: null, reserved: false, matched: null, reason: 'empty' };
  const guard = guardReservedRole(label);
  if (guard.reserved) return { ok: false, label, reserved: true, matched: guard.matched, key: guard.key, reason: 'reserved' };
  return { ok: true, label, reserved: false, matched: null, reason: null };
}

// ─── ESCO resolver (runtime, never fabricated) ────────────────────────────────
export const ESCO_API = 'https://ec.europa.eu/esco/api/search';

export async function resolveEsco(text, { language = 'de', fetchImpl = globalThis.fetch } = {}) {
  if (!text || typeof fetchImpl !== 'function') return null;
  const url = `${ESCO_API}?type=occupation&language=${encodeURIComponent(language)}` +
              `&text=${encodeURIComponent(text)}&full=false&limit=1`;
  try {
    const r = await fetchImpl(url, { headers: { accept: 'application/json' } });
    if (!r.ok) return null;
    const j = await r.json();
    const hit = j?._embedded?.results?.[0];
    if (!hit?.uri) return null;
    return { escoUri: hit.uri, isco08: hit.code || null, prefLabel: hit.title || hit.preferredLabel || null };
  } catch { return null; }
}

// ─── Dynamic role resolver (replaces the old fixed 15-role table) ─────────────
//
// Given whatever we know about a role (a free-text label, an ESCO match, an ISCO
// code), return a normalized descriptor. No fixed enumeration — this is the
// ESCO-only core. `reserved`/`group` come from the governance registry.
/**
 * @param {object} input { label?, escoUri?, isco08?, esco?:{escoUri,isco08,prefLabel} }
 * @returns {{ id, label, kind, group, reserved, reservedKey, taxonomy }}
 */
export function resolveRole(input = {}) {
  const esco = input.esco || null;
  const escoUri = input.escoUri || esco?.escoUri || null;
  const isco08  = input.isco08  || esco?.isco08  || null;
  const label   = input.label   || esco?.prefLabel || 'Role';

  const guard = guardReservedRole(label, isco08);
  const id = slugify(label);

  let taxonomy = null;
  if (escoUri || isco08) {
    taxonomy = { scheme: escoUri ? 'ESCO' : 'ISCO-08', uri: escoUri || null, isco08: isco08 || null };
  }

  return {
    id,
    label,
    kind: 'occupation',                    // everything from ESCO is an occupation
    group: guard.reserved ? 'A' : 'B',     // reserved → authoritative source exists (Group A)
    reserved: guard.reserved,
    reservedKey: guard.key || null,
    taxonomy
  };
}

function slugify(s) {
  return normalize(s).replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40) || 'role';
}

// ─── Role claim builder ───────────────────────────────────────────────────────
/**
 * Build the role/ral claim block. Resolves the role descriptor dynamically.
 * @param {object} args
 * @param {object} [args.roleInput]            { label?, escoUri?, isco08?, esco? }
 * @param {boolean}[args.custom=false]         free-text custom role (forces RAL0)
 * @param {string} [args.customLabel]
 * @param {('verified'|'claimed'|'self-declared')} [args.verificationStatus]
 * @param {string} [args.method]
 * @param {boolean}[args.humanVerified=false]
 * @param {string} [args.authoritativeSource]
 * @returns {{ ral, role, verification? }}
 */
export function buildRoleClaim({
  roleInput = null, custom = false, customLabel = null,
  verificationStatus = 'self-declared', method = 'self-declared',
  humanVerified = false, authoritativeSource = null
} = {}) {
  let ral = deriveRAL({ verificationStatus, method });
  if (custom) ral = 0;  // a free-text custom role can NEVER exceed RAL0

  const desc = custom
    ? { id: CUSTOM_ROLE_ID, label: customLabel || 'Custom role', kind: 'occupation',
        group: 'B', reserved: false, reservedKey: null, taxonomy: null }
    : resolveRole(roleInput || {});

  const selfDeclared = ral === 0;

  const role = {
    id: desc.id,
    label: desc.label,
    self_declared: selfDeclared,
    human_verified: !!humanVerified,
    kind: desc.kind,
    group: desc.group,
    taxonomy: desc.taxonomy || null,
    ...(custom ? { custom: true } : {}),
    ...(desc.reserved ? { reserved: true } : {})
  };

  let verification = null;
  if (ral >= 1) {
    verification = {
      trust_framework: ral === 2 ? 'eidas' : 'hhttps',
      assurance_level: ral === 2 ? 'high' : 'substantial',
      evidence_type:   ral === 2 ? 'eudi' : (method === 'document-checked' ? 'document' : 'domain'),
      ...(authoritativeSource ? { authoritative_source: authoritativeSource } : {}),
      verified_at: new Date().toISOString().slice(0, 10)
    };
  }

  return { ral, role, ...(verification ? { verification } : {}) };
}

// ─── Discovery document (for /.well-known) ────────────────────────────────────
export function roleAssuranceDiscovery(rpId = 'hhttps.org') {
  return {
    issuer: `https://${rpId}`,
    spec: 'https://hhttps.org/docs/protocol/role-assurance',
    version: '0.5',
    model: 'esco-dynamic',
    ral_levels: Object.values(RAL_LEVELS).map(({ ral, key, label, note }) => ({ ral, key, label, note })),
    role_claim: {
      top_level_claims: ['ral'],
      role_object: ['id', 'label', 'self_declared', 'human_verified', 'kind', 'group', 'taxonomy', 'reserved'],
      verification_object: ['trust_framework', 'assurance_level', 'evidence_type', 'authoritative_source', 'verified_at'],
      taxonomy_schemes: ['ESCO', 'ISCO-08'],
      custom_role: { id: CUSTOM_ROLE_ID, max_label_len: CUSTOM_LABEL_MAX, always_ral: 0 }
    },
    reserved_registry: RESERVED_REGISTRY
  };
}
