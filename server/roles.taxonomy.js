/**
 * HHTTPS Role Taxonomy & Assurance — v0.5 (ESCO-only, enum-free)
 *
 * CANONICAL LANGUAGE: English. Labels are returned as ESCO supplies them for
 * the requested language (see searchEsco/resolveEsco) — there is no separate
 * translation catalogue for this module. (AP1-53, #204: roles.taxonomy.i18n.js
 * had no importer and translated `kind` values resolveRole never produces.)
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
  // AP1-06: concrete 4-digit codes only — a 3-digit prefix like '261' (all legal
  // professionals) or '335' (all regulatory associate professionals) swallowed
  // judges, tax inspectors and customs officers into the wrong registry key.
  notary:  { label: 'Notary', iscoPrefixes: ['2619'],
             sourceHint: 'Notarkammer / notary chamber' },
  police:  { label: 'Police / law enforcement', iscoPrefixes: ['5412', '3355'],
             sourceHint: 'state police authority' },
  judge:   { label: 'Judge / prosecutor', iscoPrefixes: ['2612'],
             sourceHint: 'state judicial authority' }
};

// AP1-06: stem → registry key, in ONE place (no second regex table that can
// drift). German compound stems match as substrings ("Fachärztin",
// "Rechtsanwältin", "Krankenpfleger"); English words match on word boundaries
// only ("nursery teacher" is not a nurse, "doctoral student" not a doctor).
// When several stems match, the LONGEST wins: "Staatsanwältin" → judge, not
// lawyer; "Notarzt" → medical, not notary.
const STEM_KEYS = {
  // medical
  arzt: 'medical', aerzt: 'medical', notarzt: 'medical', 'dr. med': 'medical', 'dr.med': 'medical',
  drmed: 'medical', mediziner: 'medical', chirurg: 'medical', psychiater: 'medical', approbation: 'medical',
  // lawyer
  anwalt: 'lawyer', anwaelt: 'lawyer', advokat: 'lawyer',
  // notary
  notar: 'notary',
  // police
  polizei: 'police', polizist: 'police', kriminalbeamt: 'police',
  // prosecutor — the registry key that covers it is "Judge / prosecutor"
  staatsanwalt: 'judge', staatsanwaelt: 'judge',
  // nursing
  pfleger: 'nursing', pflegerin: 'nursing', pflegekraft: 'nursing', krankenpfleg: 'nursing',
  krankenschwester: 'nursing', altenpfleg: 'nursing',
  // judge
  richter: 'judge'
};
const WORD_STEM_KEYS = {
  physician: 'medical', doctor: 'medical', attorney: 'lawyer', lawyer: 'lawyer', notary: 'notary',
  police: 'police', prosecutor: 'judge', nurse: 'nursing', judge: 'judge'
};
// Compounds that CONTAIN a reserved stem but are not reserved professions.
// They are blanked out before matching (whole word).
const NOT_RESERVED = ['tierpfleg', 'einrichter'];

export const RESERVED_STEMS = [...Object.keys(STEM_KEYS), ...Object.keys(WORD_STEM_KEYS)];

function normalize(s) {
  return String(s || '').toLowerCase()
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/\s+/g, ' ').trim();
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Longest reserved stem in a normalized label, or null. */
function matchStem(n) {
  let best = null;
  const consider = (stem, key) => { if (!best || stem.length > best.stem.length) best = { stem, key }; };
  for (const [stem, key] of Object.entries(STEM_KEYS)) {
    if (n.includes(stem)) consider(stem, key);
  }
  for (const [stem, key] of Object.entries(WORD_STEM_KEYS)) {
    if (new RegExp(`(^|[^a-z])${escapeRe(stem)}([^a-z]|$)`).test(n)) consider(stem, key);
  }
  return best;
}

/**
 * Is this free-text label / ISCO code a reserved profession?
 * @returns {{ reserved:boolean, matched:string|null, key:string|null }}
 */
export function guardReservedRole(freeText, isco08 = null) {
  let n = normalize(freeText);
  if (n) {
    for (const ex of NOT_RESERVED) n = n.replace(new RegExp(`(^|[^a-z])${ex}[a-z]*`, 'g'), '$1');
    const hit = matchStem(n);
    if (hit) return { reserved: true, matched: hit.stem, key: hit.key };
  }
  if (isco08) {
    // Longest registry prefix wins ('2212' over '221'); a code never matches a
    // prefix of another registry entry by accident because prefixes are concrete.
    const code = String(isco08);
    let best = null;
    for (const [key, def] of Object.entries(RESERVED_REGISTRY)) {
      for (const p of def.iscoPrefixes) {
        if (code.startsWith(p) && (!best || p.length > best.p.length)) best = { key, p };
      }
    }
    if (best) return { reserved: true, matched: isco08, key: best.key };
  }
  return { reserved: false, matched: null, key: null };
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

/**
 * AP1-46 (#176): the raw ESCO occupation search. server.js's typeahead proxy
 * used to build this URL and unwrap `_embedded.results` a second time by hand,
 * so the two copies could (and did) drift on limit, timeout and error handling.
 *
 * @param {string} text
 * @param {object} [opts]
 * @param {string}   [opts.language='de']
 * @param {number}   [opts.limit=1]
 * @param {number}   [opts.timeoutMs] abort the upstream call after N ms
 * @param {Function} [opts.fetchImpl]
 * @returns {Promise<Array<{escoUri:string|null, isco08:string|null, prefLabel:string}>>}
 *          [] on any failure — ESCO is a suggestion source, never a hard dependency.
 */
export async function searchEsco(text, { language = 'de', limit = 1, timeoutMs = null,
                                         fetchImpl = globalThis.fetch } = {}) {
  if (!text || typeof fetchImpl !== 'function') return [];
  const url = `${ESCO_API}?type=occupation&language=${encodeURIComponent(language)}` +
              `&text=${encodeURIComponent(text)}&full=false&limit=${encodeURIComponent(limit)}`;
  try {
    const init = { headers: { accept: 'application/json' } };
    if (timeoutMs) init.signal = AbortSignal.timeout(timeoutMs);
    const r = await fetchImpl(url, init);
    if (!r.ok) return [];
    const j = await r.json();
    const hits = j?._embedded?.results || [];
    return hits.map(h => ({
      escoUri:   h.uri || null,
      isco08:    h.code || null,
      prefLabel: h.title || h.preferredLabel || ''
    }));
  } catch { return []; }
}

/** Single best ESCO match, or null. Thin wrapper over {@link searchEsco}. */
export async function resolveEsco(text, opts = {}) {
  const [hit] = await searchEsco(text, { ...opts, limit: 1 });
  return hit?.escoUri ? hit : null;
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
