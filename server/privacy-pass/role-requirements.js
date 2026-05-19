/**
 * Role verification requirements
 *
 * Defines per role:
 *   - required: methods that MUST be completed before any token issuance
 *   - optional: methods that boost trust score but are not gating
 *   - emailDomainPattern: regex hint for which email domains qualify for
 *     the role-specific email verification method
 *
 * Universal rule across all roles: webauthn is implicit (always required,
 * the user could not get here without it) plus email-verified is always
 * required for first-time issuance on a given credential. This matches the
 * user's wish: "Pflicht Email für alle beim 1. Mal in Verbindung mit dem Gerät".
 *
 * Strong roles (medical_professional, lawyer, notary, civil_servant,
 * politician, business) require BOTH email-verified AND a domain match or
 * stronger institutional attribute.
 */

import { ROLES, VERIFICATION_LEVELS } from '../roles.js';

// Per-role gating: { required: [methods], optional: [methods], emailDomainPattern? }
export const ROLE_REQUIREMENTS = {
  citizen: {
    required: ['webauthn', 'email-verified'],
    optional: [],
  },
  journalist: {
    required: ['webauthn', 'email-verified'],
    optional: ['press-card'],
  },
  student: {
    required: ['webauthn', 'email-verified'],
    optional: ['student-id'],
    emailDomainPattern: /(^|\.)(uni-[\w-]+\.de|hs-[\w-]+\.de|fh-[\w-]+\.de|tu-[\w-]+\.de|tum\.de|lmu\.de|ac\.[a-z]{2})$|\.edu$/i,
    emailDomainHint:    'Universitäts-/Hochschul-E-Mail (.uni-*, .tu-*, .hs-*, .ac.de, .edu)',
  },
  teacher: {
    required: ['webauthn', 'email-verified'],
    optional: ['teacher-id'],
    emailDomainPattern: /(^|\.)(schule\.[\w-]+\.de|bbs\.[\w-]+\.de|bildung\.[\w-]+\.de|schule\.[\w-]+|gymnasium\.[\w-]+\.de)$|\.edu$/i,
    emailDomainHint:    'Schul-E-Mail (.schule.[bundesland].de, .bbs.*, .bildung.*)',
  },
  researcher: {
    required: ['webauthn', 'email-verified'],
    optional: ['orcid'],
    emailDomainPattern: /(^|\.)(uni-[\w-]+\.de|tu-[\w-]+\.de|tum\.de|lmu\.de|mpg\.de|fraunhofer\.de|dlr\.de|helmholtz\.de|leibniz\.de|hpi\.de|dfki\.de|cispa\.de|ac\.[a-z]{2})$|\.edu$/i,
    emailDomainHint:    'Universitäts-/Institutions-E-Mail (.uni-*, .tu-*, .mpg.de, .fraunhofer.de, .dlr.de, .helmholtz.de, .leibniz.de, .edu)',
  },
  creative: {
    required: ['webauthn', 'email-verified'],
    optional: ['association-member'],
  },
  developer: {
    required: ['webauthn', 'email-verified'],
    optional: ['github-verified'],
  },
  medical_professional: {
    required: ['webauthn', 'email-verified', 'approbation-id'],
    optional: [],
    emailDomainPattern: /(^|\.)(charite\.de|klinik[\w-]*\.|klinikum[\w-]*\.|praxis[\w-]*\.|aerzte[\w-]*\.|kassenaerztliche|medi-|krankenhaus[\w-]*\.|uk-[\w-]+\.de|universitaetsklinikum)/i,
    emailDomainHint:    'Klinik-, Praxis- oder Universitätsklinikum-Domain',
    strict: true,
    strictReason: 'Medizinische Berufsidentität erfordert eine Approbations-Bestätigung. Ohne Approbations-Nummer können keine Tokens für diese Rolle ausgestellt werden.',
  },
  caregiver: {
    required: ['webauthn', 'email-verified'],
    optional: ['care-chamber-id'],
    emailDomainPattern: /(klinik[\w-]*\.|pflege[\w-]*\.|caritas|diakonie|drk|asb-|johanniter|malteser)/i,
    emailDomainHint:    'Klinik-, Pflege- oder Wohlfahrts-E-Mail',
  },
  lawyer: {
    required: ['webauthn', 'email-verified', 'bar-association-id'],
    optional: [],
    emailDomainPattern: /(rechtsanwalt|kanzlei|anwalt|brak\.de|notar)/i,
    emailDomainHint:    'Kanzlei- oder Anwaltskammer-E-Mail',
    strict: true,
    strictReason: 'Anwaltliche Identität erfordert einen Eintrag in der Rechtsanwaltskammer.',
  },
  notary: {
    required: ['webauthn', 'email-verified', 'notary-chamber-id'],
    optional: [],
    strict: true,
    strictReason: 'Notar:innen-Identität erfordert einen Eintrag in der Notarkammer — das öffentliche Amt verlangt die höchste Vertrauensstufe.',
  },
  civil_servant: {
    required: ['webauthn', 'email-verified'],
    optional: ['service-id'],
    emailDomainPattern: /(^|\.)(bund\.de|bayern\.de|berlin\.de|hamburg\.de|nrw\.de|baden-wuerttemberg\.de|niedersachsen\.de|hessen\.de|rlp\.de|sachsen\.de|thueringen\.de|brandenburg\.de|saarland\.de|sh\.de|mv-regierung\.de|bremen\.de)$|(polizei|finanzamt|zoll|verwaltung|kommune)/i,
    emailDomainHint:    'Behörden-E-Mail (.bund.de, [bundesland].de, polizei.*, finanzamt.*)',
    strict: true,
    strictReason: 'Verwaltungsidentität erfordert eine offizielle Behörden-E-Mail-Adresse.',
  },
  politician: {
    required: ['webauthn', 'email-verified'],
    optional: ['bundestag-verified'],
    emailDomainPattern: /(^|\.)(bundestag\.de|bundesrat\.de|bundesregierung\.de|landtag\.[\w-]+\.de|abgeordnete[\w.-]*)$/i,
    emailDomainHint:    'Offizielle Mandatsträger-E-Mail (@bundestag.de, @landtag.*, @bundesregierung.de)',
    strict: true,
    strictReason: 'Politische Mandatsträger-Identität erfordert eine offizielle Parlaments- oder Regierungs-E-Mail.',
  },
  business: {
    required: ['webauthn', 'email-verified'],
    optional: ['domain-verified', 'handelsregister'],
  },
  craftsman: {
    required: ['webauthn', 'email-verified'],
    optional: ['craft-chamber-id', 'master-certificate'],
  },
};

/**
 * Compute the trust score for a credential+role based on completed methods.
 * Uses the VERIFICATION_LEVELS table from roles.js for actual scoring.
 */
export function computeTrustScore(completedMethods) {
  if (!completedMethods || completedMethods.length === 0) return 0;
  let max = 0;
  for (const m of completedMethods) {
    const def = VERIFICATION_LEVELS[m];
    if (def && def.trustScore > max) max = def.trustScore;
  }
  return max;
}

/**
 * Check whether a credential is eligible for token issuance under a role.
 * Returns { ok: true, trustScore } on success or { ok: false, missing, reason }.
 */
export function checkEligibility(role, completedMethods) {
  const req = ROLE_REQUIREMENTS[role];
  if (!req) {
    return { ok: false, missing: [], reason: `Unknown role: ${role}` };
  }
  const missing = req.required.filter(m => !completedMethods.includes(m));
  if (missing.length > 0) {
    return {
      ok: false,
      missing,
      strict: req.strict || false,
      reason: req.strictReason || `Fehlend: ${missing.join(', ')}`,
    };
  }
  return { ok: true, trustScore: computeTrustScore(completedMethods) };
}

/**
 * Validate that an email domain matches the role's expected pattern.
 * Returns true if the role has no pattern (no constraint), or the domain matches.
 */
export function emailDomainMatchesRole(email, role) {
  const req = ROLE_REQUIREMENTS[role];
  if (!req?.emailDomainPattern) return true;
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  const domain = email.slice(at + 1).toLowerCase();
  return req.emailDomainPattern.test(domain);
}
