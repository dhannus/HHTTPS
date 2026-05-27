/**
 * HHTTPS Role Definitions — v4.1
 * 15 roles covering professional, public, educational, and basic citizenship.
 *
 * CANONICAL LANGUAGE: English.
 * This module is the protocol layer. Every human-readable string here is the
 * English canonical that the API serves and that is embedded into tokens.
 * User-facing translations (de, …) live in ./roles.i18n.js and never leak
 * into the protocol. Dependency direction is one-way: roles.i18n.js imports
 * from roles.js, never the reverse.
 *
 * Verification levels:
 *   self-declared        → 30 (baseline)
 *   webauthn             → 60 (cryptographic human proof)
 *   email-verified       → 65-78 (domain-based)
 *   institution-id       → 82-92 (membership/registry)
 *   official-email       → 90 (.bund.de etc.)
 *   bundestag-verified   → 98 (highest)
 */

export const ROLES = {

  // ─── Basic / Universal ─────────────────────────────────────────────────────

  citizen: {
    id: 'citizen', label: 'Citizen', icon: '🧑',
    description: 'Verified human with no specific professional role.',
    verificationMethods: ['self-declared', 'webauthn'],
    privileges: [
      'Participate in public debate as a verified human',
      "Protection against deepfake misuse of one's own identity",
      'Right to anonymous communication carrying an HHTTPS marker'
    ],
    userStory: 'US-001: As a citizen, I want to be able to prove that I am a human without revealing my identity.'
  },

  // ─── Media & Public Discourse ──────────────────────────────────────────────

  journalist: {
    id: 'journalist', label: 'Journalist', icon: '📰',
    description: 'Member of the press with journalistic privileges in the digital sphere.',
    verificationMethods: ['self-declared', 'press-card', 'email-verified'],
    verificationHints: {
      'press-card':     'Press-card number (DJV, dju, VDZ)',
      'email-verified': 'Editorial / newsroom email address'
    },
    privileges: [
      'Access to HHTTPS-protected press areas',
      'Verified attribution of sources in digital publications',
      'Protection against AI impersonation as a journalist'
    ],
    userStory: 'US-012: As a journalist, I want to be able to verify that my digital identity is not compromised by AI deepfakes.'
  },

  // ─── Education ─────────────────────────────────────────────────────────────

  student: {
    id: 'student', label: 'Student', icon: '🎓',
    description: 'Pupil or student at an educational institution.',
    verificationMethods: ['self-declared', 'email-verified', 'student-id'],
    verificationHints: {
      'email-verified': 'Educational email (.edu, .ac.de, uni-*, hs-*, fh-*)',
      'student-id':     'Matriculation number + institution'
    },
    privileges: [
      'Access to HHTTPS-protected educational platforms',
      'Verified participation in online examinations',
      'Protection against AI-generated exam answers submitted by peers'
    ],
    userStory: 'US-023: As a student, I want my online exam submissions to be unambiguously marked as originating from me.'
  },

  teacher: {
    id: 'teacher', label: 'Teacher', icon: '👨‍🏫',
    description: 'Schoolteacher or pedagogical professional.',
    verificationMethods: ['self-declared', 'school-email', 'teacher-id'],
    verificationHints: {
      'school-email': 'School email (.schule.[state].de, *.bbs.*)',
      'teacher-id':   'State-issued teacher ID'
    },
    privileges: [
      'Verified parent–teacher communication',
      'Authentic announcements, grades, and report cards',
      'Protection against fake teacher identities in school chats'
    ],
    userStory: 'US-089: As a teacher, I want parents to reliably recognise that a message genuinely comes from me — not from an AI in the school chat.'
  },

  // ─── Professionals: Knowledge & Creative ───────────────────────────────────

  researcher: {
    id: 'researcher', label: 'Researcher', icon: '🔬',
    description: 'Researcher, professor, or academic staff member.',
    verificationMethods: ['self-declared', 'email-verified', 'orcid'],
    verificationHints: {
      'email-verified': 'University email (.uni-*, .tu-*, .lmu.de, etc.)',
      'orcid':          'ORCID identifier (https://orcid.org/...)'
    },
    privileges: [
      'Verified authorship of academic publications',
      'HHTTPS proof for peer-review processes',
      'Protection of academic reputation against AI fakes'
    ],
    userStory: 'US-045: As a researcher, I want my publications to be unambiguously provable as authored by me.'
  },

  creative: {
    id: 'creative', label: 'Creative Professional', icon: '🎭',
    description: 'Artist, voice actor, author, musician, or other creative professional.',
    verificationMethods: ['self-declared', 'association-member', 'email-verified'],
    verificationHints: {
      'association-member': 'Membership number (VDS, BFFS, Die Gilde, BSD, GEMA, VG Wort)'
    },
    privileges: [
      "Protection of one's voice and face against unauthorised AI cloning",
      'Proof of human authorship for AI-like works',
      'Verified identity on creative platforms'
    ],
    userStory: 'US-034: As a voice actor, I want my voice not to be used for AI training without my consent.'
  },

  developer: {
    id: 'developer', label: 'Developer', icon: '💻',
    description: 'Software developer or technical professional.',
    verificationMethods: ['self-declared', 'github-verified', 'email-verified'],
    verificationHints: {
      'github-verified': 'GitHub account with commit history'
    },
    privileges: [
      'API access with raised rate limits',
      'Access to HHTTPS test environments',
      'Verified code authorship'
    ],
    userStory: 'US-056: As a developer, I want to integrate HHTTPS into my application and offer human verification to my users.'
  },

  // ─── Healthcare ────────────────────────────────────────────────────────────

  medical_professional: {
    id: 'medical_professional', label: 'Medical Professional', icon: '🩺',
    description: 'Licensed physician, dentist, veterinarian, or pharmacist.',
    verificationMethods: ['self-declared', 'approbation-id', 'medical-email'],
    verificationHints: {
      'approbation-id': 'Medical licence number (German Medical Association register)',
      'medical-email':  'Practice or clinic email address'
    },
    privileges: [
      'Verified medical information online',
      'Protection against fake physicians in patient forums and telemedicine',
      'Authentic telemedicine communication with patients'
    ],
    userStory: 'US-101: As a patient, I want to be sure that medical information online genuinely comes from a licensed physician — not from an AI or a layperson.'
  },

  caregiver: {
    id: 'caregiver', label: 'Care Professional', icon: '🤝',
    description: 'Certified care professional, geriatric nurse, registered nurse, or therapeutic professional.',
    verificationMethods: ['self-declared', 'care-chamber-id', 'email-verified'],
    verificationHints: {
      'care-chamber-id': 'Care-chamber membership number (NRW, Lower Saxony, RLP)',
      'email-verified':  'Clinic or care-facility email'
    },
    privileges: [
      'Verified communication with patients and relatives',
      'Protection against identity misuse on care platforms',
      'Authentic information on care levels, benefits, and therapies'
    ],
    userStory: 'US-102: As a caring relative, I want to reliably tell whether advice comes from genuine care staff — especially for vulnerable patients.'
  },

  // ─── Legal & Public Authority ──────────────────────────────────────────────

  lawyer: {
    id: 'lawyer', label: 'Attorney', icon: '⚖️',
    description: 'Admitted attorney-at-law.',
    verificationMethods: ['self-declared', 'bar-association-id', 'lawyer-email'],
    verificationHints: {
      'bar-association-id': 'Entry in the bar association register',
      'lawyer-email':       'Law-firm email address'
    },
    privileges: [
      'Verified legal advice in the digital sphere',
      "Protection against AI-generated pseudo-legal advice in one's own name",
      'Authentic client communication, attorney–client privilege made digital'
    ],
    userStory: 'US-103: As a client, I want to be sure that legal advice online comes from an admitted attorney — for life-changing legal questions.'
  },

  notary: {
    id: 'notary', label: 'Notary', icon: '📜',
    description: 'Appointed notary holding a public office.',
    verificationMethods: ['self-declared', 'notary-chamber-id'],
    verificationHints: {
      'notary-chamber-id': 'Entry in the notary chamber register'
    },
    privileges: [
      'Verified notarial information',
      'HHTTPS authentication for digital notarisation',
      'Highest trust level in matters of property law'
    ],
    userStory: 'US-104: As a citizen, I want to be sure during online notarisation that the notary is genuinely appointed and in office.'
  },

  civil_servant: {
    id: 'civil_servant', label: 'Civil Servant', icon: '🏛️',
    description: 'Civil servant, administrative staff member, or public authority (police, tax office, social services, etc.).',
    verificationMethods: ['self-declared', 'official-email', 'service-id'],
    verificationHints: {
      'official-email': 'Government email (.bund.de, [state].de)',
      'service-id':     'Service-ID number'
    },
    privileges: [
      'Verified authority communication against phishing',
      'Authentic notices, letters, and information',
      "Protection against AI-generated false notices in an authority's name"
    ],
    userStory: 'US-105: As a citizen, I want to recognise whether an email genuinely comes from the tax office or social services — not from a phishing bot with a deceptively real layout.'
  },

  politician: {
    id: 'politician', label: 'Politician', icon: '🗳️',
    description: 'Elected representative or political office holder.',
    verificationMethods: ['self-declared', 'official-email', 'bundestag-verified'],
    verificationHints: {
      'official-email':     'Official email (@bundestag.de, @landtag.*, @bundesregierung.de)',
      'bundestag-verified': 'Member-of-parliament ID (Bundestag.de profile)'
    },
    privileges: [
      'Verified political communication — no deepfake possible',
      "Protection against AI-generated false statements in one's own name",
      'Highest trust level on political discussion platforms'
    ],
    userStory: 'US-067: As a member of parliament, I want statements in my name to be unambiguously recognisable as authentic or as forgery.'
  },

  // ─── Business & Trades ─────────────────────────────────────────────────────

  business: {
    id: 'business', label: 'Business', icon: '🏢',
    description: 'Company representative or legal entity with a human point of contact.',
    verificationMethods: ['self-declared', 'domain-verified', 'handelsregister'],
    verificationHints: {
      'domain-verified': 'Company domain ownership',
      'handelsregister': 'Commercial-register number (HRB/HRA)'
    },
    privileges: [
      'Verified corporate communication',
      'HHTTPS certificate for websites ("genuine human point of contact")',
      "Protection against AI phishing in a company's name"
    ],
    userStory: 'US-078: As a business, I want to prove to my customers that communication comes from genuine employees.'
  },

  craftsman: {
    id: 'craftsman', label: 'Skilled Tradesperson', icon: '🔧',
    description: 'Master craftsperson, journeyman, or trade business.',
    verificationMethods: ['self-declared', 'craft-chamber-id', 'master-certificate'],
    verificationHints: {
      'craft-chamber-id':   'Entry in the trade register (chamber of skilled crafts)',
      'master-certificate': 'Master-craftsman certificate number'
    },
    privileges: [
      'Verified tradesperson identity on comparison portals',
      'Protection against fake reviews and identity theft',
      'Authentic quotes and invoices'
    ],
    userStory: 'US-106: As a customer, I want to tell on tradesperson platforms whether a provider is genuinely a registered master craftsperson — not a fake profile with stolen images.'
  }
};

// Verification level definitions with trust scores.
// `label` is the English canonical; German lives in roles.i18n.js.
export const VERIFICATION_LEVELS = {
  'self-declared':         { level: 1, label: 'Self-declared',              trustScore: 30 },
  'webauthn':              { level: 2, label: 'WebAuthn verified',          trustScore: 60 },
  'email-verified':        { level: 3, label: 'Email verified',             trustScore: 70 },
  'github-verified':       { level: 3, label: 'GitHub verified',            trustScore: 70 },
  'school-email':          { level: 3, label: 'School email',               trustScore: 75 },
  'medical-email':         { level: 3, label: 'Clinic/practice email',      trustScore: 78 },
  'lawyer-email':          { level: 3, label: 'Law-firm email',             trustScore: 78 },
  'press-card':            { level: 4, label: 'Press card',                 trustScore: 85 },
  'student-id':            { level: 4, label: 'Matriculation number',       trustScore: 85 },
  'teacher-id':            { level: 4, label: 'Teacher ID',                 trustScore: 86 },
  'association-member':    { level: 4, label: 'Association member',         trustScore: 85 },
  'orcid':                 { level: 4, label: 'ORCID verified',             trustScore: 88 },
  'craft-chamber-id':      { level: 4, label: 'Trade register',             trustScore: 86 },
  'master-certificate':    { level: 5, label: 'Master-craftsman certificate', trustScore: 90 },
  'care-chamber-id':       { level: 5, label: 'Care chamber',               trustScore: 90 },
  'bar-association-id':    { level: 5, label: 'Bar association',            trustScore: 92 },
  'notary-chamber-id':     { level: 5, label: 'Notary chamber',             trustScore: 95 },
  'approbation-id':        { level: 5, label: 'Medical licence number',     trustScore: 93 },
  'service-id':            { level: 5, label: 'Service ID',                 trustScore: 90 },
  'official-email':        { level: 5, label: 'Official email',             trustScore: 90 },
  'domain-verified':       { level: 4, label: 'Domain verified',            trustScore: 82 },
  'handelsregister':       { level: 5, label: 'Commercial register',        trustScore: 92 },
  'bundestag-verified':    { level: 6, label: 'Bundestag verified',         trustScore: 98 },
  'institution-verified':  { level: 5, label: 'Institution verified',       trustScore: 93 },
};

// ─── Verification check registry (honesty gate) ───────────────────────────────
//
// A method only grants its trustScore if it is BACKED BY A REAL, AUTOMATED CHECK.
// Methods that today are merely a typed-in number with NO verification against an
// authority MUST NOT raise trust — entering "any" medical-licence number cannot be
// worth more than a plain self-declaration. Until the real check exists, such a
// method is downgraded to self-declared (trust stays 30); the number is still
// recorded so we can verify it later, and the token marks it as 'claimed'.
//
// `implemented: true`  → a real automated check runs (OAuth, email link, format
//                        gate, domain classification). Grants the method's trust.
// `implemented: false` → no real check yet → BREAK: trust stays self-declared,
//                        method recorded as 'claimed', `targetTrust` documents
//                        the score it WILL grant once the check is built.
//
// `status` mirrors this in the token: 'verified' | 'claimed' | 'planned'.
// `note` is the English canonical; German lives in roles.i18n.js.
export const VERIFICATION_CHECKS = {
  // ── Really verified today (automated) ──
  'github-verified': { implemented: true,  status: 'verified', note: 'GitHub OAuth (api.github.com).' },
  'email-verified':  { implemented: true,  status: 'verified', note: 'Email link + domain classification.' },
  'school-email':    { implemented: true,  status: 'verified', note: 'Email link + domain classification.' },
  'medical-email':   { implemented: true,  status: 'verified', note: 'Email link + domain classification.' },
  'lawyer-email':    { implemented: true,  status: 'verified', note: 'Email link + domain classification.' },
  'official-email':  { implemented: true,  status: 'verified', note: 'Email link + domain classification.' },
  'domain-verified': { implemented: true,  status: 'verified', note: 'Domain classification.' },
  // ORCID: a real syntactic format gate runs (checksum-shaped regex). We treat
  // the format gate as a (weak) implemented check, but cap its trust low and
  // mark it 'claimed' because the ID is not confirmed against orcid.org.
  'orcid':           { implemented: true,  status: 'claimed',  cap: 55, note: 'Format only, not confirmed against orcid.org.' },

  // ── NOT verified today — typed-in only → BREAK (trust stays self-declared) ──
  // targetTrust = the score each will grant ONCE its real check is built.
  'press-card':         { implemented: false, status: 'claimed', targetTrust: 60, note: 'DJV/dju/VDZ check not yet connected.' },
  'student-id':         { implemented: false, status: 'claimed', targetTrust: 60, note: 'University check not yet connected.' },
  'teacher-id':         { implemented: false, status: 'claimed', targetTrust: 60, note: 'Education-authority check not yet connected.' },
  'association-member': { implemented: false, status: 'claimed', targetTrust: 60, note: 'Association check not yet connected.' },
  'craft-chamber-id':   { implemented: false, status: 'claimed', targetTrust: 62, note: 'Chamber-of-crafts check not yet connected.' },
  'master-certificate': { implemented: false, status: 'claimed', targetTrust: 62, note: 'Master-certificate check not yet connected.' },
  'care-chamber-id':    { implemented: false, status: 'claimed', targetTrust: 63, note: 'Care-chamber check not yet connected.' },
  'bar-association-id': { implemented: false, status: 'claimed', targetTrust: 65, note: 'Bar-association check not yet connected.' },
  'notary-chamber-id':  { implemented: false, status: 'claimed', targetTrust: 65, note: 'Notary-chamber check not yet connected.' },
  'approbation-id':     { implemented: false, status: 'claimed', targetTrust: 65, note: 'Medical-association check not yet connected.' },
  'service-id':         { implemented: false, status: 'claimed', targetTrust: 63, note: 'Service-ID check not yet connected.' },
  'handelsregister':    { implemented: false, status: 'claimed', targetTrust: 65, note: 'Commercial-register check not yet connected.' },
  'institution-verified':{ implemented: false, status: 'claimed', targetTrust: 63, note: 'Institution check not yet connected.' },
  'bundestag-verified': { implemented: false, status: 'claimed', targetTrust: 65, note: 'Bundestag check not yet connected.' },
};

// Helper: resolve the effective verification given a requested method.
// Returns { method, status, trustScore, note, downgraded }.
//   - real verified check  → keep method, grant its trust (or cap)
//   - unimplemented check   → BREAK: downgrade to self-declared, trust 30,
//                             status 'claimed', original method kept as claimedAs
export function resolveVerification(requestedMethod, baseTrust = 30) {
  const SELF = { method: 'self-declared', status: 'self-declared',
                 trustScore: VERIFICATION_LEVELS['self-declared'].trustScore };
  if (!requestedMethod || requestedMethod === 'self-declared') return { ...SELF, downgraded: false };

  const level = VERIFICATION_LEVELS[requestedMethod];
  const check = VERIFICATION_CHECKS[requestedMethod];
  if (!level || !check) return { ...SELF, downgraded: false };

  if (check.implemented) {
    const trust = check.cap ? Math.min(level.trustScore, check.cap) : level.trustScore;
    return { method: requestedMethod, status: check.status || 'verified',
             trustScore: trust, note: check.note, downgraded: false };
  }

  // BREAK — no real check yet. Trust stays self-declared; record what was claimed.
  return { method: 'self-declared', status: 'claimed',
           trustScore: VERIFICATION_LEVELS['self-declared'].trustScore,
           claimedAs: requestedMethod, targetTrust: check.targetTrust,
           note: check.note, downgraded: true };
}

// ─── Age groups (orthogonal claim, EUDI-aligned) ──────────────────────────────
//
// age_group is INDEPENDENT of the role: a person can be both a
// medical_professional AND adult_18_plus. It mirrors the EUDI Wallet's
// age_over_NN selective-disclosure model, so Phase 3 (real EUDI verification)
// only needs to flip the verification method + trust — no schema change.
//
// The four groups map to German legal thresholds:
//   minor_under_14  — JuSchG "child"
//   minor_14_to_15  — criminally responsible (§19 StGB), JuSchG "youth"
//   minor_16_to_17  — GDPR-consent-capable (Art. 8), limited legal capacity
//   adult_18_plus   — of full age (§2 BGB)
//
// `label`/`note` are the English canonical; German lives in roles.i18n.js.
export const AGE_GROUPS = {
  minor_under_14: {
    id: 'minor_under_14', label: 'Child (under 14)',
    icon: '🧒', minAge: 0, maxAge: 13,
    // EUDI age_over_NN booleans that characterise this group (all false here)
    eudiClaims: { age_over_14: false, age_over_16: false, age_over_18: false },
    note: 'JuSchG: child. Special protection.'
  },
  minor_14_to_15: {
    id: 'minor_14_to_15', label: 'Youth (14–15)',
    icon: '🧑', minAge: 14, maxAge: 15,
    eudiClaims: { age_over_14: true, age_over_16: false, age_over_18: false },
    note: 'Criminally responsible (§19 StGB), JuSchG: youth.'
  },
  minor_16_to_17: {
    id: 'minor_16_to_17', label: 'Youth (16–17)',
    icon: '🧑', minAge: 16, maxAge: 17,
    eudiClaims: { age_over_14: true, age_over_16: true, age_over_18: false },
    note: 'GDPR Art. 8 consent-capable, limited legal capacity.'
  },
  adult_18_plus: {
    id: 'adult_18_plus', label: 'Adult (18+)',
    icon: '🧑', minAge: 18, maxAge: null,
    eudiClaims: { age_over_14: true, age_over_16: true, age_over_18: true },
    note: 'Of full age (§2 BGB).'
  },
};

// How an age_group was established. Phase 1 ships only self-declared (honest,
// low trust). Phase 3 adds eudi-wallet once the OpenID4VP verifier is wired up.
//   self-declared → age_verified:false, trust 30 (self-declared)
//   eudi-wallet   → age_verified:true,  trust 99 (PID selective disclosure)  [planned]
//
// `label`/`note` are the English canonical; German lives in roles.i18n.js.
export const AGE_VERIFICATION_METHODS = {
  'self-declared': {
    id: 'self-declared', label: 'Self-declared',
    verified: false, trustScore: 30, available: true,
    note: 'Self-declared, not yet cryptographically verified.'
  },
  'eudi-wallet': {
    id: 'eudi-wallet', label: 'EUDI Wallet (PID)',
    verified: true, trustScore: 99, available: false,  // Phase 3
    note: 'Age proof via EUDI Wallet (age_over_NN, selective disclosure). Planned.'
  },
};

// ─── Phase 3 bridge: EUDI age_over_NN booleans → age_group (reverse mapping) ──
//
// Phase 1 stored, per band, the EUDI age_over_NN booleans in AGE_GROUPS[x].eudiClaims.
// Phase 3 reads them BACKWARDS: given what an EUDI Wallet disclosed via OpenID4VP
// (a subset of age_over_14 / age_over_16 / age_over_18), pick the narrowest band
// that matches. This is the ONLY new logic age verification needs in roles.js —
// no token-format change, exactly the upgrade path Phase 1 documented.
//
// Selective disclosure: a verifier may request only the minimal boolean it needs
// (e.g. just age_over_16 for a 16+ gate). Undisclosed booleans are treated as
// "not proven" (false). A child therefore proves "under 16" without revealing an
// exact age or date of birth — the youth-protection win.
//
// Input:  { age_over_14?, age_over_16?, age_over_18? }  (any subset; missing = false)
// Output: 'adult_18_plus' | 'minor_16_to_17' | 'minor_14_to_15' | 'minor_under_14'
export function ageGroupFromEudiClaims(claims = {}) {
  const c = (claims && typeof claims === 'object') ? claims : {};
  const over = (k) => c[k] === true;        // missing / non-true ⇒ not proven
  if (over('age_over_18')) return 'adult_18_plus';
  if (over('age_over_16')) return 'minor_16_to_17';
  if (over('age_over_14')) return 'minor_14_to_15';
  return 'minor_under_14';
}
