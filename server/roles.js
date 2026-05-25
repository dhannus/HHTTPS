/**
 * HHTTPS Role Definitions — v4.1
 * 14 roles covering professional, public, educational, and basic citizenship
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
    id: 'citizen', label: 'Bürger', labelEn: 'Citizen', icon: '🧑',
    description: 'Verifizierter Mensch ohne spezifische Berufsrolle.',
    verificationMethods: ['self-declared', 'webauthn'],
    privileges: [
      'Teilnahme an öffentlichen Debatten als verifizierter Mensch',
      'Schutz vor Deepfake-Missbrauch der eigenen Identität',
      'Recht auf anonyme Kommunikation mit HHTTPS-Kennzeichnung'
    ],
    userStory: 'US-001: Als Bürger möchte ich beweisen können, dass ich ein Mensch bin, ohne meine Identität preiszugeben.'
  },

  // ─── Media & Public Discourse ──────────────────────────────────────────────

  journalist: {
    id: 'journalist', label: 'Journalist', labelEn: 'Journalist', icon: '📰',
    description: 'Pressevertreter mit journalistischen Privilegien im digitalen Raum.',
    verificationMethods: ['self-declared', 'press-card', 'email-verified'],
    verificationHints: {
      'press-card':    'Presseausweis-Nummer (DJV, dju, VDZ)',
      'email-verified': 'Redaktions-E-Mail-Adresse'
    },
    privileges: [
      'Zugang zu HHTTPS-geschützten Pressebereichen',
      'Verifizierte Quellenangabe in digitalen Publikationen',
      'Schutz vor Identitätsmissbrauch als Journalist durch KI'
    ],
    userStory: 'US-012: Als Journalist möchte ich verifizieren können, dass meine digitale Identität nicht durch KI-Deepfakes kompromittiert wird.'
  },

  // ─── Education ─────────────────────────────────────────────────────────────

  student: {
    id: 'student', label: 'Schüler / Student', labelEn: 'Student', icon: '🎓',
    description: 'Schüler oder Student an einer Bildungseinrichtung.',
    verificationMethods: ['self-declared', 'email-verified', 'student-id'],
    verificationHints: {
      'email-verified': 'Bildungs-E-Mail (.edu, .ac.de, uni-*, hs-*, fh-*)',
      'student-id':     'Matrikelnummer + Institution'
    },
    privileges: [
      'Zugang zu HHTTPS-geschützten Bildungsplattformen',
      'Verifizierte Teilnahme an Online-Prüfungen',
      'Schutz vor KI-generierten Prüfungsantworten durch Peers'
    ],
    userStory: 'US-023: Als Schüler möchte ich, dass meine Online-Prüfungsleistungen eindeutig als von mir stammend gekennzeichnet sind.'
  },

  teacher: {
    id: 'teacher', label: 'Lehrer / Pädagoge', labelEn: 'Teacher', icon: '👨‍🏫',
    description: 'Lehrkraft an Schule oder pädagogische Fachkraft.',
    verificationMethods: ['self-declared', 'school-email', 'teacher-id'],
    verificationHints: {
      'school-email': 'Schul-E-Mail (.schule.[bundesland].de, *.bbs.*)',
      'teacher-id':   'Lehrer-ID des Bundeslandes'
    },
    privileges: [
      'Verifizierte Eltern-Lehrer-Kommunikation',
      'Authentische Bekanntmachungen, Noten, Zeugnisse',
      'Schutz vor Fake-Lehrer-Identitäten in Schulchats'
    ],
    userStory: 'US-089: Als Lehrer möchte ich, dass Eltern verlässlich erkennen können, dass eine Nachricht tatsächlich von mir stammt — nicht von einer KI im Schulchat.'
  },

  // ─── Professionals: Knowledge & Creative ───────────────────────────────────

  researcher: {
    id: 'researcher', label: 'Wissenschaftler', labelEn: 'Researcher', icon: '🔬',
    description: 'Forscher, Professor oder wissenschaftlicher Mitarbeiter.',
    verificationMethods: ['self-declared', 'email-verified', 'orcid'],
    verificationHints: {
      'email-verified': 'Universitäts-E-Mail (.uni-*, .tu-*, .lmu.de, etc.)',
      'orcid':          'ORCID-Kennung (https://orcid.org/...)'
    },
    privileges: [
      'Verifizierte Autorenschaft wissenschaftlicher Publikationen',
      'HHTTPS-Nachweis für Peer-Review-Prozesse',
      'Schutz wissenschaftlicher Reputation vor KI-Fakes'
    ],
    userStory: 'US-045: Als Forscher möchte ich, dass meine Publikationen eindeutig als von mir verfasst nachweisbar sind.'
  },

  creative: {
    id: 'creative', label: 'Kreativschaffender', labelEn: 'Creative Professional', icon: '🎭',
    description: 'Künstler, Synchronsprecher, Autor, Musiker oder anderer Kreativschaffender.',
    verificationMethods: ['self-declared', 'association-member', 'email-verified'],
    verificationHints: {
      'association-member': 'Mitgliedsnummer VDS, BFFS, Die Gilde, BSD, GEMA, VG Wort'
    },
    privileges: [
      'Schutz der Stimme und des Gesichts vor unbefugtem KI-Klonen',
      'Nachweis menschlicher Urheberschaft bei KI-ähnlichen Werken',
      'Verifizierte Identität in Kreativplattformen'
    ],
    userStory: 'US-034: Als Synchronsprecherin möchte ich, dass meine Stimme nicht ohne meine Einwilligung für KI-Training verwendet wird.'
  },

  developer: {
    id: 'developer', label: 'Entwickler', labelEn: 'Developer', icon: '💻',
    description: 'Software-Entwickler oder technischer Fachmann.',
    verificationMethods: ['self-declared', 'github-verified', 'email-verified'],
    verificationHints: {
      'github-verified': 'GitHub-Account mit Commit-History'
    },
    privileges: [
      'API-Zugang mit erhöhten Rate-Limits',
      'Zugang zu HHTTPS-Testumgebungen',
      'Verifizierte Code-Autorenschaft'
    ],
    userStory: 'US-056: Als Entwickler möchte ich HHTTPS in meine Anwendung integrieren und meinen Nutzern menschliche Verifikation anbieten.'
  },

  // ─── Healthcare ────────────────────────────────────────────────────────────

  medical_professional: {
    id: 'medical_professional', label: 'Arzt / Medizinerin', labelEn: 'Medical Professional', icon: '🩺',
    description: 'Approbierter Arzt oder Ärztin, Zahnarzt, Tierarzt oder Apotheker.',
    verificationMethods: ['self-declared', 'approbation-id', 'medical-email'],
    verificationHints: {
      'approbation-id': 'Approbationsnummer (Bundesärztekammer-Eintrag)',
      'medical-email':  'Praxis- oder Klinik-E-Mail-Adresse'
    },
    privileges: [
      'Verifizierte medizinische Auskünfte im Netz',
      'Schutz vor Fake-Ärzten in Patientenforen und Telemedizin',
      'Authentische Telemedizin-Kommunikation mit Patienten'
    ],
    userStory: 'US-101: Als Patient möchte ich sicher sein, dass medizinische Auskünfte online tatsächlich von einem approbierten Arzt stammen — nicht von einer KI oder einem Laien.'
  },

  caregiver: {
    id: 'caregiver', label: 'Pflegekraft', labelEn: 'Care Professional', icon: '🤝',
    description: 'Examinierte Pflegekraft, Altenpfleger, Krankenpfleger oder therapeutische Fachkraft.',
    verificationMethods: ['self-declared', 'care-chamber-id', 'email-verified'],
    verificationHints: {
      'care-chamber-id': 'Mitgliedsnummer Pflegekammer (NRW, Nds, RLP)',
      'email-verified':  'Klinik- oder Pflegeeinrichtungs-E-Mail'
    },
    privileges: [
      'Verifizierte Kommunikation mit Patienten und Angehörigen',
      'Schutz vor Identitätsmissbrauch in Pflegeplattformen',
      'Authentische Auskünfte zu Pflegegrad, Leistungen, Therapien'
    ],
    userStory: 'US-102: Als pflegende Angehörige möchte ich verlässlich erkennen können, ob Beratung von echtem Pflegepersonal stammt — gerade bei vulnerablen Patienten.'
  },

  // ─── Legal & Public Authority ──────────────────────────────────────────────

  lawyer: {
    id: 'lawyer', label: 'Anwalt / Anwältin', labelEn: 'Attorney', icon: '⚖️',
    description: 'Zugelassene Rechtsanwältin oder Rechtsanwalt.',
    verificationMethods: ['self-declared', 'bar-association-id', 'lawyer-email'],
    verificationHints: {
      'bar-association-id': 'Eintrag in der Rechtsanwaltskammer',
      'lawyer-email':       'Kanzlei-E-Mail-Adresse'
    },
    privileges: [
      'Verifizierte Rechtsberatung im digitalen Raum',
      'Schutz vor KI-generierter Pseudo-Rechtsberatung in eigenem Namen',
      'Authentische Mandantenkommunikation, anwaltliche Schweigepflicht digital'
    ],
    userStory: 'US-103: Als Mandant möchte ich sicher sein, dass eine Rechtsauskunft online von einer zugelassenen Anwältin stammt — bei lebensverändernden Rechtsfragen.'
  },

  notary: {
    id: 'notary', label: 'Notar', labelEn: 'Notary', icon: '📜',
    description: 'Bestellter Notar als Träger eines öffentlichen Amtes.',
    verificationMethods: ['self-declared', 'notary-chamber-id'],
    verificationHints: {
      'notary-chamber-id': 'Eintrag in der Notarkammer'
    },
    privileges: [
      'Verifizierte notarielle Auskünfte',
      'HHTTPS-Authentifizierung bei digitaler Beurkundung',
      'Höchste Vertrauensstufe in vermögensrechtlichen Angelegenheiten'
    ],
    userStory: 'US-104: Als Bürger möchte ich bei Online-Beurkundungen sicher sein, dass der Notar tatsächlich bestellt und im Amt ist.'
  },

  civil_servant: {
    id: 'civil_servant', label: 'Beamte / Behörde', labelEn: 'Civil Servant', icon: '🏛️',
    description: 'Beamtin oder Beamter, Verwaltungsmitarbeiter oder Hoheitsträger (Polizei, Finanzamt, Sozialamt etc.).',
    verificationMethods: ['self-declared', 'official-email', 'service-id'],
    verificationHints: {
      'official-email': 'Behörden-E-Mail (.bund.de, [bundesland].de)',
      'service-id':     'Dienstausweisnummer'
    },
    privileges: [
      'Verifizierte Behördenkommunikation gegen Phishing',
      'Authentische Bescheide, Anschreiben, Auskünfte',
      'Schutz vor KI-generierten Falschbescheiden im Namen einer Behörde'
    ],
    userStory: 'US-105: Als Bürger möchte ich erkennen können, ob eine E-Mail wirklich vom Finanzamt oder Sozialamt stammt — nicht von einem Phishing-Bot mit täuschend echtem Layout.'
  },

  politician: {
    id: 'politician', label: 'Politiker / Mandatsträger', labelEn: 'Politician', icon: '🗳️',
    description: 'Gewählter Mandatsträger oder politischer Amtsinhaber.',
    verificationMethods: ['self-declared', 'official-email', 'bundestag-verified'],
    verificationHints: {
      'official-email':     'Offizielle E-Mail (@bundestag.de, @landtag.*, @bundesregierung.de)',
      'bundestag-verified': 'Abgeordneten-ID (Bundestag.de-Profil)'
    },
    privileges: [
      'Verifizierte politische Kommunikation — kein Deepfake möglich',
      'Schutz vor KI-generierten Falschaussagen in eigenem Namen',
      'Höchste Vertrauensstufe in politischen Diskussionsplattformen'
    ],
    userStory: 'US-067: Als Bundestagsabgeordnete möchte ich, dass Aussagen in meinem Namen eindeutig als authentisch oder als Fälschung erkennbar sind.'
  },

  // ─── Business & Trades ─────────────────────────────────────────────────────

  business: {
    id: 'business', label: 'Unternehmen', labelEn: 'Business', icon: '🏢',
    description: 'Unternehmensvertreter oder juristische Person mit menschlichem Ansprechpartner.',
    verificationMethods: ['self-declared', 'domain-verified', 'handelsregister'],
    verificationHints: {
      'domain-verified':  'Firmen-Domain-Inhaberschaft',
      'handelsregister':  'Handelsregisternummer (HRB/HRA)'
    },
    privileges: [
      'Verifizierte Unternehmenskommunikation',
      'HHTTPS-Zertifikat für Websites ("Echter menschlicher Ansprechpartner")',
      'Schutz vor KI-Phishing in Unternehmensnamen'
    ],
    userStory: 'US-078: Als Unternehmen möchte ich meinen Kunden gegenüber nachweisen, dass Kommunikation von echten Mitarbeitern stammt.'
  },

  craftsman: {
    id: 'craftsman', label: 'Handwerker / Meister', labelEn: 'Skilled Tradesperson', icon: '🔧',
    description: 'Handwerksmeister, Geselle oder Handwerksbetrieb.',
    verificationMethods: ['self-declared', 'craft-chamber-id', 'master-certificate'],
    verificationHints: {
      'craft-chamber-id':    'Eintrag in der Handwerksrolle (Handwerkskammer)',
      'master-certificate':  'Meisterbrief-Nummer'
    },
    privileges: [
      'Verifizierte Handwerker-Identität in Vergleichsportalen',
      'Schutz vor Fake-Bewertungen und Identitätsdiebstahl',
      'Authentische Angebote und Rechnungen'
    ],
    userStory: 'US-106: Als Kunde möchte ich auf Handwerker-Plattformen erkennen können, ob ein Anbieter wirklich ein eingetragener Meister ist — nicht ein Fake-Profil mit gestohlenen Bildern.'
  }
};

// Verification level definitions with trust scores
export const VERIFICATION_LEVELS = {
  'self-declared':         { level: 1, label: 'Selbstdeklariert',         trustScore: 30 },
  'webauthn':              { level: 2, label: 'WebAuthn verifiziert',     trustScore: 60 },
  'email-verified':        { level: 3, label: 'E-Mail verifiziert',       trustScore: 70 },
  'github-verified':       { level: 3, label: 'GitHub verifiziert',       trustScore: 70 },
  'school-email':          { level: 3, label: 'Schul-E-Mail',             trustScore: 75 },
  'medical-email':         { level: 3, label: 'Klinik-/Praxis-E-Mail',    trustScore: 78 },
  'lawyer-email':          { level: 3, label: 'Kanzlei-E-Mail',           trustScore: 78 },
  'press-card':            { level: 4, label: 'Presseausweis',            trustScore: 85 },
  'student-id':            { level: 4, label: 'Matrikelnummer',           trustScore: 85 },
  'teacher-id':            { level: 4, label: 'Lehrer-ID',                trustScore: 86 },
  'association-member':    { level: 4, label: 'Verbandsmitglied',         trustScore: 85 },
  'orcid':                 { level: 4, label: 'ORCID verifiziert',        trustScore: 88 },
  'craft-chamber-id':      { level: 4, label: 'Handwerksrolle',           trustScore: 86 },
  'master-certificate':    { level: 5, label: 'Meisterbrief',             trustScore: 90 },
  'care-chamber-id':       { level: 5, label: 'Pflegekammer',             trustScore: 90 },
  'bar-association-id':    { level: 5, label: 'Rechtsanwaltskammer',      trustScore: 92 },
  'notary-chamber-id':     { level: 5, label: 'Notarkammer',              trustScore: 95 },
  'approbation-id':        { level: 5, label: 'Approbationsnummer',       trustScore: 93 },
  'service-id':            { level: 5, label: 'Dienstausweis',            trustScore: 90 },
  'official-email':        { level: 5, label: 'Offizielle E-Mail',        trustScore: 90 },
  'domain-verified':       { level: 4, label: 'Domain verifiziert',       trustScore: 82 },
  'handelsregister':       { level: 5, label: 'Handelsregister',          trustScore: 92 },
  'bundestag-verified':    { level: 6, label: 'Bundestag verifiziert',    trustScore: 98 },
  'institution-verified':  { level: 5, label: 'Institution verifiziert',  trustScore: 93 },
};

// ─── Age groups (orthogonal claim, EUDI-aligned) ──────────────────────────────
//
// age_group is INDEPENDENT of the role: a person can be both a
// medical_professional AND adult_18_plus. It mirrors the EUDI Wallet's
// age_over_NN selective-disclosure model, so Phase 3 (real EUDI verification)
// only needs to flip the verification method + trust — no schema change.
//
// The four groups map to German legal thresholds:
//   minor_under_14  — JuSchG "Kind"
//   minor_14_to_15  — strafmündig (§19 StGB), JuSchG "Jugendlicher"
//   minor_16_to_17  — DSGVO-einwilligungsfähig (Art. 8), eingeschränkt geschäftsfähig
//   adult_18_plus   — volljährig (§2 BGB)
export const AGE_GROUPS = {
  minor_under_14: {
    id: 'minor_under_14', label: 'Kind (unter 14)', labelEn: 'Child (under 14)',
    icon: '🧒', minAge: 0, maxAge: 13,
    // EUDI age_over_NN booleans that characterise this group (all false here)
    eudiClaims: { age_over_14: false, age_over_16: false, age_over_18: false },
    note: 'JuSchG: Kind. Besonderer Schutz.'
  },
  minor_14_to_15: {
    id: 'minor_14_to_15', label: 'Jugendlich (14–15)', labelEn: 'Youth (14–15)',
    icon: '🧑', minAge: 14, maxAge: 15,
    eudiClaims: { age_over_14: true, age_over_16: false, age_over_18: false },
    note: 'Strafmündig (§19 StGB), JuSchG: Jugendlicher.'
  },
  minor_16_to_17: {
    id: 'minor_16_to_17', label: 'Jugendlich (16–17)', labelEn: 'Youth (16–17)',
    icon: '🧑', minAge: 16, maxAge: 17,
    eudiClaims: { age_over_14: true, age_over_16: true, age_over_18: false },
    note: 'DSGVO Art. 8 einwilligungsfähig, eingeschränkt geschäftsfähig.'
  },
  adult_18_plus: {
    id: 'adult_18_plus', label: 'Volljährig (18+)', labelEn: 'Adult (18+)',
    icon: '🧑', minAge: 18, maxAge: null,
    eudiClaims: { age_over_14: true, age_over_16: true, age_over_18: true },
    note: 'Volljährig (§2 BGB).'
  },
};

// How an age_group was established. Phase 1 ships only self-declared (honest,
// low trust). Phase 3 adds eudi-wallet once the OpenID4VP verifier is wired up.
//   self-declared → age_verified:false, trust 30 (Eigenangabe)
//   eudi-wallet   → age_verified:true,  trust 99 (PID selective disclosure)  [planned]
export const AGE_VERIFICATION_METHODS = {
  'self-declared': {
    id: 'self-declared', label: 'Eigenangabe', labelEn: 'Self-declared',
    verified: false, trustScore: 30, available: true,
    note: 'Selbst angegeben, noch nicht kryptografisch verifiziert.'
  },
  'eudi-wallet': {
    id: 'eudi-wallet', label: 'EUDI Wallet (PID)', labelEn: 'EUDI Wallet (PID)',
    verified: true, trustScore: 99, available: false,  // Phase 3
    note: 'Altersnachweis per EUDI-Wallet (age_over_NN, Selective Disclosure). Geplant.'
  },
};
