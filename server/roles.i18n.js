/**
 * HHTTPS Role Registry — Localization Catalog
 *
 * roles.js is the PROTOCOL layer and holds the canonical ENGLISH that the API
 * serves and that is embedded into tokens. This module is the PRESENTATION
 * layer: it provides user-facing translations only.
 *
 * Design (sustainable / OOP):
 *   - Dependency is one-way: this file imports from roles.js, never the reverse.
 *     The protocol never depends on localization.
 *   - English is the canonical source of truth. The 'en' locale therefore has no
 *     catalog here — it falls back to roles.js directly.
 *   - Adding a language = add one locale key below. No change to roles.js.
 *   - Any missing key in a locale falls back to the canonical English, so a
 *     partial translation can never produce an empty label.
 *
 * Locales: 'en' (canonical, via roles.js), 'de'.
 */

import {
  ROLES,
  VERIFICATION_LEVELS,
  VERIFICATION_CHECKS,
  AGE_GROUPS,
  AGE_VERIFICATION_METHODS,
} from './roles.js';

export const SUPPORTED_LOCALES = ['en', 'de'];
export const DEFAULT_LOCALE = 'en';

// ─── German catalog ───────────────────────────────────────────────────────────
// Mirrors the keys of roles.js. Only user-facing strings are translated; the
// machine-readable structure (ids, methods, trust scores, eudiClaims) stays in
// roles.js and is never duplicated here.
const DE = {
  roles: {
    citizen: {
      label: 'Bürger',
      description: 'Verifizierter Mensch ohne spezifische Berufsrolle.',
      privileges: [
        'Teilnahme an öffentlichen Debatten als verifizierter Mensch',
        'Schutz vor Deepfake-Missbrauch der eigenen Identität',
        'Recht auf anonyme Kommunikation mit HHTTPS-Kennzeichnung'
      ],
      userStory: 'US-001: Als Bürger möchte ich beweisen können, dass ich ein Mensch bin, ohne meine Identität preiszugeben.'
    },
    journalist: {
      label: 'Journalist',
      description: 'Pressevertreter mit journalistischen Privilegien im digitalen Raum.',
      verificationHints: {
        'press-card':     'Presseausweis-Nummer (DJV, dju, VDZ)',
        'email-verified': 'Redaktions-E-Mail-Adresse'
      },
      privileges: [
        'Zugang zu HHTTPS-geschützten Pressebereichen',
        'Verifizierte Quellenangabe in digitalen Publikationen',
        'Schutz vor Identitätsmissbrauch als Journalist durch KI'
      ],
      userStory: 'US-012: Als Journalist möchte ich verifizieren können, dass meine digitale Identität nicht durch KI-Deepfakes kompromittiert wird.'
    },
    student: {
      label: 'Schüler / Student',
      description: 'Schüler oder Student an einer Bildungseinrichtung.',
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
      label: 'Lehrer / Pädagoge',
      description: 'Lehrkraft an Schule oder pädagogische Fachkraft.',
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
    researcher: {
      label: 'Wissenschaftler',
      description: 'Forscher, Professor oder wissenschaftlicher Mitarbeiter.',
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
      label: 'Kreativschaffender',
      description: 'Künstler, Synchronsprecher, Autor, Musiker oder anderer Kreativschaffender.',
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
      label: 'Entwickler',
      description: 'Software-Entwickler oder technischer Fachmann.',
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
    medical_professional: {
      label: 'Arzt / Medizinerin',
      description: 'Approbierter Arzt oder Ärztin, Zahnarzt, Tierarzt oder Apotheker.',
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
      label: 'Pflegekraft',
      description: 'Examinierte Pflegekraft, Altenpfleger, Krankenpfleger oder therapeutische Fachkraft.',
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
    lawyer: {
      label: 'Anwalt / Anwältin',
      description: 'Zugelassene Rechtsanwältin oder Rechtsanwalt.',
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
      label: 'Notar',
      description: 'Bestellter Notar als Träger eines öffentlichen Amtes.',
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
      label: 'Beamte / Behörde',
      description: 'Beamtin oder Beamter, Verwaltungsmitarbeiter oder Hoheitsträger (Polizei, Finanzamt, Sozialamt etc.).',
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
      label: 'Politiker / Mandatsträger',
      description: 'Gewählter Mandatsträger oder politischer Amtsinhaber.',
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
    business: {
      label: 'Unternehmen',
      description: 'Unternehmensvertreter oder juristische Person mit menschlichem Ansprechpartner.',
      verificationHints: {
        'domain-verified': 'Firmen-Domain-Inhaberschaft',
        'handelsregister': 'Handelsregisternummer (HRB/HRA)'
      },
      privileges: [
        'Verifizierte Unternehmenskommunikation',
        'HHTTPS-Zertifikat für Websites ("Echter menschlicher Ansprechpartner")',
        'Schutz vor KI-Phishing in Unternehmensnamen'
      ],
      userStory: 'US-078: Als Unternehmen möchte ich meinen Kunden gegenüber nachweisen, dass Kommunikation von echten Mitarbeitern stammt.'
    },
    craftsman: {
      label: 'Handwerker / Meister',
      description: 'Handwerksmeister, Geselle oder Handwerksbetrieb.',
      verificationHints: {
        'craft-chamber-id':   'Eintrag in der Handwerksrolle (Handwerkskammer)',
        'master-certificate': 'Meisterbrief-Nummer'
      },
      privileges: [
        'Verifizierte Handwerker-Identität in Vergleichsportalen',
        'Schutz vor Fake-Bewertungen und Identitätsdiebstahl',
        'Authentische Angebote und Rechnungen'
      ],
      userStory: 'US-106: Als Kunde möchte ich auf Handwerker-Plattformen erkennen können, ob ein Anbieter wirklich ein eingetragener Meister ist — nicht ein Fake-Profil mit gestohlenen Bildern.'
    }
  },

  // VERIFICATION_LEVELS[x].label
  verificationLevels: {
    'self-declared':        'Selbstdeklariert',
    'webauthn':             'WebAuthn verifiziert',
    'email-verified':       'E-Mail verifiziert',
    'github-verified':      'GitHub verifiziert',
    'school-email':         'Schul-E-Mail',
    'medical-email':        'Klinik-/Praxis-E-Mail',
    'lawyer-email':         'Kanzlei-E-Mail',
    'press-card':           'Presseausweis',
    'student-id':           'Matrikelnummer',
    'teacher-id':           'Lehrer-ID',
    'association-member':   'Verbandsmitglied',
    'orcid':                'ORCID verifiziert',
    'craft-chamber-id':     'Handwerksrolle',
    'master-certificate':   'Meisterbrief',
    'care-chamber-id':      'Pflegekammer',
    'bar-association-id':   'Rechtsanwaltskammer',
    'notary-chamber-id':    'Notarkammer',
    'approbation-id':       'Approbationsnummer',
    'service-id':           'Dienstausweis',
    'official-email':       'Offizielle E-Mail',
    'domain-verified':      'Domain verifiziert',
    'handelsregister':      'Handelsregister',
    'bundestag-verified':   'Bundestag verifiziert',
    'institution-verified': 'Institution verifiziert',
  },

  // VERIFICATION_CHECKS[x].note
  verificationChecks: {
    'github-verified': 'GitHub OAuth (api.github.com).',
    'email-verified':  'E-Mail-Link + Domain-Klassifizierung.',
    'school-email':    'E-Mail-Link + Domain-Klassifizierung.',
    'medical-email':   'E-Mail-Link + Domain-Klassifizierung.',
    'lawyer-email':    'E-Mail-Link + Domain-Klassifizierung.',
    'official-email':  'E-Mail-Link + Domain-Klassifizierung.',
    'domain-verified': 'Domain-Klassifizierung.',
    'orcid':           'Nur Format geprüft, nicht gegen orcid.org.',
    'press-card':         'DJV/dju/VDZ-Prüfung noch nicht angebunden.',
    'student-id':         'Hochschul-Prüfung noch nicht angebunden.',
    'teacher-id':         'Schulbehörden-Prüfung noch nicht angebunden.',
    'association-member': 'Verbands-Prüfung noch nicht angebunden.',
    'craft-chamber-id':   'Handwerkskammer-Prüfung noch nicht angebunden.',
    'master-certificate': 'Meisterbrief-Prüfung noch nicht angebunden.',
    'care-chamber-id':    'Pflegekammer-Prüfung noch nicht angebunden.',
    'bar-association-id': 'RAK-Prüfung noch nicht angebunden.',
    'notary-chamber-id':  'Notarkammer-Prüfung noch nicht angebunden.',
    'approbation-id':     'Bundesärztekammer-Prüfung noch nicht angebunden.',
    'service-id':         'Dienstausweis-Prüfung noch nicht angebunden.',
    'handelsregister':    'Handelsregister-Prüfung noch nicht angebunden.',
    'institution-verified': 'Institutions-Prüfung noch nicht angebunden.',
    'bundestag-verified': 'Bundestags-Prüfung noch nicht angebunden.',
  },

  // AGE_GROUPS[x] → { label, note }
  ageGroups: {
    minor_under_14: { label: 'Kind (unter 14)',   note: 'JuSchG: Kind. Besonderer Schutz.' },
    minor_14_to_15: { label: 'Jugendlich (14–15)', note: 'Strafmündig (§19 StGB), JuSchG: Jugendlicher.' },
    minor_16_to_17: { label: 'Jugendlich (16–17)', note: 'DSGVO Art. 8 einwilligungsfähig, eingeschränkt geschäftsfähig.' },
    adult_18_plus:  { label: 'Volljährig (18+)',   note: 'Volljährig (§2 BGB).' },
  },

  // AGE_VERIFICATION_METHODS[x] → { label, note }
  ageVerificationMethods: {
    'self-declared': { label: 'Eigenangabe',       note: 'Selbst angegeben, noch nicht kryptografisch verifiziert.' },
    'eudi-wallet':   { label: 'EUDI Wallet (PID)', note: 'Altersnachweis per EUDI-Wallet (age_over_NN, Selective Disclosure). Geplant.' },
  },
};

// Catalogs keyed by locale. 'en' is intentionally absent → canonical fallback.
const CATALOGS = { de: DE };

// ─── Internal helpers ──────────────────────────────────────────────────────────

function normaliseLocale(locale) {
  if (!locale) return DEFAULT_LOCALE;
  const base = String(locale).toLowerCase().split('-')[0];
  return SUPPORTED_LOCALES.includes(base) ? base : DEFAULT_LOCALE;
}

// Shallow-merge a translation over the canonical object, key by key, so any
// missing translation falls back to the canonical English value.
function overlay(canonical, translation) {
  if (!translation) return canonical;
  const out = { ...canonical };
  for (const k of Object.keys(translation)) {
    if (translation[k] != null) out[k] = translation[k];
  }
  return out;
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Localized copy of a role for display. Machine fields (id, icon,
 * verificationMethods) are preserved; label/description/privileges/
 * verificationHints are localized with English fallback.
 * Returns null for an unknown roleId.
 */
export function localizeRole(roleId, locale = DEFAULT_LOCALE) {
  const base = ROLES[roleId];
  if (!base) return null;
  const loc = normaliseLocale(locale);
  const tr = CATALOGS[loc]?.roles?.[roleId];
  if (!tr) return { ...base };

  const merged = overlay(base, {
    label: tr.label,
    description: tr.description,
    privileges: tr.privileges,
    userStory: tr.userStory,
  });
  if (base.verificationHints || tr.verificationHints) {
    merged.verificationHints = overlay(base.verificationHints || {}, tr.verificationHints);
  }
  return merged;
}

/** All roles localized, keyed by id (same shape as ROLES). */
export function localizeRoles(locale = DEFAULT_LOCALE) {
  const out = {};
  for (const id of Object.keys(ROLES)) out[id] = localizeRole(id, locale);
  return out;
}

/** Localized label for a role id (English fallback). */
export function roleLabel(roleId, locale = DEFAULT_LOCALE) {
  const loc = normaliseLocale(locale);
  return CATALOGS[loc]?.roles?.[roleId]?.label ?? ROLES[roleId]?.label ?? roleId;
}

/** Localized label for a verification level/method key (English fallback). */
export function verificationLevelLabel(method, locale = DEFAULT_LOCALE) {
  const loc = normaliseLocale(locale);
  return CATALOGS[loc]?.verificationLevels?.[method]
      ?? VERIFICATION_LEVELS[method]?.label
      ?? method;
}

/** Localized note for a verification check (English fallback). */
export function verificationCheckNote(method, locale = DEFAULT_LOCALE) {
  const loc = normaliseLocale(locale);
  return CATALOGS[loc]?.verificationChecks?.[method]
      ?? VERIFICATION_CHECKS[method]?.note
      ?? '';
}

/** Localized { label, note } for an age group (English fallback). */
export function localizeAgeGroup(groupId, locale = DEFAULT_LOCALE) {
  const base = AGE_GROUPS[groupId];
  if (!base) return null;
  const loc = normaliseLocale(locale);
  const tr = CATALOGS[loc]?.ageGroups?.[groupId];
  return overlay(base, tr ? { label: tr.label, note: tr.note } : null);
}

/** Localized { label, note } for an age verification method (English fallback). */
export function localizeAgeVerificationMethod(methodId, locale = DEFAULT_LOCALE) {
  const base = AGE_VERIFICATION_METHODS[methodId];
  if (!base) return null;
  const loc = normaliseLocale(locale);
  const tr = CATALOGS[loc]?.ageVerificationMethods?.[methodId];
  return overlay(base, tr ? { label: tr.label, note: tr.note } : null);
}
