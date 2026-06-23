/**
 * HHTTPS Role Taxonomy & Assurance — Localization Catalog
 *
 * Presentation layer for roles.taxonomy.js. Same contract as roles.i18n.js:
 * one-way import, English canonical, missing keys fall back to English.
 *
 * CRITICAL UI CONTRACT (credibility): RAL0 wording must stay free of any
 * "verified/bestätigt" language. RAL0 = "selbst angegeben", grey, no check.
 */

import { RAL_LEVELS } from './roles.taxonomy.js';

export const SUPPORTED_LOCALES = ['en', 'de'];
export const DEFAULT_LOCALE = 'en';

const DE = {
  ral: {
    0: { label: 'Selbst angegeben', short: 'selbst angegeben',
         note: 'Vom Nutzer selbst gewählte Rolle. Von keiner Stelle geprüft.' },
    1: { label: 'Bestätigt durch Dokument oder akkreditierte Stelle', short: 'akkreditiert',
         note: 'Gedeckt durch ein geprüftes Dokument oder eine verifizierte Domain/Account.' },
    2: { label: 'Amtlich bestätigt, trotzdem anonym', short: 'qualifiziert',
         note: 'Bestätigt über das EUDI Wallet (PID/QEAA/PuB-EAA) aus qualifizierter Quelle.' }
  },
  kind: {
    occupation:   'Beruf',
    status:       'Status',
    legal_entity: 'Juristische Person',
    sector:       'Öffentlicher Sektor'
  },
  group: {
    A: 'Autoritative Quelle vorhanden (RAL2 möglich)',
    B: 'Keine staatliche Quelle (selbst-deklariert)'
  },
  customReason: {
    empty:    'Bitte eine Berufsbezeichnung eingeben.',
    reserved: 'Diese Berufsbezeichnung ist geschützt und kann nicht selbst angegeben werden. Bitte über das EUDI Wallet oder einen Nachweis bestätigen lassen.'
  },
  customOption: 'Sonstiges / frei definieren …'
};

const CATALOGS = { de: DE };

export function ralLabel(ral, locale = 'en') {
  const canon = RAL_LEVELS[ral];
  if (!canon) return null;
  const cat = CATALOGS[locale]?.ral?.[ral];
  return {
    ral,
    label: cat?.label ?? canon.label,
    short: cat?.short ?? canon.short,
    note:  cat?.note  ?? canon.note,
    badge: canon.badge
  };
}

export function kindLabel(kind, locale = 'en') {
  return CATALOGS[locale]?.kind?.[kind] ?? kind;
}

export function groupLabel(group, locale = 'en') {
  return CATALOGS[locale]?.group?.[group] ?? group;
}

export function customReasonLabel(reason, locale = 'en') {
  return CATALOGS[locale]?.customReason?.[reason] ?? reason;
}

export function customOptionLabel(locale = 'en') {
  return CATALOGS[locale]?.customOption ?? 'Other / define your own …';
}
