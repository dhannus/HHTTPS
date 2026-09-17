# HHTTPS Rollen-System v0.5 — die volle Schleife (ESCO-only, issue + read)

Keine festen 15 Rollen mehr. Eine Rolle ist entweder **selbst erzeugt** (iamhmn-card
ins Wallet) oder **ausgelesen** (vorhandenes (Q)EAA). ESCO ist das Vokabular,
die `RESERVED_REGISTRY` ist die einzige feste Rollen-Governance.

## Die zwei Wege (geschlossene Schleife)

```
   ERZEUGEN (HHTTPS = Issuer)                  AUSLESEN (HHTTPS = Verifier)
   ─────────────────────────                   ──────────────────────────
   Nutzer wählt/definiert Rolle (ESCO)         Wallet zeigt ein (Q)EAA vor
   + optional Dokument                          (die iamhmn-card ODER extern,
        │                                         z. B. Ärztekammer)
        ▼                                              │
   POST /hhttps/role/card                              ▼
   → reserved-guard + ESCO-resolve              OID4VP-Präsentation (EUDIPLO)
   → buildRoleClaim (RAL 0/1)                   → roles.eaa.buildRoleEaaClaims
   → issueIamhmnCard (EUDIPLO /issuer/offer)    → RAL aus der Karte (0/1) ODER
   → Offer-URI → QR → Wallet                       RAL2 (externe qualifizierte Quelle)
```

## Was in diesem Paket FERTIG und getestet ist (Backend)

| Datei | Inhalt | Status |
|---|---|---|
| `roles.taxonomy.js` | enum-frei: `resolveRole`, `RESERVED_REGISTRY`, `deriveRAL`, `buildRoleClaim`, `resolveEsco`, Discovery | ✅ 9 Tests |
| `roles.eaa.js` | Lese-Pfad: extern→RAL2, Card-Read-back→RAL aus Karte; `guardRoleEaa` | ✅ |
| `eudi-verifier/backend-client.js` | **`issueIamhmnCard()`** + `ensureIamhmnCardConfig()` (OID4VCI, Hackathon-Flow) | ✅ node --check |
| `server.js` | `POST /hhttps/role/card`, `GET /hhttps/esco/suggest`, `GET /.well-known/hhttps-role-assurance`, Imports | ✅ node --check |
| `public/js/signin/app.js` | Frontend: ESCO-Typeahead + Freitext + Dokument + „ins Wallet laden" (AP8-37/#226: die nie eingebundene Web-Component `public/iamhmn-card-issuer.js` wurde gelöscht) | ✅ |
| `roles.taxonomy.i18n.js` | DE RAL-Strings | ✅ |
| `GET /.well-known/hhttps-role-assurance` | Discovery (model: esco-dynamic), aus `roleAssuranceDiscovery()` berechnet. AP8-54 (#249): die statische Kopie unter `public/.well-known/` war bereits gedriftet und wurde gelöscht | ✅ |

## Was du noch tun musst (kein Code, oder dein Merge)

1. **EUDIPLO-Config `iamhmn-card`** (server-seitig, einmalig): Der Issuer-Config
   muss existieren mit `refreshTokenEnabled:false` und ECDH-ES Response-
   Encryption — genau die Hackathon-Fixes. `ensureIamhmnCardConfig()` legt einen
   Minimal-Config an, aber Encryption/Key-Chain-Attestation richtest du wie im
   Hackathon ein (key-chain `usageType:"attestation"`).

2. **Frontend in `index.html`** — *erledigt, anders als hier geplant.*
   Die Rollen-Sektion ist direkt in `public/js/signin/app.js` implementiert
   (`escoSuggest()` → `GET /hhttps/esco/suggest`, `roleIssue()` →
   `POST /hhttps/role/card`, QR aus `offer.crossDeviceUri`). Die geplante
   Web-Component `<iamhmn-card-issuer>` wurde nie eingebunden und in
   Review-Welle 3 gelöscht (AP8-37, #226).

3. **Legacy-`ROLES`-Abbau (optional, separat):** Die alten 15 in `roles.js` sind
   für die Schleife nicht mehr nötig, werden aber noch von Sekundärpfaden gelesen
   (`/hhttps/info` `supported_roles`, OAuth `userinfo`, `/hhttps/machine/register`
   bot-role, `email.js`, `roles.i18n.js`). Die kann ich in einem separaten,
   sauberen Pass auf `resolveRole`/Discovery umstellen — sag Bescheid. Bis dahin
   stören sie nicht (die Schleife nutzt sie nicht).

## RAL-Regeln (Glaubwürdigkeit)

- **RAL0** — selbst angegeben (iamhmn-card ohne Dokument). Grau, kein Haken.
- **RAL1** — Dokument angehängt (Pilot: Selbstangabe, live gegen Register geprüft).
- **RAL2** — externe qualifizierte (Q)EAA (Ärztekammer …) per OID4VP.
- **Reservierte Berufe** (medical/nursing/lawyer/notary/police/judge): **nie RAL0**.
  Brauchen Dokument (RAL1) oder qualifizierte Quelle (RAL2). Erkennung per
  Stamm-Match UND per ISCO-Präfix (fängt „Internistin"/2212 ohne Schlüsselwort).

## Endpunkte (neu)

```
POST /hhttps/role/card               { sessionId, esco?{label,isco08,escoUri} | customRole, documentProvided? }
                                     → { card:{role,ral,verification?}, offer:{uri,crossDeviceUri} }
GET  /hhttps/esco/suggest?q=…&lang=  → { results:[{label,isco08,escoUri,reserved,reservedKey}] }
GET  /.well-known/hhttps-role-assurance → RAL-Stufen + Claim-Format + reserved_registry
```

## Token nach einer iamhmn-card (RAL1, Tischler-Beispiel)

```json
{
  "role": "tischler", "ral": 1,
  "role_claim": {
    "id":"tischler","label":"Tischler","self_declared":false,"human_verified":true,
    "kind":"occupation","group":"B",
    "taxonomy":{"scheme":"ISCO-08","uri":null,"isco08":"7522"}
  },
  "role_verification": {
    "trust_framework":"hhttps","assurance_level":"substantial",
    "evidence_type":"document","verified_at":"2026-06-21"
  }
}
```
