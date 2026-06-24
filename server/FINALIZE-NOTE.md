# Finalisierung — Komponente verdrahtet + /hhttps/roles auf ESCO

Ergänzungen in diesem Schritt, additiv auf den Cleanup-Stand.

## `public/index.html` — `<iamhmn-card-issuer>` eingehängt
- **Modul-Script** im `<head>` geladen: `<script type="module" src="/iamhmn-card-issuer.js">`.
- **Panel** in `#p2` (Token-Phase), direkt nach dem EUDI-Panel — gruppiert die
  Wallet-Aktionen. Enthält `<iamhmn-card-issuer id="cardIssuer">` + einen
  `#cardQrBox` (QR + Deep-Link), anfangs versteckt.
- **Wiring-Script** (am Ende des bestehenden Inline-Scripts, also im Scope von
  `sessionId`, `LANG`, `qrcode`):
  - hält `session-id` aktuell (Capture-Click-Sync → immer gesetzt, bevor ein
    Klick die Komponente erreicht);
  - hält `locale` + Panel-Titel/Sub synchron mit der Seitensprache (ohne den
    `T`/`data-i18n`-Mechanismus zu berühren — eigene Mini-Labels);
  - rendert die Wallet-Offer-URI bei `card-offer` als QR mit **deinem**
    `qrcode()`-Generator (gleicher Pfad wie der EUDI-Flow) + setzt den Deep-Link.

  Bewusst **nicht** angefasst: der `T`/i18n-Block, die Methoden-UI, der EUDI-Flow.
  Validierung: Inline-Script (jetzt inkl. Wiring) `node --check` OK; `#p2`
  div-balanciert; Komponente/Modul/QR-Elemente vorhanden.

## `server.js` — Listen auf ESCO-dynamisch umgestellt (additiv)
- `GET /hhttps/roles`: liefert statt der 15er-Liste jetzt `model:'esco-dynamic'`,
  `base_identity` (citizen), die `reserved_registry`, die `ralLevels`, und Pointer
  auf `/hhttps/esco/suggest` + `/.well-known/hhttps-role-assurance`.
- `GET /hhttps/info`: `supported_roles:'esco-dynamic'` + `roles_model`-Block;
  `roles`-Liste → `base_identity`; Feature-Flag `roles-15` → `roles-esco-dynamic`.
- Startup-Log: „Roles: ESCO-dynamic …" statt „15 (citizen … craftsman)".

Kein Bruch: `ROLES.citizen` bleibt die Basis; alle Lesepfade nutzen sie als
Fallback. `node --check server.js` OK.

## Damit ist die Schleife im Code vollständig
ERZEUGEN (Picker → `/hhttps/role/card` → `issueIamhmnCard` → QR → Wallet) und
AUSLESEN (`roles.eaa.js`, extern RAL2 / Card RAL0–1) sind verdrahtet, das
Frontend zeigt den Picker in Screen 2, und die öffentlichen Listen spiegeln das
ESCO-Modell. Offen bleibt nur Server-Konfiguration: der EUDIPLO-`iamhmn-card`-
Issuer-Config (Encryption/Key-Chain) wie im Hackathon.
