# HHTTPS Browser Extension v1.1.0

Zeigt den HHTTPS-Verifikationsstatus jeder Website in deiner Browserleiste an.

Kompatibel mit HHTTPS-Protokoll **v0.4.1** (Server `hhttps.org`).

## Was sie tut

| Status | Badge | Bedeutung |
|---|:---:|---|
| Verifizierter Mensch | ✓ (sage-grün) | Token vorhanden, kryptografisch valide, Mensch-Beweis enthalten |
| Maschine verifiziert | 🤖 (apricot) | Token gültig, aber Bot-Identität (kein Mensch) |
| HHTTPS verfügbar | ! (terra) | Server unterstützt HHTTPS, aber du bist nicht verifiziert |
| Kein HHTTPS | (grau) | Site unterstützt HHTTPS nicht |

## Was sie kann (v1.1.0)

- **Lesen** der `HHTTPS-*` HTTP-Header von jeder besuchten Seite
- **Lesen** von `<meta name="hhttps-*">` Tags (Server-injected fallback)
- **Speichern** von Tokens pro Issuer-Domain (lokal in `chrome.storage`)
- **Auto-Refresh** von Access-Tokens 5 Minuten vor Ablauf via Refresh-Token
- **Discovery**: erkennt automatisch HHTTPS-Issuer über `/.well-known/hhttps-configuration`
- **Token widerrufen** direkt aus dem Popup
- **Floating-Indicator** unten rechts auf der Seite (8 Sek. sichtbar)

## Installation (Chrome / Edge / Brave / Arc)

1. ZIP entpacken oder Extension-Ordner clonen
2. `chrome://extensions` öffnen
3. "Entwicklermodus" oben rechts aktivieren
4. "Entpackte Erweiterung laden" → den `hhttps-extension`-Ordner wählen
5. Pin die Extension in der Toolbar fest

## Installation (Firefox)

1. `about:debugging#/runtime/this-firefox` öffnen
2. "Temporäre Erweiterung laden..."
3. Die `manifest.json` aus dem Ordner auswählen

Hinweis: In Firefox muss die Extension nach jedem Neustart neu geladen werden, bis sie über `addons.mozilla.org` verfügbar ist.

## Berechtigungen erklärt

- `storage` — speichert Tokens pro Issuer-Domain lokal
- `activeTab` — liest den Status der aktuell aktiven Seite
- `alarms` — plant Refresh-Tokens vor Ablauf
- `<all_urls>` — patcht `fetch()` und `XHR` auf jeder Seite, um HHTTPS-Header zu lesen

Die Extension sendet **keine** Daten an externe Server außer:
- `https://hhttps.org/hhttps/token/refresh` (für automatischen Refresh)
- `https://hhttps.org/hhttps/revoke` (wenn du auf "Widerrufen" klickst)
- `/.well-known/hhttps-configuration` der besuchten Site (zur Discovery)

## Nutzung

1. Klick auf das HHTTPS-Icon in der Toolbar → Popup zeigt:
   - Verifikationsstatus (Mensch / Maschine / Unverified / Kein HHTTPS)
   - Trust-Score 0–100 mit visueller Anzeige
   - Rolle (z.B. "Arzt", "Anwältin") mit Privilegien-Liste
   - Token-Details (Issuer, Methode, JTI-Kürzel)
   - "Bei hhttps.org verifizieren" / "Token widerrufen" Buttons

2. Bei jeder Seite mit HHTTPS-Headern erscheint kurz ein Floating-Indicator unten rechts.

## Entwicklung & Debugging

- Console der Extension: `chrome://extensions` → Details → "Service Worker prüfen"
- Console der Popup-Seite: Rechtsklick auf Popup → "Untersuchen"
- Console des Content-Scripts: DevTools der besuchten Seite

## Lizenz

EUPL-1.2 — gleiche Lizenz wie der HHTTPS-Server.
Eine Initiative von [HumanProof](https://hhttps.org) · [github.com/dhannus/HumanProof](https://github.com/dhannus/HumanProof)
