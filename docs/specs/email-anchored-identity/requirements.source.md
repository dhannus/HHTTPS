Anforderungen Iamhmn:

1. Anforderung: Es gibt mehrere Methoden zur Anmeldung, damit es in Zukunft möglich ist hardwareübergreifend, immer den selben Benutzer mit dem selben Pseudonym anmelden kann in einer Anwendung. 
Muss sichergestellt sein, dass immer wieder der selbe Sub für ein Benutzerkonto angelegt und bei einer erneuten Anmeldung wieder als der selbe Sub übertragen wird.
Über den der Benutzer authentifiziert werden kann. Dafür haben wir eine systemische Regel getroffen. Das E-Mailverfahren wird zur Pflichtanmeldung.

E-Mail und Pseudonym müssen immer als Minimale Anmeldung erfolgen in Zukunft. Das Pseudonym bleibt dabei
optional, indem ein kryptisches iamhmn_2342kfs56 vergeben wird, falls kein Pseudonym angegeben worden ist. 
Email und Emailverifikation bleibt Pflicht.

Alle anderen Verifizierungsmethoden werden erst hinterher auswählbar, sind entweder ausgeblendet, bevor die Email verifiziert wurde.
Oder ausgegraut und nicht anklickbar, solange die Emailverifikation noch nicht erfolgt ist.

Die E-Mailadresse speichern wir in Zukunft so lange im Cache, bis wir sie sicher an die jeweiligen Issuer übertragen konnten im Klartext inklusive Pseudonym und verifizierte Methoden.
Es muss zusätzlich geprüft werden, ob diese Daten auch sicher und zum richtigen Zeitpunkt an den Jeweiligen Issuer gehen oder er sie sich per API Route abrufen kann, ich habe den Verdacht, dass nicht alle ROuten auch wirklich alle spezifizierten Daten übertragen.
So wie email_verified, github_verified, eudi_verified....wird das übertragen? mir scheint dem nicht so zu sein. Weil ich mich mit Passkey angemeldet habe aber das nicht beim Issuer erkannt wird.

#2. Anforderung: Bitte den Code in der Email die man bekommt so ändern, dass man die 6 stelligen Codes ohne leerzeichen 123456 kopieren kann und erkannt wird und nicht "000 000", Das Design anpassen an die neue WorldID Anlehnung die schon auf der hhttps.org Seite verwendet wird.


Recherche zu den Anforderungen.
# Account Linking for HHTTPS: Durably Uniting Passkeys, Email, GitHub, and EUDI Behind One Pseudonymous Identity

## TL;DR
- **Every mature auth platform solves cross-session account linking the same way: a canonical internal user record with an array of linked "identities," anchored on a *verified* identifier (almost always email) — but this anchoring model is precisely what breaks HHTTPS's zero-PII promise.** The right pattern for HHTTPS is to keep its `userId` as an opaque canonical anchor and let the *user* prove "these methods are all me" through step-up re-authentication with an already-linked method, never through a stored PII graph.
- **The single most important security rule, confirmed by Auth0, WorkOS, Stytch, Clerk, SuperTokens, Keycloak, and the Microsoft pre-hijacking research, is: never link a new method to an existing identity on the basis of an unverified/self-asserted identifier. Require proof of control of an already-linked method (re-auth or step-up) before merging.** HHTTPS already does this correctly inside a session; the gap is purely cross-session.
- **The EUDI Wallet is the strongest available anchor and is architecturally aligned with HHTTPS: eIDAS 2.0 mandates locally-generated, pairwise, unlinkable pseudonyms (WebAuthn-based), and "proof of association" lets a relying party trust a pseudonym is backed by a government-verified identity *without learning that identity*.** HHTTPS should treat a verifiable/attested pseudonym as its highest-assurance linking anchor.

## Key Findings

1. **The universal data model is "one canonical user, many identities."** Auth0 embeds secondary identities in a `user.identities[]` array on a primary profile; WorkOS/Stytch/Clerk keep one `User` object with arrays of OAuth registrations, passkey registrations, and email factors; SuperTokens designates one "primary user" that "recipe users" link into. HHTTPS's `userId` is the equivalent canonical anchor — the fix is to make multiple authentication methods resolve to one `userId`.

2. **The de facto anchor everywhere is a verified email address** — which is exactly what HHTTPS deliberately refuses to store. This is the central tension: the industry's convenience (auto-linking by matching email) is a zero-PII violation *and* a documented source of account-takeover vulnerabilities.

3. **Auto-linking by email is the single most exploited pattern.** Per Sudhodanan & Paverd (Microsoft MSRC), "Pre-hijacked accounts," USENIX Security 2022 (arXiv:2205.10174): "we analyzed 75 popular services and found that at least 35 of these were vulnerable to one or more account pre-hijacking attacks" — named vulnerable services included Instagram, LinkedIn, Dropbox, Zoom, and WordPress.com. Real CVEs bear this out: TYPO3 oidc CVE-2025-24856 (TYPO3-EXT-SA-2025-001, CWE-348, "A vulnerability in the account linking logic of the extension allows a pre-hijacking attack leading to Account Takeover"), Socialstream CVE-2024-56329 (GHSA-3q97-vjpp-c8rp, CWE-287, CVSS 9.6 CRITICAL), Keycloak CVE-2025-7365, and Novu (GHSA-xj4x-44hh-737v).

4. **Passkeys map cleanly to a single identity via the WebAuthn user handle (`user.id`).** The RP sets one stable, non-PII user handle per user; all of that user's passkeys (across devices, synced or device-bound) share it. This is the closest existing standard to what HHTTPS needs — but the user handle must be the *canonical* `userId`, not a per-credential id.

5. **The EUDI Wallet is purpose-built for exactly HHTTPS's "state-verified, yet anonymous" promise.** eIDAS 2.0 (Regulation (EU) 2024/1183) Article 5a(4)(b) requires the wallet to "generate pseudonyms and store them encrypted and locally within the European Digital Identity Wallet," pairwise per relying party, unlinkable across relying parties, yet stable for the same relying party — with cryptographic proof-of-association binding a pseudonym to a verified PID without disclosing identity.

6. **Privacy-preserving linking without a central PII graph is achievable** through user-held linkage (the wallet/device asserts the linkage), deterministic derivation from a user-controlled secret, and user-asserted linking (authenticate with method A, then add method B in a re-authenticated flow) — which is exactly the mechanism HHTTPS already has in-session.

## Details

### 1. Industry patterns: the canonical-user-with-linked-identities data model

Every major platform converges on the same shape: a **single internal user record** that owns a collection of **linked authentication methods / identities**.

- **Auth0** treats all identities as separate by default: "if a user logs in first against the Auth0 database and then via Google or Facebook, these two attempts would appear to Auth0 as two separate users." Linking is explicit, producing a **primary** and **secondary** account. After linking: "The `user_id` and all other main profile properties continue to be those of the primary identity"; "The first identity in the `user.identities` array is the primary identity"; "The secondary account is now embedded in the `user.identities` array of the primary profile." Auth0 supports **user-initiated linking** (authenticated user links via an admin/self-service screen) and **suggested linking** (identify accounts with the same email and prompt). Critically, Auth0 warns: "your tenant should request authentication for both accounts before linking occurs. In addition, every manual account link should prompt the user to enter credentials." The linking API is `POST /api/v2/users/{primaryId}/identities` with `link_with: {secondary ID token}`, requiring an access token with the `update:current_user_identities` scope for user-initiated flows.

- **WorkOS AuthKit** performs **identity linking** automatically but refuses to complete authentication "when a new identity cannot be safely linked to an existing user to ensure account takeover risks are minimized." It anchors on email verification and, for enterprise, on **verified domains** ("a verified domain implies the ability to verify all users with that email domain"). WorkOS's guidance names the **NoAuth** vulnerability class (trusting IdP-asserted attributes like email without confirming the IdP actually verified them) and recommends always performing your own email verification, preferring a **code the user types back** over a clickable link (because email security scanners consume single-use links).

- **Stytch** does linking automatically "but with consideration to the many nuances of what information is shared and verified by each login method" — e.g., "since Microsoft OAuth doesn't verify email ownership, Stytch does not merge Microsoft OAuth logins with … magic link logins automatically." Its `User` object carries arrays for OAuth `providers[]`, `webauthn_registrations[]`, and email factors. In B2B, "Stytch utilizes the email address as a unique primary key for identifying Members within an Organization" and auto-consolidates.

- **Descope** merges "based on trusted email addresses," gated by a toggle "Merge user accounts based on returned email address from provider," and its flows let developers insert an explicit email-verification step (OTP/magic link/enchanted link) before merge. It supports multiple `loginIDs` per user. Notably, for SSO Descope defaults to *not* merging: "Even if a user signs in using the same email address via SSO and via a non-SSO method, they will be treated as separate users … unless explicitly linked (which is not recommended)."

- **Clerk** "automatically attempts to link accounts whenever possible" using email as the common identifier, but only for **verified** emails: for a verified OAuth email it links and signs in; for an unverified one it "will initiate a verification process." If the provider doesn't return `email_verified`, "we assume it's not verified and force an additional email verification step." Clerk also documents `useReverification()` — requiring the user to reverify credentials before adding a new email/method.

- **SuperTokens** has the most explicit model: exactly one **primary user**; other **recipe users** link to it, and "the resulting user ID of the linked accounts will be the primary user's ID." Hard rule: "Accounts can be linked only if the resulting primary user's email / phone number / third party info is not the same as another primary user's." Auto-linking requires email verification in `REQUIRED` mode; its security docs walk through precisely the attack where a malicious unverified account could be linked when a victim clicks a verification email, and disallow sign-in in those cases.

- **Keycloak** uses the **First Broker Login** flow. When a brokered IdP login matches an existing local email, "Automatically linking the existing local account to the external identity provider is a potential security hole as you can't always trust the information you get from the external identity provider." It therefore requires either **Verify Existing Account By Re-authentication** (username+password, optionally OTP) or **Verify Existing Account By Email**. Its `AutoLink` authenticator is explicitly flagged as "dangerous in a generic environment." (CVE-2025-7365 showed even the email-verification step can be abused: an attacker edits their profile email to the victim's during first-login, triggering a verification email to the victim — a phishing vector.)

- **Okta** links external IdP accounts to one Universal Directory user via an **Account Link Policy** (Automatic matches on IdP username=email); best practice is to "consider disabling account linking after all existing users … have signed in."

**The pattern for HHTTPS:** adopt the canonical-user + linked-methods array model, but replace "email as primary key / auto-link on matching email" with an **explicit, user-proven linking event**.

### 2. The "primary anchor" problem and how zero-PII systems solve it

In every commercial platform the anchor is a **verified email** (or verified domain for enterprise). This is a deliberate trade-off: email is globally unique, user-controllable, and re-verifiable. But it is PII, it enables cross-service correlation, and — as the vulnerability record shows — it is the attack surface.

Systems that avoid a central PII anchor use one of three substitutes:

- **An opaque internal primary key** that PII maps *to* but is never derived *from* — this is what the WebAuthn user handle and OIDC pairwise `sub` already are. OpenID Connect pairwise/PPID identifiers are computed deterministically, e.g. `sub = SHA-256(sector_identifier + local_account_id + salt)` (Connect2id uses AES-SIV over sector+subject), specifically to "replace user identifiers containing PII … with opaque, random identifiers that cannot be traced back." HHTTPS's `sub = HMAC(userId | clientId, secret)` is exactly this construction — the issue is not the `sub`, it is the *instability of `userId`*.

- **A user-held anchor**: the linkage lives in the user's wallet/device (DIDs, verifiable credentials), so no server holds a graph. "No personal data is stored on-chain; only public identifiers and revocation registries." The user *is* the anchor.

- **A user-asserted anchor**: the system never decides two methods are the same person; the *user* proves it by authenticating with method A and adding method B in the same authenticated context. This is HHTTPS's existing in-session merge — the correct primitive, just needing cross-session persistence.

### 3. Secure linking: preventing account takeover

The controlling research is **"Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web"** (Sudhodanan & Paverd, Microsoft MSRC; USENIX Security 2022; arXiv:2205.10174). Root cause, verbatim: "the service fails to verify that the user actually owns the supplied identifier … before allowing use of the account." Five attack classes: Classic-Federated Merge, Unexpired Session, Trojan Identifier, Unexpired Email Change, and Non-verifying IdP.

**The attack HHTTPS most cares about** — an attacker who knows another user's public pseudonym/handle tries to link into their account — is the linking analogue of the Trojan-Identifier / Classic-Federated Merge attack. The mitigations, drawn from the research and vendor practice, are:

- **Strict identifier verification before any linking action.** Never link on a self-asserted or IdP-asserted-but-unverified identifier. (Novu's fix, GHSA-xj4x-44hh-737v, rejects linking with the error "You cannot link OAuth provider to unverified account.")
- **Proof of control of an already-linked method** (re-authentication or step-up) before adding a new method — Keycloak's re-auth, Auth0's "authenticate both accounts," Clerk's `useReverification`, Descope's verify-before-merge.
- **Confirmation step / user consent** at the moment of linking. Socialstream CVE-2024-56329 (CVSS 9.6) was caused by its absence — "When linking a social account to an already authenticated user, the lack of a confirmation step introduces a security risk"; the fix "introduces a new custom route that requires a user to 'Confirm' or 'Deny' a request to link a social account."
- **Invalidate sessions and credentials created before verification/linking** (mitigates Unexpired Session).
- **Short-lived, single-use, rate-limited verification capabilities** (mitigates Unexpired Email Change).
- **MFA/step-up.** Per Andrew Paverd (Microsoft MSRC), quoted in Help Net Security (May 24, 2022): "Correctly implemented MFA will prevent the attacker from authenticating to a pre-hijacked account after the victim starts using this account."

HHTTPS's public pseudonym (chosen username) must be treated as a **public identifier, never a proof of ownership** — knowing it must grant nothing.

### 4. WebAuthn / passkeys: multiple credentials, one identity

The WebAuthn spec provides the exact mechanism HHTTPS needs: the **user handle** (`user.id`, echoed as `response.userHandle`). Yubico's guidance: "The user handle represents the mapping of a public key credential to a user account with the Relying Party … it is the RP that sets its value." Requirements: it "Must not contain information that could identify the user," and (per go-webauthn) "It MUST be stable for the lifetime of the account and MUST be the same across every credential that user owns."

Implications:
- A user can register **many passkeys** (multiple devices, multiple authenticators) all sharing one user handle — that is how one identity spans devices. The RP manages this ("that is up to the RP to manage," per the W3C WG).
- **Synced passkeys** (iCloud Keychain, Google Password Manager) propagate one credential across a user's devices automatically; **device-bound passkeys** (Windows Hello, security keys) do not, so the user must register an additional passkey per device — but all still hang off the same user handle.
- **Cross-device authentication** (CTAP2 "hybrid"/QR + Bluetooth proximity check) lets a passkey on a phone authenticate a sign-in on another device without syncing, with a proximity check so "your passkey can't be used by a remote attacker … from far away."
- At most **one discoverable credential per user handle per RP** can be stored on an authenticator; `excludeCredentials` prevents duplicate registration.

**The fix for HHTTPS's passkey problem:** stop using the per-credential credential id as `userId`. Set the WebAuthn `user.id` (user handle) equal to the canonical HHTTPS `userId`, and store multiple credential ids against it. New devices add credentials to the same handle.

### 5. EUDI Wallet / eIDAS 2.0 as the strong anchor

The EUDI Wallet is the one anchor that is simultaneously **government-verified and privacy-preserving**, matching HHTTPS's brand promise almost exactly.

- **Legal basis:** eIDAS 2.0 (Regulation (EU) 2024/1183) Article 5a(4)(b) requires wallets to "generate pseudonyms and store them encrypted and locally within the European Digital Identity Wallet" (in force 20 May 2024, OJ 30 April 2024), and Article 5a(16) mandates "privacy preserving techniques which ensure unlinkability." Article 5b(9): "Relying parties shall not refuse the use of pseudonyms, where the identification of the user is not required."
- **Mechanism:** The implementing act CIR 2024/2979 Article 14 and Annex V specify **WebAuthn** as the technical basis; the Wallet Unit acts as a WebAuthn **Authenticator** generating a fresh per-RP key pair. Per CIR 2024/2979 Art. 14(2), the wallet supports generation "upon the request of a wallet-relying party, of a pseudonym which is specific and unique to that wallet-relying party."
- **Pairwise + unlinkable + stable:** The EUDI Wallet ARF Topic E discussion paper proposes: Requirement 13 — "A Wallet Unit SHALL always release a different value for the Pseudonym of a given User to different Relying Parties unless the User explicitly chooses otherwise"; Requirement 12 — a Relying Party "SHALL NOT be able to derive the User's true identity, or any data identifying the User, from the Pseudonym value received by the Relying Party"; Requirement 14 — colluding RPs "SHALL NOT be able to conclude that different Pseudonyms belong to the same User." Yet Requirement 2 makes it stable for the *same* RP so a returning user "logs in to the same account at the Relying Party."
- **Identity-backed without disclosure — Proof of Association:** ARF Requirement 10 — if a pseudonym is registered together with a PID/(Q)EAA presented to the same RP, that RP "SHALL be able to verify that the same User performed both actions." The cryptographic primitive (IACR ePrint 2024/1444, "Attestation Proof of Association") lets the wallet prove a pseudonym key and a PID key "are bound to the same … hardware," enabling "cryptographically binding (disclosed parts of) attestations with these pseudonyms" — i.e. an RP can trust a pseudonym is backed by a real verified person without learning who. The ARF also requires (Requirements 8–9) that an RP can verify the pseudonym is registered/used with a **non-revoked** Wallet Unit, and (via an Anonymisation CA with single-use attestation keys) that this assurance need not sacrifice RP-unlinkability.
- **Caveats (must be flagged):** Topic E is a **non-normative discussion paper** (current v1.0, 19 Nov 2025) and the WebAuthn mandate is being **softened to optional** ("it becomes optional for a Wallet Unit to also be a WebAuthn authenticator"). Independent cryptographers (Baum, Camenisch, Lysyanskaya, Preneel, et al., "Cryptographers' Feedback on the EU Digital Identity's ARF") warn the plain WebAuthn/FIDO2 approach "fails to provide … unlinkability: if the same attestation is used in two transactions, these transactions can be linked," and recommend anonymous-credential/ZKP schemes (BBS+) instead. The ARF itself (proposed Requirement 18) acknowledges plain WebAuthn is insufficient and that the Commission must define a compliant profile/extension. So the EUDI pseudonym story is directionally strong but still in flux.

### 6. Privacy-preserving linking techniques (no central PII graph)

Concrete approaches HHTTPS can combine:

- **User-asserted, session-based linking (extend the existing merge across sessions).** The user proves ownership of an already-linked method and then adds another. No PII graph is needed — only a mapping from each method's credential to the same opaque `userId`.
- **User-held linkage via the EUDI wallet or a passkey as the "linking key."** The wallet/passkey becomes the recovery/re-linking anchor: to add a method, present the anchor. The linkage effectively lives with the user.
- **Deterministic derivation from a user-controlled secret.** Hierarchical-deterministic (BIP-32-style) derivation can produce "unlinkable identifiers … from a single master key," so per-RP pseudonyms derive from one user-held secret without a server-side join table.
- **HMAC-of-email as a *linking hint*, not an anchor.** HHTTPS can keep a per-user (not per-RP) blinded email hash purely to *offer* "we think you have an existing account — prove it," never to auto-merge. This preserves data minimization while enabling suggested (user-confirmed) linking.

## Recommendations

**Design principle:** Keep `sub = HMAC(userId | clientId, secret)` unchanged. Make `userId` a **stable, opaque, internal canonical anchor** that multiple authentication methods resolve to — and let linking be an explicit, user-proven event, never an inference from stored PII.

**Stage 1 — Fix the data model (do first).**
- Introduce a canonical `userId` (random 128-bit opaque value) as the primary key. Create a `linked_methods` table: `(userId, method_type, method_key_hash, verified_at, assurance_level)`. `method_key_hash` = a salted hash of the passkey credential id / GitHub account id / wallet pseudonym / per-user email HMAC. No cleartext PII.
- For passkeys, set WebAuthn `user.id` = `userId`; store many credential ids per `userId`.
- **Benchmark to advance:** every method type can resolve to one `userId` in tests across sessions.

**Stage 2 — Persist the existing merge across sessions (the core fix).**
- When an authenticated session (already bound to `userId`) adds a new method, write a permanent `linked_methods` row. On a future session using that method, look up `method_key_hash` → resolve to the same `userId` → same `sub`. This turns today's in-session merge into durable linking with zero new PII.
- **Require step-up before linking:** to add method B, the user must hold a live session proven by method A (re-authentication), mirroring Keycloak/Auth0/Clerk. Never link on identifier match alone.

**Stage 3 — Make the pseudonymous username safe and add suggested linking.**
- Treat the user-chosen pseudonym/username strictly as a **public label**; knowing it grants nothing (defeats the "attacker knows the handle" attack).
- Optionally store one per-user blinded email HMAC to *suggest* linking ("this email may already have an account — sign in with your existing method to link"), always requiring the user to complete an existing-method challenge before merge. Prefer typed verification **codes** over clickable links (WorkOS/Clerk guidance).

**Stage 4 — Elevate EUDI/passkey to recovery + high-assurance anchor.**
- Let a verifiable/**attested** EUDI pseudonym (with proof-of-association) or a passkey serve as the account-recovery and re-linking anchor, tagging the `userId` with a higher `assurance_level`. This delivers "state-verified, yet anonymous" without a PII store.
- **Threshold that would change the plan:** if the ARF finalizes WebAuthn as *optional* and adopts BBS+/anonymous credentials, migrate the EUDI anchor to the ZKP scheme for true unlinkability rather than device-bound WebAuthn attestation.

**Security invariants (enforce always):**
1. No linking without proof of control of an already-linked method.
2. No auto-merge on unverified/self-asserted identifiers.
3. Invalidate sessions/credentials created before verification.
4. Verification capabilities short-lived, single-use, rate-limited.
5. Require explicit user consent at the linking moment.
6. Public pseudonym confers zero ownership.

## Caveats
- **No commercial platform offers a drop-in zero-PII linking model.** All of Auth0/Okta/WorkOS/Stytch/Descope/Clerk/SuperTokens anchor on stored, verified email. HHTTPS is deliberately off the beaten path; it must borrow their *security discipline* (verify-before-link, step-up, consent) while rejecting their *anchor* (stored email).
- **The EUDI pseudonym specification is not final.** Topic E is a non-normative discussion paper (v1.0, Nov 2025), the WebAuthn mandate may become optional, and respected cryptographers argue the current WebAuthn approach does not meet the regulation's own unlinkability requirement. Treat EUDI as a strategically aligned but moving target.
- **Synced vs device-bound passkeys change the UX, not the model:** device-bound passkeys require the user to register one per device, so recovery/anchor planning is essential to avoid lockout.
- **Linking inherently creates a within-HHTTPS join** (multiple methods → one `userId`). This is unavoidable if the same person must be recognized across methods; the privacy win is that the join is keyed on opaque values and, ideally, user-held/user-asserted rather than on real-world PII. This is a residual trust the user places in HHTTPS, and should be disclosed.
