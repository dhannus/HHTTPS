# HHTTPS Governance

How the HHTTPS protocol and reference implementation are governed.

## Mission

> To make humanity provable on the web — without making humans into products.

The HHTTPS protocol exists so that, in an era of increasingly sophisticated AI, real people retain a way to demonstrate that they are real, in their own role, on their own terms.

This means:
- Open source by default
- No commercial control of the protocol
- No surveillance, ever
- European data protection as a baseline, not a feature
- Standards-track inevitability (IETF)

## Decision Making

### Levels of change

| Level | Examples | Process |
|---|---|---|
| **Patch** | Typo fixes, doc clarifications, example updates | Pull request → single maintainer review → merge |
| **Minor** | New role addition, new optional claim, new verification method | Pull request → 14-day public comment → maintainer + ≥1 contributor approval |
| **Major** | Token format change, signing algorithm change, breaking endpoint changes | Pull request → 30-day public comment → maintainer consensus + 6-month migration window for any deployed integrations |

### Public comment

Public comments happen via:
- GitHub issues on `dhannus/HumanProof`
- The HHTTPS mailing list (planned)
- Direct emails to the maintainer

All accepted contributions are recorded in `CHANGELOG.md` with attribution.

## Maintainer

**Currently:** Daniel Hannuschka (daniel.hannuschka@tweakz.de)

The maintainer is responsible for:
- Reviewing pull requests
- Coordinating public discussion
- Cutting releases
- Responding to security disclosures
- Operating the reference issuer at `hhttps.org`

The maintainer **does not have**:
- Veto power over forks
- Control over independent issuer instances
- Privileged status in the protocol itself

## Adding new maintainers

Once the project has 5+ active contributors with >5 merged PRs each, a maintainer council will be formed. Until then, the project operates under benevolent-dictator-for-now governance, with the explicit understanding that contributors may fork at any time without penalty.

## Forking

Forking is **explicitly encouraged**. The reference implementation (`hhttps.org`) is not the protocol — the spec is. Anyone may run an issuer compatible with the spec without permission.

If you fork:
- You may use the name "HHTTPS" provided your implementation conforms to the published spec
- You should publish your `.well-known/hhttps-configuration` and JWKS at predictable URLs
- You should announce your issuer on the public list (when established) for federation

## Funding

The HumanProof Initiative receives **no funding** as of v0.4.1 (May 2026):
- No VC investment
- No tokens (the financial kind)
- No grants accepted yet
- No paid partnerships

If/when funding becomes necessary:
- Public foundations (Open Knowledge Foundation, Mozilla, etc.) — preferred
- Public-sector research grants (BMBF, EU Horizon) — acceptable
- Direct user donations / public-benefit company structure — possible
- VC funding — explicitly **not** pursued, as it would compromise the protocol's neutrality

## Conflicts of Interest

If a contributor has a financial or organizational interest that could influence a protocol change, they MUST disclose it in the PR/issue. The maintainer will weigh this in the decision.

The maintainer's day job and other affiliations are public:
- Daniel Hannuschka — Java developer, employer disclosed in private to inquiries; no overlap with HHTTPS commercial interests

## Trademark

"HumanProof", "HHTTPS", "iamhmn" are claimed by the initiative as descriptive names but no formal trademark has been registered as of 2026-05-10. They may be used freely for:
- Implementations conforming to the spec
- Educational, journalistic, and research mention
- Derivatives clearly marked as such

The initiative reserves the right to register trademarks in the future to protect against bad-faith confusion (e.g. fake issuers claiming to be the canonical one).

## Standardization Path

| Phase | Status | Target |
|---|---|---|
| Internet-Draft (IETF) | In preparation | Q3 2026 |
| Working Group adoption | Not yet | 2027 |
| RFC publication | Not yet | 2028 |

Once the IETF process is initiated, governance shifts partially to the IETF Working Group. The reference implementation continues to be maintained at `hhttps.org` independent of the standardization path.

## Code of Conduct

Be kind. Be specific. Be open to being wrong.

Personal attacks, harassment, and discrimination are not tolerated and will result in a ban from project spaces. If you experience or witness any of these, contact the maintainer.

We follow the [Contributor Covenant](https://www.contributor-covenant.org/) v2.1 in spirit and substance.

## Sustainability

The HHTTPS reference issuer (`hhttps.org`) is run by the maintainer at personal cost as of v0.4.1. Operating costs:
- 1 VPS (Strato Ubuntu 24.04, ~€10/month)
- 3 domains (~€50/year combined)
- TLS certificates (free, Let's Encrypt)
- PostgreSQL on the same VPS (free)

Total: < €200/year.

This is sustainable indefinitely as a hobby project. Scaling to high adoption would require institutional support — which we hope to obtain through public-sector partnership rather than commercial control.

## Contact

- **General**: daniel.hannuschka@tweakz.de
- **Security**: Same address, mark subject `[SECURITY]`
- **Press**: Same address, mark subject `[PRESS]`
- **Institutional partnerships**: Same address, mark subject `[PARTNERSHIP]`

We aim to respond within 7 days; security issues within 48 hours.

---

*This governance document is itself open to revision via the same process. Changes since v0.4.1 are tracked in this file's git history.*
