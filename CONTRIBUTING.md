# Contributing to HHTTPS / HHTTPS

Thanks for considering a contribution. HHTTPS is a civic-tech project — open to everyone, no commercial gatekeeping.

## Quick guide

| What you want to do | What to do |
|---|---|
| Report a bug | [Open an issue](https://github.com/dhannus/HHTTPS/issues/new) |
| Suggest a feature | Open an issue first, discuss before coding |
| Fix a typo or docs error | Pull request — no issue needed |
| Add a new role to the spec | Open an issue with reasoning; 14-day public discussion before PR |
| Add support for a new framework (Ruby, Go, Rust SDK) | PR welcome — follow existing examples |
| Translate the site to a new language | PR welcome — keep DE/EN as reference |
| Report a security issue | Email daniel.hannuschka@tweakz.de with subject `[SECURITY]` — do **not** open public issue |

## Decision levels

- **Patch** (typo, doc fix, example clarification): single maintainer review → merge.
- **Minor** (new role, new verification method, new SDK): 14-day public comment → maintainer + 1 contributor approval.
- **Major** (token format, signing algorithm, breaking changes): 30-day public comment → 6-month migration window.

See [`docs/governance.md`](docs/governance.md) for full process.

## Local development

### Server

```bash
git clone https://github.com/dhannus/HHTTPS.git
cd HHTTPS/server
bash scripts/install-pg.sh     # sets up PostgreSQL user + db locally
npm install
cp .env.example .env           # edit DB_PASSWORD with what install-pg.sh printed; set HHTTPS_VERIFICATION_PEPPER
npm run dev                    # node --watch on port 3000
```

Open <http://localhost:3000>. Without SMTP, add `EMAIL_DEV_MODE=1` to `.env` so the verification code is returned by `/hhttps/email/send` (development only — ignored in production).

The package manager is **npm**. `pnpm` runs the same scripts if you prefer it, but please don't commit a `pnpm-lock.yaml` (`server/package-lock.json` is currently git-ignored as well).

### Browser extension

```bash
# In Chrome:
# 1. Visit chrome://extensions
# 2. Enable "Developer mode" top-right
# 3. "Load unpacked" → select extension/ folder
```

Point the extension at your local server by editing `extension/background.js`:
```js
const DEFAULT_ISSUER = 'http://localhost:3000';
```

### Marketing site

```bash
cd sites
python3 -m http.server 8000
# Open http://localhost:8000/iamhmn.html
```

### Examples

Each example has its own README. Quick sample:

```bash
cd examples/express-comments
npm install
node server.js
```

## Code style

- **JavaScript / Node**: ES Modules. Two-space indent. Async/await preferred over `.then()`.
- **Python**: PEP 8. `black` formatter recommended.
- **PHP**: PSR-12.
- **HTML/CSS**: 2-space indent. Use the existing pastel palette variables in `:root`.
- **SQL**: lowercase keywords, snake_case identifiers.

## Commit messages

Use conventional commits where it makes sense:

```
feat(roles): add notary verification method
fix(extension): correct JWKS cache TTL
docs(spec): clarify refresh token lifetime
chore(deps): bump express to 4.19.2
```

But don't agonize over format — clarity over convention.

## Tests and lint (gates)

The server has a test suite based on Node's built-in runner (`node --test`, no extra framework) and an ESLint 9 flat config. Both are gates: a PR must pass

```bash
cd server
npm run lint                            # 0 errors (warnings are tolerated in legacy code)
TEST_PG_HOST=<host-or-socket-dir> npm test
```

- `test/unit/` — pure functions (`identity.js`, mail template, sign-in page). Run without a database.
- `test/integration/` — boot `server.js` as a child process against a local PostgreSQL (`TEST_PG_HOST`, database/role `hhttps`, password `x` or `trust`) and talk HTTP. They are **skipped** when `TEST_PG_HOST` is unset, so `npm test` without Postgres only runs the unit tests. Use a throwaway database; the tests write real rows. See the README section *Tests lokal ausführen* for the full setup.

If you add non-trivial logic, add a test next to the existing ones (`*.test.mjs`). Integration tests should create their own sessions/addresses and clean up after themselves.

## Pull requests

1. Fork → branch → commits → PR against `main`.
2. Describe **what** changes and **why** in the PR body.
3. Link to any related issues.
4. Ensure your changes don't break the existing `examples/`.
5. `npm run lint` and `npm test` pass (see *Tests and lint*).
6. Update `CHANGELOG.md` under `## [Unreleased]` (create section if absent).

## Code of conduct

Be kind. Be specific. Be open to being wrong.

Personal attacks, harassment, or discrimination are not tolerated and will result in a ban from project spaces. Report incidents to daniel.hannuschka@tweakz.de.

We follow the spirit of the [Contributor Covenant](https://www.contributor-covenant.org/) v2.1.

## Recognition

All contributors are credited in `CHANGELOG.md` and on the project site once we have a contributors page. There's no contributor agreement (CLA) — your contributions are simply licensed under the same EUPL-1.2 as the rest of the project.

## Questions?

Open a [GitHub Discussion](https://github.com/dhannus/HHTTPS/discussions) or email daniel.hannuschka@tweakz.de.

Thanks for helping make the internet a place where real humans can be recognized again.
