# Contributing to HumanProof / HHTTPS

Thanks for considering a contribution. HHTTPS is a civic-tech project — open to everyone, no commercial gatekeeping.

## Quick guide

| What you want to do | What to do |
|---|---|
| Report a bug | [Open an issue](https://github.com/dhannus/HumanProof/issues/new) |
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
git clone https://github.com/dhannus/HumanProof.git
cd HumanProof/server
bash scripts/install-pg.sh     # sets up PostgreSQL user + db locally
npm install
cp .env.example .env           # edit DB_PASSWORD with what install-pg.sh printed
npm run dev                    # nodemon on port 3000
```

Open <http://localhost:3000>.

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

## Tests

Currently the project has no formal test suite (it's still small and the spec is the test). If you're adding non-trivial logic, please include manual test commands in your PR description.

Adding a proper Jest/Vitest test suite would be a welcome contribution.

## Pull requests

1. Fork → branch → commits → PR against `main`.
2. Describe **what** changes and **why** in the PR body.
3. Link to any related issues.
4. Ensure your changes don't break the existing `examples/`.
5. Update `CHANGELOG.md` under `## [Unreleased]` (create section if absent).

## Code of conduct

Be kind. Be specific. Be open to being wrong.

Personal attacks, harassment, or discrimination are not tolerated and will result in a ban from project spaces. Report incidents to daniel.hannuschka@tweakz.de.

We follow the spirit of the [Contributor Covenant](https://www.contributor-covenant.org/) v2.1.

## Recognition

All contributors are credited in `CHANGELOG.md` and on the project site once we have a contributors page. There's no contributor agreement (CLA) — your contributions are simply licensed under the same EUPL-1.2 as the rest of the project.

## Questions?

Open a [GitHub Discussion](https://github.com/dhannus/HumanProof/discussions) or email daniel.hannuschka@tweakz.de.

Thanks for helping make the internet a place where real humans can be recognized again.
