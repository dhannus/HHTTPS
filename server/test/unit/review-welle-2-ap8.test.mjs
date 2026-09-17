// Review Welle 2 / AP8 — frontend, sites and browser extension.
//
// There is no DOM and no browser here: the pages' inline scripts and the
// extension's scripts are read as text. Where a finding is about a pure
// function (returnTo validation, the identity id) the function is cut out of
// the source and executed for real; where it is about wiring (which element
// is polled, which body is sent) the source is checked with regexes, exactly
// like signin-page.test.mjs / legacy-pages.test.mjs already do.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '../../..');
const read = (rel) => readFileSync(join(repo, rel), 'utf8');

const SIGNIN    = read('server/public/index.html');
const LANDING   = read('sites/hhttps.html');
const BG        = read('extension/background.js');
const CONTENT   = read('extension/content-universal.js');
const POPUP     = read('extension/popup.js');

/** Concatenated inline (non-src) <script> bodies of a page. */
function scriptText(html) {
  const re = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g;
  const out = [];
  let m;
  while ((m = re.exec(html))) out.push(m[2]);
  assert.ok(out.length > 0, 'page has at least one inline script');
  return out.join('\n');
}

/** Source of `[async] function <name>(` … up to its matching closing brace. */
function fnSource(js, name) {
  const re = new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\(`);
  const m = js.match(re);
  assert.ok(m, `${name}() is defined`);
  let i = js.indexOf('{', m.index);
  let depth = 0;
  for (let j = i; j < js.length; j++) {
    if (js[j] === '{') depth++;
    else if (js[j] === '}' && --depth === 0) return js.slice(m.index, j + 1);
  }
  assert.fail(`${name}() has no matching closing brace`);
}

// ── AP8-03 (#63): the workload page called routes that do not exist ─────────
test('AP8-03: the dead workload page is gone and nothing links to it', () => {
  assert.equal(existsSync(join(repo, 'server/public/workload.html')), false,
    'server/public/workload.html no longer exists');
  for (const [name, src] of [['sign-in page', SIGNIN], ['landing page', LANDING]]) {
    assert.doesNotMatch(src, /workload\.html/, `${name} does not link the workload page`);
    assert.doesNotMatch(src, /machine\/workload\//, `${name} does not call /hhttps/machine/workload/*`);
  }
});

// ── AP8-04 (#72) + AP8-05 (#80): extension identity ids ────────────────────
test('AP8-04: storeIdentity() returns the enriched identity and the caller schedules on it', () => {
  const store = fnSource(BG, 'storeIdentity');
  assert.match(store, /return enriched;/, 'storeIdentity() returns the stored (enriched) object');
  const captured = BG.match(/storeIdentity\(msg\.identity\)[\s\S]{0,220}?\);/);
  assert.ok(captured, 'the IDENTITY_CAPTURED branch calls storeIdentity(msg.identity)');
  assert.match(captured[0], /\.then\(\s*\(\s*stored\s*\)\s*=>/,
    'the then() receives the stored identity');
  assert.match(captured[0], /scheduleRefreshFor\(stored\)/,
    'scheduleRefreshFor() is called with the STORED identity, not the raw page object');
  assert.doesNotMatch(captured[0], /scheduleRefreshFor\(msg\.identity\)/,
    'the raw page object (which has no id) is not scheduled any more');
});

/** computeIdentityId() + its decodeJwtPayload() dependency, executed for real. */
function loadComputeIdentityId() {
  const src = `${fnSource(BG, 'decodeJwtPayload')}\n${fnSource(BG, 'computeIdentityId')}\nreturn computeIdentityId;`;
  return new Function(src)();
}
const jwt = (payload) =>
  'eyJhbGciOiJIUzI1NiJ9.' +
  Buffer.from(JSON.stringify(payload)).toString('base64url') + '.sig';

test('AP8-05: human and machine identities no longer collapse onto one id', () => {
  const computeIdentityId = loadComputeIdentityId();
  const human = {
    issuer: 'hhttps://hhttps.org', role: null,
    token: jwt({ sub: 'human-verified', actorType: 'human', userId: 'u-123' })
  };
  const bot = {
    issuer: 'hhttps://hhttps.org', role: null, actorType: 'bot',
    token: jwt({ sub: 'machine', actorType: 'bot', operatorId: 'op-9' })
  };
  const humanId = computeIdentityId(human);
  const botId   = computeIdentityId(bot);
  assert.notEqual(humanId, botId, 'a human and a bot get different ids');
  assert.doesNotMatch(humanId, /unknown/, 'the human id is not the old issuer#unknown');
  assert.doesNotMatch(botId,   /unknown/, 'the bot id is not the old issuer#unknown');

  // Two different humans stay apart …
  const other = { ...human, token: jwt({ sub: 'human-verified', actorType: 'human', userId: 'u-456' }) };
  assert.notEqual(computeIdentityId(other), humanId, 'two users get two ids');

  // … and a re-issued token for the SAME user replaces its entry.
  const reissued = { ...human, token: jwt({ sub: 'human-verified', actorType: 'human', userId: 'u-123', jti: 'new' }) };
  assert.equal(computeIdentityId(reissued), humanId, 're-issuance keeps the same id');
});

// ── AP8-06 (#90): a consumed e-mail code is not re-sent ────────────────────
test('AP8-06: machineRun() confirms the code once and shows the server detail', () => {
  const js = scriptText(SIGNIN);
  const run = fnSource(js, 'machineRun');
  assert.match(run, /if\(MACHINE_STEP==='code'\)\{/,
    'confirm-code only runs while the step is still "code"');
  assert.match(run, /MACHINE_STEP='confirmed'/,
    'a successful confirm-code advances the step');
  assert.doesNotMatch(run, /if\(!r\.ok\)throw 0/,
    'register/token failures no longer throw away the server answer');
  assert.match(run, /d\.detail\|\|d\.error/,
    'the server error detail is surfaced');
});

// ── AP8-07 (#98): polling with terminal states, backoff, no double start ───
test('AP8-07: one poller with terminal states, growing interval and a generation counter', () => {
  const js = scriptText(SIGNIN);
  const poll = fnSource(js, 'pollStatus');
  assert.match(poll, /POLL_GEN\[kind\]!==gen/, 'a newer run cancels the older one');
  assert.match(poll, /d\.status==='failed'\|\|d\.status==='expired'/, 'failed/expired end the loop');
  assert.match(poll, /r\.status>=400/, 'an HTTP error ends the loop');
  assert.match(poll, /document\.hidden/, 'a hidden tab does not burn the poll budget');
  assert.match(poll, /delay=Math\.min\(/, 'the interval grows (backoff)');
  assert.match(poll, /poll\.timeout/, 'the budget running out is reported');

  for (const fn of ['pollEudi', 'pollAge', 'pollGithub']) {
    const body = fnSource(js, fn);
    assert.match(body, /return pollStatus\(/, `${fn}() delegates to the shared poller`);
    assert.doesNotMatch(body, /for\(let i=0;i<80;i\+\+\)/, `${fn}() has no hand-rolled loop left`);
  }
  assert.match(SIGNIN, /id="githubHint"/, 'the GitHub panel has a hint element to report into');
  for (const key of ['poll.failed', 'poll.expired', 'poll.timeout']) {
    assert.ok(SIGNIN.split(`'${key}'`).length - 1 >= 2, `'${key}' is translated in both languages`);
  }
});

// ── AP8-08 (#108): a cached hhttps_uid must not skip the e-mail step ───────
test('AP8-08: no auto-jump to the passkey step, and role/declare handles 403', () => {
  const js = scriptText(LANDING);
  const init = js.match(/if \(userId\) \{[\s\S]*?\n\}/);
  assert.ok(init, 'the init block for a cached userId exists');
  assert.doesNotMatch(init[0], /setStep\(2\)/,
    'a cached hhttps_uid no longer jumps straight to the passkey login');

  const declare = fnSource(js, 'doDeclarRole');
  assert.match(declare, /r\.status === 403 && d\.error === 'email_verification_required'/,
    'doDeclarRole() recognises the e-mail gate');
  assert.match(declare, /setStep\(0\)/, 'a 403 sends the user back to the e-mail step');
});

// ── AP8-09 (#117): the ignored local role catalogue is not published ───────
test('AP8-09: role/declare sends no role, and only server values are published', () => {
  const js = scriptText(LANDING);
  const declare = fnSource(js, 'doDeclarRole');
  const body = declare.match(/body: JSON\.stringify\(\{[^)]*\}\)/);
  assert.ok(body, 'doDeclarRole() sends a JSON body');
  assert.doesNotMatch(body[0], /role: selRole/, 'the locally picked role is not sent any more');
  assert.doesNotMatch(body[0], /verificationMethod/, 'the ignored verificationMethod is not sent');
  assert.match(body[0], /verificationData/, 'verificationData (pseudonym) is still sent');

  const publish = declare.slice(declare.indexOf('publishIdentity({'));
  assert.doesNotMatch(publish, /role:\s*selRole/, 'the published role is not the local pick');
  assert.match(publish, /role:\s*d\.role\?\./, 'the published role comes from the server answer');
  assert.match(publish, /roleLabel:\s*d\.role\?\.label/, 'the label comes from the server answer');
});

// ── AP8-17 (#151): returnTo is same-origin only ────────────────────────────
function loadResolveReturnTo(html) {
  const src = `${fnSource(scriptText(html), 'resolveReturnTo')}\nreturn resolveReturnTo;`;
  return new Function(src)();
}

for (const [name, html] of [['sign-in page', SIGNIN], ['landing page', LANDING]]) {
  test(`AP8-17: ${name} only accepts a same-origin returnTo`, () => {
    const resolveReturnTo = loadResolveReturnTo(html);
    const origin = 'https://hhttps.org';

    // Accepted: relative paths and same-origin absolute URLs.
    assert.equal(resolveReturnTo('/oauth/consent?x=1', origin).href,
      'https://hhttps.org/oauth/consent?x=1');
    assert.equal(resolveReturnTo('https://hhttps.org/oauth/consent', origin).href,
      'https://hhttps.org/oauth/consent');

    // Rejected: every other host, protocol-relative URLs and dangerous schemes.
    for (const bad of [
      'https://evil.example/steal',
      'http://hhttps.org/oauth/consent',        // different origin (scheme)
      'https://hhttps.org.evil.example/',
      '//evil.example/steal',
      'javascript:alert(1)',
      'JavaScript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'file:///etc/passwd',
      '', null, undefined, 42
    ]) {
      assert.equal(resolveReturnTo(bad, origin), null, `rejected: ${String(bad)}`);
    }
  });
}

test('AP8-17: no page redirects to the raw returnTo parameter any more', () => {
  for (const [name, html] of [['sign-in page', SIGNIN], ['landing page', LANDING]]) {
    const js = scriptText(html);
    assert.doesNotMatch(js, /window\.location\.href\s*=\s*returnTo\b/,
      `${name} never assigns the unvalidated returnTo`);
  }
});

// ── AP8-19 (#167): page meta tags are a claim, not a verification ──────────
test('AP8-19: meta-derived page state is marked as claimed and rendered neutrally', () => {
  const meta = fnSource(CONTENT, 'readMetaTags');
  assert.match(meta, /claimed:\s*true/, 'meta tags are flagged as a claim');
  const headers = CONTENT.match(/extractHeaders[\s\S]{0,900}?claimed:\s*false/);
  assert.ok(headers, 'the header-derived state is flagged as not-claimed');
  assert.match(CONTENT, /const base = \(reported && reported\.status\) \? reported/,
    'the server-sent state wins over the page\'s own meta tags');
  assert.match(POPUP, /if \(state\.claimed\)/, 'the popup branches on the claim flag');
  assert.match(POPUP, /pageClaimsSupport/, 'a claimed state gets the neutral wording');
  const verified = POPUP.match(/state\.status === 'verified'[\s\S]{0,200}/);
  assert.ok(verified, 'the verified rendering still exists for checked states');
  for (const lang of ['de', 'en']) {
    const msgs = JSON.parse(read(`extension/_locales/${lang}/messages.json`));
    assert.ok(msgs.pageClaimsSupport?.message, `pageClaimsSupport is translated (${lang})`);
    assert.ok(msgs.sealUnavailable?.message,   `sealUnavailable is translated (${lang})`);
  }
});

// ── AP8-20 (#173): the refresh token never leaves the issuer origin ────────
for (const [name, html] of [['sign-in page', SIGNIN], ['landing page', LANDING]]) {
  test(`AP8-20: ${name} stores a refresh token only on the issuer origin`, () => {
    const js = scriptText(html);
    // isIssuerOrigin() reads window.location.hostname — provide a stub.
    const hosts = js.match(/const ISSUER_HOSTS=\[[^\]]*\];/);
    assert.ok(hosts, 'the issuer host list is defined');
    const factory = new Function('window', `
      ${hosts[0]}
      ${fnSource(js, 'isIssuerOrigin')}
      ${fnSource(js, 'storableRefreshToken')}
      return storableRefreshToken;`);
    const on = (host) => factory({ location: { hostname: host } });

    assert.equal(on('hhttps.org')('rt-1', null), 'rt-1', 'kept on the issuer origin');
    assert.equal(on('localhost')('rt-1', null), 'rt-1', 'kept in local development');
    assert.equal(on('mirror.example')('rt-1', null), null, 'dropped on a foreign origin');
    assert.equal(on('hhttps.org')('rt-1', new Date(Date.now() - 1000).toISOString()), null,
      'an already expired refresh token is dropped');
    assert.equal(on('hhttps.org')(null, null), null, 'no token, no storage');

    assert.match(js, /refreshToken:\s*storableRefreshToken\(/,
      'publishIdentity() runs the refresh token through the guard');
  });
}

// ── AP8-25 (#194): the cheap text check runs before the DOM walks ──────────
test('AP8-25: the TreeWalker filter checks the text before calling closest()', () => {
  const walker = fnSource(CONTENT, 'createMarkerWalker');
  const textAt    = walker.indexOf("t.includes('#hhttps:s:')");
  const closestAt = walker.indexOf('parentElement.closest(');
  assert.ok(textAt > 0 && closestAt > 0, 'both checks are present');
  assert.ok(textAt < closestAt, 'the substring check comes first');
});

// ── AP8-26 (#201): mutations are batched into an idle slot ─────────────────
test('AP8-26: the MutationObserver queues nodes instead of scanning inline', () => {
  const watch = fnSource(CONTENT, 'watchDocument');
  assert.match(watch, /requestIdleCallback/, 'the queue is drained in an idle slot');
  assert.match(watch, /pending\.push\(node\)/, 'added nodes are queued');
  assert.match(watch, /isOwnSealNode\(node\)/, 'our own seal nodes never enter the queue');
  const observerBody = watch.slice(watch.indexOf('new MutationObserver'));
  assert.doesNotMatch(observerBody.slice(0, observerBody.indexOf('observer.observe')),
    /scanForSignatures\(node\)/,
    'scanForSignatures() is no longer called from inside the observer callback');
  assert.match(fnSource(CONTENT, 'drain'), /scanForSignatures\(node\)/,
    'the drain step does the actual scanning');
});

// ── AP8-27 (#206): batch verify chunks at 100 and caches failures ──────────
test('AP8-27: batchVerifySlugs() splits into chunks of at most 100', async () => {
  const src = fnSource(CONTENT, 'batchVerifySlugs');
  assert.match(src, /BATCH_MAX/, 'the chunk size is applied');
  assert.match(CONTENT, /const BATCH_MAX = 100;/, 'the chunk size matches the server limit');

  const chunks = [];
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const run = new AsyncFunction('BATCH_MAX', 'batchVerifyChunk', `${src}\nreturn batchVerifySlugs;`)
    .call(null, 100, async (c) => { chunks.push(c); });
  const batchVerifySlugs = await run;
  const slugs = Array.from({ length: 250 }, (_, i) => `hp-${String(i).padStart(8, '0')}`);
  await batchVerifySlugs(slugs);
  assert.equal(chunks.length, 3, '250 slugs become 3 requests');
  assert.deepEqual(chunks.map((c) => c.length), [100, 100, 50]);
  assert.equal(new Set(chunks.flat()).size, 250, 'no slug is lost or duplicated');

  chunks.length = 0;
  await batchVerifySlugs(['hp-00000001', 'hp-00000001', 'hp-00000002']);
  assert.deepEqual(chunks, [['hp-00000001', 'hp-00000002']], 'duplicates are collapsed');
});

test('AP8-27: a failed batch is cached and the seals leave the pending state', () => {
  assert.match(CONTENT, /const ERROR_TTL = /, 'failures get their own (short) TTL');
  assert.match(CONTENT, /\(cached\.ttl \|\| CACHE_TTL\)/, 'the cache honours a per-entry TTL');
  const fail = fnSource(CONTENT, 'cacheFailure');
  assert.match(fail, /error: true/, 'the failure is recorded in the cache');
  assert.match(fail, /ttl: ERROR_TTL/, 'a failure expires quickly so the next scan retries');
  assert.match(fail, /renderSealUnavailable/, 'the pending seals are re-rendered');
  const render = fnSource(CONTENT, 'renderSealUnavailable');
  assert.match(render, /data-state', 'unavailable'/, 'an unreachable server is not shown as invalid');
  const batch = fnSource(CONTENT, 'batchVerifyChunk');
  assert.ok((batch.match(/cacheFailure\(/g) || []).length >= 2,
    'both the HTTP error and the thrown error cache the failure');
});

// ── AP1-06 (client side): the card issuer's reserved-profession matching ────
// server/public/iamhmn-card-issuer.js keeps its own copy of the reserved
// stems. It used a plain includes() and therefore produced exactly the false
// positives that were fixed server side in roles.taxonomy.js: English words
// now match on word boundaries, German compounds still as substrings, a short
// exclusion list is blanked out first and the longest match wins.
test('AP1-06: the card issuer matches reserved professions like the server does', () => {
  const src = read('server/public/iamhmn-card-issuer.js');
  const head = src.slice(0, src.indexOf('const T = {'));
  assert.doesNotMatch(head, /RESERVED_STEMS\.find\(st=>n\.includes\(st\)\)/,
    'the naive includes() matcher is gone');
  const reservedHit = new Function(`${head}\nreturn reservedHit;`)();

  for (const reserved of [
    'Ärztin', 'Fachärztin für Innere Medizin', 'Rechtsanwältin', 'Krankenpfleger',
    'Altenpflegerin', 'Staatsanwältin', 'Notar', 'Polizistin', 'Richterin',
    'nurse', 'Registered Nurse', 'judge', 'police officer', 'attorney at law'
  ]) {
    assert.ok(reservedHit(reserved), `reserved: ${reserved}`);
  }

  for (const free of [
    'nursery teacher', 'doctoral student', 'Tierpfleger', 'Tischler',
    'carpenter', 'software developer', 'Einrichter', ''
  ]) {
    assert.equal(reservedHit(free), null, `not reserved: ${free}`);
  }

  // Longest match wins — the same tie-break the server uses.
  assert.equal(reservedHit('Staatsanwältin'), 'staatsanwaelt', 'prosecutor beats "anwaelt"');
  assert.equal(reservedHit('Notarzt'), 'notarzt', 'emergency doctor beats "notar"');
});
