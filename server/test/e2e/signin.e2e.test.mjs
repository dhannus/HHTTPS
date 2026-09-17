// #25: browser end-to-end tests for the sign-in page (public/index.html) with
// Playwright + Chromium. The server is booted by the integration harness
// (startServer, TEST_PG_HOST); the page is served from `/` (static public/).
// The e-mail code is NOT fetched via the API — the browser's own
// /hhttps/email/send response is intercepted and `devCode` read from it.
//
// The page loads without network: every non-local request is answered by
// page.route — the unpkg @simplewebauthn/browser script with the REAL bundle
// of the pinned version (devDependency, same 9.0.1 as index.html), everything
// else (qrcode-generator, fonts) with an empty body. The passkey tests use
// Chromium's virtual authenticator (CDP WebAuthn domain).
//
// Run with: TEST_PG_HOST=/var/lib/pgtest npm run test:e2e
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { pgAvailable, startServer } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { createTracker, freshEmail, verifyEmail } from '../helpers/identity-flow.mjs';

const skip = pgAvailable() ? false : 'TEST_PG_HOST not set';
const CHROMIUM_FALLBACK = '/opt/pw-browsers/chromium';

const SWA_BUNDLE = readFileSync(
  fileURLToPath(new URL('../../node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js', import.meta.url)), 'utf8');

let srv, browser;
const track = createTracker();
const userIds = new Set();

async function launch() {
  try { return await chromium.launch(); } catch (e) {
    try { return await chromium.launch({ executablePath: CHROMIUM_FALLBACK }); } catch { throw e; }
  }
}

/** New context with every non-local request stubbed; returns { context, page }. */
async function openPage(path = '/') {
  const context = await browser.newContext();
  await context.route((url) => url.origin !== srv.baseUrl, (route) => {
    const body = /unpkg\.com\/@simplewebauthn\/browser@9\.0\.1\//.test(route.request().url()) ? SWA_BUNDLE : '';
    return route.fulfill({ status: 200, contentType: 'application/javascript', body });
  });
  const page = await context.newPage();
  page.on('response', (r) => {
    // Track rows the browser creates so cleanup removes them (W-6).
    if (r.url().endsWith('/hhttps/session/start') || r.url().endsWith('/hhttps/email/confirm-code')) {
      r.json().then((j) => { track.add({ sessionId: j.sessionId, userId: j.userId }); if (j.userId) userIds.add(j.userId); }).catch(() => {});
    }
  });
  await page.goto(srv.baseUrl + path);
  return { context, page };
}

const isDisabled = (page, id) => page.locator('#' + id).isDisabled();

/** Email flow in the browser; returns the devCode-confirmed pseudonym text. */
async function confirmEmailInBrowser(page, email, pseudonym) {
  await page.click('#m-email');
  await page.fill('#emailInput', email);
  if (pseudonym) await page.fill('#pseudoInput', pseudonym);
  const [sendRes] = await Promise.all([
    page.waitForResponse((r) => r.url().includes('/hhttps/email/send')),
    page.click('#emailSend'),
  ]);
  track.add({ email });
  const sent = await sendRes.json();
  const [confirmRes] = await Promise.all([
    page.waitForResponse((r) => r.url().includes('/hhttps/email/confirm-code')),
    (async () => {
      const code = String(sent.devCode);
      await page.fill('#emailCode', code.slice(0, 3) + ' ' + code.slice(3)); // K-7: "482 913"
      await page.click('#emailVerify');
    })(),
  ]);
  return { sendRes, sent, confirmRes, confirmed: await confirmRes.json() };
}

/** Attaches a CTAP2 platform authenticator to the page; returns { cdp, authenticatorId }. */
async function addVirtualAuthenticator(page, credentials = []) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
    },
  });
  for (const credential of credentials) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return { cdp, authenticatorId };
}

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '' } });
  browser = await launch();
});

test.after(async () => {
  await browser?.close();
  await srv?.stop();
  if (skip) return;
  if (userIds.size) await sql('DELETE FROM credentials WHERE user_id = ANY($1)', [[...userIds]]);
  await track.cleanup();
  await closeDb();
});

test('AK-14: on load passkey/eudi/github/age are disabled, email/machine enabled, email-first hint visible', { skip }, async () => {
  const { context, page } = await openPage();
  try {
    for (const id of ['m-passkey', 'm-eudi', 'm-github', 'm-age']) assert.equal(await isDisabled(page, id), true, `#${id} disabled`);
    for (const id of ['m-email', 'm-machine']) assert.equal(await isDisabled(page, id), false, `#${id} enabled`);
    assert.equal(await page.locator('#emailFirstHint').isVisible(), true, '#emailFirstHint visible');
    assert.notEqual((await page.locator('#emailFirstHint').textContent()).trim(), '', 'hint carries i18n text');
  } finally { await context.close(); }
});

test('AK-15/AK-14: email panel → code with a space → confirm unlocks the methods and shows the pseudonym', { skip }, async () => {
  const { context, page } = await openPage();
  try {
    const { sendRes, sent, confirmRes, confirmed } = await confirmEmailInBrowser(page, freshEmail('e2e-ak15'), 'Anna');
    assert.equal(sendRes.status(), 200);
    assert.equal(sendRes.request().postDataJSON().pseudonym, 'Anna', '/email/send body carries pseudonym');
    assert.match(String(sent.devCode), /^\d{6}$/, 'dev mode delivers a 6-digit code');
    assert.equal(confirmRes.status(), 200, JSON.stringify(confirmed));
    assert.equal(confirmed.pseudonym, 'Anna');

    await page.waitForSelector('#m-passkey:not([disabled])');
    for (const id of ['m-passkey', 'm-eudi', 'm-github', 'm-age']) assert.equal(await isDisabled(page, id), false, `#${id} unlocked`);
    assert.equal(await page.locator('#emailFirstHint').isHidden(), true, '#emailFirstHint hidden');
    assert.match(await page.locator('#st-email').textContent(), /Anna/, '#st-email shows the pseudonym');
    assert.equal(await page.locator('#st-email .check').count(), 1, 'check mark rendered');
  } finally { await context.close(); }
});

test('K-9/AK-14: ?email_verify=success&session=…&pseudonym=… unlocks the methods and cleans the URL', { skip }, async () => {
  const { sessionId } = await verifyEmail(srv, freshEmail('e2e-k9'), 'iamhmn_test', track);
  const { context, page } = await openPage(`/?email_verify=success&session=${encodeURIComponent(sessionId)}&pseudonym=iamhmn_test`);
  try {
    await page.waitForSelector('#m-passkey:not([disabled])');
    for (const id of ['m-passkey', 'm-eudi', 'm-github', 'm-age']) assert.equal(await isDisabled(page, id), false, `#${id} unlocked`);
    assert.equal(await page.locator('#emailFirstHint').isHidden(), true);
    assert.match(await page.locator('#st-email').textContent(), /iamhmn_test/);
    const url = new URL(page.url());
    assert.equal(url.search, '', 'query parameters removed');
    assert.equal(url.pathname, '/');
  } finally { await context.close(); }
});

test('AK-31/AK-32: ?login_hint=…&pseudonym=…&returnTo=… pre-fills the email panel, auto-sends the code once and keeps returnTo', { skip }, async () => {
  const email = freshEmail('e2e-hint');
  const returnTo = 'https://example.org/cb';
  const context = await browser.newContext();
  await context.route((url) => url.origin !== srv.baseUrl, (route) => {
    const body = /unpkg\.com\/@simplewebauthn\/browser@9\.0\.1\//.test(route.request().url()) ? SWA_BUNDLE : '';
    return route.fulfill({ status: 200, contentType: 'application/javascript', body });
  });
  const page = await context.newPage();
  page.on('response', (r) => {
    if (r.url().endsWith('/hhttps/session/start') || r.url().endsWith('/hhttps/email/confirm-code')) {
      r.json().then((j) => { track.add({ sessionId: j.sessionId, userId: j.userId }); if (j.userId) userIds.add(j.userId); }).catch(() => {});
    }
  });
  try {
    const sends = [];
    page.on('request', (r) => { if (r.url().includes('/hhttps/email/send')) sends.push(r.postDataJSON()); });
    const [sendRes] = await Promise.all([
      page.waitForResponse((r) => r.url().includes('/hhttps/email/send')),
      page.goto(`${srv.baseUrl}/?login_hint=${encodeURIComponent(email)}&pseudonym=Anna&returnTo=${encodeURIComponent(returnTo)}`),
    ]);
    track.add({ email });
    assert.equal(sendRes.status(), 200, await sendRes.text());
    const sent = await sendRes.json();
    assert.equal(await page.locator('#panel-email').isVisible(), true, 'email panel open');
    assert.equal(await page.inputValue('#emailInput'), email, '#emailInput pre-filled');
    assert.equal(await page.inputValue('#pseudoInput'), 'Anna', '#pseudoInput pre-filled');
    assert.equal(sends.length, 1, 'exactly one /email/send');
    assert.equal(sends[0].email, email);
    assert.equal(sends[0].pseudonym, 'Anna', '/email/send body carries pseudonym');
    await page.waitForSelector('#emailCodeRow:not(.hidden)');
    assert.equal(await page.locator('#emailCodeRow').isVisible(), true, '#emailCodeRow visible');
    const url = new URL(page.url());
    assert.equal(url.searchParams.get('returnTo'), returnTo, 'returnTo kept');
    assert.equal(url.searchParams.has('login_hint'), false, 'login_hint removed');
    assert.equal(url.searchParams.has('pseudonym'), false, 'pseudonym removed');

    const [confirmRes] = await Promise.all([
      page.waitForResponse((r) => r.url().includes('/hhttps/email/confirm-code')),
      (async () => { await page.fill('#emailCode', String(sent.devCode)); await page.click('#emailVerify'); })(),
    ]);
    assert.equal(confirmRes.status(), 200, await confirmRes.text());
    assert.equal((await confirmRes.json()).pseudonym, 'Anna');
    await page.waitForSelector('#m-passkey:not([disabled])');
    for (const id of ['m-passkey', 'm-eudi', 'm-github', 'm-age']) assert.equal(await isDisabled(page, id), false, `#${id} unlocked`);
    assert.equal(sends.length, 1, 'still exactly one /email/send');
  } finally { await context.close(); }
});

test('passkey: register + login with the virtual authenticator, then K-4 login again without re-registration', { skip }, async (t) => {
  const email = freshEmail('e2e-passkey');
  let credentials, userHandle, userId;

  // First run: email → passkey (register/finish + auth/finish).
  {
    const { context, page } = await openPage();
    try {
      const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
      const { confirmRes, confirmed } = await confirmEmailInBrowser(page, email, 'Pia');
      assert.equal(confirmRes.status(), 200);
      await page.waitForSelector('#m-passkey:not([disabled])');
      await page.click('#m-passkey');
      const calls = [];
      page.on('response', (r) => { if (r.url().includes('/hhttps/webauthn/')) calls.push(new URL(r.url()).pathname + ' ' + r.status()); });
      const [finish] = await Promise.all([
        page.waitForResponse((r) => r.url().includes('/hhttps/webauthn/auth/finish')),
        page.click('#passkeyGo'),
      ]);
      assert.equal(finish.status(), 200, await finish.text());
      await page.waitForSelector('#st-passkey .check', { state: 'attached' });
      assert.ok(calls.includes('/hhttps/webauthn/register/finish 200'), `registration happened: ${calls.join(', ')}`);
      // AP3-01: the merged passkey session must still count as e-mail-verified —
      // the very next step of the page (token issue) used to answer 403.
      const [declare] = await Promise.all([
        page.waitForResponse((r) => r.url().includes('/hhttps/role/declare')),
        page.click('#issueBtn'),
      ]);
      assert.equal(declare.status(), 200, `role/declare after passkey: ${await declare.text()}`);
      const declared = await declare.json();
      assert.ok(declared.hhttps?.verifiedMethods?.includes('email') && declared.hhttps?.verifiedMethods?.includes('passkey'),
        `token carries email + passkey: ${JSON.stringify(declared.hhttps?.verifiedMethods)}`);
      ({ credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId }));
      assert.equal(credentials.length, 1, 'one credential on the authenticator');
      userHandle = Buffer.from(credentials[0].userHandle || '', 'base64').toString('utf8');
      userId = confirmed.userId;
    } finally { await context.close(); }
  }

  // Second run (K-4): fresh context, same authenticator credential, same email
  // → the page must skip registration and log in via auth/start+finish.
  {
    const { context, page } = await openPage();
    try {
      await addVirtualAuthenticator(page, credentials);
      const { confirmRes } = await confirmEmailInBrowser(page, email);
      assert.equal(confirmRes.status(), 200);
      await page.waitForSelector('#m-passkey:not([disabled])');
      await page.click('#m-passkey');
      const calls = [];
      page.on('response', (r) => { if (r.url().includes('/hhttps/webauthn/')) calls.push(new URL(r.url()).pathname + ' ' + r.status()); });
      const [finish] = await Promise.all([
        page.waitForResponse((r) => r.url().includes('/hhttps/webauthn/auth/finish')),
        page.click('#passkeyGo'),
      ]);
      assert.equal(finish.status(), 200, await finish.text());
      await page.waitForSelector('#st-passkey .check', { state: 'attached' });
      assert.ok(!calls.some((c) => c.startsWith('/hhttps/webauthn/register/finish')), `no re-registration: ${calls.join(', ')}`);
      assert.match(await page.locator('#passkeyHint').textContent(), /Passkey erkannt|Passkey found/, 'passkey.existing hint shown');
    } finally { await context.close(); }
  }

  // D4/AK-4: the WebAuthn user handle must be the session's stable userId.
  // AK-4/D4: register/start hands `userID` to @simplewebauthn/server 9 as a
  // string, so the credential the browser registers carries the stable userId.
  await t.test('D4: the registered credential carries the userId as user handle', () => {
    assert.equal(userHandle, userId, `user handle ${JSON.stringify(userHandle)} should equal the stable userId`);
  });
});
