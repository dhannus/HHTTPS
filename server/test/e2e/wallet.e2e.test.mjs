// #27: browser end-to-end test for the Privacy Pass wallet
// (privacy-pass/public/wallet.html, served under /privacy-pass/) with
// Playwright + Chromium — same harness as signin.e2e.test.mjs: the server is
// booted by the integration helper (TEST_PG_HOST), every non-local request is
// stubbed (the unpkg @simplewebauthn/browser script with the real pinned
// bundle, everything else empty), the e-mail code is read from the browser's
// own /hhttps/email/send response (EMAIL_DEV_MODE), and the passkey comes
// from Chromium's virtual authenticator (CDP WebAuthn domain).
//
// Run with: TEST_PG_HOST=/var/lib/pgtest npm run test:e2e
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { pgAvailable, startServer } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { createTracker, freshEmail } from '../helpers/identity-flow.mjs';

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

async function openWallet() {
  const context = await browser.newContext();
  await context.route((url) => url.origin !== srv.baseUrl, (route) => {
    const body = /unpkg\.com\/@simplewebauthn\/browser@9\.0\.1\//.test(route.request().url()) ? SWA_BUNDLE : '';
    return route.fulfill({ status: 200, contentType: 'application/javascript', body });
  });
  const page = await context.newPage();
  page.on('response', (r) => {
    // Track rows the browser creates so cleanup removes them (W-6).
    if (/\/hhttps\/(session\/start|email\/confirm-code|webauthn\/auth\/finish)$/.test(r.url())) {
      r.json().then((j) => { track.add({ sessionId: j.sessionId, userId: j.userId }); if (j.userId) userIds.add(j.userId); }).catch(() => {});
    }
  });
  await page.goto(srv.baseUrl + '/privacy-pass/');
  return { context, page };
}

async function addVirtualAuthenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
    },
  });
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

test('#27 wallet: login → inline e-mail dialog → code → passkey registered (register/finish 200, auth/finish 200) → "Angemeldet"', { skip }, async () => {
  const { context, page } = await openWallet();
  try {
    const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
    await page.waitForFunction(() => typeof window.doLogin === 'function');

    // Fresh browser, no passkey → the wallet must ask for the e-mail first.
    await page.click('#btn-login');
    await page.waitForSelector('#auth-email-area:not(.hidden)');
    assert.equal(await page.locator('#auth-email-input').isVisible(), true, 'email input shown');

    const email = freshEmail('e2e-wallet');
    await page.fill('#auth-email-input', email);
    const [sendRes] = await Promise.all([
      page.waitForResponse((r) => r.url().includes('/hhttps/email/send')),
      page.click('#btn-auth-email-send'),
    ]);
    track.add({ email });
    assert.equal(sendRes.status(), 200, await sendRes.text());
    assert.ok(sendRes.request().postDataJSON().sessionId, '/email/send carries the sessionId from session/start');
    const sent = await sendRes.json();
    assert.match(String(sent.devCode), /^\d{6}$/, 'dev mode delivers a 6-digit code');

    const calls = [];
    page.on('response', (r) => { if (r.url().includes('/hhttps/webauthn/')) calls.push(new URL(r.url()).pathname + ' ' + r.status()); });
    const code = String(sent.devCode);
    await page.fill('#auth-email-code', code.slice(0, 3) + ' ' + code.slice(3)); // K-7: "482 913"
    const [confirmRes, finish] = await Promise.all([
      page.waitForResponse((r) => r.url().includes('/hhttps/email/confirm-code')),
      page.waitForResponse((r) => r.url().includes('/hhttps/webauthn/auth/finish')),
      page.click('#btn-auth-email-confirm'),
    ]);
    assert.equal(confirmRes.status(), 200, await confirmRes.text());
    const confirmed = await confirmRes.json();
    assert.equal(finish.status(), 200, await finish.text());
    assert.equal(finish.request().postDataJSON().priorSessionId, sendRes.request().postDataJSON().sessionId,
      'auth/finish merges the e-mail session');

    await page.waitForFunction(() => document.getElementById('btn-login').textContent.includes('Angemeldet'));
    assert.ok(calls.includes('/hhttps/webauthn/register/finish 200'), `registration happened: ${calls.join(', ')}`);
    assert.ok(calls.includes('/hhttps/webauthn/auth/finish 200'), `login happened: ${calls.join(', ')}`);
    assert.equal(await page.locator('#card-auth.done').count(), 1, 'auth card marked done');
    assert.equal(await page.locator('#card-creds:not(.hidden)').count(), 1, 'credential card shown');

    // D4/AK-4: the credential's user handle is the stable session userId.
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
    assert.equal(credentials.length, 1, 'one credential on the authenticator');
    const userHandle = Buffer.from(credentials[0].userHandle || '', 'base64').toString('utf8');
    assert.equal(userHandle, confirmed.userId, 'user handle == stable userId');
    assert.equal(await page.evaluate(() => localStorage.getItem('hhttps_uid')), confirmed.userId, 'hhttps_uid cache updated');
  } finally { await context.close(); }
});
