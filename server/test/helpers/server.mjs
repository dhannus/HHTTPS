// Integration harness: boots server.js as a child process against a local
// Postgres (TEST_PG_HOST) and exposes a tiny fetch wrapper.
//
// Usage:
//   const srv = await startServer({ env: { SMTP_HOST: '' } });
//   const { status, json } = await srv.api('/hhttps/info');
//   await srv.stop();
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const READY_TIMEOUT_MS = 20_000;
const POLL_MS = 150;

export function pgAvailable() {
  return !!process.env.TEST_PG_HOST;
}

export function testEnv(port, overrides = {}) {
  return {
    ...process.env,
    PORT: String(port),
    DB_HOST: process.env.TEST_PG_HOST,
    DB_USER: 'hhttps',
    DB_NAME: 'hhttps',
    DB_PASSWORD: 'x',
    RP_ID: 'localhost',
    ORIGIN: `http://localhost:${port}`,
    BASE_URL: `http://localhost:${port}`,
    HHTTPS_VERIFICATION_PEPPER: 'test-pepper',
    EUDI_VERIFIER_SECRET: 'test-secret',
    EMAIL_DEV_MODE: '1', // F-3: dev mode (code in the API response) is opt-in
    ...overrides,
  };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export async function startServer({ env = {} } = {}) {
  if (!pgAvailable()) throw new Error('startServer: TEST_PG_HOST is not set');

  const port = 3900 + Math.floor(Math.random() * 1000);
  const baseUrl = `http://localhost:${port}`;
  const output = [];

  const child = spawn(process.execPath, ['server.js'], {
    cwd: SERVER_DIR,
    env: testEnv(port, env),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => output.push(d.toString()));
  child.stderr.on('data', (d) => output.push(d.toString()));

  let exited = null;
  child.on('exit', (code, signal) => { exited = { code, signal }; });

  const api = async (p, { method = 'GET', body, headers = {} } = {}) => {
    const init = { method, headers: { ...headers } };
    if (body !== undefined) {
      init.headers['content-type'] ??= 'application/json';
      init.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    const res = await fetch(baseUrl + p, init);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text, headers: res.headers };
  };

  const stop = () => new Promise((resolve) => {
    if (exited) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
    setTimeout(() => { if (!exited) child.kill('SIGKILL'); }, 2_000).unref();
  });

  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (exited) {
      throw new Error(`server.js exited early (code=${exited.code}, signal=${exited.signal})\n${output.join('')}`);
    }
    try {
      const { status } = await api('/hhttps/info');
      if (status === 200) return { baseUrl, port, api, stop, child, logs: () => output.join('') };
    } catch {}
    await sleep(POLL_MS);
  }
  await stop();
  throw new Error(`server.js did not become ready within ${READY_TIMEOUT_MS} ms\n${output.join('')}`);
}
