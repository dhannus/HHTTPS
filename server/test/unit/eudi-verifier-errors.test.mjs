// #26: the EUDI verifier must pass the backend's business errors (e.g. the
// e-mail gate 403 email_verification_required of /hhttps/age/upgrade,
// /hhttps/age/direct, /hhttps/eid/upgrade) through to the browser with their
// status and `error` code instead of a generic 502.
import test from 'node:test';
import assert from 'node:assert/strict';
import { BackendError, mapBackendError } from '../../eudi-verifier/errors.js';

test('#26: BackendError carries status, body and a readable message', () => {
  const err = new BackendError('age/direct', 403, { error: 'email_verification_required', detail: 'Verify your email first.' });
  assert.ok(err instanceof Error);
  assert.equal(err.status, 403);
  assert.equal(err.body.error, 'email_verification_required');
  assert.equal(err.message, 'age/direct failed (403): email_verification_required');
});

test('#26: 4xx backend errors are passed through with status and error code', () => {
  const err = new BackendError('age/upgrade', 403, { error: 'email_verification_required', detail: 'Verify your email first.' });
  const { httpStatus, body } = mapBackendError(err);
  assert.equal(httpStatus, 403);
  assert.deepEqual(body, { status: 'error', error: 'email_verification_required', detail: 'Verify your email first.' });
});

test('#26: a 4xx without a detail falls back to the error message as detail', () => {
  const err = new BackendError('eid/upgrade', 404, { error: 'session_not_found' });
  const { httpStatus, body } = mapBackendError(err);
  assert.equal(httpStatus, 404);
  assert.equal(body.status, 'error');
  assert.equal(body.error, 'session_not_found');
  assert.equal(body.detail, 'eid/upgrade failed (404): session_not_found');
});

test('#26: 5xx backend errors stay a 502 with the backend error code', () => {
  const err = new BackendError('age/upgrade', 500, { error: 'age_upgrade_failed' });
  const { httpStatus, body } = mapBackendError(err);
  assert.equal(httpStatus, 502);
  assert.equal(body.status, 'error');
  assert.equal(body.error, 'age_upgrade_failed');
});

test('#26: non-backend errors (EU verifier unreachable, config) stay a 502 without an error code', () => {
  const { httpStatus, body } = mapBackendError(new Error('fetch failed'));
  assert.equal(httpStatus, 502);
  assert.deepEqual(body, { status: 'error', detail: 'fetch failed' });
});
