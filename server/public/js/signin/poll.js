/* AP8-07 (#98) / AP8-51 (#249): one poller for EUDI / age / GitHub.
   - terminal states end the loop: verified, the e-mail gate
     (status:error + email_verification_required), failed, expired, HTTP >= 400
   - the interval grows 2.5 s -> 10 s (x1.5), max 80 polls, then a timeout hint
   - a new run for the same method cancels the previous one (generation counter)
   - hidden tabs pause the requests (they do not count against the budget)
   The magic numbers used to sit inline in three copies of the loop. */

export const POLL_START_MS = 2500;
export const POLL_MAX_MS   = 10000;
export const POLL_FACTOR   = 1.5;
export const POLL_MAX_TRIES = 80;

/**
 * Create a poll runner. `deps` exists so the unit tests can drive the loop
 * without a browser: { sleep, isHidden }.
 */
export function createPoller(deps) {
  const sleep = (deps && deps.sleep) || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const isHidden = (deps && deps.isHidden) || (() => document.hidden);
  const generations = {};

  /** Bump the generation for `kind`; any in-flight run for it stops. */
  function cancel(kind) {
    generations[kind] = (generations[kind] || 0) + 1;
    return generations[kind];
  }

  /**
   * @param kind        poll channel ('eudi' | 'age' | 'github')
   * @param fetchOnce   () => Promise<Response>
   * @param isVerified  (json) => boolean
   * @param onVerified  (json) => void
   * @param onMessage   (i18nKey) => void — terminal message for the user
   */
  async function poll(kind, fetchOnce, isVerified, onVerified, onMessage) {
    const gen = cancel(kind);
    const say = onMessage || (() => {});
    let delay = POLL_START_MS;
    for (let n = 0; n < POLL_MAX_TRIES;) {
      await sleep(delay);
      if (generations[kind] !== gen) return;
      if (isHidden()) continue;
      n++;
      let r = null, d = null;
      try { r = await fetchOnce(); d = await r.json(); } catch { d = null; }
      if (generations[kind] !== gen) return;
      if (d && isVerified(d)) { onVerified(d); return; }
      if (d && d.status === 'error' && d.error === 'email_verification_required') { say('email.first'); return; }
      if (d && (d.status === 'failed' || d.status === 'expired')) { say(d.status === 'expired' ? 'poll.expired' : 'poll.failed'); return; }
      if (r && r.status >= 400) { say('poll.failed'); return; }
      delay = Math.min(Math.round(delay * POLL_FACTOR), POLL_MAX_MS);
    }
    say('poll.timeout');
  }

  return { poll, cancel };
}
