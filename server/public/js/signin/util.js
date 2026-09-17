/* AP8-34 (#215) / AP8-51 (#249): small helpers that used to live two or three
   times over inside the index.html inline script. Pure functions, no DOM, so
   the unit tests can import and call them instead of matching source text. */

/** HTML-escape for the few places that still build markup as a string. */
export function escHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

/** "header.payload.sig…" — the display form of a JWT (header + payload + the
 *  first 16 signature characters). The token card, the machine card and the
 *  restored-identity card each had their own copy of this expression. */
export function shortToken(tok) {
  if (!tok) return '';
  const p = String(tok).split('.');
  return p[0] + '.' + (p[1] || '') + '.' + (p[2] || '').slice(0, 16) + '…';
}

/** Expiry of a JWT in milliseconds since the epoch, 0 when unreadable. */
export function jwtExp(tok) {
  try {
    const p = JSON.parse(atob(String(tok).split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return p && p.exp ? p.exp * 1000 : 0;
  } catch { return 0; }
}

/** Normalise a pasted one-time code ("482 913", "482-913" → "482913"). */
export function normaliseCode(raw) {
  return String(raw || '').trim().replace(/[\s-]/g, '');
}

/* The e-mail path used a loose `/.+@.+\..+/`, the machine path a stricter
   expression. One rule now — the stricter one, which the machine path already
   applied and which the server validates against anyway. */
export const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
export function isEmail(v) { return EMAIL_RE.test(String(v || '').trim()); }
