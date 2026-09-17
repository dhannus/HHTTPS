// html.js — AP3-46 (#199): ONE HTML escaper.
//
// server.js and email.js each carried their own copy, and the two had already
// drifted: the server variant left the apostrophe alone, the mail variant
// escaped it. Anything interpolated into an attribute needs both quote forms,
// so the stricter variant is the shared one.

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** Escape &, <, >, " and ' for HTML text AND quoted attributes. null/undefined → ''. */
export function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}
