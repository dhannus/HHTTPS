/**
 * HHTTPS JSON viewer (AP1-42, #145)
 *
 * The HTML half of server.js's `sendJson`: it turns an already-serialized JSON
 * payload into a syntax-highlighted, brand-styled page. `sendJson` keeps the
 * content negotiation; everything below is pure string building with no
 * knowledge of Express, so it is unit-testable on its own.
 *
 * AP1-27: every interpolated value (title, subtitle, path) is HTML-escaped, and
 * the raw-JSON link is produced from the request URL, so neither a crafted path
 * nor a crafted query string can inject markup.
 */

/** Escape the five characters that matter inside HTML text and attributes. */
export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Server-side syntax highlighting: wrap keys, strings, numbers and
 * booleans/null in the spans the stylesheet colours. The input is escaped
 * first, so no payload value can introduce markup.
 */
export function highlightJson(json) {
  return String(json)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/("(?:[^"\\]|\\.)*")(\s*:)/g, '<span class="k">$1</span>$2')
    .replace(/:\s*("(?:[^"\\]|\\.)*")/g, ': <span class="s">$1</span>')
    .replace(/\b(true|false|null)\b/g, '<span class="b">$1</span>')
    .replace(/(:\s*)(-?\d+(?:\.\d+)?)/g, '$1<span class="n">$2</span>');
}

/**
 * AP1-15: the "Raw JSON" link used to be built from `req.path` alone, which
 * dropped every query parameter — the raw view of `/x?a=1` answered for `/x`.
 * Keep the original query string and only force `format=json`.
 *
 * @param {string} originalUrl  req.originalUrl (path + query)
 * @returns {string} same URL with format=json
 */
export function rawJsonUrl(originalUrl) {
  const url = String(originalUrl || '/');
  const q = url.indexOf('?');
  const path = q === -1 ? url : url.slice(0, q);
  const params = new URLSearchParams(q === -1 ? '' : url.slice(q + 1));
  params.set('format', 'json');
  return `${path}?${params.toString()}`;
}

/** The page stylesheet — HHTTPS brand palette, kept out of the template body. */
const STYLES = `
  :root {
    --cream:   #F8F1E4;  --paper:    #FCFAF5;  --sand: #EDE0C8;
    --terra:   #C97D5B;  --terra-dp: #A86246;  --apricot: #F2B894;
    --sage:    #A8B89E;  --sage-dp:  #889982;  --lavender: #B5A8D9;
    --ink:     #2D2823;  --ink-soft: #4A413A;  --ink-mute: #7A6F62;
    --line:    rgba(45, 40, 35, 0.1);
    --code-bg: #2D2823;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    background: var(--cream);
    color: var(--ink);
    line-height: 1.6;
    min-height: 100vh;
    padding: 32px 20px 80px;
  }
  .wrap { max-width: 980px; margin: 0 auto; }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
    margin-bottom: 24px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--line);
  }
  .logo {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    text-decoration: none;
    color: var(--ink);
  }
  .logo-mark {
    width: 32px; height: 32px;
    border-radius: 9px;
    background: linear-gradient(135deg, var(--terra), var(--apricot));
    position: relative;
  }
  .logo-mark::after {
    content: 'H';
    position: absolute; inset: 0;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Fraunces', serif; font-weight: 600; font-size: 18px;
    color: var(--paper);
  }
  .logo-text {
    font-family: 'Fraunces', serif;
    font-variation-settings: "SOFT" 100, "WONK" 1;
    font-weight: 500;
    font-size: 20px;
  }
  .meta {
    display: inline-flex; gap: 8px; flex-wrap: wrap;
  }
  .badge {
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 100px;
    padding: 6px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--ink-soft);
  }
  .badge .dot {
    display: inline-block; width: 6px; height: 6px;
    border-radius: 50%; background: var(--sage-dp);
    margin-right: 6px; vertical-align: middle;
  }
  h1 {
    font-family: 'Fraunces', serif;
    font-variation-settings: "SOFT" 50, "WONK" 1;
    font-weight: 400;
    font-size: 36px;
    letter-spacing: -0.02em;
    margin-bottom: 4px;
  }
  h1 em {
    font-style: italic;
    color: var(--terra);
    font-variation-settings: "SOFT" 100, "WONK" 1;
  }
  .sub {
    color: var(--ink-mute);
    font-size: 14px;
    margin-bottom: 28px;
    font-family: 'JetBrains Mono', monospace;
  }
  .toolbar {
    display: flex; gap: 8px; flex-wrap: wrap;
    margin-bottom: 16px;
  }
  .btn {
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 100px;
    padding: 8px 16px;
    font-family: 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 500;
    color: var(--ink-soft);
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.15s;
  }
  .btn:hover {
    background: var(--sand);
    color: var(--ink);
    transform: translateY(-1px);
  }
  .btn.primary {
    background: var(--ink);
    color: var(--cream);
    border-color: var(--ink);
  }
  .btn.primary:hover {
    background: var(--terra-dp);
    border-color: var(--terra-dp);
    color: var(--cream);
  }
  pre {
    background: var(--code-bg);
    color: #F2E8D5;
    border-radius: 14px;
    padding: 24px 28px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    line-height: 1.7;
    overflow-x: auto;
    box-shadow: 0 4px 20px rgba(45, 40, 35, 0.08);
    tab-size: 2;
  }
  .k { color: #F2B894; }     /* keys */
  .s { color: #B8C9A8; }     /* strings */
  .n { color: #DDB4B0; }     /* numbers */
  .b { color: #B5A8D9; font-style: italic; } /* booleans / null */
  footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--line);
    color: var(--ink-mute);
    font-size: 12px;
    font-family: 'JetBrains Mono', monospace;
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
  }
  footer a { color: var(--ink-soft); text-decoration: none; }
  footer a:hover { color: var(--terra-dp); }
`;

/**
 * AP1-27: the copy button re-fetches the raw JSON from the CURRENT location
 * instead of an interpolated path — nothing from the request is spliced into
 * the script source.
 */
const COPY_SCRIPT = `
async function copyJson() {
  try {
    const u = new URL(location.href);
    u.searchParams.set('format', 'json');
    const r = await fetch(u.toString());
    const t = await r.text();
    await navigator.clipboard.writeText(t);
    document.getElementById('copyLabel').textContent = 'Kopiert!';
    setTimeout(() => { document.getElementById('copyLabel').textContent = 'Kopieren'; }, 1500);
  } catch (e) {
    alert('Kopieren fehlgeschlagen: ' + e.message);
  }
}
`;

const DEFAULT_SUBTITLE = 'Open protocol — open API. JSON below, formatted for humans.';

/**
 * Render the full viewer page.
 *
 * @param {object} args
 * @param {*}      args.data        the payload (serialized here)
 * @param {string} [args.title]
 * @param {string} [args.subtitle]
 * @param {string} [args.path]        req.path — shown in the header badge
 * @param {string} [args.originalUrl] req.originalUrl — drives the raw-JSON link
 * @param {string} [args.version]     protocol version for the header badge
 * @returns {string} HTML document
 */
export function renderJsonPage({ data, title = 'HHTTPS API', subtitle, path = '/', originalUrl, version = '0.5.0' } = {}) {
  const safeTitle    = escapeHtml(title);
  const safeSubtitle = escapeHtml(subtitle || DEFAULT_SUBTITLE);
  const safePath     = escapeHtml(path);
  const rawHref      = escapeHtml(rawJsonUrl(originalUrl || path));
  const highlighted  = highlightJson(JSON.stringify(data, null, 2));

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${safeTitle} — HHTTPS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT,WONK@9..144,400..600,30..100,0..1&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>${STYLES}</style>
</head>
<body>
<div class="wrap">
  <header>
    <a class="logo" href="/">
      <div class="logo-mark"></div>
      <span class="logo-text">HHTTPS</span>
    </a>
    <div class="meta">
      <span class="badge"><span class="dot"></span>v${escapeHtml(version)}</span>
      <span class="badge">${safePath}</span>
    </div>
  </header>

  <h1>${safeTitle}</h1>
  <p class="sub">${safeSubtitle}</p>

  <div class="toolbar">
    <a class="btn primary" href="${rawHref}" target="_blank">
      <span>↓</span> Raw JSON
    </a>
    <button class="btn" id="copyBtn" onclick="copyJson()">
      <span>⎘</span> <span id="copyLabel">Kopieren</span>
    </button>
    <a class="btn" href="/spec">Spec</a>
    <a class="btn" href="https://iamhmn.org" target="_blank">iamhmn.org →</a>
  </div>

  <pre id="json">${highlighted}</pre>

  <footer>
    <span>iamhmn Initiative</span>
    <a href="https://github.com/dhannus/HHTTPS">GitHub</a>
    <a href="/.well-known/jwks.json">JWKS</a>
    <a href="/.well-known/hhttps-configuration">Discovery</a>
    <a href="/hhttps/info">Info</a>
    <a href="/hhttps/roles">Roles</a>
  </footer>
</div>
<script>${COPY_SCRIPT}</script>
</body>
</html>`;
}
