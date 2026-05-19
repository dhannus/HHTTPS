/**
 * Privacy Pass Demo — combined PP + HHTTPS protection
 *
 * Two routes:
 *   GET  /privacy-pass/demo           → serves the demo HTML
 *   POST /privacy-pass/demo/protected → requires BOTH a valid Privacy Pass
 *                                       token AND a valid HHTTPS Role JWT
 *
 * The protected endpoint demonstrates the two-layer architecture in action:
 * the anonymous "is human" proof (PP) and the pseudonymous "has role X"
 * attestation (HHTTPS) are verified independently, then combined into a
 * single access decision.
 */

import { dirname, join }    from 'path';
import { fileURLToPath }    from 'url';
import express              from 'express';
import jwt                  from 'jsonwebtoken';

import { parseTokenAndVerify } from './verifier-internal.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const demoRouter = express.Router();

// ─── GET /privacy-pass/demo — serve the HTML ─────────────────────────────────

demoRouter.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'demo.html'));
});

// ─── POST /privacy-pass/demo/protected — combined verification ───────────────

demoRouter.post('/protected', express.json({ limit: '8kb' }), async (req, res) => {
  const result = {
    privacy_pass: { presented: false, valid: false, reason: null },
    hhttps_role:  { presented: false, valid: false, reason: null, role: null },
    granted:      false,
  };

  // 1) Privacy Pass token (anonymous human proof)
  const authz = req.headers.authorization || '';
  const ppMatch = authz.match(/^PrivateToken\s+token="([^"]+)"$/i);

  if (ppMatch) {
    result.privacy_pass.presented = true;
    try {
      const tokenBuf = Buffer.from(ppMatch[1], 'base64');
      const ok = await parseTokenAndVerify(tokenBuf);
      result.privacy_pass.valid = ok;
      if (!ok) result.privacy_pass.reason = 'authenticator mismatch';
    } catch (err) {
      result.privacy_pass.reason = err.message;
    }
  }

  // 2) HHTTPS Role token (pseudonymous role attestation)
  const roleToken = req.headers['hhttps-role-token'] || req.body?.role_token;
  if (typeof roleToken === 'string' && roleToken.length > 0) {
    result.hhttps_role.presented = true;
    try {
      // Lazy-load to avoid circular import and to reuse the HHTTPS key infra
      const { verifyToken } = await import('../keys.js');
      const decoded = verifyToken(roleToken);
      result.hhttps_role.valid = true;
      result.hhttps_role.role  = decoded.role || decoded.r || 'unknown';
    } catch (err) {
      result.hhttps_role.reason = err.message;
    }
  }

  // 3) Access decision — both layers must validate
  result.granted = result.privacy_pass.valid && result.hhttps_role.valid;

  if (result.granted) {
    res.json({
      ...result,
      message: `Access granted. Anonymous human verification (Privacy Pass) and ` +
               `pseudonymous role attestation (${result.hhttps_role.role}) both passed.`,
      timestamp: new Date().toISOString(),
    });
  } else {
    res.status(401).json(result);
  }
});
