"""
Example: Online petition signed by HHTTPS-verified humans only.

Demonstrates:
  - HHTTPS token verification via JWKS in Python
  - Trust-score thresholds for petition signing
  - Role-aware messaging (citizens, students, professionals)
  - Public count of verified vs. self-declared signatures

Run:
    pip install flask requests pyjwt cryptography
    python app.py

Test:
    curl -X POST http://localhost:5000/sign \\
      -H 'Content-Type: application/json' \\
      -H 'HHTTPS-Token: <your-token>' \\
      -d '{"comment": "I support this!"}'
"""

import time
from functools import wraps
from typing import Optional

import jwt
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ─── HHTTPS verification setup ──────────────────────────────────────────────
ISSUER_BASE = "https://hhttps.org"
JWKS_URL    = f"{ISSUER_BASE}/.well-known/jwks.json"

_jwks_cache       = None
_jwks_cached_at   = 0.0
_JWKS_TTL_SECONDS = 3600  # 1 hour


def _get_jwks():
    """Cache JWKS for 1 hour to avoid repeated network calls."""
    global _jwks_cache, _jwks_cached_at
    now = time.time()
    if _jwks_cache and (now - _jwks_cached_at) < _JWKS_TTL_SECONDS:
        return _jwks_cache
    resp = requests.get(JWKS_URL, timeout=5)
    resp.raise_for_status()
    _jwks_cache     = resp.json()
    _jwks_cached_at = now
    return _jwks_cache


def _get_signing_key(token: str):
    """Look up the public key for the token's kid in the JWKS."""
    header = jwt.get_unverified_header(token)
    kid    = header.get("kid")
    for key in _get_jwks().get("keys", []):
        if key.get("kid") == kid:
            return jwt.algorithms.ECAlgorithm.from_jwk(key)
    raise ValueError(f"key with kid={kid!r} not found in JWKS")


def verify_hhttps_token(token: str) -> Optional[dict]:
    """Verify ES256-signed JWT against issuer's JWKS. Returns claims or None."""
    if not token:
        return None
    try:
        key = _get_signing_key(token)
        return jwt.decode(token, key=key, algorithms=["ES256"])
    except (jwt.PyJWTError, ValueError):
        return None


def hhttps_required(min_trust: int = 60, allowed_roles=None):
    """Decorator: require valid HHTTPS token meeting thresholds."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token   = request.headers.get("HHTTPS-Token") or \
                      (request.headers.get("Authorization", "").replace("Bearer ", "") or None)
            decoded = verify_hhttps_token(token)
            if not decoded:
                return jsonify(error="HHTTPS token required and must be valid"), 401
            if decoded.get("trustScore", 0) < min_trust:
                return jsonify(error=f"trust score too low (need ≥ {min_trust})"), 403
            if allowed_roles and decoded.get("role") not in allowed_roles:
                return jsonify(error=f"role '{decoded.get('role')}' not allowed"), 403
            request.hhttps = decoded
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ─── Demo data store ────────────────────────────────────────────────────────
signatures = []


# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Public petition info."""
    role_breakdown = {}
    for s in signatures:
        r = s["role"]
        role_breakdown[r] = role_breakdown.get(r, 0) + 1
    return jsonify({
        "title":           "Demo Petition: Mehr Datenschutz im Netz",
        "description":     "Eine Beispielpetition, die HHTTPS für authentische Unterstützung nutzt.",
        "totalSignatures": len(signatures),
        "byRole":          role_breakdown,
        "minimumTrust":    60,
    })


@app.route("/sign", methods=["POST"])
@hhttps_required(min_trust=60)
def sign_petition():
    """Sign the petition — must be verified human."""
    body    = request.get_json(silent=True) or {}
    comment = (body.get("comment") or "").strip()[:280]

    sig = {
        "id":         len(signatures) + 1,
        "signedAt":   time.time(),
        "role":       request.hhttps.get("role", "citizen"),
        "trustScore": request.hhttps.get("trustScore", 60),
        "method":     request.hhttps.get("method"),
        "comment":    comment,
        # Note: we do NOT store any identifying information from the token.
        # The HHTTPS jti is logged for revocation matching, never the user_id.
        "jti":        request.hhttps.get("jti", "")[:16] + "…",
    }
    signatures.append(sig)
    return jsonify({"ok": True, "signature": sig}), 201


@app.route("/sign/professional", methods=["POST"])
@hhttps_required(min_trust=85, allowed_roles=["lawyer", "researcher", "medical_professional", "civil_servant"])
def sign_as_professional():
    """For professionals only — gives signature higher visibility."""
    body = request.get_json(silent=True) or {}
    sig = {
        "id":            len(signatures) + 1,
        "signedAt":      time.time(),
        "role":          request.hhttps.get("role"),
        "professional":  True,
        "trustScore":    request.hhttps.get("trustScore"),
        "comment":       (body.get("comment") or "")[:500],
    }
    signatures.append(sig)
    return jsonify({"ok": True, "signature": sig}), 201


@app.route("/signatures")
def list_signatures():
    """Public list of all signatures (anonymized)."""
    return jsonify({
        "count":      len(signatures),
        "signatures": [
            {k: v for k, v in s.items() if k != "jti"}
            for s in signatures[-50:]
        ]
    })


if __name__ == "__main__":
    app.run(port=5000, debug=True)
