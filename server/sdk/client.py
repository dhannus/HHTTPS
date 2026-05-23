"""
HHTTPS Client SDK — Python 3.8+
iamhmn Initiative · github.com/dhannus/HHTTPS

Installation:
    # No dependencies for the remote check() path (stdlib urllib only).
    # For local JWKS verification (verify_local), also install:
    #   pip install "PyJWT[crypto]"

Usage:
    from sdk.client import HHTPPSClient

    hhttps = HHTPPSClient("https://hhttps.org")

    # Check a token
    result = hhttps.check(token)
    if result.human:
        print(f"Human ✓ · Role: {result.role} ({result.role_label})")
        print(f"Trust Score: {result.trust_score}/100")
    else:
        print("Bot or unverified")

    # Header-only check (fast, for middleware)
    headers = hhttps.check_headers(token)
    is_human = headers["human"]
"""

from __future__ import annotations
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error


@dataclass
class HHTPPSResult:
    """Result of a /hhttps/check call."""
    human:       bool        = False
    actor_type:  str         = "unknown"
    status:      str         = "unverified"
    trust_score: int         = 0
    method:      Optional[str] = None
    issued_at:   Optional[str] = None
    expires_at:  Optional[str] = None
    role:        Optional[str] = None
    role_label:  Optional[str] = None
    role_icon:   Optional[str] = None
    role_level:  Optional[str] = None
    level_label: Optional[str] = None
    privileges:  List[str]   = field(default_factory=list)
    user_story:  Optional[str] = None
    machine:     Optional[Dict] = None


class HHTPPSClient:
    """
    HHTTPS client for Python applications.

    :param server_url:  Base URL of the HHTTPS server
    :param timeout:     Request timeout in seconds (default 8)
    :param cache:       Cache discovery config (default True)
    """

    def __init__(self, server_url: str, timeout: int = 8, cache: bool = True):
        self.server_url = server_url.rstrip("/")
        self.timeout    = timeout
        self._cache     = cache
        self._discovery: Optional[Dict] = None
        self._jwks: Optional[Dict] = None
        self._jwks_at: float = 0.0
        self.jwks_max_age: int = 3600  # seconds

    # ── Discovery ────────────────────────────────────────────────────────────

    def discover(self) -> Dict:
        """Fetch and optionally cache the .well-known/hhttps-configuration."""
        if self._cache and self._discovery:
            return self._discovery
        data = self._get("/.well-known/hhttps-configuration")
        self._discovery = data
        return data

    # ── Core: check token ─────────────────────────────────────────────────────

    def check(self, token: str) -> HHTPPSResult:
        """
        Check an HHTTPS token: is it human? What role?
        Returns an HHTPPSResult dataclass.
        """
        if not token:
            return HHTPPSResult()
        try:
            data = self._post("/hhttps/check", headers={"HHTTPS-Token": token})
            return self._parse_result(data)
        except Exception:
            return HHTPPSResult()

    def check_headers(self, token: str) -> Dict[str, Any]:
        """
        Quick header-only check — no body parsing.
        Returns a dict of HHTTPS-* response headers.
        """
        req = urllib.request.Request(
            f"{self.server_url}/hhttps/check",
            method="POST",
            headers={"HHTTPS-Token": token or "", "Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return {
                    "human":       resp.headers.get("HHTTPS-Human") == "true",
                    "status":      resp.headers.get("HHTTPS-Status"),
                    "actor_type":  resp.headers.get("HHTTPS-Actor-Type"),
                    "role":        resp.headers.get("HHTTPS-Role"),
                    "trust_score": int(resp.headers.get("HHTTPS-Trust-Score", 0)),
                    "method":      resp.headers.get("HHTTPS-Method"),
                }
        except Exception:
            return {"human": False, "status": "error", "actor_type": "unknown",
                    "role": None, "trust_score": 0, "method": None}

    # ── Local verification (no per-request issuer call) ───────────────────────

    def get_jwks(self) -> Dict:
        """
        Fetch and cache the issuer JWKS (RFC 7517). Re-fetched after
        ``jwks_max_age`` seconds. Honours ``jwks_uri`` from discovery when
        available, else the conventional /.well-known/jwks.json path.
        """
        import time
        fresh = self._jwks and (time.time() - self._jwks_at) < self.jwks_max_age
        if self._cache and fresh:
            return self._jwks

        path = "/.well-known/jwks.json"
        try:
            disc = self.discover()
            if disc.get("jwks_uri"):
                path = disc["jwks_uri"]
        except Exception:
            pass

        if path.startswith("http"):
            req = urllib.request.Request(path, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                jwks = json.loads(resp.read().decode())
        else:
            jwks = self._get(path)

        self._jwks = jwks
        self._jwks_at = time.time()
        return jwks

    def verify_local(self, token: str) -> HHTPPSResult:
        """
        Verify a token's ES256 signature locally against the issuer JWKS.

        Does NOT contact the issuer per call (JWKS is cached). Checks the
        signature, ``exp`` and ``nbf``. Selects the verifying key by the token
        header ``kid`` so verification keeps working across a key rotation.

        Requires PyJWT with the cryptography backend::

            pip install "PyJWT[crypto]"

        For high-trust use cases that must also honour revocation, additionally
        call :meth:`is_revoked` with ``result`` JTI — local signature
        verification alone cannot see a revocation that happened after issuance.
        """
        if not token:
            return HHTPPSResult()

        try:
            import jwt  # PyJWT
            from jwt import PyJWKClient, algorithms  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                'verify_local requires PyJWT with crypto: pip install "PyJWT[crypto]"'
            ) from e

        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            return HHTPPSResult(status="invalid")

        if header.get("alg") != "ES256":
            return HHTPPSResult(status="invalid")

        kid = header.get("kid")
        jwks = self.get_jwks()
        keys = jwks.get("keys", [])
        jwk = next((k for k in keys if k.get("kid") == kid), None) or (keys[0] if keys else None)
        if not jwk:
            return HHTPPSResult(status="invalid")

        try:
            from jwt.algorithms import ECAlgorithm
            public_key = ECAlgorithm.from_jwk(json.dumps(jwk))
            claims = jwt.decode(token, key=public_key, algorithms=["ES256"])
        except jwt.ExpiredSignatureError:
            return HHTPPSResult(status="expired")
        except Exception:
            return HHTPPSResult(status="invalid")

        return self._parse_claims(claims)

    # ── Token lifecycle ───────────────────────────────────────────────────────

    def validate(self, token: str) -> Dict:
        """Validate a token and get full claims."""
        return self._post("/hhttps/validate", body={"token": token})

    def revoke(self, token: str) -> Dict:
        """Revoke a token immediately."""
        return self._post("/hhttps/revoke", body={"token": token})

    def is_revoked(self, jti: str) -> bool:
        """Check if a specific JTI has been revoked."""
        data = self._get(f"/hhttps/revoke/status?jti={jti}")
        return data.get("revoked", False)

    def refresh(self, refresh_token: str) -> Dict:
        """Refresh an access token (no biometric re-verification needed)."""
        return self._post("/hhttps/token/refresh", body={"refreshToken": refresh_token})

    # ── Roles ────────────────────────────────────────────────────────────────

    def get_roles(self) -> Dict:
        """Get all available roles and verification levels."""
        return self._get("/hhttps/roles")

    # ── Machine tokens ────────────────────────────────────────────────────────

    def register_machine(self, operator_name: str, purpose: str,
                         operator_url: str = "", contact_email: str = "") -> Dict:
        """Register a machine operator."""
        return self._post("/hhttps/machine/register", body={
            "operatorName": operator_name, "purpose": purpose,
            "operatorUrl": operator_url, "contactEmail": contact_email
        })

    def get_machine_token(self, operator_id: str, api_key: str) -> Dict:
        """Issue a machine token for a registered operator."""
        return self._post("/hhttps/machine/token", body={"operatorId": operator_id, "apiKey": api_key})

    # ── Webhooks ──────────────────────────────────────────────────────────────

    def register_webhook(self, url: str, events: List[str] = None, secret: str = "") -> Dict:
        """Register a webhook for HHTTPS events."""
        return self._post("/hhttps/webhooks", body={
            "url": url, "events": events or ["*"], "secret": secret
        })

    def list_webhooks(self) -> Dict:
        """List all registered webhooks."""
        return self._get("/hhttps/webhooks")

    def remove_webhook(self, webhook_id: str) -> Dict:
        """Remove a registered webhook."""
        return self._delete(f"/hhttps/webhooks/{webhook_id}")

    @staticmethod
    def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
        """
        Verify an incoming webhook signature.
        Use this in your webhook handler to confirm the request is from HHTTPS.

        :param payload:    Raw request body (string)
        :param signature:  Value of HHTTPS-Webhook-Sig header
        :param secret:     Your webhook secret
        :returns:          True if signature is valid
        """
        expected = "sha256=" + hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict:
        """Get public aggregated stats (no PII)."""
        return self._get("/hhttps/stats")

    # ── Django / Flask middleware helpers ─────────────────────────────────────

    def get_result_for_request(self, request, header_name: str = "HTTP_HHTTPS_TOKEN") -> HHTPPSResult:
        """
        Django helper: extract and check HHTTPS token from a Django request.

        Usage in a Django view:
            result = hhttps.get_result_for_request(request)
            if not result.human:
                return JsonResponse({"error": "humans only"}, status=401)
        """
        token = request.META.get(header_name, "") or request.META.get("HTTP_AUTHORIZATION", "").replace("Bearer ", "")
        return self.check(token)

    def flask_middleware(self, required: bool = False, min_trust: int = 0,
                         allowed_roles: List[str] = None):
        """
        Flask decorator factory.

        Usage:
            @app.route('/api/journalists-only')
            @hhttps.flask_middleware(required=True, allowed_roles=['journalist'])
            def journalists_only():
                from flask import g
                return jsonify({"role": g.hhttps.role})
        """
        client = self
        def decorator(f):
            from functools import wraps
            @wraps(f)
            def wrapped(*args, **kwargs):
                try:
                    from flask import request as freq, jsonify, g
                    token = freq.headers.get("HHTTPS-Token") or freq.headers.get("Authorization", "").replace("Bearer ", "")
                    g.hhttps = client.check(token)
                    if required and not g.hhttps.human:
                        return jsonify({"error": "HHTTPS verification required"}), 401
                    if min_trust and g.hhttps.trust_score < min_trust:
                        return jsonify({"error": f"Min trust score {min_trust} required"}), 403
                    if allowed_roles and g.hhttps.role not in allowed_roles:
                        return jsonify({"error": f"Role not allowed: {g.hhttps.role}"}), 403
                except ImportError:
                    pass
                return f(*args, **kwargs)
            return wrapped
        return decorator

    # ── Internal ──────────────────────────────────────────────────────────────

    def _parse_result(self, data: Dict) -> HHTPPSResult:
        hhttps = data.get("hhttps", {})
        role   = data.get("role", {}) or {}
        machine= data.get("machine")
        return HHTPPSResult(
            human       = hhttps.get("human", False),
            actor_type  = hhttps.get("actorType", "unknown"),
            status      = hhttps.get("status", "unverified"),
            trust_score = hhttps.get("trustScore", 0),
            method      = hhttps.get("method"),
            issued_at   = hhttps.get("issuedAt"),
            expires_at  = hhttps.get("expiresAt"),
            role        = role.get("id"),
            role_label  = role.get("label"),
            role_icon   = role.get("icon"),
            role_level  = role.get("level"),
            level_label = role.get("levelLabel"),
            privileges  = role.get("privileges", []),
            user_story  = role.get("userStory"),
            machine     = machine
        )

    def _parse_claims(self, p: Dict) -> HHTPPSResult:
        """Normalize raw JWT claims (from verify_local) into an HHTPPSResult."""
        is_machine = p.get("sub") == "machine" or p.get("human") is False
        iat = p.get("iat")
        exp = p.get("exp")
        import datetime as _dt
        def _iso(ts):
            if not ts:
                return None
            return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat()
        machine = None
        if is_machine:
            machine = {"operatorId": p.get("operatorId"),
                       "operatorName": p.get("operatorName"),
                       "purpose": p.get("purpose")}
        return HHTPPSResult(
            human       = p.get("human", False) is True,
            actor_type  = p.get("actorType", "bot" if is_machine else "human"),
            status      = "verified",
            trust_score = p.get("trustScore", 0) or 0,
            method      = p.get("method"),
            issued_at   = _iso(iat),
            expires_at  = _iso(exp),
            role        = p.get("role"),
            role_label  = p.get("role_label"),
            role_icon   = p.get("role_icon"),
            role_level  = p.get("roleLevel"),
            machine     = machine,
        )

    def _request(self, method: str, path: str, body: Dict = None, headers: Dict = None) -> Dict:
        url  = f"{self.server_url}{path}"
        data = json.dumps(body).encode() if body else None
        h    = {"Content-Type": "application/json", **(headers or {})}
        req  = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            try:   err = json.loads(e.read().decode())
            except: err = {"error": str(e)}
            raise RuntimeError(err.get("error", str(e)))

    def _get(self, path: str) -> Dict:          return self._request("GET",    path)
    def _post(self, path: str, body: Dict = None, headers: Dict = None) -> Dict:
        return self._request("POST", path, body=body, headers=headers)
    def _delete(self, path: str) -> Dict:       return self._request("DELETE", path)
