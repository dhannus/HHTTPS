"""
Example: Django middleware + view for a medical Q&A platform
where ONLY verified doctors (trust ≥ 90) can answer questions.

This file shows the middleware and a view. To wire it up in your project:

    # settings.py
    MIDDLEWARE = [
        ...
        'hhttps_middleware.HHTPPSMiddleware',
    ]

    # urls.py
    from .views import answer_view
    urlpatterns = [path('answer/<int:question_id>/', answer_view)]

Run requirements:
    pip install django requests pyjwt cryptography
"""

import time
from typing import Optional

import jwt
import requests
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


# ─── HHTTPS verification (shared with Flask example logic) ──────────────────
ISSUER_BASE = "https://hhttps.org"
JWKS_URL    = f"{ISSUER_BASE}/.well-known/jwks.json"

_jwks_cache     = None
_jwks_cached_at = 0.0
_JWKS_TTL       = 3600


def _get_jwks():
    global _jwks_cache, _jwks_cached_at
    now = time.time()
    if _jwks_cache and (now - _jwks_cached_at) < _JWKS_TTL:
        return _jwks_cache
    r = requests.get(JWKS_URL, timeout=5)
    r.raise_for_status()
    _jwks_cache, _jwks_cached_at = r.json(), now
    return _jwks_cache


def _signing_key_for(token: str):
    h   = jwt.get_unverified_header(token)
    kid = h.get("kid")
    for k in _get_jwks().get("keys", []):
        if k.get("kid") == kid:
            return jwt.algorithms.ECAlgorithm.from_jwk(k)
    raise ValueError(f"unknown kid: {kid}")


def verify_hhttps_token(token: str) -> Optional[dict]:
    if not token:
        return None
    try:
        return jwt.decode(token, key=_signing_key_for(token), algorithms=["ES256"])
    except (jwt.PyJWTError, ValueError):
        return None


# ─── Middleware ─────────────────────────────────────────────────────────────
class HHTPPSMiddleware:
    """Attach `request.hhttps` (None or claims dict) to every request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.META.get("HTTP_HHTTPS_TOKEN", "")
        if not token:
            auth = request.META.get("HTTP_AUTHORIZATION", "")
            if auth.startswith("Bearer "):
                token = auth[7:]
        request.hhttps = verify_hhttps_token(token) if token else None
        return self.get_response(request)


# ─── Decorator ──────────────────────────────────────────────────────────────
def hhttps_required(min_trust=60, allowed_roles=None):
    """Decorator for class- or function-based views."""
    from functools import wraps

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            d = getattr(request, "hhttps", None)
            if not d:
                return JsonResponse({"error": "HHTTPS token required"}, status=401)
            if d.get("trustScore", 0) < min_trust:
                return JsonResponse(
                    {"error": f"trust ≥ {min_trust} required (got {d.get('trustScore', 0)})"},
                    status=403
                )
            if allowed_roles and d.get("role") not in allowed_roles:
                return JsonResponse(
                    {"error": f"role '{d.get('role')}' not allowed; required: {allowed_roles}"},
                    status=403
                )
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# ─── Example view: medical Q&A platform ────────────────────────────────────
@csrf_exempt
@hhttps_required(min_trust=90, allowed_roles=["medical_professional"])
def answer_view(request, question_id: int):
    """
    POST /answer/123/  — Submit a medical answer.

    Requires:
      - Verified human (HHTTPS token)
      - role == 'medical_professional'
      - trustScore ≥ 90 (i.e. approbation-id verified, not just self-declared)

    The view stores no identifying info; only the role, trust score,
    and a partial JTI for revocation matching.
    """
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    import json
    try:
        body = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    answer_text = (body.get("answer") or "").strip()[:5000]
    if len(answer_text) < 50:
        return JsonResponse({"error": "answer must be ≥ 50 chars"}, status=400)

    h = request.hhttps
    answer_record = {
        "questionId":         question_id,
        "answer":             answer_text,
        "verifiedAs":         h.get("roleLevel"),  # e.g. "approbation-id"
        "trustScore":         h.get("trustScore"),
        "issuer":             h.get("iss"),
        "submittedAtUnix":    int(time.time()),
        "jtiPartial":         h.get("jti", "")[:16],
        # No personal data; the HHTTPS protocol guarantees we can't have any.
    }

    # In a real app: save to DB. Here, just echo it back.
    return JsonResponse({"ok": True, "answer": answer_record}, status=201)


# ─── Bonus: show a question with a "verified doctor only" notice for unverified users
def question_view(request, question_id: int):
    """GET /question/123/ — Show question + answers; reveal answer-form only to verified doctors."""
    h = getattr(request, "hhttps", None)
    can_answer = bool(
        h
        and h.get("trustScore", 0) >= 90
        and h.get("role") == "medical_professional"
    )

    return JsonResponse({
        "questionId": question_id,
        "title":      "Demo: Why does my back hurt?",
        "canAnswer":  can_answer,
        "verifyHint": (
            None if can_answer
            else "Only verified physicians (HHTTPS trust ≥ 90, role: doctor) may answer."
        ),
        "verifyUrl":  "https://hhttps.org",
    })
