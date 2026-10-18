"""Service-to-service HMAC authentication (annex 04 section 1.3).

Headers: X-RM-Service, X-RM-Iat (unix seconds), X-RM-Scope (a tenant id or "*"), X-RM-Signature.
signature = hex(HMAC-SHA256(secret, "\n".join([service, iat, scope, METHOD, path?query, sha256(body)]))).
A request is accepted only if |now - iat| <= window (default 30 s). Tokens scoped to a tenant
cannot touch another tenant (403); scope "*" is reserved for services listed as admin.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

H_SERVICE = "x-rm-service"
H_IAT = "x-rm-iat"
H_SCOPE = "x-rm-scope"
H_SIG = "x-rm-signature"


class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class Principal:
    service: str
    scope: str
    admin: bool

    def can_access(self, tenant: str) -> bool:
        return self.scope == "*" and self.admin or self.scope == tenant


def _string_to_sign(service: str, iat: str, scope: str, method: str, target: str,
                    body: bytes) -> bytes:
    return "\n".join([service, iat, scope, method.upper(), target,
                      hashlib.sha256(body).hexdigest()]).encode()


def sign(secret: str, service: str, scope: str, method: str, target: str, body: bytes = b"",
         iat: int | None = None) -> dict[str, str]:
    iat_s = str(int(time.time()) if iat is None else iat)
    sig = hmac.new(secret.encode(), _string_to_sign(service, iat_s, scope, method, target, body),
                   hashlib.sha256).hexdigest()
    return {"X-RM-Service": service, "X-RM-Iat": iat_s, "X-RM-Scope": scope, "X-RM-Signature": sig}


def verify(keys: dict[str, str], admin_services: set[str], headers: dict[str, str], method: str,
           target: str, body: bytes, window_s: int = 30, now: float | None = None) -> Principal:
    h = {k.lower(): v for k, v in headers.items()}
    service, iat, scope, sig = (h.get(H_SERVICE), h.get(H_IAT), h.get(H_SCOPE), h.get(H_SIG))
    if not (service and iat and scope and sig):
        raise AuthError(401, "missing_auth_headers")
    secret = keys.get(service)
    if not secret:
        raise AuthError(401, "unknown_service")
    try:
        iat_i = int(iat)
    except ValueError:
        raise AuthError(401, "bad_iat") from None
    t = time.time() if now is None else now
    if t - iat_i > window_s or iat_i - t > 5:
        raise AuthError(401, "iat_out_of_window")
    expect = hmac.new(secret.encode(), _string_to_sign(service, iat, scope, method, target, body),
                      hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        raise AuthError(401, "bad_signature")
    admin = service in admin_services
    if scope == "*" and not admin:
        raise AuthError(403, "wildcard_scope_requires_admin")
    return Principal(service, scope, admin)
