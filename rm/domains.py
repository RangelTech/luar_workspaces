"""Custom-domain verification (annex 04 2.5 option 2). Pure functions plus an injectable resolver.

Flow: the tenant creates `_rt-verify.<host> TXT <token>` and `<host> CNAME <app>-<t>.apps...`.
The RM activates the domain only when both are present and re-checks every 24 h; if the CNAME
disappears the domain is deactivated (anti-takeover).
"""
from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable
from datetime import datetime, timedelta

from .traefik import HOST_RE

TxtResolver = Callable[[str], list[str]]
CnameResolver = Callable[[str], list[str]]

# Brands that cannot be claimed as a custom domain label (typosquat/phishing guard); extend freely.
PROTECTED_BRANDS = ("google", "microsoft", "apple", "paypal", "itau", "bradesco", "nubank",
                    "santander", "mercadopago", "mercadolivre", "gov", "whatsapp", "facebook",
                    "instagram", "amazon", "netflix", "caixa", "bancodobrasil")
REVALIDATE_EVERY = timedelta(hours=24)


class DomainError(ValueError):
    pass


def make_token(secret: str, tenant: str, host: str) -> str:
    mac = hmac.new(secret.encode(), f"{tenant}|{host}".encode(), hashlib.sha256).hexdigest()
    return "rt-verify=" + mac[:32]


def txt_name(host: str) -> str:
    return f"_rt-verify.{host}"


def validate_custom_host(host: str, apps_domain: str) -> str:
    h = host.strip().lower().rstrip(".")
    if not HOST_RE.match(h):
        raise DomainError("invalid_host")
    if h == apps_domain or h.endswith("." + apps_domain):
        raise DomainError("platform_domain_not_allowed")
    if h.endswith(".rangeltech.net") or h == "rangeltech.net":
        raise DomainError("platform_domain_not_allowed")
    labels = re.split(r"[.-]", h)
    for brand in PROTECTED_BRANDS:
        if any(brand in lab for lab in labels):
            raise DomainError(f"protected_brand:{brand}")
    return h


def check_txt(host: str, token: str, resolver: TxtResolver) -> bool:
    try:
        values = resolver(txt_name(host))
    except Exception:
        return False
    return any(v.strip().strip('"') == token for v in values)


def check_cname(host: str, target: str, resolver: CnameResolver) -> bool:
    try:
        values = resolver(host)
    except Exception:
        return False
    return any(v.rstrip(".").lower() == target.lower() for v in values)


def verify(host: str, token: str, target: str, txt: TxtResolver, cname: CnameResolver) -> tuple[
        bool, str]:
    if not check_txt(host, token, txt):
        return False, "txt_missing"
    if not check_cname(host, target, cname):
        return False, "cname_missing"
    return True, "ok"


def due_for_revalidation(last_check_at: datetime | None, now: datetime) -> bool:
    return last_check_at is None or now - last_check_at >= REVALIDATE_EVERY


def dns_resolvers() -> tuple[TxtResolver, CnameResolver]:
    """Real resolvers (dnspython). Imported lazily so tests never need the network."""
    import dns.resolver

    def txt(name: str) -> list[str]:
        ans = dns.resolver.resolve(name, "TXT", lifetime=5)
        return [b"".join(r.strings).decode() for r in ans]

    def cname(name: str) -> list[str]:
        ans = dns.resolver.resolve(name, "CNAME", lifetime=5)
        return [str(r.target) for r in ans]

    return txt, cname
