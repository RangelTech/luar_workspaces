"""Traefik file-provider route writer for exposures (annex 04 2.5, 2.6).

One YAML per tenant under the dynamic dir (provider `file`, watch: true). Host is strict:
a tenant can only route `<app>-<tenant>.apps.<domain>` (or a verified custom domain).
When the workspace is asleep the service points to the RM wake endpoint instead.
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

from . import naming

HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def managed_host(app: str, tenant: str, apps_domain: str) -> str:
    if not naming.APP_PATTERN.match(app):
        raise ValueError(f"invalid app name: {app!r}")
    if not naming.valid_tenant(tenant):
        raise ValueError(f"invalid tenant: {tenant!r}")
    return f"{app}-{tenant}.{apps_domain}"


def host_belongs_to_tenant(host: str, tenant: str, apps_domain: str) -> bool:
    """Strict Host: <app>-<tenant>.<apps_domain> and nothing else under the platform domain."""
    pat = rf"([a-z][a-z0-9]{{1,19}})-{re.escape(tenant)}\.{re.escape(apps_domain)}"
    return bool(re.fullmatch(pat, host))


def _rid(tenant: str, app: str) -> str:
    return f"rt-{tenant}-{app}"


def _hosts_for(tenant: str, app: str, apps_domain: str,
               custom_hosts: dict[str, str] | None) -> list[str]:
    hosts = [managed_host(app, tenant, apps_domain)]
    hosts += sorted(h for h, a in (custom_hosts or {}).items() if a == app)
    return hosts


def _host_rule(hosts: list[str]) -> str:
    return " || ".join(f"Host(`{h}`)" for h in hosts)


def render_front_routes(tenant: str, exposures: list[dict], apps_domain: str, edge_url: str,
                        custom_hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """Platform Traefik (TLS, Let's Encrypt per host): exact hosts -> rt-edge.

    exposures: [{"app": "metabase", "port": 3000, "auth": "none|basic"}]
    custom_hosts: {host: app} for verified, active custom domains.
    """
    routers: dict[str, Any] = {}
    services: dict[str, Any] = {}
    middlewares: dict[str, Any] = {
        f"rt-{tenant}-rl": {"rateLimit": {"average": 50, "burst": 100, "period": "1s"}},
        f"rt-{tenant}-inflight": {"inFlightReq": {"amount": 100}},
        f"rt-{tenant}-body": {"buffering": {"maxRequestBodyBytes": 50 * 1024 * 1024,
                                            "memRequestBodyBytes": 1024 * 1024}},
        f"rt-{tenant}-hdr": {"headers": {
            "stsSeconds": 31536000, "stsIncludeSubdomains": False,
            "frameDeny": True, "contentTypeNosniff": True,
            "referrerPolicy": "same-origin", "browserXssFilter": True,
            "customResponseHeaders": {"Server": "", "X-Powered-By": ""},
        }},
    }
    mw = [f"rt-{tenant}-rl", f"rt-{tenant}-inflight", f"rt-{tenant}-body", f"rt-{tenant}-hdr"]
    for e in exposures:
        app = e["app"]
        rid = _rid(tenant, app)
        routers[rid] = {"rule": _host_rule(_hosts_for(tenant, app, apps_domain, custom_hosts)),
                        "entryPoints": ["websecure"], "service": rid, "middlewares": list(mw),
                        "tls": {"certResolver": "letsencrypt"}}
        services[rid] = {"loadBalancer": {"servers": [{"url": edge_url}],
                                          "passHostHeader": True}}
    return {"http": {"routers": routers, "services": services, "middlewares": middlewares}}


def render_edge_routes(tenant: str, exposures: list[dict], apps_domain: str, upstream_tpl: str,
                       wake_url: str, workspace_running: bool,
                       custom_hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """rt-edge (plain HTTP, only reachable from the platform Traefik): strict Host -> workspace.

    A Host that is not listed here gets Traefik's 404, so a tenant can only ever receive
    traffic for its own <app>-<tenant> name or a verified custom domain. While the workspace is
    asleep the service points to the RM wake endpoint instead.
    """
    routers: dict[str, Any] = {}
    services: dict[str, Any] = {}
    hdr = f"rt-{tenant}-edgehdr"
    middlewares: dict[str, Any] = {hdr: {"headers": {"customRequestHeaders": {
        "X-RT-Tenant": tenant}}}}
    for e in exposures:
        app, port = e["app"], int(e["port"])
        rid = _rid(tenant, app)
        if workspace_running:
            url = upstream_tpl.format(tenant=tenant, port=port)
        else:
            url = f"{wake_url.rstrip('/')}/wake/{tenant}"
        routers[rid] = {"rule": _host_rule(_hosts_for(tenant, app, apps_domain, custom_hosts)),
                        "entryPoints": ["web"], "service": rid, "middlewares": [hdr]}
        services[rid] = {"loadBalancer": {"servers": [{"url": url}], "passHostHeader": True}}
    return {"http": {"routers": routers, "services": services, "middlewares": middlewares}}


class RouteWriter:
    def __init__(self, directory: str):
        self.dir = Path(directory)

    def path(self, tenant: str) -> Path:
        if not naming.valid_tenant(tenant):
            raise ValueError("invalid tenant")
        return self.dir / f"{tenant}.yml"

    def write(self, tenant: str, config: dict) -> bool:
        """Atomic write; returns True when the file changed. Empty config removes the file."""
        if not config.get("http", {}).get("routers"):
            return self.remove(tenant)
        text = yaml.safe_dump(config, sort_keys=True)
        p = self.path(tenant)
        if p.exists() and p.read_text(encoding="utf-8") == text:
            return False
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f".{tenant}.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, p)
        return True

    def remove(self, tenant: str) -> bool:
        p = self.path(tenant)
        if p.exists():
            p.unlink()
            return True
        return False


def wake_decision(workspace_state: str, suspended: bool, has_exposures: bool, wakes_last_hour: int,
                  max_wakes_per_hour: int = 20) -> tuple[str, int]:
    """Pure decision for the wake-on-request hook. Returns (action, http_status).

    action: start | wait | deny | ready. 503 + Retry-After while starting; 404 when nothing is
    exposed (do not leak tenants); 403 when suspended; 429 when abusing wake.
    """
    if not has_exposures:
        return "deny", 404
    if suspended:
        return "deny", 403
    if workspace_state == "running":
        return "ready", 200
    if workspace_state in ("created", "restarting", "starting"):
        return "wait", 503
    if wakes_last_hour >= max_wakes_per_hour:
        return "deny", 429
    return "start", 503


WAKE_PAGE = (
    "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5>"
    "<title>Iniciando</title>"
    "<body style='font-family:sans-serif;text-align:center;margin-top:20vh'>"
    "<h2>Seu ambiente est&aacute; acordando</h2><p>Tentando de novo em 5 segundos.</p>"
)
