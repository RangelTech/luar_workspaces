"""HTTP API (annex 04 section 1.3 plus pool management). JSON, idempotent, HMAC authenticated."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from . import auth, naming, traefik
from .abuse import AbuseMonitor
from .config import Settings
from .docker_client import DockerError
from .executor import ExecutorRunner
from .policy import PolicyViolation
from .pool import PoolManager
from .service import ServiceError, TenantService
from .usage import UsageSampler

log = logging.getLogger("rm")


class Ctx:
    def __init__(self, settings: Settings, svc: TenantService, pool: PoolManager,
                 usage: UsageSampler | None = None, executor: ExecutorRunner | None = None,
                 abuse: AbuseMonitor | None = None):
        self.settings = settings
        self.svc = svc
        self.pool = pool
        self.usage = usage
        self.executor = executor
        self.abuse = abuse


def _err(status: int, code: str, detail: str = "") -> JSONResponse:
    return JSONResponse({"error": code, "detail": detail}, status_code=status)


async def _body_json(request: Request) -> dict:
    raw = await request.body()
    if not raw:
        return {}
    try:
        v = json.loads(raw)
    except ValueError:
        raise ServiceError(400, "invalid_json") from None
    if not isinstance(v, dict):
        raise ServiceError(400, "json_object_required")
    return v


def create_app(ctx: Ctx) -> FastAPI:
    app = FastAPI(title="runtime-manager", version="0.1.0", docs_url=None, redoc_url=None,
                  openapi_url=None)
    s, svc, pool = ctx.settings, ctx.svc, ctx.pool

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        task = None
        if s.reconcile_enabled:
            task = asyncio.create_task(_loop())
        try:
            yield
        finally:
            if task:
                task.cancel()

    app.router.lifespan_context = lifespan

    async def _loop() -> None:
        usage_due = 0.0
        while True:
            try:
                await asyncio.to_thread(_cycle)
                usage_due += s.reconcile_interval_s
                if ctx.usage and usage_due >= s.usage_interval_s:
                    usage_due = 0.0
                    await asyncio.to_thread(ctx.usage.sample_once)
            except Exception:
                log.exception("reconcile cycle failed")
            await asyncio.sleep(s.reconcile_interval_s)

    def _cycle() -> None:
        svc.reconcile_all()
        if ctx.abuse:
            ctx.abuse.scan()
        if pool.config()["size"]:
            pool.heal()
            pool.recycle_due()

    # ----- error mapping ----------------------------------------------------------------------
    @app.exception_handler(ServiceError)
    async def _svc_err(_: Request, e: ServiceError):
        return _err(e.status, e.code, e.detail)

    @app.exception_handler(auth.AuthError)
    async def _auth_err(_: Request, e: auth.AuthError):
        return _err(e.status, e.detail)

    @app.exception_handler(PolicyViolation)
    async def _pol_err(_: Request, e: PolicyViolation):
        return _err(422, "policy_violation", str(e))

    @app.exception_handler(DockerError)
    async def _dock_err(_: Request, e: DockerError):
        return _err(502, "docker_error", e.message)

    async def principal(request: Request) -> auth.Principal:
        body = await request.body()
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return auth.verify(s.service_keys, s.admin_services, dict(request.headers),
                           request.method, target, body, s.iat_window_s)

    def need_tenant(p: auth.Principal, t: str) -> None:
        if not naming.valid_tenant(t):
            raise ServiceError(400, "invalid_tenant_id", t)
        if not p.can_access(t):
            raise ServiceError(403, "forbidden_tenant", t)

    def need_admin(p: auth.Principal) -> None:
        if not (p.admin and p.scope == "*"):
            raise ServiceError(403, "admin_required")

    async def idempotent(request: Request, t: str, fn):
        key = request.headers.get("idempotency-key")
        if not key:
            return await asyncio.to_thread(fn)
        raw = await request.body()
        h = svc.hash_request(request.method, request.url.path, raw)
        prev = svc.store.idem_get(t, key)
        if prev:
            if prev["request_hash"] != h:
                raise ServiceError(409, "idempotency_key_conflict")
            return JSONResponse(prev["response"], status_code=prev["status_code"])
        result = await asyncio.to_thread(fn)
        payload = json.loads(json.dumps(result, default=str))
        svc.store.idem_put(t, key, h, payload, 200)
        return JSONResponse(payload)

    # ----- open endpoints -------------------------------------------------------------------------
    @app.get("/health")
    def health():
        return {"status": "ok", "store": svc.store.ping(), "docker": svc.docker.ping()}

    @app.get("/wake/{t}")
    async def wake(t: str, request: Request):
        # Public hit coming from Traefik for a sleeping workspace. No auth, no data leaked.
        if not naming.valid_tenant(t):
            return PlainTextResponse("not found", status_code=404)
        action, status = await asyncio.to_thread(svc.wake, t)
        if status == 404 or action == "deny" and status in (403, 429):
            return PlainTextResponse({404: "not found", 403: "suspended", 429: "slow down"}
                                     .get(status, "denied"), status_code=status)
        return HTMLResponse(traefik.WAKE_PAGE, status_code=status, headers={"Retry-After": "5"})

    @app.get("/metrics")
    async def metrics(request: Request):
        tok = request.headers.get("authorization", "")
        if s.metrics_token and tok == f"Bearer {s.metrics_token}":
            pass
        else:
            p = await principal(request)
            need_admin(p)
        return PlainTextResponse(await asyncio.to_thread(svc.metrics_text))

    # ----- fleet --------------------------------------------------------------------------------------
    @app.get("/v1/fleet")
    async def fleet(request: Request):
        need_admin(await principal(request))
        return await asyncio.to_thread(svc.fleet)

    @app.post("/v1/fleet:freeze")
    async def freeze(request: Request):
        p = await principal(request)
        need_admin(p)
        b = await _body_json(request)
        done = await asyncio.to_thread(svc.freeze_fleet, p.service, str(b.get("reason", "")))
        return {"frozen": done}

    # ----- executor ----------------------------------------------------------------------------------
    @app.post("/v1/executor/runs")
    async def executor_run(request: Request):
        need_admin(await principal(request))
        if ctx.executor is None:
            raise ServiceError(503, "executor_not_configured")
        b = await _body_json(request)
        return await asyncio.to_thread(
            ctx.executor.run, str(b.get("script", "")), b.get("inputs") or {},
            int(b.get("timeout_s", 60)), int(b.get("mem_mb", 512)), float(b.get("cpus", 1.0)))

    # ----- pool -------------------------------------------------------------------------------------------
    @app.get("/v1/pool")
    async def pool_status(request: Request):
        need_admin(await principal(request))
        return await asyncio.to_thread(pool.status)

    @app.put("/v1/pool")
    async def pool_ensure(request: Request):
        need_admin(await principal(request))
        b = await _body_json(request)
        return await asyncio.to_thread(
            lambda: pool.ensure(b.get("size"), b.get("image"), int(b.get("wait_s", 90))) if
            not (b.get("recycle_after_runs") is not None and pool.set_config(
                recycle_after_runs=int(b["recycle_after_runs"])) and False) else {})

    @app.get("/v1/pool/assign/{tenant}")
    async def pool_assign(tenant: str, request: Request):
        need_admin(await principal(request))
        if not naming.valid_tenant(tenant):
            raise ServiceError(400, "invalid_tenant_id", tenant)
        return await asyncio.to_thread(pool.assign, tenant)

    @app.post("/v1/pool/workers/{wid}/recycle")
    async def pool_recycle(wid: str, request: Request):
        need_admin(await principal(request))
        return await asyncio.to_thread(pool.recycle, wid, "on_demand")

    @app.post("/v1/pool/workers/{wid}/fence")
    async def pool_fence(wid: str, request: Request):
        p = await principal(request)
        need_admin(p)
        return await asyncio.to_thread(pool.fence, wid, p.service)

    @app.post("/v1/pool/workers/{wid}/runs")
    async def pool_runs(wid: str, request: Request):
        need_admin(await principal(request))
        b = await _body_json(request)
        return await asyncio.to_thread(pool.report_runs, wid, int(b.get("finished", 0)),
                                       b.get("inflight"))

    @app.post("/v1/pool/upgrade")
    async def pool_upgrade(request: Request):
        need_admin(await principal(request))
        b = await _body_json(request)
        return await asyncio.to_thread(pool.upgrade, str(b.get("image", "")),
                                       int(b.get("wave_size", 2)), int(b.get("wait_s", 90)))

    # ----- tenants (verb routes first: "{t}:suspend" must not match "{t}") ---------------------
    @app.post("/v1/tenants/{t}:{verb}")
    async def tenant_verb(t: str, verb: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        need_admin(p)
        b = await _body_json(request)
        if verb == "suspend":
            return await idempotent(request, t, lambda: svc.suspend(
                t, p.service, str(b.get("reason", "")), str(b.get("severity", "high"))))
        if verb == "resume":
            return await idempotent(request, t, lambda: svc.resume(
                t, p.service, str(b.get("approver", "")), p.admin))
        raise ServiceError(404, "unknown_verb", verb)

    @app.post("/v1/tenants/{t}")
    async def tenant_create(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        need_admin(p)
        b = await _body_json(request)
        return await idempotent(request, t, lambda: svc.create_tenant(
            t, p.service, b.get("plan", "standard"), bool(b.get("runtime", False)),
            bool(b.get("workspace", True)), b.get("runtime_image"), b.get("workspace_image"),
            b.get("limits"), b.get("quota_gb")))

    @app.get("/v1/tenants/{t}")
    async def tenant_get(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        return await asyncio.to_thread(svc.view, t)

    @app.delete("/v1/tenants/{t}")
    async def tenant_delete(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        need_admin(p)
        q = request.query_params
        if q.get("purge") == "true":
            return await asyncio.to_thread(svc.purge, t, p.service, q.get("confirm", ""), p.admin,
                                           q.get("override") == "true")
        return await asyncio.to_thread(svc.retire, t, p.service)

    @app.post("/v1/tenants/{t}/runtime:{action}")
    async def runtime_action(t: str, action: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        if action == "upgrade":
            need_admin(p)
            b = await _body_json(request)
            return await idempotent(request, t, lambda: svc.upgrade_runtime(
                t, str(b.get("image_digest", "")), p.service))
        return await idempotent(request, t, lambda: svc.set_component(t, "runtime", action,
                                                                      p.service))

    @app.post("/v1/tenants/{t}/workspace:{action}")
    async def workspace_action(t: str, action: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        if action == "put":
            b = await _body_json(request)
            import base64 as b64
            try:
                data = b64.b64decode(str(b.get("content_base64", "")), validate=True)
            except ValueError:
                raise ServiceError(400, "bad_content") from None
            return await asyncio.to_thread(svc.put_workspace_file, t, str(b.get("path", "")), data,
                                           p.service)
        if action == "get":
            b = await _body_json(request)
            import base64 as b64
            res = await asyncio.to_thread(svc.get_workspace_file, t, str(b.get("path", "")), p.service)
            return {"path": res["path"], "size": res["size"],
                    "content_base64": b64.b64encode(res["content"]).decode()}
        if action == "exec":
            b = await _body_json(request)
            return await asyncio.to_thread(
                svc.exec_workspace, t, str(b.get("command", "")), p.service,
                int(b.get("timeout_s", 60)), str(b.get("cwd") or "/workspace"),
                b.get("env") if isinstance(b.get("env"), dict) else None)
        return await idempotent(request, t, lambda: svc.set_component(t, "workspace", action,
                                                                      p.service))

    @app.get("/v1/tenants/{t}/services")
    async def services_list(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        return await asyncio.to_thread(svc.list_services, t, p.service)

    @app.get("/v1/tenants/{t}/services/{name}/logs")
    async def service_logs(t: str, name: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        q = request.query_params
        try:
            lines = int(q.get("lines", "200"))
        except ValueError:
            raise ServiceError(400, "invalid_lines") from None
        return await asyncio.to_thread(svc.service_logs, t, name, p.service, lines,
                                       str(q.get("by", "")))

    @app.post("/v1/tenants/{t}/services/{name}:{action}")
    async def service_act(t: str, name: str, action: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        b = await _body_json(request)
        return await asyncio.to_thread(svc.service_action, t, name, action, p.service,
                                       str(b.get("by", "")))

    @app.post("/v1/tenants/{t}/activity")
    async def activity(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        await asyncio.to_thread(svc.touch_activity, t)
        return {"ok": True}

    @app.post("/v1/tenants/{t}/backup")
    async def backup(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        return await idempotent(request, t, lambda: svc.make_backup(t, p.service))

    @app.get("/v1/tenants/{t}/backups")
    async def backups(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        rows = await asyncio.to_thread(svc.store.backup_list, t)
        return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r.items()}
                for r in rows]

    @app.post("/v1/tenants/{t}/restore")
    async def restore(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        b = await _body_json(request)
        if b.get("mode") == "clone":
            need_admin(p)
        return await idempotent(request, t, lambda: svc.restore(
            t, str(b.get("backup_id", "")), str(b.get("mode", "replace")), p.service,
            b.get("clone_as")))

    @app.post("/v1/tenants/{t}/exposures")
    async def expose(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        b = await _body_json(request)
        return await idempotent(request, t, lambda: svc.publish(
            t, str(b.get("app", "")), int(b.get("port", 0)), p.service, str(b.get("auth", "none"))))

    @app.delete("/v1/tenants/{t}/exposures/{appname}")
    async def unexpose(t: str, appname: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        return await asyncio.to_thread(svc.unpublish, t, appname, p.service)

    @app.post("/v1/tenants/{t}/domains")
    async def add_domain(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        b = await _body_json(request)
        return await asyncio.to_thread(svc.add_domain, t, str(b.get("host", "")),
                                       str(b.get("app", "")), p.service)

    @app.post("/v1/tenants/{t}/domains/{host}/verify")
    async def verify_domain(t: str, host: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        return await asyncio.to_thread(svc.verify_domain, t, host, p.service)

    @app.get("/v1/tenants/{t}/events")
    async def events(t: str, request: Request):
        p = await principal(request)
        need_tenant(p, t)
        rows = await asyncio.to_thread(svc.store.list_events, t, 100)
        return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r.items()}
                for r in rows]

    return app


def _unused(*_: Any) -> None:  # keeps imports honest for type checkers
    return None
