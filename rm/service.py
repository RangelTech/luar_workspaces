"""Tenant service: desired state in the store, observed state in Docker labels, one reconciler.

Rules enforced here (annex 04 1.4, 1.9):
- every mutation runs under a per-tenant lock; tenants run in parallel (bounded by the caller);
- create is "ensure": deterministic names, 409 from Docker means "already exists";
- volumes and data directories are never deleted outside an explicit, guarded purge;
- the old container is stopped before a new generation starts (never two writers);
- only rt.managed=true resources are visible (PolicyDockerClient filters everything else).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from . import domains as dom
from . import naming, nft, sshkeys, templates, traefik
from .backup import BackupBackend, BackupError
from .config import Settings
from .docker_client import Conflict, DockerClient, DockerError
from .firewall import Firewall
from .quota import QuotaBackend
from .store import MemoryStore, PostgresStore

Store = MemoryStore | PostgresStore

RUNTIME_IDLE_S = 30 * 60
WS_IDLE_S = 4 * 3600
PURGE_RETENTION = timedelta(days=30)


class ServiceError(Exception):
    def __init__(self, status: int, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.status = status
        self.code = code
        self.detail = detail


class KeyRevoker(Protocol):
    def revoke(self, tenant: str) -> bool: ...


class NoopRevoker:
    def __init__(self) -> None:
        self.revoked: list[str] = []

    def revoke(self, tenant: str) -> bool:
        self.revoked.append(tenant)
        return True


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime) else v


class TenantService:
    def __init__(self, settings: Settings, store: Store, docker: DockerClient,
                 quota: QuotaBackend, firewall: Firewall, backup: BackupBackend,
                 revoker: KeyRevoker | None = None,
                 txt_resolver: dom.TxtResolver | None = None,
                 cname_resolver: dom.CnameResolver | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC),
                 key_sink: Callable[[str, str], None] | None = None):
        self.s = settings
        self.store = store
        self.docker = docker
        self.quota = quota
        self.firewall = firewall
        self.backup = backup
        self.revoker = revoker or NoopRevoker()
        self.txt = txt_resolver or (lambda name: [])
        self.cname = cname_resolver or (lambda name: [])
        self.sleep = sleep
        self.clock = clock
        self.routes = traefik.RouteWriter(settings.traefik_dir)          # platform Traefik
        self.edge_routes = traefik.RouteWriter(settings.edge_dir)        # rt-edge
        self.key_sink = key_sink  # tests/dev only: receives (tenant, private key)
        self.metrics: Counter[str] = Counter()
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._wakes: dict[str, list[float]] = defaultdict(list)
        self._quota_applied: dict[str, int] = {}

    # ----- paths -------------------------------------------------------------------------
    def tenant_dir(self, t: str) -> str:
        return f"{self.s.tenants_root.rstrip('/')}/{t}"

    def runtime_dir(self, t: str) -> str:
        return f"{self.tenant_dir(t)}/hermes"

    def ws_dir(self, t: str) -> str:
        return f"{self.tenant_dir(t)}/ws"

    def _ensure_dirs(self, t: str) -> None:
        if not self.s.manage_host_dirs:
            return
        for sub in ("hermes", "keys", "ws/home", "ws/workspace", "ws/opt", "ws/rt"):
            os.makedirs(f"{self.tenant_dir(t)}/{sub}", exist_ok=True)
        os.makedirs(f"{self.s.hermes_root.rstrip('/')}/ssh/{t}", exist_ok=True)

    def _write_keys(self, t: str) -> str:
        priv, pub = sshkeys.generate_keypair(f"rt-{t}")
        if self.s.manage_host_dirs:
            for p in (f"{self.tenant_dir(t)}/keys/id_ed25519",
                      f"{self.s.hermes_root.rstrip('/')}/ssh/{t}/id_ed25519"):
                Path(p).parent.mkdir(parents=True, exist_ok=True)
                Path(p).write_text(priv, encoding="utf-8", newline="\n")
                os.chmod(p, 0o400)
        if self.key_sink:
            self.key_sink(t, priv)
        return pub

    # ----- helpers -----------------------------------------------------------------------
    def _need(self, t: str) -> dict:
        row = self.store.get_tenant(t)
        if row is None or row["desired_state"] == "destroyed":
            raise ServiceError(404, "tenant_not_found", t)
        return row

    def _event(self, t: str, actor: str, action: str, detail: dict | None = None) -> None:
        self.store.add_event(t, actor, action, detail)

    def ensure_infra_networks(self) -> None:
        for body in (templates.pool_network(), templates.ssh_hub_network()):
            self._ensure_network(body)

    def _ensure_network(self, body: dict) -> None:
        if self.docker.inspect_network(body["Name"]) is not None:
            return
        try:
            self.docker.create_network(body)
            self.metrics["network_created"] += 1
        except Conflict:
            pass

    # ----- API operations ----------------------------------------------------------------
    def create_tenant(self, t: str, actor: str, plan: str = templates.DEFAULT_PLAN,
                      runtime: bool = False, workspace: bool = True,
                      runtime_image: str | None = None, workspace_image: str | None = None,
                      limits: dict | None = None, quota_gb: int | None = None) -> dict:
        if not naming.valid_tenant(t):
            raise ServiceError(400, "invalid_tenant_id", t)
        if plan not in templates.PLANS:
            raise ServiceError(400, "invalid_plan", plan)
        with self.store.lock(f"tenant:{t}"):
            existing = self.store.get_tenant(t)
            if existing and existing["desired_state"] == "destroyed":
                raise ServiceError(409, "tenant_destroyed", t)
            row, created = self.store.create_tenant(
                t, plan=plan, runtime_enabled=runtime, workspace_enabled=workspace,
                runtime_image_digest=runtime_image or self.s.runtime_image,
                workspace_image_digest=workspace_image or self.s.workspace_image,
                limits_json=limits or {}, quota_gb=quota_gb or templates.PLANS[plan]["quota_gb"])
            if created:
                self._ensure_dirs(t)
                pub = self._write_keys(t)
                row = self.store.update_tenant(t, authorized_key=pub)
                self._event(t, actor, "tenant.create", {"plan": plan, "runtime": runtime,
                                                         "workspace": workspace})
            row = self._reconcile_locked(row, actor)
        return self.view(t)

    def view(self, t: str) -> dict:
        row = self._need(t)
        obs = self.observed(t)
        out = {k: _iso(v) for k, v in row.items() if k not in ("authorized_key",)}
        out["observed"] = obs
        out["usage"] = [{k: _iso(v) for k, v in u.items()} for u in self.store.usage_list(t, 2)]
        out["hosts"] = [traefik.managed_host(e["app"], t, self.s.apps_domain)
                        for e in row["exposures"]]
        return out

    def observed(self, t: str) -> dict:
        res: dict[str, Any] = {}
        for kind, name in (("runtime", naming.runtime_name(t)),
                           ("workspace", naming.workspace_name(t))):
            info = self.docker.inspect_container(name)
            if info is None:
                res[kind] = {"state": "absent"}
                continue
            st = info.get("State") or {}
            lab = (info.get("Config") or {}).get("Labels") or {}
            res[kind] = {"state": "paused" if st.get("Paused") else st.get("Status", "unknown"),
                         "health": (st.get("Health") or {}).get("Status", "none"),
                         "oom_killed": bool(st.get("OOMKilled")),
                         "generation": lab.get(naming.LABEL_GENERATION),
                         "image_digest": lab.get(naming.LABEL_DIGEST),
                         "started_at": st.get("StartedAt")}
        return res

    def set_component(self, t: str, kind: str, action: str, actor: str,
                      timeout_s: int = 60) -> dict:
        if kind not in ("runtime", "workspace"):
            raise ServiceError(400, "bad_component", kind)
        if action not in ("start", "stop", "restart"):
            raise ServiceError(400, "bad_action", action)
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            if not row[f"{kind}_enabled"]:
                raise ServiceError(409, f"{kind}_not_enabled")
            if row["suspended"] and action != "stop":
                raise ServiceError(423, "tenant_suspended")
            if action == "restart":
                name = (naming.runtime_name if kind == "runtime" else naming.workspace_name)(t)
                if self.docker.inspect_container(name) is not None:
                    self.docker.stop(name, 20)
                row = self.store.update_tenant(t, **{f"{kind}_desired": "running"})
            else:
                row = self.store.update_tenant(
                    t, **{f"{kind}_desired": "running" if action == "start" else "stopped"})
            self._event(t, actor, f"{kind}.{action}")
            row = self._reconcile_locked(row, actor)
        if action != "stop" and kind == "runtime":
            self.wait_healthy(naming.runtime_name(t), timeout_s)
        return self.view(t)

    def wait_healthy(self, name: str, timeout_s: int = 60) -> bool:
        deadline = self.clock() + timedelta(seconds=timeout_s)
        while True:
            info = self.docker.inspect_container(name)
            st = (info or {}).get("State") or {}
            health = (st.get("Health") or {}).get("Status")
            if st.get("Running") and health in (None, "healthy"):
                return True
            if self.clock() >= deadline:
                return False
            self.sleep(1)

    def touch_activity(self, t: str) -> None:
        self.store.update_tenant(t, last_activity_at=self.clock())

    # ----- exposures / domains -------------------------------------------------------------
    def publish(self, t: str, app: str, port: int, actor: str, auth: str = "none") -> dict:
        if not naming.APP_PATTERN.match(app):
            raise ServiceError(400, "invalid_app", app)
        if not 1024 <= port <= 65535:
            raise ServiceError(400, "invalid_port", str(port))
        if auth not in ("none", "basic"):
            raise ServiceError(400, "invalid_auth", auth)
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            if not row["workspace_enabled"]:
                raise ServiceError(409, "workspace_not_enabled")
            if row["suspended"]:
                raise ServiceError(423, "tenant_suspended")
            exp = [e for e in row["exposures"] if e["app"] != app]
            exp.append({"app": app, "port": port, "auth": auth})
            self.store.update_tenant(t, exposures=exp)
            self._event(t, actor, "exposure.publish", {"app": app, "port": port})
            self.refresh_routes(t)
        return self.view(t)

    def unpublish(self, t: str, app: str, actor: str) -> dict:
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            exp = [e for e in row["exposures"] if e["app"] != app]
            self.store.update_tenant(t, exposures=exp)
            for d in self.store.domain_list(t):
                if d["app"] == app:
                    self.store.domain_upsert(d["host"], active=False)
            self._event(t, actor, "exposure.unpublish", {"app": app})
            self.refresh_routes(t)
        return self.view(t)

    def add_domain(self, t: str, host: str, app: str, actor: str) -> dict:
        row = self._need(t)
        try:
            h = dom.validate_custom_host(host, self.s.apps_domain)
        except dom.DomainError as e:
            raise ServiceError(400, "invalid_domain", str(e)) from None
        if not any(e["app"] == app for e in row["exposures"]):
            raise ServiceError(409, "app_not_published", app)
        other = self.store.domain_get(h)
        if other and other["tenant_id"] != t:
            raise ServiceError(409, "domain_in_use")
        token = dom.make_token(self.s.domain_secret or "dev", t, h)
        self.store.domain_upsert(h, tenant_id=t, app=app, token=token)
        self._event(t, actor, "domain.add", {"host": h, "app": app})
        return {"host": h, "txt_name": dom.txt_name(h), "txt_value": token,
                "cname_target": traefik.managed_host(app, t, self.s.apps_domain)}

    def verify_domain(self, t: str, host: str, actor: str) -> dict:
        d = self.store.domain_get(host)
        if not d or d["tenant_id"] != t:
            raise ServiceError(404, "domain_not_found", host)
        target = traefik.managed_host(d["app"], t, self.s.apps_domain)
        ok, why = dom.verify(host, d["token"], target, self.txt, self.cname)
        with self.store.lock(f"tenant:{t}"):
            self.store.domain_upsert(host, verified=ok, active=ok, last_check_at=self.clock(),
                                     **({"verified_at": self.clock()} if ok else {}))
            self._event(t, actor, "domain.verify", {"host": host, "ok": ok, "why": why})
            self.refresh_routes(t)
        return {"host": host, "active": ok, "reason": why}

    def revalidate_domains(self) -> int:
        """Run every cycle; only checks domains older than 24 h. Deactivates on failure."""
        changed = 0
        for d in self.store.domain_list():
            if not d["active"] or not dom.due_for_revalidation(d.get("last_check_at"), self.clock()):
                continue
            target = traefik.managed_host(d["app"], d["tenant_id"], self.s.apps_domain)
            ok, why = dom.verify(d["host"], d["token"], target, self.txt, self.cname)
            self.store.domain_upsert(d["host"], last_check_at=self.clock(), active=ok,
                                     verified=ok)
            if not ok:
                changed += 1
                self._event(d["tenant_id"], "reconciler", "domain.deactivate",
                            {"host": d["host"], "why": why})
                self.refresh_routes(d["tenant_id"])
        return changed

    def _remove_routes(self, t: str) -> bool:
        a = self.routes.remove(t)
        b = self.edge_routes.remove(t)
        return a or b

    def refresh_routes(self, t: str) -> bool:
        row = self.store.get_tenant(t)
        if row is None:
            return False
        if row["suspended"] or row["desired_state"] != "running" or not row["exposures"]:
            changed = self._remove_routes(t)
            self._detach_edge(row)
            return changed
        self._attach_edge(row)
        info = self.docker.inspect_container(naming.workspace_name(t))
        running = bool(info and (info.get("State") or {}).get("Running")
                       and not (info.get("State") or {}).get("Paused"))
        custom = {d["host"]: d["app"] for d in self.store.domain_list(t) if d["active"]}
        edge_cfg = traefik.render_edge_routes(t, row["exposures"], self.s.apps_domain,
                                              self.s.edge_upstream_tpl, self.s.wake_url, running,
                                              custom)
        front_cfg = traefik.render_front_routes(t, row["exposures"], self.s.apps_domain,
                                                self.s.edge_front_url, custom)
        # edge first: the platform Traefik must never point at a host the edge does not know
        a = self.edge_routes.write(t, edge_cfg)
        b = self.routes.write(t, front_cfg)
        return a or b

    def _attach_edge(self, row: dict) -> None:
        """rt-edge joins the tenant's egress network at a fixed address (nft allows only it in)."""
        edge = self.s.edge_container
        if not edge or not row["workspace_enabled"]:
            return
        net = naming.egress_net(row["tenant_id"])
        info = self.docker.inspect_container(edge)
        if info is None or self.docker.inspect_network(net) is None:
            return
        if net in ((info.get("NetworkSettings") or {}).get("Networks") or {}):
            return
        self.docker.connect_network(net, edge, naming.edge_ip(row["net_index"]), [edge])

    def _detach_edge(self, row: dict) -> None:
        edge = self.s.edge_container
        if not edge:
            return
        net = naming.egress_net(row["tenant_id"])
        info = self.docker.inspect_container(edge)
        if info and net in ((info.get("NetworkSettings") or {}).get("Networks") or {}):
            self.docker.disconnect_network(net, edge)

    def wake(self, t: str) -> tuple[str, int]:
        row = self.store.get_tenant(t)
        if row is None or row["desired_state"] == "destroyed":
            return "deny", 404
        info = self.docker.inspect_container(naming.workspace_name(t))
        state = (info.get("State") or {}).get("Status", "absent") if info else "absent"
        cutoff = time.time() - 3600
        self._wakes[t] = [x for x in self._wakes[t] if x > cutoff]
        action, status = traefik.wake_decision(state, row["suspended"], bool(row["exposures"]),
                                               len(self._wakes[t]))
        if action == "start" and self.s.allow_wake:
            self._wakes[t].append(time.time())
            try:
                self.set_component(t, "workspace", "start", "wake", timeout_s=0)
            except ServiceError:
                return "deny", 503
        return action, status

    # ----- reconciliation ----------------------------------------------------------------
    def reconcile_tenant(self, t: str, actor: str = "reconciler") -> dict | None:
        with self.store.lock(f"tenant:{t}"):
            row = self.store.get_tenant(t)
            if row is None:
                return None
            return self._reconcile_locked(row, actor)

    def reconcile_all(self) -> int:
        n = 0
        for row in self.store.list_tenants():
            if row["desired_state"] == "destroyed":
                continue
            try:
                self.reconcile_tenant(row["tenant_id"])
                n += 1
            except Exception as e:  # keep the loop alive; the error is surfaced in last_error
                self.metrics["reconcile_errors"] += 1
                try:
                    self.store.update_tenant(row["tenant_id"], last_error=str(e)[:500],
                                             status="degraded")
                except Exception:
                    pass
        self.revalidate_domains()
        self.sleep_idle()
        self.metrics["reconcile_cycles"] += 1
        return n

    def _reconcile_locked(self, row: dict, actor: str) -> dict:
        t = row["tenant_id"]
        stopped_all = row["suspended"] or row["desired_state"] in ("stopped", "retired")
        actions: list[str] = []
        try:
            if row["desired_state"] == "retired":
                actions += self._remove_containers(t)
                self._remove_routes(t)
            else:
                self.ensure_infra_networks()
                actions += self._ensure_tenant_networks(row)
                self._apply_quota(row)
                if row["workspace_enabled"]:
                    run = (not stopped_all) and row["workspace_desired"] == "running"
                    actions += self._ensure_container("workspace", row, run)
                if row["runtime_enabled"]:
                    run = (not stopped_all) and row["runtime_desired"] == "running"
                    actions += self._ensure_container("runtime", row, run)
                self.refresh_routes(t)
            status = self._status(row)
            err = ""
        except Exception as e:
            status, err = "degraded", str(e)[:500]
            self.metrics["reconcile_errors"] += 1
        for a in actions:
            self.metrics[f"action_{a.split(':')[0]}"] += 1
        if actions:
            self._event(t, actor, "reconcile", {"actions": actions})
        upd: dict[str, Any] = {}
        if row["status"] != status:
            upd["status"] = status
        if row["last_error"] != err:
            upd["last_error"] = err
        if upd:
            row = self.store.update_tenant(t, **upd)
        self.refresh_firewall()
        return row

    def _status(self, row: dict) -> str:
        if row["suspended"]:
            return "suspended"
        if row["desired_state"] == "retired":
            return "retired"
        if row["desired_state"] == "stopped":
            return "stopped"
        obs = self.observed(row["tenant_id"])
        want = [k for k in ("runtime", "workspace")
                if row[f"{k}_enabled"] and row[f"{k}_desired"] == "running"]
        if self._is_degraded(row["tenant_id"]):
            return "degraded"
        if all(obs[k]["state"] == "running" for k in want):
            return "running"
        return "provisioning" if row["status"] == "provisioning" else "degraded" if any(
            obs[k]["state"] in ("exited", "dead") for k in want) else "starting"

    def _is_degraded(self, t: str) -> bool:
        cutoff = time.time() - 600
        self._failures[t] = [x for x in self._failures[t] if x > cutoff]
        return len(self._failures[t]) >= 3

    def _apply_quota(self, row: dict) -> None:
        t = row["tenant_id"]
        if not row["workspace_enabled"] and not row["runtime_enabled"]:
            return
        if self._quota_applied.get(t) == row["quota_gb"]:
            return
        self.quota.set_limit(t, self.tenant_dir(t), row["quota_gb"])
        self._quota_applied[t] = row["quota_gb"]

    def _ensure_tenant_networks(self, row: dict) -> list[str]:
        t, idx = row["tenant_id"], row["net_index"]
        acts: list[str] = []
        bodies = []
        if row["runtime_enabled"] or row["workspace_enabled"]:
            bodies.append(templates.tenant_network(t, idx))
        if row["workspace_enabled"]:
            bodies.append(templates.egress_network(t, idx))
        for b in bodies:
            if self.docker.inspect_network(b["Name"]) is None:
                try:
                    self.docker.create_network(b)
                    acts.append(f"network_create:{b['Name']}")
                except Conflict:
                    pass
        return acts

    def _spec_for(self, kind: str, row: dict) -> tuple[str, dict]:
        t = row["tenant_id"]
        if kind == "workspace":
            digest = row["workspace_image_digest"]
            if not digest:
                raise ServiceError(400, "workspace_image_missing")
            listen = [str(naming.tenant_subnet(row["net_index"])), str(naming.SSH_HUB_CIDR)]
            body = templates.workspace_spec(self.s, t, digest, row["generation"],
                                            row["authorized_key"], row["plan"], listen,
                                            row["limits_json"])
            return naming.workspace_name(t), body
        digest = row["runtime_image_digest"]
        if not digest:
            raise ServiceError(400, "runtime_image_missing")
        key = templates.derive_key(self.s.domain_secret or "dev", f"api:{naming.runtime_name(t)}")
        return naming.runtime_name(t), templates.runtime_spec(self.s, t, digest,
                                                              row["generation"], key)

    def _extra_networks(self, kind: str, row: dict) -> list[tuple[str, str | None]]:
        t = row["tenant_id"]
        if kind == "workspace":
            nets: list[tuple[str, str | None]] = []
            if row["runtime_enabled"]:
                nets.append((naming.tenant_net(t), None))
            nets.append((naming.SSH_HUB_NET, naming.hub_workspace_ip(row["net_index"])))
            return nets
        return []

    def _remove_containers(self, t: str) -> list[str]:
        acts = []
        for name in (naming.workspace_name(t), naming.runtime_name(t)):
            info = self.docker.inspect_container(name)
            if info is None:
                continue
            if (info.get("State") or {}).get("Running") or (info.get("State") or {}).get("Paused"):
                self.docker.stop(name, 20)
            self.docker.remove_container(name)  # volumes untouched (v=false)
            acts.append(f"container_remove:{name}")
        return acts

    def _ensure_container(self, kind: str, row: dict, run: bool) -> list[str]:
        t = row["tenant_id"]
        name, body = self._spec_for(kind, row)
        acts: list[str] = []
        info = self.docker.inspect_container(name)
        want_digest = naming.image_digest(body["Image"])
        if info is not None:
            lab = (info.get("Config") or {}).get("Labels") or {}
            if (lab.get(naming.LABEL_GENERATION) != str(row["generation"])
                    or lab.get(naming.LABEL_DIGEST) != want_digest):
                st = info.get("State") or {}
                if st.get("Running") or st.get("Paused"):
                    self.docker.stop(name, 20)  # stop old before creating new: single writer
                self.docker.remove_container(name)
                acts.append(f"container_recreate:{name}")
                info = None
        if info is None:
            if not run:
                return acts
            try:
                self.docker.create_container(name, body)
            except Conflict:
                pass
            for net, ip in self._extra_networks(kind, row):
                self._ensure_network_attached(net, name, ip)
            acts.append(f"container_create:{name}")
            self.docker.start(name)
            acts.append(f"container_start:{name}")
            return acts
        st = info.get("State") or {}
        if st.get("OOMKilled") and not st.get("Running"):
            self._failures[t].append(time.time())
            acts.append(f"oom:{name}")
        if run:
            if st.get("Paused"):
                self.docker.unpause(name)
                acts.append(f"container_unpause:{name}")
            elif not st.get("Running"):
                if st.get("ExitCode", 0) != 0:
                    self._failures[t].append(time.time())
                self.docker.start(name)
                acts.append(f"container_start:{name}")
            elif (st.get("Health") or {}).get("Status") == "unhealthy":
                self._failures[t].append(time.time())
                self.docker.restart(name, 20)
                acts.append(f"container_heal:{name}")
        else:
            if st.get("Running") or st.get("Paused"):
                self.docker.stop(name, 20)
                acts.append(f"container_stop:{name}")
        return acts

    def _ensure_network_attached(self, net: str, container: str, ip: str | None) -> None:
        info = self.docker.inspect_container(container) or {}
        attached = ((info.get("NetworkSettings") or {}).get("Networks") or {})
        if net in attached:
            return
        try:
            self.docker.connect_network(net, container, ip, [container])
        except DockerError as e:
            if e.status != 403 and "already exists" not in e.message:
                raise

    def sleep_idle(self) -> list[str]:
        """Runtime sleeps after 30 min idle; workspace after 4 h, never with exposures."""
        slept: list[str] = []
        now = self.clock()
        for row in self.store.list_tenants():
            if row["desired_state"] != "running" or row["suspended"]:
                continue
            last = row["last_activity_at"]
            if last is None:
                continue
            idle = (now - last).total_seconds()
            t = row["tenant_id"]
            if row["runtime_enabled"] and row["runtime_desired"] == "running" and \
                    idle > RUNTIME_IDLE_S:
                self.store.update_tenant(t, runtime_desired="stopped")
                self._event(t, "reconciler", "runtime.sleep", {"idle_s": int(idle)})
                slept.append(f"{t}:runtime")
            if (row["workspace_enabled"] and row["workspace_desired"] == "running"
                    and not row["exposures"] and idle > WS_IDLE_S):
                self.store.update_tenant(t, workspace_desired="stopped")
                self._event(t, "reconciler", "workspace.sleep", {"idle_s": int(idle)})
                slept.append(f"{t}:workspace")
        return slept

    # ----- firewall ----------------------------------------------------------------------
    def refresh_firewall(self, workers: list[dict] | None = None) -> bool:
        tenants = []
        for r in self.store.list_tenants():
            if r["desired_state"] in ("destroyed", "retired") or not r["workspace_enabled"]:
                continue
            tenants.append(nft.tenant_net_for(r["tenant_id"], r["net_index"], r["suspended"]))
        ws = workers if workers is not None else self.store.worker_list()
        ips = [naming.hub_worker_ip(w["slot"]) for w in ws if w["slot"] <= 13]
        return self.firewall.apply(nft.FirewallInput(
            tenants=tenants, worker_ips=ips, dns_servers=list(self.s.workspace_dns)))

    # ----- kill switch -------------------------------------------------------------------
    def suspend(self, t: str, actor: str, reason: str, severity: str = "high") -> dict:
        t0 = time.monotonic()
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            if row["suspended"]:
                return self.view(t)
            # (1) cut routes and network first
            self._remove_routes(t)
            row = self.store.update_tenant(t, suspended=True, suspend_reason=reason[:300],
                                           suspended_by=actor, status="suspended")
            self.refresh_firewall()
            # (6 early) forensic snapshot while the memory is still there
            forensic = self._forensics(t, reason)
            # (2) pause the workspace (keeps memory for forensics) or stop on severity=critical
            ws = naming.workspace_name(t)
            info = self.docker.inspect_container(ws)
            if info and (info.get("State") or {}).get("Running"):
                if severity == "critical":
                    self.docker.stop(ws, 5)
                else:
                    self.docker.pause(ws)
            # (3) runtime stop
            rt = naming.runtime_name(t)
            if self.docker.inspect_container(rt) is not None:
                self.docker.stop(rt, 10)
            # (4) revoke the virtual LLM key
            revoked = self.revoker.revoke(t)
            elapsed = time.monotonic() - t0
            self._event(t, actor, "tenant.suspend", {"reason": reason, "severity": severity,
                                                      "revoked": revoked, "forensics": forensic,
                                                      "elapsed_s": round(elapsed, 3)})
        return self.view(t)

    def _forensics(self, t: str, reason: str) -> str:
        d = Path(self.s.forensics_dir) / t / self.clock().strftime("%Y%m%dT%H%M%SZ")
        try:
            d.mkdir(parents=True, exist_ok=True)
            snap: dict[str, Any] = {"tenant": t, "reason": reason, "containers": {}}
            for name in (naming.workspace_name(t), naming.runtime_name(t)):
                info = self.docker.inspect_container(name)
                if info is not None:
                    snap["containers"][name] = {"inspect": info,
                                                "stats": self.docker.container_stats(name),
                                                "logs_tail": self.docker.container_logs(name, 200)}
            (d / "snapshot.json").write_text(json.dumps(snap, default=str, indent=2),
                                             encoding="utf-8")
            return str(d)
        except OSError:
            return ""

    def resume(self, t: str, actor: str, approver: str, is_admin: bool) -> dict:
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            if not row["suspended"]:
                return self.view(t)
            if not is_admin:
                raise ServiceError(403, "resume_requires_admin")
            if not approver or approver in (row["suspended_by"], actor):
                raise ServiceError(403, "second_approver_required",
                                   "approver must differ from the suspending actor and requester")
            row = self.store.update_tenant(t, suspended=False, suspend_reason="", suspended_by="",
                                           status="starting")
            ws = naming.workspace_name(t)
            info = self.docker.inspect_container(ws)
            if info and (info.get("State") or {}).get("Paused"):
                self.docker.unpause(ws)
            self._event(t, actor, "tenant.resume", {"approver": approver})
            self._reconcile_locked(row, actor)
        return self.view(t)

    def freeze_fleet(self, actor: str, reason: str) -> list[str]:
        """Global kill switch: stop every workspace (runtimes keep their state on disk)."""
        done = []
        for row in self.store.list_tenants():
            if row["workspace_enabled"] and row["desired_state"] == "running":
                self.suspend(row["tenant_id"], actor, f"fleet freeze: {reason}", "critical")
                done.append(row["tenant_id"])
        self.store.kv_set("fleet_frozen", {"by": actor, "reason": reason,
                                           "at": self.clock().isoformat()})
        return done

    # ----- destroy / purge ---------------------------------------------------------------
    def retire(self, t: str, actor: str) -> dict:
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            row = self.store.update_tenant(t, desired_state="retired", status="retired",
                                           purge_after=self.clock() + PURGE_RETENTION)
            self._event(t, actor, "tenant.retire", {"purge_after": _iso(row["purge_after"])})
            self._reconcile_locked(row, actor)
        return self.view(t)

    def purge(self, t: str, actor: str, confirm: str, is_admin: bool,
              override: bool = False) -> dict:
        """Irreversible. Guards: admin scope, confirm == tenant id, retention elapsed (or an
        explicit override), and a fresh pre_purge backup. Volumes and data dirs go only here."""
        if not is_admin:
            raise ServiceError(403, "purge_requires_admin")
        if confirm != t:
            raise ServiceError(400, "purge_confirm_mismatch", "confirm must equal the tenant id")
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            due = row["purge_after"] is not None and row["purge_after"] <= self.clock()
            if row["desired_state"] != "retired" or not (due or override):
                raise ServiceError(409, "purge_guard",
                                   "tenant must be retired and past retention (or override=true)")
            recent = [b for b in self.store.backup_list(t) if b["kind"] == "pre_purge"
                      and self.clock() - b["created_at"] < timedelta(hours=24)]
            if not recent:
                rec = self.backup.create(t, "pre_purge", self.runtime_dir(t), self.ws_dir(t),
                                         {"generation": row["generation"]})
                self.store.backup_add(rec)
            self._remove_containers(t)
            self._detach_edge(row)
            for net in (naming.tenant_net(t), naming.egress_net(t)):
                self.docker.remove_network(net)
            for v in self.docker.list_volumes([f"{naming.LABEL_TENANT}={t}"]):
                self.docker.remove_volume(v["Name"], purge_of=t)
            self.quota.remove(t)
            self._quota_applied.pop(t, None)
            self._remove_routes(t)
            if self.s.manage_host_dirs:
                import shutil
                for p in (self.tenant_dir(t), f"{self.s.hermes_root.rstrip('/')}/ssh/{t}"):
                    shutil.rmtree(p, ignore_errors=True)
            self.store.update_tenant(t, desired_state="destroyed", status="destroyed",
                                     exposures=[])
            for d in self.store.domain_list(t):
                self.store.domain_delete(d["host"])
            self._event(t, actor, "tenant.purge", {"override": override})
            self.refresh_firewall()
        return {"tenant_id": t, "status": "destroyed"}

    # ----- backup / restore / upgrade ----------------------------------------------------------
    def make_backup(self, t: str, actor: str, kind: str = "manual") -> dict:
        row = self._need(t)
        rec = self.backup.create(t, kind, self.runtime_dir(t) if row["runtime_enabled"] else None,
                                 self.ws_dir(t) if row["workspace_enabled"] else None,
                                 {"generation": row["generation"],
                                  "runtime_digest": row["runtime_image_digest"],
                                  "workspace_digest": row["workspace_image_digest"]})
        self.store.backup_add(rec)
        self._event(t, actor, "backup.create", {"backup_id": rec["backup_id"], "kind": kind})
        return {"backup_id": rec["backup_id"], "sha256": rec["sha256"], "kind": kind}

    def restore(self, t: str, backup_id: str, mode: str, actor: str,
                clone_as: str | None = None) -> dict:
        rec = self.store.backup_get(backup_id)
        if rec is None or rec["tenant_id"] != t:
            raise ServiceError(404, "backup_not_found", backup_id)
        if mode not in ("replace", "clone"):
            raise ServiceError(400, "bad_mode", mode)
        src = self._need(t)
        if mode == "clone":
            if not clone_as or not naming.valid_tenant(clone_as) or clone_as == t:
                raise ServiceError(400, "clone_as_required")
            if self.store.get_tenant(clone_as):
                raise ServiceError(409, "clone_exists", clone_as)
            self.create_tenant(clone_as, actor, src["plan"], src["runtime_enabled"],
                               src["workspace_enabled"], src["runtime_image_digest"],
                               src["workspace_image_digest"], src["limits_json"], src["quota_gb"])
            target = clone_as
        else:
            target = t
        with self.store.lock(f"tenant:{target}"):
            row = self._need(target)
            self._remove_containers(target)  # stop before writing: single writer
            res = self.backup.restore(rec, self.runtime_dir(target) if row["runtime_enabled"]
                                      else None, self.ws_dir(target) if row["workspace_enabled"]
                                      else None)
            self._event(target, actor, "backup.restore",
                        {"backup_id": backup_id, "mode": mode, **res})
            self._reconcile_locked(self.store.get_tenant(target), actor)
        return {"tenant_id": target, "mode": mode, **res}

    def upgrade_runtime(self, t: str, digest: str, actor: str, timeout_s: int = 60) -> dict:
        """Backup, recreate with the new digest on the same data, wait health; roll back on failure."""
        if not naming.image_digest(digest):
            raise ServiceError(400, "digest_required")
        with self.store.lock(f"tenant:{t}"):
            row = self._need(t)
            if not row["runtime_enabled"]:
                raise ServiceError(409, "runtime_not_enabled")
            prev = row["runtime_image_digest"]
            if prev == digest:
                return {"tenant_id": t, "result": "noop", "digest": digest}
        bk = self.make_backup(t, actor, "pre_upgrade")
        with self.store.lock(f"tenant:{t}"):
            row = self.store.update_tenant(t, runtime_image_digest=digest,
                                           generation=self._need(t)["generation"] + 1)
            self._reconcile_locked(row, actor)
        ok = self.wait_healthy(naming.runtime_name(t), timeout_s)
        if ok:
            self._event(t, actor, "runtime.upgrade", {"from": prev, "to": digest})
            return {"tenant_id": t, "result": "upgraded", "digest": digest, "backup": bk}
        with self.store.lock(f"tenant:{t}"):
            row = self.store.update_tenant(t, runtime_image_digest=prev,
                                           generation=self._need(t)["generation"] + 1)
            self._reconcile_locked(row, actor)
        self._event(t, actor, "runtime.upgrade_rollback", {"from": digest, "to": prev})
        self.metrics["upgrade_rollbacks"] += 1
        return {"tenant_id": t, "result": "rolled_back", "digest": prev, "backup": bk}

    # ----- fleet / metrics -----------------------------------------------------------------
    def fleet(self) -> dict:
        rows = self.store.list_tenants()
        by_status = Counter(r["status"] for r in rows if r["desired_state"] != "destroyed")
        return {"tenants": sum(by_status.values()), "by_status": dict(by_status),
                "workers": Counter(w["status"] for w in self.store.worker_list()),
                "quota": self.quota.report(), "frozen": self.store.kv_get("fleet_frozen")}

    def metrics_text(self) -> str:
        f = self.fleet()
        lines = ["# TYPE rt_tenants gauge"]
        for st, n in sorted(f["by_status"].items()):
            lines.append(f'rt_tenants{{status="{st}"}} {n}')
        lines.append("# TYPE rt_pool_workers gauge")
        for st, n in sorted(f["workers"].items()):
            lines.append(f'rt_pool_workers{{status="{st}"}} {n}')
        lines.append("# TYPE rt_reconcile_actions_total counter")
        for k, v in sorted(self.metrics.items()):
            lines.append(f'rt_reconcile_actions_total{{action="{k}"}} {v}')
        lines.append("# TYPE rt_disk_used_bytes gauge")
        for t, q in sorted(f["quota"].items()):
            lines.append(f'rt_disk_used_bytes{{tenant="{t}"}} {q["used"]}')
            lines.append(f'rt_disk_limit_bytes{{tenant="{t}"}} {q["hard"]}')
        return "\n".join(lines) + "\n"

    def hash_request(self, method: str, path: str, body: bytes) -> str:
        return hashlib.sha256(f"{method}\n{path}\n".encode() + body).hexdigest()


__all__ = ["BackupError", "ServiceError", "TenantService", "NoopRevoker", "KeyRevoker"]
