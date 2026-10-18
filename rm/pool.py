"""Worker pool: ensure N, recycle, fencing and upgrade by waves (spec 04 5.3, 9.1; annex 1.8).

Invariants:
- one writer per profile: a tenant is assigned to exactly one worker (rendezvous hashing over the
  candidate set) and is reassigned only after the previous owner is confirmed stopped;
- fencing = stop (then kill) + inspect proves the container is not running; if that cannot be
  proven the tenants stay unavailable (assignment returns worker=None) rather than double-assigned.
"""
from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from datetime import UTC, datetime

from . import naming, templates
from .config import Settings
from .docker_client import Conflict, DockerClient
from .firewall import Firewall
from .service import ServiceError
from .store import MemoryStore, PostgresStore

Store = MemoryStore | PostgresStore

CANDIDATE_STATES = ("ready", "fencing", "recycling", "failed")  # still potentially running: block reassign
MAX_WORKERS = 13


def hrw_pick(tenant: str, worker_ids: list[str]) -> str | None:
    """Highest-random-weight (rendezvous) hash: stable when the set changes by one."""
    best, best_w = None, -1
    for w in worker_ids:
        weight = int.from_bytes(hashlib.sha256(f"{tenant}|{w}".encode()).digest()[:8], "big")
        if weight > best_w:
            best, best_w = w, weight
    return best


class FencingError(ServiceError):
    def __init__(self, worker_id: str):
        super().__init__(409, "fencing_unconfirmed", f"{worker_id} could not be proven stopped")


class PoolManager:
    def __init__(self, settings: Settings, store: Store, docker: DockerClient, firewall: Firewall,
                 refresh_firewall: Callable[[list[dict]], bool] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.s = settings
        self.store = store
        self.docker = docker
        self.firewall = firewall
        self.refresh_firewall = refresh_firewall
        self.sleep = sleep

    # ----- config ------------------------------------------------------------------------
    def config(self) -> dict:
        cfg = self.store.kv_get("pool_config") or {}
        return {"size": cfg.get("size", self.s.pool_size),
                "image": cfg.get("image", self.s.pool_image),
                "recycle_after_runs": cfg.get("recycle_after_runs", self.s.pool_recycle_after_runs)}

    def set_config(self, **kw) -> dict:
        cfg = {**self.config(), **{k: v for k, v in kw.items() if v is not None}}
        if not 0 <= int(cfg["size"]) <= MAX_WORKERS:
            raise ServiceError(400, "pool_size_out_of_range", f"0..{MAX_WORKERS}")
        if cfg["image"] and not naming.image_digest(cfg["image"]):
            raise ServiceError(400, "digest_required", "pool image must be pinned by digest")
        self.store.kv_set("pool_config", cfg)
        return cfg

    # ----- networks / containers -----------------------------------------------------------------
    def _ensure_nets(self) -> None:
        for b in (templates.pool_network(), templates.ssh_hub_network()):
            if self.docker.inspect_network(b["Name"]) is None:
                try:
                    self.docker.create_network(b)
                except Conflict:
                    pass

    def _create_worker(self, w: dict, image: str, generation: int) -> None:
        name = naming.worker_name(w["worker_id"])
        body = templates.worker_spec(self.s, w["worker_id"], image, generation)
        try:
            self.docker.create_container(name, body)
        except Conflict:
            pass
        self.docker.connect_network(naming.SSH_HUB_NET, name, naming.hub_worker_ip(w["slot"]),
                                    [name])
        self.docker.start(name)

    def _wait_ready(self, worker_id: str, timeout_s: int) -> bool:
        name = naming.worker_name(worker_id)
        t0 = time.monotonic()
        while True:
            info = self.docker.inspect_container(name)
            st = (info or {}).get("State") or {}
            if st.get("Running") and (st.get("Health") or {}).get("Status") in (None, "healthy"):
                return True
            if st.get("Status") in ("exited", "dead") or time.monotonic() - t0 >= timeout_s:
                return False
            self.sleep(1)

    def status(self) -> dict:
        workers = []
        for w in self.store.worker_list():
            info = self.docker.inspect_container(naming.worker_name(w["worker_id"]))
            st = (info or {}).get("State") or {}
            workers.append({**{k: (v.isoformat() if isinstance(v, datetime) else v)
                               for k, v in w.items()},
                            "container": st.get("Status", "absent"),
                            "health": (st.get("Health") or {}).get("Status", "none")})
        return {"config": self.config(), "workers": workers, "epoch": self._epoch()}

    def _epoch(self) -> int:
        return (self.store.kv_get("pool_epoch") or {}).get("n", 0)

    def _bump_epoch(self) -> int:
        n = self._epoch() + 1
        self.store.kv_set("pool_epoch", {"n": n})
        return n

    # ----- ensure N ----------------------------------------------------------------------------
    def ensure(self, size: int | None = None, image: str | None = None,
               wait_s: int = 90) -> dict:
        cfg = self.set_config(size=size, image=image)
        if cfg["size"] and not cfg["image"]:
            raise ServiceError(400, "pool_image_missing")
        with self.store.lock("pool"):
            self._ensure_nets()
            want = [f"w{i}" for i in range(1, int(cfg["size"]) + 1)]
            for i, wid in enumerate(want, start=1):
                w = self.store.worker_get(wid) or self.store.worker_upsert(wid, slot=i)
                if w["status"] in ("fenced", "failed", "pending") or self.docker.inspect_container(
                        naming.worker_name(wid)) is None:
                    self._start_fresh(w, cfg["image"], wait_s)
                else:
                    info = self.docker.inspect_container(naming.worker_name(wid))
                    st = (info or {}).get("State") or {}
                    if not st.get("Running"):
                        self.docker.start(naming.worker_name(wid))
                    self.store.worker_upsert(wid, status="ready")
            # scale down: fence then remove extra workers
            for w in self.store.worker_list():
                if w["worker_id"] not in want:
                    self._fence_locked(w["worker_id"])
                    self.docker.remove_container(naming.worker_name(w["worker_id"]))
                    self.store.worker_delete(w["worker_id"])
            self._bump_epoch()
            self._fw()
        return self.status()

    def _fw(self) -> None:
        if self.refresh_firewall:
            self.refresh_firewall(self.store.worker_list())

    def _start_fresh(self, w: dict, image: str, wait_s: int) -> None:
        wid = w["worker_id"]
        name = naming.worker_name(wid)
        if self.docker.inspect_container(name) is not None:
            if not self._stop_and_confirm(wid):
                raise FencingError(wid)
            self.docker.remove_container(name)
        gen = w["generation"] + (1 if w["status"] != "pending" else 0)
        self._create_worker(w, image, gen)
        ok = self._wait_ready(wid, wait_s)
        self.store.worker_upsert(wid, status="ready" if ok else "failed", image_digest=
                                 naming.image_digest(image), generation=gen, runs_served=0,
                                 inflight=0, recycle_due=False,
                                 last_error="" if ok else "not healthy in time")

    # ----- assignment ----------------------------------------------------------------------------
    def assign(self, tenant: str) -> dict:
        """Which worker owns this tenant right now. worker=None means: unavailable, retry."""
        ws = self.store.worker_list()
        cand = [w["worker_id"] for w in ws if w["status"] in CANDIDATE_STATES]
        owner = hrw_pick(tenant, cand)
        if owner is None:
            return {"tenant": tenant, "worker": None, "reason": "no_worker", "epoch": self._epoch()}
        st = next(w["status"] for w in ws if w["worker_id"] == owner)
        if st != "ready":
            # owner is being fenced/recycled: do not hand the tenant to another worker until the
            # owner is confirmed stopped (then it leaves the candidate set).
            return {"tenant": tenant, "worker": None, "reason": f"owner_{st}",
                    "epoch": self._epoch()}
        return {"tenant": tenant, "worker": owner, "reason": "ok", "epoch": self._epoch(),
                "container": naming.worker_name(owner)}

    # ----- fencing / recycle -------------------------------------------------------------------
    def _stop_and_confirm(self, worker_id: str) -> bool:
        name = naming.worker_name(worker_id)
        info = self.docker.inspect_container(name)
        if info is None:
            return True
        if (info.get("State") or {}).get("Running") or (info.get("State") or {}).get("Paused"):
            try:
                self.docker.stop(name, 10)
            except Exception:
                pass
            info = self.docker.inspect_container(name)
            if info and (info.get("State") or {}).get("Running"):
                try:
                    self.docker.kill(name)
                except Exception:
                    pass
        info = self.docker.inspect_container(name)
        return info is None or not (info.get("State") or {}).get("Running")

    def _fence_locked(self, worker_id: str) -> list[str]:
        w = self.store.worker_get(worker_id)
        if w is None:
            raise ServiceError(404, "worker_not_found", worker_id)
        before = [x["worker_id"] for x in self.store.worker_list()
                  if x["status"] in CANDIDATE_STATES]
        self.store.worker_upsert(worker_id, status="fencing")
        if not self._stop_and_confirm(worker_id):
            self.store.worker_upsert(worker_id, last_error="fence unconfirmed")
            raise FencingError(worker_id)
        self.store.worker_upsert(worker_id, status="fenced", last_error="")
        self._bump_epoch()
        return before

    def fence(self, worker_id: str, actor: str = "api") -> dict:
        with self.store.lock("pool"):
            self._fence_locked(worker_id)
        return {"worker": worker_id, "status": "fenced", "epoch": self._epoch()}

    def recycle(self, worker_id: str, reason: str = "on_demand", wait_s: int = 90) -> dict:
        with self.store.lock("pool"):
            w = self.store.worker_get(worker_id)
            if w is None:
                raise ServiceError(404, "worker_not_found", worker_id)
            cfg = self.config()
            self.store.worker_upsert(worker_id, status="recycling")
            self._fence_locked(worker_id)
            self.docker.remove_container(naming.worker_name(worker_id))
            w = self.store.worker_get(worker_id)
            self._start_fresh(w, cfg["image"] or self._current_image(w), wait_s)
            self._bump_epoch()
        return {"worker": worker_id, "reason": reason, **{k: v for k, v in
                self.store.worker_get(worker_id).items() if k in ("status", "generation")}}

    def _current_image(self, w: dict) -> str:
        info = self.docker.inspect_container(naming.worker_name(w["worker_id"]))
        return (info or {}).get("Config", {}).get("Image", "")

    def report_runs(self, worker_id: str, finished: int = 0, inflight: int | None = None) -> dict:
        with self.store.lock("pool"):
            w = self.store.worker_get(worker_id)
            if w is None:
                raise ServiceError(404, "worker_not_found", worker_id)
            served = w["runs_served"] + max(finished, 0)
            limit = int(self.config()["recycle_after_runs"] or 0)
            due = bool(limit and served >= limit)
            w = self.store.worker_upsert(worker_id, runs_served=served,
                                         inflight=w["inflight"] if inflight is None else inflight,
                                         recycle_due=due or w["recycle_due"])
        return {"worker": worker_id, "runs_served": w["runs_served"],
                "recycle_due": w["recycle_due"], "inflight": w["inflight"]}

    def recycle_due(self) -> list[str]:
        """Called by the reconciler: recycle workers past the run limit that have nothing in flight."""
        done = []
        for w in self.store.worker_list():
            if w["recycle_due"] and w["inflight"] == 0 and w["status"] == "ready":
                self.recycle(w["worker_id"], reason="recycle_after_runs")
                done.append(w["worker_id"])
        return done

    def heal(self) -> list[str]:
        """Restart/replace workers whose container vanished or died."""
        fixed = []
        cfg = self.config()
        for w in self.store.worker_list():
            if w["status"] not in ("ready", "failed"):
                continue
            info = self.docker.inspect_container(naming.worker_name(w["worker_id"]))
            st = (info or {}).get("State") or {}
            if w["status"] == "failed":
                with self.store.lock("pool"):
                    self._start_fresh(self.store.worker_get(w["worker_id"]), cfg["image"], 90)
                self._bump_epoch()
                fixed.append(w["worker_id"])
            elif info is None:
                with self.store.lock("pool"):
                    self._start_fresh(self.store.worker_get(w["worker_id"]), cfg["image"], 90)
                self._bump_epoch()
                fixed.append(w["worker_id"])
            elif not st.get("Running"):
                self.recycle(w["worker_id"], reason="died")
                fixed.append(w["worker_id"])
        return fixed

    # ----- upgrade by waves --------------------------------------------------------------------------
    def upgrade(self, image: str, wave_size: int = 2, wait_s: int = 90,
                smoke: Callable[[str], bool] | None = None) -> dict:
        """Canary first (one worker), then waves of `wave_size`. Any failure rolls the failed worker
        back to the previous image and aborts the remaining waves."""
        if not naming.image_digest(image):
            raise ServiceError(400, "digest_required")
        prev_image = self.config()["image"]
        if not prev_image:
            raise ServiceError(409, "pool_not_configured")
        ids = [w["worker_id"] for w in self.store.worker_list()]
        if not ids:
            raise ServiceError(409, "pool_empty")
        waves = [ids[:1]] + [ids[i:i + wave_size] for i in range(1, len(ids), wave_size)]
        report: dict = {"from": prev_image, "to": image, "waves": [], "result": "upgraded"}
        done: list[str] = []
        for wi, wave in enumerate(waves):
            wres = {"wave": wi, "canary": wi == 0, "workers": {}}
            failed = None
            for wid in wave:
                ok = self._upgrade_one(wid, image, wait_s, smoke)
                wres["workers"][wid] = "ok" if ok else "failed"
                if not ok:
                    failed = wid
                    break
                done.append(wid)
            report["waves"].append(wres)
            if failed:
                self._upgrade_one(failed, prev_image, wait_s, None)
                for wid in done:  # roll back the ones already moved so the pool is uniform
                    self._upgrade_one(wid, prev_image, wait_s, None)
                report["result"] = "rolled_back"
                report["failed_worker"] = failed
                self.store.kv_set("pool_last_upgrade", report)
                return report
        self.set_config(image=image)
        self.store.kv_set("pool_last_upgrade", report)
        return report

    def _upgrade_one(self, wid: str, image: str, wait_s: int, smoke) -> bool:
        with self.store.lock("pool"):
            w = self.store.worker_get(wid)
            self.store.worker_upsert(wid, status="recycling")
            self._fence_locked(wid)
            self.docker.remove_container(naming.worker_name(wid))
            self._start_fresh(self.store.worker_get(wid) or w, image, wait_s)
            self._bump_epoch()
        ok = self.store.worker_get(wid)["status"] == "ready"
        if ok and smoke is not None:
            ok = bool(smoke(wid))
            if not ok:
                self.store.worker_upsert(wid, status="failed", last_error="smoke failed")
        return ok


def utcnow() -> datetime:
    return datetime.now(UTC)
