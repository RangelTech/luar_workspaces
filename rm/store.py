"""State store: Postgres in production (desired state), in-memory for unit tests.

Both implementations satisfy the same contract (tests/unit/test_store_contract.py).
"""
from __future__ import annotations

import hashlib
import json
import threading
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TENANT_FIELDS = {
    "plan", "desired_state", "runtime_enabled", "workspace_enabled", "runtime_desired",
    "workspace_desired", "runtime_image_digest",
    "workspace_image_digest", "limits_json", "quota_gb", "exposures", "generation", "suspended",
    "suspend_reason", "suspended_by", "status", "last_activity_at", "last_error",
    "authorized_key", "purge_after",
}
WORKER_FIELDS = {"status", "image_digest", "generation", "runs_served", "inflight", "recycle_due",
                 "last_error"}
USAGE_FIELDS = ("cpu_seconds", "mem_gb_hours", "ws_uptime_h", "runtime_uptime_h", "disk_gb",
                "egress_gb", "runs")
DOMAIN_FIELDS = {"tenant_id", "app", "token", "verified", "active", "last_check_at",
                 "verified_at"}


def now() -> datetime:
    return datetime.now(UTC)


def chain_hash(prev: str, tenant: str, ts: str, actor: str, action: str, detail: dict) -> str:
    payload = json.dumps([prev, tenant, ts, actor, action, detail], sort_keys=True,
                         separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def tenant_defaults(tenant_id: str, net_index: int, **kw: Any) -> dict:
    row = {
        "tenant_id": tenant_id, "plan": "standard", "desired_state": "running",
        "runtime_enabled": False, "workspace_enabled": True, "runtime_desired": "running",
        "workspace_desired": "running", "runtime_image_digest": "",
        "workspace_image_digest": "", "limits_json": {}, "quota_gb": 10, "exposures": [],
        "generation": 1, "suspended": False, "suspend_reason": "", "suspended_by": "",
        "status": "provisioning", "last_activity_at": None, "last_error": "",
        "net_index": net_index, "authorized_key": "", "purge_after": None,
        "created_at": now(), "updated_at": now(),
    }
    row.update({k: v for k, v in kw.items() if k in TENANT_FIELDS})
    return row


class MemoryStore:
    def __init__(self) -> None:
        self._mu = threading.RLock()
        self.tenants: dict[str, dict] = {}
        self._next_index = 0
        self.events: list[dict] = []
        self.idem: dict[tuple[str, str], dict] = {}
        self.workers: dict[str, dict] = {}
        self.kv: dict[str, Any] = {}
        self.usage: dict[tuple[str, datetime], dict] = {}
        self.backups: dict[str, dict] = {}
        self.domains: dict[str, dict] = {}
        self._locks: dict[str, threading.RLock] = defaultdict(threading.RLock)

    def migrate(self) -> None: ...
    def ping(self) -> bool:
        return True

    @contextmanager
    def lock(self, key: str) -> Iterator[None]:
        lk = self._locks[key]
        with lk:
            yield

    # tenants
    def create_tenant(self, tenant_id: str, **kw: Any) -> tuple[dict, bool]:
        with self._mu:
            if tenant_id in self.tenants:
                return dict(self.tenants[tenant_id]), False
            used = {t["net_index"] for t in self.tenants.values()}
            idx = 0
            while idx in used:
                idx += 1
            self.tenants[tenant_id] = tenant_defaults(tenant_id, idx, **kw)
            return dict(self.tenants[tenant_id]), True

    def get_tenant(self, tenant_id: str) -> dict | None:
        with self._mu:
            t = self.tenants.get(tenant_id)
            return dict(t) if t else None

    def list_tenants(self) -> list[dict]:
        with self._mu:
            return [dict(t) for t in sorted(self.tenants.values(), key=lambda x: x["tenant_id"])]

    def update_tenant(self, tenant_id: str, **fields: Any) -> dict:
        bad = set(fields) - TENANT_FIELDS
        if bad:
            raise KeyError(f"unknown tenant fields: {sorted(bad)}")
        with self._mu:
            t = self.tenants[tenant_id]
            t.update(fields)
            t["updated_at"] = now()
            return dict(t)

    def delete_tenant(self, tenant_id: str) -> None:
        with self._mu:
            self.tenants.pop(tenant_id, None)

    # events (hash chained)
    def add_event(self, tenant_id: str, actor: str, action: str, detail: dict | None = None) -> dict:
        with self._mu:
            prev = self.events[-1]["hash"] if self.events else "0" * 64
            ts = now()
            detail = json.loads(json.dumps(detail or {}, default=str))
            h = chain_hash(prev, tenant_id, ts.isoformat(), actor, action, detail)
            ev = {"id": len(self.events) + 1, "tenant_id": tenant_id, "ts": ts, "actor": actor,
                  "action": action, "detail": detail, "prev_hash": prev, "hash": h}
            self.events.append(ev)
            return dict(ev)

    def list_events(self, tenant_id: str | None = None, limit: int = 100) -> list[dict]:
        with self._mu:
            ev = [e for e in self.events if tenant_id in (None, e["tenant_id"])]
            return [dict(e) for e in reversed(ev[-limit:])]

    def verify_chain(self) -> bool:
        with self._mu:
            prev = "0" * 64
            for e in self.events:
                h = chain_hash(prev, e["tenant_id"], e["ts"].isoformat(), e["actor"], e["action"],
                               e["detail"])
                if e["prev_hash"] != prev or e["hash"] != h:
                    return False
                prev = e["hash"]
            return True

    # idempotency
    def idem_get(self, tenant_id: str, key: str) -> dict | None:
        with self._mu:
            r = self.idem.get((tenant_id, key))
            return dict(r) if r else None

    def idem_put(self, tenant_id: str, key: str, request_hash: str, response: dict,
                 status_code: int = 200) -> None:
        with self._mu:
            self.idem.setdefault((tenant_id, key), {
                "request_hash": request_hash, "response": response, "status_code": status_code})

    # pool
    def worker_get(self, worker_id: str) -> dict | None:
        with self._mu:
            w = self.workers.get(worker_id)
            return dict(w) if w else None

    def worker_list(self) -> list[dict]:
        with self._mu:
            return [dict(w) for w in sorted(self.workers.values(), key=lambda x: x["slot"])]

    def worker_upsert(self, worker_id: str, slot: int | None = None, **fields: Any) -> dict:
        bad = set(fields) - WORKER_FIELDS
        if bad:
            raise KeyError(f"unknown worker fields: {sorted(bad)}")
        with self._mu:
            w = self.workers.get(worker_id)
            if w is None:
                if slot is None:
                    raise KeyError("slot required for a new worker")
                w = {"worker_id": worker_id, "slot": slot, "status": "pending", "image_digest": "",
                     "generation": 1, "runs_served": 0, "inflight": 0, "recycle_due": False,
                     "last_error": ""}
                self.workers[worker_id] = w
            w.update(fields)
            w["updated_at"] = now()
            return dict(w)

    def worker_delete(self, worker_id: str) -> None:
        with self._mu:
            self.workers.pop(worker_id, None)

    def kv_get(self, key: str) -> Any:
        with self._mu:
            return json.loads(json.dumps(self.kv.get(key))) if key in self.kv else None

    def kv_set(self, key: str, value: Any) -> None:
        with self._mu:
            self.kv[key] = json.loads(json.dumps(value, default=str))

    # usage
    def usage_add(self, tenant_id: str, hour: datetime, **deltas: float) -> None:
        with self._mu:
            row = self.usage.setdefault((tenant_id, hour), {f: 0 for f in USAGE_FIELDS})
            for k, v in deltas.items():
                if k not in USAGE_FIELDS:
                    raise KeyError(k)
                if k == "disk_gb":
                    row[k] = max(row[k], v)  # level, not a flow
                else:
                    row[k] += v

    def usage_list(self, tenant_id: str, limit: int = 48) -> list[dict]:
        with self._mu:
            rows = [{"tenant_id": t, "hour": h, **v} for (t, h), v in self.usage.items()
                    if t == tenant_id]
            return sorted(rows, key=lambda r: r["hour"], reverse=True)[:limit]

    # backups
    def backup_add(self, rec: dict) -> None:
        with self._mu:
            self.backups[rec["backup_id"]] = {**rec, "created_at": now()}

    def backup_get(self, backup_id: str) -> dict | None:
        with self._mu:
            b = self.backups.get(backup_id)
            return dict(b) if b else None

    def backup_list(self, tenant_id: str) -> list[dict]:
        with self._mu:
            rows = [dict(b) for b in self.backups.values() if b["tenant_id"] == tenant_id]
            return sorted(rows, key=lambda r: r["created_at"], reverse=True)

    # domains
    def domain_upsert(self, host: str, **fields: Any) -> dict:
        bad = set(fields) - DOMAIN_FIELDS
        if bad:
            raise KeyError(f"unknown domain fields: {sorted(bad)}")
        with self._mu:
            d = self.domains.setdefault(host, {"host": host, "verified": False, "active": False,
                                               "last_check_at": None, "verified_at": None})
            d.update(fields)
            return dict(d)

    def domain_get(self, host: str) -> dict | None:
        with self._mu:
            d = self.domains.get(host)
            return dict(d) if d else None

    def domain_list(self, tenant_id: str | None = None) -> list[dict]:
        with self._mu:
            return [dict(d) for d in self.domains.values()
                    if tenant_id in (None, d["tenant_id"])]

    def domain_delete(self, host: str) -> None:
        with self._mu:
            self.domains.pop(host, None)


class PostgresStore:
    """Synchronous psycopg3 store. One short connection per call; locks hold their own."""

    def __init__(self, dsn: str):
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.types.json import Jsonb
        self._psycopg = psycopg
        self._row = dict_row
        self._jsonb = Jsonb
        self.dsn = dsn

    def _conn(self):
        return self._psycopg.connect(self.dsn, autocommit=True, row_factory=self._row)

    def _j(self, v: Any):
        return self._jsonb(v)

    def migrate(self) -> None:
        sql = (Path(__file__).resolve().parent.parent / "migrations" / "001_init.sql").read_text(
            encoding="utf-8")
        with self._conn() as c:
            c.execute("SELECT pg_advisory_lock(7770001)")
            try:
                c.execute(sql)
            finally:
                c.execute("SELECT pg_advisory_unlock(7770001)")

    def ping(self) -> bool:
        try:
            with self._conn() as c:
                c.execute("SELECT 1")
            return True
        except Exception:
            return False

    @contextmanager
    def lock(self, key: str) -> Iterator[None]:
        with self._conn() as c:
            c.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))", (key,))
            try:
                yield
            finally:
                c.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (key,))

    # tenants
    def create_tenant(self, tenant_id: str, **kw: Any) -> tuple[dict, bool]:
        with self._conn() as c:
            c.execute("SELECT pg_advisory_lock(7770002)")
            try:
                row = c.execute("SELECT * FROM tenant_runtime WHERE tenant_id=%s",
                                (tenant_id,)).fetchone()
                if row:
                    return row, False
                idx = c.execute("SELECT COALESCE(MIN(g), 0) AS i FROM generate_series(0, 999) g "
                                "WHERE g NOT IN (SELECT net_index FROM tenant_runtime)"
                                ).fetchone()["i"]
                d = tenant_defaults(tenant_id, idx, **kw)
                cols = [k for k in d if k not in ("created_at", "updated_at")]
                vals = [self._j(d[k]) if k in ("limits_json", "exposures") else d[k] for k in cols]
                c.execute(f"INSERT INTO tenant_runtime ({','.join(cols)}) "
                          f"VALUES ({','.join(['%s'] * len(cols))})", vals)
                return c.execute("SELECT * FROM tenant_runtime WHERE tenant_id=%s",
                                 (tenant_id,)).fetchone(), True
            finally:
                c.execute("SELECT pg_advisory_unlock(7770002)")

    def get_tenant(self, tenant_id: str) -> dict | None:
        with self._conn() as c:
            return c.execute("SELECT * FROM tenant_runtime WHERE tenant_id=%s",
                             (tenant_id,)).fetchone()

    def list_tenants(self) -> list[dict]:
        with self._conn() as c:
            return c.execute("SELECT * FROM tenant_runtime ORDER BY tenant_id").fetchall()

    def update_tenant(self, tenant_id: str, **fields: Any) -> dict:
        bad = set(fields) - TENANT_FIELDS
        if bad:
            raise KeyError(f"unknown tenant fields: {sorted(bad)}")
        sets = ", ".join(f"{k}=%s" for k in fields) + (", " if fields else "") + "updated_at=now()"
        vals = [self._j(v) if k in ("limits_json", "exposures") else v for k, v in fields.items()]
        with self._conn() as c:
            return c.execute(f"UPDATE tenant_runtime SET {sets} WHERE tenant_id=%s RETURNING *",
                             [*vals, tenant_id]).fetchone()

    def delete_tenant(self, tenant_id: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM tenant_runtime WHERE tenant_id=%s", (tenant_id,))

    # events
    def add_event(self, tenant_id: str, actor: str, action: str, detail: dict | None = None) -> dict:
        detail = json.loads(json.dumps(detail or {}, default=str))
        with self._conn() as c:
            c.execute("SELECT pg_advisory_lock(7770003)")
            try:
                last = c.execute("SELECT hash FROM tenant_runtime_event ORDER BY id DESC LIMIT 1"
                                 ).fetchone()
                prev = last["hash"] if last else "0" * 64
                ts = now()
                h = chain_hash(prev, tenant_id, ts.isoformat(), actor, action, detail)
                return c.execute(
                    "INSERT INTO tenant_runtime_event (tenant_id, ts, actor, action, detail, "
                    "prev_hash, hash) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                    (tenant_id, ts, actor, action, self._j(detail), prev, h)).fetchone()
            finally:
                c.execute("SELECT pg_advisory_unlock(7770003)")

    def list_events(self, tenant_id: str | None = None, limit: int = 100) -> list[dict]:
        with self._conn() as c:
            if tenant_id:
                return c.execute("SELECT * FROM tenant_runtime_event WHERE tenant_id=%s "
                                 "ORDER BY id DESC LIMIT %s", (tenant_id, limit)).fetchall()
            return c.execute("SELECT * FROM tenant_runtime_event ORDER BY id DESC LIMIT %s",
                             (limit,)).fetchall()

    def verify_chain(self) -> bool:
        with self._conn() as c:
            prev = "0" * 64
            for e in c.execute("SELECT * FROM tenant_runtime_event ORDER BY id").fetchall():
                h = chain_hash(prev, e["tenant_id"], e["ts"].isoformat(), e["actor"], e["action"],
                               e["detail"])
                if e["prev_hash"] != prev or e["hash"] != h:
                    return False
                prev = e["hash"]
            return True

    # idempotency
    def idem_get(self, tenant_id: str, key: str) -> dict | None:
        with self._conn() as c:
            return c.execute("SELECT request_hash, response, status_code FROM rm_idempotency "
                             "WHERE tenant_id=%s AND idem_key=%s", (tenant_id, key)).fetchone()

    def idem_put(self, tenant_id: str, key: str, request_hash: str, response: dict,
                 status_code: int = 200) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO rm_idempotency (tenant_id, idem_key, request_hash, response, "
                      "status_code) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                      (tenant_id, key, request_hash, self._j(response), status_code))

    # pool
    def worker_get(self, worker_id: str) -> dict | None:
        with self._conn() as c:
            return c.execute("SELECT * FROM pool_worker WHERE worker_id=%s",
                             (worker_id,)).fetchone()

    def worker_list(self) -> list[dict]:
        with self._conn() as c:
            return c.execute("SELECT * FROM pool_worker ORDER BY slot").fetchall()

    def worker_upsert(self, worker_id: str, slot: int | None = None, **fields: Any) -> dict:
        bad = set(fields) - WORKER_FIELDS
        if bad:
            raise KeyError(f"unknown worker fields: {sorted(bad)}")
        with self._conn() as c:
            if not c.execute("SELECT 1 FROM pool_worker WHERE worker_id=%s",
                             (worker_id,)).fetchone():
                if slot is None:
                    raise KeyError("slot required for a new worker")
                c.execute("INSERT INTO pool_worker (worker_id, slot) VALUES (%s,%s)",
                          (worker_id, slot))
            sets = ", ".join(f"{k}=%s" for k in fields) + (", " if fields else "")
            return c.execute(f"UPDATE pool_worker SET {sets}updated_at=now() WHERE worker_id=%s "
                             "RETURNING *", [*fields.values(), worker_id]).fetchone()

    def worker_delete(self, worker_id: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM pool_worker WHERE worker_id=%s", (worker_id,))

    def kv_get(self, key: str) -> Any:
        with self._conn() as c:
            r = c.execute("SELECT v FROM rm_kv WHERE k=%s", (key,)).fetchone()
            return r["v"] if r else None

    def kv_set(self, key: str, value: Any) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO rm_kv (k, v) VALUES (%s,%s) ON CONFLICT (k) DO UPDATE "
                      "SET v=EXCLUDED.v, updated_at=now()", (key, self._j(value)))

    # usage
    def usage_add(self, tenant_id: str, hour: datetime, **deltas: float) -> None:
        for k in deltas:
            if k not in USAGE_FIELDS:
                raise KeyError(k)
        cols = list(deltas)
        if not cols:
            return
        ins_cols = ", ".join(["tenant_id", "hour", *cols])
        ins_vals = ", ".join(["%s"] * (2 + len(cols)))
        upd = ", ".join(
            f"{k}=GREATEST(tenant_usage_hourly.{k}, EXCLUDED.{k})" if k == "disk_gb"
            else f"{k}=tenant_usage_hourly.{k}+EXCLUDED.{k}" for k in cols)
        with self._conn() as c:
            c.execute(f"INSERT INTO tenant_usage_hourly ({ins_cols}) VALUES ({ins_vals}) "
                      f"ON CONFLICT (tenant_id, hour) DO UPDATE SET {upd}",
                      [tenant_id, hour, *[deltas[k] for k in cols]])

    def usage_list(self, tenant_id: str, limit: int = 48) -> list[dict]:
        with self._conn() as c:
            return c.execute("SELECT * FROM tenant_usage_hourly WHERE tenant_id=%s "
                             "ORDER BY hour DESC LIMIT %s", (tenant_id, limit)).fetchall()

    # backups
    def backup_add(self, rec: dict) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO tenant_backup (backup_id, tenant_id, kind, location, sha256, "
                      "manifest) VALUES (%s,%s,%s,%s,%s,%s)",
                      (rec["backup_id"], rec["tenant_id"], rec["kind"], rec["location"],
                       rec.get("sha256", ""), self._j(rec.get("manifest", {}))))

    def backup_get(self, backup_id: str) -> dict | None:
        with self._conn() as c:
            return c.execute("SELECT * FROM tenant_backup WHERE backup_id=%s",
                             (backup_id,)).fetchone()

    def backup_list(self, tenant_id: str) -> list[dict]:
        with self._conn() as c:
            return c.execute("SELECT * FROM tenant_backup WHERE tenant_id=%s "
                             "ORDER BY created_at DESC", (tenant_id,)).fetchall()

    # domains
    def domain_upsert(self, host: str, **fields: Any) -> dict:
        bad = set(fields) - DOMAIN_FIELDS
        if bad:
            raise KeyError(f"unknown domain fields: {sorted(bad)}")
        with self._conn() as c:
            if not c.execute("SELECT 1 FROM tenant_domain WHERE host=%s", (host,)).fetchone():
                c.execute("INSERT INTO tenant_domain (host, tenant_id, app, token) "
                          "VALUES (%s,%s,%s,%s)", (host, fields.get("tenant_id", ""),
                                                   fields.get("app", ""), fields.get("token", "")))
            if fields:
                sets = ", ".join(f"{k}=%s" for k in fields)
                c.execute(f"UPDATE tenant_domain SET {sets} WHERE host=%s",
                          [*fields.values(), host])
            return c.execute("SELECT * FROM tenant_domain WHERE host=%s", (host,)).fetchone()

    def domain_get(self, host: str) -> dict | None:
        with self._conn() as c:
            return c.execute("SELECT * FROM tenant_domain WHERE host=%s", (host,)).fetchone()

    def domain_list(self, tenant_id: str | None = None) -> list[dict]:
        with self._conn() as c:
            if tenant_id:
                return c.execute("SELECT * FROM tenant_domain WHERE tenant_id=%s ORDER BY host",
                                 (tenant_id,)).fetchall()
            return c.execute("SELECT * FROM tenant_domain ORDER BY host").fetchall()

    def domain_delete(self, host: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM tenant_domain WHERE host=%s", (host,))
