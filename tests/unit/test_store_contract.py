"""MemoryStore and PostgresStore must behave the same. Postgres runs when RM_TEST_DATABASE_URL is
set, or (locally) in a throwaway postgres container if Docker is available."""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from datetime import UTC, datetime

import pytest

from rm.store import MemoryStore, PostgresStore


def _start_pg_container() -> tuple[str, str] | None:
    if not shutil.which("docker"):
        return None
    name = "rm-test-pg-" + uuid.uuid4().hex[:6]
    r = subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD=pw",
                        "-p", "127.0.0.1::5432", "postgres:16-alpine"], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    port = subprocess.run(["docker", "port", name, "5432/tcp"], capture_output=True,
                          text=True).stdout.strip().rsplit(":", 1)[-1]
    dsn = f"postgresql://postgres:pw@127.0.0.1:{port}/postgres"
    import psycopg
    for _ in range(60):
        try:
            psycopg.connect(dsn, connect_timeout=2).close()
            return dsn, name
        except Exception:
            time.sleep(1)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    return None


@pytest.fixture(scope="session")
def pg_dsn():
    dsn = os.environ.get("RM_TEST_DATABASE_URL")
    if dsn:
        yield dsn
        return
    started = _start_pg_container()
    if not started:
        pytest.skip("no Postgres (set RM_TEST_DATABASE_URL or run Docker)")
    yield started[0]
    subprocess.run(["docker", "rm", "-f", started[1]], capture_output=True)


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
def store(request):
    if request.param == "memory":
        s = MemoryStore()
        s.migrate()
        return s
    dsn = request.getfixturevalue("pg_dsn")
    s = PostgresStore(dsn)
    s.migrate()
    with s._conn() as c:
        c.execute("TRUNCATE tenant_runtime, tenant_runtime_event, rm_idempotency, pool_worker, "
                  "rm_kv, tenant_usage_hourly, tenant_backup, tenant_domain")
    return s


def test_tenant_crud_and_index_reuse(store):
    a, created = store.create_tenant("acme1", plan="pro", quota_gb=20)
    assert created and a["net_index"] == 0 and a["plan"] == "pro" and a["quota_gb"] == 20
    b, _ = store.create_tenant("beta1")
    assert b["net_index"] == 1
    again, created = store.create_tenant("acme1", plan="small")
    assert not created and again["plan"] == "pro"                 # create is idempotent
    store.update_tenant("acme1", exposures=[{"app": "web", "port": 8000}], suspended=True)
    got = store.get_tenant("acme1")
    assert got["exposures"] == [{"app": "web", "port": 8000}] and got["suspended"] is True
    store.delete_tenant("acme1")
    c, _ = store.create_tenant("gamma1")
    assert c["net_index"] == 0                                    # lowest free index is reused
    assert [t["tenant_id"] for t in store.list_tenants()] == ["beta1", "gamma1"]
    with pytest.raises(KeyError):
        store.update_tenant("beta1", bogus=1)


def test_event_chain(store):
    for i in range(5):
        store.add_event("acme1", "ops", f"act{i}", {"i": i})
    ev = store.list_events("acme1")
    assert [e["action"] for e in ev][:2] == ["act4", "act3"]
    assert store.verify_chain()
    assert ev[0]["prev_hash"] == ev[1]["hash"]
    assert store.list_events("other") == []


def test_idempotency_first_write_wins(store):
    assert store.idem_get("acme1", "k") is None
    store.idem_put("acme1", "k", "h1", {"a": 1}, 200)
    store.idem_put("acme1", "k", "h2", {"a": 2}, 201)
    got = store.idem_get("acme1", "k")
    assert got["request_hash"] == "h1" and got["response"] == {"a": 1}
    assert store.idem_get("beta1", "k") is None


def test_workers_kv_usage_backup_domain(store):
    w = store.worker_upsert("w1", slot=1, status="ready", runs_served=3)
    assert w["slot"] == 1 and w["status"] == "ready"
    store.worker_upsert("w1", inflight=2)
    assert store.worker_get("w1")["inflight"] == 2 and store.worker_get("w1")["runs_served"] == 3
    with pytest.raises(KeyError):
        store.worker_upsert("w2", status="ready")                 # new worker needs a slot
    store.worker_delete("w1")
    assert store.worker_list() == []

    assert store.kv_get("x") is None
    store.kv_set("x", {"n": 1})
    store.kv_set("x", {"n": 2})
    assert store.kv_get("x") == {"n": 2}

    h = datetime(2026, 10, 18, 10, tzinfo=UTC)
    store.usage_add("acme1", h, cpu_seconds=2, disk_gb=3)
    store.usage_add("acme1", h, cpu_seconds=3, disk_gb=1)
    row = store.usage_list("acme1")[0]
    assert row["cpu_seconds"] == 5 and row["disk_gb"] == 3        # flow adds, level keeps the max
    with pytest.raises(KeyError):
        store.usage_add("acme1", h, bogus=1)

    store.backup_add({"backup_id": "b1", "tenant_id": "acme1", "kind": "manual",
                      "location": "/x", "sha256": "ab", "manifest": {"n": 1}})
    assert store.backup_get("b1")["manifest"] == {"n": 1}
    assert [b["backup_id"] for b in store.backup_list("acme1")] == ["b1"]
    assert store.backup_list("beta1") == []

    store.domain_upsert("a.example.com", tenant_id="acme1", app="web", token="t")
    store.domain_upsert("a.example.com", active=True, verified=True)
    d = store.domain_get("a.example.com")
    assert d["active"] and d["tenant_id"] == "acme1"
    assert [x["host"] for x in store.domain_list("acme1")] == ["a.example.com"]
    assert store.domain_list("beta1") == []
    store.domain_delete("a.example.com")
    assert store.domain_get("a.example.com") is None


def test_lock_is_mutually_exclusive_per_key(store):
    import threading
    order = []

    def worker(tag):
        with store.lock("tenant:acme1"):
            order.append(f"{tag}-in")
            time.sleep(0.15)
            order.append(f"{tag}-out")
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    for i in range(0, 6, 2):                                       # never interleaved
        assert order[i].split("-")[0] == order[i + 1].split("-")[0]


def test_locks_of_different_keys_run_in_parallel(store):
    import threading
    t0 = time.monotonic()

    def worker(k):
        with store.lock(k):
            time.sleep(0.3)
    ts = [threading.Thread(target=worker, args=(f"tenant:t{i}",)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert time.monotonic() - t0 < 0.9
