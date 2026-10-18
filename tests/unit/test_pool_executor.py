"""Worker pool (ensure, assignment, fencing, recycle, waves) and the ephemeral executor."""
from __future__ import annotations

import base64

import pytest

from rm import naming
from rm.executor import ExecutorRunner
from rm.pool import FencingError, hrw_pick
from rm.service import ServiceError
from tests.conftest import POOL_IMAGE, digest

NEW_IMAGE = digest("rt-pool-v2")


@pytest.fixture
def pool(env):
    env.settings.pool_size = 3
    p = env.pool()
    p.ensure(3, POOL_IMAGE, wait_s=1)
    return p


def test_ensure_creates_n_healthy_workers_on_pool_and_hub(env, pool):
    st = pool.status()
    assert [w["status"] for w in st["workers"]] == ["ready"] * 3
    c = env.fake.containers["rt-pool-w1"]
    assert set(c["NetworkSettings"]["Networks"]) == {"rt-pool", "rt-ssh"}
    assert c["NetworkSettings"]["Networks"]["rt-ssh"]["IPAddress"] == naming.hub_worker_ip(1)
    assert c["HostConfig"]["CapDrop"] == ["ALL"] and c["HostConfig"]["ReadonlyRootfs"] is True
    assert env.fw.applied[-1].worker_ips == [naming.hub_worker_ip(i) for i in (1, 2, 3)]


def test_ensure_is_idempotent_and_scales(env, pool):
    n = len(env.fake.verbs("create_container"))
    pool.ensure(3, POOL_IMAGE, wait_s=1)
    assert len(env.fake.verbs("create_container")) == n
    pool.ensure(2, POOL_IMAGE, wait_s=1)
    assert "rt-pool-w3" not in env.fake.containers and len(pool.status()["workers"]) == 2
    with pytest.raises(ServiceError):
        pool.ensure(14, POOL_IMAGE, wait_s=1)
    with pytest.raises(ServiceError) as e:
        pool.ensure(3, "rt-pool:latest", wait_s=1)
    assert e.value.code == "digest_required"


def test_assignment_is_stable_and_spreads(env, pool):
    tenants = [f"tenant{i}" for i in range(60)]
    first = {t: pool.assign(t)["worker"] for t in tenants}
    assert first == {t: pool.assign(t)["worker"] for t in tenants}
    assert set(first.values()) == {"w1", "w2", "w3"}
    counts = [list(first.values()).count(w) for w in ("w1", "w2", "w3")]
    assert min(counts) >= 8


def test_hrw_moves_only_the_removed_workers_tenants():
    ids = ["w1", "w2", "w3"]
    before = {f"t{i}": hrw_pick(f"t{i}", ids) for i in range(200)}
    after = {t: hrw_pick(t, ["w1", "w2"]) for t in before}
    moved = [t for t in before if before[t] != after[t]]
    assert moved and all(before[t] == "w3" for t in moved)


def test_owner_being_fenced_means_unavailable_never_double_assigned(env, pool):
    owner = pool.assign("tenant7")["worker"]
    env.fake.unstoppable.add(f"rt-pool-{owner}")
    with pytest.raises(FencingError):
        pool.fence(owner)
    r = pool.assign("tenant7")
    assert r["worker"] is None and r["reason"] == "owner_fencing"
    env.fake.unstoppable.clear()
    pool.fence(owner)                                         # now provably stopped
    r = pool.assign("tenant7")
    assert r["worker"] not in (None, owner)
    assert env.fake.containers[f"rt-pool-{owner}"]["State"]["Running"] is False


def test_recycle_after_runs_waits_for_idle(env, pool):
    pool.set_config(recycle_after_runs=5)
    pool.report_runs("w1", finished=5, inflight=1)
    assert pool.recycle_due() == []                           # a run is in flight
    gen = pool.store.worker_get("w1")["generation"]
    pool.report_runs("w1", finished=0, inflight=0)
    assert pool.recycle_due() == ["w1"]
    w = pool.store.worker_get("w1")
    assert w["generation"] == gen + 1 and w["runs_served"] == 0 and w["status"] == "ready"


def test_heal_replaces_dead_and_missing_workers(env, pool):
    env.fake.crash("rt-pool-w1")
    del env.fake.containers["rt-pool-w2"]
    assert sorted(pool.heal()) == ["w1", "w2"]
    assert all(env.fake.containers[f"rt-pool-w{i}"]["State"]["Running"] for i in (1, 2, 3))


def test_upgrade_by_waves_canary_first(env, pool):
    rep = pool.upgrade(NEW_IMAGE, wave_size=2, wait_s=1)
    assert rep["result"] == "upgraded"
    assert [w["canary"] for w in rep["waves"]] == [True, False]
    assert [len(w["workers"]) for w in rep["waves"]] == [1, 2]
    assert pool.config()["image"] == NEW_IMAGE
    for i in (1, 2, 3):
        assert env.fake.containers[f"rt-pool-w{i}"]["Config"]["Image"] == NEW_IMAGE


def test_upgrade_rolls_back_everything_when_a_wave_fails(env, pool):
    seen = []

    def smoke(wid):
        seen.append(wid)
        return wid != "w2"                                    # canary w1 ok, w2 fails
    rep = pool.upgrade(NEW_IMAGE, wave_size=2, wait_s=1, smoke=smoke)
    assert rep["result"] == "rolled_back" and rep["failed_worker"] == "w2"
    assert seen == ["w1", "w2"]                               # w3 never touched
    assert pool.config()["image"] == POOL_IMAGE
    for i in (1, 2, 3):
        assert env.fake.containers[f"rt-pool-w{i}"]["Config"]["Image"] == POOL_IMAGE


# ----- executor ---------------------------------------------------------------------------------
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def test_executor_body_has_no_network_no_caps_and_passes_policy(env):
    r = ExecutorRunner(env.settings, env.docker)
    body = r.build_body("0123456789abcdef", 30, 256, 1.0)
    hc = body["HostConfig"]
    assert hc["NetworkMode"] == "none" and hc["CapDrop"] == ["ALL"] and "CapAdd" not in hc
    assert hc["ReadonlyRootfs"] and hc["PidsLimit"] == 64 and hc["MemorySwap"] == hc["Memory"]
    assert hc["Binds"][0].endswith(":/in:ro")
    assert "NetworkingConfig" not in body
    env.docker.policy.validate_container("rt-exec-0123456789ab", body)


@pytest.mark.parametrize("kw,code", [
    ({"script": ""}, "script_required"),
    ({"script": "x" * (300 * 1024)}, "script_too_large"),
    ({"script": "1", "inputs": {"../etc/passwd": b64(b"x")}}, "bad_input_name"),
    ({"script": "1", "inputs": {"script.py": b64(b"x")}}, "bad_input_name"),
    ({"script": "1", "inputs": {"a.csv": "***not-base64***"}}, "bad_input_base64"),
    ({"script": "1", "timeout_s": 0}, "bad_timeout"),
    ({"script": "1", "timeout_s": 301}, "bad_timeout"),
    ({"script": "1", "mem_mb": 8192}, "bad_memory"),
    ({"script": "1", "cpus": 8}, "bad_cpus"),
])
def test_executor_validates_requests(env, kw, code):
    with pytest.raises(ServiceError) as e:
        ExecutorRunner(env.settings, env.docker).run(**kw)
    assert e.value.code == code


def test_executor_requires_configuration(env):
    env.settings.executor_image = ""
    with pytest.raises(ServiceError) as e:
        ExecutorRunner(env.settings, env.docker).run("print(1)")
    assert e.value.status == 503


def test_executor_cleans_up_container_and_workdir(env, tmp_path):
    env.settings.executor_root = "/srv/executor"
    env.settings.executor_local_root = str(tmp_path / "exec")
    r = ExecutorRunner(env.settings, env.docker, sleep=lambda s: None)
    orig_create = env.fake.create_container

    def create(name, body):
        cid = orig_create(name, body)
        run_dir = next((tmp_path / "exec").iterdir())
        assert (run_dir / "in" / "script.py").read_text() == "print(1)"
        (run_dir / "out" / "_result.json").write_text('{"exit_code": 0, "timed_out": false}')
        (run_dir / "out" / "_stdout.txt").write_bytes(b"1\n")
        (run_dir / "out" / "chart.png").write_bytes(b"\x89PNG")
        return cid
    env.fake.create_container = create
    env.fake.start = lambda name: env.fake.containers[name]["State"].update(Running=False,
                                                                           Status="exited")
    res = r.run("print(1)", {"d.csv": b64(b"a,b\n1,2")})
    assert res["exit_code"] == 0 and res["stdout"] == "1\n"
    assert base64.b64decode(res["outputs"]["chart.png"]) == b"\x89PNG"
    assert "_stdout.txt" not in res["outputs"]
    assert env.fake.containers == {}                          # container removed
    assert list((tmp_path / "exec").iterdir()) == []          # workdir removed
