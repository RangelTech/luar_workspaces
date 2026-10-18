"""Reconciliation: desired (store) vs observed (Docker labels); healing; upgrade; backup/restore."""
from __future__ import annotations

from datetime import timedelta

import pytest

from rm.service import ServiceError
from tests.conftest import digest


def test_reconcile_recreates_missing_container_without_touching_volumes(env, tenant):
    env.fake.volumes["rt-hermes-acme1-data"] = {"Name": "rt-hermes-acme1-data", "Labels": {
        "rt.managed": "true", "rt.tenant": "acme1"}}
    del env.fake.containers["rt-ws-acme1"]
    env.svc.reconcile_tenant(tenant)
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"]
    assert "rt-hermes-acme1-data" in env.fake.volumes
    assert not env.fake.verbs("remove_volume")


def test_reconcile_restarts_crashed_container(env, tenant):
    env.fake.crash("rt-ws-acme1", code=1)
    env.svc.reconcile_tenant(tenant)
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"]


def test_reconcile_heals_unhealthy_and_marks_degraded_after_three(env, tenant):
    for _ in range(3):
        env.fake.set_health("rt-ws-acme1", "unhealthy")
        env.svc.reconcile_tenant(tenant)
    assert env.fake.verbs("restart")
    assert env.store.get_tenant(tenant)["status"] == "degraded"


def test_oom_is_counted_and_container_restarted(env, tenant):
    env.fake.crash("rt-ws-acme1", oom=True)
    env.svc.reconcile_tenant(tenant)
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"]
    assert any(c.startswith("oom:") for e in env.store.list_events(tenant)
               for c in e["detail"].get("actions", []))


def test_generation_change_stops_old_before_creating_new(env, tenant):
    env.fake.calls.clear()
    env.store.update_tenant(tenant, generation=2)
    env.svc.reconcile_tenant(tenant)
    verbs = [c[0] for c in env.fake.calls if c[1] == "rt-ws-acme1"]
    assert verbs.index("stop") < verbs.index("remove_container") < verbs.index("create_container")
    assert env.fake.containers["rt-ws-acme1"]["Config"]["Labels"]["rt.generation"] == "2"


def test_digest_change_recreates(env, tenant):
    env.store.update_tenant(tenant, workspace_image_digest=digest("rt-workspace-v2"))
    env.svc.reconcile_tenant(tenant)
    lab = env.fake.containers["rt-ws-acme1"]["Config"]["Labels"]
    assert lab["rt.image.digest"] == digest("rt-workspace-v2").split("@")[1]


def test_foreign_containers_are_invisible_and_untouchable(env, tenant):
    env.fake.foreign_container("evolution-api")
    env.fake.foreign_container("rt-hermes-zzzz1")  # even an rt- name without the label
    assert env.docker.inspect_container("evolution-api") is None
    assert [c["Names"][0] for c in env.docker.list_containers()] == ["/rt-ws-acme1"]
    from rm.policy import NotManaged
    for op in (env.docker.stop, env.docker.start, env.docker.pause, env.docker.kill):
        with pytest.raises(NotManaged):
            op("evolution-api")
    with pytest.raises(NotManaged):
        env.docker.remove_container("evolution-api")
    env.svc.reconcile_all()
    assert env.fake.containers["evolution-api"]["State"]["Running"]


def test_reconcile_all_survives_a_broken_tenant(env):
    env.svc.create_tenant("acme1", "backend")
    env.svc.create_tenant("beta1", "backend")
    env.store.update_tenant("acme1", workspace_image_digest="not-pinned")
    env.fake.crash("rt-ws-beta1", code=1)
    env.fake.crash("rt-ws-acme1", code=1)
    env.fake.containers["rt-ws-acme1"]["Config"]["Labels"]["rt.generation"] = "9"
    env.svc.reconcile_all()
    assert env.fake.containers["rt-ws-beta1"]["State"]["Running"]
    assert env.store.get_tenant("acme1")["status"] == "degraded"
    assert "image" in env.store.get_tenant("acme1")["last_error"].lower() or \
        env.store.get_tenant("acme1")["last_error"]


def test_idle_sleep_runtime_30min_workspace_4h_never_with_exposure(env):
    env.svc.create_tenant("acme1", "backend", runtime=True)
    env.svc.create_tenant("beta1", "backend")
    env.svc.publish("beta1", "web", 8000, "backend")
    now = env.svc.clock()
    for t in ("acme1", "beta1"):
        env.store.update_tenant(t, last_activity_at=now - timedelta(hours=5))
    slept = env.svc.sleep_idle()
    assert "acme1:runtime" in slept and "acme1:workspace" in slept
    assert "beta1:workspace" not in slept   # has an exposure
    env.store.update_tenant("acme1", workspace_desired="running", runtime_desired="running",
                            last_activity_at=now - timedelta(minutes=10))
    assert env.svc.sleep_idle() == []


def test_upgrade_runtime_success_backs_up_first(env):
    env.svc.create_tenant("acme1", "backend", runtime=True)
    new = digest("rt-hermes-v2")
    res = env.svc.upgrade_runtime("acme1", new, "ops")
    assert res["result"] == "upgraded"
    assert [b for b in env.store.backup_list("acme1") if b["kind"] == "pre_upgrade"]
    assert env.store.get_tenant("acme1")["runtime_image_digest"] == new
    assert env.fake.containers["rt-hermes-acme1"]["State"]["Running"]


def test_upgrade_runtime_rolls_back_when_new_digest_is_unhealthy(env):
    env.svc.create_tenant("acme1", "backend", runtime=True)
    old = env.store.get_tenant("acme1")["runtime_image_digest"]
    env.fake.fail_start.add("rt-hermes-acme1")
    # health never turns green with the new image; the old one is restored
    orig_start = env.fake.start

    def start(name):
        orig_start(name)
        if env.store.get_tenant("acme1")["runtime_image_digest"] == old:
            env.fake.containers[name]["State"]["Health"] = {"Status": "healthy"}
    env.fake.start = start
    res = env.svc.upgrade_runtime("acme1", digest("rt-hermes-broken"), "ops", timeout_s=2)
    assert res["result"] == "rolled_back"
    assert env.store.get_tenant("acme1")["runtime_image_digest"] == old
    assert env.svc.metrics["upgrade_rollbacks"] == 1
    assert env.fake.containers["rt-hermes-acme1"]["State"]["Running"]


def test_upgrade_requires_digest_and_noops_on_same(env):
    env.svc.create_tenant("acme1", "backend", runtime=True)
    with pytest.raises(ServiceError):
        env.svc.upgrade_runtime("acme1", "rt-hermes:latest", "ops")
    same = env.store.get_tenant("acme1")["runtime_image_digest"]
    assert env.svc.upgrade_runtime("acme1", same, "ops")["result"] == "noop"


def test_backup_restore_replace_and_clone(env, tmp_path):
    env.settings.manage_host_dirs = True
    env.settings.tenants_root = str(tmp_path / "tenants")  # real dirs for the file backend
    env.svc.s.tenants_root = env.settings.tenants_root
    # workspace data lives in the tenant dir; bind sources must be POSIX for the policy, so use
    # the fake store directly and exercise the backend through the service paths
    (tmp_path / "tenants" / "acme1" / "ws" / "home").mkdir(parents=True)
    (tmp_path / "tenants" / "acme1" / "ws" / "home" / "notes.txt").write_text("v1")
    env.store.create_tenant("acme1", workspace_enabled=True, runtime_enabled=False,
                            workspace_image_digest=digest("rt-workspace"),
                            runtime_image_digest="", quota_gb=5, limits_json={})
    rec = env.svc.make_backup("acme1", "ops")
    (tmp_path / "tenants" / "acme1" / "ws" / "home" / "notes.txt").write_text("v2-broken")
    env.svc._remove_containers = lambda t: []          # no Docker in this check
    env.svc._reconcile_locked = lambda row, actor: row
    out = env.svc.restore("acme1", rec["backup_id"], "replace", "ops")
    assert out["restored_files"] >= 1
    assert (tmp_path / "tenants" / "acme1" / "ws" / "home" / "notes.txt").read_text() == "v1"
    env.svc.create_tenant = lambda *a, **k: env.store.create_tenant("acme2")[0]
    with pytest.raises(ServiceError):
        env.svc.restore("acme1", rec["backup_id"], "clone", "ops")           # clone_as required
    env.svc.restore("acme1", rec["backup_id"], "clone", "ops", clone_as="acme2")
    assert (tmp_path / "tenants" / "acme2" / "ws" / "home" / "notes.txt").read_text() == "v1"


def test_restore_unknown_or_foreign_backup(env, tenant):
    with pytest.raises(ServiceError) as e:
        env.svc.restore(tenant, "nope", "replace", "ops")
    assert e.value.status == 404
    env.svc.create_tenant("beta1", "backend")
    rec = env.svc.make_backup("beta1", "ops")
    with pytest.raises(ServiceError) as e:
        env.svc.restore(tenant, rec["backup_id"], "replace", "ops")   # another tenant's backup
    assert e.value.status == 404
