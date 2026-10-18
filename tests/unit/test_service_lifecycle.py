"""Tenant lifecycle: create / start / stop / restart / suspend / resume / retire / purge."""
from __future__ import annotations

import pytest

from rm import naming
from rm.service import ServiceError


def test_create_builds_networks_container_and_labels(env):
    v = env.svc.create_tenant("acme1", "backend")
    assert v["status"] == "running"
    assert v["observed"]["workspace"]["state"] == "running"
    assert v["observed"]["runtime"]["state"] == "absent"
    f = env.fake
    assert {"rt-net-acme1", "rt-ws-acme1", "rt-pool", "rt-ssh"} <= set(f.networks) | {"rt-net-acme1"}
    ws = f.containers["rt-ws-acme1"]
    labels = ws["Config"]["Labels"]
    assert labels["rt.managed"] == "true" and labels["rt.tenant"] == "acme1"
    assert labels["rt.role"] == "workspace" and labels["rt.generation"] == "1"
    assert "rt-ssh" in ws["NetworkSettings"]["Networks"]
    assert env.quota.limits["acme1"] == 10
    assert "acme1" in env.keys and env.keys["acme1"].startswith("-----BEGIN OPENSSH PRIVATE KEY")


def test_authorized_key_is_public_and_private_never_in_container_env(env, tenant):
    env_list = env.fake.containers["rt-ws-acme1"]["Config"]["Env"]
    joined = "\n".join(env_list)
    assert "ssh-ed25519" in joined and "PRIVATE KEY" not in joined
    assert not any(e.startswith(("API_SERVER_KEY", "LITELLM", "DATABASE")) for e in env_list)


def test_create_is_idempotent(env, tenant):
    n = len(env.fake.verbs("create_container"))
    v1 = env.svc.create_tenant("acme1", "backend")
    v2 = env.svc.create_tenant("acme1", "backend")
    assert v1["net_index"] == v2["net_index"]
    assert len(env.fake.verbs("create_container")) == n
    assert len(env.keys) == 1  # keys generated once


def test_invalid_tenant_ids_rejected(env):
    for bad in ("Acme1", "1abc", "ab", "a" * 21, "ac me", "a;rm", "../x"):
        with pytest.raises(ServiceError) as e:
            env.svc.create_tenant(bad, "backend")
        assert e.value.status == 400


def test_distinct_net_indexes_and_subnets(env):
    a = env.svc.create_tenant("acme1", "backend")
    b = env.svc.create_tenant("beta1", "backend")
    assert a["net_index"] != b["net_index"]
    sa = env.fake.networks["rt-ws-acme1"]["IPAM"]["Config"][0]["Subnet"]
    sb = env.fake.networks["rt-ws-beta1"]["IPAM"]["Config"][0]["Subnet"]
    assert sa != sb
    assert env.fake.networks["rt-net-acme1"]["Internal"] is True
    assert env.fake.networks["rt-ws-acme1"]["Internal"] is False


def test_stop_start_restart_workspace(env, tenant):
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"] is False
    env.svc.set_component(tenant, "workspace", "start", "backend")
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"] is True
    env.svc.set_component(tenant, "workspace", "restart", "backend")
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"] is True
    assert env.fake.verbs("stop")  # restart stopped it first


def test_runtime_disabled_cannot_be_started(env, tenant):
    with pytest.raises(ServiceError) as e:
        env.svc.set_component(tenant, "runtime", "start", "backend")
    assert e.value.code == "runtime_not_enabled"


def test_runtime_and_workspace_share_tenant_net_and_ssh_hub(env):
    env.svc.create_tenant("acme1", "backend", runtime=True)
    ws = env.fake.containers["rt-ws-acme1"]["NetworkSettings"]["Networks"]
    rt = env.fake.containers["rt-hermes-acme1"]["NetworkSettings"]["Networks"]
    assert set(ws) == {"rt-ws-acme1", "rt-net-acme1", "rt-ssh"}
    assert set(rt) == {"rt-net-acme1"}
    # the runtime has no way out: only the internal tenant net
    assert env.fake.networks["rt-net-acme1"]["Internal"] is True
    api_key = [e for e in env.fake.containers["rt-hermes-acme1"]["Config"]["Env"]
               if e.startswith("API_SERVER_KEY=")]
    assert len(api_key) == 1 and len(api_key[0]) > 40


def test_unique_api_key_per_tenant(env):
    env.svc.create_tenant("acme1", "backend", runtime=True)
    env.svc.create_tenant("beta1", "backend", runtime=True)

    def key(t):
        return next(e for e in env.fake.containers[f"rt-hermes-{t}"]["Config"]["Env"]
                    if e.startswith("API_SERVER_KEY="))
    assert key("acme1") != key("beta1")


def test_suspend_cuts_everything_fast_and_resume_needs_second_approver(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    assert (env.svc.edge_routes.dir / "acme1.yml").exists()
    v = env.svc.suspend(tenant, "ops", "abuse report", "high")
    assert v["status"] == "suspended"
    ev = [e for e in env.store.list_events(tenant) if e["action"] == "tenant.suspend"][0]
    assert ev["detail"]["elapsed_s"] < 2
    assert not (env.svc.edge_routes.dir / "acme1.yml").exists()
    assert not (env.svc.routes.dir / "acme1.yml").exists()
    assert env.fake.containers["rt-ws-acme1"]["State"]["Paused"] is True
    assert env.revoker.revoked == ["acme1"]
    killed = env.fw.applied[-1].tenants[0]
    assert killed.killed is True
    assert (env.settings.forensics_dir and any(
        p.name == "snapshot.json" for p in __import__("pathlib").Path(
            env.settings.forensics_dir).rglob("*.json")))
    with pytest.raises(ServiceError) as e:
        env.svc.set_component(tenant, "workspace", "start", "backend")
    assert e.value.status == 423
    with pytest.raises(ServiceError) as e:
        env.svc.resume(tenant, "ops", "ops", True)       # same person approves: refused
    assert e.value.code == "second_approver_required"
    with pytest.raises(ServiceError) as e:
        env.svc.resume(tenant, "ops", "other", False)    # not admin: refused
    assert e.value.status == 403
    v = env.svc.resume(tenant, "ops", "security-lead", True)
    assert v["status"] in ("running", "starting")
    assert env.fake.containers["rt-ws-acme1"]["State"]["Paused"] is False


def test_critical_suspend_stops_instead_of_pausing(env, tenant):
    env.svc.suspend(tenant, "ops", "malware", "critical")
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"] is False


def test_fleet_freeze_suspends_every_workspace(env):
    env.svc.create_tenant("acme1", "backend")
    env.svc.create_tenant("beta1", "backend")
    done = env.svc.freeze_fleet("ops", "incident")
    assert sorted(done) == ["acme1", "beta1"]
    assert env.store.kv_get("fleet_frozen")["by"] == "ops"
    assert all(env.store.get_tenant(t)["suspended"] for t in done)


def test_retire_keeps_data_and_purge_is_guarded(env, tenant):
    env.svc.retire(tenant, "backend")
    assert "rt-ws-acme1" not in env.fake.containers
    assert env.store.get_tenant(tenant)["desired_state"] == "retired"
    assert env.store.get_tenant(tenant)["purge_after"] is not None
    with pytest.raises(ServiceError) as e:
        env.svc.purge(tenant, "ops", tenant, is_admin=False)
    assert e.value.code == "purge_requires_admin"
    with pytest.raises(ServiceError) as e:
        env.svc.purge(tenant, "ops", "wrong", is_admin=True)
    assert e.value.code == "purge_confirm_mismatch"
    with pytest.raises(ServiceError) as e:   # retention (30 d) not elapsed
        env.svc.purge(tenant, "ops", tenant, is_admin=True)
    assert e.value.code == "purge_guard"
    assert env.store.get_tenant(tenant)["desired_state"] == "retired"


def test_purge_after_retention_takes_backup_and_removes_resources(env, tenant, tmp_path):
    from datetime import timedelta
    env.svc.retire(tenant, "backend")
    env.store.update_tenant(tenant, purge_after=env.svc.clock() - timedelta(days=1))
    res = env.svc.purge(tenant, "ops", tenant, is_admin=True)
    assert res["status"] == "destroyed"
    assert [b for b in env.store.backup_list(tenant) if b["kind"] == "pre_purge"]
    assert "rt-ws-acme1" not in env.fake.networks and "rt-net-acme1" not in env.fake.networks
    with pytest.raises(ServiceError) as e:
        env.svc.view(tenant)
    assert e.value.status == 404
    with pytest.raises(ServiceError) as e:
        env.svc.create_tenant(tenant, "backend")
    assert e.value.code == "tenant_destroyed"


def test_purge_override_for_operator(env, tenant):
    env.svc.retire(tenant, "backend")
    assert env.svc.purge(tenant, "ops", tenant, is_admin=True, override=True)["status"] == "destroyed"


def test_volumes_only_removed_by_purge(env, tenant):
    env.fake.volumes["rt-hermes-acme1-data"] = {
        "Name": "rt-hermes-acme1-data", "Labels": naming.labels(naming.ROLE_VOLUME, "acme1")}
    env.svc.retire(tenant, "backend")
    assert "rt-hermes-acme1-data" in env.fake.volumes
    env.svc.purge(tenant, "ops", tenant, is_admin=True, override=True)
    assert "rt-hermes-acme1-data" not in env.fake.volumes


def test_event_chain_is_intact_and_tamper_evident(env, tenant):
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    env.svc.set_component(tenant, "workspace", "start", "backend")
    assert env.store.verify_chain()
    env.store.events[1]["action"] = "tampered"
    assert not env.store.verify_chain()


def test_metrics_text_has_fleet_and_disk(env, tenant):
    txt = env.svc.metrics_text()
    assert 'rt_tenants{status="running"} 1' in txt
    assert "rt_disk_limit_bytes" in txt


def test_usage_sampler_accumulates(env, tenant):
    from datetime import UTC, datetime, timedelta

    from rm.usage import UsageSampler
    env.fake.containers["rt-ws-acme1"]["_cpu_ns"] = 2_000_000_000
    s = UsageSampler(env.docker, env.store, env.quota)
    t0 = datetime(2026, 10, 18, 10, 0, tzinfo=UTC)
    s.sample_once(t0)
    env.fake.containers["rt-ws-acme1"]["_cpu_ns"] = 5_000_000_000
    s.sample_once(t0 + timedelta(minutes=30))
    row = env.store.usage_list(tenant)[0]
    assert round(row["cpu_seconds"], 1) == 3.0
    assert round(row["ws_uptime_h"], 2) == 0.5
