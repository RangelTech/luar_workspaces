"""Matrix W1-W12 (spec 04 section 13), offline half. Each test proves the part of the criterion that
the runtime-manager decides (container body, firewall ruleset, routes, state machine); the half that
needs a kernel (real OOM, real nft, real XFS) lives in tests/integration and scripts/qa."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from rm import naming, nft, quota, templates
from rm.abuse import AbuseMonitor
from rm.service import ServiceError

ROOT = Path(__file__).resolve().parents[2]


def body(env, t="acme1"):
    return env.fake.containers[f"rt-ws-{t}"]


def ruleset(env):
    return nft.render(env.fw.applied[-1])


def test_w01_state_survives_restart_and_recreation(env, tenant):
    binds = list(body(env)["HostConfig"]["Binds"])
    assert any(b.endswith(":/var/lib/rt") for b in binds)      # service list + packages.list
    assert any(b.endswith(":/opt") for b in binds) and any(b.endswith(":/home/ws") for b in binds)
    env.svc.set_component(tenant, "workspace", "restart", "backend")
    assert body(env)["State"]["Running"]
    env.fake.containers.pop("rt-ws-acme1")                     # recreation: container gone, data stays
    env.svc.reconcile_tenant(tenant)
    assert body(env)["HostConfig"]["Binds"] == binds
    rf = ROOT / "images/rt-workspace/rootfs/etc/s6-overlay"
    assert "packages.list" in (rf / "scripts/rt-packages").read_text(encoding="utf-8")
    assert (rf / "s6-rc.d/rt-services/run").exists() and (rf / "s6-rc.d/sshd/run").exists()


def test_w02_oom_hits_only_the_workspace_process_tree(env, tenant):
    hc = body(env)["HostConfig"]
    assert hc["Memory"] == hc["MemorySwap"] > 0                # hard cap, no swap
    assert hc["OomScoreAdj"] > 0 and not hc.get("OomKillDisable")
    assert hc["MemoryReservation"] < hc["Memory"]
    assert hc["RestartPolicy"]["Name"] == "on-failure"


def test_w03_resource_abuse_is_contained(env, tenant):
    hc = body(env)["HostConfig"]
    assert hc["PidsLimit"] == 512                              # fork bomb
    assert hc["NanoCpus"] == 1_000_000_000 and hc["Ulimits"][0]["Hard"] == 4096
    assert hc["LogConfig"]["Config"]["max-size"] == "10m"
    assert hc["CapDrop"] == ["ALL"] and not hc["Privileged"]
    assert "no-new-privileges" in hc["SecurityOpt"]
    rs = ruleset(env)
    assert f"ct count over {nft.CONNLIMIT}" in rs              # 1000 connections
    assert nft.NEW_CONN_RATE in rs                             # iperf-style flood
    io = templates._host_limits(templates.workspace_limits("standard"), "/dev/sda")
    assert "BlkioDeviceWriteBps" in io                         # dd throttled when device is known


def test_w04_workspace_cannot_reach_platform_or_other_tenants(env):
    env.svc.create_tenant("acme1", "backend")
    env.svc.create_tenant("beta1", "backend")
    rs = ruleset(env)
    for rng in ("169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert rng in rs                                       # metadata, DB, LiteLLM live in private space
    assert "ip saddr @ws_egress ip daddr @ws_egress counter drop" in rs
    assert "ip saddr @ws_hub ip daddr @ws_hub counter drop" in rs
    assert "ip saddr @ws_hub ip daddr @workers counter drop" in rs
    assert set(body(env)["NetworkSettings"]["Networks"]) == {"rt-ws-acme1", "rt-ssh"}
    assert set(body(env, "beta1")["NetworkSettings"]["Networks"]) == {"rt-ws-beta1", "rt-ssh"}
    assert not any("LITELLM" in e or "DATABASE" in e for e in body(env)["Config"]["Env"])


def test_w05_smtp_and_friends_are_closed(env, tenant):
    rs = ruleset(env)
    blocked = next(x for x in rs.splitlines() if "tcp dport" in x and "drop" in x and "465" in x)
    for p in ("25", "465", "587", "22", "23", "445", "3389"):
        assert p in blocked.replace(",", " ").split()
    allowed = next(x for x in rs.splitlines() if x.strip().endswith("accept") and "443" in x)
    assert "25," not in allowed and "587" not in allowed


def test_w06_exposure_gets_managed_host_with_tls(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    front = yaml.safe_load((env.svc.routes.dir / "acme1.yml").read_text(encoding="utf-8"))["http"]
    r = front["routers"]["rt-acme1-web"]
    assert r["rule"] == "Host(`web-acme1.apps.example.test`)"
    assert r["tls"] == {"certResolver": "letsencrypt"} and r["entryPoints"] == ["websecure"]


def test_w07_host_of_another_tenant_is_never_routed(env):
    env.svc.create_tenant("acme1", "backend")
    env.svc.create_tenant("beta1", "backend")
    env.svc.publish("acme1", "web", 8000, "backend")
    assert "beta1" not in (env.svc.edge_routes.dir / "acme1.yml").read_text(encoding="utf-8")
    assert not (env.svc.edge_routes.dir / "beta1.yml").exists()   # no route -> edge answers 404
    cfg = yaml.safe_load((ROOT / "images/rt-edge/traefik.yml").read_text(encoding="utf-8"))
    assert "web" in cfg["entryPoints"]


def test_w08_custom_domain_txt_cname_and_removal(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    d = env.svc.add_domain(tenant, "app.cliente.com", "web", "backend")
    assert env.svc.verify_domain(tenant, "app.cliente.com", "backend")["active"] is False
    env.txt[d["txt_name"]] = [d["txt_value"]]
    env.cname["app.cliente.com"] = [d["cname_target"]]
    assert env.svc.verify_domain(tenant, "app.cliente.com", "backend")["active"] is True
    env.svc.unpublish(tenant, "web", "backend")                  # removal: no route left
    assert not (env.svc.edge_routes.dir / "acme1.yml").exists()
    assert not (env.svc.routes.dir / "acme1.yml").exists()
    assert env.store.domain_get("app.cliente.com")["active"] is False


def test_w09_wake_on_request(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    edge = yaml.safe_load((env.svc.edge_routes.dir / "acme1.yml").read_text(encoding="utf-8"))["http"]
    url = edge["services"]["rt-acme1-web"]["loadBalancer"]["servers"][0]["url"]
    assert url.endswith("/wake/acme1")
    assert env.svc.wake(tenant) == ("start", 503)
    assert body(env)["State"]["Running"]


def test_w10_abuse_miner_suspends(env, tenant):
    body(env)["_procs"] = ["/init", "/tmp/xmrig --donate-level=1"]
    hits = AbuseMonitor(env.settings, env.docker, env.svc).scan()
    assert hits and env.store.get_tenant(tenant)["suspended"]
    assert any(e["action"] == "tenant.suspend" for e in env.store.list_events(tenant))
    assert "set mining_ips" in nft.render(nft.FirewallInput())    # known pools are dropped at the firewall


def test_w11_kill_switch_is_fast_and_total(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    env.svc.suspend(tenant, "ops", "abuse", "high")
    ev = next(e for e in env.store.list_events(tenant) if e["action"] == "tenant.suspend")
    assert ev["detail"]["elapsed_s"] < 2
    assert env.fw.applied[-1].tenants[0].killed
    rs = ruleset(env)
    idx = env.store.get_tenant(tenant)["net_index"]
    killed_set = rs.split("set killed_egress")[1].split("}")[0]
    assert str(naming.egress_subnet(idx)) in killed_set
    chain = rs[rs.index("chain forward"):]
    assert chain.index("@killed_egress counter drop") < chain.index("ct state established")  # cuts live flows
    with pytest.raises(ServiceError) as e:
        env.svc.set_component(tenant, "workspace", "start", "backend")
    assert e.value.status == 423


def test_w12_disk_quota_is_set_and_enforced_by_xfs_commands(env, tenant):
    assert env.quota.limits["acme1"] == 10
    cmds = quota.XfsQuota(runner=lambda c: "").commands_for("acme1", "/srv/tenants/acme1", 10)
    assert any("bhard=10g" in " ".join(c) for c in cmds)         # ENOSPC comes from the hard limit
    rep = quota.parse_report("rt_acme1 10485760 0 10485760 00 [--------]\n")
    assert rep["acme1"]["used"] == rep["acme1"]["hard"]
