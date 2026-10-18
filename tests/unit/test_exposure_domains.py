"""Exposure (<app>-<tenant>.apps.*), strict Host, custom domains (TXT + CNAME), wake-on-request."""
from __future__ import annotations

from datetime import timedelta

import pytest
import yaml

from rm import domains as dom
from rm import naming, traefik
from rm.service import ServiceError

APPS = "apps.example.test"


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_managed_host_shape_and_strictness():
    assert traefik.managed_host("metabase", "acme1", APPS) == "metabase-acme1.apps.example.test"
    assert traefik.host_belongs_to_tenant("metabase-acme1.apps.example.test", "acme1", APPS)
    for host in ("metabase-beta1.apps.example.test", "acme1.apps.example.test",
                 "metabase-acme1.apps.example.test.evil.com", "x.metabase-acme1.apps.example.test",
                 "metabase-acme1.example.test"):
        assert not traefik.host_belongs_to_tenant(host, "acme1", APPS)
    for bad in ("Meta", "a", "web-x", "web.x", "../x", "web;x", "1web"):
        with pytest.raises(ValueError):
            traefik.managed_host(bad, "acme1", APPS)


def test_publish_writes_edge_and_front_routes(env, tenant):
    v = env.svc.publish(tenant, "web", 8000, "backend")
    assert v["hosts"] == ["web-acme1.apps.example.test"]
    edge = load(env.svc.edge_routes.dir / "acme1.yml")["http"]
    front = load(env.svc.routes.dir / "acme1.yml")["http"]
    r = edge["routers"]["rt-acme1-web"]
    assert r["rule"] == "Host(`web-acme1.apps.example.test`)" and r["entryPoints"] == ["web"]
    assert "tls" not in r                                    # edge is plain HTTP
    assert edge["services"]["rt-acme1-web"]["loadBalancer"]["servers"] == [
        {"url": "http://rt-ws-acme1:8000"}]
    fr = front["routers"]["rt-acme1-web"]
    assert fr["tls"] == {"certResolver": "letsencrypt"} and fr["entryPoints"] == ["websecure"]
    assert front["services"]["rt-acme1-web"]["loadBalancer"]["servers"] == [
        {"url": "http://rt-edge:8080"}]
    for mw in ("rl", "inflight", "body", "hdr"):             # protections are on the front
        assert f"rt-acme1-{mw}" in fr["middlewares"]
    assert edge["middlewares"]["rt-acme1-edgehdr"]["headers"]["customRequestHeaders"] == {
        "X-RT-Tenant": "acme1"}


def test_tenant_cannot_route_hosts_of_another_tenant(env):
    env.svc.create_tenant("acme1", "backend")
    env.svc.create_tenant("beta1", "backend")
    env.svc.publish("acme1", "web", 8000, "backend")
    env.svc.publish("beta1", "web", 9000, "backend")
    for t in ("acme1", "beta1"):
        hosts = [yaml.safe_load(p.read_text())["http"]["routers"][f"rt-{t}-web"]["rule"]
                 for p in (env.svc.edge_routes.dir / f"{t}.yml",)]
        assert hosts == [f"Host(`web-{t}.apps.example.test`)"]
    assert "beta1" not in (env.svc.edge_routes.dir / "acme1.yml").read_text()


def test_publish_validation(env, tenant):
    for app, port, auth in [("Bad", 80, "none"), ("web", 80, "none"), ("web", 70000, "none"),
                            ("web", 8000, "oauth"), ("a", 8000, "none")]:
        with pytest.raises(ServiceError) as e:
            env.svc.publish(tenant, app, port, "backend", auth)
        assert e.value.status == 400


def test_publish_requires_workspace_and_not_suspended(env):
    env.svc.create_tenant("acme1", "backend", workspace=False, runtime=True)
    with pytest.raises(ServiceError) as e:
        env.svc.publish("acme1", "web", 8000, "backend")
    assert e.value.code == "workspace_not_enabled"
    env.svc.create_tenant("beta1", "backend")
    env.svc.suspend("beta1", "ops", "x")
    with pytest.raises(ServiceError) as e:
        env.svc.publish("beta1", "web", 8000, "backend")
    assert e.value.status == 423


def test_unpublish_removes_routes_and_deactivates_domains(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    env.svc.unpublish(tenant, "web", "backend")
    assert not (env.svc.edge_routes.dir / "acme1.yml").exists()
    assert not (env.svc.routes.dir / "acme1.yml").exists()


def test_edge_is_attached_at_fixed_ip_only_while_exposed(env, tenant):
    env.fake.containers["rt-edge"] = env.fake._new("rt-edge", {
        "Image": "rt-edge", "Labels": {"rt.managed": "true", "rt.role": "edge"},
        "HostConfig": {}}, running=True)
    env.svc.publish(tenant, "web", 8000, "backend")
    nets = env.fake.containers["rt-edge"]["NetworkSettings"]["Networks"]
    idx = env.store.get_tenant(tenant)["net_index"]
    assert nets["rt-ws-acme1"]["IPAddress"] == naming.edge_ip(idx)
    env.svc.unpublish(tenant, "web", "backend")
    assert "rt-ws-acme1" not in env.fake.containers["rt-edge"]["NetworkSettings"]["Networks"]


def test_sleeping_workspace_routes_to_wake_endpoint(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    url = load(env.svc.edge_routes.dir / "acme1.yml")["http"]["services"]["rt-acme1-web"][
        "loadBalancer"]["servers"][0]["url"]
    assert url == "http://rm:8080/wake/acme1"
    env.svc.set_component(tenant, "workspace", "start", "backend")
    url = load(env.svc.edge_routes.dir / "acme1.yml")["http"]["services"]["rt-acme1-web"][
        "loadBalancer"]["servers"][0]["url"]
    assert url == "http://rt-ws-acme1:8000"


def test_wake_decisions(env, tenant):
    assert env.svc.wake("nosuch") == ("deny", 404)
    assert env.svc.wake(tenant) == ("deny", 404)          # nothing exposed: do not leak existence
    env.svc.publish(tenant, "web", 8000, "backend")
    assert env.svc.wake(tenant) == ("ready", 200)
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    assert env.svc.wake(tenant) == ("start", 503)
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"]
    assert env.svc.wake(tenant) == ("ready", 200)


def test_wake_rate_limit_and_suspended():
    assert traefik.wake_decision("exited", False, True, 20) == ("deny", 429)
    assert traefik.wake_decision("exited", False, True, 19) == ("start", 503)
    assert traefik.wake_decision("exited", True, True, 0) == ("deny", 403)
    assert traefik.wake_decision("restarting", False, True, 0) == ("wait", 503)


def test_wake_does_not_start_suspended_tenant(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    env.svc.suspend(tenant, "ops", "x", "critical")
    assert env.svc.wake(tenant) == ("deny", 403)
    assert env.fake.containers["rt-ws-acme1"]["State"]["Running"] is False


# ----- custom domains ------------------------------------------------------------------------
def test_validate_custom_host():
    assert dom.validate_custom_host("App.Cliente.com.", APPS) == "app.cliente.com"
    for bad, code in [("nodot", "invalid_host"), ("a b.com", "invalid_host"),
                      ("x.apps.example.test", "platform_domain_not_allowed"),
                      ("foo.rangeltech.net", "platform_domain_not_allowed"),
                      ("login-paypal.com", "protected_brand:paypal"),
                      ("secure.itau.com.br", "protected_brand:itau"),
                      ("www.gov.br", "protected_brand:gov")]:
        with pytest.raises(dom.DomainError) as e:
            dom.validate_custom_host(bad, APPS)
        assert str(e.value) == code


def test_domain_flow_requires_txt_and_cname(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    d = env.svc.add_domain(tenant, "app.cliente.com", "web", "backend")
    assert d["txt_name"] == "_rt-verify.app.cliente.com"
    assert d["cname_target"] == "web-acme1.apps.example.test"
    # CNAME without TXT: refused
    env.cname["app.cliente.com"] = ["web-acme1.apps.example.test."]
    r = env.svc.verify_domain(tenant, "app.cliente.com", "backend")
    assert r == {"host": "app.cliente.com", "active": False, "reason": "txt_missing"}
    # TXT without CNAME: refused
    env.cname.clear()
    env.txt[d["txt_name"]] = [f'"{d["txt_value"]}"']
    assert env.svc.verify_domain(tenant, "app.cliente.com", "backend")["reason"] == "cname_missing"
    # both: active, and the custom host appears in both route files
    env.cname["app.cliente.com"] = ["web-acme1.apps.example.test."]
    assert env.svc.verify_domain(tenant, "app.cliente.com", "backend")["active"] is True
    for f in (env.svc.edge_routes.dir, env.svc.routes.dir):
        rule = load(f / "acme1.yml")["http"]["routers"]["rt-acme1-web"]["rule"]
        assert "Host(`app.cliente.com`)" in rule and "Host(`web-acme1.apps.example.test`)" in rule


def test_domain_is_deactivated_when_cname_disappears_after_24h(env, tenant):
    env.svc.publish(tenant, "web", 8000, "backend")
    d = env.svc.add_domain(tenant, "app.cliente.com", "web", "backend")
    env.txt[d["txt_name"]] = [d["txt_value"]]
    env.cname["app.cliente.com"] = ["web-acme1.apps.example.test"]
    assert env.svc.verify_domain(tenant, "app.cliente.com", "backend")["active"]
    assert env.svc.revalidate_domains() == 0                      # checked just now: nothing due
    env.cname.clear()                                              # tenant removed the CNAME
    assert env.svc.revalidate_domains() == 0                      # still inside the 24 h window
    env.store.domain_upsert("app.cliente.com", last_check_at=env.svc.clock() - timedelta(hours=25))
    assert env.svc.revalidate_domains() == 1
    assert env.store.domain_get("app.cliente.com")["active"] is False
    rule = load(env.svc.edge_routes.dir / "acme1.yml")["http"]["routers"]["rt-acme1-web"]["rule"]
    assert "cliente.com" not in rule                              # no takeover surface left
    assert any(e["action"] == "domain.deactivate" for e in env.store.list_events(tenant))


def test_domain_cannot_be_claimed_by_two_tenants_or_for_unpublished_app(env):
    env.svc.create_tenant("acme1", "backend")
    env.svc.create_tenant("beta1", "backend")
    env.svc.publish("acme1", "web", 8000, "backend")
    env.svc.publish("beta1", "web", 8000, "backend")
    with pytest.raises(ServiceError) as e:
        env.svc.add_domain("acme1", "app.cliente.com", "other", "backend")
    assert e.value.code == "app_not_published"
    env.svc.add_domain("acme1", "app.cliente.com", "web", "backend")
    with pytest.raises(ServiceError) as e:
        env.svc.add_domain("beta1", "app.cliente.com", "web", "backend")
    assert e.value.code == "domain_in_use"
    with pytest.raises(ServiceError) as e:
        env.svc.verify_domain("beta1", "app.cliente.com", "backend")
    assert e.value.status == 404


def test_token_is_bound_to_tenant_and_host():
    a = dom.make_token("s", "acme1", "app.cliente.com")
    assert a != dom.make_token("s", "beta1", "app.cliente.com")
    assert a != dom.make_token("s", "acme1", "other.cliente.com")
    assert a != dom.make_token("t", "acme1", "app.cliente.com")


def test_route_writer_is_atomic_and_idempotent(tmp_path):
    w = traefik.RouteWriter(str(tmp_path / "d"))
    cfg = traefik.render_edge_routes("acme1", [{"app": "web", "port": 8000}], APPS,
                                     "http://rt-ws-{tenant}:{port}", "http://rm", True)
    assert w.write("acme1", cfg) is True
    assert w.write("acme1", cfg) is False
    assert not list((tmp_path / "d").glob(".*.tmp"))
    assert w.write("acme1", {"http": {"routers": {}}}) is True       # empty config removes file
    assert w.remove("acme1") is False
    with pytest.raises(ValueError):
        w.path("../etc")
