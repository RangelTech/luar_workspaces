"""HTTP API: HMAC auth, IDOR across tenants, idempotency keys, admin-only verbs, wake endpoint."""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from rm import auth
from rm.api import Ctx, create_app
from rm.pool import PoolManager


@pytest.fixture
def client(env):
    pool = PoolManager(env.settings, env.store, env.docker, env.fw,
                       refresh_firewall=env.svc.refresh_firewall, sleep=lambda s: None)
    app = create_app(Ctx(env.settings, env.svc, pool))
    return Client(TestClient(app), env)


class Client:
    def __init__(self, tc, env):
        self.tc, self.env = tc, env

    def call(self, method, path, *, svc="backend", scope="*", body=None, headers=None, iat=None,
             secret=None):
        raw = b"" if body is None else json.dumps(body).encode()
        key = secret or self.env.settings.service_keys[svc]
        h = auth.sign(key, svc, scope, method, path, raw, iat)
        h.update(headers or {})
        return self.tc.request(method, path, content=raw, headers=h)


def test_health_is_open(client):
    r = client.tc.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


@pytest.mark.parametrize("mut,code", [
    ({"secret": "wrong"}, "bad_signature"),
    ({"iat": int(time.time()) - 120}, "iat_out_of_window"),
    ({"iat": int(time.time()) + 60}, "iat_out_of_window"),
])
def test_bad_credentials_are_401(client, mut, code):
    r = client.call("GET", "/v1/fleet", **mut)
    assert r.status_code == 401 and r.json()["error"] == code


def test_missing_headers_unknown_service_and_replayed_other_path(client):
    assert client.tc.get("/v1/fleet").status_code == 401
    r = client.tc.get("/v1/fleet", headers=auth.sign("x", "ghost", "*", "GET", "/v1/fleet"))
    assert r.json()["error"] == "unknown_service"
    # a signature for one path cannot be replayed on another
    h = auth.sign("k-backend", "backend", "*", "GET", "/v1/fleet")
    assert client.tc.get("/v1/pool", headers=h).status_code == 401


def test_tampered_body_is_rejected(client):
    raw = json.dumps({"plan": "standard"}).encode()
    h = auth.sign("k-backend", "backend", "*", "POST", "/v1/tenants/acme1", raw)
    r = client.tc.post("/v1/tenants/acme1", content=json.dumps({"plan": "pro"}).encode(), headers=h)
    assert r.status_code == 401


def test_wildcard_scope_needs_admin_service(client):
    r = client.call("GET", "/v1/fleet", svc="tenant-a", scope="*")
    assert r.status_code == 403 and r.json()["error"] == "wildcard_scope_requires_admin"


def test_create_and_get_tenant(client):
    r = client.call("POST", "/v1/tenants/acme1", body={"plan": "standard"})
    assert r.status_code == 200 and r.json()["status"] == "running"
    assert "authorized_key" not in r.json()                 # nothing key related leaves the RM
    g = client.call("GET", "/v1/tenants/acme1")
    assert g.json()["observed"]["workspace"]["state"] == "running"


def test_idor_token_of_t1_on_t2_is_403(client):
    client.call("POST", "/v1/tenants/acme1", body={})
    client.call("POST", "/v1/tenants/beta1", body={})
    ok = client.call("GET", "/v1/tenants/acme1", svc="tenant-a", scope="acme1")
    assert ok.status_code == 200
    for method, path in [("GET", "/v1/tenants/beta1"), ("GET", "/v1/tenants/beta1/events"),
                         ("POST", "/v1/tenants/beta1/workspace:stop"),
                         ("POST", "/v1/tenants/beta1/backup"),
                         ("POST", "/v1/tenants/beta1/exposures"),
                         ("POST", "/v1/tenants/beta1/activity")]:
        r = client.call(method, path, svc="tenant-a", scope="acme1", body={})
        assert r.status_code == 403, (method, path, r.text)
        assert r.json()["error"] == "forbidden_tenant"
    assert client.env.fake.containers["rt-ws-beta1"]["State"]["Running"]


def test_tenant_scoped_token_cannot_use_admin_verbs(client):
    client.call("POST", "/v1/tenants/acme1", body={})
    for method, path, body in [
            ("POST", "/v1/tenants/acme1:suspend", {"reason": "x"}),
            ("POST", "/v1/tenants/acme1", {}),
            ("DELETE", "/v1/tenants/acme1", None),
            ("POST", "/v1/tenants/acme1/runtime:upgrade", {"image_digest": "x"}),
            ("GET", "/v1/fleet", None), ("GET", "/v1/pool", None),
            ("POST", "/v1/executor/runs", {"script": "print(1)"}),
            ("POST", "/v1/fleet:freeze", {})]:
        r = client.call(method, path, svc="tenant-a", scope="acme1", body=body)
        assert r.status_code == 403, (method, path)


def test_invalid_tenant_id_in_path(client):
    r = client.call("GET", "/v1/tenants/Bad_Id")
    assert r.status_code == 400


def test_idempotency_key_replays_without_repeating_side_effects(client):
    body = {"plan": "standard"}
    r1 = client.call("POST", "/v1/tenants/acme1", body=body, headers={"Idempotency-Key": "k1"})
    n = len(client.env.fake.verbs("create_container"))
    r2 = client.call("POST", "/v1/tenants/acme1", body=body, headers={"Idempotency-Key": "k1"})
    assert r1.json() == r2.json()
    assert len(client.env.fake.verbs("create_container")) == n
    r3 = client.call("POST", "/v1/tenants/acme1", body={"plan": "pro"},
                     headers={"Idempotency-Key": "k1"})
    assert r3.status_code == 409 and r3.json()["error"] == "idempotency_key_conflict"


def test_same_idempotency_key_is_scoped_per_tenant(client):
    a = client.call("POST", "/v1/tenants/acme1", body={}, headers={"Idempotency-Key": "k"})
    b = client.call("POST", "/v1/tenants/beta1", body={}, headers={"Idempotency-Key": "k"})
    assert a.status_code == b.status_code == 200
    assert a.json()["tenant_id"] != b.json()["tenant_id"]


def test_suspend_resume_over_http(client):
    client.call("POST", "/v1/tenants/acme1", body={})
    r = client.call("POST", "/v1/tenants/acme1:suspend", body={"reason": "abuse"})
    assert r.json()["status"] == "suspended"
    bad = client.call("POST", "/v1/tenants/acme1:resume", body={"approver": "ops"}, svc="ops")
    assert bad.status_code == 403
    ok = client.call("POST", "/v1/tenants/acme1:resume", body={"approver": "lead"}, svc="ops")
    assert ok.status_code == 200 and ok.json()["suspended"] is False


def test_unknown_verb_is_404(client):
    client.call("POST", "/v1/tenants/acme1", body={})
    assert client.call("POST", "/v1/tenants/acme1:explode", body={}).status_code == 404


def test_exposure_and_domain_endpoints(client):
    client.call("POST", "/v1/tenants/acme1", body={})
    r = client.call("POST", "/v1/tenants/acme1/exposures", body={"app": "web", "port": 8000})
    assert r.json()["hosts"] == ["web-acme1.apps.example.test"]
    d = client.call("POST", "/v1/tenants/acme1/domains",
                    body={"host": "app.cliente.com", "app": "web"})
    assert d.json()["txt_name"] == "_rt-verify.app.cliente.com"
    bad = client.call("POST", "/v1/tenants/acme1/domains", body={"host": "x.rangeltech.net",
                                                                  "app": "web"})
    assert bad.status_code == 400
    v = client.call("POST", "/v1/tenants/acme1/domains/app.cliente.com/verify")
    assert v.json()["active"] is False
    assert client.call("DELETE", "/v1/tenants/acme1/exposures/web").status_code == 200


def test_policy_violation_is_422_and_never_reaches_docker(client, monkeypatch):
    from rm import templates
    client.call("POST", "/v1/tenants/acme1", body={})
    before = len(client.env.fake.verbs("create_container"))
    orig = templates.workspace_spec

    def evil(*a, **k):
        b = orig(*a, **k)
        b["HostConfig"]["Privileged"] = True
        return b
    monkeypatch.setattr(templates, "workspace_spec", evil)
    client.env.fake.crash("rt-ws-acme1")
    client.env.store.update_tenant("acme1", generation=5)
    client.env.svc.reconcile_tenant("acme1")
    assert len(client.env.fake.verbs("create_container")) == before
    assert "privileged" in client.env.store.get_tenant("acme1")["last_error"]


def test_events_endpoint_returns_chain(client):
    client.call("POST", "/v1/tenants/acme1", body={})
    ev = client.call("GET", "/v1/tenants/acme1/events").json()
    assert ev[0]["hash"] and ev[-1]["action"] == "tenant.create"


def test_wake_endpoint_is_public_and_leaks_nothing(client):
    assert client.tc.get("/wake/nosuch1").status_code == 404
    assert client.tc.get("/wake/BAD").status_code == 404
    client.call("POST", "/v1/tenants/acme1", body={})
    assert client.tc.get("/wake/acme1").status_code == 404        # nothing published
    client.call("POST", "/v1/tenants/acme1/exposures", body={"app": "web", "port": 8000})
    client.call("POST", "/v1/tenants/acme1/workspace:stop")
    r = client.tc.get("/wake/acme1")
    assert r.status_code == 503 and r.headers["retry-after"] == "5"
    assert "acordando" in r.text
    assert client.env.fake.containers["rt-ws-acme1"]["State"]["Running"]


def test_metrics_with_token_or_admin(client):
    client.env.settings.metrics_token = "tok"
    assert client.tc.get("/metrics", headers={"Authorization": "Bearer tok"}).status_code == 200
    assert client.tc.get("/metrics").status_code == 401
    assert client.call("GET", "/metrics").status_code == 200


def test_delete_retires_and_purge_requires_confirm(client):
    client.call("POST", "/v1/tenants/acme1", body={})
    assert client.call("DELETE", "/v1/tenants/acme1").json()["status"] == "retired"
    r = client.call("DELETE", "/v1/tenants/acme1?purge=true&confirm=wrong")
    assert r.status_code == 400
    r = client.call("DELETE", "/v1/tenants/acme1?purge=true&confirm=acme1&override=true")
    assert r.status_code == 200 and r.json()["status"] == "destroyed"


def test_openapi_and_docs_are_not_exposed(client):
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.tc.get(p).status_code == 404
