"""AMB-1/AMB-5: lista de servicos do workspace (somente leitura), acoes auditadas, redacao, isolamento."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from rm import redact
from rm.service import ServiceError

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "images/rt-workspace/rootfs/usr/local/bin/rt-services-json"
CMD = " ".join(["timeout", "-k", "2", "20", "/usr/local/bin/rt-services-json"])


def load_script():
    loader = importlib.machinery.SourceFileLoader("rt_services_json", str(SCRIPT))
    spec = importlib.util.spec_from_loader("rt_services_json", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


PAYLOAD = {
    "schema": 2, "gerado_em": 1, "docker": True, "avisos": [],
    "servicos": [{"nome": "web", "estado": "rodando", "pid": 40, "uptime_s": 90, "reinicios": None,
                  "cpu_pct": 1.2, "mem_mb": 30.5, "portas": [8000], "origem": "supervisionado"}],
    "soltos": [{"pid": 99, "comando": "python3", "argumentos": "python3 x.py --password hunter2 token=abc123",
                "uptime_s": 5, "cpu_pct": 0.0, "mem_mb": 9.0, "portas": [], "origem": "solto"}],
    "conteineres": [],
}


def test_list_services_merges_public_url_and_redacts(env, tenant):
    env.svc.publish(tenant, "site", 8000, "backend", "none")
    env.fake.exec_results = {CMD: {"exit_code": 0, "stdout": json.dumps(PAYLOAD) + "\n", "stderr": ""}}
    out = env.svc.list_services(tenant, "backend")
    assert out["ambiente"] == "ativo"
    assert out["servicos"][0]["url_publica"] == "https://site-acme1.apps.example.test"
    assert "hunter2" not in json.dumps(out) and "abc123" not in json.dumps(out)
    assert out["soltos"][0]["url_publica"] is None


def test_zero_services_is_valid(env, tenant):
    empty = {"schema": 2, "servicos": [], "soltos": [], "conteineres": [], "docker": False, "avisos": []}
    env.fake.exec_results = {CMD: {"exit_code": 0, "stdout": json.dumps(empty), "stderr": ""}}
    out = env.svc.list_services(tenant, "backend")
    assert out["servicos"] == [] and out["soltos"] == [] and out["ambiente"] == "ativo"


def test_broken_probe_is_502_not_a_crash(env, tenant):
    env.fake.exec_results = {CMD: {"exit_code": 0, "stdout": "lixo", "stderr": ""}}
    with pytest.raises(ServiceError) as e:
        env.svc.list_services(tenant, "backend")
    assert e.value.status == 502


def test_stopped_or_suspended_environment_is_listed_without_waking(env, tenant):
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    n = len(env.fake.calls)
    out = env.svc.list_services(tenant, "backend")
    assert out["ambiente"] == "parado" and out["servicos"] == []
    assert not [c for c in env.fake.calls[n:] if c[0] in ("start", "exec_run", "create_container")]
    assert not env.fake.containers["rt-ws-acme1"]["State"]["Running"]
    env.svc.suspend(tenant, "backend", "teste", "high")
    assert env.svc.list_services(tenant, "backend")["ambiente"] == "suspenso"


def test_service_actions_audited_and_validated(env, tenant):
    for action in ("stop", "start", "restart"):
        assert env.svc.service_action(tenant, "web", action, "backend", by="ana")["ok"]
    cmds = [c[2] for c in env.fake.calls if c[0] == "exec_run"]
    assert ["timeout", "-k", "2", "20", "/usr/local/bin/rt-service", "stop", "web"] in cmds
    ev = [e for e in env.store.list_events(tenant, 50) if e["action"].startswith("workspace.service.")]
    assert {e["action"] for e in ev} == {"workspace.service.stop", "workspace.service.start",
                                         "workspace.service.restart"}
    assert all(e["detail"]["by"] == "ana" for e in ev)
    for bad in ("../x", "A b", "x;rm -rf /", "", "9a"):
        with pytest.raises(ServiceError) as e:
            env.svc.service_action(tenant, bad, "stop", "backend")
        assert e.value.status == 400
    with pytest.raises(ServiceError):
        env.svc.service_action(tenant, "web", "rm", "backend")


def test_action_on_stopped_environment_does_not_wake(env, tenant):
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    with pytest.raises(ServiceError) as e:
        env.svc.service_action(tenant, "web", "start", "backend")
    assert e.value.status == 409
    assert not env.fake.containers["rt-ws-acme1"]["State"]["Running"]


def test_logs_redacted_and_capped(env, tenant):
    key = " ".join(["timeout", "-k", "2", "20", "/usr/local/bin/rt-service", "logs", "web", "200"])
    env.fake.exec_results = {key: {"exit_code": 0, "stderr": "",
                                   "stdout": "ok\nDB_PASSWORD=supersecret\n"
                                             "Authorization: Bearer abcdefghijkl1234\n"}}
    out = env.svc.service_logs(tenant, "web", "backend", 9999, by="ana")
    assert out["lines"] == 200
    assert "supersecret" not in out["log"] and "abcdefghijkl1234" not in out["log"]
    assert "ok" in out["log"]


def test_isolation_between_tenants(env, tenant):
    env.svc.create_tenant("other1", "backend")
    env.fake.exec_results = {CMD: {"exit_code": 0, "stdout": json.dumps(PAYLOAD), "stderr": ""}}
    env.svc.list_services(tenant, "backend")
    env.svc.list_services("other1", "backend")
    targets = [c[1] for c in env.fake.calls if c[0] == "exec_run"]
    assert targets == ["rt-ws-acme1", "rt-ws-other1"]


# ---- HTTP ---------------------------------------------------------------------------------------
def test_http_routes_and_cross_tenant_403(env, tenant):
    from fastapi.testclient import TestClient

    from rm.api import Ctx, create_app
    from tests.unit.test_api import Client
    env.fake.exec_results = {CMD: {"exit_code": 0, "stdout": json.dumps(PAYLOAD), "stderr": ""}}
    c = Client(TestClient(create_app(Ctx(env.settings, env.svc, env.pool()))), env)
    r = c.call("GET", f"/v1/tenants/{tenant}/services", svc="backend")
    assert r.status_code == 200 and r.json()["servicos"][0]["nome"] == "web"
    r = c.call("POST", f"/v1/tenants/{tenant}/services/web:stop", svc="backend", body={"by": "ana"})
    assert r.status_code == 200 and r.json()["action"] == "stop"
    r = c.call("GET", f"/v1/tenants/{tenant}/services/web/logs?lines=50", svc="backend")
    assert r.status_code == 200
    r = c.call("GET", f"/v1/tenants/{tenant}/services", svc="tenant-b")  # servico escopado a outro tenant
    assert r.status_code == 403


# ---- script da imagem -----------------------------------------------------------------------------
def test_script_runs_with_zero_services_and_valid_json(tmp_path):
    e = dict(os.environ, PATH=str(tmp_path), RT_SERVICES_DIR=str(tmp_path / "nada"),
             RT_PROC_ROOT=str(tmp_path / "semproc"))
    out = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, env=e, timeout=30)
    data = json.loads(out.stdout)
    assert data["servicos"] == [] and data["soltos"] == [] and data["schema"] == 2


def test_script_parsers():
    m = load_script()
    assert m.parse_svstat("up (pid 12) 30 seconds")["estado"] == "rodando"
    assert m.parse_svstat("up (pid 12) 30 seconds")["uptime_s"] == 30
    assert m.parse_svstat("down (exitcode 1) 1 seconds, want up")["estado"] == "reiniciando"
    assert m.parse_svstat("down (exitcode 0) 500 seconds, normally up")["estado"] == "parado"
    assert m.parse_svstat("")["estado"] == "parado"
    ports = m.parse_ss('LISTEN 0 128 0.0.0.0:8000 0.0.0.0:* users:(("python3",pid=40,fd=3))\n'
                       'LISTEN 0 128 [::]:22 [::]:*\n')
    assert ports == [(8000, [40]), (22, [])]


VECTORS = [
    ["python", "app.py", "--password", "hunter2"],
    ["run", "--api-key=zzz", "DB_PASS=abc", "postgres://u:pw@h/db"],
    ["curl", "-H", "Authorization: Bearer abcdefghijkl", "sk-abcdefghijklmnopqrstuv"],
]


def test_redaction_parity_between_script_and_manager_and_no_leak():
    m = load_script()
    for argv in VECTORS:
        a, b = m.redact_argv(argv), redact.redact_argv(argv)
        assert a == b
        joined = " ".join(a)
        for secret in ("hunter2", "zzz", "pw@", "abcdefghijkl", "sk-abcdefgh"):
            assert secret not in joined
    assert m.redact_text("token=abc123 x") == redact.redact_text("token=abc123 x")


def test_vocabulary_has_no_internal_names():
    blob = SCRIPT.read_text(encoding="utf-8").lower()
    for w in ("kernel", "hermes", "harness"):
        assert w not in blob


def test_old_workspace_without_script_gets_it_installed_then_lists(env, tenant):
    calls = {"n": 0}
    real = env.fake.exec_run

    def exec_run(name, cmd, **kw):
        if " ".join(cmd) == CMD:
            calls["n"] += 1
            if calls["n"] == 1:
                return {"exit_code": 127, "stdout": "", "stderr": "timeout: No such file"}
            return {"exit_code": 0, "stdout": json.dumps(PAYLOAD), "stderr": ""}
        return real(name, cmd, **kw)

    env.fake.exec_run = exec_run
    out = env.svc.list_services(tenant, "backend")
    assert out["servicos"][0]["nome"] == "web" and calls["n"] == 2


def test_bundled_script_is_identical_to_image_script():
    bundled = ROOT / "rm/assets/rt-services-json"
    assert bundled.read_bytes() == SCRIPT.read_bytes()


def test_svstat_real_format_with_pgid_is_running():
    mod = load_script()
    d = mod.parse_svstat("up (pid 371 pgid 371) 4219 seconds")
    assert d["estado"] == "rodando" and d["pid"] == 371 and d["uptime_s"] == 4219


def test_stale_schema_script_is_refreshed(env, tenant):
    old = dict(PAYLOAD, schema=1)
    seq = [json.dumps(old), json.dumps(PAYLOAD)]
    real = env.fake.exec_run

    def exec_run(name, cmd, **kw):
        if " ".join(cmd) == CMD:
            return {"exit_code": 0, "stdout": seq.pop(0), "stderr": ""}
        return real(name, cmd, **kw)

    env.fake.exec_run = exec_run
    out = env.svc.list_services(tenant, "backend")
    assert out["servicos"][0]["nome"] == "web" and not seq
