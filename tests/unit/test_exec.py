"""Exec de comando no workspace do tenant (terminal do agente mediado pelo RM)."""
from __future__ import annotations

import pytest

from rm.docker_client import HttpDockerClient, _demux
from rm.service import ServiceError


def frame(kind: int, data: bytes) -> bytes:
    return bytes([kind, 0, 0, 0]) + len(data).to_bytes(4, "big") + data


def test_demux_splits_stdout_and_stderr():
    raw = frame(1, b"hello ") + frame(2, b"oops") + frame(1, b"world")
    assert _demux(raw) == ("hello world", "oops")
    assert _demux(b"") == ("", "")


def test_exec_runs_in_running_workspace_and_audits(env, tenant):
    env.fake.exec_results = {
        "timeout -k 5 60 bash -lc echo oi": {"exit_code": 0, "stdout": "oi\n", "stderr": ""}}
    out = env.svc.exec_workspace(tenant, "echo oi", "kernel-harness")
    assert out == {"exit_code": 0, "stdout": "oi\n", "stderr": ""}
    assert env.fake.verbs("exec_run")


def test_exec_needs_command_and_running_workspace(env, tenant):
    with pytest.raises(ServiceError) as e:
        env.svc.exec_workspace(tenant, "  ", "kernel-harness")
    assert e.value.code == "command_required"
    env.svc.set_component(tenant, "workspace", "stop", "backend")
    with pytest.raises(ServiceError) as e:
        env.svc.exec_workspace(tenant, "ls", "kernel-harness")
    assert e.value.code == "workspace_not_running"


def test_exec_refused_for_suspended_tenant(env, tenant):
    env.svc.suspend(tenant, "ops", "abuse", "high")
    with pytest.raises(ServiceError) as e:
        env.svc.exec_workspace(tenant, "ls", "kernel-harness")
    assert e.value.code == "tenant_suspended"


def test_http_client_exec_roundtrip():
    import httpx

    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path))
        if req.url.path.endswith("/containers/ws/exec"):
            return httpx.Response(201, json={"Id": "e1"})
        if req.url.path.endswith("/exec/e1/start"):
            return httpx.Response(200, content=frame(1, b"out") + frame(2, b"err"))
        if req.url.path.endswith("/exec/e1/json"):
            return httpx.Response(200, json={"ExitCode": 3})
        return httpx.Response(404, json={"message": "x"})

    cli = HttpDockerClient("http://docker", transport=httpx.MockTransport(handler))
    res = cli.exec_run("ws", ["bash", "-lc", "x"], workdir="/workspace")
    assert res == {"exit_code": 3, "stdout": "out", "stderr": "err"}
    assert [m for m, _ in calls] == ["POST", "POST", "GET"]


def test_exec_passes_only_valid_env_names(env, tenant):
    env.svc.exec_workspace(tenant, "python x.py", "kernel-harness",
                           env={"MERCADO_PAGO_TOKEN": "tok", "bad-name": "x", "OK": 5})
    rec = [r for r in env.fake.calls if r[0] == "exec_run"][-1]
    assert rec[-1] == {"MERCADO_PAGO_TOKEN": "tok"}
