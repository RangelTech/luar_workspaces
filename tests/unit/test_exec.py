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


def test_local_image_tags_are_pinned_to_content_id_at_boot(tmp_path):
    from rm.fake_docker import FakeDocker
    from rm.main import _pin_local_images
    from tests.conftest import make_settings

    s = make_settings(tmp_path, workspace_image="rt/workspace:abc", executor_image="rt/executor:def")
    fake = FakeDocker()
    fake.images = {"rt/workspace:abc": {"Id": "sha256:" + "a" * 64}}
    _pin_local_images(s, fake)
    assert s.workspace_image == "sha256:" + "a" * 64
    assert s.executor_image == "rt/executor:def"  # sem imagem local: nada muda


def test_put_then_get_workspace_file_roundtrip_and_path_rules(env, tenant):
    import io
    import tarfile

    out = env.svc.put_workspace_file(tenant, "/workspace/inbox/planilha.xlsx", b"BYTES", "kernel-harness")
    assert out == {"path": "/workspace/inbox/planilha.xlsx", "size": 5}
    raw = env.fake.archives[("rt-ws-acme1", "/workspace/inbox")]
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        assert [m.name for m in tf.getmembers()] == ["planilha.xlsx"]
    # leitura devolve o arquivo do tar guardado pelo docker falso
    env.fake.archives[("rt-ws-acme1", "/workspace/out/r.txt")] = raw
    got = env.svc.get_workspace_file(tenant, "/workspace/out/r.txt", "kernel-harness")
    assert got["content"] == b"BYTES"
    for bad in ("/etc/passwd", "/workspace/../etc/passwd", "relativo.txt"):
        with pytest.raises(ServiceError) as e:
            env.svc.put_workspace_file(tenant, bad, b"x", "kernel-harness")
        assert e.value.code == "bad_path"
    with pytest.raises(ServiceError) as e:
        env.svc.get_workspace_file(tenant, "/workspace/nao-existe", "kernel-harness")
    assert e.value.code == "file_not_found"
