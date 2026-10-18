"""Fixtures for the real-Docker tests. They run against whatever daemon `docker` talks to, through
the same docker-socket-proxy the VPS uses, with the real images built from this repository."""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from rm import naming
from rm.api import Ctx, create_app
from rm.backup import LocalBackupBackend
from rm.config import Settings
from rm.docker_client import HttpDockerClient, PolicyDockerClient
from rm.executor import ExecutorRunner
from rm.policy import PolicyConfig
from rm.pool import PoolManager
from rm.quota import FakeQuota
from rm.service import NoopRevoker, TenantService
from rm.store import MemoryStore
from tests.integration.harness import (
    IS_WIN,
    EdgeSyncWriter,
    LiveFirewall,
    docker,
    nft_delete,
    wait_healthy,
    wait_until,
)

ROOT = Path(__file__).resolve().parents[2]
PROXY_IMAGE = "tecnativa/docker-socket-proxy:0.3.0"
EDGE_NAME = "rt-edge-test"
APPS = "apps.test.local"


def pytest_collection_modifyitems(items):
    for it in items:
        if "tests/integration" in it.nodeid.replace("\\", "/"):
            it.add_marker(pytest.mark.docker)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def daemon_path(p: Path) -> str:
    """Path as the Docker daemon sees it (Docker Desktop mounts Windows drives under /run)."""
    if not IS_WIN:
        return str(p)
    drive, rest = os.path.splitdrive(str(p))
    return "/run/desktop/mnt/host/" + drive[0].lower() + rest.replace("\\", "/")


@dataclass
class Stack:
    run: str
    ws_ref: str
    edge_ref: str
    exec_ref: str
    stub_ref: str
    tools: str
    proxy_url: str
    edge_port: int
    edge_dir: Path
    keys: dict = field(default_factory=dict)


def _build(tag: str, context: Path, dockerfile: Path | None = None) -> str:
    args = ["build", "-q", "-t", tag]
    if dockerfile:
        args += ["-f", str(dockerfile)]
    docker(*args, str(context), timeout=900)
    return "sha256:" + docker("image", "inspect", "-f", "{{.Id}}", tag).stdout.strip().split(":")[-1]


def _sweep() -> None:
    """Remove leftovers of an earlier aborted run (only names this suite creates)."""
    out = docker("ps", "-a", "--format", "{{.Names}}", check=False).stdout.split()
    for n in out:
        if n.startswith(("rt-ws-qa", "rt-hermes-qa", "rt-exec-", "rt-test-proxy-")) or n == EDGE_NAME:
            docker("rm", "-f", n, check=False)
    nets = docker("network", "ls", "--format", "{{.Name}}", check=False).stdout.split()
    for n in nets:
        if n.startswith(("rt-net-qa", "rt-ws-qa")) or n in (naming.SSH_HUB_NET, naming.POOL_NET):
            docker("network", "rm", n, check=False)


@pytest.fixture(scope="session")
def stack(tmp_path_factory):
    if not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True
                                                    ).returncode != 0:
        pytest.skip("no Docker daemon")
    _sweep()
    run = uuid.uuid4().hex[:6]
    img = ROOT / "images"
    ws = _build("rt-workspace:test", img / "rt-workspace")
    edge = _build("rt-edge:test", img / "rt-edge")
    exe = _build("rt-executor:test", img / "rt-executor")
    tools = "rt-test-tools:latest"
    _build(tools, ROOT / "tests" / "integration" / "images",
           ROOT / "tests" / "integration" / "images" / "tools.Dockerfile")
    stub = _build("rt-stub-runtime:test", ROOT / "tests" / "integration" / "images",
                  ROOT / "tests" / "integration" / "images" / "stub-runtime.Dockerfile")

    # the socket proxy, with the verbs the annex allows and nothing else
    pport = free_port()
    pname = f"rt-test-proxy-{run}"
    docker("run", "-d", "--rm", "--name", pname, "-p", f"127.0.0.1:{pport}:2375",
           "-v", "/var/run/docker.sock:/var/run/docker.sock",
           "-e", "CONTAINERS=1", "-e", "NETWORKS=1", "-e", "VOLUMES=1", "-e", "IMAGES=1",
           "-e", "POST=1", "-e", "EXEC=0", "-e", "SERVICES=0", "-e", "SWARM=0", "-e", "SECRETS=0",
           "-e", "BUILD=0", "-e", "COMMIT=0", "-e", "PLUGINS=0", "-e", "SYSTEM=0", "-e", "AUTH=0",
           PROXY_IMAGE)
    wait_until(lambda: HttpDockerClient(f"http://127.0.0.1:{pport}").ping(), 30, 0.5, "proxy")

    # rt-edge, labelled so the RM may attach it to tenant networks
    edge_dir = tmp_path_factory.mktemp("edge")
    eport = free_port()
    docker("rm", "-f", EDGE_NAME, check=False)
    args = ["run", "-d", "--name", EDGE_NAME, "--label", "rt.managed=true", "--label",
            "rt.role=edge", "-p", f"127.0.0.1:{eport}:8080", "--add-host",
            "host.docker.internal:host-gateway"]
    if not IS_WIN:
        args += ["-v", f"{edge_dir}:/etc/traefik/dynamic"]
    docker(*args, edge)
    wait_healthy(EDGE_NAME, 60)

    st = Stack(run, ws, edge, exe, stub, tools, f"http://127.0.0.1:{pport}", eport, edge_dir)
    yield st

    nft_delete(tools)
    docker("rm", "-f", EDGE_NAME, pname, check=False)
    for n in (naming.SSH_HUB_NET, naming.POOL_NET):
        docker("network", "rm", n, check=False)
    docker("run", "--rm", "-v", "/srv:/s", tools, "rm", "-rf", f"/s/rt-qa-{run}", check=False)


class Rm:
    """A TenantService wired to the real daemon, plus bookkeeping and cleanup."""

    def __init__(self, stack: Stack, tmp_path: Path):
        self.stack = stack
        self.tmp = tmp_path
        self.created: list[str] = []
        self.txt: dict[str, list[str]] = {}
        self.cname: dict[str, list[str]] = {}
        self.keys: dict[str, str] = {}
        self.http_port = free_port()
        s = Settings(
            tenants_root=f"/srv/rt-qa-{stack.run}/tenants", hermes_root=f"/srv/rt-qa-{stack.run}/h",
            executor_root=daemon_path(tmp_path / "executor"),
            executor_local_root=str(tmp_path / "executor"), manage_host_dirs=False,
            traefik_dir=str(tmp_path / "front"), edge_dir=str(stack.edge_dir),
            edge_container=EDGE_NAME, backup_dir=str(tmp_path / "backups"),
            forensics_dir=str(tmp_path / "forensics"),
            nft_ruleset_path=str(tmp_path / "rt.nft"), workspace_image=stack.ws_ref,
            runtime_image=stack.stub_ref, executor_image=stack.exec_ref, apps_domain=APPS,
            domain_secret="itest", service_keys={"backend": "k"}, admin_services={"backend"},
            reconcile_enabled=False, pool_command=["python3", "/stub.py"], pool_user="10001",
            pool_health_cmd="true", wake_url=f"http://host.docker.internal:{self.http_port}",
            workspace_dns=["1.1.1.1", "9.9.9.9"])
        self.settings = s
        inner = HttpDockerClient(stack.proxy_url)
        self.docker = PolicyDockerClient(inner, cfg=PolicyConfig(
            tenants_root=s.tenants_root, hermes_root=s.hermes_root, executor_root=s.executor_root))
        self.store = MemoryStore()
        self.fw = LiveFirewall(s.nft_ruleset_path, stack.tools)
        self.svc = TenantService(
            s, self.store, self.docker, FakeQuota(), self.fw, LocalBackupBackend(s.backup_dir),
            revoker=NoopRevoker(), txt_resolver=lambda n: self.txt.get(n, []),
            cname_resolver=lambda n: self.cname.get(n, []),
            key_sink=lambda t, k: self.keys.__setitem__(t, k))
        self.svc.edge_routes = EdgeSyncWriter(self.svc.edge_routes, EDGE_NAME,
                                              "/etc/traefik/dynamic", push=IS_WIN)
        # the pool worker stand-in (10.199.0.2) is what may reach port 22 of a workspace
        self.store.worker_upsert("w1", slot=1, status="ready")
        self.pool = PoolManager(s, self.store, self.docker, self.fw,
                                refresh_firewall=self.svc.refresh_firewall)
        self.executor = ExecutorRunner(s, self.docker)
        self._server = None

    def tenant(self, t: str, **kw) -> dict:
        t = f"{t}{self.stack.run}"[:20]
        v = self.svc.create_tenant(t, "backend", **kw)
        self.created.append(t)
        assert not v["last_error"], f"provisioning failed: {v['last_error']}"
        return v

    def name(self, t: str) -> str:
        return f"{t}{self.stack.run}"[:20]

    def ws_ready(self, t: str) -> None:
        # same probe as the image HEALTHCHECK, polled faster than its 15 s interval
        c = naming.workspace_name(t)
        wait_until(lambda: docker("exec", c, "python3", "/usr/local/bin/rt-healthcheck",
                                  check=False).returncode == 0, 120, 1, f"{c} ready")

    def hub_ip(self, t: str) -> str:
        return naming.hub_workspace_ip(self.store.get_tenant(t)["net_index"])

    def serve_http(self) -> None:
        import uvicorn
        app = create_app(Ctx(self.settings, self.svc, self.pool, None, self.executor))
        cfg = uvicorn.Config(app, host="127.0.0.1", port=self.http_port, log_level="warning")
        self._server = uvicorn.Server(cfg)
        threading.Thread(target=self._server.run, daemon=True).start()
        wait_until(lambda: self._server.started, 15, 0.1, "rm http")

    def close(self) -> None:
        if self._server:
            self._server.should_exit = True
        for t in self.created:
            try:
                self.svc.retire(t, "test")
                self.svc.purge(t, "test", t, True, override=True)
            except Exception:
                for n in (naming.workspace_name(t), naming.runtime_name(t)):
                    docker("rm", "-f", n, check=False)
        time.sleep(0.2)


@pytest.fixture
def rm(stack, tmp_path):
    r = Rm(stack, tmp_path)
    yield r
    r.close()
