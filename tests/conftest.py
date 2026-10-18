"""Shared fixtures. Unit tests never touch a real Docker daemon: FakeDocker sits under the same
PolicyDockerClient used in production, so every create body is validated for real."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import pytest

from rm import traefik
from rm.backup import LocalBackupBackend
from rm.config import Settings
from rm.docker_client import PolicyDockerClient
from rm.fake_docker import FakeDocker
from rm.firewall import RecordingFirewall
from rm.policy import PolicyConfig
from rm.pool import PoolManager
from rm.quota import FakeQuota
from rm.service import NoopRevoker, TenantService
from rm.store import MemoryStore


def digest(tag: str) -> str:
    """A well-formed pinned image reference for tests."""
    return "rt/" + tag + "@sha256:" + hashlib.sha256(tag.encode()).hexdigest()


WS_IMAGE = digest("rt-workspace")
RT_IMAGE = digest("rt-hermes")
POOL_IMAGE = digest("rt-pool")
EXEC_IMAGE = digest("rt-executor")


def make_settings(tmp_path, **kw) -> Settings:
    s = Settings(
        tenants_root="/srv/tenants", hermes_root="/srv/hermes", manage_host_dirs=False,
        traefik_dir=str(tmp_path / "front"), edge_dir=str(tmp_path / "edge"),
        forensics_dir=str(tmp_path / "forensics"), backup_dir=str(tmp_path / "backups"),
        nft_ruleset_path=str(tmp_path / "rt.nft"), workspace_image=WS_IMAGE,
        runtime_image=RT_IMAGE, pool_image=POOL_IMAGE, executor_image=EXEC_IMAGE,
        executor_root="/srv/executor", apps_domain="apps.example.test",
        domain_secret="s3cret", service_keys={"backend": "k-backend", "tenant-a": "k-a",
                                              "tenant-b": "k-b", "ops": "k-ops"},
        admin_services={"backend", "ops"}, reconcile_enabled=False,
        edge_upstream_tpl="http://rt-ws-{tenant}:{port}", wake_url="http://rm:8080",
    )
    for k, v in kw.items():
        setattr(s, k, v)
    return s


@dataclass
class Env:
    settings: Settings
    fake: FakeDocker
    docker: PolicyDockerClient
    store: MemoryStore
    quota: FakeQuota
    fw: RecordingFirewall
    backup: LocalBackupBackend
    revoker: NoopRevoker
    svc: TenantService
    keys: dict[str, str] = field(default_factory=dict)
    txt: dict[str, list[str]] = field(default_factory=dict)
    cname: dict[str, list[str]] = field(default_factory=dict)
    now: list = field(default_factory=list)

    def pool(self) -> PoolManager:
        return PoolManager(self.settings, self.store, self.docker, self.fw,
                           refresh_firewall=self.svc.refresh_firewall, sleep=lambda s: None)


@pytest.fixture
def env(tmp_path) -> Env:
    s = make_settings(tmp_path)
    fake = FakeDocker()
    docker = PolicyDockerClient(fake, cfg=PolicyConfig(
        tenants_root=s.tenants_root, hermes_root=s.hermes_root, executor_root=s.executor_root))
    store = MemoryStore()
    quota, fw, revoker = FakeQuota(), RecordingFirewall(), NoopRevoker()
    backup = LocalBackupBackend(s.backup_dir)
    e = Env(s, fake, docker, store, quota, fw, backup, revoker, svc=None)  # type: ignore[arg-type]
    e.svc = TenantService(
        s, store, docker, quota, fw, backup, revoker=revoker,
        txt_resolver=lambda n: e.txt.get(n, []), cname_resolver=lambda n: e.cname.get(n, []),
        sleep=lambda x: None, key_sink=lambda t, k: e.keys.__setitem__(t, k))
    return e


@pytest.fixture
def tenant(env):
    """A running workspace-only tenant named acme1."""
    env.svc.create_tenant("acme1", "backend")
    return "acme1"


def route_files(path) -> list[str]:
    return sorted(p.name for p in traefik.Path(path).glob("*.yml")) if path.exists() else []
