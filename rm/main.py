"""Process wiring: environment -> Settings -> backends -> FastAPI app.

`uvicorn rm.main:create --factory` is the production entry point. Dev and tests build the same
graph with fakes through `build_ctx`.
"""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI

from .abuse import AbuseMonitor
from .api import Ctx, create_app
from .backup import BackupBackend, LocalBackupBackend
from .config import Settings
from .docker_client import DockerClient, HttpDockerClient, PolicyDockerClient
from .domains import dns_resolvers
from .executor import ExecutorRunner
from .firewall import Firewall, NullFirewall, RulesetFileFirewall
from .policy import PolicyConfig
from .pool import PoolManager
from .quota import FakeQuota, QuotaBackend, XfsQuota
from .service import TenantService
from .store import MemoryStore, PostgresStore
from .usage import UsageSampler


def build_ctx(settings: Settings, *, docker: DockerClient | None = None,
              store: MemoryStore | PostgresStore | None = None,
              quota: QuotaBackend | None = None, firewall: Firewall | None = None,
              backup: BackupBackend | None = None, resolvers: tuple | None = None) -> Ctx:
    if store is None:
        store = PostgresStore(settings.database_url) if settings.database_url else MemoryStore()
    store.migrate()
    if docker is None:
        docker = HttpDockerClient(settings.docker_host, settings.docker_api_version)
    docker = PolicyDockerClient(docker, cfg=PolicyConfig(
        tenants_root=settings.tenants_root, hermes_root=settings.hermes_root,
        executor_root=settings.executor_root,
        allowed_image_prefixes=settings.allowed_image_prefixes))
    if quota is None:
        if settings.quota_backend == "xfs":
            quota = XfsQuota(settings.tenants_root,
                             index_of=lambda t: (store.get_tenant(t) or {}).get("net_index", 0))
        else:
            quota = FakeQuota()
    if firewall is None:
        firewall = (RulesetFileFirewall(settings.nft_ruleset_path)
                    if settings.firewall_backend == "file" else NullFirewall())
    if backup is None:
        backup = LocalBackupBackend(settings.backup_dir)
    txt, cname = resolvers or dns_resolvers()
    svc = TenantService(settings, store, docker, quota, firewall, backup,
                        txt_resolver=txt, cname_resolver=cname)
    pool = PoolManager(settings, store, docker, firewall, refresh_firewall=svc.refresh_firewall)
    return Ctx(settings, svc, pool, UsageSampler(docker, store, quota),
               ExecutorRunner(settings, docker), AbuseMonitor(settings, docker, svc))


def create() -> FastAPI:
    logging.basicConfig(level=os.environ.get("RM_LOG_LEVEL", "INFO"))
    return create_app(build_ctx(Settings.from_env()))
