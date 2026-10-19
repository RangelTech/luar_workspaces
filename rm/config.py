"""Configuration, read from the environment (names listed in release manifest env.required)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

TENANT_RE = r"^[a-z][a-z0-9]{3,19}$"


def _bool(v: str | None, default: bool) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _parse_keys(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, secret = part.partition(":")
        if name and secret:
            out[name] = secret
    return out


@dataclass
class Settings:
    database_url: str = ""
    docker_host: str = "http://docker-socket-proxy:2375"
    docker_api_version: str = "v1.43"
    service_keys: dict[str, str] = field(default_factory=dict)
    admin_services: set[str] = field(default_factory=set)
    metrics_token: str = ""
    iat_window_s: int = 30
    tenants_root: str = "/srv/tenants"
    hermes_root: str = "/srv/hermes"
    manage_host_dirs: bool = True
    traefik_dir: str = "/etc/traefik/dynamic/tenants"  # platform Traefik (TLS) file provider
    edge_dir: str = "/etc/rt-edge/dynamic"  # rt-edge file provider (strict Host -> workspace)
    edge_front_url: str = "http://rt-edge:8080"  # what the platform Traefik forwards to
    edge_container: str = "rt-edge"  # attached to every workspace egress network
    nft_ruleset_path: str = "/var/lib/rt/nft/rt.nft"
    forensics_dir: str = "/var/lib/rt/forensics"
    backup_dir: str = "/var/lib/rt/backups"
    apps_domain: str = "apps.rangeltech.net"
    edge_upstream_tpl: str = "http://rt-ws-{tenant}:{port}"
    wake_url: str = "http://runtime-manager:8080"
    domain_secret: str = ""
    reconcile_interval_s: int = 15
    reconcile_enabled: bool = True
    usage_interval_s: int = 60
    max_parallel_provisioning: int = 4
    # executor (ephemeral, no network)
    executor_image: str = ""
    executor_root: str = "/srv/executor"  # path as the Docker daemon sees it (bind sources)
    executor_local_root: str = ""  # path this process writes to; empty = same as executor_root
    executor_max_parallel: int = 4
    # abuse monitor
    abuse_cpu_threshold: float = 0.9
    # O cpu.max ja limita o impacto; instalar/compilar (Metabase, Airflow) passa de 15 min a 100 % legitimamente.
    # Mineradores sao pegos pela assinatura do processo; so um uso colado no limite por 6 h vira suspensao.
    abuse_cpu_window_s: int = 21600
    # pool
    pool_size: int = 0
    pool_image: str = ""
    pool_recycle_after_runs: int = 20
    pool_command: list[str] = field(default_factory=lambda: ["gateway", "run"])
    pool_port: int = 8642
    pool_health_cmd: str = (
        "python3 -c \"import urllib.request,sys;"
        "sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8642/health',timeout=2)"
        ".status==200 else 1)\""
    )
    pool_user: str = ""
    pool_caps: list[str] = field(
        default_factory=lambda: ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "KILL"])
    pool_read_only: bool = True
    pool_env: dict[str, str] = field(default_factory=dict)
    pool_mem_mb: int = 1536
    pool_cpus: float = 2.0
    workspace_image: str = ""
    runtime_image: str = ""
    allowed_image_prefixes: list[str] = field(default_factory=list)
    quota_backend: str = "fake"  # fake | xfs
    firewall_backend: str = "file"  # file | null
    allow_wake: bool = True
    # resolvers handed to workspaces; the same addresses are allowed on port 53 by the firewall
    workspace_dns: list[str] = field(default_factory=lambda: ["1.1.1.1", "9.9.9.9"])

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = dict(os.environ if env is None else env)
        s = cls()
        s.database_url = e.get("RM_DATABASE_URL", "")
        s.docker_host = e.get("RM_DOCKER_HOST", s.docker_host)
        s.docker_api_version = e.get("RM_DOCKER_API_VERSION", s.docker_api_version)
        s.service_keys = _parse_keys(e.get("RM_SERVICE_KEYS", ""))
        s.admin_services = {x for x in e.get("RM_ADMIN_SERVICES", "").split(",") if x}
        s.metrics_token = e.get("RM_METRICS_TOKEN", "")
        s.iat_window_s = int(e.get("RM_IAT_WINDOW_S", s.iat_window_s))
        s.tenants_root = e.get("RM_TENANTS_ROOT", s.tenants_root)
        s.hermes_root = e.get("RM_HERMES_ROOT", s.hermes_root)
        s.manage_host_dirs = _bool(e.get("RM_MANAGE_HOST_DIRS"), True)
        s.traefik_dir = e.get("RM_TRAEFIK_DIR", s.traefik_dir)
        s.edge_dir = e.get("RM_EDGE_DIR", s.edge_dir)
        s.edge_front_url = e.get("RM_EDGE_FRONT_URL", s.edge_front_url)
        s.edge_container = e.get("RM_EDGE_CONTAINER", s.edge_container)
        s.executor_image = e.get("RM_EXECUTOR_IMAGE", "")
        s.executor_root = e.get("RM_EXECUTOR_ROOT", s.executor_root)
        s.executor_local_root = e.get("RM_EXECUTOR_LOCAL_ROOT", "")
        s.executor_max_parallel = int(e.get("RM_EXECUTOR_MAX_PARALLEL", s.executor_max_parallel))
        s.abuse_cpu_threshold = float(e.get("RM_ABUSE_CPU_THRESHOLD", s.abuse_cpu_threshold))
        s.abuse_cpu_window_s = int(e.get("RM_ABUSE_CPU_WINDOW_S", s.abuse_cpu_window_s))
        s.nft_ruleset_path = e.get("RM_NFT_RULESET_PATH", s.nft_ruleset_path)
        s.forensics_dir = e.get("RM_FORENSICS_DIR", s.forensics_dir)
        s.backup_dir = e.get("RM_BACKUP_DIR", s.backup_dir)
        s.apps_domain = e.get("RM_APPS_DOMAIN", s.apps_domain)
        s.edge_upstream_tpl = e.get("RM_EDGE_UPSTREAM_TPL", s.edge_upstream_tpl)
        s.wake_url = e.get("RM_WAKE_URL", s.wake_url)
        s.domain_secret = e.get("RM_DOMAIN_SECRET", "")
        s.reconcile_interval_s = int(e.get("RM_RECONCILE_INTERVAL_S", s.reconcile_interval_s))
        s.reconcile_enabled = _bool(e.get("RM_RECONCILE_ENABLED"), True)
        s.usage_interval_s = int(e.get("RM_USAGE_INTERVAL_S", s.usage_interval_s))
        s.pool_size = int(e.get("RM_POOL_SIZE", 0))
        s.pool_image = e.get("RM_POOL_IMAGE", "")
        s.pool_recycle_after_runs = int(e.get("RM_POOL_RECYCLE_AFTER_RUNS", 20))
        if e.get("RM_POOL_COMMAND"):
            s.pool_command = e["RM_POOL_COMMAND"].split()
        s.pool_port = int(e.get("RM_POOL_PORT", s.pool_port))
        s.pool_health_cmd = e.get("RM_POOL_HEALTH_CMD", s.pool_health_cmd)
        s.pool_user = e.get("RM_POOL_USER", "")
        if e.get("RM_POOL_CAPS") is not None:
            s.pool_caps = [x for x in e["RM_POOL_CAPS"].split(",") if x]
        s.pool_read_only = _bool(e.get("RM_POOL_READ_ONLY"), True)
        s.pool_mem_mb = int(e.get("RM_POOL_MEM_MB", s.pool_mem_mb))
        s.pool_cpus = float(e.get("RM_POOL_CPUS", s.pool_cpus))
        s.pool_env = {
            k[len("RM_POOL_ENV_"):]: v for k, v in e.items() if k.startswith("RM_POOL_ENV_")
        }
        s.workspace_image = e.get("RM_WORKSPACE_IMAGE", "")
        s.runtime_image = e.get("RM_RUNTIME_IMAGE", "")
        s.allowed_image_prefixes = [x for x in e.get("RM_ALLOWED_IMAGES", "").split(",") if x]
        if e.get("RM_WORKSPACE_DNS") is not None:
            s.workspace_dns = [x for x in e["RM_WORKSPACE_DNS"].split(",") if x]
        s.quota_backend = e.get("RM_QUOTA_BACKEND", s.quota_backend)
        s.firewall_backend = e.get("RM_FIREWALL_BACKEND", s.firewall_backend)
        return s
