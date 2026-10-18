"""Fixed templates: the only place that builds Docker create bodies (annex 04 section 1.7).

No field coming from a tenant reaches these dictionaries except validated scalars (tenant id,
plan, digest, port numbers). The result is validated again by rm/policy.py before the daemon.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from . import naming
from .config import Settings

MiB = 1024 * 1024
GiB = 1024 * MiB

PLANS: dict[str, dict] = {
    "small": {"ws_mem": 512 * MiB, "quota_gb": 5},
    "standard": {"ws_mem": 1 * GiB, "quota_gb": 10},
    "plus": {"ws_mem": 2 * GiB, "quota_gb": 10},
    "pro": {"ws_mem": 4 * GiB, "quota_gb": 20},
}
DEFAULT_PLAN = "standard"


@dataclass
class Limits:
    mem: int
    cpus: float
    pids: int
    tmpfs_mb: int = 256
    cpu_shares: int = 512
    nofile: int = 4096
    io_read_bps: int = 0
    io_write_bps: int = 0
    io_device: str = ""


def runtime_limits() -> Limits:
    return Limits(mem=1 * GiB, cpus=1.0, pids=256, cpu_shares=512,
                  io_read_bps=50 * MiB, io_write_bps=50 * MiB)


def workspace_limits(plan: str, override: dict | None = None) -> Limits:
    p = PLANS.get(plan, PLANS[DEFAULT_PLAN])
    lim = Limits(mem=p["ws_mem"], cpus=1.0, pids=512, cpu_shares=256,
                 io_read_bps=30 * MiB, io_write_bps=30 * MiB)
    for k, v in (override or {}).items():
        if k in ("mem", "cpus", "pids", "tmpfs_mb", "cpu_shares", "nofile"):
            setattr(lim, k, v)
    return lim


def _host_limits(lim: Limits, io_device: str = "") -> dict:
    hc: dict = {
        "Memory": lim.mem,
        "MemorySwap": lim.mem,  # no swap
        "MemoryReservation": int(lim.mem * 0.8),  # soft limit, memory.high analogue
        "NanoCpus": int(lim.cpus * 1_000_000_000),
        "CpuShares": lim.cpu_shares,
        "PidsLimit": lim.pids,
        "Ulimits": [{"Name": "nofile", "Soft": lim.nofile, "Hard": lim.nofile}],
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}},
    }
    if io_device and lim.io_read_bps:
        hc["BlkioDeviceReadBps"] = [{"Path": io_device, "Rate": lim.io_read_bps}]
        hc["BlkioDeviceWriteBps"] = [{"Path": io_device, "Rate": lim.io_write_bps}]
    return hc


def _healthcheck(cmd: str, interval_s: int = 15) -> dict:
    return {"Test": ["CMD-SHELL", cmd], "Interval": interval_s * 1_000_000_000,
            "Timeout": 5 * 1_000_000_000, "Retries": 3, "StartPeriod": 20 * 1_000_000_000}


def derive_key(secret: str, purpose: str) -> str:
    return hmac.new(secret.encode(), purpose.encode(), hashlib.sha256).hexdigest()


def worker_spec(s: Settings, worker_id: str, image: str, generation: int,
                io_device: str = "") -> dict:
    name = naming.worker_name(worker_id)
    lim = Limits(mem=s.pool_mem_mb * MiB, cpus=s.pool_cpus, pids=256, cpu_shares=1024)
    env = {
        "HERMES_HOME": "/opt/data",
        "API_SERVER_ENABLED": "true",
        "API_SERVER_HOST": "0.0.0.0",
        "API_SERVER_PORT": str(s.pool_port),
        "API_SERVER_KEY": derive_key(s.domain_secret or "dev", f"api:{name}"),
        **s.pool_env,
    }
    hc = {
        **_host_limits(lim, io_device),
        "NetworkMode": naming.POOL_NET,
        "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
        "CapDrop": ["ALL"],
        "CapAdd": list(s.pool_caps),
        "SecurityOpt": ["no-new-privileges"],
        "ReadonlyRootfs": s.pool_read_only,
        "Tmpfs": {"/tmp": f"rw,noexec,nosuid,size={lim.tmpfs_mb}m"},
        "Binds": [f"{s.hermes_root}/workers/{worker_id}:/opt/data",
                  f"{s.hermes_root}/profiles:{s.hermes_root}/profiles",
                  f"{s.hermes_root}/ssh:/opt/ssh:ro"],
        "Privileged": False,
    }
    body = {
        "Image": image,
        "Cmd": list(s.pool_command),
        "Env": [f"{k}={v}" for k, v in env.items()],
        "Labels": naming.labels(naming.ROLE_WORKER, None, generation, naming.image_digest(image),
                                {naming.LABEL_POOL: "default", "rt.worker": worker_id}),
        "Healthcheck": _healthcheck(s.pool_health_cmd),
        "HostConfig": hc,
        "StopTimeout": 20,
        "NetworkingConfig": {"EndpointsConfig": {naming.POOL_NET: {"Aliases": [name]}}},
    }
    if s.pool_user:
        body["User"] = s.pool_user
    return body


def runtime_spec(s: Settings, tenant: str, image: str, generation: int, api_key: str,
                 io_device: str = "") -> dict:
    name = naming.runtime_name(tenant)
    lim = runtime_limits()
    env = {"HERMES_HOME": "/opt/data", "API_SERVER_ENABLED": "true", "API_SERVER_HOST": "0.0.0.0",
           "API_SERVER_PORT": str(s.pool_port), "API_SERVER_KEY": api_key, **s.pool_env}
    return {
        "Image": image,
        "Cmd": list(s.pool_command),
        "Env": [f"{k}={v}" for k, v in env.items()],
        "Labels": naming.labels(naming.ROLE_RUNTIME, tenant, generation,
                                naming.image_digest(image)),
        "Healthcheck": _healthcheck(s.pool_health_cmd),
        "StopTimeout": 20,
        "HostConfig": {
            **_host_limits(lim, io_device),
            "NetworkMode": naming.tenant_net(tenant),
            "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
            "CapDrop": ["ALL"], "CapAdd": list(s.pool_caps),
            "SecurityOpt": ["no-new-privileges"],
            "ReadonlyRootfs": s.pool_read_only,
            "Tmpfs": {"/tmp": f"rw,noexec,nosuid,size={lim.tmpfs_mb}m"},
            "Binds": [f"{s.tenants_root.rstrip('/')}/{tenant}/hermes:/opt/data",
                      f"{s.tenants_root.rstrip('/')}/{tenant}/keys:/opt/keys:ro"],
            "Privileged": False,
        },
        "NetworkingConfig": {"EndpointsConfig": {naming.tenant_net(tenant): {"Aliases": [name]}}},
    }


WS_CAPS = ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "KILL", "SYS_CHROOT",
           "AUDIT_WRITE", "NET_BIND_SERVICE"]
WS_BINDS = [("home", "/home/ws"), ("workspace", "/workspace"), ("opt", "/opt"),
            ("rt", "/var/lib/rt")]


def workspace_spec(s: Settings, tenant: str, image: str, generation: int, authorized_key: str,
                   plan: str, listen_cidrs: list[str], limits_override: dict | None = None,
                   io_device: str = "") -> dict:
    name = naming.workspace_name(tenant)
    lim = workspace_limits(plan, limits_override)
    base = f"{s.tenants_root.rstrip('/')}/{tenant}/ws"
    return {
        "Image": image,
        "Hostname": "ws",
        "Env": [f"RT_AUTHORIZED_KEYS={authorized_key}", f"SSH_LISTEN_CIDRS={','.join(listen_cidrs)}",
                f"RT_TENANT={tenant}"],
        "Labels": naming.labels(naming.ROLE_WORKSPACE, tenant, generation,
                                naming.image_digest(image)),
        "Healthcheck": _healthcheck("python3 /usr/local/bin/rt-healthcheck"),
        "StopTimeout": 30,
        "HostConfig": {
            **_host_limits(lim, io_device),
            "NetworkMode": naming.egress_net(tenant),
            "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
            "CapDrop": ["ALL"], "CapAdd": list(WS_CAPS),
            "SecurityOpt": ["no-new-privileges"],
            "OomScoreAdj": 500,
            "Dns": list(s.workspace_dns),
            "Binds": [f"{base}/{sub}:{dst}" for sub, dst in WS_BINDS],
            "Privileged": False,
        },
        "NetworkingConfig": {"EndpointsConfig": {naming.egress_net(tenant): {"Aliases": [name]}}},
    }


# ----- networks -------------------------------------------------------------------------
def _net(name: str, subnet: str, internal: bool, role: str, tenant: str | None,
         icc: bool = True) -> dict:
    return {
        "Name": name, "Driver": "bridge", "Internal": internal,
        "IPAM": {"Driver": "default", "Config": [{"Subnet": subnet}]},
        "Options": {"com.docker.network.bridge.enable_icc": "true" if icc else "false"},
        "Labels": naming.labels(naming.ROLE_NET, tenant, None, None, {naming.LABEL_ROLE: role}),
    }


def tenant_network(tenant: str, index: int) -> dict:
    return _net(naming.tenant_net(tenant), str(naming.tenant_subnet(index)), True,
                naming.ROLE_NET, tenant)


def egress_network(tenant: str, index: int) -> dict:
    # icc stays on: the network holds only this tenant's workspace and rt-edge (fixed .14);
    # cross-tenant traffic never shares a bridge and is dropped by the nft ruleset.
    return _net(naming.egress_net(tenant), str(naming.egress_subnet(index)), False,
                naming.ROLE_NET, tenant, icc=True)


def pool_network() -> dict:
    return _net(naming.POOL_NET, str(naming.POOL_NET_CIDR), True, naming.ROLE_HUB, None)


def ssh_hub_network() -> dict:
    return _net(naming.SSH_HUB_NET, str(naming.SSH_HUB_CIDR), True, naming.ROLE_HUB, None)
