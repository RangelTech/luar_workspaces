"""Names, labels and address plan (annex 04 section 1.5). Pure functions."""
from __future__ import annotations

import ipaddress
import re

from .config import TENANT_RE

TENANT_PATTERN = re.compile(TENANT_RE)
APP_PATTERN = re.compile(r"^[a-z][a-z0-9]{1,19}$")

LABEL_MANAGED = "rt.managed"
LABEL_TENANT = "rt.tenant"
LABEL_ROLE = "rt.role"
LABEL_GENERATION = "rt.generation"
LABEL_DIGEST = "rt.image.digest"
LABEL_POOL = "rt.pool"

ROLE_RUNTIME = "runtime"
ROLE_WORKSPACE = "workspace"
ROLE_NET = "net"
ROLE_WORKER = "worker"
ROLE_HUB = "hub"
ROLE_EXECUTOR = "executor"
ROLE_EDGE = "edge"
ROLE_VOLUME = "volume"

POOL_NET = "rt-pool"
SSH_HUB_NET = "rt-ssh"

# Address plan. All inside 10.0.0.0/8, which is blocked for workspaces by the egress rules.
TENANT_POOL = ipaddress.ip_network("10.208.0.0/12")  # rt-net-<t>, /28 slices (internal)
EGRESS_POOL = ipaddress.ip_network("10.224.0.0/12")  # rt-ws-<t>, /28 slices (internet egress)
POOL_NET_CIDR = ipaddress.ip_network("10.198.0.0/24")  # rt-pool (workers)
SSH_HUB_CIDR = ipaddress.ip_network("10.199.0.0/22")  # rt-ssh hub
WORKER_RANGE = ipaddress.ip_network("10.199.0.0/28")  # worker addresses inside the hub
WS_RANGE_START = 16  # workspace addresses inside the hub start at .16
HUB_WS_FIRST = ipaddress.ip_address("10.199.0.16")  # first workspace address in the hub
HUB_WS_LAST = ipaddress.ip_address("10.199.3.253")  # last one (hub_workspace_ip bound)
MAX_TENANT_INDEX = 1000  # bounded by the ssh hub (/22 minus the worker range)


def valid_tenant(t: str) -> bool:
    return bool(TENANT_PATTERN.match(t or ""))


def tenant_net(t: str) -> str:
    return f"rt-net-{t}"


def egress_net(t: str) -> str:
    return f"rt-ws-{t}"


def runtime_name(t: str) -> str:
    return f"rt-hermes-{t}"


def workspace_name(t: str) -> str:
    return f"rt-ws-{t}"


def runtime_volume(t: str) -> str:
    return f"rt-hermes-{t}-data"


def worker_name(worker_id: str) -> str:
    return f"rt-pool-{worker_id}"


def tenant_subnet(index: int) -> ipaddress.IPv4Network:
    return _slice(TENANT_POOL, index)


def egress_subnet(index: int) -> ipaddress.IPv4Network:
    return _slice(EGRESS_POOL, index)


def _slice(pool: ipaddress.IPv4Network, index: int) -> ipaddress.IPv4Network:
    if not 0 <= index < MAX_TENANT_INDEX:
        raise ValueError("net index out of range")
    base = int(pool.network_address) + index * 16
    return ipaddress.ip_network((base, 28))


def edge_ip(index: int) -> str:
    """Fixed address of rt-edge inside a tenant egress /28 (.14; .1 is the gateway)."""
    return str(egress_subnet(index).network_address + 14)


def hub_workspace_ip(index: int) -> str:
    n = WS_RANGE_START + index
    if n >= SSH_HUB_CIDR.num_addresses - 2:
        raise ValueError("ssh hub exhausted")
    return str(SSH_HUB_CIDR.network_address + n)


def hub_worker_ip(slot: int) -> str:
    """slot 1..13 maps to 10.199.0.2 .. 10.199.0.14."""
    if not 1 <= slot <= 13:
        raise ValueError("worker slot out of range")
    return str(WORKER_RANGE.network_address + 1 + slot)


def labels(role: str, tenant: str | None = None, generation: int | None = None,
           digest: str | None = None, extra: dict[str, str] | None = None) -> dict[str, str]:
    out = {LABEL_MANAGED: "true", LABEL_ROLE: role}
    if tenant:
        out[LABEL_TENANT] = tenant
    if generation is not None:
        out[LABEL_GENERATION] = str(generation)
    if digest:
        out[LABEL_DIGEST] = digest
    if extra:
        out.update(extra)
    return out


def image_digest(image: str) -> str:
    """Return the sha256 pin of an image reference (name@sha256:x or sha256:x)."""
    if "@sha256:" in image:
        return "sha256:" + image.split("@sha256:", 1)[1]
    if image.startswith("sha256:"):
        return image
    return ""
