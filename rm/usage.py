"""Usage accounting: sample `docker stats` per rt.tenant into tenant_usage_hourly (annex 04 5)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from . import naming


def hour_bucket(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def cpu_total_ns(stats: dict) -> int:
    return int(((stats.get("cpu_stats") or {}).get("cpu_usage") or {}).get("total_usage") or 0)


def mem_bytes(stats: dict) -> int:
    ms = stats.get("memory_stats") or {}
    usage = int(ms.get("usage") or 0)
    cache = int((ms.get("stats") or {}).get("inactive_file") or 0)
    return max(usage - cache, 0)


@dataclass
class Sample:
    tenant: str
    role: str
    cpu_ns: int
    mem: int
    running: bool


class UsageSampler:
    """Keeps the last cumulative CPU counter per container so a restart does not go negative."""

    def __init__(self, docker, store, quota=None):
        self.docker = docker
        self.store = store
        self.quota = quota
        self._last_cpu: dict[str, int] = {}
        self._last_ts: dict[str, datetime] = {}

    def sample_once(self, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        n = 0
        per_tenant: dict[str, dict[str, float]] = {}
        for c in self.docker.list_containers([f"{naming.LABEL_TENANT}"]):
            labels = c.get("Labels") or {}
            tenant = labels.get(naming.LABEL_TENANT)
            role = labels.get(naming.LABEL_ROLE)
            name = (c.get("Names") or ["/?"])[0].lstrip("/")
            if not tenant or role not in (naming.ROLE_RUNTIME, naming.ROLE_WORKSPACE):
                continue
            running = c.get("State") == "running"
            acc = per_tenant.setdefault(tenant, {})
            dt_h = 0.0
            if name in self._last_ts:
                dt_h = max((now - self._last_ts[name]).total_seconds(), 0) / 3600
            self._last_ts[name] = now
            if not running:
                self._last_cpu.pop(name, None)
                continue
            st = self.docker.container_stats(name) or {}
            cpu = cpu_total_ns(st)
            prev = self._last_cpu.get(name)
            self._last_cpu[name] = cpu
            if prev is not None and cpu >= prev:
                acc["cpu_seconds"] = acc.get("cpu_seconds", 0) + (cpu - prev) / 1e9
            acc["mem_gb_hours"] = acc.get("mem_gb_hours", 0) + mem_bytes(st) / 1024**3 * dt_h
            key = "ws_uptime_h" if role == naming.ROLE_WORKSPACE else "runtime_uptime_h"
            acc[key] = acc.get(key, 0) + dt_h
            n += 1
        used = self.quota.report() if self.quota else {}
        for tenant, acc in per_tenant.items():
            if tenant in used:
                acc["disk_gb"] = used[tenant]["used"] / 1024**3
            if acc:
                self.store.usage_add(tenant, hour_bucket(now), **acc)
        return n
