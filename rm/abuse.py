"""Abuse detection for workspaces (annex 04 section 2.8): known miners and sustained CPU burn.

The monitor only observes (docker top / stats) and, on a hit, calls the same kill switch an
operator would use (TenantService.suspend). Everything else (SMTP, scans, banda) is enforced by
the nftables ruleset, not here.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from collections.abc import Callable

from . import naming
from .config import Settings

MINER_NAMES = {"xmrig", "xmr-stak", "minerd", "cpuminer", "ethminer", "nbminer", "t-rex",
               "phoenixminer", "cgminer", "bfgminer", "cpuminer-multi", "lolminer"}
MINER_ARGS = re.compile(r"stratum\+(tcp|ssl|tls)://|--donate-level|--coin[= ]", re.I)


def miner_in_process(rows: list[list[str]]) -> str | None:
    """Return a description of the first suspicious process, else None. The last column of each
    row is the full command line (`ps -eo pid,user,args`)."""
    for r in rows:
        cmd = r[-1] if r else ""
        base = cmd.split()[0].rsplit("/", 1)[-1].lower() if cmd.split() else ""
        if base in MINER_NAMES:
            return f"known miner binary: {base}"
        if MINER_ARGS.search(cmd):
            return f"mining pool arguments: {cmd[:80]}"
    return None


class AbuseMonitor:
    def __init__(self, settings: Settings, docker, service,
                 clock: Callable[[], float] = time.monotonic):
        self.s = settings
        self.docker = docker
        self.svc = service
        self.clock = clock
        self._cpu: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.hits: list[tuple[str, str]] = []

    def _limit_cpus(self, info: dict) -> float:
        nano = (info.get("HostConfig") or {}).get("NanoCpus") or 1_000_000_000
        return nano / 1e9

    def scan(self) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        for c in self.docker.list_containers([f"{naming.LABEL_ROLE}={naming.ROLE_WORKSPACE}"]):
            if c.get("State") != "running":
                continue
            t = (c.get("Labels") or {}).get(naming.LABEL_TENANT)
            if not t:
                continue
            name = naming.workspace_name(t)
            reason = None
            top = self.docker.top(name)
            if top:
                reason = miner_in_process(top.get("Processes") or [])
            if reason is None:
                reason = self._cpu_burn(t, name)
            if reason:
                row = self.svc.store.get_tenant(t)
                if row and not row["suspended"]:
                    self.svc.suspend(t, "abuse-monitor", reason, "high")
                    self.svc.metrics["abuse_suspensions"] += 1
                found.append((t, reason))
        self.hits.extend(found)
        return found

    def _cpu_burn(self, t: str, name: str) -> str | None:
        st = self.docker.container_stats(name)
        if not st:
            return None
        now = self.clock()
        cpu = int(((st.get("cpu_stats") or {}).get("cpu_usage") or {}).get("total_usage") or 0)
        dq = self._cpu[t]
        dq.append((now, cpu))
        win = self.s.abuse_cpu_window_s
        while len(dq) > 1 and now - dq[1][0] >= win:
            dq.popleft()
        t0, c0 = dq[0]
        if now - t0 < win * 0.95:
            return None
        info = self.docker.inspect_container(name) or {}
        used = (cpu - c0) / 1e9 / (now - t0) / self._limit_cpus(info)
        if used >= self.s.abuse_cpu_threshold:
            return f"cpu at {used:.0%} of limit for {int(now - t0)}s"
        return None
