"""Disk quota per tenant (annex 04 1.7): one XFS project per tenant on the loop-mounted FS.

QuotaBackend is an interface. FakeQuota keeps state in memory (dev, tests). XfsQuota drives the
real xfs_quota binary through an injectable runner; it is NOT run against a real XFS here.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

Runner = Callable[[list[str]], str]


class QuotaBackend(Protocol):
    def set_limit(self, tenant: str, path: str, gb: int) -> None: ...
    def usage_bytes(self, tenant: str) -> int: ...
    def remove(self, tenant: str) -> None: ...
    def report(self) -> dict[str, dict[str, int]]: ...


class FakeQuota:
    def __init__(self) -> None:
        self.limits: dict[str, int] = {}
        self.paths: dict[str, str] = {}
        self.used: dict[str, int] = {}

    def set_limit(self, tenant: str, path: str, gb: int) -> None:
        self.limits[tenant] = gb
        self.paths[tenant] = path

    def usage_bytes(self, tenant: str) -> int:
        return self.used.get(tenant, 0)

    def remove(self, tenant: str) -> None:
        self.limits.pop(tenant, None)
        self.paths.pop(tenant, None)

    def report(self) -> dict[str, dict[str, int]]:
        return {t: {"used": self.used.get(t, 0), "hard": g * 1024**3}
                for t, g in self.limits.items()}


class FileQuota:
    """Quota por tenant sem privilegios: o RM so escreve o que quer e le o que o host mediu.

    Mesmo desenho do firewall (o RM nunca roda nft): `limits.json` e escrito atomicamente aqui; uma unit
    `systemd.path` no host (host/rt-quota-apply.sh) aplica `xfs_quota` e publica `usage.json`.
    """

    def __init__(self, state_dir: str = "/var/lib/rt/quota"):
        self.dir = Path(state_dir)

    def _read(self, name: str) -> dict:
        try:
            return json.loads((self.dir / name).read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    def _write_limits(self, data: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".limits.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, sort_keys=True)
        os.replace(tmp, self.dir / "limits.json")

    def set_limit(self, tenant: str, path: str, gb: int) -> None:
        data = self._read("limits.json")
        if data.get(tenant) != {"path": path, "gb": gb}:
            data[tenant] = {"path": path, "gb": gb}
            self._write_limits(data)

    def usage_bytes(self, tenant: str) -> int:
        return int(self._read("usage.json").get(tenant, {}).get("used", 0))

    def remove(self, tenant: str) -> None:
        data = self._read("limits.json")
        if data.pop(tenant, None) is not None:
            self._write_limits(data)

    def report(self) -> dict[str, dict[str, int]]:
        usage = self._read("usage.json")
        return {t: {"used": int(usage.get(t, {}).get("used", 0)), "hard": int(v["gb"]) * 1024**3}
                for t, v in self._read("limits.json").items()}


def project_name(tenant: str) -> str:
    return f"rt_{tenant}"


def project_id(index: int) -> int:
    """Stable XFS project id from the tenant net_index (ids below 10000 are left to the OS)."""
    return 100000 + index


def projects_line(pid: int, path: str) -> str:
    return f"{pid}:{path}"


def projid_line(tenant: str, pid: int) -> str:
    return f"{project_name(tenant)}:{pid}"


def parse_report(text: str) -> dict[str, dict[str, int]]:
    """Parse `xfs_quota -x -c 'report -p -N -b' <mount>` output (blocks in 1K units).

    Columns: Project  Used  Soft  Hard  Warn/Grace
    """
    out: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].startswith("rt_"):
            continue
        try:
            used, hard = int(parts[1]) * 1024, int(parts[3]) * 1024
        except ValueError:
            continue
        out[parts[0][3:]] = {"used": used, "hard": hard}
    return out


class XfsQuota:
    def __init__(self, mount: str = "/srv/tenants", projects_file: str = "/etc/projects",
                 projid_file: str = "/etc/projid", runner: Runner | None = None,
                 index_of: Callable[[str], int] | None = None):
        self.mount = mount
        self.projects_file = projects_file
        self.projid_file = projid_file
        self.run = runner or self._run
        self.index_of = index_of or (lambda t: 0)

    @staticmethod
    def _run(cmd: list[str]) -> str:
        return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60).stdout

    def commands_for(self, tenant: str, path: str, gb: int) -> list[list[str]]:
        name = project_name(tenant)
        return [
            ["xfs_quota", "-x", "-c", f"project -s -p {path} {name}", self.mount],
            ["xfs_quota", "-x", "-c", f"limit -p bhard={gb}g {name}", self.mount],
        ]

    def set_limit(self, tenant: str, path: str, gb: int) -> None:
        pid = project_id(self.index_of(tenant))
        self._ensure_line(self.projects_file, projects_line(pid, path))
        self._ensure_line(self.projid_file, projid_line(tenant, pid))
        for cmd in self.commands_for(tenant, path, gb):
            self.run(cmd)

    def _ensure_line(self, file: str, line: str) -> None:
        try:
            with open(file, encoding="utf-8") as f:
                have = f.read().splitlines()
        except FileNotFoundError:
            have = []
        if line not in have:
            with open(file, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def report(self) -> dict[str, dict[str, int]]:
        return parse_report(self.run(["xfs_quota", "-x", "-c", "report -p -N -b", self.mount]))

    def usage_bytes(self, tenant: str) -> int:
        return self.report().get(tenant, {}).get("used", 0)

    def remove(self, tenant: str) -> None:
        self.run(["xfs_quota", "-x", "-c", f"limit -p bhard=0 {project_name(tenant)}", self.mount])
