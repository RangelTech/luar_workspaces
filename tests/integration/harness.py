"""Helpers for the real-Docker (W family) tests: docker CLI wrappers, ssh from a worker stand-in,
live nftables, HTTP against rt-edge. Nothing here is imported by the service itself."""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

from rm import naming, nft
from rm.firewall import RulesetFileFirewall

IS_WIN = sys.platform == "win32"
WORKER_IP = naming.hub_worker_ip(1)  # 10.199.0.2: the address a pool worker would have


def docker(*args: str, input: str | None = None, timeout: int = 180, check: bool = True,
           ) -> subprocess.CompletedProcess:
    # bytes in/out: text mode would rewrite line endings on Windows (breaks nft and sh)
    r = subprocess.run(["docker", *args], input=None if input is None else input.encode(),
                       capture_output=True, timeout=timeout)
    r.stdout = r.stdout.decode("utf-8", "replace")
    r.stderr = r.stderr.decode("utf-8", "replace")
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:4])} failed rc={r.returncode}: "
                           f"{r.stderr.strip()[:400]}")
    return r


def exec_in(container: str, cmd: str, timeout: int = 60, user: str | None = None,
            ) -> subprocess.CompletedProcess:
    args = ["exec"] + (["-u", user] if user else []) + [container, "sh", "-c", cmd]
    return docker(*args, timeout=timeout, check=False)


def wait_until(fn, timeout: float = 30, interval: float = 0.5, what: str = "condition"):
    t0 = time.monotonic()
    last = None
    while time.monotonic() - t0 < timeout:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # noqa: BLE001 - the condition may fail while things boot
            last = e
        time.sleep(interval)
    raise AssertionError(f"timeout waiting for {what} (last={last!r})")


def inspect(name: str) -> dict:
    return __import__("json").loads(docker("inspect", name).stdout)[0]


def container_health(name: str) -> str:
    return (inspect(name)["State"].get("Health") or {}).get("Status", "none")


def wait_healthy(name: str, timeout: float = 90) -> None:
    wait_until(lambda: container_health(name) == "healthy", timeout, 1, f"{name} healthy")


# ----- ssh as a worker would do it -------------------------------------------------------------
def ssh(ws_image: str, private_key: str, hub_ip: str, cmd: str, timeout: int = 120,
        connect_timeout: int = 10) -> subprocess.CompletedProcess:
    script = ('printf "%s\\n" "$K" > /tmp/k && chmod 600 /tmp/k && exec ssh -i /tmp/k '
              '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR '
              f'-o ConnectTimeout={connect_timeout} root@{hub_ip} "$C"')
    return docker("run", "--rm", "--entrypoint", "sh", "--network", naming.SSH_HUB_NET, "--ip",
                  WORKER_IP, "-e", f"K={private_key}", "-e", f"C={cmd}", ws_image, "-c", script,
                  timeout=timeout, check=False)


# ----- live nftables (inside the Docker VM, where the bridges live) --------------------------
class LiveFirewall(RulesetFileFirewall):
    """Same file the host's path unit would load, applied immediately through a privileged
    helper that shares the VM network namespace."""

    def __init__(self, path: str, tools_image: str):
        super().__init__(path)
        self.tools = tools_image
        self.last_text = ""

    def apply(self, fw: nft.FirewallInput) -> bool:
        changed = super().apply(fw)
        if changed:
            self.last_text = nft.render(fw)
            docker("run", "-i", "--rm", "--privileged", "--net=host", self.tools, "nft", "-f", "-",
                   input=self.last_text, timeout=60)
        return changed


def nft_counter(tools_image: str, needle: str) -> int:
    """Packets counted by the first forward-chain rule containing `needle`."""
    out = docker("run", "--rm", "--privileged", "--net=host", tools_image, "nft", "list",
                 "chain", "inet", "rt_fw", "forward", timeout=60).stdout
    for line in out.splitlines():
        if needle in line:
            m = re.search(r"counter packets (\d+)", line)
            return int(m.group(1)) if m else 0
    raise AssertionError(f"no nft rule containing {needle!r}:\n{out}")


def nft_delete(tools_image: str) -> None:
    docker("run", "--rm", "--privileged", "--net=host", tools_image, "nft", "delete", "table",
           "inet", "rt_fw", timeout=60, check=False)


# ----- rt-edge ----------------------------------------------------------------------------------
def edge_get(port: int, host: str, path: str = "/", timeout: float = 8) -> httpx.Response:
    return httpx.get(f"http://127.0.0.1:{port}{path}", headers={"Host": host}, timeout=timeout,
                     follow_redirects=False)


class EdgeSyncWriter:
    """On Windows the dynamic dir cannot be a bind mount (inotify does not cross the host file
    system), so every write is also pushed into the edge container. On Linux the directory is
    bind-mounted and this wrapper only forwards."""

    def __init__(self, inner, container: str, directory: str, push: bool):
        self.inner, self.container, self.dir, self.push = inner, container, directory, push

    def __getattr__(self, n):
        return getattr(self.inner, n)

    def write(self, tenant: str, config: dict) -> bool:
        changed = self.inner.write(tenant, config)
        if self.push:
            p = Path(self.inner.path(tenant))
            if p.exists():
                self._put(tenant, p.read_text(encoding="utf-8"))
            else:
                self._rm(tenant)
        return changed

    def remove(self, tenant: str) -> bool:
        changed = self.inner.remove(tenant)
        if self.push:
            self._rm(tenant)
        return changed

    def _put(self, tenant: str, text: str) -> None:
        docker("exec", "-i", self.container, "sh", "-c",
               f"cat > /tmp/.{tenant}.tmp && mv /tmp/.{tenant}.tmp {self.dir}/{tenant}.yml",
               input=text, timeout=30)

    def _rm(self, tenant: str) -> None:
        docker("exec", self.container, "rm", "-f", f"{self.dir}/{tenant}.yml", timeout=30,
               check=False)
