"""Ephemeral script executor (spec 04 section 7.3).

One throwaway container per run: no network (NetworkMode none), cap-drop ALL, read-only root,
tmpfs, memory/pid/cpu limits, wall-clock timeout, inputs mounted read-only and outputs in a
directory that exists only for that run. The container image (rt-executor) applies rlimits to the
script itself; this module applies the container-level limits and always cleans up.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from . import naming
from .config import Settings
from .docker_client import DockerClient
from .service import ServiceError

NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
MAX_SCRIPT = 256 * 1024
MAX_INPUT_TOTAL = 50 * 1024 * 1024
MAX_OUTPUT_TOTAL = 20 * 1024 * 1024
MAX_OUTPUT_FILES = 50
MAX_LOG = 64 * 1024
MiB = 1024 * 1024


def container_name(run_id: str) -> str:
    return f"rt-exec-{run_id[:12]}"


class ExecutorRunner:
    def __init__(self, settings: Settings, docker: DockerClient,
                 sleep: Callable[[float], None] = time.sleep):
        self.s = settings
        self.docker = docker
        self.sleep = sleep
        self._slots = threading.BoundedSemaphore(max(1, settings.executor_max_parallel))

    # daemon-visible root (bind sources) and the path this process writes to
    @property
    def daemon_root(self) -> str:
        return self.s.executor_root.rstrip("/")

    @property
    def local_root(self) -> str:
        return (self.s.executor_local_root or self.s.executor_root).rstrip("/")

    def build_body(self, run_id: str, timeout_s: int, mem_mb: int, cpus: float) -> dict:
        base = f"{self.daemon_root}/{run_id}"
        mem = mem_mb * MiB
        return {
            "Image": self.s.executor_image,
            "User": "10001",
            "Env": [f"RT_TIMEOUT_S={timeout_s}", f"RT_CPU_S={max(timeout_s, 1)}",
                    f"RT_MEM_MB={mem_mb}", "RT_NPROC=64"],
            "Labels": naming.labels(naming.ROLE_EXECUTOR, None, None,
                                    naming.image_digest(self.s.executor_image),
                                    {"rt.run": run_id}),
            "StopTimeout": 2,
            "HostConfig": {
                "NetworkMode": "none",
                "Memory": mem + 64 * MiB, "MemorySwap": mem + 64 * MiB,
                "NanoCpus": int(cpus * 1_000_000_000), "PidsLimit": 64, "CpuShares": 256,
                "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                "ReadonlyRootfs": True, "Privileged": False,
                "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=64m"},
                "Binds": [f"{base}/in:/in:ro", f"{base}/out:/out"],
                "Ulimits": [{"Name": "nofile", "Soft": 256, "Hard": 256}],
                "LogConfig": {"Type": "json-file", "Config": {"max-size": "1m", "max-file": "1"}},
            },
        }

    def run(self, script: str, inputs: dict[str, str] | None = None, timeout_s: int = 60,
            mem_mb: int = 512, cpus: float = 1.0) -> dict:
        if not self.s.executor_image:
            raise ServiceError(503, "executor_not_configured")
        if not 1 <= timeout_s <= 300:
            raise ServiceError(400, "bad_timeout", "1..300")
        if not 64 <= mem_mb <= 2048:
            raise ServiceError(400, "bad_memory", "64..2048 MB")
        if not 0.1 <= cpus <= 2:
            raise ServiceError(400, "bad_cpus", "0.1..2")
        data = self._decode_inputs(script, inputs or {})
        if not self._slots.acquire(timeout=2):
            raise ServiceError(429, "executor_busy")
        run_id = uuid.uuid4().hex
        local = Path(self.local_root) / run_id
        name = container_name(run_id)
        try:
            self._prepare(local, script, data)
            self.docker.create_container(name, self.build_body(run_id, timeout_s, mem_mb, cpus))
            self.docker.start(name)
            killed = self._wait(name, timeout_s + 10)
            info = self.docker.inspect_container(name) or {}
            oom = bool((info.get("State") or {}).get("OOMKilled"))
            return self._collect(local, run_id, killed, oom)
        finally:
            try:
                info = self.docker.inspect_container(name)
                if info is not None:
                    if (info.get("State") or {}).get("Running"):
                        self.docker.kill(name)
                    self.docker.remove_container(name, force=True)
            finally:
                shutil.rmtree(local, ignore_errors=True)
                self._slots.release()

    def _decode_inputs(self, script: str, inputs: dict[str, str]) -> dict[str, bytes]:
        if not isinstance(script, str) or not script.strip():
            raise ServiceError(400, "script_required")
        if len(script.encode()) > MAX_SCRIPT:
            raise ServiceError(413, "script_too_large")
        out: dict[str, bytes] = {}
        total = 0
        for k, v in inputs.items():
            if not NAME_OK.match(k) or k == "script.py":
                raise ServiceError(400, "bad_input_name", k)
            try:
                raw = base64.b64decode(v, validate=True)
            except (binascii.Error, ValueError):
                raise ServiceError(400, "bad_input_base64", k) from None
            total += len(raw)
            if total > MAX_INPUT_TOTAL:
                raise ServiceError(413, "inputs_too_large")
            out[k] = raw
        return out

    def _prepare(self, local: Path, script: str, data: dict[str, bytes]) -> None:
        (local / "in").mkdir(parents=True)
        (local / "out").mkdir()
        (local / "in" / "script.py").write_text(script, encoding="utf-8", newline="\n")
        for k, raw in data.items():
            (local / "in" / k).write_bytes(raw)
        if os.name == "posix":
            os.chmod(local, 0o755)
            os.chmod(local / "in", 0o755)
            for p in (local / "in").iterdir():
                os.chmod(p, 0o644)
            os.chmod(local / "out", 0o777)  # the executor runs as uid 10001

    def _wait(self, name: str, limit_s: int) -> bool:
        """Poll until the container exits; kill it if the limit passes. True when killed."""
        t0 = time.monotonic()
        while True:
            info = self.docker.inspect_container(name) or {}
            if not (info.get("State") or {}).get("Running"):
                return False
            if time.monotonic() - t0 >= limit_s:
                self.docker.kill(name)
                return True
            self.sleep(0.2)

    def _collect(self, local: Path, run_id: str, killed: bool, oom: bool) -> dict:
        out_dir = local / "out"
        res: dict = {}
        rj = out_dir / "_result.json"
        if rj.exists():
            try:
                res = json.loads(rj.read_text(encoding="utf-8"))
            except ValueError:
                res = {}
        outputs: dict[str, str] = {}
        total = 0
        truncated = False
        for p in sorted(out_dir.iterdir()):
            if not p.is_file() or p.is_symlink() or p.name.startswith("_"):
                continue
            size = p.stat().st_size
            if len(outputs) >= MAX_OUTPUT_FILES or total + size > MAX_OUTPUT_TOTAL:
                truncated = True
                continue
            total += size
            outputs[p.name] = base64.b64encode(p.read_bytes()).decode()

        def _log(n: str) -> str:
            f = out_dir / n
            return f.read_bytes()[:MAX_LOG].decode("utf-8", "replace") if f.exists() else ""

        return {"run_id": run_id, "exit_code": res.get("exit_code", 137 if (killed or oom) else -1),
                "timed_out": bool(res.get("timed_out")) or killed, "oom_killed": oom,
                "duration_s": res.get("duration_s"), "stdout": _log("_stdout.txt"),
                "stderr": _log("_stderr.txt"), "outputs": outputs, "outputs_truncated": truncated}
