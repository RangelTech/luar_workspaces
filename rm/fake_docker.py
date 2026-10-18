"""In-memory DockerClient for tests and the offline dev loop.

It reproduces the behaviours the reconciler depends on: 409 on duplicate create, labels on
every object, State transitions (running/paused/exited), health, OOM, network attachment and
label-filtered listings. It enforces nothing about policy (that is PolicyDockerClient's job).
"""
from __future__ import annotations

import copy
import itertools
import threading
from datetime import UTC, datetime
from typing import Any

from .docker_client import Conflict, DockerError


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _match(labels: dict | None, filters: list[str] | None) -> bool:
    for f in filters or []:
        k, _, v = f.partition("=")
        if k not in (labels or {}) or (v and labels[k] != v):
            return False
    return True


class FakeDocker:
    def __init__(self, auto_healthy: bool = True) -> None:
        self._mu = threading.RLock()
        self.containers: dict[str, dict] = {}
        self.networks: dict[str, dict] = {}
        self.volumes: dict[str, dict] = {}
        self.images: dict[str, dict] = {}
        self.archives: dict = {}
        self.calls: list[tuple] = []
        self.auto_healthy = auto_healthy
        self.fail_start: set[str] = set()      # names whose start leaves them unhealthy
        self.unstoppable: set[str] = set()     # names that ignore stop and kill (fencing tests)
        self._ids = itertools.count(1)

    # ----- helpers --------------------------------------------------------------------------
    def _rec(self, verb: str, *a: Any) -> None:
        self.calls.append((verb, *a))

    def _c(self, name: str) -> dict:
        c = self.containers.get(name)
        if c is None:
            raise DockerError(404, f"no such container {name}")
        return c

    def verbs(self, verb: str) -> list[tuple]:
        return [c for c in self.calls if c[0] == verb]

    # ----- test hooks -----------------------------------------------------------------------
    def foreign_container(self, name: str, labels: dict | None = None) -> None:
        """A container the RM must never see (no rt.managed label)."""
        with self._mu:
            self.containers[name] = self._new(
                name, {"Image": "foreign", "Labels": labels or {}, "HostConfig": {}}, running=True)

    def crash(self, name: str, oom: bool = False, code: int = 137) -> None:
        with self._mu:
            st = self._c(name)["State"]
            st.update(Status="exited", Running=False, ExitCode=code, OOMKilled=oom,
                      Health={"Status": "none"})

    def set_health(self, name: str, status: str) -> None:
        with self._mu:
            self._c(name)["State"]["Health"] = {"Status": status}

    # ----- generic ---------------------------------------------------------------------------
    def ping(self) -> bool:
        return True

    def _new(self, name: str, body: dict, running: bool = False) -> dict:
        body = copy.deepcopy(body)
        nets: dict[str, dict] = {}
        nm = (body.get("HostConfig") or {}).get("NetworkMode")
        if nm:
            nets[nm] = {"Aliases": [name], "IPAddress": ""}
        for n, ep in ((body.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}).items():
            nets[n] = {"Aliases": ep.get("Aliases", []), "IPAddress": ""}
        return {
            "Id": f"fake{next(self._ids):060d}", "Name": "/" + name,
            "Config": {"Image": body.get("Image", ""), "Labels": body.get("Labels") or {},
                       "Env": body.get("Env") or [], "Cmd": body.get("Cmd"),
                       "User": body.get("User", "")},
            "HostConfig": body.get("HostConfig") or {},
            "State": {"Status": "running" if running else "created", "Running": running,
                      "Paused": False, "OOMKilled": False, "ExitCode": 0,
                      "Health": {"Status": "healthy" if running and self.auto_healthy else "none"},
                      "StartedAt": _now() if running else ""},
            "NetworkSettings": {"Networks": nets},
        }

    # ----- containers --------------------------------------------------------------------------
    def list_containers(self, label_filters=None):
        with self._mu:
            out = []
            for name, c in self.containers.items():
                if _match(c["Config"]["Labels"], label_filters):
                    out.append({"Id": c["Id"], "Names": ["/" + name],
                                "State": c["State"]["Status"],
                                "Labels": dict(c["Config"]["Labels"]),
                                "Image": c["Config"]["Image"]})
            return out

    def inspect_container(self, name):
        with self._mu:
            c = self.containers.get(name)
            return copy.deepcopy(c) if c else None

    def put_archive(self, name, path, tar_bytes):
        with self._mu:
            self._rec("put_archive", name, path)
            self._c(name)
            self.archives[(name, path)] = tar_bytes

    def get_archive(self, name, path):
        with self._mu:
            self._c(name)
            return self.archives.get((name, path))

    def exec_run(self, name, cmd, *, user="", workdir="", timeout=60, env=None):
        with self._mu:
            self._rec("exec_run", name, cmd, env)
            self._c(name)
            out = getattr(self, "exec_results", {}).get(" ".join(cmd))
            return out or {"exit_code": 0, "stdout": "ok\n", "stderr": ""}

    def create_container(self, name, body):
        with self._mu:
            self._rec("create_container", name, body)
            if name in self.containers:
                raise Conflict(409, f"container name {name} already in use")
            self.containers[name] = self._new(name, body)
            return self.containers[name]["Id"]

    def start(self, name):
        with self._mu:
            self._rec("start", name)
            c = self._c(name)
            st = c["State"]
            if st["Running"]:
                return
            healthy = self.auto_healthy and name not in self.fail_start
            st.update(Status="running", Running=True, Paused=False, OOMKilled=False,
                      ExitCode=0, StartedAt=_now(),
                      Health={"Status": "healthy" if healthy else "unhealthy"})

    def stop(self, name, timeout=10):
        with self._mu:
            self._rec("stop", name)
            c = self._c(name)
            if name in self.unstoppable:
                return
            c["State"].update(Status="exited", Running=False, Paused=False, ExitCode=0,
                              Health={"Status": "none"})

    def restart(self, name, timeout=10):
        with self._mu:
            self._rec("restart", name)
            self.stop(name, timeout)
            self.start(name)

    def kill(self, name):
        with self._mu:
            self._rec("kill", name)
            c = self._c(name)
            if name in self.unstoppable:
                return
            c["State"].update(Status="exited", Running=False, ExitCode=137)

    def pause(self, name):
        with self._mu:
            self._rec("pause", name)
            st = self._c(name)["State"]
            if not st["Running"]:
                raise DockerError(409, "container is not running")
            st.update(Status="paused", Paused=True)

    def unpause(self, name):
        with self._mu:
            self._rec("unpause", name)
            st = self._c(name)["State"]
            st.update(Status="running", Paused=False)

    def remove_container(self, name, force=False):
        with self._mu:
            self._rec("remove_container", name, force)
            c = self.containers.get(name)
            if c is None:
                return
            if c["State"]["Running"] and not force:
                raise DockerError(409, "cannot remove a running container")
            del self.containers[name]

    def container_stats(self, name):
        with self._mu:
            c = self.containers.get(name)
            if c is None or not c["State"]["Running"]:
                return None
            return {"cpu_stats": {"cpu_usage": {"total_usage": c.get("_cpu_ns", 0)}},
                    "memory_stats": {"usage": c.get("_mem", 50 * 1024 * 1024),
                                     "stats": {"inactive_file": 0}}}

    def top(self, name):
        with self._mu:
            c = self.containers.get(name)
            if c is None or not c["State"]["Running"]:
                return None
            procs = c.get("_procs", ["/init", "/usr/sbin/sshd -D"])
            return {"Titles": ["PID", "USER", "COMMAND"],
                    "Processes": [[str(i + 1), "root", p] for i, p in enumerate(procs)]}

    def container_logs(self, name, tail=200):
        with self._mu:
            return f"log of {name}\n" if name in self.containers else ""

    # ----- networks ----------------------------------------------------------------------------
    def list_networks(self, label_filters=None):
        with self._mu:
            return [copy.deepcopy(n) for n in self.networks.values()
                    if _match(n.get("Labels"), label_filters)]

    def inspect_network(self, name):
        with self._mu:
            n = self.networks.get(name)
            return copy.deepcopy(n) if n else None

    def create_network(self, body):
        with self._mu:
            self._rec("create_network", body["Name"])
            if body["Name"] in self.networks:
                raise Conflict(409, "network already exists")
            self.networks[body["Name"]] = {"Id": f"net{next(self._ids)}", **copy.deepcopy(body)}
            return self.networks[body["Name"]]["Id"]

    def connect_network(self, network, container, ipv4=None, aliases=None):
        with self._mu:
            self._rec("connect_network", network, container, ipv4)
            if network not in self.networks:
                raise DockerError(404, f"network {network} not found")
            nets = self._c(container)["NetworkSettings"]["Networks"]
            if network in nets:
                raise DockerError(403, "endpoint already exists in network")
            nets[network] = {"Aliases": aliases or [], "IPAddress": ipv4 or ""}

    def disconnect_network(self, network, container):
        with self._mu:
            self._c(container)["NetworkSettings"]["Networks"].pop(network, None)

    def remove_network(self, name):
        with self._mu:
            self._rec("remove_network", name)
            self.networks.pop(name, None)

    # ----- volumes -----------------------------------------------------------------------------
    def list_volumes(self, label_filters=None):
        with self._mu:
            return [copy.deepcopy(v) for v in self.volumes.values()
                    if _match(v.get("Labels"), label_filters)]

    def inspect_volume(self, name):
        with self._mu:
            v = self.volumes.get(name)
            return copy.deepcopy(v) if v else None

    def create_volume(self, body):
        with self._mu:
            self.volumes[body["Name"]] = copy.deepcopy(body)
            return body["Name"]

    def remove_volume(self, name, purge_of=None):
        with self._mu:
            self._rec("remove_volume", name, purge_of)
            self.volumes.pop(name, None)

    def inspect_image(self, ref):
        return self.images.get(ref)
