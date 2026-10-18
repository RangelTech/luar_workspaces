"""Docker access: an HTTP client compatible with docker-socket-proxy, plus a policy layer.

Backend (a): HttpDockerClient talks the Docker Engine REST API over HTTP (the proxy URL) or a unix
socket; it only issues verbs that the proxy allows (CONTAINERS, NETWORKS, VOLUMES, IMAGES, POST).
Backend (b): PolicyDockerClient wraps any DockerClient. Every create is validated against the
allowlist in rm/policy.py, and every mutation of an existing resource requires rt.managed=true, so
Evolution or compose stacks are invisible and untouchable. Volumes are only removed with an
explicit purge authorization naming the owning tenant.
"""
from __future__ import annotations

from typing import Any, Protocol

import httpx

from . import naming
from .policy import NotManaged, Policy, PolicyConfig, PolicyViolation


class DockerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"docker {status}: {message}")
        self.status = status
        self.message = message


class Conflict(DockerError):
    pass


class DockerClient(Protocol):
    def ping(self) -> bool: ...
    def list_containers(self, label_filters: list[str] | None = None) -> list[dict]: ...
    def inspect_container(self, name: str) -> dict | None: ...
    def create_container(self, name: str, body: dict) -> str: ...
    def start(self, name: str) -> None: ...
    def stop(self, name: str, timeout: int = 10) -> None: ...
    def restart(self, name: str, timeout: int = 10) -> None: ...
    def kill(self, name: str) -> None: ...
    def pause(self, name: str) -> None: ...
    def unpause(self, name: str) -> None: ...
    def remove_container(self, name: str, force: bool = False) -> None: ...
    def container_stats(self, name: str) -> dict | None: ...
    def container_logs(self, name: str, tail: int = 200) -> str: ...
    def top(self, name: str) -> dict | None: ...
    def list_networks(self, label_filters: list[str] | None = None) -> list[dict]: ...
    def inspect_network(self, name: str) -> dict | None: ...
    def create_network(self, body: dict) -> str: ...
    def connect_network(self, network: str, container: str, ipv4: str | None = None,
                        aliases: list[str] | None = None) -> None: ...
    def disconnect_network(self, network: str, container: str) -> None: ...
    def remove_network(self, name: str) -> None: ...
    def list_volumes(self, label_filters: list[str] | None = None) -> list[dict]: ...
    def inspect_volume(self, name: str) -> dict | None: ...
    def create_volume(self, body: dict) -> str: ...
    def remove_volume(self, name: str, purge_of: str | None = None) -> None: ...
    def inspect_image(self, ref: str) -> dict | None: ...
    def exec_run(self, name: str, cmd: list[str], *, user: str = "", workdir: str = "",
                 timeout: int = 60, env: dict | None = None) -> dict: ...


def _demux(raw: bytes) -> tuple[str, str]:
    """Docker multiplexed stream (8-byte header: stream id, 3 zero bytes, big-endian length)."""
    out, err, i = bytearray(), bytearray(), 0
    while i + 8 <= len(raw):
        kind = raw[i]
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        chunk = raw[i + 8:i + 8 + size]
        (err if kind == 2 else out).extend(chunk)
        i += 8 + size
    return out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


class HttpDockerClient:
    """Docker Engine API over HTTP (docker-socket-proxy) or a unix socket."""

    def __init__(self, host: str, api_version: str = "v1.43", timeout: float = 60.0,
                 transport: httpx.BaseTransport | None = None):
        self.api = api_version.strip("/")
        if host.startswith("unix://"):
            tr = transport or httpx.HTTPTransport(uds=host[len("unix://"):])
            self.http = httpx.Client(base_url="http://docker", transport=tr, timeout=timeout)
        else:
            self.http = httpx.Client(base_url=host.replace("tcp://", "http://"),
                                     transport=transport, timeout=timeout)

    def _req(self, method: str, path: str, ok: tuple[int, ...] = (200, 201, 204),
             **kw: Any) -> httpx.Response:
        r = self.http.request(method, f"/{self.api}{path}", **kw)
        if r.status_code in ok:
            return r
        msg = r.text[:300]
        try:
            msg = r.json().get("message", msg)
        except Exception:
            pass
        if r.status_code == 409:
            raise Conflict(409, msg)
        raise DockerError(r.status_code, msg)

    @staticmethod
    def _filters(label_filters: list[str] | None, extra: dict | None = None) -> str:
        import json
        f: dict[str, Any] = dict(extra or {})
        if label_filters:
            f["label"] = label_filters
        return json.dumps(f)

    def ping(self) -> bool:
        try:
            return self.http.get("/_ping").status_code == 200
        except httpx.HTTPError:
            return False

    # exec (one command in a running container; output demultiplexed)
    def exec_run(self, name, cmd, *, user="", workdir="", timeout=60, env=None):
        body = {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True, "Tty": False}
        if env:
            body["Env"] = [f"{k}={v}" for k, v in env.items()]
        if user:
            body["User"] = user
        if workdir:
            body["WorkingDir"] = workdir
        eid = self._req("POST", f"/containers/{name}/exec", json=body).json()["Id"]
        r = self._req("POST", f"/exec/{eid}/start", json={"Detach": False, "Tty": False},
                      timeout=timeout + 15)
        out, err = _demux(r.content)
        info = self._req("GET", f"/exec/{eid}/json").json()
        return {"exit_code": info.get("ExitCode"), "stdout": out, "stderr": err}

    # containers
    def list_containers(self, label_filters=None):
        r = self._req("GET", "/containers/json",
                      params={"all": "true", "filters": self._filters(label_filters)})
        return r.json()

    def inspect_container(self, name):
        r = self._req("GET", f"/containers/{name}/json", ok=(200, 404))
        return r.json() if r.status_code == 200 else None

    def create_container(self, name, body):
        r = self._req("POST", "/containers/create", params={"name": name}, json=body)
        return r.json()["Id"]

    def start(self, name):
        self._req("POST", f"/containers/{name}/start", ok=(204, 304))

    def stop(self, name, timeout=10):
        self._req("POST", f"/containers/{name}/stop", params={"t": timeout}, ok=(204, 304),
                  timeout=timeout + 30)

    def restart(self, name, timeout=10):
        self._req("POST", f"/containers/{name}/restart", params={"t": timeout}, ok=(204,),
                  timeout=timeout + 60)

    def kill(self, name):
        self._req("POST", f"/containers/{name}/kill", ok=(204,))

    def pause(self, name):
        self._req("POST", f"/containers/{name}/pause", ok=(204,))

    def unpause(self, name):
        self._req("POST", f"/containers/{name}/unpause", ok=(204,))

    def remove_container(self, name, force=False):
        # v=false: anonymous volumes are never removed implicitly
        self._req("DELETE", f"/containers/{name}",
                  params={"force": str(force).lower(), "v": "false"}, ok=(204, 404))

    def container_stats(self, name):
        r = self._req("GET", f"/containers/{name}/stats",
                      params={"stream": "false", "one-shot": "true"}, ok=(200, 404, 409))
        return r.json() if r.status_code == 200 else None

    def top(self, name):
        r = self._req("GET", f"/containers/{name}/top", params={"ps_args": "-eo pid,user,args"},
                      ok=(200, 404, 409))
        return r.json() if r.status_code == 200 else None

    def container_logs(self, name, tail=200):
        r = self._req("GET", f"/containers/{name}/logs",
                      params={"stdout": "1", "stderr": "1", "tail": tail}, ok=(200, 404))
        return r.content.decode("utf-8", "replace") if r.status_code == 200 else ""

    # networks
    def list_networks(self, label_filters=None):
        return self._req("GET", "/networks", params={"filters": self._filters(label_filters)}).json()

    def inspect_network(self, name):
        r = self._req("GET", f"/networks/{name}", ok=(200, 404))
        return r.json() if r.status_code == 200 else None

    def create_network(self, body):
        r = self._req("POST", "/networks/create", json=body)
        return r.json()["Id"]

    def connect_network(self, network, container, ipv4=None, aliases=None):
        ep: dict[str, Any] = {}
        if ipv4:
            ep["IPAMConfig"] = {"IPv4Address": ipv4}
        if aliases:
            ep["Aliases"] = aliases
        self._req("POST", f"/networks/{network}/connect",
                  json={"Container": container, "EndpointConfig": ep}, ok=(200, 204))

    def disconnect_network(self, network, container):
        self._req("POST", f"/networks/{network}/disconnect",
                  json={"Container": container, "Force": True}, ok=(200, 204, 404))

    def remove_network(self, name):
        self._req("DELETE", f"/networks/{name}", ok=(204, 404))

    # volumes
    def list_volumes(self, label_filters=None):
        r = self._req("GET", "/volumes", params={"filters": self._filters(label_filters)})
        return r.json().get("Volumes") or []

    def inspect_volume(self, name):
        r = self._req("GET", f"/volumes/{name}", ok=(200, 404))
        return r.json() if r.status_code == 200 else None

    def create_volume(self, body):
        r = self._req("POST", "/volumes/create", json=body)
        return r.json()["Name"]

    def remove_volume(self, name, purge_of=None):
        self._req("DELETE", f"/volumes/{name}", ok=(204, 404))

    # images
    def inspect_image(self, ref):
        r = self._req("GET", f"/images/{ref}/json", ok=(200, 404))
        return r.json() if r.status_code == 200 else None


def _is_managed(labels: dict | None) -> bool:
    return (labels or {}).get(naming.LABEL_MANAGED) == "true"


class PolicyDockerClient:
    """Validating wrapper. All create bodies are checked; all mutations require rt.managed."""

    def __init__(self, inner: DockerClient, policy: Policy | None = None,
                 cfg: PolicyConfig | None = None):
        self.inner = inner
        self.policy = policy or Policy(cfg)

    # reads: always scoped to managed resources so foreign stacks stay invisible
    @staticmethod
    def _scoped(label_filters: list[str] | None) -> list[str]:
        return [f"{naming.LABEL_MANAGED}=true", *(label_filters or [])]

    def ping(self):
        return self.inner.ping()

    def list_containers(self, label_filters=None):
        return self.inner.list_containers(self._scoped(label_filters))

    def list_networks(self, label_filters=None):
        return self.inner.list_networks(self._scoped(label_filters))

    def list_volumes(self, label_filters=None):
        return self.inner.list_volumes(self._scoped(label_filters))

    def inspect_container(self, name):
        info = self.inner.inspect_container(name)
        if info is None:
            return None
        if not _is_managed((info.get("Config") or {}).get("Labels")):
            return None  # foreign containers do not exist for the RM
        return info

    def exec_run(self, name, cmd, *, user="", workdir="", timeout=60, env=None):
        if self.inspect_container(name) is None:  # only managed containers can be exec'd into
            raise DockerError(404, f"container {name} not found")
        return self.inner.exec_run(name, cmd, user=user, workdir=workdir, timeout=timeout, env=env)

    def inspect_network(self, name):
        info = self.inner.inspect_network(name)
        if info is None or not _is_managed(info.get("Labels")):
            return None
        return info

    def inspect_volume(self, name):
        info = self.inner.inspect_volume(name)
        if info is None or not _is_managed(info.get("Labels")):
            return None
        return info

    def inspect_image(self, ref):
        return self.inner.inspect_image(ref)

    def container_stats(self, name):
        self._require_container(name)
        return self.inner.container_stats(name)

    def container_logs(self, name, tail=200):
        self._require_container(name)
        return self.inner.container_logs(name, tail)

    def top(self, name):
        self._require_container(name)
        return self.inner.top(name)

    # creates are validated
    def create_container(self, name, body):
        self.policy.validate_container(name, body)
        return self.inner.create_container(name, body)

    def create_network(self, body):
        self.policy.validate_network(body)
        return self.inner.create_network(body)

    def create_volume(self, body):
        self.policy.validate_volume(body)
        return self.inner.create_volume(body)

    # mutations require managed
    def _require_container(self, name: str) -> dict:
        raw = self.inner.inspect_container(name)
        if raw is None:
            raise DockerError(404, f"no such container {name}")
        if not _is_managed((raw.get("Config") or {}).get("Labels")):
            raise NotManaged(name)
        return raw

    def start(self, name):
        self._require_container(name)
        self.inner.start(name)

    def stop(self, name, timeout=10):
        self._require_container(name)
        self.inner.stop(name, timeout)

    def restart(self, name, timeout=10):
        self._require_container(name)
        self.inner.restart(name, timeout)

    def kill(self, name):
        self._require_container(name)
        self.inner.kill(name)

    def pause(self, name):
        self._require_container(name)
        self.inner.pause(name)

    def unpause(self, name):
        self._require_container(name)
        self.inner.unpause(name)

    def remove_container(self, name, force=False):
        raw = self.inner.inspect_container(name)
        if raw is None:
            return
        if not _is_managed((raw.get("Config") or {}).get("Labels")):
            raise NotManaged(name)
        self.inner.remove_container(name, force)

    def connect_network(self, network, container, ipv4=None, aliases=None):
        if not str(network).startswith("rt-"):
            raise PolicyViolation("network_not_allowed", network)
        self._require_container(container)
        self.inner.connect_network(network, container, ipv4, aliases)

    def disconnect_network(self, network, container):
        self._require_container(container)
        self.inner.disconnect_network(network, container)

    def remove_network(self, name):
        info = self.inner.inspect_network(name)
        if info is None:
            return
        if not _is_managed(info.get("Labels")):
            raise NotManaged(name)
        self.inner.remove_network(name)

    def remove_volume(self, name, purge_of=None):
        info = self.inner.inspect_volume(name)
        if info is None:
            return
        labels = info.get("Labels") or {}
        if not _is_managed(labels):
            raise NotManaged(name)
        if not purge_of or labels.get(naming.LABEL_TENANT) != purge_of:
            raise PolicyViolation("volume_delete_without_purge", name)
        self.inner.remove_volume(name, purge_of)
