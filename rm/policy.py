"""Container/network/volume policy: everything outside the allowlist is rejected.

The RM builds every container spec from fixed templates (rm/templates.py). This module is the
second barrier: it validates the final Docker API body before it reaches the daemon, so a bug in a
template (or a compromised caller) cannot create a privileged or host-mounted container.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from . import naming


class PolicyViolation(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class NotManaged(PolicyViolation):
    def __init__(self, name: str):
        super().__init__("not_managed", f"resource {name} has no rt.managed=true label")


DIGEST_REF = re.compile(r"^(?:[a-z0-9][a-zA-Z0-9._/:-]*@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})$")
NAME_RE = re.compile(r"^rt-[a-z0-9][a-z0-9_.-]{0,80}$")
VOLUME_RE = re.compile(r"^rt-[a-z0-9][a-z0-9_.-]{0,80}$")

# Role -> capabilities that may be added back after cap-drop ALL.
ROLE_CAPS: dict[str, set[str]] = {
    naming.ROLE_EXECUTOR: set(),  # nothing added back after cap-drop ALL
    naming.ROLE_WORKER: {"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "KILL"},
    naming.ROLE_RUNTIME: {"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "KILL"},
    # apt and sshd privilege separation need these nine; nothing else.
    naming.ROLE_WORKSPACE: {"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "KILL",
                            "SYS_CHROOT", "AUDIT_WRITE", "NET_BIND_SERVICE"},
}

ALLOWED_HOSTCONFIG_KEYS = {
    "Binds", "Mounts", "NetworkMode", "RestartPolicy", "Memory", "MemorySwap",
    "MemoryReservation", "NanoCpus", "CpuShares", "PidsLimit", "BlkioWeight",
    "BlkioDeviceReadBps", "BlkioDeviceWriteBps", "CapDrop", "CapAdd", "SecurityOpt",
    "ReadonlyRootfs", "Tmpfs", "Ulimits", "LogConfig", "OomScoreAdj", "Init",
    "Privileged", "PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode",
    "Devices", "DeviceCgroupRules", "DeviceRequests", "PortBindings", "PublishAllPorts",
    "Sysctls", "ExtraHosts", "Dns", "DnsSearch", "CgroupParent", "StorageOpt", "ShmSize",
    "AutoRemove", "VolumesFrom", "Links", "Runtime", "OomKillDisable", "CpuPeriod", "CpuQuota",
}

PUBLIC_ENV = {"RT_AUTHORIZED_KEYS"}  # public keys only
FORBIDDEN_SECURITY_OPT = ("unconfined", "label=disable", "label:disable", "systempaths")
ALLOWED_TOP_KEYS = {
    "Image", "Cmd", "Entrypoint", "Env", "Labels", "User", "WorkingDir", "Hostname",
    "Healthcheck", "HostConfig", "NetworkingConfig", "StopTimeout", "StopSignal",
    "ExposedPorts", "Tty", "OpenStdin", "AttachStdin", "AttachStdout", "AttachStderr",
}


@dataclass
class PolicyConfig:
    tenants_root: str = "/srv/tenants"
    hermes_root: str = "/srv/hermes"
    executor_root: str = "/srv/executor"
    allowed_image_prefixes: list[str] = field(default_factory=list)
    require_limits: bool = True


def _norm(path: str) -> str:
    if not path.startswith("/"):
        raise PolicyViolation("bind_not_absolute", path)
    if ".." in path.split("/"):
        raise PolicyViolation("bind_path_traversal", path)
    return posixpath.normpath(path)


def _under(path: str, root: str) -> bool:
    root = root.rstrip("/")
    return path == root or path.startswith(root + "/")


class Policy:
    def __init__(self, cfg: PolicyConfig | None = None):
        self.cfg = cfg or PolicyConfig()

    # ----- shared pieces -------------------------------------------------------------
    def check_image(self, image: str) -> None:
        if not image or not DIGEST_REF.match(image):
            raise PolicyViolation("image_not_pinned", f"image must carry @sha256 digest: {image!r}")
        pre = self.cfg.allowed_image_prefixes
        if pre and not any(image.startswith(p) or image.startswith("sha256:") for p in pre):
            raise PolicyViolation("image_not_allowed", image)

    def check_bind_source(self, src: str, tenant: str | None, role: str) -> None:
        if src.startswith("/"):
            p = _norm(src)
            if p in ("/", "/var/run/docker.sock", "/run/docker.sock") or "docker.sock" in p:
                raise PolicyViolation("bind_outside_allowlist", p)
            ok = False
            if tenant and _under(p, f"{self.cfg.tenants_root.rstrip('/')}/{tenant}"):
                ok = True
            root = self.cfg.executor_root.rstrip("/")
            if role == naming.ROLE_EXECUTOR and p != root and _under(p, root):
                ok = True
            if _under(p, self.cfg.hermes_root.rstrip("/")) and role in (
                    naming.ROLE_WORKER, naming.ROLE_RUNTIME):
                ok = True
            if not ok:
                raise PolicyViolation("bind_outside_allowlist", p)
            return
        # named volume
        if not VOLUME_RE.match(src):
            raise PolicyViolation("volume_name_not_allowed", src)

    # ----- container create ------------------------------------------------------------
    def validate_container(self, name: str, body: dict) -> None:
        if not NAME_RE.match(name or ""):
            raise PolicyViolation("name_not_allowed", name)
        unknown_top = set(body) - ALLOWED_TOP_KEYS
        if unknown_top:
            raise PolicyViolation("unknown_field", ",".join(sorted(unknown_top)))
        labels = body.get("Labels") or {}
        if labels.get(naming.LABEL_MANAGED) != "true":
            raise PolicyViolation("missing_managed_label")
        role = labels.get(naming.LABEL_ROLE, "")
        if role not in ROLE_CAPS:
            raise PolicyViolation("bad_role", role)
        tenant = labels.get(naming.LABEL_TENANT)
        if role in (naming.ROLE_RUNTIME, naming.ROLE_WORKSPACE):
            if not tenant or not naming.valid_tenant(tenant):
                raise PolicyViolation("bad_tenant_label", str(tenant))
            if tenant not in name:
                raise PolicyViolation("name_tenant_mismatch", name)
        self.check_image(body.get("Image", ""))
        hc = body.get("HostConfig")
        if not isinstance(hc, dict):
            raise PolicyViolation("missing_hostconfig")
        unknown = set(hc) - ALLOWED_HOSTCONFIG_KEYS
        if unknown:
            raise PolicyViolation("unknown_hostconfig_field", ",".join(sorted(unknown)))
        if hc.get("Privileged"):
            raise PolicyViolation("privileged")
        for key, code in (("PidMode", "host_pid"), ("IpcMode", "host_ipc"),
                          ("UTSMode", "host_uts"), ("UsernsMode", "host_userns")):
            if hc.get(key) not in (None, "", "private"):
                raise PolicyViolation(code, str(hc.get(key)))
        if hc.get("CgroupnsMode") not in (None, "", "private"):
            raise PolicyViolation("host_cgroupns", str(hc.get("CgroupnsMode")))
        nm = hc.get("NetworkMode")
        if role == naming.ROLE_EXECUTOR:
            # the executor is the one role that must have NO network at all
            if nm != "none":
                raise PolicyViolation("executor_needs_no_network", str(nm))
            if not hc.get("ReadonlyRootfs"):
                raise PolicyViolation("executor_needs_readonly_rootfs")
            if body.get("NetworkingConfig", {}).get("EndpointsConfig"):
                raise PolicyViolation("executor_needs_no_network")
        elif not nm or not str(nm).startswith("rt-"):
            raise PolicyViolation("network_mode_not_allowed", str(nm))
        if hc.get("Devices"):
            raise PolicyViolation("devices")
        if hc.get("DeviceCgroupRules") or hc.get("DeviceRequests"):
            raise PolicyViolation("devices")
        if hc.get("PortBindings") or hc.get("PublishAllPorts"):
            raise PolicyViolation("published_ports")
        if hc.get("VolumesFrom") or hc.get("Links"):
            raise PolicyViolation("volumes_from_or_links")
        if hc.get("Sysctls"):
            raise PolicyViolation("sysctls")
        if hc.get("CgroupParent") and not str(hc["CgroupParent"]).startswith("rt"):
            raise PolicyViolation("cgroup_parent")
        if hc.get("Runtime") not in (None, "", "runc"):
            raise PolicyViolation("runtime_not_allowed", str(hc["Runtime"]))
        if hc.get("OomKillDisable"):
            raise PolicyViolation("oom_kill_disable")
        caps_add = set(hc.get("CapAdd") or [])
        extra = {c.upper().removeprefix("CAP_") for c in caps_add} - ROLE_CAPS[role]
        if extra:
            raise PolicyViolation("extra_caps", ",".join(sorted(extra)))
        if "ALL" not in {c.upper() for c in (hc.get("CapDrop") or [])}:
            raise PolicyViolation("cap_drop_all_missing")
        sec = [str(s) for s in (hc.get("SecurityOpt") or [])]
        if not any(s in ("no-new-privileges", "no-new-privileges:true",
                         "no-new-privileges=true") for s in sec):
            raise PolicyViolation("no_new_privileges_missing")
        if any(any(bad in s for bad in FORBIDDEN_SECURITY_OPT) for s in sec):
            raise PolicyViolation("security_opt_unconfined")
        if self.cfg.require_limits:
            if not hc.get("Memory") or hc["Memory"] <= 0:
                raise PolicyViolation("limit_memory_missing")
            if not hc.get("PidsLimit") or hc["PidsLimit"] <= 0:
                raise PolicyViolation("limit_pids_missing")
            if not hc.get("NanoCpus") or hc["NanoCpus"] <= 0:
                raise PolicyViolation("limit_cpu_missing")
        for b in hc.get("Binds") or []:
            parts = str(b).split(":")
            if len(parts) < 2:
                raise PolicyViolation("bind_malformed", str(b))
            self.check_bind_source(parts[0], tenant, role)
            if "docker.sock" in parts[1]:
                raise PolicyViolation("bind_outside_allowlist", str(b))
        for m in hc.get("Mounts") or []:
            typ = m.get("Type")
            if typ == "tmpfs":
                continue
            if typ == "bind":
                self.check_bind_source(str(m.get("Source", "")), tenant, role)
            elif typ == "volume":
                src = str(m.get("Source", ""))
                if not VOLUME_RE.match(src):
                    raise PolicyViolation("volume_name_not_allowed", src)
                vo = m.get("VolumeOptions") or {}
                if vo.get("DriverConfig"):
                    raise PolicyViolation("volume_driver_opts")
            else:
                raise PolicyViolation("mount_type_not_allowed", str(typ))
        # Network config must only reference rt-* networks
        for net in ((body.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}):
            if not str(net).startswith("rt-"):
                raise PolicyViolation("network_not_allowed", str(net))
        env_names = [e.split("=", 1)[0] for e in (body.get("Env") or [])]
        if role == naming.ROLE_WORKSPACE and any(
                re.search(r"KEY|SECRET|TOKEN|PASSWORD", n, re.I) and n not in PUBLIC_ENV
                for n in env_names):
            raise PolicyViolation("secret_in_workspace_env")

    # ----- network / volume ------------------------------------------------------------
    def validate_network(self, body: dict) -> None:
        name = body.get("Name", "")
        if not NAME_RE.match(name):
            raise PolicyViolation("network_name_not_allowed", name)
        if body.get("Driver") not in (None, "", "bridge"):
            raise PolicyViolation("network_driver_not_allowed", str(body.get("Driver")))
        if (body.get("Labels") or {}).get(naming.LABEL_MANAGED) != "true":
            raise PolicyViolation("missing_managed_label")
        if body.get("Attachable") or body.get("Ingress") or body.get("ConfigFrom"):
            raise PolicyViolation("network_option_not_allowed")
        for k, v in (body.get("Options") or {}).items():
            if k.startswith("com.docker.network.bridge.") or k == "com.docker.network.driver.mtu":
                continue
            raise PolicyViolation("network_option_not_allowed", f"{k}={v}")

    def validate_volume(self, body: dict) -> None:
        name = body.get("Name", "")
        if not VOLUME_RE.match(name):
            raise PolicyViolation("volume_name_not_allowed", name)
        if body.get("Driver") not in (None, "", "local"):
            raise PolicyViolation("volume_driver_not_allowed", str(body.get("Driver")))
        if body.get("DriverOpts"):
            # local driver DriverOpts can bind arbitrary host paths (type=none,o=bind,device=/)
            raise PolicyViolation("volume_driver_opts")
        if (body.get("Labels") or {}).get(naming.LABEL_MANAGED) != "true":
            raise PolicyViolation("missing_managed_label")
