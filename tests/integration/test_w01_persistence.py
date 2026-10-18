"""W1: apt packages, files and a supervised service survive restart AND container recreation."""
from __future__ import annotations

import time

from rm import naming
from tests.integration.harness import docker, exec_in, inspect, ssh, wait_until


def sh(rm, t, cmd, timeout=120):
    r = ssh(rm.stack.ws_ref, rm.keys[t], rm.hub_ip(t), cmd, timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def test_w1_workspace_container_follows_the_template(rm):
    t = rm.name("qaw1a")
    rm.tenant("qaw1a")
    rm.ws_ready(t)
    info = inspect(naming.workspace_name(t))
    hc = info["HostConfig"]
    assert hc["Privileged"] is False and hc["CapDrop"] == ["ALL"]
    assert sorted(hc["CapAdd"]) == sorted(["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER",
                                           "KILL", "SYS_CHROOT", "AUDIT_WRITE", "NET_BIND_SERVICE"])
    assert "no-new-privileges" in hc["SecurityOpt"][0]
    assert hc["Memory"] == hc["MemorySwap"] == 1024**3 and hc["PidsLimit"] == 512
    assert info["Config"]["Labels"]["rt.managed"] == "true"
    assert not info["Mounts"] or all(m["Source"].startswith(rm.settings.tenants_root)
                                     for m in info["Mounts"])
    assert hc["Dns"] == ["1.1.1.1", "9.9.9.9"]
    env = "\n".join(info["Config"]["Env"])
    assert "PRIVATE KEY" not in env and "ssh-ed25519" in env


def test_w1_ssh_works_with_the_tenant_key_only(rm):
    t = rm.name("qaw1b")
    rm.tenant("qaw1b")
    rm.ws_ready(t)
    rc, out = sh(rm, t, "whoami; pwd")
    assert rc == 0 and out.splitlines() == ["root", "/home/ws"]
    # another tenant's key (or a random one) is refused
    from rm.sshkeys import generate_keypair
    other, _ = generate_keypair()
    r = ssh(rm.stack.ws_ref, other, rm.hub_ip(t), "true")
    assert r.returncode != 0 and "Permission denied" in r.stderr
    # password login is off
    rc, out = sh(rm, t, "grep -E '^(PasswordAuthentication|PermitRootLogin|AllowTcpForwarding)' "
                        "/etc/ssh/sshd_config")
    assert "PasswordAuthentication no" in out and "PermitRootLogin prohibit-password" in out
    assert "AllowTcpForwarding no" in out


def test_w1_apt_file_and_service_survive_restart_and_recreation(rm):
    t = rm.name("qaw1c")
    rm.tenant("qaw1c")
    rm.ws_ready(t)
    c = naming.workspace_name(t)

    rc, out = sh(rm, t, "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1 "
                        "&& apt-get install -y -qq jq >/dev/null 2>&1 && jq --version "
                        "&& cat /var/lib/rt/packages.list")
    assert rc == 0, out
    assert "jq-" in out and out.splitlines()[-1] == "jq"
    rc, out = sh(rm, t, "echo persisted > /workspace/note.txt && "
                        "rt-service add web --cwd /workspace -- python3 -m http.server 8000 && "
                        "sleep 2 && curl -fsS localhost:8000/note.txt")
    assert rc == 0 and out.endswith("persisted"), out

    # --- docker restart: same container, supervisor brings the service back
    docker("restart", "-t", "10", c)
    rm.ws_ready(t)
    wait_until(lambda: exec_in(c, "curl -fsS localhost:8000/note.txt").stdout.strip() == "persisted",
               30, 1, "service back after restart")
    assert exec_in(c, "jq --version").returncode == 0

    # --- recreation: new generation, new container, same volumes
    old_id = inspect(c)["Id"]
    row = rm.store.get_tenant(t)
    rm.store.update_tenant(t, generation=row["generation"] + 1)
    rm.svc.reconcile_tenant(t)
    assert inspect(c)["Id"] != old_id
    assert inspect(c)["Config"]["Labels"]["rt.generation"] == str(row["generation"] + 1)
    rm.ws_ready(t)
    assert exec_in(c, "cat /workspace/note.txt").stdout.strip() == "persisted"       # bind data
    wait_until(lambda: exec_in(c, "curl -fsS localhost:8000/note.txt").stdout.strip() == "persisted",
               30, 1, "service back after recreation")                                # s6 tree
    # jq was reinstalled from /var/lib/rt/packages.list by the boot job
    wait_until(lambda: exec_in(c, "jq --version").returncode == 0, 120, 2, "apt package restored")
    assert "restored" in exec_in(c, "cat /var/lib/rt/log/packages.log").stdout


def test_w1_supervisor_restarts_killed_service_within_5s(rm):
    t = rm.name("qaw1d")
    rm.tenant("qaw1d")
    rm.ws_ready(t)
    c = naming.workspace_name(t)
    sh(rm, t, "rt-service add web --cwd /workspace -- python3 -m http.server 8000")
    wait_until(lambda: exec_in(c, "curl -fsS localhost:8000/").returncode == 0, 20, 0.5, "up")
    pid1 = exec_in(c, "pgrep -f 'http.server 8000'").stdout.split()[0]
    t0 = time.monotonic()
    exec_in(c, f"kill -9 {pid1}")
    wait_until(lambda: exec_in(c, "curl -fsS localhost:8000/").returncode == 0, 10, 0.25, "respawn")
    assert time.monotonic() - t0 < 5
    pid2 = exec_in(c, "pgrep -f 'http.server 8000'").stdout.split()[0]
    assert pid2 != pid1
    # service run as the unprivileged account, not root
    assert exec_in(c, f"ps -o user= -p {pid2}").stdout.strip() == "ws"
    # removing a service stops it for good
    sh(rm, t, "rt-service rm web")
    wait_until(lambda: exec_in(c, "curl -fsS localhost:8000/").returncode != 0, 10, 0.5, "gone")


def test_w1_host_key_is_pinned_across_recreation(rm):
    t = rm.name("qaw1e")
    rm.tenant("qaw1e")
    rm.ws_ready(t)
    c = naming.workspace_name(t)
    k1 = exec_in(c, "cat /var/lib/rt/ssh/ssh_host_ed25519_key.pub").stdout
    rm.store.update_tenant(t, generation=2)
    rm.svc.reconcile_tenant(t)
    rm.ws_ready(t)
    assert exec_in(c, "cat /var/lib/rt/ssh/ssh_host_ed25519_key.pub").stdout == k1 != ""
