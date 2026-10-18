"""Negative suite for the body policy (spec 04 3.1 item 5, annex 1.2).

Every template output must pass; every dangerous mutation of it must be refused with a precise
code. A refusal here means the request never reaches the Docker daemon.
"""
from __future__ import annotations

import copy

import pytest

from rm import naming, templates
from rm.policy import Policy, PolicyConfig, PolicyViolation
from tests.conftest import EXEC_IMAGE, POOL_IMAGE, RT_IMAGE, WS_IMAGE, digest, make_settings


@pytest.fixture
def pol():
    return Policy(PolicyConfig(tenants_root="/srv/tenants", hermes_root="/srv/hermes",
                               executor_root="/srv/executor"))


@pytest.fixture
def st(tmp_path):
    return make_settings(tmp_path)


def ws_body(st):
    return "rt-ws-acme1", templates.workspace_spec(st, "acme1", WS_IMAGE, 1, "ssh-ed25519 AAAA k",
                                                   "standard", ["10.0.0.0/28"])


def rt_body(st):
    return "rt-hermes-acme1", templates.runtime_spec(st, "acme1", RT_IMAGE, 1, "k" * 64)


def worker_body(st):
    return "rt-pool-w1", templates.worker_spec(st, "w1", POOL_IMAGE, 1)


def exec_body(st):
    from rm.executor import ExecutorRunner
    r = ExecutorRunner(st, None)
    return "rt-exec-0123456789ab", r.build_body("0123456789abcdef", 30, 256, 1.0)


@pytest.mark.parametrize("factory", [ws_body, rt_body, worker_body, exec_body])
def test_templates_pass_policy(pol, st, factory):
    name, body = factory(st)
    pol.validate_container(name, body)


def mutate(factory, st, fn):
    name, body = factory(st)
    body = copy.deepcopy(body)
    fn(body)
    return name, body


def hc(b):
    return b["HostConfig"]


CASES = [
    # (id, mutation, expected code)
    ("privileged", lambda b: hc(b).update(Privileged=True), "privileged"),
    ("host_net", lambda b: hc(b).update(NetworkMode="host"), "network_mode_not_allowed"),
    ("bridge_net", lambda b: hc(b).update(NetworkMode="bridge"), "network_mode_not_allowed"),
    ("foreign_net", lambda b: hc(b).update(NetworkMode="public"), "network_mode_not_allowed"),
    ("container_net", lambda b: hc(b).update(NetworkMode="container:traefik"),
     "network_mode_not_allowed"),
    ("host_pid", lambda b: hc(b).update(PidMode="host"), "host_pid"),
    ("host_ipc", lambda b: hc(b).update(IpcMode="host"), "host_ipc"),
    ("host_uts", lambda b: hc(b).update(UTSMode="host"), "host_uts"),
    ("host_userns", lambda b: hc(b).update(UsernsMode="host"), "host_userns"),
    ("host_cgroupns", lambda b: hc(b).update(CgroupnsMode="host"), "host_cgroupns"),
    ("device", lambda b: hc(b).update(Devices=[{"PathOnHost": "/dev/sda"}]), "devices"),
    ("device_rules", lambda b: hc(b).update(DeviceCgroupRules=["a *:* rwm"]), "devices"),
    ("gpu", lambda b: hc(b).update(DeviceRequests=[{"Driver": "nvidia"}]), "devices"),
    ("ports", lambda b: hc(b).update(PortBindings={"22/tcp": [{"HostPort": "22"}]}),
     "published_ports"),
    ("publish_all", lambda b: hc(b).update(PublishAllPorts=True), "published_ports"),
    ("volumes_from", lambda b: hc(b).update(VolumesFrom=["traefik"]), "volumes_from_or_links"),
    ("links", lambda b: hc(b).update(Links=["db:db"]), "volumes_from_or_links"),
    ("sysctl", lambda b: hc(b).update(Sysctls={"net.ipv4.ip_forward": "1"}), "sysctls"),
    ("runtime_nvidia", lambda b: hc(b).update(Runtime="nvidia"), "runtime_not_allowed"),
    ("oom_disable", lambda b: hc(b).update(OomKillDisable=True), "oom_kill_disable"),
    ("cgroup_parent", lambda b: hc(b).update(CgroupParent="/system.slice"), "cgroup_parent"),
    ("cap_sys_admin", lambda b: hc(b).update(CapAdd=["SYS_ADMIN"]), "extra_caps"),
    ("cap_net_admin", lambda b: hc(b).update(CapAdd=["NET_ADMIN", "CHOWN"]), "extra_caps"),
    ("cap_all", lambda b: hc(b).update(CapAdd=["ALL"]), "extra_caps"),
    ("cap_prefix", lambda b: hc(b).update(CapAdd=["CAP_SYS_PTRACE"]), "extra_caps"),
    ("no_cap_drop", lambda b: hc(b).update(CapDrop=[]), "cap_drop_all_missing"),
    ("no_nnp", lambda b: hc(b).update(SecurityOpt=[]), "no_new_privileges_missing"),
    ("seccomp_off", lambda b: hc(b).update(SecurityOpt=["no-new-privileges", "seccomp=unconfined"]),
     "security_opt_unconfined"),
    ("apparmor_off", lambda b: hc(b).update(
        SecurityOpt=["no-new-privileges", "apparmor=unconfined"]), "security_opt_unconfined"),
    ("label_disable", lambda b: hc(b).update(SecurityOpt=["no-new-privileges", "label=disable"]),
     "security_opt_unconfined"),
    ("unknown_hostconfig", lambda b: hc(b).update(MaskedPaths=[]), "unknown_hostconfig_field"),
    ("unknown_top", lambda b: b.update(Domainname="x"), "unknown_field"),
    ("no_limits_mem", lambda b: hc(b).update(Memory=0), "limit_memory_missing"),
    ("no_limits_pids", lambda b: hc(b).pop("PidsLimit"), "limit_pids_missing"),
    ("no_limits_cpu", lambda b: hc(b).update(NanoCpus=0), "limit_cpu_missing"),
    ("tag_not_digest", lambda b: b.update(Image="debian:13-slim"), "image_not_pinned"),
    ("latest", lambda b: b.update(Image="rt-workspace:latest"), "image_not_pinned"),
    ("short_digest", lambda b: b.update(Image="x@sha256:abc"), "image_not_pinned"),
    ("no_hostconfig", lambda b: b.pop("HostConfig"), "missing_hostconfig"),
    ("no_managed_label", lambda b: b["Labels"].pop("rt.managed"), "missing_managed_label"),
    ("bad_role", lambda b: b["Labels"].update({"rt.role": "root"}), "bad_role"),
]
# cases that make no sense for the no-network executor are skipped by role
EXEC_SKIP = {"host_net", "bridge_net", "foreign_net", "container_net"}


@pytest.mark.parametrize("factory", [ws_body, rt_body, worker_body, exec_body])
@pytest.mark.parametrize("cid,fn,code", CASES, ids=[c[0] for c in CASES])
def test_dangerous_mutation_refused(pol, st, factory, cid, fn, code):
    if factory is exec_body and cid in EXEC_SKIP:
        code = "executor_needs_no_network"
    if factory is exec_body and cid == "cap_sys_admin":
        code = "extra_caps"
    name, body = mutate(factory, st, fn)
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == code


BIND_CASES = [
    ("root", "/:/host", "bind_outside_allowlist"),
    ("docker_sock", "/var/run/docker.sock:/var/run/docker.sock", "bind_outside_allowlist"),
    ("run_sock", "/run/docker.sock:/s", "bind_outside_allowlist"),
    ("etc", "/etc:/etc:ro", "bind_outside_allowlist"),
    ("proc", "/proc:/hostproc", "bind_outside_allowlist"),
    ("other_tenant", "/srv/tenants/beta1/ws/home:/home/ws", "bind_outside_allowlist"),
    ("tenants_root", "/srv/tenants:/t", "bind_outside_allowlist"),
    ("prefix_trick", "/srv/tenants/acme1-evil/ws:/w", "bind_outside_allowlist"),
    ("traversal", "/srv/tenants/acme1/../beta1/ws:/w", "bind_path_traversal"),
    ("relative", "./data:/data", "volume_name_not_allowed"),
    ("foreign_volume", "traefik-data:/data", "volume_name_not_allowed"),
    ("hermes_root_for_ws", "/srv/hermes/profiles:/p", "bind_outside_allowlist"),
    ("sock_dest", "/srv/tenants/acme1/ws/home:/var/run/docker.sock", "bind_outside_allowlist"),
    ("malformed", "justonepart", "bind_malformed"),
]


@pytest.mark.parametrize("cid,bind,code", BIND_CASES, ids=[c[0] for c in BIND_CASES])
def test_workspace_bind_mounts_are_confined(pol, st, cid, bind, code):
    name, body = mutate(ws_body, st, lambda b: hc(b)["Binds"].append(bind))
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == code


def test_runtime_may_use_hermes_root_but_workspace_may_not(pol, st):
    name, body = mutate(rt_body, st, lambda b: hc(b)["Binds"].append("/srv/hermes/ssh/acme1:/k:ro"))
    pol.validate_container(name, body)
    name, body = mutate(ws_body, st, lambda b: hc(b)["Binds"].append("/srv/hermes/ssh/acme1:/k:ro"))
    with pytest.raises(PolicyViolation):
        pol.validate_container(name, body)


@pytest.mark.parametrize("mount,code", [
    ({"Type": "bind", "Source": "/", "Target": "/h"}, "bind_outside_allowlist"),
    ({"Type": "npipe", "Source": "x", "Target": "/p"}, "mount_type_not_allowed"),
    ({"Type": "volume", "Source": "rt-v", "Target": "/v",
      "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"device": "/"}}}},
     "volume_driver_opts"),
    ({"Type": "volume", "Source": "pg-data", "Target": "/v"}, "volume_name_not_allowed"),
])
def test_mounts_are_confined(pol, st, mount, code):
    name, body = mutate(ws_body, st, lambda b: hc(b).update(Mounts=[mount]))
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == code


def test_tenant_label_must_match_name_and_be_valid(pol, st):
    name, body = mutate(ws_body, st, lambda b: b["Labels"].update({"rt.tenant": "beta1"}))
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == "name_tenant_mismatch"
    name, body = mutate(ws_body, st, lambda b: b["Labels"].update({"rt.tenant": "BAD!"}))
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == "bad_tenant_label"


@pytest.mark.parametrize("name", ["traefik", "evolution-api", "rt_ws", "rt-", "rt-ws acme1",
                                  "rt-ws-acme1;x", "../rt-ws-x"])
def test_container_names_outside_rt_prefix_refused(pol, st, name):
    _, body = ws_body(st)
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == "name_not_allowed"


def test_workspace_cannot_carry_secrets_in_env(pol, st):
    for var in ("API_KEY", "LITELLM_MASTER_KEY", "DB_PASSWORD", "GITHUB_TOKEN", "CLIENT_SECRET"):
        name, body = mutate(ws_body, st, lambda b, v=var: b["Env"].append(f"{v}=x"))
        with pytest.raises(PolicyViolation) as e:
            pol.validate_container(name, body)
        assert e.value.code == "secret_in_workspace_env"


def test_networking_config_must_stay_in_rt_namespace(pol, st):
    name, body = mutate(ws_body, st, lambda b: b["NetworkingConfig"]["EndpointsConfig"].update(
        {"public": {}}))
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == "network_not_allowed"


def test_executor_may_not_get_a_network_even_via_networking_config(pol, st):
    name, body = mutate(exec_body, st, lambda b: b.update(
        NetworkingConfig={"EndpointsConfig": {"rt-net-acme1": {}}}))
    with pytest.raises(PolicyViolation):
        pol.validate_container(name, body)


def test_executor_binds_only_under_its_root(pol, st):
    name, body = mutate(exec_body, st, lambda b: hc(b)["Binds"].append("/srv/tenants/acme1:/t"))
    with pytest.raises(PolicyViolation) as e:
        pol.validate_container(name, body)
    assert e.value.code == "bind_outside_allowlist"
    name, body = mutate(exec_body, st, lambda b: hc(b)["Binds"].append("/srv/executor:/all"))
    with pytest.raises(PolicyViolation):    # the root itself, not a run directory
        pol.validate_container(name, body)


def test_image_prefix_allowlist(st):
    p = Policy(PolicyConfig(allowed_image_prefixes=["ghcr.io/rangeltech/"]))
    p.check_image("ghcr.io/rangeltech/rt-workspace@sha256:" + "a" * 64)
    with pytest.raises(PolicyViolation) as e:
        p.check_image("docker.io/evil/img@sha256:" + "a" * 64)
    assert e.value.code == "image_not_allowed"


def test_image_id_form_is_accepted(pol):
    pol.check_image("sha256:" + "b" * 64)


# ----- networks and volumes ----------------------------------------------------------------
def test_network_policy(pol):
    ok = templates.tenant_network("acme1", 0)
    pol.validate_network(ok)
    for mut, code in [
        ({"Name": "public"}, "network_name_not_allowed"),
        ({"Driver": "macvlan"}, "network_driver_not_allowed"),
        ({"Driver": "overlay"}, "network_driver_not_allowed"),
        ({"Attachable": True}, "network_option_not_allowed"),
        ({"Options": {"parent": "eth0"}}, "network_option_not_allowed"),
        ({"Labels": {}}, "missing_managed_label"),
    ]:
        with pytest.raises(PolicyViolation) as e:
            pol.validate_network({**ok, **mut})
        assert e.value.code == code


def test_volume_policy(pol):
    ok = {"Name": "rt-hermes-acme1-data", "Labels": naming.labels(naming.ROLE_VOLUME, "acme1")}
    pol.validate_volume(ok)
    for mut, code in [
        ({"Name": "pgdata"}, "volume_name_not_allowed"),
        ({"Driver": "nfs"}, "volume_driver_not_allowed"),
        # the local driver can bind any host path through DriverOpts
        ({"DriverOpts": {"type": "none", "o": "bind", "device": "/"}}, "volume_driver_opts"),
        ({"Labels": {}}, "missing_managed_label"),
    ]:
        with pytest.raises(PolicyViolation) as e:
            pol.validate_volume({**ok, **mut})
        assert e.value.code == code


def test_digest_helper():
    assert naming.image_digest(digest("x")).startswith("sha256:")
    assert naming.image_digest("debian:13") == ""
    assert EXEC_IMAGE != WS_IMAGE
