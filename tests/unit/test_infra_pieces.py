"""HTTP docker client, nft ruleset, xfs quota, backup backends, abuse monitor."""
from __future__ import annotations

import json
import sqlite3
import tarfile
from pathlib import Path

import httpx
import pytest

from rm import naming, nft, quota, templates
from rm.abuse import AbuseMonitor, miner_in_process
from rm.backup import BackupError, LocalBackupBackend, ResticBackupBackend, sqlite_online_backup
from rm.docker_client import Conflict, DockerError, HttpDockerClient


# ----- HttpDockerClient against a mock transport ------------------------------------------------
def client_with(handler):
    return HttpDockerClient("http://proxy:2375", "v1.43", transport=httpx.MockTransport(handler))


def test_http_client_paths_params_and_conflict():
    seen = []

    def h(req: httpx.Request):
        seen.append((req.method, req.url.path, dict(req.url.params)))
        if req.url.path.endswith("/containers/create"):
            if req.url.params["name"] == "dup":
                return httpx.Response(409, json={"message": "Conflict. name in use"})
            return httpx.Response(201, json={"Id": "abc"})
        if req.url.path.endswith("/json") and "ghost" in req.url.path:
            return httpx.Response(404, json={"message": "no such"})
        return httpx.Response(204)

    c = client_with(h)
    assert c.create_container("x", {"Image": "i"}) == "abc"
    with pytest.raises(Conflict):
        c.create_container("dup", {})
    assert c.inspect_container("ghost") is None
    c.start("x")
    c.stop("x", 7)
    c.remove_container("x")
    assert ("POST", "/v1.43/containers/x/stop", {"t": "7"}) in seen
    assert ("DELETE", "/v1.43/containers/x", {"force": "false", "v": "false"}) in seen


def test_http_client_error_mapping_and_ping():
    c = client_with(lambda r: httpx.Response(500, json={"message": "boom"}))
    with pytest.raises(DockerError) as e:
        c.start("x")
    assert e.value.status == 500 and "boom" in e.value.message
    assert client_with(lambda r: httpx.Response(200, text="OK")).ping() is True
    assert client_with(lambda r: httpx.Response(500)).ping() is False


def test_http_client_only_uses_verbs_the_proxy_allows():
    """The documented proxy allows CONTAINERS NETWORKS VOLUMES IMAGES POST; EXEC, BUILD, SYSTEM,
    SERVICES, SECRETS and friends stay off. No path of the client may touch them."""
    seen = []

    def h(req):
        seen.append(req.url.path)
        return httpx.Response(200, json=[] if "json" in req.url.path or "volumes" in
                              req.url.path or "networks" in req.url.path else {"Volumes": []})
    c = client_with(h)
    for fn in (c.ping, lambda: c.list_containers(), lambda: c.inspect_container("a"),
               lambda: c.start("a"), lambda: c.pause("a"), lambda: c.container_stats("a"),
               lambda: c.container_logs("a"), lambda: c.top("a"), lambda: c.list_networks(),
               lambda: c.inspect_network("n"), lambda: c.connect_network("n", "a"),
               lambda: c.list_volumes(), lambda: c.inspect_image("i")):
        try:
            fn()
        except Exception:
            pass
    banned = ("/exec", "/build", "/commit", "/system", "/services", "/swarm", "/secrets",
              "/plugins", "/auth", "/session", "/info")
    assert seen and not [p for p in seen if any(b in p for b in banned)]


def test_policy_client_scopes_every_list_to_managed():
    calls = []

    class Inner:
        def list_containers(self, f=None):
            calls.append(f)
            return []
    from rm.docker_client import PolicyDockerClient
    PolicyDockerClient(Inner()).list_containers(["rt.role=workspace"])  # type: ignore[arg-type]
    assert calls == [["rt.managed=true", "rt.role=workspace"]]


# ----- nft --------------------------------------------------------------------------------------
def rules(**kw):
    return nft.render(nft.FirewallInput(
        tenants=[nft.tenant_net_for("acme1", 0), nft.tenant_net_for("beta1", 1, killed=True)],
        worker_ips=[naming.hub_worker_ip(1)], **kw))


def test_nft_blocks_what_the_spec_says():
    r = rules()
    for must in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"):
        assert must in r
    fwd = r[r.index("chain forward"):]
    for port in (25, 465, 587, 22, 23, 445, 3389, 6667):
        assert str(port) in fwd.split("tcp dport { 22")[1].split("}")[0] or str(port) in fwd
    assert "ip saddr @ws_egress ip daddr @ws_egress counter drop" in fwd          # tenant to tenant
    assert "ip saddr @ws_hub ip daddr @ws_hub counter drop" in fwd                # hub: ws to ws
    assert "ip saddr @ws_hub ip daddr @workers counter drop" in fwd               # ws never calls a worker
    assert "ip saddr @workers ip daddr @ws_hub tcp dport 22 accept" in fwd


def test_nft_bridge_table_isolates_workspaces_at_layer_2():
    r = rules()
    br = r[r.index("table bridge rt_br"):]
    ws = f"{naming.HUB_WS_FIRST}-{naming.HUB_WS_LAST}"
    workers = str(naming.WORKER_RANGE)
    lines = [ln.strip() for ln in br.splitlines()]
    assert "delete table bridge rt_br" in lines
    # ws -> ws: every port and protocol, matched on the static range (no set to go stale)
    ww = f"ip saddr {ws} ip daddr {ws} counter drop"
    assert ww in lines
    assert f"ip saddr {workers} ip daddr {ws} tcp dport 22 accept" in lines
    assert f"ip saddr {workers} ip daddr {ws} counter drop" in lines
    assert f"ip saddr {ws} ip daddr {workers} counter drop" in lines
    # a workspace may only answer a worker (never open a connection: pure SYN is not accepted)
    reply = next(ln for ln in lines if "tcp sport 22" in ln)
    assert "!= syn accept" in reply and ln_idx(lines, reply) < ln_idx(
        lines, f"ip saddr {ws} ip daddr {workers} counter drop")
    # the kill switch and ws<->ws drop come before any accept
    first_accept = min(i for i, ln in enumerate(lines) if ln.endswith("accept")
                       and "policy" not in ln)
    assert ln_idx(lines, ww) < first_accept
    assert ln_idx(lines, "ip saddr @killed_hub counter drop") < first_accept


def ln_idx(lines, needle):
    return lines.index(needle)


def test_nft_bridge_range_covers_every_workspace_hub_address_and_no_worker():
    import ipaddress
    lo, hi = int(naming.HUB_WS_FIRST), int(naming.HUB_WS_LAST)
    for i in (0, 1, 500, naming.MAX_TENANT_INDEX - 1):
        assert lo <= int(ipaddress.ip_address(naming.hub_workspace_ip(i))) <= hi
    for slot in range(1, 14):
        assert int(ipaddress.ip_address(naming.hub_worker_ip(slot))) < lo


def test_nft_bridge_killed_tenant_hub_ip_is_dropped_both_ways():
    r = rules()
    br = r[r.index("table bridge rt_br"):]
    assert naming.hub_workspace_ip(1) in br.split("chain forward")[0]
    assert naming.hub_workspace_ip(0) not in br.split("chain forward")[0]


def test_nft_rule_order_is_kill_then_established_then_allow_then_default_drop():
    fwd = rules().split("chain forward")[1].splitlines()
    keys = ("ct state established", "ip saddr @killed_egress counter drop",
            "ip saddr @ws_egress ip daddr @blocked_ranges counter drop",
            "tcp dport { 53, 80, 123, 443 } accept", "ip saddr @ws_egress counter drop")
    idx = {k: next(i for i, line in enumerate(fwd) if k in line) for k in keys}
    assert (idx["ip saddr @killed_egress counter drop"] < idx["ct state established"]
            < idx["ip saddr @ws_egress ip daddr @blocked_ranges counter drop"]
            < idx["tcp dport { 53, 80, 123, 443 } accept"] < idx["ip saddr @ws_egress counter drop"])


def test_nft_limiters_only_touch_workspace_traffic():
    fwd = rules().split("chain forward")[1]
    for line in fwd.splitlines():
        if "@ws_conn" in line or "@ws_rate" in line:
            assert line.strip().startswith("ip saddr @ws_egress ct state new add"), line


def test_nft_dns_to_configured_resolvers_precedes_private_range_block():
    fwd = rules(dns_servers=["192.168.65.7"]).split("chain forward")[1].splitlines()
    dns = next(i for i, line in enumerate(fwd) if "@dns_servers udp dport 53 accept" in line)
    blocked = next(i for i, line in enumerate(fwd) if "@blocked_ranges counter drop" in line)
    assert dns < blocked and "192.168.65.7" in rules(dns_servers=["192.168.65.7"])


def test_nft_killed_tenant_addresses_only():
    r = rules()
    assert "set killed_egress" in r
    killed = r.split("set killed_egress")[1].split("set killed_hub")[0]
    assert str(naming.egress_subnet(1)) in killed
    assert str(naming.egress_subnet(0)) not in killed


def test_nft_git_protocol_is_opt_in_and_mining_ips_blocked():
    assert "9418" not in rules()
    assert "9418" in rules(allow_git_protocol=True)
    assert "203.0.113.9" in rules(mining_ips=["203.0.113.9"])


def test_nft_rejects_addresses_outside_the_plan():
    with pytest.raises(ValueError):
        nft.render(nft.FirewallInput(tenants=[nft.TenantNet("x", "192.168.1.0/28", "10.199.0.20")]))
    with pytest.raises(ValueError):
        nft.render(nft.FirewallInput(tenants=[nft.TenantNet(
            "x", str(naming.egress_subnet(0)), "10.199.0.5")]))   # inside the worker range
    with pytest.raises(ValueError):
        nft.render(nft.FirewallInput(worker_ips=["10.199.0.200"]))


def test_address_plan_never_overlaps():
    import ipaddress
    nets = [naming.TENANT_POOL, naming.EGRESS_POOL, naming.POOL_NET_CIDR, naming.SSH_HUB_CIDR]
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b), (a, b)
    seen = set()
    for i in (0, 1, 2, 999):
        for n in (naming.tenant_subnet(i), naming.egress_subnet(i)):
            assert n not in seen
            seen.add(n)
        assert ipaddress.ip_address(naming.edge_ip(i)) in naming.egress_subnet(i)
        assert ipaddress.ip_address(naming.hub_workspace_ip(i)) in naming.SSH_HUB_CIDR
    with pytest.raises(ValueError):
        naming.tenant_subnet(1000)


def test_ruleset_file_firewall_is_atomic_and_idempotent(tmp_path):
    from rm.firewall import RulesetFileFirewall
    fw = RulesetFileFirewall(str(tmp_path / "x" / "rt.nft"))
    inp = nft.FirewallInput(tenants=[nft.tenant_net_for("acme1", 0)])
    assert fw.apply(inp) is True and fw.apply(inp) is False
    assert not list((tmp_path / "x").glob(".rt.*"))
    assert fw.apply(nft.FirewallInput()) is True


# ----- quota ------------------------------------------------------------------------------------
def test_xfs_quota_commands_and_report_parse(tmp_path):
    ran = []

    def runner(cmd):
        ran.append(cmd)
        if "report" in " ".join(cmd):
            return ("rt_acme1  1048576  0  5242880  00 [--------]\n"
                    "rt_beta1  2048  0  10485760  00 [--------]\nnot a row\n")
        return ""
    q = quota.XfsQuota("/srv/tenants", str(tmp_path / "projects"), str(tmp_path / "projid"),
                       runner, index_of=lambda t: 7)
    q.set_limit("acme1", "/srv/tenants/acme1", 5)
    assert ["xfs_quota", "-x", "-c", "limit -p bhard=5g rt_acme1", "/srv/tenants"] in ran
    assert (tmp_path / "projects").read_text().strip() == "100007:/srv/tenants/acme1"
    assert (tmp_path / "projid").read_text().strip() == "rt_acme1:100007"
    q.set_limit("acme1", "/srv/tenants/acme1", 5)              # idempotent files
    assert (tmp_path / "projects").read_text().count("\n") == 1
    assert q.report()["acme1"] == {"used": 1048576 * 1024, "hard": 5242880 * 1024}
    assert q.usage_bytes("nobody") == 0


# ----- backup -----------------------------------------------------------------------------------
def make_runtime_dir(root: Path):
    root.mkdir(parents=True)
    (root / ".env").write_text("OPENAI_API_KEY=sk-super-secret")
    (root / "config.yaml").write_text("model: x")
    (root / "skills").mkdir()
    (root / "skills" / "a.md").write_text("skill")
    (root / "cache").mkdir()
    (root / "cache" / "junk.bin").write_text("cache")
    db = sqlite3.connect(root / "state.db")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("create table t(x)")
    db.executemany("insert into t values (?)", [(i,) for i in range(100)])
    db.commit()
    return db   # left open on purpose: a live WAL database


def test_backup_is_online_consistent_and_never_includes_env(tmp_path):
    rd = tmp_path / "rt"
    live = make_runtime_dir(rd)
    ws = tmp_path / "ws"
    (ws / "home" / ".cache").mkdir(parents=True)
    (ws / "home" / "keep.txt").write_text("keep")
    (ws / "home" / ".cache" / "x").write_text("junk")
    b = LocalBackupBackend(str(tmp_path / "bk"))
    rec = b.create("acme1", "manual", str(rd), str(ws), {"generation": 3})
    live.close()
    names = tarfile.open(rec["location"]).getnames()
    assert "runtime/state.db" in names and "runtime/config.yaml" in names
    assert "runtime/skills/a.md" in names and "ws/home/keep.txt" in names
    assert not any(n.endswith(".env") for n in names)
    assert "runtime/cache/junk.bin" not in names and "ws/home/.cache/x" not in names
    assert b.verify(rec)
    out = tmp_path / "restored"
    b.restore(rec, str(out / "rt"), str(out / "ws"))
    assert sqlite3.connect(out / "rt" / "state.db").execute("select count(*) from t").fetchone()[0] == 100
    assert (out / "ws" / "home" / "keep.txt").read_text() == "keep"
    assert not (out / "rt" / ".env").exists()


def test_backup_detects_corruption_and_unsafe_paths(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "f").write_text("x")
    b = LocalBackupBackend(str(tmp_path / "bk"))
    rec = b.create("acme1", "manual", None, str(ws), {})
    Path(rec["location"]).write_bytes(Path(rec["location"]).read_bytes() + b"x")
    assert not b.verify(rec)
    with pytest.raises(BackupError, match="checksum"):
        b.restore(rec, None, str(tmp_path / "out"))
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as t:
        data = tmp_path / "d"
        data.write_text("pwn")
        t.add(data, arcname="ws/../../pwned.txt")
    import hashlib
    rec2 = {"location": str(evil), "sha256": hashlib.sha256(evil.read_bytes()).hexdigest()}
    with pytest.raises(BackupError, match="unsafe"):
        b.restore(rec2, None, str(tmp_path / "out2"))
    assert not (tmp_path / "pwned.txt").exists()


def test_sqlite_online_backup_of_wal_db(tmp_path):
    src = tmp_path / "a.db"
    live = sqlite3.connect(src)
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("create table t(x)")
    live.execute("insert into t values (1)")
    live.commit()
    live.execute("insert into t values (2)")      # uncommitted: must not leak
    sqlite_online_backup(src, tmp_path / "b.db")
    assert sqlite3.connect(tmp_path / "b.db").execute("select count(*) from t").fetchone()[0] == 1
    live.close()


def test_restic_backend_builds_expected_commands():
    ran = []

    def runner(cmd, env):
        ran.append((cmd, env))
        return json.dumps({"message_type": "summary", "snapshot_id": "snap123"}) + "\n"
    r = ResticBackupBackend("rclone:gdrive:rt/prd", "/run/secrets/restic", runner)
    rec = r.create("acme1", "manual", "/srv/tenants/acme1/hermes", "/srv/tenants/acme1/ws", {})
    cmd, env = ran[0]
    assert rec["backup_id"] == "snap123"
    assert cmd[:2] == ["restic", "backup"] and "tenant:acme1" in cmd
    assert cmd[cmd.index("--exclude") + 1] == ".env"
    assert env["RESTIC_REPOSITORY"] == "rclone:gdrive:rt/prd"
    assert "--read-data-subset=5%" in r.check_cmd()
    with pytest.raises(BackupError):
        ResticBackupBackend("r", "p", lambda c, e: "no json").create("a", "m", "/x", None, {})


# ----- abuse ------------------------------------------------------------------------------------
@pytest.mark.parametrize("cmd,hit", [
    ("/tmp/xmrig --donate-level 1", True), ("./minerd -o x", True),
    ("python3 miner.py --url stratum+tcp://pool:3333", True), ("/usr/bin/cpuminer", True),
    ("/usr/sbin/sshd -D", False), ("python3 -m http.server 8000", False),
    ("node server.js --coin-flip", False),
])
def test_miner_signatures(cmd, hit):
    assert bool(miner_in_process([["1", "root", cmd]])) is hit


def test_abuse_monitor_suspends_on_miner(env, tenant):
    env.fake.containers["rt-ws-acme1"]["_procs"] = ["/init", "/tmp/xmrig --donate-level=1"]
    mon = AbuseMonitor(env.settings, env.docker, env.svc)
    hits = mon.scan()
    assert hits and hits[0][0] == "acme1" and "miner" in hits[0][1]
    assert env.store.get_tenant("acme1")["suspended"] is True
    assert env.svc.metrics["abuse_suspensions"] == 1
    assert mon.scan() == []     # suspended workspace is paused: not scanned again


def test_abuse_monitor_cpu_burn_needs_the_full_window(env, tenant):
    clock = [0.0]
    mon = AbuseMonitor(env.settings, env.docker, env.svc, clock=lambda: clock[0])
    env.settings.abuse_cpu_window_s = 900
    c = env.fake.containers["rt-ws-acme1"]
    c["_cpu_ns"] = 0
    assert mon.scan() == []
    clock[0] = 600
    vcpus = templates.workspace_limits(templates.DEFAULT_PLAN).cpus
    c["_cpu_ns"] = int(600e9 * vcpus)      # 100 % of the limit, but only for 10 minutes
    assert mon.scan() == []
    clock[0] = 905
    c["_cpu_ns"] = int(905e9 * vcpus)
    hits = mon.scan()
    assert hits and "cpu at" in hits[0][1]


def test_abuse_monitor_ignores_normal_load(env, tenant):
    clock = [0.0]
    mon = AbuseMonitor(env.settings, env.docker, env.svc, clock=lambda: clock[0])
    c = env.fake.containers["rt-ws-acme1"]
    c["_cpu_ns"] = 0
    mon.scan()
    clock[0] = 1000
    c["_cpu_ns"] = int(300e9)       # 30 %
    assert mon.scan() == []
    assert env.store.get_tenant("acme1")["suspended"] is False


# ----- file quota (host aplica) ----------------------------------------------------------------
def test_file_quota_writes_limits_atomically_and_reads_host_usage(tmp_path):
    import json

    q = quota.FileQuota(str(tmp_path))
    q.set_limit("acme1", "/srv/rt/tenants/acme1", 5)
    q.set_limit("acme1", "/srv/rt/tenants/acme1", 5)  # idempotente
    saved = json.loads((tmp_path / "limits.json").read_text())
    assert saved["acme1"] == {"path": "/srv/rt/tenants/acme1", "gb": 5}
    assert q.usage_bytes("acme1") == 0
    (tmp_path / "usage.json").write_text(json.dumps({"acme1": {"used": 4096}}))
    assert q.usage_bytes("acme1") == 4096
    assert q.report()["acme1"] == {"used": 4096, "hard": 5 * 1024**3}
    q.remove("acme1")
    assert q.report() == {}


def test_nft_public_proxy_https_only_precedes_private_block():
    txt = rules(public_proxy_ips=["172.21.0.5"])
    fwd = txt.split("chain forward")[1].splitlines()
    ok = next(i for i, line in enumerate(fwd) if "@public_proxy tcp dport 443 accept" in line)
    blocked = next(i for i, line in enumerate(fwd) if "@blocked_ranges counter drop" in line)
    assert ok < blocked and "172.21.0.5" in txt
    assert "@public_proxy tcp dport 22" not in txt
