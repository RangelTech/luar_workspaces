"""Backup and restore (annex 04 section 4).

BackupBackend is the interface. LocalBackupBackend implements it with sqlite3.backup (online,
WAL-safe) and tar; it never includes `.env`. ResticBackupBackend builds restic/rclone commands
behind an injectable runner (offsite repository on Google Drive via rclone; not run here).
"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

RUNTIME_NEVER = {".env"}
WS_EXCLUDES = ("node_modules/.cache", ".cache", "__pycache__")


class BackupError(Exception):
    pass


class BackupBackend(Protocol):
    def create(self, tenant: str, kind: str, runtime_dir: str | None, ws_dir: str | None,
               meta: dict) -> dict: ...
    def restore(self, record: dict, runtime_dir: str | None, ws_dir: str | None) -> dict: ...
    def verify(self, record: dict) -> bool: ...


def sqlite_online_backup(src: Path, dst: Path) -> None:
    """Consistent copy of a live (WAL) database using the sqlite3 backup API."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    d = sqlite3.connect(str(dst))
    try:
        s.backup(d)
    finally:
        d.close()
        s.close()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _excluded(rel: str, excludes: tuple[str, ...]) -> bool:
    return any(x in rel.split("/") or rel.startswith(x) or f"/{x}" in rel for x in excludes)


class LocalBackupBackend:
    def __init__(self, root: str):
        self.root = Path(root)

    def create(self, tenant: str, kind: str, runtime_dir: str | None, ws_dir: str | None,
               meta: dict) -> dict:
        bid = f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
        out_dir = self.root / tenant
        out_dir.mkdir(parents=True, exist_ok=True)
        archive = out_dir / f"{bid}.tar.gz"
        files: list[str] = []
        with tempfile.TemporaryDirectory() as td, tarfile.open(archive, "w:gz") as tar:
            if runtime_dir and Path(runtime_dir).is_dir():
                rd = Path(runtime_dir)
                for p in sorted(rd.rglob("*")):
                    rel = p.relative_to(rd).as_posix()
                    if p.is_dir() or p.name in RUNTIME_NEVER:
                        continue
                    if p.name in ("state.db", "state.db-wal", "state.db-shm"):
                        continue  # handled by the online backup below
                    if rel.split("/")[0] not in ("config.yaml", "skills") and rel != "config.yaml":
                        continue
                    tar.add(p, arcname=f"runtime/{rel}")
                    files.append(f"runtime/{rel}")
                db = rd / "state.db"
                if db.exists():
                    tmp = Path(td) / "state.db"
                    sqlite_online_backup(db, tmp)
                    tar.add(tmp, arcname="runtime/state.db")
                    files.append("runtime/state.db")
            if ws_dir and Path(ws_dir).is_dir():
                wd = Path(ws_dir)
                for p in sorted(wd.rglob("*")):
                    rel = p.relative_to(wd).as_posix()
                    if p.is_dir() or _excluded(rel, WS_EXCLUDES):
                        continue
                    if p.is_symlink() and not p.exists():
                        continue
                    tar.add(p, arcname=f"ws/{rel}")
                    files.append(f"ws/{rel}")
            manifest = {"tenant": tenant, "kind": kind, "files": files,
                        "created": datetime.now(UTC).isoformat(), **meta}
            raw = json.dumps(manifest, sort_keys=True).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(raw)
            tar.addfile(ti, io.BytesIO(raw))
        return {"backup_id": bid, "tenant_id": tenant, "kind": kind, "location": str(archive),
                "sha256": _sha256(archive), "manifest": manifest}

    def verify(self, record: dict) -> bool:
        p = Path(record["location"])
        return p.exists() and _sha256(p) == record.get("sha256")

    def restore(self, record: dict, runtime_dir: str | None, ws_dir: str | None) -> dict:
        if not self.verify(record):
            raise BackupError("checksum_mismatch")
        restored = 0
        with tarfile.open(record["location"], "r:gz") as tar:
            for m in tar.getmembers():
                if not m.isfile() or m.name == "manifest.json":
                    continue
                if m.name.startswith("runtime/") and runtime_dir:
                    base, rel = Path(runtime_dir), m.name[len("runtime/"):]
                elif m.name.startswith("ws/") and ws_dir:
                    base, rel = Path(ws_dir), m.name[len("ws/"):]
                else:
                    continue
                dest = (base / rel).resolve()
                if not str(dest).startswith(str(base.resolve())):
                    raise BackupError(f"unsafe path in archive: {m.name}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                src = tar.extractfile(m)
                assert src is not None
                with open(dest, "wb") as f:
                    shutil.copyfileobj(src, f)
                restored += 1
        return {"restored_files": restored}


Runner = Callable[[list[str], dict], str]


class ResticBackupBackend:
    """restic over rclone (Google Drive). Commands are built here, executed by `runner`."""

    def __init__(self, repo: str, password_file: str, runner: Runner | None = None):
        self.repo = repo  # e.g. rclone:gdrive:rt-backups/<env>
        self.password_file = password_file
        self.run = runner or self._run

    @staticmethod
    def _run(cmd: list[str], env: dict) -> str:
        import os
        return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=3600,
                              env={**os.environ, **env}).stdout

    def _env(self) -> dict:
        return {"RESTIC_REPOSITORY": self.repo, "RESTIC_PASSWORD_FILE": self.password_file}

    def backup_cmd(self, tenant: str, paths: list[str], kind: str) -> list[str]:
        cmd = ["restic", "backup", "--tag", f"tenant:{tenant}", "--tag", f"kind:{kind}",
               "--host", "rt", "--json"]
        for x in (".env", *WS_EXCLUDES):
            cmd += ["--exclude", x]
        return cmd + paths

    def restore_cmd(self, snapshot: str, target: str) -> list[str]:
        return ["restic", "restore", snapshot, "--target", target]

    def check_cmd(self) -> list[str]:
        return ["restic", "check", "--read-data-subset=5%"]

    def create(self, tenant, kind, runtime_dir, ws_dir, meta):
        paths = [p for p in (runtime_dir, ws_dir) if p]
        out = self.run(self.backup_cmd(tenant, paths, kind), self._env())
        snap = ""
        for line in out.splitlines():
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if j.get("message_type") == "summary":
                snap = j.get("snapshot_id", "")
        if not snap:
            raise BackupError("restic returned no snapshot id")
        return {"backup_id": snap, "tenant_id": tenant, "kind": kind,
                "location": f"restic:{self.repo}:{snap}", "sha256": "",
                "manifest": {"paths": paths, **meta}}

    def restore(self, record, runtime_dir, ws_dir):
        target = runtime_dir or ws_dir
        if not target:
            raise BackupError("no target")
        self.run(self.restore_cmd(record["backup_id"], target), self._env())
        return {"restored_files": -1}

    def verify(self, record):
        try:
            self.run(self.check_cmd(), self._env())
            return True
        except Exception:
            return False
