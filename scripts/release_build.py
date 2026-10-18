"""Builds every image of the repo, writes <service>.image.tar.gz and release-manifest.<service>.json
(contract: specs/anexos/03/CONTRATO_RELEASE.md, schema 1). Used by the release workflow."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

# service -> (dockerfile, context, healthcheck, env.required, resources)
HTTP_RM = {"path": "/health", "expect": 200, "timeout_s": 90, "port": 8080}
SERVICES = {
    "runtime-manager": ("docker/rm.Dockerfile", ".", HTTP_RM,
                        ["RM_DATABASE_URL", "RM_SERVICE_KEYS", "RM_ADMIN_SERVICES", "RM_DOMAIN_SECRET",
                         "RM_DOCKER_HOST", "RM_APPS_DOMAIN"], {"memory": "512m", "cpus": "1"}),
    "workspace": ("images/rt-workspace/Dockerfile", "images/rt-workspace", None, [],
                  {"memory": "2g", "cpus": "2"}),  # imagem de tenant: o RM a cria, nao ha servico fixo
    "executor": ("images/rt-executor/Dockerfile", "images/rt-executor", None, [],
                 {"memory": "512m", "cpus": "1"}),  # efemera, sem rede
    "edge": ("images/rt-edge/Dockerfile", "images/rt-edge",
             {"path": "/ping", "expect": 200, "timeout_s": 60, "port": 8082}, [],
             {"memory": "256m", "cpus": "0.5"}),
}


def sh(*a: str) -> str:
    return subprocess.run(a, check=True, capture_output=True, text=True).stdout


def main(version: str) -> None:
    sha = os.environ.get("GITHUB_SHA") or sh("git", "rev-parse", "HEAD").strip()
    for name, (dockerfile, ctx, hc, env_req, res) in SERVICES.items():
        tag = f"rangeltech/{name}:{version}"
        sh("docker", "build", "-f", dockerfile, "--build-arg", f"GIT_COMMIT={sha}", "-t", tag, ctx)
        asset = f"{name}.image.tar.gz"
        with open(asset, "wb") as out:
            save = subprocess.Popen(["docker", "save", tag], stdout=subprocess.PIPE)
            gz = subprocess.Popen(["gzip", "-9"], stdin=save.stdout, stdout=out)
            save.stdout.close()
            if gz.wait() or save.wait():
                raise SystemExit(f"falha ao salvar {tag}")
        h = hashlib.sha256()
        with open(asset, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        mf = subprocess.run(f"gunzip -c {asset} | tar -xO manifest.json", shell=True, check=True,
                            capture_output=True).stdout
        cfg = re.sub(r"^.*/", "", json.loads(mf)[0]["Config"]).replace(".json", "")
        m = {
            "schema": 1, "service": name, "repo": "RangelTech/runtime-manager", "commit": sha[:7],
            "version": version,
            "artifact": {"type": "docker-archive", "asset": asset, "sha256": h.hexdigest(),
                         "image_id": f"sha256:{cfg}", "tag": tag},
            "built_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "healthcheck": hc if hc else {"type": "docker-healthcheck", "timeout_s": 60},
            "env": {"required": env_req}, "resources": res,
        }
        with open(f"release-manifest.{name}.json", "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2)
        print(name, asset, cfg)


if __name__ == "__main__":
    main(sys.argv[1])
