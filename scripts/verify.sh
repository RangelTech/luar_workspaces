#!/usr/bin/env bash
# Gate local e do CI: lint + testes offline (familia W incluida) + build da imagem do RM e smoke de /health.
# Os testes @docker (tests/integration) NAO entram aqui: rodam so onde ha daemon dedicado (scripts/qa/).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" -m ruff check .
"$PY" -m pytest -q tests/unit -m "not docker and not integration and not postgres and not hermes"
if [ "${VERIFY_SKIP_IMAGE:-0}" = "1" ]; then echo "verify OK (sem imagem)"; exit 0; fi
IMG="runtime-manager-verify:local"
docker build -q -f docker/rm.Dockerfile --build-arg GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo local)" -t "$IMG" .
for ctx in workspace executor edge; do
  docker build -q -f "images/rt-$ctx/Dockerfile" -t "rt-$ctx-verify:local" "images/rt-$ctx" >/dev/null
done
cid="$(docker run -d --rm -p 18080:8080 -e RM_SERVICE_KEYS=verify:verify -e RM_ADMIN_SERVICES=verify -e RM_DOMAIN_SECRET=verify "$IMG")"
trap 'docker stop "$cid" >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi
  sleep 1
  [ "$i" -eq 30 ] && { echo "health nao respondeu"; docker logs "$cid" | tail -20; exit 1; }
done
echo "verify OK"
