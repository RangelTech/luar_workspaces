# runtime-manager

Servico FastAPI que gerencia os ambientes (workspace, runtime, executor) de cada tenant via
docker-socket-proxy. Imagens: `rt-workspace` (Debian + s6-overlay + sshd), `rt-executor` (efemero, sem rede),
`rt-edge` (Traefik de borda para `*.apps`). Spec: `specs/04_KERNEL_LLM_PARA_KERNEL_HARNESS.md`.

- Testes offline: `bash scripts/verify.sh` (ruff + `tests/unit`, familia W em `tests/unit/test_w_family.py`).
- Testes com Docker: `tests/integration` (marcador `docker`), fora do gate.
- Release: tag `v*`; 4 assets `<servico>.image.tar.gz` + `release-manifest.<servico>.json`
  (`runtime-manager`, `workspace`, `executor`, `edge`). Deploy so pelo `vps_rt_infra`.
