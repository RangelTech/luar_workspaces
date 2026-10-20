# luar_workspaces

O ambiente de cada empresa: workspace com terminal e arquivos, executor efêmero para as ferramentas e a borda que publica os apps. Um serviço FastAPI cria e controla tudo pelo docker-socket-proxy, com cotas e firewall por empresa.

> Nome anterior: `runtime-manager`.

## Onde ele se encaixa

```
                    Cliente (navegador e canais)
                                |
                        Traefik (VPS)
                                |
 luar_chatwoot --contexto assinado--> luar_engine --runs--> luar_harness
 (telas, inbox, Kanban,               (motor de IA:         (fila, broker,
  bridge, gateway de canais)           templates, skills,    workers Hermes)
                                       credenciais, uso)            |
                                            |                luar_workspaces
                                       luar_ai_gateway       (ambiente de cada
                                       (LLM multi-tenant)     empresa)

 vps_rt_infra: compose, releases por digest, deploy e backup (só ela implanta)
 airflow:      orquestração da empresa, inclui o backup noturno da VPS
 luar_docs:    specs, evidências e ADRs
```

## Árvore de pastas

```
rm/                   serviço FastAPI (executor, cota, firewall nft, domínios, uso, traefik)
images/rt-workspace/  imagem do workspace (Debian, s6-overlay, sshd)
images/rt-executor/   executor efêmero, sem rede
images/rt-edge/       Traefik de borda para os apps
tests/unit/           testes offline (família W)
tests/integration/    testes com Docker (fora do gate)
scripts/              verify.sh e release_build.py
```

## Como rodar e testar

```bash
bash scripts/verify.sh                 # ruff + testes unitários
pytest tests/integration -m docker     # precisa de Docker
```

## Como implantar

Uma tag `v*` publica 4 artefatos (`runtime-manager`, `workspace`, `executor`, `edge`), cada um com seu manifesto. O deploy é só pelo `vps_rt_infra`.

## Isolamento e segurança

- O nome da empresa é validado (`^[a-z][a-z0-9]{3,19}$`).
- O executor não tem rede; o workspace sai para a internet só pelo que o firewall da empresa permite.
- O serviço nunca fala com o Docker direto, só pelo socket-proxy.

## Como contribuir

Uma branch por tarefa, Conventional Commits em português, `verify.sh` verde.
