# Kill switch

O RM nunca executa `nft`. Ele grava o ruleset em `RM_NFT_RULESET_PATH` (escrita atomica); uma unit
`systemd.path` no host observa o arquivo e roda `nft -f`. O container do RM nao tem NET_ADMIN.

1. `POST /tenants/{t}/suspend` (ou `freeze_fleet`) pausa/para os containers, remove rotas, revoga a chave
   do LiteLLM e regenera o ruleset com o tenant em `killed_egress`/`killed_hub`.
2. As regras de kill vem ANTES de `ct state established`: fluxos vivos tambem caem.
3. Retomar exige segundo aprovador administrador (`resume`).
4. Host: `systemctl status rt-nft.path rt-nft.service`; ruleset atual em `nft list table inet rt_fw`.
