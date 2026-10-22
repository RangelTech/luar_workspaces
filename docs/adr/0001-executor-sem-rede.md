# ADR 0001: o executor não tem rede

Status: aceita.

**Contexto.** Ferramentas rodam código gerado por IA em nome de uma empresa. Rede aberta permitiria vazar dados ou atacar a rede interna.

**Decisão.** O executor efêmero roda sem rede. O workspace só sai para a internet pelo que o firewall (nft) da empresa permite. O serviço nunca fala com o Docker diretamente, só pelo docker-socket-proxy.

**Consequências.** Ferramentas que precisam de rede passam pelo broker do `luar_harness`, que aplica credenciais e limites. Nome de empresa validado por `^[a-z][a-z0-9]{3,19}$`.
