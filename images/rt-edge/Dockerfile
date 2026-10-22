# rt-edge: edge proxy for tenant apps (annex 04 section 2.5). A second Traefik, plain HTTP, whose
# only configuration is the per-tenant files written by the runtime-manager. The platform
# Traefik terminates TLS and forwards <app>-<tenant>.apps.* here.
FROM traefik:v3.3.5

COPY traefik.yml /etc/traefik/traefik.yml
RUN mkdir -p /etc/traefik/dynamic
ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}
LABEL org.opencontainers.image.source="https://github.com/RangelTech/luar_workspaces" \
      org.opencontainers.image.revision="${GIT_COMMIT}"
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD ["traefik", "healthcheck", "--ping"]
