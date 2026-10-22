# rt-workspace: environment of a tenant (annex 04 section 2). Debian + s6-overlay (PID 1) + sshd.
# Built by CI and loaded on the VPS as a docker-archive; never built on the host.
FROM debian:13-slim

ARG TARGETARCH=amd64
ARG S6_VERSION=3.2.0.2
ARG S6_NOARCH_SHA256=6dbcde158a3e78b9bb141d7bcb5ccb421e563523babbe2c64470e76f4fd02dae
ARG S6_X86_64_SHA256=59289456ab1761e277bd456a95e737c06b03ede99158beb24f12b165a904f478
ARG S6_AARCH64_SHA256=8b22a2eaca4bf0b27a43d36e65c89d2701738f628d1abd0cea5569619f66f785

ENV DEBIAN_FRONTEND=noninteractive \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=60000 \
    S6_KEEP_ENV=0 \
    LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils openssh-server openssh-client python3 python3-pip python3-venv git procps iproute2 \
      less nano locales \
 && rm -rf /var/lib/apt/lists/* \
 && arch="$(case "${TARGETARCH}" in arm64) echo aarch64;; *) echo x86_64;; esac)" \
 && sha="$(case "${arch}" in aarch64) echo ${S6_AARCH64_SHA256};; *) echo ${S6_X86_64_SHA256};; esac)" \
 && base="https://github.com/just-containers/s6-overlay/releases/download/v${S6_VERSION}" \
 && curl -fsSL -o /tmp/s6-noarch.tar.xz "${base}/s6-overlay-noarch.tar.xz" \
 && curl -fsSL -o /tmp/s6-arch.tar.xz "${base}/s6-overlay-${arch}.tar.xz" \
 && echo "${S6_NOARCH_SHA256}  /tmp/s6-noarch.tar.xz" | sha256sum -c - \
 && echo "${sha}  /tmp/s6-arch.tar.xz" | sha256sum -c - \
 && tar -C / -Jxpf /tmp/s6-noarch.tar.xz \
 && tar -C / -Jxpf /tmp/s6-arch.tar.xz \
 && rm -f /tmp/s6-*.tar.xz

# Unprivileged account for supervised customer services; root (key only) is what the agent uses
# over SSH. sudo is not installed: no-new-privileges (mandatory in policy) would disable it anyway.
# root's home is moved to the persistent volume so agent sessions land on durable storage.
RUN useradd -m -u 1000 -s /bin/bash ws \
 && mkdir -p /home/ws /workspace /var/lib/rt /etc/rt /run/sshd \
 && sed -i 's|^root:\(.*\):/root:|root:\1:/home/ws:|' /etc/passwd \
 && chown 1000:1000 /workspace

COPY rootfs/ /
RUN chmod 0755 /usr/local/bin/rt-* /usr/local/bin/luar-* /etc/s6-overlay/scripts/* /etc/s6-overlay/s6-rc.d/*/run \
 && apt-mark showmanual | sort > /etc/rt/baseline.manual \
 && rm -rf /var/lib/apt/lists/*

ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}
LABEL org.opencontainers.image.source="https://github.com/RangelTech/luar_workspaces" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.description="rt-workspace: persistent tenant environment"

VOLUME ["/home/ws", "/workspace", "/opt", "/var/lib/rt"]
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python3", "/usr/local/bin/rt-healthcheck"]
ENTRYPOINT ["/init"]
