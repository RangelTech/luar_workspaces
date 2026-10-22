# rt-executor: one throwaway container per script run. The RM starts it with NetworkMode=none,
# cap-drop ALL, read-only rootfs, tmpfs, rlimits and a wall-clock timeout (spec 04 section 7.3).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MPLBACKEND=Agg MPLCONFIGDIR=/tmp/mpl HOME=/tmp
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY rt_exec.py /srv/rt_exec.py
RUN useradd -r -u 10001 executor
USER executor

ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}
LABEL org.opencontainers.image.source="https://github.com/RangelTech/luar_workspaces" \
      org.opencontainers.image.revision="${GIT_COMMIT}"
HEALTHCHECK --interval=30s --timeout=10s --retries=2 \
  CMD ["python", "-c", "import pandas, openpyxl, matplotlib, pypdf, reportlab, qrcode"]
ENTRYPOINT ["python", "/srv/rt_exec.py"]
