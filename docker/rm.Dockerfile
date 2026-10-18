FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY rm ./rm
COPY migrations ./migrations
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/RangelTech/runtime-manager
ENV GIT_COMMIT=${GIT_COMMIT} PORT=8080
LABEL org.opencontainers.image.source=${SOURCE_URL} \
      org.opencontainers.image.revision=${GIT_COMMIT} \
      org.opencontainers.image.description="runtime-manager: tenant environments, exposures, executor"
RUN useradd -r -u 10001 rm
USER rm
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 --start-period=10s \
  CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2).status==200 else 1)"
CMD ["sh", "-c", "uvicorn rm.main:create --factory --host 0.0.0.0 --port ${PORT}"]
