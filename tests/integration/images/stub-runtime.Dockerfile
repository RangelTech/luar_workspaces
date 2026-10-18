# Test-only stand-in for the Hermes runtime: answers /health and has an ssh client + curl.
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssh-client curl iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY stub.py /stub.py
USER 10001
CMD ["python3", "/stub.py"]
