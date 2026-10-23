#!/usr/bin/env python3
"""ProxyCommand do ssh: liga o ssh do ambiente ao hub do conector (spec 11 §26.2).

Uso (ProxyCommand):  python3 luar-relay.py HUB_HOST HUB_PORT TOKEN
  - porta 443 (ou 8443): relay por WebSocket seguro (o ambiente da empresa só alcança 80/443);
  - outra porta: relay TCP simples do hub (rede interna e testes).
Só biblioteca padrão. Erros do hub vão para stderr e o código de saída é 1.
"""
import base64
import os
import select
import socket
import ssl
import struct
import sys
import threading


def fail(msg: str) -> int:
    sys.stderr.write(msg.strip() + "\n")
    return 1


# ---------------------------------------------------------------- TCP simples
def run_tcp(host: str, port: int, token: str) -> int:
    try:
        s = socket.create_connection((host, port), timeout=15)
    except OSError as exc:
        return fail(f"hub inacessivel: {exc}")
    s.sendall(f"RELAY {token}\n".encode())
    line = b""
    while not line.endswith(b"\n"):
        ch = s.recv(1)
        if not ch:
            break
        line += ch
    if line.strip() != b"OK":
        return fail(line.decode(errors="replace"))
    s.settimeout(None)

    def to_hub():
        try:
            while True:
                data = os.read(0, 65536)
                if not data:
                    break
                s.sendall(data)
        except OSError:
            pass
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    threading.Thread(target=to_hub, daemon=True).start()
    try:
        while True:
            data = s.recv(65536)
            if not data:
                break
            os.write(1, data)
    except OSError:
        pass
    return 0


# ---------------------------------------------------------------- WebSocket (RFC 6455, cliente mínimo)
def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def ws_send(sock, opcode: int, payload: bytes) -> None:
    mask = os.urandom(4)
    n = len(payload)
    head = bytes([0x80 | opcode])
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload)) if n else b""
    sock.sendall(head + mask + masked)


def ws_recv(sock):
    """Devolve (opcode, payload) de um quadro completo (sem fragmentação além de 1 nível)."""
    b1, b2 = recv_exact(sock, 2)
    op, n = b1 & 0x0F, b2 & 0x7F
    if n == 126:
        n = struct.unpack(">H", recv_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if b2 & 0x80 else None
    data = recv_exact(sock, n) if n else b""
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return op, data


def run_ws(host: str, port: int, token: str) -> int:
    try:
        raw = socket.create_connection((host, port), timeout=15)
        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    except OSError as exc:
        return fail(f"hub inacessivel: {exc}")
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET /relay?token={token} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
        if len(resp) > 65536:
            break
    head, _, rest = resp.partition(b"\r\n\r\n")
    if b" 101 " not in head.split(b"\r\n")[0] + b" ":
        body = rest.decode(errors="replace").strip() or head.split(b"\r\n")[0].decode(errors="replace")
        return fail(body)
    sock.settimeout(None)
    lock = threading.Lock()

    def to_hub():
        try:
            while True:
                data = os.read(0, 32768)
                if not data:
                    break
                with lock:
                    ws_send(sock, 2, data)
        except OSError:
            pass
        try:
            with lock:
                ws_send(sock, 8, b"")
        except OSError:
            pass

    threading.Thread(target=to_hub, daemon=True).start()
    buf = rest  # bytes que já vieram depois do cabeçalho HTTP
    try:
        # alimenta o leitor com o resto do handshake, se houver
        class Prefix:
            def __init__(self, first):
                self.first = first

            def recv(self, n):
                if self.first:
                    out, self.first = self.first[:n], self.first[n:]
                    return out
                return sock.recv(n)

        src = Prefix(buf)
        while True:
            op, data = ws_recv(src)
            if op in (1, 2, 0):
                os.write(1, data)
            elif op == 9:
                with lock:
                    ws_send(sock, 10, data)
            elif op == 8:
                break
    except (EOFError, OSError):
        pass
    return 0


def main() -> int:
    host, port, token = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    return run_ws(host, port, token) if port in (443, 8443) else run_tcp(host, port, token)


if __name__ == "__main__":
    sys.exit(main())
