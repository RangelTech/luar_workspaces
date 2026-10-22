#!/usr/bin/env python3
"""ProxyCommand do ssh: liga o ssh do ambiente ao hub do conector (spec 11 §26.2).

Uso (no ~/.ssh/config):  ProxyCommand python3 /caminho/luar-relay.py HUB_HOST HUB_PORT TOKEN
Só biblioteca padrão. Escreve a mensagem de erro do hub em stderr e sai com 1.
"""
import os
import socket
import sys
import threading


def main() -> int:
    host, port, token = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    try:
        s = socket.create_connection((host, port), timeout=15)
    except OSError as exc:
        sys.stderr.write(f"hub inacessivel: {exc}\n")
        return 1
    s.sendall(f"RELAY {token}\n".encode())
    line = b""
    while not line.endswith(b"\n"):
        ch = s.recv(1)
        if not ch:
            break
        line += ch
    if line.strip() != b"OK":
        sys.stderr.write(line.decode(errors="replace").strip() + "\n")
        return 1
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


if __name__ == "__main__":
    sys.exit(main())
