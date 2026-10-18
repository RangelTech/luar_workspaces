"""Per-tenant ed25519 key pair for the runtime -> workspace SSH hop (annex 04 2.2)."""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keypair(comment: str = "") -> tuple[str, str]:
    """Return (private_openssh, public_openssh)."""
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                        serialization.PublicFormat.OpenSSH).decode()
    if comment:
        pub += " " + comment
    return priv, pub
