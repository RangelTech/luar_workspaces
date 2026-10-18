"""Firewall application (interface). The RM never runs nft itself.

RulesetFileFirewall writes the generated ruleset atomically to a path; a host-side systemd path
unit (see docs/runbooks/kill-switch.md) runs `nft -f` on change, so the RM container needs no
NET_ADMIN. RecordingFirewall is for tests.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Protocol

from . import nft


class Firewall(Protocol):
    def apply(self, fw: nft.FirewallInput) -> bool: ...


class NullFirewall:
    def apply(self, fw: nft.FirewallInput) -> bool:
        return False


class RecordingFirewall:
    def __init__(self) -> None:
        self.applied: list[nft.FirewallInput] = []

    def apply(self, fw: nft.FirewallInput) -> bool:
        self.applied.append(fw)
        return True


class RulesetFileFirewall:
    def __init__(self, path: str):
        self.path = Path(path)

    def apply(self, fw: nft.FirewallInput) -> bool:
        text = nft.render(fw)
        if self.path.exists() and self.path.read_text(encoding="utf-8") == text:
            return False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".rt.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, self.path)
        return True
