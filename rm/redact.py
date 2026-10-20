"""Redacao de segredos em argumentos de processo e em logs de servico.

Mesmo conjunto de regras do script `rt-services-json` da imagem do workspace (um teste garante a
paridade). Marca igual a do kernel: [REDACTED]."""
from __future__ import annotations

import re

MARK = "[REDACTED]"

_SENSITIVE = r"(?:pass(?:word|wd)?|secret|token|api[-_]?key|apikey|auth|credential|private[-_]?key|key)"
_FLAG_WORD = re.compile(r"^--?[A-Za-z0-9_.-]*" + _SENSITIVE + r"[A-Za-z0-9_.-]*$", re.I)
_FLAG_EQ = re.compile(r"^(--?[A-Za-z0-9_.-]*" + _SENSITIVE + r"[A-Za-z0-9_.-]*)=(.*)$", re.I | re.S)
_ENV_EQ = re.compile(r"^([A-Za-z0-9_]*" + _SENSITIVE + r"[A-Za-z0-9_]*)=(.*)$", re.I | re.S)
_TEXT_KV = re.compile(
    r"(?i)(\b[A-Za-z0-9_.-]*" + _SENSITIVE + r"[A-Za-z0-9_.-]*\b\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;\"']+)")
_FLAG_TEXT = re.compile(
    r"(?i)(--?[A-Za-z0-9_.-]*" + _SENSITIVE + r"[A-Za-z0-9_.-]*\s+)(?!-)(\"[^\"]*\"|'[^']*'|\S+)")
_URL_USER = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@/\s]+)(@)", re.I)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_TOKENS = re.compile(
    r"\b(?:sk|pk|rk)[-_][A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"
    r"|\bAIza[0-9A-Za-z_-]{30,}")


def redact_text(text):
    s = str(text)
    s = _URL_USER.sub(lambda m: m.group(1) + MARK + m.group(3), s)
    s = _BEARER.sub(lambda m: m.group(1) + " " + MARK, s)
    s = _FLAG_TEXT.sub(lambda m: m.group(1) + MARK, s)
    s = _TEXT_KV.sub(lambda m: m.group(1) + MARK, s)
    s = _TOKENS.sub(MARK, s)
    return s


def redact_argv(argv):
    out, hide_next = [], False
    for a in argv:
        if hide_next:
            out.append(MARK)
            hide_next = False
            continue
        m = _FLAG_EQ.match(a) or None
        if m:
            out.append(m.group(1) + "=" + MARK)
            continue
        m = _ENV_EQ.match(a)
        if m:
            out.append(m.group(1) + "=" + MARK)
            continue
        if _FLAG_WORD.match(a):
            out.append(a)
            hide_next = True
            continue
        out.append(redact_text(a))
    return out


def redact_lines(text: str) -> str:
    return chr(10).join(redact_text(line) for line in str(text).splitlines())
