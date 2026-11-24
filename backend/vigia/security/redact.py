# vigia:ignore-file — catálogo de patrones de detección (las expresiones regulares se detectarían a sí mismas)
"""Redaction of secrets in evidence, logs and reports (evidence must prove, never leak)."""
from __future__ import annotations

import re
from typing import Any

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "x-auth-token",
                     "x-csrf-token", "x-xsrf-token", "api-key", "apikey", "x-amz-security-token"}

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)"),
     "-----BEGIN PRIVATE KEY-----[REDACTADO]-----END PRIVATE KEY-----"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), None),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), None),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), None),
    (re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"), None),
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b"), None),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), None),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9+/=._\-]{12,}"), None),
    (re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^:/\s@]+:)([^@\s]{2,})(@)"), "url"),
    (re.compile(r"""(?ix)
        ((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|
            auth[_-]?token|session[_-]?secret|db[_-]?pass(?:word)?|aws_secret_access_key|signing[_-]?key)
         [A-Za-z0-9_]*["']?\s*[:=]\s*["']?)
        ([^\s"',;&<>]{3,})"""), "kv"),
]


def mask(value: str, keep: int = 4) -> str:
    if len(value) <= keep + 2:
        return "****"
    return value[:keep] + "****" + f"[{len(value)}]"


def redact(text: str | None, max_len: int | None = None) -> str:
    if not text:
        return ""
    out = text
    for pat, mode in _PATTERNS:
        if mode == "url":
            out = pat.sub(lambda m: m.group(1) + "****" + m.group(3), out)
        elif mode == "kv":
            out = pat.sub(lambda m: m.group(1) + mask(m.group(2)), out)
        elif mode is None:
            out = pat.sub(lambda m: mask(m.group(0)), out)
        else:
            out = pat.sub(mode, out)
    if max_len is not None and len(out) > max_len:
        out = out[:max_len] + f"… [truncado, {len(text)} bytes]"
    return out


def redact_headers(headers: dict[str, str] | Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in dict(headers).items():
        if k.lower() in SENSITIVE_HEADERS:
            if k.lower() == "set-cookie" and "=" in v:
                name = v.split("=", 1)[0]
                attrs = v.split(";", 1)[1] if ";" in v else ""
                out[k] = f"{name}=****;{attrs}"
            else:
                out[k] = mask(v, 6)
        else:
            out[k] = redact(v)
    return out


def redact_obj(obj: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "…"
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: ("****" if isinstance(k, str) and k.lower() in SENSITIVE_HEADERS | {"password", "secret", "token"}
                    else redact_obj(v, depth + 1)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, depth + 1) for v in obj]
    return obj
