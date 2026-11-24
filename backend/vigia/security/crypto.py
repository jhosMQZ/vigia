"""Key management and encryption at rest.

* Credential payloads: Fernet (AES-128-CBC + HMAC-SHA256) via MultiFernet, so keys can be rotated:
  the first key encrypts, all keys decrypt (``vigia keys rotate`` re-encrypts stored secrets).
* Separate random secrets for JWT signing and the audit-chain HMAC (compromise of one does not give the others).
* Key material comes from env vars (VIGIA_MASTER_KEY / VIGIA_JWT_SECRET / VIGIA_AUDIT_KEY) or from files in
  ``data/keys`` created with owner-only permissions.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from vigia.config import get_settings


class CryptoError(Exception):
    pass


def _restrict(path: Path) -> None:
    """Owner-only permissions (POSIX 0600; Windows: remove inherited ACLs, grant current user only)."""
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME")
            icacls = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "icacls.exe"
            if user and icacls.is_file():  # absolute path: no PATH hijacking
                subprocess.run([str(icacls), str(path), "/inheritance:r", "/grant:r", f"{user}:F"],  # noqa: S603
                               capture_output=True, timeout=15, check=False)
        else:
            path.chmod(0o600)
    except (OSError, subprocess.SubprocessError):
        pass


def _key_file(name: str, generator) -> list[bytes]:  # noqa: ANN001
    keys_dir = get_settings().data_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    path = keys_dir / name
    if not path.exists():
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(generator() + b"\n")
        _restrict(tmp)
        os.replace(tmp, path)
    return [line.strip() for line in path.read_bytes().splitlines() if line.strip()]


@lru_cache
def _fernet() -> MultiFernet:
    env = os.environ.get("VIGIA_MASTER_KEY")
    raw = [k.strip().encode() for k in env.split(",") if k.strip()] if env else _key_file("master.key", Fernet.generate_key)
    try:
        return MultiFernet([Fernet(k) for k in raw])
    except (ValueError, TypeError) as e:
        raise CryptoError("Clave maestra inválida (se espera una clave Fernet en base64 urlsafe)") from e


@lru_cache
def jwt_secret() -> bytes:
    env = os.environ.get("VIGIA_JWT_SECRET")
    if env:
        if len(env) < 32:
            raise CryptoError("VIGIA_JWT_SECRET debe tener al menos 32 caracteres")
        return env.encode()
    return base64.urlsafe_b64decode(_key_file("jwt.key", lambda: base64.urlsafe_b64encode(secrets.token_bytes(64)))[0])


@lru_cache
def audit_key() -> bytes:
    env = os.environ.get("VIGIA_AUDIT_KEY")
    if env:
        return env.encode()
    return base64.urlsafe_b64decode(_key_file("audit.key", lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)))[0])


def encrypt_json(obj: Any) -> str:
    return _fernet().encrypt(json.dumps(obj, separators=(",", ":")).encode()).decode()


def decrypt_json(token: str) -> Any:
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except InvalidToken as e:
        raise CryptoError("No se pudo descifrar (clave incorrecta o dato manipulado)") from e


def rotate_token(token: str) -> str:
    return _fernet().rotate(token.encode()).decode()


def add_master_key() -> None:
    """Prepend a new primary key (old keys keep decrypting until secrets are re-encrypted)."""
    if os.environ.get("VIGIA_MASTER_KEY"):
        raise CryptoError("La clave maestra viene de VIGIA_MASTER_KEY: rótala en tu gestor de secretos")
    path = get_settings().data_dir / "keys" / "master.key"
    existing = _key_file("master.key", Fernet.generate_key)
    path.write_bytes(b"\n".join([Fernet.generate_key(), *existing]) + b"\n")
    _restrict(path)
    _fernet.cache_clear()


def reset_caches_for_tests() -> None:
    _fernet.cache_clear()
    jwt_secret.cache_clear()
    audit_key.cache_clear()


if sys.platform == "win32":  # pragma: no cover - documentation aid
    __doc__ += "\nEn Windows los ficheros de clave se protegen con ACL (icacls) del usuario que ejecuta Vigía."
