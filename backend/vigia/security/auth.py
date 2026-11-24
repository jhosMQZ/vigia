"""Authentication primitives: argon2id passwords, short-lived JWT, revocation, lockout, password policy."""
from __future__ import annotations

import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from vigia.config import get_settings
from vigia.db import RevokedToken, User, utcnow
from vigia.security.crypto import jwt_secret

ROLES = ("admin", "analyst", "viewer")
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
# Pre-computed hash so that unknown usernames cost the same as known ones (no user enumeration by timing).
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))

_COMMON = {"password", "123456", "12345678", "123456789", "qwerty", "admin", "letmein", "welcome", "iloveyou",
           "password1", "admin123", "changeme", "vigia", "contraseña", "passw0rd", "administrator", "root", "toor"}


class AuthError(Exception):
    pass


def password_problems(password: str, username: str = "") -> list[str]:
    probs = []
    if len(password) < 12:
        probs.append("mínimo 12 caracteres")
    if len(password) > 256:
        probs.append("máximo 256 caracteres")
    lowered = password.lower()
    if lowered in _COMMON or any(lowered.startswith(c) and len(lowered) - len(c) <= 3 for c in _COMMON if len(c) >= 6):
        probs.append("contraseña demasiado común")
    if username and username.lower() in lowered:
        probs.append("no puede contener el nombre de usuario")
    classes = sum(bool(any(f(ch) for ch in password)) for f in (str.islower, str.isupper, str.isdigit,
                                                               lambda c: not c.isalnum()))
    if classes < 3:
        probs.append("usa al menos 3 tipos de carácter (minúsculas, mayúsculas, dígitos, símbolos)")
    return probs


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored: str | None, password: str) -> bool:
    try:
        return _ph.verify(stored or _DUMMY_HASH, password) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored: str) -> bool:
    try:
        return _ph.check_needs_rehash(stored)
    except InvalidHashError:
        return True


@dataclass
class TokenInfo:
    token: str
    jti: str
    expires_at: datetime


def issue_token(user: User) -> TokenInfo:
    s = get_settings()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=s.jwt_ttl_minutes)
    jti = uuid.uuid4().hex
    claims = {"sub": str(user.id), "usr": user.username, "role": user.role, "ver": user.token_version,
              "jti": jti, "iat": int(now.timestamp()), "nbf": int(now.timestamp()) - 5, "exp": int(exp.timestamp()),
              "iss": s.jwt_issuer, "typ": "access"}
    return TokenInfo(jwt.encode(claims, jwt_secret(), algorithm="HS256"), jti, exp.replace(tzinfo=None))


def decode_token(token: str) -> dict:
    s = get_settings()
    try:
        claims = jwt.decode(token, jwt_secret(), algorithms=["HS256"], issuer=s.jwt_issuer,
                            options={"require": ["sub", "jti", "exp", "iat", "iss", "ver", "typ"]}, leeway=5)
    except jwt.PyJWTError as e:
        raise AuthError("Token inválido o caducado") from e
    if claims.get("typ") != "access":
        raise AuthError("Tipo de token inválido")
    return claims


def authenticate_token(db: Session, token: str) -> tuple[User, dict]:
    claims = decode_token(token)
    if db.get(RevokedToken, claims["jti"]) is not None:
        raise AuthError("Sesión cerrada")
    try:
        uid = int(claims["sub"])
    except (TypeError, ValueError) as e:
        raise AuthError("Token inválido") from e
    user = db.get(User, uid)
    if user is None or not user.is_active or user.token_version != claims["ver"]:
        raise AuthError("Sesión no válida")
    return user, claims


def revoke(db: Session, claims: dict) -> None:
    exp = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc).replace(tzinfo=None)
    if db.get(RevokedToken, claims["jti"]) is None:
        db.add(RevokedToken(jti=claims["jti"], exp=exp))
    db.execute(delete(RevokedToken).where(RevokedToken.exp < utcnow()))
    db.commit()


def login(db: Session, username: str, password: str) -> User:
    """Verify credentials with lockout. Raises AuthError with a generic message."""
    s = get_settings()
    user = db.scalar(select(User).where(User.username == username.strip().lower()))
    now = utcnow()
    if user is not None and user.locked_until and user.locked_until > now:
        verify_password(None, password)  # constant work
        raise AuthError("Cuenta bloqueada temporalmente por intentos fallidos")
    ok = verify_password(user.password_hash if user else None, password)
    if not ok or user is None or not user.is_active:
        if user is not None:
            user.failed_logins += 1
            if user.failed_logins >= s.login_max_attempts:
                user.locked_until = now + timedelta(minutes=s.login_lockout_minutes)
                user.failed_logins = 0
            db.commit()
        raise AuthError("Usuario o contraseña incorrectos")
    user.failed_logins = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    db.commit()
    return user


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_matches(a: str | None, b: str | None) -> bool:
    return bool(a and b and hmac.compare_digest(a.encode(), b.encode()))
