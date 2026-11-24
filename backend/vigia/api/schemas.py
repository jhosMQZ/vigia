"""Strict request schemas (extra fields forbidden, bounded lengths, typed enums)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vigia.core.profiles import PROFILES, ScanConfig

NAME_RE = re.compile(r"^[\w .,:()\-/áéíóúÁÉÍÓÚñÑüÜ]{1,120}$")
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]{2,63}$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginIn(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordChangeIn(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class UserCreateIn(Strict):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "analyst", "viewer"] = "analyst"

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        v = v.lower()
        if not USER_RE.match(v):
            raise ValueError("usuario: 3-64 caracteres [a-z0-9._-]")
        return v


class UserUpdateIn(Strict):
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None
    password: str | None = Field(None, min_length=12, max_length=256)


class ProjectIn(Strict):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field("", max_length=4000)

    @field_validator("name")
    @classmethod
    def _n(cls, v: str) -> str:
        if not NAME_RE.match(v):
            raise ValueError("nombre con caracteres no permitidos")
        return v


class ProjectUpdateIn(Strict):
    name: str | None = Field(None, min_length=1, max_length=120)
    description: str | None = Field(None, max_length=4000)


class MemberIn(Strict):
    username: str = Field(min_length=3, max_length=64)
    role: Literal["owner", "analyst", "viewer"] = "viewer"


class ScopeIn(Strict):
    name: str = Field(min_length=1, max_length=120)
    targets: list[str] = Field(min_length=1, max_length=100)
    exclusions: list[str] = Field(default_factory=list, max_length=200)
    allow_private: bool = False
    lab_mode: bool = False
    allowed_ports: list[int] | None = Field(None, max_length=2000)
    max_rps: float = Field(10.0, gt=0, le=100)

    @field_validator("targets", "exclusions")
    @classmethod
    def _items(cls, v: list[str]) -> list[str]:
        out = []
        for s in v:
            s = s.strip()
            if not s:
                continue
            if len(s) > 2048 or any(ord(c) < 32 for c in s):
                raise ValueError("entrada inválida")
            out.append(s)
        return out

    @field_validator("allowed_ports")
    @classmethod
    def _ports(cls, v: list[int] | None) -> list[int] | None:
        if v is not None and any(p < 1 or p > 65535 for p in v):
            raise ValueError("puertos 1-65535")
        return v


class ScopeUpdateIn(Strict):
    name: str | None = Field(None, min_length=1, max_length=120)
    targets: list[str] | None = Field(None, min_length=1, max_length=100)
    exclusions: list[str] | None = Field(None, max_length=200)
    allow_private: bool | None = None
    lab_mode: bool | None = None
    allowed_ports: list[int] | None = None
    max_rps: float | None = Field(None, gt=0, le=100)


AUTH_STATEMENT = ("Declaro que soy titular de los sistemas incluidos en este alcance o que dispongo de autorización "
                  "expresa y vigente de su titular para realizar pruebas de seguridad sobre ellos, dentro de los límites "
                  "indicados, y que asumo la responsabilidad del uso de esta herramienta.")


class AuthorizeIn(Strict):
    accept: Literal[True]
    statement: str = Field(min_length=20, max_length=4000)
    reference: str = Field(min_length=3, max_length=255)  # contract / ticket / written authorization reference
    valid_until: datetime | None = None
    owner_contact: str = Field("", max_length=255)


class GitSourceIn(Strict):
    url: str = Field(min_length=10, max_length=2048)
    ref: str | None = Field(None, max_length=120)


class PathSourceIn(Strict):
    path: str = Field(min_length=1, max_length=1024)


class CredentialIn(Strict):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[\w.\-]+$")
    kind: Literal["form", "json", "bearer", "header", "basic", "cookie"]
    role: Literal["admin", "user"] = "user"
    data: dict[str, Any]

    @field_validator("data")
    @classmethod
    def _d(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json
        if len(json.dumps(v)) > 16000:
            raise ValueError("datos de credencial demasiado grandes")
        return v


class ScanIn(Strict):
    profile: str
    scope_id: int | None = None
    source_id: int | None = None
    config: ScanConfig = Field(default_factory=ScanConfig)

    @field_validator("profile")
    @classmethod
    def _p(cls, v: str) -> str:
        if v not in PROFILES:
            raise ValueError(f"perfil desconocido; válidos: {', '.join(PROFILES)}")
        return v


class FindingUpdateIn(Strict):
    remediation_status: Literal["open", "in_progress", "fixed", "accepted_risk", "false_positive"] | None = None
    analyst_notes: str | None = Field(None, max_length=8000)


class TargetsValidateIn(Strict):
    targets: list[str] = Field(min_length=1, max_length=100)
