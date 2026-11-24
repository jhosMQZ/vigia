"""Assessment profiles and per-scan configuration (validated, bounded)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Intensity = Literal["passive", "light", "standard", "deep"]
INTENSITY_RANK = {"passive": 0, "light": 1, "standard": 2, "deep": 3}


@dataclass(frozen=True)
class Profile:
    key: str
    name: str
    description: str
    modules: tuple[str, ...]
    tools: tuple[str, ...]
    intensity: Intensity
    needs_target: bool
    needs_source: bool
    max_duration_min: int
    max_requests: int
    rps: float
    concurrency: int
    crawl_depth: int
    crawl_max_pages: int
    port_set: Literal["none", "web", "top", "extended"]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_WEB = ("recon", "headers", "exposure", "frontend")
PROFILES: dict[str, Profile] = {p.key: p for p in (
    Profile("quick", "Quick Scan", "Evaluación inicial pasiva/ligera: huellas, cabeceras, ficheros expuestos y JS servido.",
            _WEB + ("crawler", "infra"), ("nuclei",), "light", True, False, 15, 1500, 8, 4, 1, 40, "web"),
    Profile("standard", "Standard Scan", "Auditoría ampliada: rastreo, inyecciones con canarios, APIs, puertos habituales.",
            _WEB + ("crawler", "browser", "injection", "api", "infra"), ("nuclei", "sslyze"), "standard", True, False, 60, 8000,
            10, 5, 3, 300, "top"),
    Profile("deep", "Deep Scan", "Cobertura máxima sin pruebas destructivas: rastreo profundo, inyecciones ciegas por "
            "tiempo, ZAP activo con política no destructiva, fuzzing de contenido limitado.",
            _WEB + ("crawler", "browser", "injection", "api", "infra"), ("nuclei", "zap", "ffuf", "subfinder", "sslyze", "testssl",
                                                             "nmap"),
            "deep", True, False, 240, 40000, 15, 8, 5, 1500, "extended"),
    Profile("code", "Code Audit", "Análisis del código fuente: SAST propio y externo, secretos, dependencias (CVE), IaC.",
            ("sast", "secrets", "sca", "iac"), ("opengrep", "semgrep", "bandit", "trivy", "betterleaks", "gitleaks",
                                                 "checkov"),
            "standard", False, True, 60, 0, 0, 1, 0, 0, "none"),
    Profile("api", "API Audit", "Evaluación de APIs (OWASP API Top 10 2023): inventario, autenticación, BOLA/BFLA, JWT, "
            "CORS, rate limiting, inyección en parámetros.",
            ("recon", "headers", "api", "injection", "exposure", "browser"), ("nuclei",), "standard", True, False, 90, 12000, 10, 5,
            2, 150, "web"),
    Profile("infra", "Infrastructure Audit", "Puertos y servicios, TLS y certificados, bases de datos y paneles expuestos, "
            "Docker/Kubernetes accesibles.",
            ("recon", "infra"), ("nmap", "nuclei", "sslyze", "testssl"), "standard", True, False, 90, 4000, 20, 20, 0, 0,
            "extended"),
    Profile("full", "Full Security Assessment", "Evaluación integral: Deep Scan + Code Audit + correlación código ↔ "
            "despliegue (rutas declaradas frente a expuestas).",
            _WEB + ("crawler", "browser", "injection", "api", "infra", "sast", "secrets", "sca", "iac", "routes"),
            ("nuclei", "zap", "ffuf", "subfinder", "sslyze", "testssl", "nmap", "opengrep", "semgrep", "bandit", "trivy",
             "betterleaks", "gitleaks", "checkov"),
            "deep", True, True, 300, 40000, 15, 8, 5, 1500, "extended"),
)}


class Window(BaseModel):
    """Allowed execution window (local hours of the server, 0-23); scans stop when it ends."""
    start_hour: int = Field(ge=0, le=23)
    end_hour: int = Field(ge=0, le=23)
    weekdays: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])

    @field_validator("weekdays")
    @classmethod
    def _wd(cls, v: list[int]) -> list[int]:
        if not v or any(d < 0 or d > 6 for d in v):
            raise ValueError("weekdays: valores 0 (lunes) a 6 (domingo)")
        return sorted(set(v))


class StopConditions(BaseModel):
    max_error_ratio: float = Field(0.3, ge=0.05, le=1.0)  # 5xx/timeouts in the recent window
    max_consecutive_conn_errors: int = Field(15, ge=3, le=200)
    stop_on_first_critical: bool = False


class ScanConfig(BaseModel):
    """User overrides; every value is clamped to the profile's hard ceiling."""
    model_config = {"extra": "forbid"}

    intensity: Intensity | None = None
    max_duration_min: int | None = Field(None, ge=1, le=720)
    max_requests: int | None = Field(None, ge=10, le=200000)
    rps: float | None = Field(None, gt=0, le=100)
    concurrency: int | None = Field(None, ge=1, le=32)
    crawl_depth: int | None = Field(None, ge=0, le=10)
    crawl_max_pages: int | None = Field(None, ge=0, le=10000)
    port_set: Literal["none", "web", "top", "extended"] | None = None
    extra_exclusions: list[str] = Field(default_factory=list, max_length=200)
    credential_ids: list[int] = Field(default_factory=list, max_length=4)
    modules_disabled: list[str] = Field(default_factory=list, max_length=30)
    tools_disabled: list[str] = Field(default_factory=list, max_length=30)
    window: Window | None = None
    stop: StopConditions = Field(default_factory=StopConditions)
    openapi_url: str | None = Field(None, max_length=2048)
    include_paths: list[str] = Field(default_factory=list, max_length=200)  # extra seed paths ("/admin", "/api/v1/…")
    spec_source_ids: list[int] = Field(default_factory=list, max_length=10)  # uploaded OpenAPI/Postman specs

    @field_validator("extra_exclusions", "include_paths")
    @classmethod
    def _short(cls, v: list[str]) -> list[str]:
        out = []
        for s in v:
            s = s.strip()
            if not s:
                continue
            if len(s) > 512 or any(ord(c) < 32 for c in s):
                raise ValueError("Entrada inválida (longitud o caracteres de control)")
            out.append(s)
        return out

    @model_validator(mode="after")
    def _paths(self) -> "ScanConfig":
        for p in self.include_paths:
            if not p.startswith("/"):
                raise ValueError("include_paths debe contener rutas que empiecen por '/'")
        return self


@dataclass
class EffectiveConfig:
    profile: Profile
    intensity: Intensity
    max_duration_min: int
    max_requests: int
    rps: float
    concurrency: int
    crawl_depth: int
    crawl_max_pages: int
    port_set: str
    modules: list[str]
    tools: list[str]
    exclusions: list[str] = field(default_factory=list)
    credential_ids: list[int] = field(default_factory=list)
    window: dict | None = None
    stop: dict = field(default_factory=dict)
    openapi_url: str | None = None
    include_paths: list[str] = field(default_factory=list)
    spec_source_ids: list[int] = field(default_factory=list)

    def at_least(self, level: Intensity) -> bool:
        return INTENSITY_RANK[self.intensity] >= INTENSITY_RANK[level]


def effective_config(profile_key: str, cfg: ScanConfig | dict | None) -> EffectiveConfig:
    prof = PROFILES[profile_key]
    c = cfg if isinstance(cfg, ScanConfig) else ScanConfig(**(cfg or {}))
    intensity = c.intensity or prof.intensity
    # Users may lower intensity freely; raising above the profile is allowed only up to "deep" (non-destructive).
    return EffectiveConfig(
        profile=prof, intensity=intensity,
        max_duration_min=min(c.max_duration_min or prof.max_duration_min, 720),
        max_requests=c.max_requests or prof.max_requests,
        rps=c.rps or prof.rps or 1, concurrency=c.concurrency or prof.concurrency or 1,
        crawl_depth=prof.crawl_depth if c.crawl_depth is None else c.crawl_depth,
        crawl_max_pages=prof.crawl_max_pages if c.crawl_max_pages is None else c.crawl_max_pages,
        port_set=c.port_set or prof.port_set,
        modules=[m for m in prof.modules if m not in c.modules_disabled],
        tools=[t for t in prof.tools if t not in c.tools_disabled],
        exclusions=c.extra_exclusions, credential_ids=c.credential_ids,
        window=c.window.model_dump() if c.window else None, stop=c.stop.model_dump(),
        openapi_url=c.openapi_url, include_paths=c.include_paths, spec_source_ids=c.spec_source_ids)
