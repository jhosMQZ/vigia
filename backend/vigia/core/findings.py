"""Normalised finding produced by native modules and tool adapters (before correlation)."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 … critical=4
CONFIDENCES = ("confirmed", "likely", "suspected", "false_positive")
CONF_RANK = {"false_positive": 0, "suspected": 1, "likely": 2, "confirmed": 3}

# Configuration issues are properties of a host, not of each URL (engines such as ZAP report them per URL).
HOST_LEVEL = {"missing_hsts", "missing_csp", "weak_csp", "clickjacking", "missing_xcto", "missing_referrer_policy",
              "missing_permissions_policy", "version_disclosure", "no_https", "cache_sensitive", "insecure_cookie",
              "mixed_content", "cors_misconfig", "dangerous_methods", "tech_fingerprint", "error_disclosure"}
_ID_SEG = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[0-9a-f]{32,64})$",
                     re.I)


def endpoint_template(url: str | None) -> str:
    """URL without query values and with id-like path segments generalised: /users/42?x=1 -> /users/{id}?x"""
    if not url:
        return ""
    p = urlsplit(url)
    segs = ["{id}" if _ID_SEG.match(s) else s for s in p.path.split("/")]
    q = "&".join(sorted({kv.split("=", 1)[0] for kv in p.query.split("&") if kv})) if p.query else ""
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    return f"{p.scheme}://{host}{port}{'/'.join(segs) or '/'}" + (f"?{q}" if q else "")


def normalise_asset(asset: str) -> str:
    a = asset.strip().lower().rstrip("/")
    return re.sub(r"^https?://", "", a)


@dataclass
class FindingDraft:
    title: str
    category: str  # key in correlation.catalog.CATALOG
    module: str
    severity: str = "medium"
    confidence: str = "suspected"
    asset: str = ""
    endpoint: str | None = None
    method: str | None = None
    parameter: str | None = None
    file: str | None = None
    line: int | None = None
    function: str | None = None
    snippet: str | None = None
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    likelihood: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str | None = None
    cve: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cvss_vector: str | None = None
    sources: list[str] = field(default_factory=list)
    # True when Vigía itself observed/verified the issue (differential test, served file…). Only native
    # modules may set it; adapters never do (correlation rule: tools alone can't confirm).
    native_evidence: bool = False
    tags: list[str] = field(default_factory=list)
    fingerprint_extra: str = ""
    # When True the severity set by the producer is kept (no catalogue default vector / severity override).
    keep_severity: bool = False

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "info"
        if self.confidence not in CONFIDENCES:
            self.confidence = "suspected"
        if not self.sources:
            self.sources = [self.module]

    @property
    def fingerprint(self) -> str:
        # Code findings are identified by category + location, so overlapping rules (lexical + AST) merge.
        extra = "" if self.file and self.line else self.fingerprint_extra
        # CWE only disambiguates generic external results; mapped categories must merge across engines.
        cwe = (self.cwe or "") if self.category in ("external_finding", "sast_generic") else ""
        ep = "" if self.category in HOST_LEVEL else endpoint_template(self.endpoint)
        parts = [self.category, cwe, normalise_asset(self.asset), ep,
                 (self.parameter or "").lower(), f"{self.file or ''}:{self.line or ''}", extra]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d
