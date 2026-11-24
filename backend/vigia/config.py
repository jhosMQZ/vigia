"""Central configuration (env vars prefixed VIGIA_)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_home() -> Path:
    """Repository root when running from a source checkout, otherwise the current directory."""
    here = Path(__file__).resolve()
    root = here.parents[2]
    if (root / "backend" / "vigia").is_dir():
        return root
    return Path.cwd()


HOME = _default_home()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VIGIA_", env_file=".env", extra="ignore")

    home: Path = Field(default=HOME)
    data_dir: Path = Field(default=HOME / "data")
    database_url: str | None = None  # default: sqlite in data_dir

    # API
    bind_host: str = "127.0.0.1"
    bind_port: int = 8600
    cors_origins: list[str] = []  # same-origin by default; the Vite dev server proxies /api (no CORS needed)
    jwt_ttl_minutes: int = 30
    jwt_issuer: str = "vigia"
    login_max_attempts: int = 5
    login_lockout_minutes: int = 15
    api_rate_limit_per_minute: int = 300
    login_rate_limit_per_minute: int = 10
    max_upload_mb: int = 200
    max_json_body_kb: int = 512
    embedded_worker: bool = True  # run a worker inside the API process (single-node mode)
    serve_frontend: bool = True  # serve frontend/dist from the API when it exists

    # Worker / engine
    worker_poll_seconds: float = 1.0
    worker_lease_seconds: int = 120
    worker_max_parallel_scans: int = 1
    tools_dir: Path = Field(default=HOME / "tools")
    tool_default_timeout: int = 900
    tool_max_memory_mb: int = 2048
    tool_max_output_mb: int = 64
    tool_allow_path_lookup: bool = True  # also detect engines installed system-wide (PATH)
    zap_api_url: str | None = None  # e.g. http://127.0.0.1:8090 (ZAP daemon)
    zap_api_key: str | None = None
    git_allowed_hosts: list[str] = ["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"]
    allowed_import_roots: list[Path] = []  # local folders allowed for "path" imports (empty = disabled)

    # Network policy
    offline: bool = False  # disables OSV/NVD/KEV lookups
    allow_private_targets: bool = False  # global kill-switch: scopes may only use private IPs if this is True
    http_verify_tls: bool = False  # scanners must reach staging with self-signed certs; TLS module reports cert issues
    nvd_api_key: str | None = None

    # Egress / privacy — route the scanner's outbound traffic through dedicated infrastructure.
    # When set, every scan request goes through the proxy; there is NEVER a silent fallback to a direct
    # connection (a scan is refused if the proxy is unreachable). Supports http(s):// and socks5(h)://.
    http_proxy: str | None = None  # VIGIA_HTTP_PROXY
    require_proxy: bool = False  # VIGIA_REQUIRE_PROXY: refuse scans of public targets when no proxy is configured
    egress_check_url: str | None = None  # VIGIA_EGRESS_CHECK_URL: optional IP-echo endpoint for the privacy panel
    # VIGIA_DNS_RESOLVER: auto (remote DoH through the egress when a proxy is set, system otherwise) | system |
    # https://…/dns-query (DoH) | tcp://IP:53. A remote resolver failure never falls back to the local resolver.
    dns_resolver: str = "auto"
    # VIGIA_EGRESS_KILL_SWITCH: with an egress configured, kill any engine that opens a socket outside loopback.
    egress_kill_switch: bool = True
    # VIGIA_EGRESS_ISOLATION: auto | appcontainer | external | detect. With an egress, preventive isolation of the
    # engines must verify (probe) or the scan is refused; "detect" is the explicit opt-out (kill switch only).
    egress_isolation: str = "auto"
    # VIGIA_CONFINE_WORKER: with a local tunnel egress (proxy on loopback) and AppContainer isolation, run the whole
    # scan (worker + engines) inside its own per-scan AppContainer, so Vigía's own process is confined too.
    confine_worker: bool = True
    # Managed SSH tunnel (recommended egress): VIGIA_SSH_TUNNEL=user@host[:port]; VIGIA_SSH_KNOWN_HOSTS is mandatory
    # (strict host-key verification, never trust-on-first-use); VIGIA_SSH_IDENTITY: private key (optional).
    ssh_tunnel: str | None = None
    ssh_known_hosts: str | None = None
    ssh_identity: str | None = None
    browser_enabled: bool = True  # allow Playwright-based crawling/DOM-XSS when the browser is available

    # Retention
    evidence_retention_days: int = 180
    workspace_retention_hours: int = 24

    @field_validator("data_dir", "tools_dir", mode="after")
    @classmethod
    def _absolute(cls, v: Path) -> Path:
        return v if v.is_absolute() else (HOME / v)

    @property
    def tool_bin_dir(self) -> Path:
        return self.tools_dir / "bin"

    @property
    def tool_py_dir(self) -> Path:
        return self.tools_dir / "py"

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'vigia.db').resolve().as_posix()}"

    def ensure_dirs(self) -> None:
        import os
        for sub in ("", "evidence", "workspaces", "sources", "reports", "keys", "cache", "uploads"):
            d = self.data_dir / sub
            d.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":  # database, evidence and keys: owner only (Windows inherits the profile ACL)
                try:
                    d.chmod(0o700)
                except OSError:
                    pass


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    # privacy settings saved from the UI (admin) apply only where no VIGIA_* environment variable pins the value
    from vigia.security.runtime_settings import env_locked, load
    for k, v in load().items():
        if not env_locked(k):
            setattr(s, k, v)
    s.ensure_dirs()
    return s
