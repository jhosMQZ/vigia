"""ZAP integration through its REST API (daemon mode).

Either an operator-provided daemon (VIGIA_ZAP_API_URL + VIGIA_ZAP_API_KEY) or a local, on-demand daemon
started from tools/bin/zap with the bundled JRE, bound to 127.0.0.1 on a random port with a random API key
and a throw-away home directory. ZAP runs in *protected mode* with a context that only includes in-scope
hosts, so its spider/active scanner cannot touch anything else.

Egress: the local daemon's outgoing proxy is set (and verified) to Vigía's scope gateway before any scan action,
so every request goes through the gateway (scope, remote DNS, egress only). With a dedicated egress the JVM also
gets ``-Djdk.net.hosts.file`` pointing at a loopback-only hosts file — Java cannot resolve any name locally — and
the daemon runs under the kill switch.
"""
from __future__ import annotations

import json
import re
import secrets
import socket
import time
from pathlib import Path
from typing import Any

import httpx

from vigia.config import get_settings
from vigia.core.toolrunner import Daemon, RunLimits, ToolRunner


class ZapError(Exception):
    pass


def zap_version(url: str, key: str | None) -> str:
    return ZapClient(url, key).get("core/view/version")["version"]


class ZapClient:
    def __init__(self, base: str, key: str | None, timeout: float = 60):
        if not re.match(r"^https?://(127\.0\.0\.1|localhost|\[::1\]|[\w.\-]+)(:\d+)?/?$", base):
            raise ZapError("URL de ZAP inválida")
        self.base = base.rstrip("/")
        self.key = key or ""
        self.client = httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False)

    def _call(self, kind: str, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        comp, typ, name = path.split("/")
        url = f"{self.base}/JSON/{comp}/{typ}/{name}/"
        p = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in (params or {}).items()}
        r = self.client.get(url, params=p, headers={"X-ZAP-API-Key": self.key})
        if r.status_code != 200:
            raise ZapError(f"ZAP {path}: HTTP {r.status_code} {r.text[:200]}")
        return r.json()

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        return self._call("view", path, params)

    def act(self, path: str, **params: Any) -> dict[str, Any]:
        return self._call("action", path, params)

    def close(self) -> None:
        self.client.close()


def local_install() -> tuple[Path, Path] | None:
    s = get_settings()
    jar = next(iter(sorted((s.tool_bin_dir / "zap").glob("zap-*.jar"))), None)
    java = s.tool_bin_dir / "jre" / "bin" / ("java.exe" if __import__("os").name == "nt" else "java")
    if jar and jar.exists() and java.exists():
        return java, jar
    return None


def local_version() -> str | None:
    s = get_settings()
    try:
        return json.loads((s.tool_bin_dir / "zap" / ".vigia-install.json").read_text(encoding="utf-8"))["version"]
    except (OSError, ValueError, KeyError):
        return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ZapSession:
    """Context manager yielding a ready ZapClient; stops the local daemon on exit."""

    def __init__(self, runner: ToolRunner, workdir: Path, memory_mb: int = 2048, *, gateway=None,  # noqa: ANN001
                 netwatch: bool = False, isolate: bool = False):
        self.runner, self.workdir, self.memory_mb = runner, workdir, memory_mb
        self.gateway = gateway
        self.netwatch = netwatch
        self.isolate = isolate
        self.daemon: Daemon | None = None
        self.client: ZapClient | None = None

    @property
    def net_violations(self) -> list:
        return self.daemon.net_violations if self.daemon is not None else []

    def __enter__(self) -> ZapClient:
        s = get_settings()
        if s.zap_api_url:
            self.client = ZapClient(s.zap_api_url, s.zap_api_key)
            self.client.get("core/view/version")
            return self.client
        inst = local_install()
        if not inst:
            raise ZapError("ZAP no está instalado (vigia tools install zap jre) ni configurado (VIGIA_ZAP_API_URL)")
        java, jar = inst
        port, key = _free_port(), secrets.token_urlsafe(24)
        home = self.workdir / "zaphome"
        home.mkdir(parents=True, exist_ok=True)
        jvm = [f"-Xmx{max(512, self.memory_mb - 512)}m"]
        if self.netwatch:  # dedicated egress: the JVM may not resolve names locally at all
            hosts = self.workdir / "hosts"
            hosts.write_text(f"127.0.0.1 localhost {socket.gethostname()}\n::1 localhost\n", encoding="utf-8")
            jvm += [f"-Djdk.net.hosts.file={hosts}", "-Djava.net.preferIPv4Stack=true"]
        argv = [str(java), *jvm, "-jar", str(jar), "-daemon", "-host", "127.0.0.1",
                "-port", str(port), "-dir", str(home), "-config", f"api.key={key}",
                "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.regex=false",
                "-config", "start.checkForUpdates=false", "-config", "start.checkAddonUpdates=false",
                "-config", "start.installAddonUpdates=false", "-config", "start.installScannerRules=false",
                "-config", "database.recoverylog=false", "-config", "connection.timeoutInSecs=20"]
        self.daemon = self.runner.spawn("zap", argv, limits=RunLimits(max_memory_mb=self.memory_mb + 512,
                                                                      netwatch=self.netwatch, isolate=self.isolate),
                                        workdir=self.workdir)
        self.client = ZapClient(f"http://127.0.0.1:{port}", key, timeout=120)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if not self.daemon.alive:
                raise ZapError(f"El demonio ZAP terminó al arrancar: {self.daemon.log_tail(800)}")
            try:
                self.client.get("core/view/version")
            except (httpx.HTTPError, ZapError):
                time.sleep(2)
                continue
            self._route_through_gateway()
            return self.client
        raise ZapError("ZAP no respondió en 180 s")

    def _route_through_gateway(self) -> None:
        """Point ZAP's outgoing connections at the scope gateway and verify it (fail closed)."""
        if self.gateway is None or self.client is None:
            return
        z = self.client
        z.act("network/action/setHttpProxy", host="127.0.0.1", port=str(self.gateway.port), realm="vigia",
              username=self.gateway.username, password=self.gateway.password)
        z.act("network/action/setHttpProxyEnabled", enabled=True)
        z.act("network/action/setHttpProxyAuthEnabled", enabled=True)  # send the gateway's per-run credentials
        cfg = z.get("network/view/getHttpProxy").get("getHttpProxy", {})
        enabled = str(z.get("network/view/isHttpProxyEnabled").get("isHttpProxyEnabled")).lower() == "true"
        enabled = enabled and str(z.get("network/view/isHttpProxyAuthEnabled").get("isHttpProxyAuthEnabled")).lower() == "true"
        excl = z.get("network/view/getHttpProxyExclusions").get("getHttpProxyExclusions", [])
        if not enabled or str(cfg.get("host")) != "127.0.0.1" or int(cfg.get("port", 0)) != self.gateway.port or excl:
            raise ZapError(f"No se pudo forzar la salida de ZAP por la pasarela (config={cfg}, activo={enabled}, "
                           f"exclusiones={excl}); no se ejecuta sin ella")

    def __exit__(self, *exc: Any) -> None:
        if self.client is not None and self.daemon is not None:
            try:
                self.client.act("core/action/shutdown")
            except (httpx.HTTPError, ZapError):
                pass
            time.sleep(1)
        if self.client is not None:
            self.client.close()
        if self.daemon is not None:
            self.daemon.stop()


# Active-scan rules disabled in Vigía's policy (resource-exhaustion style tests).
DISABLED_ASCAN = ["30001", "30002", "30003", "40032", "10104", "40033"]
# ZAP plugin id -> Vigía category (precise mappings first; CWE fallback in the adapter).
ZAP_PLUGIN_CATEGORY = {
    "10038": "missing_csp", "10055": "weak_csp", "10020": "clickjacking", "10021": "missing_xcto", "10035": "missing_hsts",
    "10010": "insecure_cookie", "10011": "insecure_cookie", "10054": "insecure_cookie", "10036": "version_disclosure",
    "10037": "version_disclosure", "40012": "xss_reflected", "40014": "xss_stored", "40016": "xss_stored",
    "40017": "xss_stored", "40018": "sqli", "40019": "sqli", "40020": "sqli", "40021": "sqli", "40022": "sqli",
    "40024": "sqli", "40027": "sqli", "90020": "cmdi", "6": "path_traversal", "40046": "ssrf", "20019": "open_redirect",
    "90035": "ssti", "90036": "ssti", "40003": "crlf_injection", "10098": "cors_misconfig", "40040": "cors_misconfig",
    "90022": "error_disclosure", "10023": "error_disclosure", "0": "directory_listing", "10015": "cache_sensitive",
    "10202": "csrf", "10063": "missing_permissions_policy", "90023": "external_finding", "40009": "external_finding",
    "10045": "exposed_sourcemap", "40034": "exposed_config", "40035": "exposed_debug", "10105": "auth_weakness",
}
ZAP_NOISE = {"10096", "10027", "10109", "10049", "10104", "10112", "10024", "10111", "10050"}
