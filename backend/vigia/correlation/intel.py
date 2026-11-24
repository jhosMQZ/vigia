"""Vulnerability intelligence: OSV (dependencies), NVD (CVE details), CISA KEV, FIRST EPSS.

Only these fixed public endpoints are contacted (verified TLS, no proxies from env), results are cached
on disk, and everything is disabled in offline mode (VIGIA_OFFLINE=true).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from vigia import USER_AGENT
from vigia.config import get_settings

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

_nvd_lock = threading.Lock()
_nvd_last: list[float] = []


class IntelUnavailable(Exception):
    pass


def _cache_dir(kind: str) -> Path:
    d = get_settings().data_dir / "cache" / "intel" / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cached(kind: str, key: str, ttl: float) -> Any | None:
    p = _cache_dir(kind) / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")
    try:
        if time.time() - p.stat().st_mtime < ttl:
            return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return None


def _store(kind: str, key: str, value: Any) -> None:
    p = _cache_dir(kind) / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(value), encoding="utf-8")
    tmp.replace(p)


def _client() -> httpx.Client:
    if get_settings().offline:
        raise IntelUnavailable("modo offline activado")
    from vigia.security.egress import egress_client  # through a single-use egress gateway when configured
    return egress_client(verify=True, timeout=httpx.Timeout(30, connect=10), follow_redirects=False,
                         headers={"User-Agent": USER_AGENT})


# ------------------------------------------------------------------ OSV
def osv_query(packages: list[dict[str, str]]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    """packages: [{ecosystem, name, version}] -> {(eco,name,ver): [vuln details]}"""
    out: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    todo = []
    for p in packages:
        key = (p["ecosystem"], p["name"], p["version"])
        hit = _cached("osv-q", "|".join(key), 86400)
        if hit is not None:
            out[key] = hit
        else:
            todo.append(p)
    if not todo:
        return out
    with _client() as c:
        for i in range(0, len(todo), 500):
            chunk = todo[i:i + 500]
            body = {"queries": [{"package": {"ecosystem": p["ecosystem"], "name": p["name"]}, "version": p["version"]}
                                for p in chunk]}
            r = c.post(OSV_BATCH, json=body)
            r.raise_for_status()
            results = r.json().get("results", [])
            for p, res in zip(chunk, results):
                ids = [v["id"] for v in (res or {}).get("vulns", [])]
                details = [d for d in (osv_vuln(c, vid) for vid in ids[:30]) if d]
                key = (p["ecosystem"], p["name"], p["version"])
                out[key] = details
                _store("osv-q", "|".join(key), details)
    return out


def osv_vuln(client: httpx.Client, vid: str) -> dict[str, Any] | None:
    hit = _cached("osv-v", vid, 7 * 86400)
    if hit is not None:
        return hit
    r = client.get(OSV_VULN.format(vid))
    if r.status_code != 200:
        return None
    v = r.json()
    fixed: list[str] = []
    for aff in v.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    vector = None
    for sev in v.get("severity", []) or []:
        if sev.get("type") == "CVSS_V3" and str(sev.get("score", "")).startswith("CVSS:3"):
            vector = sev["score"]
    db_sev = (v.get("database_specific") or {}).get("severity")
    slim = {"id": v["id"], "aliases": v.get("aliases", []), "summary": (v.get("summary") or v.get("details", ""))[:400],
            "fixed": sorted(set(fixed))[:10], "cvss_vector": vector, "severity": db_sev,
            "references": [r["url"] for r in v.get("references", [])[:5]], "published": v.get("published")}
    _store("osv-v", vid, slim)
    return slim


# ------------------------------------------------------------------ KEV / EPSS / NVD
def kev_set() -> set[str]:
    hit = _cached("kev", "catalog", 86400)
    if hit is None:
        try:
            with _client() as c:
                r = c.get(KEV_FEED)
                r.raise_for_status()
                hit = sorted({v["cveID"] for v in r.json().get("vulnerabilities", [])})
                _store("kev", "catalog", hit)
        except (httpx.HTTPError, IntelUnavailable, ValueError, KeyError):
            return set()
    return set(hit)


def epss(cves: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    todo = []
    for cve in cves:
        hit = _cached("epss", cve, 86400)
        if hit is not None:
            out[cve] = hit
        else:
            todo.append(cve)
    if todo:
        try:
            with _client() as c:
                for i in range(0, len(todo), 100):
                    r = c.get(EPSS_API, params={"cve": ",".join(todo[i:i + 100])})
                    r.raise_for_status()
                    for row in r.json().get("data", []):
                        val = float(row.get("epss", 0))
                        out[row["cve"]] = val
                        _store("epss", row["cve"], val)
        except (httpx.HTTPError, IntelUnavailable, ValueError):
            pass
    return out


def nvd_cve(cve: str) -> dict[str, Any] | None:
    hit = _cached("nvd", cve, 7 * 86400)
    if hit is not None:
        return hit
    s = get_settings()
    window, limit = 30.0, (50 if s.nvd_api_key else 5)
    with _nvd_lock:  # respect NVD rate limit (5 or 50 requests / 30 s)
        now = time.time()
        while _nvd_last and now - _nvd_last[0] > window:
            _nvd_last.pop(0)
        if len(_nvd_last) >= limit:
            time.sleep(window - (now - _nvd_last[0]) + 0.5)
        _nvd_last.append(time.time())
    try:
        with _client() as c:
            headers = {"apiKey": s.nvd_api_key} if s.nvd_api_key else {}
            r = c.get(NVD_CVE, params={"cveId": cve}, headers=headers)
            if r.status_code != 200:
                return None
            items = r.json().get("vulnerabilities", [])
    except (httpx.HTTPError, IntelUnavailable, ValueError):
        return None
    if not items:
        return None
    c = items[0]["cve"]
    vector = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in c.get("metrics", {}).get(key, []):
            vector = m.get("cvssData", {}).get("vectorString")
            if vector:
                break
        if vector:
            break
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = [d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if d["value"].startswith("CWE-")]
    slim = {"id": cve, "cvss_vector": vector, "description": desc[:600], "cwe": cwes[:3]}
    _store("nvd", cve, slim)
    return slim
