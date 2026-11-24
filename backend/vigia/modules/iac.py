"""Infrastructure as code: Dockerfile, docker-compose, Kubernetes manifests and basic Terraform rules (native)."""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import yaml

from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.modules.source import iter_files, read_text

SECRET_ENV = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)")
DB_PORTS = {"3306", "5432", "27017", "6379", "9200", "11211", "1433", "1521", "5984", "9042"}


def _f(rel: str, line: int, cat: str, title: str, conf: str = "confirmed", **ev: Any) -> FindingDraft:
    return FindingDraft(title=f"{title} ({rel}:{line})", category=cat, module="iac", confidence=conf, native_evidence=True,
                        asset=rel, file=rel, line=line, evidence=ev, sources=["native:iac"])


def dockerfile(rel: str, text: str) -> list[FindingDraft]:
    out = []
    lines = text.splitlines()
    users = [i for i, l in enumerate(lines, 1) if re.match(r"^\s*USER\s+", l, re.I)]
    last_from = max((i for i, l in enumerate(lines, 1) if re.match(r"^\s*FROM\s", l, re.I)), default=1)
    if not users or any(re.match(r"^\s*USER\s+(root|0)(\s|:|$)", lines[i - 1], re.I) for i in users[-1:]) or users[-1] < last_from:
        out.append(_f(rel, last_from, "iac_container_root", "El contenedor se ejecuta como root (sin USER no privilegiado)"))
    for i, l in enumerate(lines, 1):
        m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", l, re.I)
        if m:
            img = m.group(1)
            if img.lower() != "scratch" and "@sha256:" not in img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
                out.append(_f(rel, i, "iac_image_unpinned", f"Imagen base sin versión fijada ({img})", imagen=img))
        if re.match(r"^\s*(ENV|ARG)\s+\S*", l, re.I) and SECRET_ENV.search(l) and "=" in l and not re.search(r"=\s*\$", l):
            out.append(_f(rel, i, "iac_secret", "Posible secreto en ENV/ARG del Dockerfile", linea=re.sub(r"=.*", "=****", l)))
        if re.match(r"^\s*ADD\s+https?://", l, re.I):
            out.append(_f(rel, i, "iac_insecure_config", "ADD descarga remota sin verificación de integridad"))
        if re.search(r"curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh", l):
            out.append(_f(rel, i, "iac_insecure_config", "Script remoto ejecutado con curl|sh"))
        if re.match(r"^\s*EXPOSE\s+.*\b22\b", l, re.I):
            out.append(_f(rel, i, "iac_insecure_config", "El contenedor expone SSH (22)"))
    return out


def compose(rel: str, data: dict[str, Any], text: str) -> list[FindingDraft]:
    out = []
    lines = text.splitlines()

    def line_of(needle: str) -> int:
        return next((i for i, l in enumerate(lines, 1) if needle in l), 1)

    for name, svc in (data.get("services") or {}).items():
        if not isinstance(svc, dict):
            continue
        ln = line_of(f"{name}:")
        if svc.get("privileged"):
            out.append(_f(rel, ln, "iac_privileged", f"Servicio «{name}» privilegiado"))
        for key in ("network_mode", "pid", "ipc"):
            if str(svc.get(key, "")).lower() == "host":
                out.append(_f(rel, ln, "iac_privileged", f"Servicio «{name}» con {key}: host"))
        for cap in svc.get("cap_add") or []:
            if str(cap).upper() in ("ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"):
                out.append(_f(rel, ln, "iac_privileged", f"Servicio «{name}» añade la capacidad {cap}"))
        for v in svc.get("volumes") or []:
            vs = v if isinstance(v, str) else str((v or {}).get("source", ""))
            if "docker.sock" in vs or re.match(r"^/(:|$)|^/etc|^/root|^/proc|^/sys", vs):
                out.append(_f(rel, ln, "iac_privileged", f"Servicio «{name}» monta una ruta sensible del host ({vs.split(':')[0]})"))
        for p in svc.get("ports") or []:
            ps = str(p if not isinstance(p, dict) else p.get("published", ""))
            parts = ps.split(":")
            if len(parts) >= 2 and parts[-1].split("/")[0] in DB_PORTS and (len(parts) == 2 or parts[0] in ("0.0.0.0", "")):  # nosec B104 vigia:ignore - comparación, no es un bind
                out.append(_f(rel, ln, "iac_insecure_config", f"Servicio «{name}» publica un puerto de base de datos en todas "
                                                              f"las interfaces ({ps})"))
        env = svc.get("environment") or {}
        items = env.items() if isinstance(env, dict) else [tuple(str(e).split("=", 1)) + ("",) for e in env]
        for item in items:
            k, v = str(item[0]), str(item[1]) if len(item) > 1 else ""
            if SECRET_ENV.search(k) and v and not v.startswith(("${", "/run/secrets/")) and not k.upper().endswith(
                    "_FILE") and v.lower() not in ("changeme", ""):
                out.append(_f(rel, line_of(k), "iac_secret", f"Secreto literal en el entorno de «{name}» ({k})"))
        img = str(svc.get("image", ""))
        if img and "@sha256:" not in img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
            out.append(_f(rel, ln, "iac_image_unpinned", f"Imagen sin versión fijada en «{name}» ({img})"))
        if str(svc.get("user", "")) in ("root", "0"):
            out.append(_f(rel, ln, "iac_container_root", f"Servicio «{name}» ejecutado como root"))
    return out


def kubernetes(rel: str, doc: dict[str, Any], text: str) -> list[FindingDraft]:
    out = []
    kind = doc.get("kind", "")
    spec = doc.get("spec") or {}
    pod = (spec.get("template") or {}).get("spec") or (spec.get("jobTemplate", {}).get("spec", {}).get("template", {})
                                                       .get("spec")) or (spec if kind == "Pod" else None)
    name = (doc.get("metadata") or {}).get("name", kind)
    ln = next((i for i, l in enumerate(text.splitlines(), 1) if f"name: {name}" in l), 1)
    if kind == "Service" and spec.get("type") in ("LoadBalancer", "NodePort"):
        ports = [str(p.get("port")) for p in spec.get("ports", []) if isinstance(p, dict)]
        if set(ports) & DB_PORTS:
            out.append(_f(rel, ln, "iac_insecure_config", f"Service «{name}» expone una base de datos ({spec['type']})"))
    if not isinstance(pod, dict):
        return out
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(flag):
            out.append(_f(rel, ln, "iac_privileged", f"«{name}» usa {flag}"))
    for vol in pod.get("volumes") or []:
        if isinstance(vol, dict) and "hostPath" in vol:
            out.append(_f(rel, ln, "iac_privileged", f"«{name}» monta hostPath {vol['hostPath'].get('path')}"))
    psc = pod.get("securityContext") or {}
    for c in (pod.get("containers") or []) + (pod.get("initContainers") or []):
        if not isinstance(c, dict):
            continue
        cn = c.get("name", "?")
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            out.append(_f(rel, ln, "iac_privileged", f"Contenedor «{cn}» privilegiado"))
        if sc.get("allowPrivilegeEscalation", True) is not False:
            out.append(_f(rel, ln, "iac_insecure_config", f"Contenedor «{cn}» sin allowPrivilegeEscalation: false"))
        if not (sc.get("runAsNonRoot") or psc.get("runAsNonRoot")) and sc.get("runAsUser", psc.get("runAsUser")) in (None, 0):
            out.append(_f(rel, ln, "iac_container_root", f"Contenedor «{cn}» puede ejecutarse como root"))
        caps = ((sc.get("capabilities") or {}).get("add")) or []
        if any(str(x).upper() in ("ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE") for x in caps):
            out.append(_f(rel, ln, "iac_privileged", f"Contenedor «{cn}» añade capacidades peligrosas {caps}"))
        if not (c.get("resources") or {}).get("limits"):
            out.append(_f(rel, ln, "iac_insecure_config", f"Contenedor «{cn}» sin límites de CPU/memoria", conf="likely"))
        img = str(c.get("image", ""))
        if img and "@sha256:" not in img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
            out.append(_f(rel, ln, "iac_image_unpinned", f"Imagen sin versión fijada en «{cn}» ({img})"))
        for e in c.get("env") or []:
            if isinstance(e, dict) and SECRET_ENV.search(str(e.get("name", ""))) and "value" in e and e["value"]:
                out.append(_f(rel, ln, "iac_secret", f"Secreto literal en el entorno de «{cn}» ({e['name']})"))
    return out


def terraform(rel: str, text: str) -> list[FindingDraft]:
    out = []
    for m in re.finditer(r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"", text):
        window = text[max(0, m.start() - 400): m.end() + 100]
        port = re.search(r"from_port\s*=\s*(\d+)", window)
        if port and port.group(1) in {"22", "3389"} | DB_PORTS:
            out.append(_f(rel, text.count("\n", 0, m.start()) + 1, "iac_insecure_config",
                          f"Grupo de seguridad abierto a Internet en el puerto {port.group(1)}"))
    for m in re.finditer(r"acl\s*=\s*\"public-read(-write)?\"", text):
        out.append(_f(rel, text.count("\n", 0, m.start()) + 1, "iac_insecure_config", "Bucket con ACL pública"))
    for m in re.finditer(r"(storage_encrypted|encrypted)\s*=\s*false", text):
        out.append(_f(rel, text.count("\n", 0, m.start()) + 1, "iac_insecure_config", "Almacenamiento sin cifrado"))
    return out


class IacModule(Module):
    name = "iac"
    title = "Infraestructura como código"
    phase = "recon"
    needs_source = True

    async def run(self, ctx: ScanContext) -> None:
        drafts = await asyncio.to_thread(scan_tree, ctx.source_dir)
        ctx.emit("info", self.name, f"{len(drafts)} problemas en ficheros de infraestructura")
        for d in drafts:
            ctx.add(d)


def scan_tree(root: Path) -> list[FindingDraft]:
    out: list[FindingDraft] = []
    for path, rel in iter_files(root):
        name = path.name.lower()
        text = None
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            text = read_text(path)
            if text:
                out.extend(dockerfile(rel, text))
        elif name.endswith(".tf"):
            text = read_text(path)
            if text:
                out.extend(terraform(rel, text))
        elif name.endswith((".yml", ".yaml")):
            text = read_text(path)
            if not text or len(text) > 2_000_000:
                continue
            try:
                docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
            except yaml.YAMLError:
                continue
            for d in docs:
                if "services" in d and isinstance(d["services"], dict) and ("compose" in name or "version" in d or
                                                                            any(isinstance(s, dict) and ("image" in s or "build" in s)
                                                                                for s in d["services"].values())):
                    out.extend(compose(rel, d, text))
                elif "apiVersion" in d and "kind" in d:
                    out.extend(kubernetes(rel, d, text))
    return out
