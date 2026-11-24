"""Vigía launcher for Windows (used by INICIAR_VIGIA.bat and DETENER_VIGIA.bat).

    python -m vigia.launcher prepare            Python dependencies (hashed lock) and the built interface
    python -m vigia.launcher start [--no-browser] [--port N]
    python -m vigia.launcher stop               stops only the instance this launcher started
    python -m vigia.launcher status

Guarantees:
- the server always listens on 127.0.0.1 only, whatever VIGIA_BIND_HOST says;
- one instance per data folder (exclusive lock); an occupied port is explained, never taken over;
- privacy settings, isolation and the egress are not touched; no analysis is started;
- no secret is printed or stored; the stop path only ends the processes of the recorded instance (checked by PID,
  creation time and command line), never other programs.

Only the standard library is imported at module level: ``prepare`` runs before the dependencies exist.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
LOCK_FILE = BACKEND / "requirements-windows.lock"
HOST = "127.0.0.1"
MIN_PY = (3, 11)

# exit codes understood by INICIAR_VIGIA.bat
OK, ALREADY_RUNNING, FAILED = 0, 10, 1


def say(msg: str = "") -> None:
    print(msg, flush=True)


def fail(msg: str, detail: str | None = None) -> int:
    say(f"\n[ERROR] {msg}")
    if detail:
        say(f"        {detail}")
    return FAILED


# ---------------------------------------------------------------------------------------------- prepare
def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_requirements(path: Path = LOCK_FILE) -> dict[str, str]:
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", line)
        if m:
            pins[_norm(m.group(1))] = m.group(2)
    return pins


def installed_versions() -> dict[str, str]:
    from importlib import metadata
    return {_norm(d.metadata["Name"]): d.version for d in metadata.distributions() if d.metadata["Name"]}


def missing_requirements(pins: dict[str, str], installed: dict[str, str]) -> list[str]:
    return sorted(f"{n}=={v}" for n, v in pins.items() if installed.get(n) != v)


def _run(cmd: list[str], cwd: Path | None = None) -> int:
    try:
        return subprocess.call(cmd, cwd=cwd)
    except OSError as e:
        say(f"        {e}")
        return 1


def _installer() -> list[str] | None:
    """uv when available (fast, honours the hashes); otherwise pip from the virtual environment."""
    uv = shutil.which("uv")
    if uv:
        return [uv, "pip", "install", "--python", sys.executable]
    if subprocess.call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) != 0:
        say("Preparando pip en el entorno virtual…")
        if subprocess.call([sys.executable, "-m", "ensurepip", "--upgrade", "--default-pip"]) != 0:
            return None
    return [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input"]


def prepare_python() -> int:
    if sys.version_info < MIN_PY:
        return fail(f"Vigía necesita Python {MIN_PY[0]}.{MIN_PY[1]} o superior; este entorno usa "
                    f"{sys.version_info.major}.{sys.version_info.minor}.",
                    "Elimina o renombra la carpeta .venv e instala un Python más reciente.")
    if not LOCK_FILE.exists():
        return fail("Falta el archivo de dependencias backend/requirements-windows.lock.")
    pins = locked_requirements()
    todo = missing_requirements(pins, installed_versions())
    has_vigia = "vigia" in installed_versions()
    if not todo and has_vigia:
        say(f"Dependencias de Python: correctas ({len(pins)} paquetes con versión fijada).")
        return OK
    inst = _installer()
    if inst is None:
        return fail("No se pudo preparar pip en el entorno virtual.")
    if todo:
        say(f"Instalando {len(todo)} dependencias con las versiones y hashes del proyecto (requiere Internet)…")
        if _run(inst + ["--require-hashes", "-r", str(LOCK_FILE)]) != 0:
            return fail("No se pudieron instalar las dependencias de Python.",
                        "Comprueba la conexión a Internet (se descargan de PyPI) y vuelve a ejecutar el archivo.")
    if _run(inst + ["--no-deps", "-e", str(BACKEND)]) != 0:
        return fail("No se pudo registrar Vigía en el entorno virtual.")
    still = missing_requirements(pins, installed_versions())
    if still:
        return fail("Algunas dependencias siguen sin la versión esperada: " + ", ".join(still[:6]))
    say("Dependencias de Python: instaladas y verificadas.")
    return OK


def _newest_mtime(*paths: Path) -> float:
    newest = 0.0
    for p in paths:
        if p.is_file():
            newest = max(newest, p.stat().st_mtime)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file():
                    newest = max(newest, f.stat().st_mtime)
    return newest


def prepare_frontend() -> int:
    index = FRONTEND / "dist" / "index.html"
    sources = [FRONTEND / "src", FRONTEND / "public", FRONTEND / "index.html", FRONTEND / "package-lock.json"]
    stale = index.exists() and _newest_mtime(*sources) > index.stat().st_mtime
    if index.exists() and not stale:
        say("Interfaz web: compilada.")
        return OK
    npm = shutil.which("npm")
    if not npm:
        if index.exists():
            say("Interfaz web: hay cambios sin compilar y no se encontró Node.js; se usa la versión compilada.")
            return OK
        return fail("Falta la interfaz compilada y no se encontró Node.js para compilarla.",
                    "Instala Node.js LTS desde https://nodejs.org y vuelve a ejecutar este archivo.")
    say("Compilando la interfaz web (la primera vez descarga sus dependencias; requiere Internet)…")
    stamp = FRONTEND / "node_modules" / ".package-lock.json"
    lock = FRONTEND / "package-lock.json"
    if not stamp.exists() or lock.stat().st_mtime > stamp.stat().st_mtime:
        if _run([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=FRONTEND) != 0:
            return fail("No se pudieron instalar las dependencias de la interfaz (npm ci).",
                        "Comprueba la conexión a Internet y vuelve a intentarlo.")
    if _run([npm, "run", "build"], cwd=FRONTEND) != 0 or not index.exists():
        return fail("No se pudo compilar la interfaz web (npm run build).")
    say("Interfaz web: compilada.")
    return OK


def cmd_prepare(_: argparse.Namespace) -> int:
    say("Comprobando lo necesario para Vigía…")
    rc = prepare_python()
    if rc != OK:
        return rc
    return prepare_frontend()


# ---------------------------------------------------------------------------------------------- shared state
def _settings():  # noqa: ANN202
    from vigia.config import get_settings
    return get_settings()


def config_error(e: BaseException) -> str:
    """Which VIGIA_* value is wrong and why, in one line (no traceback)."""
    errs = getattr(e, "errors", None)
    if callable(errs):
        try:
            parts = [f"VIGIA_{str(x['loc'][0]).upper()}: {x['msg']}" for x in errs()[:3] if x.get("loc")]
            if parts:
                return "; ".join(parts)
        except Exception:  # noqa: BLE001
            pass
    return str(e).splitlines()[0][:300]


def state_paths(data_dir: Path) -> dict[str, Path]:
    run = data_dir / "run"
    run.mkdir(parents=True, exist_ok=True)
    return {"lock": run / "launcher.lock", "state": run / "launcher.json", "stop": run / "launcher.stop"}


def read_state(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class InstanceLock:
    """Exclusive lock held for the whole life of the launcher: a second launcher on the same data folder cannot start."""

    def __init__(self, path: Path):
        self.path = path
        self.fh = None

    def acquire(self) -> bool:
        self.fh = open(self.path, "a+b")  # noqa: SIM115 - held open on purpose
        try:
            if sys.platform == "win32":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.fh.close()
            self.fh = None
            return False

    def release(self) -> None:
        if self.fh is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            self.fh.close()
            self.fh = None


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex((HOST, port)) == 0:
            return True
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if sys.platform == "win32":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            s.bind((HOST, port))
        except OSError:
            return True
    return False


def _http_get(url: str, timeout: float = 2.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"Accept": "application/json, text/html"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - loopback only
            return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (OSError, ValueError):
        return 0, ""


def is_vigia(port: int) -> bool:
    code, body = _http_get(f"http://{HOST}:{port}/api/health")
    if code != 200:
        return False
    try:
        return json.loads(body).get("status") == "ok"
    except ValueError:
        return False


def port_owner(port: int) -> str:
    try:
        import psutil
        for c in psutil.net_connections(kind="tcp"):
            if c.laddr and c.laddr.port == port and c.status == psutil.CONN_LISTEN and c.pid:
                try:
                    return f"{psutil.Process(c.pid).name()} (PID {c.pid})"
                except psutil.Error:
                    return f"PID {c.pid}"
    except Exception:  # noqa: BLE001 - best effort, explanation only
        pass
    return "otro programa"


def wait_healthy(port: int, proc: subprocess.Popen, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            return False
        if is_vigia(port):
            return True
        time.sleep(0.5)
    return False


def is_our_server(st: dict) -> bool:
    """The recorded server is still the same process: same PID, same creation time, `vigia.cli serve` command."""
    try:
        import psutil
        p = psutil.Process(int(st["server_pid"]))
        if abs(p.create_time() - float(st["server_created"])) > 1.0:
            return False
        cmd = " ".join(p.cmdline())
        return "vigia.cli" in cmd and " serve" in cmd
    except Exception:  # noqa: BLE001 - gone, reused PID or no access: not ours
        return False


def end_process_tree(pid: int, grace: float = 10.0) -> None:
    import psutil
    try:
        root = psutil.Process(pid)
    except psutil.Error:
        return
    procs = root.children(recursive=True) + [root]
    for p in procs:
        try:
            p.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(procs, timeout=grace)
    for p in alive:
        try:
            p.kill()
        except psutil.Error:
            pass


# ---------------------------------------------------------------------------------------------- start
def _first_line(e: BaseException) -> str:
    text = str(e).strip().splitlines()
    return f"{type(e).__name__}: {text[0][:240] if text else ''}"


def ensure_admin(interactive: bool) -> int:
    from vigia.db import SessionLocal, User, init_db
    try:
        init_db()  # creates or upgrades the database, exactly as the server does at start-up
        with SessionLocal() as db:
            if db.query(User).count():
                return OK
    except Exception as e:  # noqa: BLE001 - explained to the person, not a traceback
        return fail("No se pudo abrir o preparar la base de datos de Vigía.",
                    f"Comprueba que la carpeta de datos existe y se puede escribir (VIGIA_DATA_DIR / VIGIA_DATABASE_URL). "
                    f"Detalle: {_first_line(e)}")
    from vigia.cli import cmd_init_admin
    say("\nNo hay ninguna cuenta todavía. Crea la cuenta de administración (la contraseña no se muestra).")
    if os.environ.get("VIGIA_ADMIN_PASSWORD"):
        return OK if cmd_init_admin(argparse.Namespace(username="admin", reset=False)) == 0 else FAILED
    if not interactive:
        return fail("No hay ninguna cuenta y la consola no es interactiva.",
                    "Ejecuta INICIAR_VIGIA.bat con doble clic, o crea la cuenta con: vigia init-admin --username admin")
    from vigia.security.auth import password_problems
    user = (input("Nombre de usuario [admin]: ").strip() or "admin").lower()
    for _ in range(3):
        pw = getpass.getpass("Contraseña (mínimo 12 caracteres, tres tipos distintos): ")
        problems = password_problems(pw, user)
        if problems:
            say("  No es válida: " + "; ".join(problems))
            continue
        if getpass.getpass("Repite la contraseña: ") != pw:
            say("  No coinciden. Prueba otra vez.")
            continue
        os.environ["VIGIA_ADMIN_PASSWORD"] = pw  # read by init-admin in this process only, removed right after
        try:
            rc = cmd_init_admin(argparse.Namespace(username=user, reset=False))
        finally:
            os.environ.pop("VIGIA_ADMIN_PASSWORD", None)
        return OK if rc == 0 else FAILED
    return fail("No se creó la cuenta de administración.")


def describe_components(s) -> None:  # noqa: ANN001
    say("\nEstado de los componentes:")
    say(f"  Interfaz web ............. {'lista' if (FRONTEND / 'dist' / 'index.html').exists() else 'falta compilarla'}")
    if s.ssh_tunnel:
        egress = "túnel SSH gestionado (se abre en cada análisis)"
        if not shutil.which("ssh"):
            egress += " — AVISO: no se encontró el cliente OpenSSH"
    elif s.http_proxy:
        egress = "proxy de salida configurado"
    else:
        egress = "sin salida protegida: los sitios analizados verían tu dirección IP"
    say(f"  Salida de los análisis ... {egress}")
    if s.require_proxy:
        say("                             (se exige salida protegida: sin ella no se analizan sitios públicos)")
    say(f"  Aislamiento .............. {s.egress_isolation}")
    try:
        from vigia.tools.browser import availability
        ok, why = availability()
        say(f"  Navegador aislado ........ {'disponible' if ok else 'no disponible (' + why + ')'}")
    except Exception:  # noqa: BLE001
        say("  Navegador aislado ........ no disponible")
    try:
        from vigia.tools.registry import get_registry
        engines = get_registry().all()
        avail = sum(1 for e in engines if e.status == "available")
        say(f"  Motores externos ......... {avail} de {len(engines)} disponibles (opcionales; se instalan con: "
            "vigia tools install)")
    except Exception:  # noqa: BLE001 - informative only
        pass


def cmd_start(a: argparse.Namespace) -> int:
    if sys.platform != "win32":
        return fail("Este lanzador está pensado para Windows. En otros sistemas usa: vigia serve")
    try:
        s = _settings()
    except Exception as e:  # noqa: BLE001 - invalid VIGIA_* value
        return fail("La configuración de Vigía no es válida.", config_error(e))
    port = a.port or s.bind_port
    url = f"http://{HOST}:{port}/"
    paths = state_paths(s.data_dir)
    lock = InstanceLock(paths["lock"])
    if not lock.acquire():
        st = read_state(paths["state"]) or {}
        running = st.get("url", url)
        say(f"\nVigía ya está en marcha en {running} (abierto desde otra ventana).")
        say("No se inicia una segunda instancia.")
        if not a.no_browser:
            open_browser(running)
        return ALREADY_RUNNING
    try:
        if port_in_use(port):
            if is_vigia(port):
                say(f"\nYa hay un servidor de Vigía escuchando en {url}, iniciado fuera de este lanzador.")
                say("No se inicia otro. Ciérralo desde su propia ventana si quieres usar este lanzador.")
                if not a.no_browser:
                    open_browser(url)
                return ALREADY_RUNNING
            return fail(f"El puerto {port} está ocupado por {port_owner(port)}.",
                        "Cierra ese programa o elige otro puerto con la variable VIGIA_BIND_PORT.")
        if s.bind_host not in (HOST, "localhost"):
            say(f"Aviso: VIGIA_BIND_HOST={s.bind_host} se ignora; el lanzador solo escucha en {HOST}.")
        rc = ensure_admin(sys.stdin is not None and sys.stdin.isatty())
        if rc != OK:
            return rc
        describe_components(s)
        return run_server(s, port, url, paths, a.no_browser)
    except KeyboardInterrupt:
        say("\nInicio cancelado.")
        return FAILED
    except Exception as e:  # noqa: BLE001 - an unexpected problem is explained, never shown as a traceback
        return fail("No se pudo iniciar Vigía por un error inesperado.", f"Detalle: {_first_line(e)}")
    finally:
        lock.release()


def open_browser(url: str) -> None:
    if os.environ.get("VIGIA_NO_BROWSER"):
        return
    import webbrowser
    say(f"Abriendo {url} en el navegador…")
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        say(f"No se pudo abrir el navegador. Abre manualmente {url}")


def run_server(s, port: int, url: str, paths: dict[str, Path], no_browser: bool) -> int:  # noqa: ANN001
    env = {k: v for k, v in os.environ.items() if k != "VIGIA_ADMIN_PASSWORD"}
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    say(f"\nIniciando Vigía (solo accesible desde este equipo: {url})…\n")
    proc = subprocess.Popen([sys.executable, "-m", "vigia.cli", "serve", "--host", HOST, "--port", str(port)],
                            cwd=BACKEND, env=env, creationflags=flags)
    token = secrets.token_hex(16)
    try:
        import psutil
        created = psutil.Process(proc.pid).create_time()
    except Exception:  # noqa: BLE001
        created = time.time()
    me = os.getpid()
    try:
        import psutil
        me_created = psutil.Process(me).create_time()
    except Exception:  # noqa: BLE001
        me_created = 0.0
    paths["stop"].unlink(missing_ok=True)
    paths["state"].write_text(json.dumps({
        "launcher_pid": me, "launcher_created": me_created, "server_pid": proc.pid, "server_created": created,
        "port": port, "url": url, "token": token, "started": time.strftime("%Y-%m-%d %H:%M:%S")}), encoding="utf-8")
    try:
        if not wait_healthy(port, proc, timeout=120):
            code = proc.poll()
            if code is None:
                stop_server(proc)
                return fail("Vigía no respondió a tiempo a la comprobación de salud.",
                            "Revisa los mensajes anteriores de esta ventana.")
            return fail(f"El servidor se detuvo durante el arranque (código {code}).",
                        "Revisa los mensajes anteriores de esta ventana; suelen indicar la causa.")
        say(f"\nVigía está listo en {url}")
        if not no_browser:
            open_browser(url)
        say("Para detenerlo: pulsa Ctrl+C en esta ventana o ejecuta DETENER_VIGIA.bat.\n")
        while proc.poll() is None:
            if paths["stop"].exists():
                req = paths["stop"].read_text(encoding="utf-8", errors="replace").strip()
                paths["stop"].unlink(missing_ok=True)
                if req == token:
                    say("\nDetención solicitada desde DETENER_VIGIA.bat…")
                    stop_server(proc)
                    break
            time.sleep(0.5)
    except KeyboardInterrupt:
        say("\nDeteniendo Vigía…")
        stop_server(proc)
    finally:
        if proc.poll() is None:
            stop_server(proc)
        paths["state"].unlink(missing_ok=True)
        paths["stop"].unlink(missing_ok=True)
    say("Vigía se ha detenido.")
    return OK


def stop_server(proc: subprocess.Popen, grace: float = 25.0) -> None:
    """Orderly stop (Ctrl+Break to the server's own process group, which uvicorn handles), then the process tree."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=grace)
    except (OSError, subprocess.TimeoutExpired):
        pass
    except KeyboardInterrupt:
        pass
    if proc.poll() is None:
        end_process_tree(proc.pid)


# ---------------------------------------------------------------------------------------------- stop / status
def cmd_stop(_: argparse.Namespace) -> int:
    try:
        s = _settings()
    except Exception as e:  # noqa: BLE001
        return fail("La configuración de Vigía no es válida.", config_error(e))
    paths = state_paths(s.data_dir)
    st = read_state(paths["state"])
    if not st:
        if port_in_use(s.bind_port) and is_vigia(s.bind_port):
            say("Hay un servidor de Vigía en marcha que no se inició con INICIAR_VIGIA.bat; ciérralo desde su ventana.")
        else:
            say("Vigía no está en marcha.")
        return OK
    if not is_our_server(st):
        paths["state"].unlink(missing_ok=True)
        say("Vigía no está en marcha (se limpió un registro antiguo).")
        return OK
    import psutil
    say("Deteniendo Vigía de forma ordenada…")
    paths["stop"].write_text(st["token"], encoding="utf-8")
    launcher = None
    try:
        lp = psutil.Process(int(st["launcher_pid"]))
        if abs(lp.create_time() - float(st.get("launcher_created", 0))) <= 1.0:
            launcher = lp
    except (psutil.Error, ValueError, KeyError):
        launcher = None
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline and is_our_server(st):
        time.sleep(0.5)
    if is_our_server(st):  # the launcher did not answer: end only the recorded server and its children
        say("El lanzador no respondió; se termina el proceso del servidor de Vigía y sus subprocesos.")
        end_process_tree(int(st["server_pid"]))
    if launcher is not None:
        try:
            launcher.wait(timeout=10)
        except psutil.Error:
            pass
    paths["state"].unlink(missing_ok=True)
    paths["stop"].unlink(missing_ok=True)
    say("Vigía se ha detenido.")
    return OK


def cmd_status(_: argparse.Namespace) -> int:
    s = _settings()
    st = read_state(state_paths(s.data_dir)["state"])
    if st and is_our_server(st) and is_vigia(int(st["port"])):
        say(f"Vigía está en marcha en {st['url']} (desde {st['started']}).")
        return OK
    say("Vigía no está en marcha.")
    return 3


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="python -m vigia.launcher", description="Lanzador de Vigía para Windows")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prepare").set_defaults(fn=cmd_prepare)
    sp = sub.add_parser("start")
    sp.add_argument("--no-browser", action="store_true")
    sp.add_argument("--port", type=int)
    sp.set_defaults(fn=cmd_start)
    sub.add_parser("stop").set_defaults(fn=cmd_stop)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
