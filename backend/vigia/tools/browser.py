"""Ephemeral, scope-enforced headless browser (Playwright) for SPA crawling and execution-based DOM XSS.

Privacy and safety properties:
  * a brand-new ephemeral context per scan: no persistent profile, no personal cookies, no extensions, no
    stored sessions; the user-data dir lives inside the scan sandbox and is deleted afterwards;
  * every request the browser makes is checked by the same ScopeGuard as the HTTP client (host in scope,
    port allowed, exclusions, and the resolved IP validated): the browser cannot be used to reach
    out-of-scope hosts, internal ranges or cloud metadata, even via a redirect or a subresource;
  * with ``proxy`` (Vigía's scope gateway) every connection — redirect hops and WebSockets included, which
    ``route()`` does not see — goes through the gateway; Chromium may not resolve any name locally
    (host-resolver-rules), QUIC is off and WebRTC may not send UDP outside the proxy; optional kill switch;
  * downloads are refused and dialogs are auto-dismissed.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from vigia.config import get_settings
from vigia.security.scope import ScopeGuard, ScopeViolation


def browsers_path() -> Path:
    return get_settings().tools_dir / "playwright"


def availability() -> tuple[bool, str]:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False, "Playwright no está instalado (pip install playwright)"
    path = browsers_path()
    if not path.exists() or not any(path.glob("chromium-*")):
        return False, "El navegador Chromium no está descargado (vigia tools install browser)"
    return True, ""


# Runs in every page and frame before any page script (Playwright init script). Analysis never needs WebRTC, and
# WebRTC is the classic way a page learns the real IP (STUN over UDP, outside any proxy).
NO_WEBRTC = """(() => { for (const k of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel',
  'RTCSessionDescription', 'RTCIceCandidate', 'RTCRtpSender', 'RTCRtpReceiver', 'RTCRtpTransceiver']) {
  try { Object.defineProperty(window, k, {value: undefined, writable: false, configurable: false}); } catch (e) {} }
  try { if (navigator.mediaDevices) Object.defineProperty(navigator, 'mediaDevices', {value: undefined}); } catch (e) {}
})();"""


class BrowserEngine:
    """Async context manager yielding an isolated browser context bound to a scope."""

    def __init__(self, guard: ScopeGuard, workdir: Path, *, proxy: str | None = None, verify_tls: bool = False,
                 netwatch: bool = False, isolate: bool = False):
        self.guard = guard
        self.workdir = workdir
        self.proxy = proxy
        self.verify_tls = verify_tls
        self.netwatch = netwatch
        self.isolate = isolate  # Chromium inside the network-less AppContainer (preventive), CDP over pipes
        self.watch = None
        self._contained = None
        self.net_violations: list = []
        self.blocked: list[str] = []
        self._pw = None
        self._browser = None
        self.context = None

    async def __aenter__(self) -> "BrowserEngine":
        from playwright.async_api import async_playwright
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(browsers_path()))
        profile = self.workdir / "browser-profile"
        profile.mkdir(parents=True, exist_ok=True)
        self._pw = await async_playwright().start()
        launch: dict[str, Any] = {"headless": True, "chromium_sandbox": False,
                                  "args": ["--no-first-run", "--no-default-browser-check", "--disable-extensions",
                                           "--disable-sync", "--disable-background-networking", "--incognito"]}
        proxy_opt = None
        if self.proxy:
            from urllib.parse import unquote, urlsplit
            pu = urlsplit(self.proxy)
            proxy_opt = {"server": f"{pu.scheme}://{pu.hostname}:{pu.port}", "bypass": "<-loopback>"}
            if pu.username:  # the gateway's per-run credentials (answered by Playwright on the 407 challenge)
                proxy_opt.update(username=unquote(pu.username), password=unquote(pu.password or ""))
            launch["proxy"] = proxy_opt
            launch["args"] += ["--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1", "--disable-quic",
                               "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                               "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                               "--disable-features=MediaRouter,DialMediaRouteProvider,WebRtcHideLocalIpsWithMdns", "--no-pings",
                               "--disable-component-update", "--disable-domain-reliability"]
        if self.isolate:
            self._contained = ContainedChromium(self.workdir, launch["args"])
            ws_url = await self._contained.start()
            self._browser = await self._pw.chromium.connect_over_cdp(ws_url)
        else:
            self._browser = await self._pw.chromium.launch(**launch)
        if self.netwatch:
            from vigia.security.netwatch import NetWatchThread
            self.watch = NetWatchThread(_browser_pids, self._violation).start()
        self.context = await self._browser.new_context(
            ignore_https_errors=not self.verify_tls, accept_downloads=False, service_workers="block",
            user_agent=None, viewport={"width": 1280, "height": 900},
            **({"proxy": proxy_opt} if self.isolate and proxy_opt else {}))
        self.context.set_default_navigation_timeout(20000)
        self.context.set_default_timeout(15000)
        if self.proxy:  # WebRTC binds UDP sockets on every interface even with disable_non_proxied_udp: remove the API
            await self.context.add_init_script(NO_WEBRTC)
        await self.context.route("**/*", self._route)
        self.context.on("page", lambda p: p.on("dialog", lambda d: _safe(d.dismiss())))
        return self

    def _violation(self, found: list) -> None:
        self.net_violations.extend(found)
        for pid in _browser_pids():
            try:
                import psutil
                psutil.Process(pid).kill()
            except Exception:  # noqa: BLE001
                pass

    async def __aexit__(self, *exc: Any) -> None:
        if self.watch is not None:
            self.watch.stop()
        if self._contained is not None:
            try:
                await asyncio.wait_for(self.context.close(), 10) if self.context else None
            except Exception:  # noqa: BLE001
                pass
            await self._contained.stop()
            self.context = self._browser = None
        for closer in (getattr(self.context, "close", None), getattr(self._browser, "close", None),
                       getattr(self._pw, "stop", None)):
            try:
                if closer:
                    res = closer()
                    if res is not None:
                        await res
            except Exception:  # noqa: BLE001 - teardown must not raise
                pass

    async def _route(self, route, request=None) -> None:  # noqa: ANN001
        req = route.request
        url = req.url
        try:
            if not url.startswith(("http://", "https://")):
                raise ScopeViolation(f"esquema no permitido: {url[:40]}")
            await self.guard.check_url(url)  # host in scope + port + exclusions + resolved-IP validation
        except ScopeViolation:
            self.blocked.append(url)
            try:
                await route.abort()
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            await route.continue_()
        except Exception:  # noqa: BLE001 - page already closed, etc.
            pass

    async def render(self, url: str) -> dict[str, Any] | None:
        """Load a page with JavaScript and return the links, forms, scripts and endpoints it reveals."""
        from playwright.async_api import Error as PwError
        page = await self.context.new_page()
        xhr: list[dict[str, str]] = []
        page.on("request", lambda r: xhr.append({"method": r.method, "url": r.url})
                if r.resource_type in ("xhr", "fetch") else None)
        try:
            resp = await page.goto(url, wait_until="domcontentloaded")
            try:
                await page.wait_for_load_state("networkidle", timeout=6000)
            except PwError:
                pass
            data = await page.evaluate(
                """() => {
                    const abs = (u) => { try { return new URL(u, location.href).href } catch { return null } };
                    const links = [...document.querySelectorAll('a[href],area[href]')].map(a => abs(a.getAttribute('href')));
                    const scripts = [...document.querySelectorAll('script[src]')].map(s => abs(s.getAttribute('src')));
                    const forms = [...document.forms].map(f => ({
                        action: abs(f.getAttribute('action') || location.href),
                        method: (f.getAttribute('method') || 'GET').toUpperCase(),
                        fields: [...f.elements].filter(e => e.name).map(e => ({name: e.name, type: (e.type||'text')}))
                    }));
                    return {title: document.title, links, scripts, forms, url: location.href};
                }""")
            data["status"] = resp.status if resp else None
            data["xhr"] = xhr[:200]
            return data
        except PwError:
            return None
        finally:
            await page.close()

    async def dom_xss(self, url: str, param: str, payload_marker: str) -> dict[str, Any] | None:
        """Navigate with an execution payload; if the page actually runs it, it's a confirmed DOM/reflected XSS."""
        from playwright.async_api import Error as PwError
        from vigia.modules.common import with_param
        fired: list[str] = []
        page = await self.context.new_page()
        try:
            await page.expose_function("__vigiaXss", lambda m: fired.append(str(m)))
            await page.add_init_script(
                "window.alert=window.confirm=window.prompt=(m)=>window.__vigiaXss('dialog:'+m);")
            payload = f'"><img src=x onerror="window.__vigiaXss(\'{payload_marker}\')">'
            try:
                await page.goto(with_param(url, param, payload), wait_until="networkidle", timeout=12000)
            except PwError:
                pass
            await page.wait_for_timeout(600)
            if fired:
                return {"executed": True, "marker": fired[0], "param": param,
                        "evidence": f"El navegador ejecutó el payload inyectado en «{param}» (marcador {fired[0]})"}
            return None
        except PwError:
            return None
        finally:
            await page.close()


def headless_shell() -> Path | None:
    return next(iter(sorted(browsers_path().glob("chromium_headless_shell-*/chrome-headless-shell-*/"
                                                 "chrome-headless-shell.exe"))), None)


class ContainedChromium:
    """Chromium started by Vigía *inside* the AppContainer (no network but loopback, enforced by the kernel), driven
    over --remote-debugging-pipe (inherited handles, no socket). A loopback WebSocket bridge — random path token, a
    single client — lets Playwright attach with connect_over_cdp. The whole browser tree lives in a Job Object."""

    def __init__(self, workdir: Path, args: list[str]):
        self.workdir = workdir
        self.args = args
        self.proc = None
        self.job = None
        self._server = None
        self._wfd = self._rfd = None
        self._clients = 0
        self.token = ""

    async def start(self) -> str:
        import msvcrt
        import secrets

        from vigia.core.toolrunner import _Job
        from vigia.security import appcontainer as ac
        exe = headless_shell()
        if exe is None:
            raise RuntimeError("No se encuentra chrome-headless-shell (vigia tools install browser)")
        prof = self.workdir / "browser-profile"
        prof.mkdir(parents=True, exist_ok=True)
        ac.prepare([str(exe)], read=[browsers_path()], write=[self.workdir])
        r3, w3 = os.pipe()  # Vigía writes w3 → Chromium reads fd 3
        r4, w4 = os.pipe()  # Chromium writes fd 4 → Vigía reads r4
        home = self.workdir / "home"
        home.mkdir(exist_ok=True)
        env = {"SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"), "LOCALAPPDATA": str(home),
               "TEMP": str(home), "TMP": str(home), "USERPROFILE": str(home)}
        argv = [str(exe), "--headless", "--no-sandbox", "--remote-debugging-pipe", f"--user-data-dir={prof}",
                "--disable-field-trial-config", "--disable-background-timer-throttling", "--disable-default-apps",
                "--mute-audio", "--hide-scrollbars", "--disable-breakpad", *self.args, "about:blank"]
        err = open(self.workdir / "chromium.log", "wb")  # noqa: SIM115 - inherited by the child, closed below
        self.job = _Job(2048)
        try:
            self.proc = ac.spawn(argv, env=env, cwd=str(self.workdir), stdout_fd=err.fileno(), stderr_fd=err.fileno(),
                                 suspended=True, extra_handles=[msvcrt.get_osfhandle(r3), msvcrt.get_osfhandle(w4)])
            self.job.assign_and_resume(self.proc)
        finally:
            os.close(r3)
            os.close(w4)
            err.close()
        self._wfd, self._rfd = w3, r4
        return await self._serve()

    async def _serve(self) -> str:
        import secrets
        import threading

        from websockets.asyncio.server import serve
        loop = asyncio.get_running_loop()
        inbox: asyncio.Queue = asyncio.Queue()
        self.token = secrets.token_urlsafe(18)

        def reader() -> None:
            buf = b""
            while True:
                try:
                    data = os.read(self._rfd, 1 << 20)
                except OSError:
                    data = b""
                if not data:
                    loop.call_soon_threadsafe(inbox.put_nowait, None)
                    return
                buf += data
                while b"\0" in buf:
                    msg, _, buf = buf.partition(b"\0")
                    loop.call_soon_threadsafe(inbox.put_nowait, msg.decode("utf-8", "replace"))
        threading.Thread(target=reader, name="vigia-cdp-pipe", daemon=True).start()

        def write_all(data: bytes) -> None:
            view = memoryview(data)
            while view:
                n = os.write(self._wfd, view)
                view = view[n:]

        async def handler(ws) -> None:  # noqa: ANN001
            if ws.request.path != f"/{self.token}" or self._clients:
                await ws.close(1008, "forbidden")
                return
            self._clients += 1

            async def down() -> None:
                while True:
                    msg = await inbox.get()
                    if msg is None:
                        await ws.close()
                        return
                    await ws.send(msg)
            t = asyncio.ensure_future(down())
            try:
                async for msg in ws:
                    data = (msg if isinstance(msg, str) else msg.decode()).encode() + b"\0"
                    await loop.run_in_executor(None, write_all, data)
            except Exception:  # noqa: BLE001 - client went away / browser closed: end of session
                pass
            finally:
                t.cancel()
        self._server = await serve(handler, "127.0.0.1", 0, max_size=None, compression=None, ping_interval=None)
        port = list(self._server.sockets)[0].getsockname()[1]
        return f"ws://127.0.0.1:{port}/{self.token}"

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        for fd in (self._wfd, self._rfd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._wfd = self._rfd = None
        if self.job is not None:
            self.job.terminate()
            self.job.close()
        if self.proc is not None:
            self.proc.close()
        self.token = ""


def _browser_pids() -> list[int]:
    """Chromium processes started by this Vigía process (identified by their executable under tools/playwright)."""
    import psutil
    root = str(browsers_path().resolve()).lower()
    out = []
    try:
        for p in psutil.Process().children(recursive=True):
            try:
                if (p.exe() or "").lower().startswith(root):
                    out.append(p.pid)
            except psutil.Error:
                continue
    except psutil.Error:
        pass
    return out


def _safe(coro) -> None:  # noqa: ANN001 - fire-and-forget dialog dismissal
    try:
        import asyncio
        asyncio.ensure_future(coro)
    except Exception:  # noqa: BLE001
        pass


_ = urlsplit
