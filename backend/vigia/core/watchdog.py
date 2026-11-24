"""Out-of-loop watchdog for a running scan.

Runs in its own thread so it keeps working even if the scan's event loop is blocked:
  * a heartbeat task in the loop updates ``beat``; if it goes stale for ``stall_seconds`` the watchdog
    dumps every thread's stack to the workspace (evidence for diagnosis) and records an error event;
  * it enforces the scan deadline and user cancellation from outside the loop (cancels the loop's
    stop event thread-safely and signals external tools to die).
"""
from __future__ import annotations

import asyncio
import faulthandler
import threading
import time
from datetime import datetime

from vigia.db import Scan, ScanEvent, SessionLocal, utcnow


class Watchdog:
    def __init__(self, ctx, loop: asyncio.AbstractEventLoop, stall_seconds: float = 90.0, grace_seconds: float = 120.0):  # noqa: ANN001
        self.ctx, self.loop = ctx, loop
        self.stall_seconds, self.grace_seconds = stall_seconds, grace_seconds
        self.beat = time.monotonic()
        self.stop = threading.Event()
        self.stalls = 0
        self.thread = threading.Thread(target=self._run, name=f"vigia-watchdog-{ctx.scan_id}", daemon=True)

    async def heartbeat(self) -> None:
        while not self.stop.is_set():
            self.beat = time.monotonic()
            await asyncio.sleep(1.0)

    def start(self) -> None:
        self.thread.start()

    def _event(self, level: str, message: str) -> None:
        try:
            with SessionLocal() as db:
                db.add(ScanEvent(scan_id=self.ctx.scan_id, ts=utcnow(), level=level, module="watchdog", message=message))
                db.commit()
        except Exception:  # noqa: BLE001 - the watchdog must never die
            pass

    def _signal_stop(self, reason: str) -> None:
        if self.ctx.stop_reason is None:
            self.ctx.stop_reason = reason
        self.ctx.thread_cancel.set()  # external engines are killed by their ToolRunner
        try:
            self.loop.call_soon_threadsafe(self.ctx.cancel_event.set)
        except RuntimeError:
            pass

    def _run(self) -> None:
        last_cancel_poll = 0.0
        while not self.stop.wait(5.0):
            now = time.monotonic()
            stale = now - self.beat
            if stale > self.stall_seconds:
                self.stalls += 1
                path = self.ctx.workspace / f"stall-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
                try:
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(f"Bucle de eventos sin responder durante {stale:.0f} s\n")
                        faulthandler.dump_traceback(file=fh, all_threads=True)
                except OSError:
                    pass
                self._event("error", f"El bucle de eventos del escaneo no responde desde hace {stale:.0f} s; "
                                     f"pila de hilos guardada en {path.name}")
                self.beat = now  # report each stall once per window
            if now > self.ctx.deadline + self.grace_seconds:
                self._signal_stop(f"duración máxima alcanzada ({self.ctx.cfg.max_duration_min} min; parada forzada)")
            if now - last_cancel_poll > 5:
                last_cancel_poll = now
                try:
                    with SessionLocal() as db:
                        s = db.get(Scan, self.ctx.scan_id)
                        if s is not None and s.cancel_requested:
                            self._signal_stop("cancelado por el usuario")
                except Exception:  # noqa: BLE001
                    pass

    def close(self) -> None:
        self.stop.set()
