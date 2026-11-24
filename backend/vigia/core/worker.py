"""Worker loop: claims scans from the persistent queue and runs them (standalone or embedded in the API)."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor

from vigia.config import get_settings
from vigia.core import queue
from vigia.core.orchestrator import run_scan
from vigia.db import init_db

log = logging.getLogger("vigia.worker")


class Worker:
    def __init__(self, parallel: int | None = None):
        s = get_settings()
        self.parallel = max(1, parallel or s.worker_max_parallel_scans)
        self.stop_event = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=self.parallel, thread_name_prefix="vigia-scan")
        self.running: dict[int, Future] = {}
        self.worker_id = queue.worker_identity()

    def loop(self) -> None:
        s = get_settings()
        init_db()
        last_reap = 0.0
        log.info("worker %s iniciado (paralelo=%d)", self.worker_id, self.parallel)
        while not self.stop_event.is_set():
            if time.monotonic() - last_reap > 30:
                for sid in queue.reap_expired():
                    log.warning("scan %s marcado como fallido: lease caducado", sid)
                last_reap = time.monotonic()
            self.running = {k: f for k, f in self.running.items() if not f.done()}
            if len(self.running) < self.parallel:
                sid = queue.claim_next(self.worker_id)
                if sid is not None:
                    log.info("scan %s reclamado", sid)
                    self.running[sid] = self.pool.submit(self._safe_run, sid)
                    continue
            self.stop_event.wait(s.worker_poll_seconds)
        self.pool.shutdown(wait=False, cancel_futures=True)

    def _safe_run(self, sid: int) -> None:
        try:
            run_scan(sid, self.worker_id)
        except Exception:  # noqa: BLE001
            log.exception("scan %s terminó con una excepción no controlada", sid)
            queue.finish(sid, self.worker_id, "failed", error="Excepción no controlada en el worker (ver logs)")

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.loop, name="vigia-worker", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self.stop_event.set()
