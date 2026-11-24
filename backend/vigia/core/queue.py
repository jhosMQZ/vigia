"""Persistent scan queue on the database (atomic claim + lease).

A worker claims the oldest queued scan with a single conditional UPDATE; the lease is renewed while the
scan runs. Scans whose lease expired (worker crashed) are marked failed rather than silently re-run, so a
target is never re-tested without a human decision.
"""
from __future__ import annotations

import os
import socket
import uuid
from datetime import timedelta

from sqlalchemy import select, update

from vigia.config import get_settings
from vigia.db import Scan, SessionLocal, utcnow


def worker_identity() -> str:
    return f"{socket.gethostname()[:24]}:{os.getpid()}:{uuid.uuid4().hex[:6]}"


def claim_next(worker_id: str) -> int | None:
    s = get_settings()
    now = utcnow()
    with SessionLocal() as db:
        candidates = db.scalars(select(Scan.id).where(Scan.status == "queued").order_by(Scan.created_at, Scan.id)
                                .limit(5)).all()
        for sid in candidates:
            res = db.execute(update(Scan).where(Scan.id == sid, Scan.status == "queued")
                             .values(status="running", worker_id=worker_id, started_at=now,
                                     lease_until=now + timedelta(seconds=s.worker_lease_seconds)))
            db.commit()
            if res.rowcount == 1:
                return sid
    return None


def renew_lease(scan_id: int, worker_id: str) -> bool:
    s = get_settings()
    with SessionLocal() as db:
        res = db.execute(update(Scan).where(Scan.id == scan_id, Scan.worker_id == worker_id, Scan.status == "running")
                         .values(lease_until=utcnow() + timedelta(seconds=s.worker_lease_seconds)))
        db.commit()
        return res.rowcount == 1


def reap_expired() -> list[int]:
    """Mark scans whose worker vanished as failed."""
    now = utcnow()
    with SessionLocal() as db:
        ids = db.scalars(select(Scan.id).where(Scan.status == "running", Scan.lease_until < now)).all()
        for sid in ids:
            db.execute(update(Scan).where(Scan.id == sid, Scan.status == "running", Scan.lease_until < now)
                       .values(status="failed", finished_at=now,
                               error="El worker dejó de responder (lease caducado). No se reintenta automáticamente."))
        db.commit()
        return list(ids)


def finish(scan_id: int, worker_id: str, status: str, *, summary: dict | None = None, error: str | None = None) -> None:
    with SessionLocal() as db:
        values = {"status": status, "finished_at": utcnow(), "lease_until": None}
        if summary is not None:
            values["summary"] = summary
        if error is not None:
            values["error"] = error[:4000]
        db.execute(update(Scan).where(Scan.id == scan_id, Scan.worker_id == worker_id).values(**values))
        db.commit()
