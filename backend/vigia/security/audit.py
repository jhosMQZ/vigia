"""Tamper-evident audit log: each entry stores HMAC-SHA256(key, prev_hash || canonical(entry)).

Someone with write access to the database but without the audit key cannot rewrite history without
``verify_chain`` detecting it. Appends are serialised (SQLite: BEGIN IMMEDIATE; PostgreSQL: advisory lock)
so concurrent writers (API + workers) never fork the chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from datetime import datetime
from typing import Any

from sqlalchemy import select, text

from vigia.db import AuditLog, get_engine, utcnow
from vigia.security.crypto import audit_key
from vigia.security.redact import redact_obj

GENESIS = "0" * 64
_lock = threading.Lock()


def _canonical(ts: datetime, user_id: int | None, username: str, action: str, target: str, details: dict,
               ip: str, severity: str) -> bytes:
    return json.dumps({"ts": ts.isoformat(timespec="microseconds"), "uid": user_id, "usr": username, "act": action,
                       "tgt": target, "det": details, "ip": ip, "sev": severity},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _mac(prev: str, payload: bytes) -> str:
    return hmac.new(audit_key(), prev.encode() + b"|" + payload, hashlib.sha256).hexdigest()


def record(action: str, *, user_id: int | None = None, username: str = "system", target: str = "",
           details: dict[str, Any] | None = None, ip: str = "", severity: str = "info") -> None:
    details = redact_obj(details or {})
    target = (target or "")[:255]
    engine = get_engine()
    ts = utcnow()
    with _lock, engine.connect() as conn:
        if engine.dialect.name == "sqlite":
            conn.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            conn.begin()
            conn.execute(text("SELECT pg_advisory_xact_lock(742001)"))
        try:
            prev = conn.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar() or GENESIS
            payload = _canonical(ts, user_id, username, action, target, details, ip, severity)
            conn.execute(AuditLog.__table__.insert().values(
                ts=ts, user_id=user_id, username=username[:64], action=action[:64], target=target, details=details,
                ip=ip[:64], severity=severity, prev_hash=prev, hash=_mac(prev, payload)))
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def verify_chain(db) -> dict[str, Any]:  # noqa: ANN001
    prev = GENESIS
    count = 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)).yield_per(500):
        payload = _canonical(row.ts, row.user_id, row.username, row.action, row.target, row.details or {}, row.ip,
                             row.severity)
        if row.prev_hash != prev or not hmac.compare_digest(row.hash, _mac(prev, payload)):
            return {"ok": False, "entries": count, "broken_at": row.id,
                    "reason": "hash previo no coincide" if row.prev_hash != prev else "HMAC no coincide (entrada alterada)"}
        prev = row.hash
        count += 1
    return {"ok": True, "entries": count, "broken_at": None, "reason": None}
