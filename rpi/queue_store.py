"""
vtr-continuity v0.2.0 — RPi 4 OT Tier
rpi/queue_store.py

Persistencia SQLite (WAL) de eventos OT en el RPi.
Cuando el canal IP está caído, los eventos se acumulan aquí.
Al restaurarse la conectividad, SyncManager hace flush FIFO.

Tablas:
  offline_queue  — eventos pendientes de envío
  sync_log       — registro de intentos de sincronización

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("/var/lib/vtr-continuity/queue.db")


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

@dataclass
class QueuedEvent:
    """Evento en cola de sincronización."""
    idempotency_key: str
    event_type: str       # "api_call" | "data_sync" | "alert" | "heartbeat"
    payload: dict[str, Any]
    queued_at: float      # Unix timestamp
    source: str           # "browser" | "agent" | "modbus" | "dnp3"
    attempts: int = 0
    last_attempt_at: float | None = None
    row_id: int | None = None


# ---------------------------------------------------------------------------
# QueueStore
# ---------------------------------------------------------------------------

class QueueStore:
    """
    Almacén SQLite WAL para la cola offline del RPi.

    Thread-safe via thread-local connections.
    El WAL permite lecturas concurrentes sin bloquear escrituras —
    crítico cuando el agente OT y el sync manager corren en paralelo.
    """

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Thread-local por instancia — evita contaminación entre instancias en tests
        self._local = threading.local()
        self._init_db()
        logger.info("[queue_store] SQLite WAL inicializado: %s", self.db_path)

    # ------------------------------------------------------------------
    # Conexión thread-local
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level=None,   # autocommit, manejamos transacciones manual
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager de transacción explícita."""
        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------
    # Inicialización de esquema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            BEGIN;

            CREATE TABLE IF NOT EXISTS offline_queue (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT    NOT NULL UNIQUE,
                event_type      TEXT    NOT NULL,
                payload         TEXT    NOT NULL,   -- JSON
                queued_at       REAL    NOT NULL,
                source          TEXT    NOT NULL DEFAULT 'unknown',
                attempts        INTEGER NOT NULL DEFAULT 0,
                last_attempt_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_queue_queued_at
                ON offline_queue(queued_at ASC);

            CREATE INDEX IF NOT EXISTS idx_queue_source
                ON offline_queue(source);

            CREATE TABLE IF NOT EXISTS sync_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                synced_at       REAL    NOT NULL,
                events_sent     INTEGER NOT NULL DEFAULT 0,
                events_failed   INTEGER NOT NULL DEFAULT 0,
                transport_type  TEXT    NOT NULL DEFAULT 'ip_http',
                duration_ms     REAL,
                error           TEXT
            );

            CREATE TABLE IF NOT EXISTS rpi_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO rpi_meta(key, value)
                VALUES ('schema_version', '1'),
                       ('created_at', strftime('%s', 'now'));

            COMMIT;
        """)

    # ------------------------------------------------------------------
    # Operaciones de cola
    # ------------------------------------------------------------------

    def enqueue(self, event: QueuedEvent) -> int:
        """
        Inserta un evento en la cola.
        Si el idempotency_key ya existe, ignora silenciosamente (idempotente).

        Returns:
            row_id del registro insertado, o -1 si ya existía.
        """
        if not event.idempotency_key:
            raise ValueError("idempotency_key no puede ser vacío")
        if not event.event_type:
            raise ValueError("event_type no puede ser vacío")
        if event.payload is None:
            raise ValueError("payload no puede ser None")

        try:
            payload_json = json.dumps(event.payload, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"payload no es serializable a JSON: {exc}") from exc

        with self._tx() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO offline_queue
                    (idempotency_key, event_type, payload, queued_at, source, attempts)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.idempotency_key,
                    event.event_type,
                    payload_json,
                    event.queued_at or time.time(),
                    event.source,
                    event.attempts,
                ),
            )
            row_id = cur.lastrowid if cur.rowcount > 0 else -1

        if row_id == -1:
            logger.debug(
                "[queue_store] enqueue ignorado — idempotency_key ya existe: %s",
                event.idempotency_key,
            )
        else:
            logger.debug(
                "[queue_store] enqueue OK — id=%d key=%s type=%s",
                row_id,
                event.idempotency_key,
                event.event_type,
            )
        return row_id

    def peek(self, limit: int = 50) -> list[QueuedEvent]:
        """
        Retorna los próximos `limit` eventos pendientes en orden FIFO.
        No los elimina — usar ack() o ack_batch() tras envío exitoso.
        """
        if limit <= 0:
            raise ValueError("limit debe ser > 0")

        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT id, idempotency_key, event_type, payload,
                   queued_at, source, attempts, last_attempt_at
            FROM offline_queue
            ORDER BY queued_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        events = []
        for row in rows:
            payload = None
            try:
                payload = json.loads(row["payload"])
            except (json.JSONDecodeError, TypeError):
                logger.error(
                    "[queue_store] payload JSON inválido en row id=%d", row["id"]
                )
                payload = {}

            events.append(QueuedEvent(
                idempotency_key=row["idempotency_key"],
                event_type=row["event_type"],
                payload=payload,
                queued_at=row["queued_at"],
                source=row["source"],
                attempts=row["attempts"],
                last_attempt_at=row["last_attempt_at"],
                row_id=row["id"],
            ))

        return events

    def ack(self, idempotency_key: str) -> bool:
        """Elimina un evento de la cola tras envío exitoso."""
        if not idempotency_key:
            return False

        with self._tx() as conn:
            cur = conn.execute(
                "DELETE FROM offline_queue WHERE idempotency_key = ?",
                (idempotency_key,),
            )
        deleted = cur.rowcount > 0
        if deleted:
            logger.debug("[queue_store] ack OK — key=%s", idempotency_key)
        else:
            logger.warning("[queue_store] ack — key no encontrada: %s", idempotency_key)
        return deleted

    def ack_batch(self, idempotency_keys: list[str]) -> int:
        """
        Elimina múltiples eventos en una sola transacción.
        Returns: cantidad de registros eliminados.
        """
        if not idempotency_keys:
            return 0

        placeholders = ",".join("?" * len(idempotency_keys))
        with self._tx() as conn:
            cur = conn.execute(
                f"DELETE FROM offline_queue WHERE idempotency_key IN ({placeholders})",
                idempotency_keys,
            )
        deleted = cur.rowcount
        logger.info("[queue_store] ack_batch — %d/%d eliminados", deleted, len(idempotency_keys))
        return deleted

    def mark_attempt(self, idempotency_key: str) -> None:
        """Incrementa contador de intentos fallidos y registra timestamp."""
        if not idempotency_key:
            return

        with self._tx() as conn:
            conn.execute(
                """
                UPDATE offline_queue
                SET attempts = attempts + 1,
                    last_attempt_at = ?
                WHERE idempotency_key = ?
                """,
                (time.time(), idempotency_key),
            )

    def depth(self) -> int:
        """Cantidad de eventos pendientes en cola."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) FROM offline_queue").fetchone()
        return row[0] if row else 0

    def clear(self) -> int:
        """Vacía la cola completa. Usar solo en tests o reset manual."""
        with self._tx() as conn:
            cur = conn.execute("DELETE FROM offline_queue")
        logger.warning("[queue_store] cola vaciada — %d registros eliminados", cur.rowcount)
        return cur.rowcount

    # ------------------------------------------------------------------
    # Sync log
    # ------------------------------------------------------------------

    def log_sync(
        self,
        events_sent: int,
        events_failed: int,
        transport_type: str,
        duration_ms: float | None = None,
        error: str | None = None,
    ) -> None:
        """Registra el resultado de un ciclo de sincronización."""
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO sync_log
                    (synced_at, events_sent, events_failed, transport_type, duration_ms, error)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (time.time(), events_sent, events_failed, transport_type, duration_ms, error),
            )

    def last_sync(self) -> dict[str, Any] | None:
        """Retorna el registro del último ciclo de sync."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM sync_log ORDER BY synced_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Resumen del estado de la cola para dashboard/monitor."""
        conn = self._get_conn()
        depth = self.depth()
        oldest = conn.execute(
            "SELECT MIN(queued_at) FROM offline_queue"
        ).fetchone()[0]
        max_attempts = conn.execute(
            "SELECT MAX(attempts) FROM offline_queue"
        ).fetchone()[0]
        last = self.last_sync()

        return {
            "queue_depth": depth,
            "oldest_event_age_s": round(time.time() - oldest, 1) if oldest else None,
            "max_attempts": max_attempts or 0,
            "last_sync": last,
        }
