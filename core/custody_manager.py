"""
vtr-continuity v0.4.0 — Core
core/custody_manager.py

Transferencia de custodia explícita inspirada en DTN Bundle Protocol RFC 9171.

Principio: ningún nodo borra un bundle hasta recibir confirmación explícita
de que el siguiente nodo lo tiene. Esto es lo que diferencia DTN de
"retry con backoff" — la responsabilidad se transfiere, no se asume.

Lecciones de Marte aplicadas a OT Tamaulipas:
  - Un ACK de radio no es confirmación de procesamiento en el destino
  - La custodia es simétrica — cualquier nodo puede ser custodio
  - Bundles sin ack después de timeout → reintento automático
  - custody.db separado de queue.db — sobrevive corrupción independiente

Nodos que usan este módulo:
  v0.3.0: rpi/sync_manager.py        — RPi 4 como nodo custodio
  v0.4.0: server/sync_server.py      — servidor central
  v0.5.0: lora/node.py               — nodos LoRa intermedios

Memory budget: <4MB RSS — SQLite WAL, sin estructuras en memoria
que crezcan con el número de bundles históricos.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

DEFAULT_CUSTODY_DB = Path("/var/lib/vtr-continuity/custody.db")

# Límite físico LoRa SX1262 SF7/BW125kHz CR4/5 — v0.5.0
MAX_LORA_FRAME_BYTES = 222


# ---------------------------------------------------------------------------
# Tipos
# ---------------------------------------------------------------------------

class CustodyStatus(str, Enum):
    PENDING  = "PENDING"   # bundle en tránsito, esperando ack del destino
    ACKED    = "ACKED"     # destino confirmó recepción — puede liberarse
    FAILED   = "FAILED"    # timeout agotado sin ack — requiere intervención
    TRANSFER = "TRANSFER"  # custodia transferida a otro nodo (multi-hop)


@dataclass
class CustodyBundle:
    """Registro de un bundle bajo custodia."""
    bundle_id: str
    payload_hash: str           # SHA-256 del payload original
    status: CustodyStatus
    granted_at: float           # Unix timestamp de grant inicial
    acked_at: float | None
    next_hop: str | None        # nodo destino de transferencia
    retries: int
    last_retry_at: float | None
    timeout_seconds: float
    row_id: int | None = None


# ---------------------------------------------------------------------------
# CustodyManager
# ---------------------------------------------------------------------------

class CustodyManager:
    """
    Gestor de custodia de bundles DTN-inspired.

    Thread-safe via thread-local connections.
    Persiste en SQLite WAL separado de queue.db.

    Uso desde SyncManager:
        cm = CustodyManager()
        cm.grant(bundle_id, payload_hash)       # antes de enviar
        # ... envío ...
        cm.ack(bundle_id)                       # al recibir confirmación
        # QueueStore.ack_batch() solo si custody_ack exitoso
    """

    def __init__(
        self,
        db_path: Path | str = DEFAULT_CUSTODY_DB,
        default_timeout_seconds: float = 300.0,   # 5 min default
        max_retries: int = 5,
    ) -> None:
        if not db_path:
            raise ValueError("db_path no puede ser vacío")
        if default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds debe ser > 0")
        if max_retries < 0:
            raise ValueError("max_retries debe ser >= 0")

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.default_timeout_seconds = default_timeout_seconds
        self.max_retries = max_retries
        self._local = threading.local()
        self._init_db()
        logger.info(
            "[custody] inicializado — db=%s timeout=%.0fs max_retries=%d",
            self.db_path, default_timeout_seconds, max_retries,
        )

    # ------------------------------------------------------------------
    # Conexión thread-local
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Connection, None, None]:
        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------
    # Esquema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            BEGIN;

            CREATE TABLE IF NOT EXISTS custody_bundles (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                bundle_id        TEXT    NOT NULL UNIQUE,
                payload_hash     TEXT    NOT NULL,
                status           TEXT    NOT NULL DEFAULT 'PENDING',
                granted_at       REAL    NOT NULL,
                acked_at         REAL,
                next_hop         TEXT,
                retries          INTEGER NOT NULL DEFAULT 0,
                last_retry_at    REAL,
                timeout_seconds  REAL    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_custody_status
                ON custody_bundles(status);

            CREATE INDEX IF NOT EXISTS idx_custody_granted_at
                ON custody_bundles(granted_at ASC);

            CREATE TABLE IF NOT EXISTS custody_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO custody_meta(key, value)
                VALUES ('schema_version', '1'),
                       ('created_at', strftime('%s', 'now'));

            COMMIT;
        """)

    # ------------------------------------------------------------------
    # Operaciones de custodia
    # ------------------------------------------------------------------

    def grant(
        self,
        bundle_id: str,
        payload_hash: str,
        timeout_seconds: float | None = None,
    ) -> bool:
        """
        Registra que este nodo toma custodia de un bundle.
        Debe llamarse ANTES de enviar el bundle al siguiente nodo.

        Args:
            bundle_id:       Identificador único del bundle (idempotency_key)
            payload_hash:    SHA-256 del payload — verifica integridad en ack
            timeout_seconds: Override del timeout default para este bundle

        Returns:
            True si se registró, False si el bundle_id ya existía (idempotente)
        """
        if not bundle_id:
            raise ValueError("bundle_id no puede ser vacío")
        if not payload_hash:
            raise ValueError("payload_hash no puede ser vacío")

        timeout = timeout_seconds if timeout_seconds is not None else self.default_timeout_seconds
        if timeout <= 0:
            raise ValueError("timeout_seconds debe ser > 0")

        with self._tx() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO custody_bundles
                    (bundle_id, payload_hash, status, granted_at, timeout_seconds)
                VALUES (?, ?, ?, ?, ?)
                """,
                (bundle_id, payload_hash, CustodyStatus.PENDING.value,
                 time.time(), timeout),
            )
            inserted = cur.rowcount > 0

        if inserted:
            logger.debug("[custody] grant — bundle_id=%s", bundle_id)
        else:
            logger.debug("[custody] grant ignorado — bundle_id ya existe: %s", bundle_id)

        return inserted

    def ack(self, bundle_id: str, verify_hash: str | None = None) -> bool:
        """
        El destino confirmó recepción del bundle.
        Marca el bundle como ACKED — el QueueStore puede liberar el evento.

        Args:
            bundle_id:    Bundle confirmado
            verify_hash:  Si se provee, verifica que coincida con payload_hash
                         registrado en grant(). Rechaza si no coincide.

        Returns:
            True si se marcó como ACKED, False si no existía o hash inválido.
        """
        if not bundle_id:
            return False

        if verify_hash is not None:
            row = self._get_conn().execute(
                "SELECT payload_hash FROM custody_bundles WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone()

            if row is None:
                logger.warning("[custody] ack — bundle_id no encontrado: %s", bundle_id)
                return False

            if row["payload_hash"] != verify_hash:
                logger.error(
                    "[custody] ack rechazado — hash no coincide bundle_id=%s "
                    "esperado=%s recibido=%s",
                    bundle_id, row["payload_hash"], verify_hash,
                )
                return False

        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE custody_bundles
                SET status = ?, acked_at = ?
                WHERE bundle_id = ? AND status = ?
                """,
                (CustodyStatus.ACKED.value, time.time(),
                 bundle_id, CustodyStatus.PENDING.value),
            )
            updated = cur.rowcount > 0

        if updated:
            logger.info("[custody] ack OK — bundle_id=%s", bundle_id)
        else:
            logger.warning(
                "[custody] ack sin efecto — bundle_id=%s "
                "(ya acked, transferido, o no existe)", bundle_id,
            )
        return updated

    def transfer(self, bundle_id: str, next_hop: str) -> bool:
        """
        Transfiere custodia a otro nodo (multi-hop DTN).
        El nodo actual ya no es responsable — el next_hop lo es.
        Usado en v0.5.0 para nodos LoRa intermedios.

        Args:
            bundle_id: Bundle a transferir
            next_hop:  Identificador del nodo que recibe la custodia
        """
        if not bundle_id:
            raise ValueError("bundle_id no puede ser vacío")
        if not next_hop:
            raise ValueError("next_hop no puede ser vacío")

        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE custody_bundles
                SET status = ?, next_hop = ?
                WHERE bundle_id = ? AND status = ?
                """,
                (CustodyStatus.TRANSFER.value, next_hop,
                 bundle_id, CustodyStatus.PENDING.value),
            )
            updated = cur.rowcount > 0

        if updated:
            logger.info(
                "[custody] transfer — bundle_id=%s next_hop=%s",
                bundle_id, next_hop,
            )
        return updated

    def mark_failed(self, bundle_id: str) -> bool:
        """Marca un bundle como FAILED tras agotar retries."""
        if not bundle_id:
            return False

        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE custody_bundles SET status = ? WHERE bundle_id = ?",
                (CustodyStatus.FAILED.value, bundle_id),
            )
        return cur.rowcount > 0

    def increment_retry(self, bundle_id: str) -> int:
        """
        Incrementa contador de reintentos.
        Returns: nuevo valor de retries, o -1 si no existe el bundle.
        """
        if not bundle_id:
            return -1

        with self._tx() as conn:
            conn.execute(
                """
                UPDATE custody_bundles
                SET retries = retries + 1, last_retry_at = ?
                WHERE bundle_id = ?
                """,
                (time.time(), bundle_id),
            )
            row = conn.execute(
                "SELECT retries FROM custody_bundles WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone()

        return row["retries"] if row else -1

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------

    def pending(self) -> list[CustodyBundle]:
        """
        Retorna todos los bundles en estado PENDING.
        Estos NO deben borrarse del QueueStore hasta recibir ack.
        """
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT * FROM custody_bundles
            WHERE status = ?
            ORDER BY granted_at ASC
            """,
            (CustodyStatus.PENDING.value,),
        ).fetchall()
        return [self._row_to_bundle(r) for r in rows]

    def timed_out(self) -> list[CustodyBundle]:
        """
        Retorna bundles PENDING que superaron su timeout.
        El SyncManager debe reintentarlos o marcarlos FAILED.
        """
        now = time.time()
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT * FROM custody_bundles
            WHERE status = ?
              AND (granted_at + timeout_seconds) < ?
            ORDER BY granted_at ASC
            """,
            (CustodyStatus.PENDING.value, now),
        ).fetchall()
        return [self._row_to_bundle(r) for r in rows]

    def get(self, bundle_id: str) -> CustodyBundle | None:
        """Retorna el estado de un bundle específico."""
        if not bundle_id:
            return None

        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM custody_bundles WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone()
        return self._row_to_bundle(row) if row else None

    def is_safe_to_delete(self, bundle_id: str) -> bool:
        """
        Retorna True solo si el bundle está ACKED o TRANSFER.
        El QueueStore consulta esto antes de borrar un evento.
        """
        if not bundle_id:
            return False

        bundle = self.get(bundle_id)
        if bundle is None:
            # Sin registro de custodia — no es seguro asumir que se puede borrar
            return False
        return bundle.status in (CustodyStatus.ACKED, CustodyStatus.TRANSFER)

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Resumen del estado de custodia para dashboard."""
        conn = self._get_conn()
        by_status = {}
        for row in conn.execute(
            "SELECT status, COUNT(*) as n FROM custody_bundles GROUP BY status"
        ).fetchall():
            by_status[row["status"]] = row["n"]

        timed_out_count = len(self.timed_out())

        return {
            "by_status": by_status,
            "timed_out": timed_out_count,
            "max_lora_frame_bytes": MAX_LORA_FRAME_BYTES,
        }

    def purge_acked(self, older_than_seconds: float = 86400.0) -> int:
        """
        Elimina registros ACKED más antiguos de N segundos.
        Resource-constrained: mantiene custody.db pequeño.
        Default: 24 horas.
        """
        if older_than_seconds <= 0:
            raise ValueError("older_than_seconds debe ser > 0")

        cutoff = time.time() - older_than_seconds
        with self._tx() as conn:
            cur = conn.execute(
                """
                DELETE FROM custody_bundles
                WHERE status = ? AND acked_at < ?
                """,
                (CustodyStatus.ACKED.value, cutoff),
            )
        deleted = cur.rowcount
        if deleted > 0:
            logger.info("[custody] purge_acked — %d registros eliminados", deleted)
        return deleted

    @staticmethod
    def _row_to_bundle(row: sqlite3.Row) -> CustodyBundle:
        return CustodyBundle(
            bundle_id=row["bundle_id"],
            payload_hash=row["payload_hash"],
            status=CustodyStatus(row["status"]),
            granted_at=row["granted_at"],
            acked_at=row["acked_at"],
            next_hop=row["next_hop"],
            retries=row["retries"],
            last_retry_at=row["last_retry_at"],
            timeout_seconds=row["timeout_seconds"],
            row_id=row["id"],
        )

    @staticmethod
    def compute_hash(payload: bytes | str) -> str:
        """
        Computa SHA-256 de un payload.
        Helper para que los llamadores no importen hashlib directamente.
        """
        if payload is None:
            raise ValueError("payload no puede ser None")
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
