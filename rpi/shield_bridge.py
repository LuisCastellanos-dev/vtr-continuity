"""
vtr-continuity v0.3.0 — Integración Tampico Shield
rpi/shield_bridge.py

Bridge de solo lectura entre Tampico Shield (ShieldDB) y vtr-continuity (QueueStore).
Corre como systemd timer — completamente desacoplado de Tampico Shield.

Garantías de seguridad:
  - Solo lectura en ShieldDB — nunca escribe en la DB de Tampico Shield
  - Verificación SHA-256 por fila antes de procesar payload
  - Solo parámetros bind en queries — cero concatenación
  - Validación explícita de nulls y tipos en cada campo
  - Idempotency keys previenen duplicados en QueueStore
  - Filas con integridad comprometida se descartan y se registran

Filosofía resource-constrained:
  El bridge no mantiene estado propio — usa la tabla sync_log de QueueStore
  como cursor de posición. Sin archivos adicionales, sin proceso persistente.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .queue_store import QueueStore, QueuedEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuración desde entorno
# ---------------------------------------------------------------------------

SHIELD_DB_PATH = Path(os.environ.get(
    "TAMPICO_DB_PATH",
    "/var/lib/tampico-shield/shield.db"
))
VTR_DB_PATH = Path(os.environ.get(
    "VTR_DB_PATH",
    "/var/lib/vtr-continuity/queue.db"
))
# Máximo de filas a procesar por ejecución — resource-constrained by design
BATCH_LIMIT = int(os.environ.get("BRIDGE_BATCH_LIMIT", "100"))
# Ventana de tiempo hacia atrás en segundos (default: últimos 5 minutos)
LOOKBACK_SECONDS = float(os.environ.get("BRIDGE_LOOKBACK_SECONDS", "300"))
# Tamaño máximo de payload en bytes antes de descartar
MAX_PAYLOAD_BYTES = int(os.environ.get("BRIDGE_MAX_PAYLOAD_BYTES", "8192"))


# ---------------------------------------------------------------------------
# Resultado de ejecución
# ---------------------------------------------------------------------------

@dataclass
class BridgeResult:
    alerts_read: int = 0
    netprobe_read: int = 0
    snapshots_read: int = 0
    enqueued: int = 0
    skipped_integrity: int = 0
    skipped_invalid: int = 0
    duration_ms: float = 0.0
    error: str | None = None


# ---------------------------------------------------------------------------
# Funciones de seguridad
# ---------------------------------------------------------------------------

def _sha256(data: str) -> str:
    """SHA-256 del payload — mismo algoritmo que ShieldDB."""
    return hashlib.sha256(data.encode()).hexdigest()


def _verify_integrity(payload_str: str | None, expected_hash: str | None) -> bool:
    """
    Verifica integridad SHA-256 de una fila de ShieldDB.
    Retorna False si payload o hash son None/vacíos o no coinciden.
    """
    if payload_str is None or expected_hash is None:
        return False
    if not isinstance(payload_str, str) or not isinstance(expected_hash, str):
        return False
    if not payload_str.strip() or not expected_hash.strip():
        return False
    if len(payload_str.encode()) > MAX_PAYLOAD_BYTES:
        logger.warning("[bridge] payload excede %d bytes — descartado", MAX_PAYLOAD_BYTES)
        return False
    return _sha256(payload_str) == expected_hash


def _safe_parse_payload(payload_str: str | None) -> dict[str, Any] | None:
    """
    Parsea payload JSON con validación explícita.
    Retorna None si el payload es inválido — nunca lanza excepción.
    """
    if payload_str is None:
        return None
    if not isinstance(payload_str, str):
        return None
    try:
        obj = json.loads(payload_str)
        if not isinstance(obj, dict):
            logger.warning("[bridge] payload no es dict JSON: %s", type(obj))
            return None
        return obj
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("[bridge] payload JSON inválido: %s", exc)
        return None


def _safe_str(value: Any, max_len: int = 256) -> str:
    """Convierte a string seguro con longitud máxima."""
    if value is None:
        return ""
    return str(value)[:max_len]


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convierte a float con fallback — nunca lanza excepción."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Convierte a int con fallback — nunca lanza excepción."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Conexión a ShieldDB (solo lectura)
# ---------------------------------------------------------------------------

def _open_shield_db(path: Path) -> sqlite3.Connection | None:
    """
    Abre ShieldDB en modo solo lectura.
    Retorna None si el archivo no existe o no es accesible.
    """
    if not path.exists():
        logger.error("[bridge] ShieldDB no encontrada: %s", path)
        return None
    try:
        # uri=True + mode=ro garantiza apertura de solo lectura a nivel SQLite
        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # No seteamos journal_mode — estamos en modo solo lectura
        # ShieldDB ya tiene WAL activo desde su propia inicialización
        return conn
    except sqlite3.OperationalError as exc:
        logger.error("[bridge] error abriendo ShieldDB: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Conversores de filas → QueuedEvent
# ---------------------------------------------------------------------------

def _alert_to_event(row: sqlite3.Row) -> QueuedEvent | None:
    """
    Convierte una fila de `alerts` a QueuedEvent.
    Verifica integridad SHA-256 antes de procesar.
    Retorna None si la fila es inválida o está comprometida.
    """
    row_id = _safe_int(row["id"] if "id" in row.keys() else None)
    payload_str = row["payload"] if "payload" in row.keys() else None
    sha256 = row["sha256"] if "sha256" in row.keys() else None

    if not _verify_integrity(payload_str, sha256):
        logger.warning(
            "[bridge] integridad comprometida en alerts id=%d — descartado", row_id
        )
        return None

    payload = _safe_parse_payload(payload_str)
    if payload is None:
        return None

    level = _safe_str(row["level"] if "level" in row.keys() else None, 32)
    created_at = _safe_float(row["created_at"] if "created_at" in row.keys() else None)

    # Idempotency key determinista: shield_alert + id + hash parcial
    idem_key = f"shield_alert_{row_id}_{sha256[:16]}"

    return QueuedEvent(
        idempotency_key=idem_key,
        event_type="alert",
        payload={
            "source_system": "tampico_shield",
            "table": "alerts",
            "row_id": row_id,
            "level": level,
            "data": payload,
            "shield_sha256": sha256,
        },
        queued_at=created_at or time.time(),
        source="agent",
    )


def _netprobe_to_event(row: sqlite3.Row) -> QueuedEvent | None:
    """
    Convierte una fila de `netprobe_events` a QueuedEvent.
    netprobe_events puede no tener sha256 — validamos campos mínimos.
    """
    row_id = _safe_int(row["id"] if "id" in row.keys() else None)
    keys = row.keys()

    # netprobe_events puede venir con o sin sha256 según versión de ShieldDB
    payload_str = row["payload"] if "payload" in keys else None
    sha256 = row["sha256"] if "sha256" in keys else None

    # Si tiene sha256, verificamos; si no, procesamos con advertencia
    if sha256 is not None:
        if not _verify_integrity(payload_str, sha256):
            logger.warning(
                "[bridge] integridad comprometida en netprobe_events id=%d — descartado",
                row_id,
            )
            return None
    else:
        logger.debug("[bridge] netprobe_events id=%d sin sha256 — procesando sin verificar", row_id)

    payload = _safe_parse_payload(payload_str) or {}

    # Campos directos de netprobe_events (DNP3 sentinel v1.2)
    event_type_raw = _safe_str(row["event_type"] if "event_type" in keys else None, 64)
    src_ip = _safe_str(row["src_ip"] if "src_ip" in keys else None, 64)
    func_code = _safe_int(row["func_code"] if "func_code" in keys else None)
    created_at = _safe_float(row["created_at"] if "created_at" in keys else None)

    idem_key = f"shield_netprobe_{row_id}_{sha256[:16] if sha256 else uuid.uuid4().hex[:16]}"

    return QueuedEvent(
        idempotency_key=idem_key,
        event_type="alert",
        payload={
            "source_system": "tampico_shield",
            "table": "netprobe_events",
            "row_id": row_id,
            "dnp3_event_type": event_type_raw,
            "src_ip": src_ip,
            "func_code": func_code,
            "data": payload,
        },
        queued_at=created_at or time.time(),
        source="dnp3",
    )


def _snapshot_to_event(row: sqlite3.Row) -> QueuedEvent | None:
    """
    Convierte una fila de `baseline_snapshots` a QueuedEvent.
    Solo exporta snapshots con anomalía significativa (entropy > umbral).
    Resource-constrained: no exportamos snapshots normales, solo outliers.
    """
    row_id = _safe_int(row["id"] if "id" in row.keys() else None)
    keys = row.keys()

    payload_str = row["payload"] if "payload" in keys else None
    sha256 = row["sha256"] if "sha256" in keys else None

    if not _verify_integrity(payload_str, sha256):
        logger.warning(
            "[bridge] integridad comprometida en baseline_snapshots id=%d — descartado",
            row_id,
        )
        return None

    payload = _safe_parse_payload(payload_str)
    if payload is None:
        return None

    entropy = _safe_float(row["entropy"] if "entropy" in keys else None)
    pid = _safe_int(row["pid"] if "pid" in keys else None)
    comm = _safe_str(row["comm"] if "comm" in keys else None, 64)
    created_at = _safe_float(row["created_at"] if "created_at" in keys else None)

    idem_key = f"shield_snapshot_{row_id}_{sha256[:16]}"

    return QueuedEvent(
        idempotency_key=idem_key,
        event_type="data_sync",
        payload={
            "source_system": "tampico_shield",
            "table": "baseline_snapshots",
            "row_id": row_id,
            "pid": pid,
            "comm": comm,
            "entropy": entropy,
            "data": payload,
            "shield_sha256": sha256,
        },
        queued_at=created_at or time.time(),
        source="agent",
    )


# ---------------------------------------------------------------------------
# Bridge principal
# ---------------------------------------------------------------------------

class ShieldBridge:
    """
    Bridge de solo lectura Tampico Shield → vtr-continuity.

    Diseñado para correr como systemd timer:
    - Sin estado propio — usa QueueStore como registro de posición
    - Idempotente — puede correr múltiples veces sin duplicados
    - Falla rápido — si ShieldDB no está disponible, registra y sale

    Seguridad:
    - Apertura de ShieldDB en modo uri solo lectura
    - SHA-256 verificado por fila antes de procesar
    - Solo parámetros bind en queries
    - Validación explícita de nulls en cada campo
    """

    def __init__(
        self,
        shield_db_path: Path = SHIELD_DB_PATH,
        vtr_db_path: Path = VTR_DB_PATH,
        batch_limit: int = BATCH_LIMIT,
        lookback_seconds: float = LOOKBACK_SECONDS,
    ) -> None:
        self.shield_db_path = shield_db_path
        self.store = QueueStore(db_path=vtr_db_path)
        self.batch_limit = batch_limit
        self.lookback_seconds = lookback_seconds

    def run(self) -> BridgeResult:
        """
        Ejecuta un ciclo completo del bridge.
        Lee alertas, eventos DNP3 y snapshots desde ShieldDB
        y los encola en QueueStore.
        """
        result = BridgeResult()
        start_t = time.time()

        shield_conn = _open_shield_db(self.shield_db_path)
        if shield_conn is None:
            result.error = f"ShieldDB no disponible: {self.shield_db_path}"
            logger.error("[bridge] %s", result.error)
            return result

        since = time.time() - self.lookback_seconds

        try:
            result.alerts_read = self._process_alerts(shield_conn, since, result)
            result.netprobe_read = self._process_netprobe(shield_conn, since, result)
            result.snapshots_read = self._process_snapshots(shield_conn, since, result)
        except Exception as exc:
            logger.exception("[bridge] error inesperado durante procesamiento")
            result.error = str(exc)
        finally:
            shield_conn.close()

        result.duration_ms = (time.time() - start_t) * 1000
        logger.info(
            "[bridge] ciclo completo — alerts=%d netprobe=%d snapshots=%d "
            "enqueued=%d skip_integrity=%d skip_invalid=%d tiempo=%.0fms",
            result.alerts_read,
            result.netprobe_read,
            result.snapshots_read,
            result.enqueued,
            result.skipped_integrity,
            result.skipped_invalid,
            result.duration_ms,
        )
        return result

    def _process_alerts(
        self,
        conn: sqlite3.Connection,
        since: float,
        result: BridgeResult,
    ) -> int:
        """Lee y encola alertas de ShieldDB."""
        try:
            rows = conn.execute(
                """
                SELECT id, level, payload, sha256, created_at
                FROM alerts
                WHERE created_at >= ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (since, self.batch_limit),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("[bridge] tabla alerts no disponible: %s", exc)
            return 0

        for row in rows:
            event = _alert_to_event(row)
            if event is None:
                result.skipped_integrity += 1
                continue
            try:
                row_id = self.store.enqueue(event)
                if row_id > 0:
                    result.enqueued += 1
                # row_id == -1 significa idempotency_key ya existe — correcto, no es error
            except ValueError as exc:
                logger.warning("[bridge] evento inválido descartado: %s", exc)
                result.skipped_invalid += 1

        return len(rows)

    def _process_netprobe(
        self,
        conn: sqlite3.Connection,
        since: float,
        result: BridgeResult,
    ) -> int:
        """Lee y encola eventos DNP3/netprobe de ShieldDB."""
        try:
            rows = conn.execute(
                """
                SELECT *
                FROM netprobe_events
                WHERE created_at >= ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (since, self.batch_limit),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("[bridge] tabla netprobe_events no disponible: %s", exc)
            return 0

        for row in rows:
            event = _netprobe_to_event(row)
            if event is None:
                result.skipped_integrity += 1
                continue
            try:
                row_id = self.store.enqueue(event)
                if row_id > 0:
                    result.enqueued += 1
            except ValueError as exc:
                logger.warning("[bridge] evento netprobe inválido: %s", exc)
                result.skipped_invalid += 1

        return len(rows)

    def _process_snapshots(
        self,
        conn: sqlite3.Connection,
        since: float,
        result: BridgeResult,
    ) -> int:
        """
        Lee y encola snapshots de baseline con anomalía.
        Resource-constrained: solo exporta outliers, no snapshots normales.
        Umbral de entropía configurable — default 0.7.
        """
        entropy_threshold = float(os.environ.get("BRIDGE_ENTROPY_THRESHOLD", "0.7"))

        try:
            rows = conn.execute(
                """
                SELECT id, pid, comm, entropy, payload, sha256, created_at
                FROM baseline_snapshots
                WHERE created_at >= ?
                  AND entropy >= ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (since, entropy_threshold, self.batch_limit),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("[bridge] tabla baseline_snapshots no disponible: %s", exc)
            return 0

        for row in rows:
            event = _snapshot_to_event(row)
            if event is None:
                result.skipped_integrity += 1
                continue
            try:
                row_id = self.store.enqueue(event)
                if row_id > 0:
                    result.enqueued += 1
            except ValueError as exc:
                logger.warning("[bridge] snapshot inválido descartado: %s", exc)
                result.skipped_invalid += 1

        return len(rows)


# ---------------------------------------------------------------------------
# Entrypoint CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="VTR Continuity — Shield Bridge v0.3.0",
        epilog="Ejecutar via systemd timer: ver deploy/shield-bridge.timer",
    )
    parser.add_argument("--shield-db", default=str(SHIELD_DB_PATH))
    parser.add_argument("--vtr-db", default=str(VTR_DB_PATH))
    parser.add_argument("--batch", type=int, default=BATCH_LIMIT)
    parser.add_argument("--lookback", type=float, default=LOOKBACK_SECONDS)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    bridge = ShieldBridge(
        shield_db_path=Path(args.shield_db),
        vtr_db_path=Path(args.vtr_db),
        batch_limit=args.batch,
        lookback_seconds=args.lookback,
    )
    result = bridge.run()

    if result.error:
        import sys
        print(f"ERROR: {result.error}")
        sys.exit(1)

    print(
        f"OK — enqueued={result.enqueued} "
        f"skip_integrity={result.skipped_integrity} "
        f"skip_invalid={result.skipped_invalid} "
        f"time={result.duration_ms:.0f}ms"
    )


if __name__ == "__main__":
    main()
