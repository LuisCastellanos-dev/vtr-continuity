"""
vtr-continuity v0.4.0 — RPi 4 OT Tier
rpi/sync_manager.py

Orquestador de sincronización en el RPi.
- Heartbeat periódico hacia el servidor central
- Flush FIFO de la cola SQLite cuando el canal IP se restaura
- Backoff exponencial idéntico al HeartbeatMonitor del frontend v0.1.0
- Custodia DTN-inspired via CustodyManager (v0.4.0)
  grant() → send() → ack() → is_safe_to_delete() → borrar
  Ningún evento se borra hasta confirmación explícita del destino.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .queue_store import QueueStore, QueuedEvent
from .transport import AbstractTransport, TransportResult
from core.custody_manager import CustodyManager, MAX_LORA_FRAME_BYTES

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

@dataclass
class SyncConfig:
    heartbeat_interval_s: float = 30.0
    flush_batch_size: int = 50
    backoff_base: float = 2.0
    backoff_max: float = 300.0
    max_attempts_before_dead: int = 10
    offline_threshold_s: float = 60.0
    custody_timeout_s: float = 300.0      # timeout de custodia por bundle
    custody_db_path: str = "/var/lib/vtr-continuity/custody.db"


# ---------------------------------------------------------------------------
# Estado observable
# ---------------------------------------------------------------------------

@dataclass
class SyncState:
    status: str = "INITIALIZING"
    last_contact_at: float | None = None
    consecutive_failures: int = 0
    total_sent: int = 0
    total_failed: int = 0
    queue_depth: int = 0
    custody_pending: int = 0
    last_error: str | None = None


# ---------------------------------------------------------------------------
# SyncManager
# ---------------------------------------------------------------------------

class SyncManager:
    """
    Gestiona el ciclo de vida de sincronización en el RPi 4.

    v0.4.0: integra CustodyManager para custodia DTN-inspired.
    Ningún evento se elimina del QueueStore hasta que CustodyManager
    confirme que el destino lo recibió (custody_ack).

    Flujo por evento:
        1. custody.grant(bundle_id, hash)   — tomo custodia
        2. transport.send_with_retry()       — envío al servidor
        3. custody.ack(bundle_id)            — destino confirmó
        4. custody.is_safe_to_delete()       — verifico antes de borrar
        5. store.ack_batch()                 — borro del QueueStore
    """

    def __init__(
        self,
        transport: AbstractTransport,
        store: QueueStore,
        config: SyncConfig | None = None,
        custody: CustodyManager | None = None,
    ) -> None:
        if transport is None:
            raise ValueError("transport no puede ser None")
        if store is None:
            raise ValueError("store no puede ser None")

        self._transport = transport
        self._store = store
        self._config = config or SyncConfig()
        self._state = SyncState()
        self._state_lock = threading.Lock()

        # CustodyManager — inyectable para tests, auto-creado en producción
        self._custody = custody or CustodyManager(
            db_path=Path(self._config.custody_db_path),
            default_timeout_seconds=self._config.custody_timeout_s,
        )

        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Estado público (thread-safe)
    # ------------------------------------------------------------------

    @property
    def state(self) -> SyncState:
        with self._state_lock:
            return SyncState(
                status=self._state.status,
                last_contact_at=self._state.last_contact_at,
                consecutive_failures=self._state.consecutive_failures,
                total_sent=self._state.total_sent,
                total_failed=self._state.total_failed,
                queue_depth=self._state.queue_depth,
                custody_pending=self._state.custody_pending,
                last_error=self._state.last_error,
            )

    def is_online(self) -> bool:
        return self._state.status == "ONLINE"

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            logger.warning("[sync_manager] ya está corriendo")
            return

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="vtr-sync-manager",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "[sync_manager] iniciado — transporte=%s heartbeat=%.0fs custody_timeout=%.0fs",
            self._transport.transport_type,
            self._config.heartbeat_interval_s,
            self._config.custody_timeout_s,
        )

    def stop(self, timeout: float = 10.0) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("[sync_manager] detenido")

    # ------------------------------------------------------------------
    # Loop principal
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        failures = 0

        while self._running and not self._stop_event.is_set():
            try:
                available = self._transport.health_check()
            except Exception as exc:
                logger.error("[sync_manager] health_check excepción: %s", exc)
                available = False

            if available:
                failures = 0
                self._update_state("SYNCING", consecutive_failures=0)
                self._retry_timed_out_custody()
                self._flush_queue()
                self._update_state(
                    "ONLINE",
                    last_contact_at=time.time(),
                    consecutive_failures=0,
                )
                wait = self._config.heartbeat_interval_s
            else:
                failures += 1
                wait = min(
                    self._config.backoff_base ** failures,
                    self._config.backoff_max,
                )
                self._update_state(
                    "OFFLINE",
                    consecutive_failures=failures,
                    last_error=f"health_check falló (intento {failures})",
                )
                logger.warning(
                    "[sync_manager] OFFLINE — intento %d, próximo en %.0fs",
                    failures, wait,
                )

            try:
                depth = self._store.depth()
                pending = len(self._custody.pending())
                with self._state_lock:
                    self._state.queue_depth = depth
                    self._state.custody_pending = pending
            except Exception:
                pass

            self._stop_event.wait(timeout=wait)

    # ------------------------------------------------------------------
    # Flush FIFO con custodia DTN
    # ------------------------------------------------------------------

    def _flush_queue(self) -> None:
        """
        Envía eventos pendientes con ciclo de custodia completo.

        Por cada evento:
          1. Serializar payload y computar SHA-256
          2. custody.grant() — tomo custodia antes de enviar
          3. Verificar límite LoRa (MAX_LORA_FRAME_BYTES = 222)
          4. transport.send_with_retry()
          5. custody.ack() con verify_hash — confirmo integridad
          6. custody.is_safe_to_delete() — puerta de seguridad
          7. store.ack_batch() — solo entonces borro

        Si el ack falla o is_safe_to_delete() es False,
        el evento permanece en QueueStore para el próximo ciclo.
        """
        start_t = time.time()
        sent = 0
        failed = 0

        while True:
            batch = self._store.peek(limit=self._config.flush_batch_size)
            if not batch:
                break

            safe_to_delete: list[str] = []

            for event in batch:
                if event.attempts >= self._config.max_attempts_before_dead:
                    logger.critical(
                        "[sync_manager] evento con %d intentos — "
                        "key=%s type=%s source=%s",
                        event.attempts,
                        event.idempotency_key,
                        event.event_type,
                        event.source,
                    )

                payload = {
                    "idempotency_key": event.idempotency_key,
                    "event_type": event.event_type,
                    "source": event.source,
                    "queued_at": event.queued_at,
                    "data": event.payload if event.payload is not None else {},
                }

                # Serializar y computar hash para custodia
                try:
                    payload_bytes = json.dumps(
                        payload, separators=(",", ":"), ensure_ascii=False
                    ).encode("utf-8")
                except (TypeError, ValueError) as exc:
                    logger.error(
                        "[sync_manager] payload no serializable key=%s: %s",
                        event.idempotency_key, exc,
                    )
                    self._store.mark_attempt(event.idempotency_key)
                    failed += 1
                    continue

                payload_hash = CustodyManager.compute_hash(payload_bytes)

                # Advertencia si el payload supera límite LoRa
                if len(payload_bytes) > MAX_LORA_FRAME_BYTES:
                    logger.debug(
                        "[sync_manager] payload %d bytes > LoRa limit %d — "
                        "requerirá fragmentación en v0.5.0 key=%s",
                        len(payload_bytes),
                        MAX_LORA_FRAME_BYTES,
                        event.idempotency_key,
                    )

                # 1. Tomar custodia antes de enviar
                self._custody.grant(
                    event.idempotency_key,
                    payload_hash,
                    timeout_seconds=self._config.custody_timeout_s,
                )

                # 2. Enviar con retry
                result: TransportResult = self._transport.send_with_retry(payload)

                if result.success:
                    # 3. Ack con verificación de hash — integridad end-to-end
                    acked = self._custody.ack(
                        event.idempotency_key,
                        verify_hash=payload_hash,
                    )

                    # 4. Puerta de seguridad antes de borrar
                    if acked and self._custody.is_safe_to_delete(event.idempotency_key):
                        safe_to_delete.append(event.idempotency_key)
                        sent += 1
                        logger.debug(
                            "[sync_manager] custodia completada — key=%s retries=%d",
                            event.idempotency_key, result.retries,
                        )
                    else:
                        # Ack falló — mantener en queue para reintento
                        self._store.mark_attempt(event.idempotency_key)
                        failed += 1
                        logger.warning(
                            "[sync_manager] ack de custodia falló — key=%s",
                            event.idempotency_key,
                        )
                else:
                    self._custody.increment_retry(event.idempotency_key)
                    self._store.mark_attempt(event.idempotency_key)
                    failed += 1
                    logger.warning(
                        "[sync_manager] envío falló — key=%s error=%s",
                        event.idempotency_key, result.error,
                    )

                # Canal perdido durante flush — abortar
                if not self._transport.health_check():
                    logger.warning("[sync_manager] canal perdido durante flush — abortando")
                    if safe_to_delete:
                        self._store.ack_batch(safe_to_delete)
                    self._log_sync(sent, failed, start_t, error="canal perdido durante flush")
                    return

            # 5. Borrar solo los confirmados por custodia
            if safe_to_delete:
                self._store.ack_batch(safe_to_delete)

            if len(safe_to_delete) == 0:
                break

        duration_ms = (time.time() - start_t) * 1000
        self._log_sync(sent, failed, start_t)

        with self._state_lock:
            self._state.total_sent += sent
            self._state.total_failed += failed

        if sent > 0 or failed > 0:
            logger.info(
                "[sync_manager] flush completo — enviados=%d fallidos=%d "
                "custody_pending=%d tiempo=%.0fms",
                sent, failed, len(self._custody.pending()), duration_ms,
            )

    # ------------------------------------------------------------------
    # Reintento de bundles con custodia vencida
    # ------------------------------------------------------------------

    def _retry_timed_out_custody(self) -> None:
        """
        Bundles PENDING con timeout vencido — reintento o mark_failed.
        Corre al inicio de cada ciclo ONLINE antes del flush normal.
        """
        expired = self._custody.timed_out()
        if not expired:
            return

        logger.warning(
            "[sync_manager] %d bundles con custodia vencida — reintentando",
            len(expired),
        )

        for bundle in expired:
            retries = self._custody.increment_retry(bundle.bundle_id)
            if retries > self._config.max_attempts_before_dead:
                self._custody.mark_failed(bundle.bundle_id)
                logger.critical(
                    "[sync_manager] bundle marcado FAILED tras %d reintentos — "
                    "key=%s",
                    retries, bundle.bundle_id,
                )

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _log_sync(
        self,
        sent: int,
        failed: int,
        start_t: float,
        error: str | None = None,
    ) -> None:
        try:
            self._store.log_sync(
                events_sent=sent,
                events_failed=failed,
                transport_type=self._transport.transport_type,
                duration_ms=(time.time() - start_t) * 1000,
                error=error,
            )
        except Exception as exc:
            logger.error("[sync_manager] error al guardar sync_log: %s", exc)

    def enqueue(self, event: QueuedEvent) -> int:
        return self._store.enqueue(event)

    def _update_state(self, status: str, **kwargs: Any) -> None:
        with self._state_lock:
            self._state.status = status
            for k, v in kwargs.items():
                if hasattr(self._state, k):
                    setattr(self._state, k, v)
