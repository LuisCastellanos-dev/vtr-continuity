"""
vtr-continuity v0.2.0 — RPi 4 OT Tier
rpi/sync_manager.py

Orquestador de sincronización en el RPi.
- Heartbeat periódico hacia el servidor central
- Flush FIFO de la cola SQLite cuando el canal IP se restaura
- Backoff exponencial idéntico al HeartbeatMonitor del frontend v0.1.0

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .queue_store import QueueStore, QueuedEvent
from .transport import AbstractTransport, TransportResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

@dataclass
class SyncConfig:
    heartbeat_interval_s: float = 30.0      # intervalo base cuando online
    flush_batch_size: int = 50              # eventos por ciclo de flush
    backoff_base: float = 2.0              # backoff exponencial base (s)
    backoff_max: float = 300.0             # máximo 5 min entre intentos
    max_attempts_before_dead: int = 10     # eventos con >= N intentos → log crítico
    offline_threshold_s: float = 60.0     # tiempo sin contacto para declarar OFFLINE


# ---------------------------------------------------------------------------
# Estado observable
# ---------------------------------------------------------------------------

@dataclass
class SyncState:
    status: str = "INITIALIZING"   # ONLINE | OFFLINE | SYNCING | ERROR
    last_contact_at: float | None = None
    consecutive_failures: int = 0
    total_sent: int = 0
    total_failed: int = 0
    queue_depth: int = 0
    last_error: str | None = None


# ---------------------------------------------------------------------------
# SyncManager
# ---------------------------------------------------------------------------

class SyncManager:
    """
    Gestiona el ciclo de vida de sincronización en el RPi 4.

    Corre en un thread de fondo. El proxy HTTP (proxy.py) puede
    consultarlo via state para exponer métricas al dashboard.

    Flujo:
        1. health_check() → si OK → flush() → estado ONLINE
        2. health_check() → si FAIL → backoff → estado OFFLINE
        3. Al reconectar: flush FIFO completo antes de aceptar nuevos eventos
    """

    def __init__(
        self,
        transport: AbstractTransport,
        store: QueueStore,
        config: SyncConfig | None = None,
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

        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Estado público (thread-safe)
    # ------------------------------------------------------------------

    @property
    def state(self) -> SyncState:
        """Snapshot del estado actual. No mutarlo externamente."""
        with self._state_lock:
            return SyncState(
                status=self._state.status,
                last_contact_at=self._state.last_contact_at,
                consecutive_failures=self._state.consecutive_failures,
                total_sent=self._state.total_sent,
                total_failed=self._state.total_failed,
                queue_depth=self._state.queue_depth,
                last_error=self._state.last_error,
            )

    def is_online(self) -> bool:
        return self._state.status == "ONLINE"

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Inicia el loop de sincronización en thread de fondo."""
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
            "[sync_manager] iniciado — transporte=%s heartbeat=%.0fs",
            self._transport.transport_type,
            self._config.heartbeat_interval_s,
        )

    def stop(self, timeout: float = 10.0) -> None:
        """Detiene el loop de sincronización."""
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
                    failures,
                    wait,
                )

            # Actualizar depth en estado
            try:
                depth = self._store.depth()
                with self._state_lock:
                    self._state.queue_depth = depth
            except Exception:
                pass

            self._stop_event.wait(timeout=wait)

    # ------------------------------------------------------------------
    # Flush FIFO
    # ------------------------------------------------------------------

    def _flush_queue(self) -> None:
        """
        Envía todos los eventos pendientes en orden FIFO.
        Si un evento falla, se registra el intento y se continúa
        con el siguiente (no se bloquea el batch completo).
        """
        start_t = time.time()
        sent = 0
        failed = 0

        while True:
            batch = self._store.peek(limit=self._config.flush_batch_size)
            if not batch:
                break

            ack_keys: list[str] = []

            for event in batch:
                if event.attempts >= self._config.max_attempts_before_dead:
                    logger.critical(
                        "[sync_manager] evento con %d intentos fallidos — "
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
                    "data": event.payload,
                }

                result: TransportResult = self._transport.send_with_retry(payload)

                if result.success:
                    ack_keys.append(event.idempotency_key)
                    sent += 1
                    logger.debug(
                        "[sync_manager] enviado OK — key=%s retries=%d",
                        event.idempotency_key,
                        result.retries,
                    )
                else:
                    self._store.mark_attempt(event.idempotency_key)
                    failed += 1
                    logger.warning(
                        "[sync_manager] falló envío — key=%s error=%s",
                        event.idempotency_key,
                        result.error,
                    )

                # Si el canal se pierde durante el flush, abortar
                if not self._transport.health_check():
                    logger.warning("[sync_manager] canal perdido durante flush — abortando")
                    if ack_keys:
                        self._store.ack_batch(ack_keys)
                    self._log_sync(sent, failed, start_t, error="canal perdido durante flush")
                    return

            if ack_keys:
                self._store.ack_batch(ack_keys)

            # Si todo el batch falló, no seguir intentando en este ciclo
            if len(ack_keys) == 0:
                break

        duration_ms = (time.time() - start_t) * 1000
        self._log_sync(sent, failed, start_t)

        with self._state_lock:
            self._state.total_sent += sent
            self._state.total_failed += failed

        if sent > 0 or failed > 0:
            logger.info(
                "[sync_manager] flush completo — enviados=%d fallidos=%d tiempo=%.0fms",
                sent,
                failed,
                duration_ms,
            )

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

    # ------------------------------------------------------------------
    # Enqueue directo (para uso desde proxy.py y agent.py)
    # ------------------------------------------------------------------

    def enqueue(self, event: QueuedEvent) -> int:
        """
        Encola un evento. Si estamos ONLINE, el loop lo enviará
        en el próximo heartbeat. Si estamos OFFLINE, persiste en SQLite.
        """
        return self._store.enqueue(event)

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _update_state(self, status: str, **kwargs: Any) -> None:
        with self._state_lock:
            self._state.status = status
            for k, v in kwargs.items():
                if hasattr(self._state, k):
                    setattr(self._state, k, v)
