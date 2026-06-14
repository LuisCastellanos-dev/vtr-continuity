"""
vtr-continuity v0.4.0 — Tests SyncManager con CustodyManager
rpi/tests/test_sync_custody.py

Verifica el ciclo completo:
  grant → send → ack → is_safe_to_delete → ack_batch

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from rpi.queue_store import QueueStore, QueuedEvent
from rpi.transport import TransportResult
from core.custody_manager import CustodyManager, CustodyStatus


def make_event(**kwargs):
    defaults = dict(
        idempotency_key=str(uuid.uuid4()),
        event_type="agent_event",
        payload={"k": "v"},
        queued_at=time.time(),
        source="agent",
    )
    defaults.update(kwargs)
    return QueuedEvent(**defaults)


def make_sync_manager(tmp_path, transport, store):
    from rpi.sync_manager import SyncManager, SyncConfig
    custody = CustodyManager(
        db_path=tmp_path / "custody.db",
        default_timeout_seconds=60.0,
    )
    config = SyncConfig(custody_db_path=str(tmp_path / "custody.db"))
    return SyncManager(transport=transport, store=store, config=config, custody=custody), custody


@pytest.fixture
def store(tmp_path):
    return QueueStore(db_path=tmp_path / "queue.db")


class TestSyncManagerCustody:

    def test_flush_completa_ciclo_custodia(self, tmp_path, store):
        """Evento enviado OK → custodia ACKED → borrado del QueueStore."""
        transport = MagicMock()
        transport.transport_type = "ip_http"
        transport.health_check.return_value = True
        transport.send_with_retry.return_value = TransportResult(
            success=True, transport_type="ip_http"
        )

        sm, custody = make_sync_manager(tmp_path, transport, store)
        evt = make_event()
        store.enqueue(evt)

        sm._flush_queue()

        # Queue vacía — evento borrado
        assert store.depth() == 0
        # Custodia completada
        bundle = custody.get(evt.idempotency_key)
        assert bundle is not None
        assert bundle.status == CustodyStatus.ACKED

    def test_flush_fallo_envio_mantiene_en_queue(self, tmp_path, store):
        """Envío fallido → evento permanece en QueueStore → custodia PENDING."""
        transport = MagicMock()
        transport.transport_type = "ip_http"
        transport.health_check.return_value = True
        transport.send_with_retry.return_value = TransportResult(
            success=False, error="timeout", transport_type="ip_http"
        )

        sm, custody = make_sync_manager(tmp_path, transport, store)
        evt = make_event()
        store.enqueue(evt)

        sm._flush_queue()

        # Evento sigue en queue
        assert store.depth() == 1
        # Custodia PENDING — no se borró
        bundle = custody.get(evt.idempotency_key)
        assert bundle is not None
        assert bundle.status == CustodyStatus.PENDING
        assert bundle.retries == 1

    def test_flush_no_borra_sin_custody_ack(self, tmp_path, store):
        """is_safe_to_delete() False → no borra aunque send() retorne success."""
        transport = MagicMock()
        transport.transport_type = "ip_http"
        transport.health_check.return_value = True
        transport.send_with_retry.return_value = TransportResult(
            success=True, transport_type="ip_http"
        )

        sm, custody = make_sync_manager(tmp_path, transport, store)

        # Pre-registrar custodia con hash incorrecto para forzar ack fallido
        evt = make_event()
        store.enqueue(evt)
        # Registrar custodia con hash diferente al que generará _flush_queue
        custody.grant(evt.idempotency_key, "hash_incorrecto_000000000000000")

        sm._flush_queue()

        # Aunque send() tuvo éxito, ack falló por hash mismatch
        # El evento queda en queue
        assert store.depth() == 1

    def test_flush_multiples_eventos_ciclo_completo(self, tmp_path, store):
        """Múltiples eventos — todos completan ciclo de custodia."""
        transport = MagicMock()
        transport.transport_type = "ip_http"
        transport.health_check.return_value = True
        transport.send_with_retry.return_value = TransportResult(
            success=True, transport_type="ip_http"
        )

        sm, custody = make_sync_manager(tmp_path, transport, store)

        keys = []
        for _ in range(5):
            evt = make_event()
            keys.append(evt.idempotency_key)
            store.enqueue(evt)

        sm._flush_queue()

        assert store.depth() == 0
        for key in keys:
            bundle = custody.get(key)
            assert bundle.status == CustodyStatus.ACKED

    def test_retry_custody_vencida(self, tmp_path, store):
        """Bundles con timeout vencido incrementan retry en _retry_timed_out_custody."""
        transport = MagicMock()
        transport.transport_type = "ip_http"
        transport.health_check.return_value = True

        custody = CustodyManager(
            db_path=tmp_path / "custody.db",
            default_timeout_seconds=0.01,  # vence casi inmediatamente
        )
        from rpi.sync_manager import SyncManager, SyncConfig
        sm = SyncManager(
            transport=transport,
            store=store,
            config=SyncConfig(),
            custody=custody,
        )

        bid = str(uuid.uuid4())
        custody.grant(bid, "hash_x", timeout_seconds=0.01)
        time.sleep(0.05)  # dejar vencer

        sm._retry_timed_out_custody()

        bundle = custody.get(bid)
        assert bundle.retries == 1

    def test_estado_incluye_custody_pending(self, tmp_path, store):
        """SyncState expone custody_pending para dashboard."""
        transport = MagicMock()
        transport.transport_type = "ip_http"

        sm, custody = make_sync_manager(tmp_path, transport, store)

        custody.grant(str(uuid.uuid4()), "hash_a")
        custody.grant(str(uuid.uuid4()), "hash_b")

        # Forzar actualización de estado
        with sm._state_lock:
            sm._state.custody_pending = len(custody.pending())

        assert sm.state.custody_pending == 2

    def test_canal_perdido_durante_flush_borra_confirmados(self, tmp_path, store):
        """Si canal se pierde durante flush, los ya confirmados se borran."""
        call_count = [0]

        def health_check_side_effect():
            call_count[0] += 1
            # Primera llamada OK, segunda (dentro del flush) falla
            return call_count[0] == 1

        transport = MagicMock()
        transport.transport_type = "ip_http"
        transport.health_check.side_effect = health_check_side_effect
        transport.send_with_retry.return_value = TransportResult(
            success=True, transport_type="ip_http"
        )

        sm, custody = make_sync_manager(tmp_path, transport, store)

        evt = make_event()
        store.enqueue(evt)
        sm._flush_queue()

        # El evento fue enviado y confirmado antes de perder el canal
        assert store.depth() == 0
