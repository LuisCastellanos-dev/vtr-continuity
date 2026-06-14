"""
vtr-continuity v0.2.0 — Tests RPi OT Tier
tests/test_rpi.py

Cubre:
  - QueueStore: enqueue, peek, ack, ack_batch, mark_attempt, depth, stats
  - IPTransport: health_check, send (mock httpx)
  - SyncManager: flush FIFO, backoff, estado
  - Agent: parse_line, ProxyClient fallback
  - AbstractTransport: interfaz, send_with_retry

pytest tests/test_rpi.py -v

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import json
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path: Path):
    """Base de datos SQLite temporal para cada test."""
    return tmp_path / "test_queue.db"


@pytest.fixture
def store(tmp_db: Path):
    from rpi.queue_store import QueueStore
    return QueueStore(db_path=tmp_db)


def make_event(**kwargs):
    from rpi.queue_store import QueuedEvent
    defaults = dict(
        idempotency_key=str(uuid.uuid4()),
        event_type="agent_event",
        payload={"k": "v"},
        queued_at=time.time(),
        source="agent",
    )
    defaults.update(kwargs)
    return QueuedEvent(**defaults)


# ===========================================================================
# QueueStore
# ===========================================================================

class TestQueueStore:

    def test_enqueue_basic(self, store):
        evt = make_event()
        row_id = store.enqueue(evt)
        assert row_id > 0
        assert store.depth() == 1

    def test_enqueue_idempotent(self, store):
        key = str(uuid.uuid4())
        evt = make_event(idempotency_key=key)
        r1 = store.enqueue(evt)
        r2 = store.enqueue(evt)
        assert r1 > 0
        assert r2 == -1
        assert store.depth() == 1

    def test_enqueue_empty_key_raises(self, store):
        with pytest.raises(ValueError):
            store.enqueue(make_event(idempotency_key=""))

    def test_enqueue_none_payload_raises(self, store):
        with pytest.raises(ValueError):
            store.enqueue(make_event(payload=None))

    def test_enqueue_non_serializable_payload_raises(self, store):
        with pytest.raises(ValueError):
            store.enqueue(make_event(payload={"fn": lambda x: x}))

    def test_peek_fifo_order(self, store):
        keys = []
        for i in range(5):
            k = str(uuid.uuid4())
            keys.append(k)
            store.enqueue(make_event(idempotency_key=k, queued_at=time.time() + i))
        events = store.peek(limit=10)
        assert [e.idempotency_key for e in events] == keys

    def test_peek_limit(self, store):
        for _ in range(10):
            store.enqueue(make_event())
        events = store.peek(limit=3)
        assert len(events) == 3

    def test_peek_limit_zero_raises(self, store):
        with pytest.raises(ValueError):
            store.peek(limit=0)

    def test_ack_removes_event(self, store):
        evt = make_event()
        store.enqueue(evt)
        assert store.depth() == 1
        result = store.ack(evt.idempotency_key)
        assert result is True
        assert store.depth() == 0

    def test_ack_nonexistent_returns_false(self, store):
        result = store.ack("no-existe")
        assert result is False

    def test_ack_empty_key_returns_false(self, store):
        result = store.ack("")
        assert result is False

    def test_ack_batch(self, store):
        keys = []
        for _ in range(5):
            k = str(uuid.uuid4())
            keys.append(k)
            store.enqueue(make_event(idempotency_key=k))
        deleted = store.ack_batch(keys[:3])
        assert deleted == 3
        assert store.depth() == 2

    def test_ack_batch_empty_list(self, store):
        assert store.ack_batch([]) == 0

    def test_mark_attempt(self, store):
        evt = make_event()
        store.enqueue(evt)
        store.mark_attempt(evt.idempotency_key)
        store.mark_attempt(evt.idempotency_key)
        # Buscar por idempotency_key, no asumir posición en peek
        events = store.peek(limit=100)
        target = next(e for e in events if e.idempotency_key == evt.idempotency_key)
        assert target.attempts == 2
        assert target.last_attempt_at is not None

    def test_clear(self, store):
        for _ in range(5):
            store.enqueue(make_event())
        deleted = store.clear()
        assert deleted == 5
        assert store.depth() == 0

    def test_stats_empty(self, store):
        s = store.stats()
        assert s["queue_depth"] == 0
        assert s["oldest_event_age_s"] is None
        assert s["max_attempts"] == 0

    def test_stats_with_events(self, store):
        store.enqueue(make_event())
        s = store.stats()
        assert s["queue_depth"] == 1
        assert s["oldest_event_age_s"] is not None

    def test_log_sync_and_last_sync(self, store):
        store.log_sync(events_sent=10, events_failed=1, transport_type="ip_http", duration_ms=250.0)
        last = store.last_sync()
        assert last is not None
        assert last["events_sent"] == 10
        assert last["events_failed"] == 1
        assert last["transport_type"] == "ip_http"

    def test_payload_roundtrip(self, store):
        payload = {"nested": {"a": 1, "b": [1, 2, 3]}, "unicode": "señal"}
        evt = make_event(payload=payload)
        store.enqueue(evt)
        events = store.peek()
        assert events[0].payload == payload


# ===========================================================================
# Transport
# ===========================================================================

class TestTransportConfig:

    def test_defaults(self):
        from rpi.transport import TransportConfig
        cfg = TransportConfig()
        assert cfg.max_retries == 3
        assert cfg.timeout_seconds == 10.0

    def test_lora_stub_raises(self):
        from rpi.transport import LoRaTransport
        t = LoRaTransport()
        with pytest.raises(NotImplementedError):
            t.health_check()
        with pytest.raises(NotImplementedError):
            t.send({})

    def test_lora_transport_type(self):
        from rpi.transport import LoRaTransport
        assert LoRaTransport().transport_type == "lora_915mhz"


class TestIPTransport:

    def test_empty_server_url_raises(self):
        from rpi.transport import IPTransport
        with pytest.raises(ValueError):
            IPTransport(server_url="", api_key="key")

    def test_empty_api_key_raises(self):
        from rpi.transport import IPTransport
        with pytest.raises(ValueError):
            IPTransport(server_url="http://localhost", api_key="")

    def test_transport_type(self):
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        assert t.transport_type == "ip_http"

    def test_send_success(self):
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            result = t.send({"idempotency_key": "abc", "data": {}})
        assert result.success is True
        assert result.status_code == 202

    def test_send_none_payload(self):
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        result = t.send(None)
        assert result.success is False
        assert "None" in result.error

    def test_send_http_error(self):
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            result = t.send({"idempotency_key": "x"})
        assert result.success is False
        assert "500" in result.error

    def test_send_timeout(self):
        import httpx
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.post.side_effect = httpx.TimeoutException("timeout")
            result = t.send({"idempotency_key": "x"})
        assert result.success is False
        assert "timeout" in result.error

    def test_health_check_ok(self):
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            assert t.health_check() is True

    def test_health_check_fail(self):
        import httpx
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = httpx.RequestError("fail")
            assert t.health_check() is False

    def test_send_with_retry_success_first(self):
        from rpi.transport import IPTransport, TransportResult
        t = IPTransport(server_url="http://localhost", api_key="k")
        t.send = MagicMock(return_value=TransportResult(success=True, transport_type="ip_http"))
        result = t.send_with_retry({"idempotency_key": "x"})
        assert result.success is True
        assert t.send.call_count == 1

    def test_send_with_retry_exhausted(self):
        from rpi.transport import IPTransport, TransportResult, TransportConfig
        cfg = TransportConfig(max_retries=2, retry_backoff_base=0.01)
        t = IPTransport(server_url="http://localhost", api_key="k", config=cfg)
        t.send = MagicMock(return_value=TransportResult(success=False, error="fail", transport_type="ip_http"))
        result = t.send_with_retry({"idempotency_key": "x"})
        assert result.success is False
        assert t.send.call_count == 3   # 1 intento + 2 reintentos


# ===========================================================================
# SyncManager
# ===========================================================================

class TestSyncManager:

    def test_init_none_transport_raises(self, store):
        from rpi.sync_manager import SyncManager
        with pytest.raises(ValueError):
            SyncManager(transport=None, store=store)

    def test_init_none_store_raises(self):
        from rpi.sync_manager import SyncManager
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        with pytest.raises(ValueError):
            SyncManager(transport=t, store=None)

    def test_initial_state(self, store):
        from rpi.sync_manager import SyncManager
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        sm = SyncManager(transport=t, store=store)
        assert sm.state.status == "INITIALIZING"
        assert sm.is_online() is False

    def test_flush_sends_events(self, store):
        from rpi.sync_manager import SyncManager
        from rpi.transport import IPTransport, TransportResult
        t = IPTransport(server_url="http://localhost", api_key="k")
        t.send = MagicMock(return_value=TransportResult(success=True, transport_type="ip_http"))
        t.health_check = MagicMock(return_value=True)
        sm = SyncManager(transport=t, store=store)

        # Encolar 3 eventos
        for _ in range(3):
            store.enqueue(make_event())

        sm._flush_queue()
        assert store.depth() == 0
        assert sm.state.total_sent == 3

    def test_flush_marks_failed_events(self, store):
        from rpi.sync_manager import SyncManager
        from rpi.transport import IPTransport, TransportResult
        t = IPTransport(server_url="http://localhost", api_key="k")
        t.send = MagicMock(return_value=TransportResult(success=False, error="fail", transport_type="ip_http"))
        t.health_check = MagicMock(return_value=True)
        sm = SyncManager(transport=t, store=store)

        store.enqueue(make_event())
        sm._flush_queue()

        # El evento sigue en cola con attempt incrementado
        assert store.depth() == 1
        events = store.peek()
        # send_with_retry agota TransportConfig.max_retries (3) + 1 mark_attempt
        assert events[0].attempts >= 1

    def test_enqueue_via_sync_manager(self, store):
        from rpi.sync_manager import SyncManager
        from rpi.transport import IPTransport
        t = IPTransport(server_url="http://localhost", api_key="k")
        sm = SyncManager(transport=t, store=store)
        evt = make_event()
        row_id = sm.enqueue(evt)
        assert row_id > 0
        assert store.depth() == 1


# ===========================================================================
# Agent — parse_line
# ===========================================================================

class TestAgentParseLine:

    def test_parse_valid(self):
        from rpi.agent import parse_line
        line = json.dumps({"event_type": "agent_event", "data": {"x": 1}})
        result = parse_line(line)
        assert result is not None
        assert result["event_type"] == "agent_event"
        assert result["data"] == {"x": 1}
        assert result["idempotency_key"]   # generado si faltaba
        assert result["source"] == "agent"

    def test_parse_with_idempotency_key(self):
        from rpi.agent import parse_line
        key = str(uuid.uuid4())
        line = json.dumps({"event_type": "alert", "idempotency_key": key, "data": {}})
        result = parse_line(line)
        assert result["idempotency_key"] == key

    def test_parse_empty_line(self):
        from rpi.agent import parse_line
        assert parse_line("") is None
        assert parse_line("   ") is None

    def test_parse_comment_line(self):
        from rpi.agent import parse_line
        assert parse_line("# esto es un comentario") is None

    def test_parse_invalid_json(self):
        from rpi.agent import parse_line
        assert parse_line("{invalid json}") is None

    def test_parse_missing_event_type(self):
        from rpi.agent import parse_line
        assert parse_line(json.dumps({"data": {}})) is None

    def test_parse_invalid_event_type(self):
        from rpi.agent import parse_line
        assert parse_line(json.dumps({"event_type": "invalid_type"})) is None

    def test_parse_invalid_source_defaults_to_agent(self):
        from rpi.agent import parse_line
        line = json.dumps({"event_type": "agent_event", "source": "unknown_source"})
        result = parse_line(line)
        assert result["source"] == "agent"

    def test_parse_non_dict_data_defaults_empty(self):
        from rpi.agent import parse_line
        line = json.dumps({"event_type": "agent_event", "data": "no es dict"})
        result = parse_line(line)
        assert result["data"] == {}

    def test_parse_all_valid_event_types(self):
        from rpi.agent import parse_line, VALID_EVENT_TYPES
        for etype in VALID_EVENT_TYPES:
            result = parse_line(json.dumps({"event_type": etype}))
            assert result is not None, f"event_type '{etype}' debería ser válido"

    def test_parse_timestamp_preserved(self):
        from rpi.agent import parse_line
        ts = 1700000000.0
        line = json.dumps({"event_type": "heartbeat", "timestamp": ts})
        result = parse_line(line)
        assert result["timestamp"] == ts

    def test_parse_missing_timestamp_filled(self):
        from rpi.agent import parse_line
        before = time.time()
        result = parse_line(json.dumps({"event_type": "heartbeat"}))
        after = time.time()
        assert before <= result["timestamp"] <= after
