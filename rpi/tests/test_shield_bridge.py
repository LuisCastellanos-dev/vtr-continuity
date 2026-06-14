"""
vtr-continuity v0.3.0 — Tests Shield Bridge
rpi/tests/test_shield_bridge.py

Cubre:
  - _verify_integrity: casos normales, null, hash incorrecto, payload grande
  - _safe_parse_payload: JSON válido, inválido, null, no-dict
  - _safe_str / _safe_float / _safe_int: nulls y tipos incorrectos
  - _alert_to_event: conversión, idempotency key, integridad fallida
  - _netprobe_to_event: con y sin sha256
  - _snapshot_to_event: umbral entropía, integridad
  - ShieldBridge.run(): mock de ShieldDB completo
  - Idempotencia: doble ejecución no duplica eventos

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers de test
# ---------------------------------------------------------------------------

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _make_payload(**kwargs) -> tuple[str, str]:
    """Genera (payload_json, sha256) para tests."""
    data = {"test": True, **kwargs}
    payload_str = json.dumps(data, sort_keys=True)
    return payload_str, _sha256(payload_str)


def _make_shield_db(tmp_path: Path) -> sqlite3.Connection:
    """Crea una ShieldDB mínima en memoria para tests."""
    db_path = tmp_path / "shield.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            payload TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS netprobe_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            src_ip TEXT,
            func_code INTEGER,
            payload TEXT,
            sha256 TEXT,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS baseline_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            comm TEXT,
            entropy REAL,
            payload TEXT,
            sha256 TEXT,
            created_at REAL NOT NULL
        );
    """)
    conn.commit()
    return conn, db_path


def _insert_alert(conn, level="WARNING", extra=None, corrupt=False):
    payload_str, sha = _make_payload(level=level, **(extra or {}))
    if corrupt:
        sha = "badhash000000000"
    conn.execute(
        "INSERT INTO alerts (level, payload, sha256, created_at) VALUES (?,?,?,?)",
        (level, payload_str, sha, time.time()),
    )
    conn.commit()


def _insert_netprobe(conn, event_type="DNP3_UNKNOWN_FC", src_ip="192.168.1.100",
                     func_code=99, with_sha=True, corrupt=False):
    payload_str, sha = _make_payload(event_type=event_type)
    if corrupt:
        sha = "badhash000000000"
    conn.execute(
        """INSERT INTO netprobe_events
           (event_type, src_ip, func_code, payload, sha256, created_at)
           VALUES (?,?,?,?,?,?)""",
        (event_type, src_ip, func_code, payload_str, sha if with_sha else None, time.time()),
    )
    conn.commit()


def _insert_snapshot(conn, pid=1234, comm="modbus_server", entropy=0.85, corrupt=False):
    payload_str, sha = _make_payload(pid=pid, comm=comm, entropy=entropy)
    if corrupt:
        sha = "badhash000000000"
    conn.execute(
        """INSERT INTO baseline_snapshots
           (pid, comm, entropy, payload, sha256, created_at)
           VALUES (?,?,?,?,?,?)""",
        (pid, comm, entropy, payload_str, sha, time.time()),
    )
    conn.commit()


# ===========================================================================
# _verify_integrity
# ===========================================================================

class TestVerifyIntegrity:

    def test_valid(self):
        from rpi.shield_bridge import _verify_integrity
        payload, sha = _make_payload(x=1)
        assert _verify_integrity(payload, sha) is True

    def test_wrong_hash(self):
        from rpi.shield_bridge import _verify_integrity
        payload, _ = _make_payload(x=1)
        assert _verify_integrity(payload, "wronghash") is False

    def test_none_payload(self):
        from rpi.shield_bridge import _verify_integrity
        assert _verify_integrity(None, "abc") is False

    def test_none_hash(self):
        from rpi.shield_bridge import _verify_integrity
        assert _verify_integrity('{"x":1}', None) is False

    def test_both_none(self):
        from rpi.shield_bridge import _verify_integrity
        assert _verify_integrity(None, None) is False

    def test_empty_payload(self):
        from rpi.shield_bridge import _verify_integrity
        assert _verify_integrity("", "abc") is False

    def test_empty_hash(self):
        from rpi.shield_bridge import _verify_integrity
        assert _verify_integrity('{"x":1}', "") is False

    def test_payload_too_large(self, tmp_path):
        from rpi.shield_bridge import _verify_integrity
        large = "x" * 9000
        sha = _sha256(large)
        # MAX_PAYLOAD_BYTES default es 8192
        assert _verify_integrity(large, sha) is False

    def test_non_string_payload(self):
        from rpi.shield_bridge import _verify_integrity
        assert _verify_integrity(123, "abc") is False

    def test_non_string_hash(self):
        from rpi.shield_bridge import _verify_integrity
        assert _verify_integrity('{"x":1}', 999) is False


# ===========================================================================
# _safe_parse_payload
# ===========================================================================

class TestSafeParsePayload:

    def test_valid_dict(self):
        from rpi.shield_bridge import _safe_parse_payload
        result = _safe_parse_payload('{"a": 1, "b": "x"}')
        assert result == {"a": 1, "b": "x"}

    def test_none(self):
        from rpi.shield_bridge import _safe_parse_payload
        assert _safe_parse_payload(None) is None

    def test_invalid_json(self):
        from rpi.shield_bridge import _safe_parse_payload
        assert _safe_parse_payload("{invalid}") is None

    def test_json_list_not_dict(self):
        from rpi.shield_bridge import _safe_parse_payload
        assert _safe_parse_payload("[1,2,3]") is None

    def test_json_string_not_dict(self):
        from rpi.shield_bridge import _safe_parse_payload
        assert _safe_parse_payload('"just a string"') is None

    def test_non_string_input(self):
        from rpi.shield_bridge import _safe_parse_payload
        assert _safe_parse_payload(42) is None

    def test_nested_payload(self):
        from rpi.shield_bridge import _safe_parse_payload
        data = {"nested": {"a": 1}, "list": [1, 2, 3], "unicode": "señal"}
        result = _safe_parse_payload(json.dumps(data))
        assert result == data


# ===========================================================================
# Helpers de conversión de tipos
# ===========================================================================

class TestSafeHelpers:

    def test_safe_str_none(self):
        from rpi.shield_bridge import _safe_str
        assert _safe_str(None) == ""

    def test_safe_str_truncates(self):
        from rpi.shield_bridge import _safe_str
        assert len(_safe_str("x" * 300, max_len=10)) == 10

    def test_safe_float_none(self):
        from rpi.shield_bridge import _safe_float
        assert _safe_float(None) == 0.0

    def test_safe_float_invalid(self):
        from rpi.shield_bridge import _safe_float
        assert _safe_float("notanumber") == 0.0

    def test_safe_float_valid(self):
        from rpi.shield_bridge import _safe_float
        assert _safe_float("3.14") == pytest.approx(3.14)

    def test_safe_int_none(self):
        from rpi.shield_bridge import _safe_int
        assert _safe_int(None) == 0

    def test_safe_int_invalid(self):
        from rpi.shield_bridge import _safe_int
        assert _safe_int("abc") == 0

    def test_safe_int_valid(self):
        from rpi.shield_bridge import _safe_int
        assert _safe_int("42") == 42


# ===========================================================================
# Conversores de filas
# ===========================================================================

class TestAlertToEvent:

    def test_valid_alert(self, tmp_path):
        from rpi.shield_bridge import _alert_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_alert(conn, level="CRITICAL")
        row = conn.execute("SELECT * FROM alerts LIMIT 1").fetchone()
        event = _alert_to_event(row)
        assert event is not None
        assert event.event_type == "alert"
        assert event.source == "agent"
        assert event.payload["source_system"] == "tampico_shield"
        assert event.payload["level"] == "CRITICAL"
        assert event.idempotency_key.startswith("shield_alert_")

    def test_corrupted_alert_returns_none(self, tmp_path):
        from rpi.shield_bridge import _alert_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_alert(conn, corrupt=True)
        row = conn.execute("SELECT * FROM alerts LIMIT 1").fetchone()
        assert _alert_to_event(row) is None

    def test_idempotency_key_determinista(self, tmp_path):
        from rpi.shield_bridge import _alert_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_alert(conn)
        row = conn.execute("SELECT * FROM alerts LIMIT 1").fetchone()
        e1 = _alert_to_event(row)
        e2 = _alert_to_event(row)
        assert e1.idempotency_key == e2.idempotency_key


class TestNetprobeToEvent:

    def test_valid_with_sha(self, tmp_path):
        from rpi.shield_bridge import _netprobe_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_netprobe(conn, with_sha=True)
        row = conn.execute("SELECT * FROM netprobe_events LIMIT 1").fetchone()
        event = _netprobe_to_event(row)
        assert event is not None
        assert event.source == "dnp3"
        assert event.payload["table"] == "netprobe_events"

    def test_valid_without_sha(self, tmp_path):
        from rpi.shield_bridge import _netprobe_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_netprobe(conn, with_sha=False)
        row = conn.execute("SELECT * FROM netprobe_events LIMIT 1").fetchone()
        # Sin sha256 se procesa con advertencia, no se descarta
        event = _netprobe_to_event(row)
        assert event is not None

    def test_corrupted_with_sha_returns_none(self, tmp_path):
        from rpi.shield_bridge import _netprobe_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_netprobe(conn, with_sha=True, corrupt=True)
        row = conn.execute("SELECT * FROM netprobe_events LIMIT 1").fetchone()
        assert _netprobe_to_event(row) is None


class TestSnapshotToEvent:

    def test_valid_snapshot(self, tmp_path):
        from rpi.shield_bridge import _snapshot_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_snapshot(conn, entropy=0.9)
        row = conn.execute("SELECT * FROM baseline_snapshots LIMIT 1").fetchone()
        event = _snapshot_to_event(row)
        assert event is not None
        assert event.event_type == "data_sync"
        assert event.payload["entropy"] == pytest.approx(0.9)

    def test_corrupted_snapshot_returns_none(self, tmp_path):
        from rpi.shield_bridge import _snapshot_to_event
        conn, _ = _make_shield_db(tmp_path)
        _insert_snapshot(conn, corrupt=True)
        row = conn.execute("SELECT * FROM baseline_snapshots LIMIT 1").fetchone()
        assert _snapshot_to_event(row) is None


# ===========================================================================
# ShieldBridge.run() — integración completa con mock DB
# ===========================================================================

class TestShieldBridge:

    def test_run_shield_db_not_found(self, tmp_path):
        from rpi.shield_bridge import ShieldBridge
        bridge = ShieldBridge(
            shield_db_path=tmp_path / "noexiste.db",
            vtr_db_path=tmp_path / "queue.db",
        )
        result = bridge.run()
        assert result.error is not None
        assert result.enqueued == 0

    def test_run_enqueues_alerts(self, tmp_path):
        from rpi.shield_bridge import ShieldBridge
        conn, shield_path = _make_shield_db(tmp_path)
        _insert_alert(conn, level="WARNING")
        _insert_alert(conn, level="CRITICAL")
        conn.close()

        bridge = ShieldBridge(
            shield_db_path=shield_path,
            vtr_db_path=tmp_path / "queue.db",
            lookback_seconds=60,
        )
        result = bridge.run()
        assert result.error is None
        assert result.alerts_read == 2
        assert result.enqueued == 2
        assert result.skipped_integrity == 0

    def test_run_skips_corrupted_alerts(self, tmp_path):
        from rpi.shield_bridge import ShieldBridge
        conn, shield_path = _make_shield_db(tmp_path)
        _insert_alert(conn, level="WARNING")
        _insert_alert(conn, level="CRITICAL", corrupt=True)
        conn.close()

        bridge = ShieldBridge(
            shield_db_path=shield_path,
            vtr_db_path=tmp_path / "queue.db",
            lookback_seconds=60,
        )
        result = bridge.run()
        assert result.enqueued == 1
        assert result.skipped_integrity == 1

    def test_run_enqueues_netprobe(self, tmp_path):
        from rpi.shield_bridge import ShieldBridge
        conn, shield_path = _make_shield_db(tmp_path)
        _insert_netprobe(conn)
        _insert_netprobe(conn, func_code=3)
        conn.close()

        bridge = ShieldBridge(
            shield_db_path=shield_path,
            vtr_db_path=tmp_path / "queue.db",
            lookback_seconds=60,
        )
        result = bridge.run()
        assert result.netprobe_read == 2
        assert result.enqueued == 2

    def test_run_enqueues_snapshots_above_threshold(self, tmp_path):
        from rpi.shield_bridge import ShieldBridge
        conn, shield_path = _make_shield_db(tmp_path)
        _insert_snapshot(conn, entropy=0.9)   # sobre umbral 0.7
        _insert_snapshot(conn, entropy=0.3)   # bajo umbral — no debe exportarse
        conn.close()

        bridge = ShieldBridge(
            shield_db_path=shield_path,
            vtr_db_path=tmp_path / "queue.db",
            lookback_seconds=60,
        )
        result = bridge.run()
        assert result.snapshots_read == 1   # solo el de 0.9
        assert result.enqueued == 1

    def test_run_idempotente(self, tmp_path):
        """Doble ejecución no duplica eventos en QueueStore."""
        from rpi.shield_bridge import ShieldBridge
        from rpi.queue_store import QueueStore

        conn, shield_path = _make_shield_db(tmp_path)
        _insert_alert(conn, level="WARNING")
        conn.close()

        vtr_db = tmp_path / "queue.db"
        bridge = ShieldBridge(
            shield_db_path=shield_path,
            vtr_db_path=vtr_db,
            lookback_seconds=60,
        )
        r1 = bridge.run()
        r2 = bridge.run()

        store = QueueStore(db_path=vtr_db)
        assert store.depth() == 1   # no duplicado
        assert r1.enqueued == 1
        assert r2.enqueued == 0    # segundo run: idempotency_key ya existe

    def test_run_mixed_tables(self, tmp_path):
        """Alertas + netprobe + snapshots en un solo ciclo."""
        from rpi.shield_bridge import ShieldBridge
        conn, shield_path = _make_shield_db(tmp_path)
        _insert_alert(conn)
        _insert_netprobe(conn)
        _insert_snapshot(conn, entropy=0.85)
        conn.close()

        bridge = ShieldBridge(
            shield_db_path=shield_path,
            vtr_db_path=tmp_path / "queue.db",
            lookback_seconds=60,
        )
        result = bridge.run()
        assert result.enqueued == 3
        assert result.error is None

    def test_run_fuera_de_ventana_lookback(self, tmp_path):
        """Eventos más antiguos que lookback_seconds no se procesan."""
        from rpi.shield_bridge import ShieldBridge
        conn, shield_path = _make_shield_db(tmp_path)

        # Insertar alerta con timestamp de hace 10 minutos
        payload_str, sha = _make_payload(old=True)
        conn.execute(
            "INSERT INTO alerts (level, payload, sha256, created_at) VALUES (?,?,?,?)",
            ("WARNING", payload_str, sha, time.time() - 600),
        )
        conn.commit()
        conn.close()

        bridge = ShieldBridge(
            shield_db_path=shield_path,
            vtr_db_path=tmp_path / "queue.db",
            lookback_seconds=60,   # solo últimos 60 segundos
        )
        result = bridge.run()
        assert result.alerts_read == 0
        assert result.enqueued == 0
