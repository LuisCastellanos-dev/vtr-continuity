"""
tests/test_liveness.py — Suite formal para core/liveness.py.

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5), implementa Q-01
(docs/VTR-ARCH-DECISIONS-001.md). Usa NonceCounter REAL (no mocks) para
que la lectura de updated_at se valide contra el comportamiento genuino
de SQLite, no contra un valor inventado — un mock de sqlite3 no habría
expuesto el error real encontrado durante el desarrollo de este módulo
(medir el caso límite contra una variable de tiempo capturada en el
momento equivocado del flujo, en vez de contra el updated_at realmente
persistido).

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from core.crypto_transport import NonceCounter
from core.liveness import (
    DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
    LivenessState,
    LivenessStatus,
    LivenessTracker,
)
from crypto_layer.errors import ConfigError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def node_id() -> bytes:
    return b"\x01\x02\x03\x04\x05\x06\x07\x08"


@pytest.fixture
def other_node_id() -> bytes:
    return b"\x10\x11\x12\x13\x14\x15\x16\x17"


@pytest.fixture
def empty_db_path(tmp_path: Path) -> Path:
    """Ruta de DB que aún no fue inicializada por ningún NonceCounter."""
    return tmp_path / "nonce_counter.db"


@pytest.fixture
def populated_db(tmp_path: Path, node_id: bytes) -> tuple[Path, float]:
    """
    Crea un NonceCounter real, avanza su counter una vez, y retorna la
    ruta de la DB junto con el updated_at REAL persistido — no un
    time.time() capturado por separado, que fue exactamente el error
    cometido al desarrollar este módulo (ver docstring del archivo).
    """
    db_path = tmp_path / "nonce_counter.db"
    nc = NonceCounter(node_id=node_id, db_path=db_path)
    nc.next_nonce()

    tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
    status = tracker.check(node_id)
    return db_path, status.last_updated_at


# ---------------------------------------------------------------------------
# Tests felices — UNKNOWN cuando no hay datos
# ---------------------------------------------------------------------------

class TestUnknownStateHappy:
    def test_nonexistent_db_returns_unknown(self, empty_db_path, node_id):
        tracker = LivenessTracker(db_path=empty_db_path)
        status = tracker.check(node_id)
        assert status.state == LivenessState.UNKNOWN

    def test_unknown_has_zero_counter(self, empty_db_path, node_id):
        tracker = LivenessTracker(db_path=empty_db_path)
        status = tracker.check(node_id)
        assert status.last_counter == 0

    def test_unknown_has_none_updated_at(self, empty_db_path, node_id):
        tracker = LivenessTracker(db_path=empty_db_path)
        status = tracker.check(node_id)
        assert status.last_updated_at is None

    def test_unknown_has_none_seconds_since_update(self, empty_db_path, node_id):
        tracker = LivenessTracker(db_path=empty_db_path)
        status = tracker.check(node_id)
        assert status.seconds_since_update is None

    def test_unseen_node_independent_of_known_node(
        self, populated_db, other_node_id
    ):
        db_path, _ = populated_db
        tracker = LivenessTracker(db_path=db_path)
        status = tracker.check(other_node_id)
        assert status.state == LivenessState.UNKNOWN


# ---------------------------------------------------------------------------
# Tests felices — ALIVE y transición a SUSPECTED_DOWN
# ---------------------------------------------------------------------------

class TestAliveAndSuspectedDownHappy:
    def test_just_after_next_nonce_is_alive(self, populated_db, node_id):
        db_path, _ = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id)
        assert status.state == LivenessState.ALIVE

    def test_alive_reports_correct_counter(self, populated_db, node_id):
        db_path, _ = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id)
        assert status.last_counter == 1

    def test_far_future_is_suspected_down(self, populated_db, node_id):
        db_path, updated_at = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id, now=updated_at + 1000)
        assert status.state == LivenessState.SUSPECTED_DOWN

    def test_far_future_reports_correct_elapsed(self, populated_db, node_id):
        db_path, updated_at = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id, now=updated_at + 1000)
        assert abs(status.seconds_since_update - 1000) < 0.01

    def test_exactly_at_threshold_is_alive(self, populated_db, node_id):
        """elapsed == heartbeat_timeout_seconds usa <=, no <."""
        db_path, updated_at = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id, now=updated_at + 300)
        assert status.state == LivenessState.ALIVE

    def test_just_over_threshold_is_suspected_down(self, populated_db, node_id):
        db_path, updated_at = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id, now=updated_at + 300.001)
        assert status.state == LivenessState.SUSPECTED_DOWN

    def test_just_under_threshold_is_alive(self, populated_db, node_id):
        db_path, updated_at = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id, now=updated_at + 299.999)
        assert status.state == LivenessState.ALIVE

    def test_recovery_after_new_real_traffic(self, populated_db, node_id):
        """Tras SUSPECTED_DOWN, nuevo tráfico real (next_nonce) debe
        devolver el estado a ALIVE — confirma que no hay estado
        'pegado' una vez marcado SUSPECTED_DOWN."""
        db_path, updated_at = populated_db
        nc = NonceCounter(node_id=node_id, db_path=db_path)

        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status_down = tracker.check(node_id, now=updated_at + 1000)
        assert status_down.state == LivenessState.SUSPECTED_DOWN

        nc.next_nonce()  # nuevo tráfico real
        status_recovered = tracker.check(node_id)
        assert status_recovered.state == LivenessState.ALIVE
        assert status_recovered.last_counter == 2


# ---------------------------------------------------------------------------
# Tests felices — check_all
# ---------------------------------------------------------------------------

class TestCheckAllHappy:
    def test_check_all_returns_one_status_per_node(
        self, populated_db, node_id, other_node_id
    ):
        db_path, _ = populated_db
        tracker = LivenessTracker(db_path=db_path)
        results = tracker.check_all([node_id, other_node_id])
        assert len(results) == 2

    def test_check_all_mixed_states(self, populated_db, node_id, other_node_id):
        db_path, _ = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        results = tracker.check_all([node_id, other_node_id])
        states = {r.node_id: r.state for r in results}
        assert states[node_id] == LivenessState.ALIVE
        assert states[other_node_id] == LivenessState.UNKNOWN

    def test_check_all_empty_list_returns_empty(self, empty_db_path):
        tracker = LivenessTracker(db_path=empty_db_path)
        results = tracker.check_all([])
        assert results == []


# ---------------------------------------------------------------------------
# Adversarial
# ---------------------------------------------------------------------------

class TestAdversarial:
    def test_check_node_id_none_raises(self, empty_db_path):
        tracker = LivenessTracker(db_path=empty_db_path)
        with pytest.raises(ConfigError):
            tracker.check(None)

    def test_check_node_id_non_bytes_raises(self, empty_db_path):
        tracker = LivenessTracker(db_path=empty_db_path)
        with pytest.raises(ConfigError):
            tracker.check("not-bytes")

    def test_check_node_id_empty_bytes_raises(self, empty_db_path):
        tracker = LivenessTracker(db_path=empty_db_path)
        with pytest.raises(ConfigError):
            tracker.check(b"")

    def test_constructor_empty_db_path_raises(self):
        with pytest.raises(ConfigError):
            LivenessTracker(db_path="")

    def test_constructor_timeout_zero_raises(self, empty_db_path):
        with pytest.raises(ConfigError):
            LivenessTracker(db_path=empty_db_path, heartbeat_timeout_seconds=0)

    def test_constructor_timeout_negative_raises(self, empty_db_path):
        with pytest.raises(ConfigError):
            LivenessTracker(db_path=empty_db_path, heartbeat_timeout_seconds=-1)

    def test_constructor_timeout_non_int_raises(self, empty_db_path):
        with pytest.raises(ConfigError):
            LivenessTracker(db_path=empty_db_path, heartbeat_timeout_seconds="300")

    def test_constructor_timeout_float_raises(self, empty_db_path):
        """float no es int — el tipo debe ser exacto, no solo numérico,
        para que el umbral sea siempre un número de segundos entero
        consistente con DEFAULT_HEARTBEAT_TIMEOUT_SECONDS."""
        with pytest.raises(ConfigError):
            LivenessTracker(db_path=empty_db_path, heartbeat_timeout_seconds=300.5)

    def test_constructor_timeout_bool_raises(self, empty_db_path):
        """bool es subclase de int en Python — debe rechazarse
        explícitamente, o True se aceptaría silenciosamente como
        heartbeat_timeout_seconds=1 (umbral absurdamente bajo)."""
        with pytest.raises(ConfigError):
            LivenessTracker(db_path=empty_db_path, heartbeat_timeout_seconds=True)

    def test_check_all_none_raises(self, empty_db_path):
        tracker = LivenessTracker(db_path=empty_db_path)
        with pytest.raises(ConfigError):
            tracker.check_all(None)

    def test_check_all_non_list_raises(self, empty_db_path):
        tracker = LivenessTracker(db_path=empty_db_path)
        with pytest.raises(ConfigError):
            tracker.check_all("not-a-list")

    def test_default_timeout_matches_module_constant(self, empty_db_path):
        tracker = LivenessTracker(db_path=empty_db_path)
        status = tracker.check(b"\x01" * 8)
        assert status.heartbeat_timeout_seconds == DEFAULT_HEARTBEAT_TIMEOUT_SECONDS

    def test_status_is_dataclass_instance(self, empty_db_path, node_id):
        tracker = LivenessTracker(db_path=empty_db_path)
        status = tracker.check(node_id)
        assert isinstance(status, LivenessStatus)

    def test_now_defaults_to_current_time_when_omitted(self, populated_db, node_id):
        """Sin pasar now explícito, debe usar time.time() real — el
        elapsed debe ser pequeño (recién actualizado), no None ni
        arbitrario."""
        db_path, _ = populated_db
        tracker = LivenessTracker(db_path=db_path, heartbeat_timeout_seconds=300)
        status = tracker.check(node_id)
        assert status.seconds_since_update is not None
        assert status.seconds_since_update < 5

    def test_db_file_exists_without_table_returns_unknown(self, tmp_path, node_id):
        """Archivo .db existe físicamente (ej. creado por error, o por
        otro propósito) pero nunca tuvo un NonceCounter inicializado —
        no debe fallar, debe tratarse como UNKNOWN igual que un archivo
        que no existe en absoluto."""
        import sqlite3

        db_path = tmp_path / "nonce_counter.db"
        # Crear el archivo .db real, pero con una tabla completamente
        # distinta — simula el escenario real, no solo un archivo vacío.
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE otra_tabla (id INTEGER)")
        conn.commit()
        conn.close()

        tracker = LivenessTracker(db_path=db_path)
        status = tracker.check(node_id)
        assert status.state == LivenessState.UNKNOWN
