"""
vtr-continuity v0.4.0 — Tests Core
core/tests/test_custody_manager.py

Cubre:
  - grant: básico, idempotente, validaciones
  - ack: básico, verify_hash, bundle inexistente, doble ack
  - transfer: multi-hop, validaciones
  - mark_failed / increment_retry
  - pending / timed_out / is_safe_to_delete
  - purge_acked
  - stats
  - compute_hash
  - MAX_LORA_FRAME_BYTES — test de límite físico LoRa

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path

import pytest

from core.custody_manager import (
    CustodyManager,
    CustodyStatus,
    MAX_LORA_FRAME_BYTES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cm(tmp_path: Path) -> CustodyManager:
    return CustodyManager(
        db_path=tmp_path / "custody.db",
        default_timeout_seconds=60.0,
        max_retries=3,
    )


def new_id() -> str:
    return str(uuid.uuid4())


def sha(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


# ===========================================================================
# Inicialización
# ===========================================================================

class TestInit:

    def test_empty_db_path_raises(self):
        with pytest.raises(ValueError):
            CustodyManager(db_path="")

    def test_invalid_timeout_raises(self, tmp_path):
        with pytest.raises(ValueError):
            CustodyManager(db_path=tmp_path / "c.db", default_timeout_seconds=0)

    def test_negative_timeout_raises(self, tmp_path):
        with pytest.raises(ValueError):
            CustodyManager(db_path=tmp_path / "c.db", default_timeout_seconds=-1)

    def test_negative_retries_raises(self, tmp_path):
        with pytest.raises(ValueError):
            CustodyManager(db_path=tmp_path / "c.db", max_retries=-1)

    def test_creates_db_file(self, tmp_path):
        db = tmp_path / "sub" / "custody.db"
        CustodyManager(db_path=db)
        assert db.exists()


# ===========================================================================
# grant()
# ===========================================================================

class TestGrant:

    def test_grant_basic(self, cm):
        bid = new_id()
        result = cm.grant(bid, sha("payload"))
        assert result is True

    def test_grant_idempotente(self, cm):
        bid = new_id()
        h = sha("payload")
        r1 = cm.grant(bid, h)
        r2 = cm.grant(bid, h)
        assert r1 is True
        assert r2 is False

    def test_grant_empty_bundle_id_raises(self, cm):
        with pytest.raises(ValueError):
            cm.grant("", sha("x"))

    def test_grant_empty_hash_raises(self, cm):
        with pytest.raises(ValueError):
            cm.grant(new_id(), "")

    def test_grant_none_hash_raises(self, cm):
        with pytest.raises(ValueError):
            cm.grant(new_id(), None)

    def test_grant_invalid_timeout_raises(self, cm):
        with pytest.raises(ValueError):
            cm.grant(new_id(), sha("x"), timeout_seconds=0)

    def test_grant_custom_timeout(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"), timeout_seconds=120.0)
        bundle = cm.get(bid)
        assert bundle.timeout_seconds == 120.0

    def test_grant_status_pending(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        bundle = cm.get(bid)
        assert bundle.status == CustodyStatus.PENDING


# ===========================================================================
# ack()
# ===========================================================================

class TestAck:

    def test_ack_basic(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        result = cm.ack(bid)
        assert result is True
        assert cm.get(bid).status == CustodyStatus.ACKED

    def test_ack_sets_acked_at(self, cm):
        bid = new_id()
        before = time.time()
        cm.grant(bid, sha("x"))
        cm.ack(bid)
        after = time.time()
        bundle = cm.get(bid)
        assert bundle.acked_at is not None
        assert before <= bundle.acked_at <= after

    def test_ack_with_valid_hash(self, cm):
        bid = new_id()
        h = sha("payload_real")
        cm.grant(bid, h)
        result = cm.ack(bid, verify_hash=h)
        assert result is True

    def test_ack_with_wrong_hash_rejected(self, cm):
        bid = new_id()
        cm.grant(bid, sha("payload_real"))
        result = cm.ack(bid, verify_hash=sha("payload_falso"))
        assert result is False
        assert cm.get(bid).status == CustodyStatus.PENDING

    def test_ack_nonexistent_returns_false(self, cm):
        assert cm.ack("no-existe") is False

    def test_ack_empty_bundle_id_returns_false(self, cm):
        assert cm.ack("") is False

    def test_double_ack_returns_false(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.ack(bid)
        result = cm.ack(bid)
        assert result is False

    def test_ack_nonexistent_with_hash_returns_false(self, cm):
        assert cm.ack("no-existe", verify_hash=sha("x")) is False


# ===========================================================================
# transfer()
# ===========================================================================

class TestTransfer:

    def test_transfer_basic(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        result = cm.transfer(bid, next_hop="rpi-node-02")
        assert result is True
        bundle = cm.get(bid)
        assert bundle.status == CustodyStatus.TRANSFER
        assert bundle.next_hop == "rpi-node-02"

    def test_transfer_empty_bundle_id_raises(self, cm):
        with pytest.raises(ValueError):
            cm.transfer("", "node-02")

    def test_transfer_empty_next_hop_raises(self, cm):
        with pytest.raises(ValueError):
            cm.transfer(new_id(), "")

    def test_transfer_already_acked_returns_false(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.ack(bid)
        result = cm.transfer(bid, "node-02")
        assert result is False


# ===========================================================================
# mark_failed / increment_retry
# ===========================================================================

class TestRetryAndFail:

    def test_mark_failed(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.mark_failed(bid)
        assert cm.get(bid).status == CustodyStatus.FAILED

    def test_mark_failed_empty_id(self, cm):
        assert cm.mark_failed("") is False

    def test_increment_retry(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        r1 = cm.increment_retry(bid)
        r2 = cm.increment_retry(bid)
        assert r1 == 1
        assert r2 == 2

    def test_increment_retry_sets_last_retry_at(self, cm):
        bid = new_id()
        before = time.time()
        cm.grant(bid, sha("x"))
        cm.increment_retry(bid)
        after = time.time()
        bundle = cm.get(bid)
        assert bundle.last_retry_at is not None
        assert before <= bundle.last_retry_at <= after

    def test_increment_retry_nonexistent(self, cm):
        assert cm.increment_retry("no-existe") == -1

    def test_increment_retry_empty_id(self, cm):
        assert cm.increment_retry("") == -1


# ===========================================================================
# pending() / timed_out() / is_safe_to_delete()
# ===========================================================================

class TestQueries:

    def test_pending_empty(self, cm):
        assert cm.pending() == []

    def test_pending_returns_pending_only(self, cm):
        b1 = new_id()
        b2 = new_id()
        b3 = new_id()
        cm.grant(b1, sha("x"))
        cm.grant(b2, sha("y"))
        cm.grant(b3, sha("z"))
        cm.ack(b3)
        pending = [b.bundle_id for b in cm.pending()]
        assert b1 in pending
        assert b2 in pending
        assert b3 not in pending

    def test_timed_out_empty_when_no_timeout(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"), timeout_seconds=3600)
        assert cm.timed_out() == []

    def test_timed_out_detects_expired(self, tmp_path):
        cm_fast = CustodyManager(
            db_path=tmp_path / "c2.db",
            default_timeout_seconds=0.01,
        )
        bid = new_id()
        cm_fast.grant(bid, sha("x"))
        time.sleep(0.05)
        expired = cm_fast.timed_out()
        assert any(b.bundle_id == bid for b in expired)

    def test_is_safe_to_delete_pending(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        assert cm.is_safe_to_delete(bid) is False

    def test_is_safe_to_delete_acked(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.ack(bid)
        assert cm.is_safe_to_delete(bid) is True

    def test_is_safe_to_delete_transfer(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.transfer(bid, "node-02")
        assert cm.is_safe_to_delete(bid) is True

    def test_is_safe_to_delete_failed(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.mark_failed(bid)
        assert cm.is_safe_to_delete(bid) is False

    def test_is_safe_to_delete_nonexistent(self, cm):
        assert cm.is_safe_to_delete("no-existe") is False

    def test_is_safe_to_delete_empty_id(self, cm):
        assert cm.is_safe_to_delete("") is False

    def test_get_nonexistent_returns_none(self, cm):
        assert cm.get("no-existe") is None

    def test_get_empty_id_returns_none(self, cm):
        assert cm.get("") is None


# ===========================================================================
# purge_acked()
# ===========================================================================

class TestPurge:

    def test_purge_removes_old_acked(self, tmp_path):
        cm = CustodyManager(db_path=tmp_path / "c.db", default_timeout_seconds=60)
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.ack(bid)
        time.sleep(0.05)
        deleted = cm.purge_acked(older_than_seconds=0.01)
        assert deleted == 1
        assert cm.get(bid) is None

    def test_purge_keeps_recent_acked(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.ack(bid)
        deleted = cm.purge_acked(older_than_seconds=3600)
        assert deleted == 0
        assert cm.get(bid) is not None

    def test_purge_does_not_touch_pending(self, cm):
        bid = new_id()
        cm.grant(bid, sha("x"))
        cm.purge_acked(older_than_seconds=0.0001)
        assert cm.get(bid) is not None

    def test_purge_invalid_param_raises(self, cm):
        with pytest.raises(ValueError):
            cm.purge_acked(older_than_seconds=0)


# ===========================================================================
# stats()
# ===========================================================================

class TestStats:

    def test_stats_empty(self, cm):
        s = cm.stats()
        assert s["by_status"] == {}
        assert s["timed_out"] == 0
        assert s["max_lora_frame_bytes"] == MAX_LORA_FRAME_BYTES

    def test_stats_counts(self, cm):
        b1, b2, b3 = new_id(), new_id(), new_id()
        cm.grant(b1, sha("x"))
        cm.grant(b2, sha("y"))
        cm.grant(b3, sha("z"))
        cm.ack(b3)
        s = cm.stats()
        assert s["by_status"]["PENDING"] == 2
        assert s["by_status"]["ACKED"] == 1


# ===========================================================================
# compute_hash()
# ===========================================================================

class TestComputeHash:

    def test_string_input(self):
        h = CustodyManager.compute_hash("hola")
        assert h == hashlib.sha256(b"hola").hexdigest()

    def test_bytes_input(self):
        h = CustodyManager.compute_hash(b"hola")
        assert h == hashlib.sha256(b"hola").hexdigest()

    def test_none_raises(self):
        with pytest.raises(ValueError):
            CustodyManager.compute_hash(None)

    def test_determinista(self):
        assert CustodyManager.compute_hash("x") == CustodyManager.compute_hash("x")

    def test_diferente_para_diferente_payload(self):
        assert CustodyManager.compute_hash("a") != CustodyManager.compute_hash("b")


# ===========================================================================
# MAX_LORA_FRAME_BYTES — límite físico SX1262
# ===========================================================================

class TestLoRaFrameLimit:

    def test_constante_valor(self):
        """SX1262 SF7/BW125kHz CR4/5 — límite físico documentado."""
        assert MAX_LORA_FRAME_BYTES == 222

    def test_payload_dentro_del_limite(self):
        """Un evento OT mínimo debe caber en un frame LoRa."""
        evento = {
            "idempotency_key": str(uuid.uuid4()),
            "event_type": "alert",
            "source": "dnp3",
            "data": {"level": "WARNING", "src_ip": "192.168.1.100"},
        }
        serializado = json.dumps(evento, separators=(",", ":")).encode()
        assert len(serializado) <= MAX_LORA_FRAME_BYTES, (
            f"Evento OT mínimo excede límite LoRa: "
            f"{len(serializado)} > {MAX_LORA_FRAME_BYTES} bytes"
        )

    def test_payload_grande_supera_limite(self):
        """Confirma que el test detecta payloads que requieren fragmentación."""
        payload_grande = {"data": "x" * 300}
        serializado = json.dumps(payload_grande).encode()
        assert len(serializado) > MAX_LORA_FRAME_BYTES
