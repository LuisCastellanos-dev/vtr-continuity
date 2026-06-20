"""
tests/test_vtrc_bundle.py — Suite formal para crypto_layer/vtrc_bundle.py.

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5) — mismo patrón
que tests/test_crypto_layer.py (propuesta #9): tests felices + clase
adversarial dedicada. No es parte de las 10 propuestas originales — es
la pieza de validación correspondiente al módulo de formato de bundle
que la propuesta #7 dejó explícitamente fuera de alcance.

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from crypto_layer.ed25519_sign import generate_keypair
from crypto_layer.errors import BundleIntegrityError, InvalidKeyLengthError
from crypto_layer.vtrc_bundle import (
    HEADER_SIZE,
    MAGIC,
    MAX_BUNDLE_SIZE_BYTES,
    CounterVerificationStore,
    VtrcBundle,
    build_bundle,
    parse_bundle,
    verify_bundle,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def node_id() -> bytes:
    return b"\x01\x02\x03\x04\x05\x06\x07\x08"


@pytest.fixture
def counter_store(tmp_path: Path) -> CounterVerificationStore:
    db_path = tmp_path / "counter_seen.db"
    return CounterVerificationStore(db_path=db_path)


# ---------------------------------------------------------------------------
# Tests felices — round-trip build/parse/verify
# ---------------------------------------------------------------------------

class TestBuildParseVerifyHappy:
    def test_build_bundle_returns_bytes(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"payload-real", priv)
        assert isinstance(raw, bytes)
        assert len(raw) > HEADER_SIZE

    def test_build_bundle_starts_with_magic(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"payload-real", priv)
        assert raw[:4] == MAGIC

    def test_round_trip_node_id_preserved(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 7, b"data", priv)
        parsed = parse_bundle(raw)
        assert parsed.node_id == node_id

    def test_round_trip_counter_preserved(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 999, b"data", priv)
        parsed = parse_bundle(raw)
        assert parsed.counter == 999

    def test_round_trip_payload_preserved_exactly(self, keypair, node_id):
        priv, _pub = keypair
        payload = b"\x00\x01\xff\xfe-payload-binario-exacto"
        raw = build_bundle(node_id, 1, payload, priv)
        parsed = parse_bundle(raw)
        assert parsed.payload == payload

    def test_round_trip_metadata_preserved(self, keypair, node_id):
        priv, _pub = keypair
        metadata = {"purpose": "telemetry", "origin_hint": "bench-tampico"}
        raw = build_bundle(node_id, 1, b"data", priv, metadata=metadata)
        parsed = parse_bundle(raw)
        assert parsed.metadata == metadata

    def test_metadata_defaults_to_empty_dict(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"data", priv)
        parsed = parse_bundle(raw)
        assert parsed.metadata == {}

    def test_verify_bundle_accepts_valid_signature(self, keypair, node_id):
        priv, pub = keypair
        raw = build_bundle(node_id, 1, b"data", priv)
        assert verify_bundle(raw, pub) is True

    def test_verify_bundle_rejects_wrong_public_key(self, keypair, node_id):
        priv, _pub = keypair
        _other_priv, other_pub = generate_keypair()
        raw = build_bundle(node_id, 1, b"data", priv)
        assert verify_bundle(raw, other_pub) is False

    def test_verify_bundle_rejects_tampered_payload(self, keypair, node_id):
        priv, pub = keypair
        raw = bytearray(build_bundle(node_id, 1, b"data-original", priv))
        raw[HEADER_SIZE] ^= 0xFF  # corromper primer byte del payload
        assert verify_bundle(bytes(raw), pub) is False

    def test_verify_bundle_rejects_tampered_metadata(self, keypair, node_id):
        priv, pub = keypair
        raw = bytearray(
            build_bundle(node_id, 1, b"data", priv, metadata={"a": "b"})
        )
        raw[-1] ^= 0xFF  # corromper último byte (dentro de metadata)
        assert verify_bundle(bytes(raw), pub) is False

    def test_parse_bundle_returns_vtrc_bundle_instance(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"data", priv)
        parsed = parse_bundle(raw)
        assert isinstance(parsed, VtrcBundle)

    def test_signature_field_has_correct_length(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"data", priv)
        parsed = parse_bundle(raw)
        assert len(parsed.signature) == 64  # RFC 8032


# ---------------------------------------------------------------------------
# Tests felices — CounterVerificationStore (Q-02)
# ---------------------------------------------------------------------------

class TestCounterVerificationStoreHappy:
    def test_first_contact_accepted(self, counter_store, node_id):
        assert counter_store.check_and_record(node_id, 5) is True

    def test_first_contact_recorded(self, counter_store, node_id):
        counter_store.check_and_record(node_id, 5)
        assert counter_store.max_counter_seen(node_id) == 5

    def test_higher_counter_accepted(self, counter_store, node_id):
        counter_store.check_and_record(node_id, 5)
        assert counter_store.check_and_record(node_id, 6) is True

    def test_unrelated_node_independent(self, counter_store, node_id):
        other_node = b"\x10\x11\x12\x13\x14\x15\x16\x17"
        counter_store.check_and_record(node_id, 100)
        assert counter_store.max_counter_seen(other_node) == 0

    def test_persists_across_new_instance(self, tmp_path, node_id):
        db_path = tmp_path / "persist.db"
        store1 = CounterVerificationStore(db_path=db_path)
        store1.check_and_record(node_id, 42)
        del store1

        store2 = CounterVerificationStore(db_path=db_path)
        assert store2.max_counter_seen(node_id) == 42


# ---------------------------------------------------------------------------
# Adversarial — ≥15 casos, mismo estándar que test_crypto_layer.py
# ---------------------------------------------------------------------------

class TestAdversarial:
    # --- build_bundle ---

    def test_node_id_none_raises(self, keypair):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(None, 1, b"x", priv)

    def test_node_id_wrong_length_raises(self, keypair):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(b"short", 1, b"x", priv)

    def test_node_id_non_bytes_raises(self, keypair):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle("not-bytes-8ch", 1, b"x", priv)

    def test_counter_zero_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 0, b"x", priv)

    def test_counter_negative_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, -1, b"x", priv)

    def test_counter_bool_raises(self, keypair, node_id):
        """bool es subclase de int en Python — debe rechazarse explícitamente."""
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, True, b"x", priv)

    def test_counter_none_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, None, b"x", priv)

    def test_payload_none_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, None, priv)

    def test_payload_empty_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, b"", priv)

    def test_payload_non_bytes_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, "not-bytes", priv)

    def test_private_key_none_raises(self, node_id):
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, b"x", None)

    def test_metadata_non_dict_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, b"x", priv, metadata="not-a-dict")

    def test_metadata_non_serializable_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, b"x", priv, metadata={"bad": object()})

    def test_oversized_bundle_raises(self, keypair, node_id):
        priv, _pub = keypair
        huge_payload = b"x" * (MAX_BUNDLE_SIZE_BYTES + 1)
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, huge_payload, priv)

    # --- parse_bundle ---

    def test_parse_none_raises(self):
        with pytest.raises(InvalidKeyLengthError):
            parse_bundle(None)

    def test_parse_truncated_raises_bundle_integrity_error(self):
        with pytest.raises(BundleIntegrityError):
            parse_bundle(b"short")

    def test_parse_wrong_magic_raises_bundle_integrity_error(self):
        fake_header = b"XXXX" + b"\x00" * (HEADER_SIZE - 4)
        with pytest.raises(BundleIntegrityError):
            parse_bundle(fake_header)

    def test_parse_length_mismatch_raises_bundle_integrity_error(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"data-real-aqui", priv)
        truncated = raw[:-3]  # header dice una longitud, bytes reales no calzan
        with pytest.raises(BundleIntegrityError):
            parse_bundle(truncated)

    def test_parse_oversized_raw_raises_bundle_integrity_error(self):
        oversized = b"\x00" * (MAX_BUNDLE_SIZE_BYTES + 1)
        with pytest.raises(BundleIntegrityError):
            parse_bundle(oversized)

    # --- verify_bundle ---

    def test_verify_public_key_none_raises(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"data", priv)
        with pytest.raises(InvalidKeyLengthError):
            verify_bundle(raw, None)

    def test_verify_public_key_wrong_length_raises(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"data", priv)
        with pytest.raises(InvalidKeyLengthError):
            verify_bundle(raw, b"too-short")

    def test_verify_corrupt_raw_returns_false_not_raises(self, keypair):
        _priv, pub = keypair
        # raw corrupto: debe devolver False, no lanzar excepción
        # (mismo contrato que ed25519_sign.verify — falla esperada != excepción)
        result = verify_bundle(b"esto-no-es-un-bundle-valido-en-absoluto", pub)
        assert result is False

    # --- CounterVerificationStore ---

    def test_counter_store_replay_exact_rejected(self, counter_store, node_id):
        counter_store.check_and_record(node_id, 10)
        assert counter_store.check_and_record(node_id, 10) is False

    def test_counter_store_lower_counter_rejected(self, counter_store, node_id):
        counter_store.check_and_record(node_id, 10)
        assert counter_store.check_and_record(node_id, 5) is False

    def test_counter_store_empty_node_id_returns_false(self, counter_store):
        assert counter_store.check_and_record(b"", 1) is False

    def test_counter_store_none_node_id_returns_false(self, counter_store):
        assert counter_store.check_and_record(None, 1) is False

    def test_counter_store_non_int_counter_returns_false(self, counter_store, node_id):
        assert counter_store.check_and_record(node_id, "not-an-int") is False

    def test_counter_store_zero_counter_returns_false(self, counter_store, node_id):
        assert counter_store.check_and_record(node_id, 0) is False

    # --- Ramas adicionales detectadas por coverage real (90% -> mejorar) ---
    # Mismo criterio que tests/test_crypto_layer.py (propuesta #9): solo se
    # agregan casos que ejercitan validación real ya existente en el código,
    # nunca relleno artificial para subir el número sin sentido.

    def test_counter_exceeds_8_byte_range_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 2**64, b"x", priv)

    def test_payload_exceeds_4_byte_range_raises(self, keypair, node_id):
        """No se construye un payload real de 4GB — se prueba el validador
        directamente, ya que generar ese payload en memoria solo para el
        test sería un costo de recursos desproporcionado al valor del
        check (la rama es trivial: comparación de longitud)."""
        from crypto_layer.vtrc_bundle import _validate_payload

        class FakeBytesTooLong(bytes):
            def __len__(self) -> int:
                return 2**32

        with pytest.raises(InvalidKeyLengthError):
            _validate_payload(FakeBytesTooLong(b"x"))

    def test_metadata_none_raises(self, keypair, node_id):
        from crypto_layer.vtrc_bundle import _validate_metadata

        with pytest.raises(InvalidKeyLengthError):
            _validate_metadata(None)

    def test_metadata_exceeds_2_byte_range_raises(self):
        from crypto_layer.vtrc_bundle import _validate_metadata

        huge_metadata = {"k": "v" * (2**16)}
        with pytest.raises(InvalidKeyLengthError):
            _validate_metadata(huge_metadata)

    def test_created_at_hint_non_numeric_raises(self, keypair, node_id):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, b"x", priv, created_at_hint="not-a-number")

    def test_private_key_non_bytes_raises(self, node_id):
        with pytest.raises(InvalidKeyLengthError):
            build_bundle(node_id, 1, b"x", "not-bytes-key")

    def test_parse_raw_non_bytes_raises(self):
        with pytest.raises(InvalidKeyLengthError):
            parse_bundle("not-bytes-at-all")

    def test_parse_wrong_format_version_raises(self, keypair, node_id):
        """Construye un bundle válido y le sube artificialmente el byte
        de format_version para simular una versión futura desconocida."""
        priv, _pub = keypair
        raw = bytearray(build_bundle(node_id, 1, b"data", priv))
        # byte 4 (índice 4) es format_version, justo después del magic de 4 bytes
        raw[4] = 99
        with pytest.raises(BundleIntegrityError):
            parse_bundle(bytes(raw))

    def test_parse_metadata_not_a_dict_raises(self, keypair, node_id):
        """Bundle con metadata que es JSON válido pero no un objeto
        (ej. una lista) — debe rechazarse aunque el JSON parseé bien."""
        priv, _pub = keypair
        # Construir manualmente sin pasar por _validate_metadata, para
        # simular un bundle de un emisor que no respeta el contrato
        # (o un formato_version futuro con semántica distinta).
        import json as _json
        import struct as _struct
        from crypto_layer.vtrc_bundle import (
            _HEADER_STRUCT_NO_SIG,
            FORMAT_VERSION,
            MAGIC,
        )

        payload = b"data"
        metadata_bytes = _json.dumps([1, 2, 3]).encode("utf-8")  # lista, no dict
        fixed = _struct.pack(
            _HEADER_STRUCT_NO_SIG,
            MAGIC,
            FORMAT_VERSION,
            int.from_bytes(node_id, "big"),
            1,
            len(payload),
            len(metadata_bytes),
            0,
        )
        zero_sig = b"\x00" * 64
        to_sign = fixed + zero_sig + payload + metadata_bytes
        sig = __import__("crypto_layer.ed25519_sign", fromlist=["sign"]).sign(
            to_sign, priv
        )
        raw = fixed + sig + payload + metadata_bytes

        with pytest.raises(BundleIntegrityError):
            parse_bundle(raw)

    def test_verify_public_key_non_bytes_raises(self, keypair, node_id):
        priv, _pub = keypair
        raw = build_bundle(node_id, 1, b"data", priv)
        with pytest.raises(InvalidKeyLengthError):
            verify_bundle(raw, "not-bytes")

    def test_verify_reraises_invalid_key_length_from_raw_non_bytes(self, keypair):
        """verify_bundle valida public_key antes de llegar a parse_bundle,
        así que para forzar el re-raise de InvalidKeyLengthError desde
        parse_bundle dentro de verify_bundle, public_key debe ser válido
        y raw debe ser el tipo incorrecto."""
        _priv, pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            verify_bundle("not-bytes-raw", pub)

    def test_counter_store_empty_db_path_raises(self, tmp_path):
        with pytest.raises(InvalidKeyLengthError):
            CounterVerificationStore(db_path="")

    def test_max_counter_seen_invalid_node_id_returns_zero(self, counter_store):
        assert counter_store.max_counter_seen(None) == 0
        assert counter_store.max_counter_seen(b"") == 0
        assert counter_store.max_counter_seen("not-bytes") == 0
