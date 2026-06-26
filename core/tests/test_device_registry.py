"""
vtr-continuity v0.5.0 — Tests core/device_registry.py
core/tests/test_device_registry.py

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5): implementa
device_registry.vtrdb según docs/VTR-PKI-001.md §3.3 y
docs/DECISIONS-v0.5.0.md Decisión 3 (Opción 3A).

Usa llaves Ed25519 reales (crypto_layer.ed25519_sign.generate_keypair)
y cifrado XChaCha20-Poly1305 real (nacl.secret.Aead) — no mocks. La
manipulación directa de SQLite vía sqlite3.connect() crudo (no a través
de DeviceRegistry) es deliberada en TestHashChainTampering: simula a un
atacante con acceso de disco al archivo .vtrdb, que es exactamente el
escenario que el hash chain existe para detectar.

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import nacl.secret
import nacl.utils
import pytest

from core.device_registry import (
    AEAD_KEY_SIZE,
    DeviceRegistry,
    DeviceRegistryEntry,
)
from crypto_layer.ed25519_sign import PUBLIC_KEY_LENGTH_BYTES, generate_keypair
from crypto_layer.errors import InvalidKeyLengthError


@pytest.fixture
def encryption_key() -> bytes:
    return nacl.utils.random(AEAD_KEY_SIZE)


@pytest.fixture
def intermediate_keypair():
    return generate_keypair()


@pytest.fixture
def registry(tmp_path, encryption_key) -> DeviceRegistry:
    return DeviceRegistry(
        registry_path=tmp_path / "device_registry.vtrdb",
        encryption_key=encryption_key,
    )


def _device_keypair():
    return generate_keypair()


# ---------------------------------------------------------------------------
# Tests felices — append/get_all/verify_chain con material criptográfico real
# ---------------------------------------------------------------------------

class TestAppendAndReadHappy:
    def test_append_returns_entry(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        entry = registry.append(
            "device-001.vtr.local", device_pub, "INT-001", intermediate_priv
        )
        assert isinstance(entry, DeviceRegistryEntry)
        assert entry.device_id == "device-001.vtr.local"

    def test_get_all_returns_correct_count(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        for i in range(5):
            _, device_pub = _device_keypair()
            registry.append(
                f"device-{i:03d}.vtr.local", device_pub, "INT-001", intermediate_priv
            )
        assert len(registry.get_all()) == 5

    def test_device_public_key_roundtrip_exact(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        registry.append("device-001.vtr.local", device_pub, "INT-001", intermediate_priv)
        entries = registry.get_all()
        assert entries[0].device_public_key == device_pub

    def test_entries_preserve_insertion_order(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        for i in range(3):
            _, device_pub = _device_keypair()
            registry.append(
                f"device-{i:03d}.vtr.local", device_pub, "INT-001", intermediate_priv
            )
        entries = registry.get_all()
        assert [e.device_id for e in entries] == [
            "device-000.vtr.local",
            "device-001.vtr.local",
            "device-002.vtr.local",
        ]

    def test_verify_chain_valid_with_correct_key(self, registry, intermediate_keypair):
        intermediate_priv, intermediate_pub = intermediate_keypair
        _, device_pub = _device_keypair()
        registry.append("device-001.vtr.local", device_pub, "INT-001", intermediate_priv)
        assert registry.verify_chain(intermediate_pub) is True

    def test_verify_chain_multiple_entries(self, registry, intermediate_keypair):
        intermediate_priv, intermediate_pub = intermediate_keypair
        for i in range(10):
            _, device_pub = _device_keypair()
            registry.append(
                f"device-{i:03d}.vtr.local", device_pub, "INT-001", intermediate_priv
            )
        assert registry.verify_chain(intermediate_pub) is True

    def test_empty_registry_verify_chain_is_true(self, registry, intermediate_keypair):
        """Un registro recién creado, sin entradas, debe verificar
        como íntegro — la cadena vacía no es una cadena rota."""
        _, intermediate_pub = intermediate_keypair
        assert registry.verify_chain(intermediate_pub) is True


# ---------------------------------------------------------------------------
# Confidencialidad real — no solo afirmada
# ---------------------------------------------------------------------------

class TestConfidentiality:
    def test_device_id_never_in_plaintext_on_disk(
        self, tmp_path, encryption_key, intermediate_keypair
    ):
        intermediate_priv, _ = intermediate_keypair
        registry_path = tmp_path / "device_registry.vtrdb"
        registry = DeviceRegistry(
            registry_path=registry_path, encryption_key=encryption_key
        )
        _, device_pub = _device_keypair()
        registry.append(
            "device-secreto-unico.vtr.local", device_pub, "INT-001", intermediate_priv
        )

        raw_bytes = registry_path.read_bytes()
        assert b"device-secreto-unico" not in raw_bytes

    def test_wrong_encryption_key_fails_loudly(
        self, tmp_path, encryption_key, intermediate_keypair
    ):
        intermediate_priv, _ = intermediate_keypair
        registry_path = tmp_path / "device_registry.vtrdb"
        registry = DeviceRegistry(
            registry_path=registry_path, encryption_key=encryption_key
        )
        _, device_pub = _device_keypair()
        registry.append("device-001.vtr.local", device_pub, "INT-001", intermediate_priv)

        wrong_key = nacl.utils.random(AEAD_KEY_SIZE)
        wrong_registry = DeviceRegistry(
            registry_path=registry_path, encryption_key=wrong_key
        )
        with pytest.raises(Exception):
            wrong_registry.get_all()


# ---------------------------------------------------------------------------
# Manipulación directa de SQLite — el caso que el hash chain debe detectar
# ---------------------------------------------------------------------------

class TestHashChainTampering:
    def test_deleting_middle_entry_breaks_chain(
        self, tmp_path, encryption_key, intermediate_keypair
    ):
        intermediate_priv, intermediate_pub = intermediate_keypair
        registry_path = tmp_path / "device_registry.vtrdb"
        registry = DeviceRegistry(
            registry_path=registry_path, encryption_key=encryption_key
        )
        for i in range(5):
            _, device_pub = _device_keypair()
            registry.append(
                f"device-{i:03d}.vtr.local", device_pub, "INT-001", intermediate_priv
            )

        assert registry.verify_chain(intermediate_pub) is True

        # Manipulación directa vía SQL crudo — simula acceso de disco,
        # no pasa por la API de DeviceRegistry en absoluto.
        conn = sqlite3.connect(str(registry_path))
        conn.execute("DELETE FROM registry_entries WHERE id = 3")
        conn.commit()
        conn.close()

        registry2 = DeviceRegistry(
            registry_path=registry_path, encryption_key=encryption_key
        )
        assert registry2.verify_chain(intermediate_pub) is False

    def test_wrong_intermediate_public_key_fails_verification(
        self, registry, intermediate_keypair
    ):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        registry.append("device-001.vtr.local", device_pub, "INT-001", intermediate_priv)

        _, wrong_pub = generate_keypair()
        assert registry.verify_chain(wrong_pub) is False

    def test_no_update_or_delete_methods_exist(self, registry):
        """Append-only real, no solo por convención de nombres — no
        debe existir ningún método que permita modificar o borrar una
        entrada ya escrita."""
        assert not hasattr(registry, "update")
        assert not hasattr(registry, "delete")
        assert not hasattr(registry, "remove")

    def test_modifying_content_without_breaking_link_detected(
        self, tmp_path, encryption_key, intermediate_keypair
    ):
        """Caso distinto de borrar una fila: aquí se modifica el
        CONTENIDO cifrado de una entrada SIN tocar su previous_hash ni
        borrar ninguna fila — el enlace de la cadena entre filas sigue
        intacto, pero el hash recalculado del contenido ya no coincide
        con el entry_hash almacenado. Esta rama es distinta de
        test_deleting_middle_entry_breaks_chain (que rompe el ENLACE)
        — aquí se rompe el CONTENIDO sin tocar el enlace, y debe
        detectarse igual."""
        intermediate_priv, intermediate_pub = intermediate_keypair
        registry_path = tmp_path / "device_registry.vtrdb"
        registry = DeviceRegistry(
            registry_path=registry_path, encryption_key=encryption_key
        )
        _, device_pub = _device_keypair()
        registry.append("device-001.vtr.local", device_pub, "INT-001", intermediate_priv)

        assert registry.verify_chain(intermediate_pub) is True

        # Re-cifrar un contenido DISTINTO con la misma llave, y
        # sobrescribir el ciphertext de la fila existente sin tocar
        # entry_hash ni previous_hash — simula a un atacante con la
        # llave de cifrado del bench pero sin la llave privada de la
        # Intermediate (escenario real: backup cifrado robado).
        import json

        import nacl.secret as nacl_secret

        aead = nacl_secret.Aead(encryption_key)
        tampered_plaintext = json.dumps(
            {
                "device_id": "device-001.vtr.local",
                "device_public_key": device_pub.hex(),
                "provisioned_at": 999999999.0,  # timestamp alterado
                "intermediate_serial": "INT-001",
                "previous_hash": "0" * 64,
                "entry_hash": "this-is-not-recomputable-correctly",
                "signature": "00" * 64,
            },
            sort_keys=True,
        ).encode("utf-8")
        tampered_encrypted = aead.encrypt(tampered_plaintext)

        conn = sqlite3.connect(str(registry_path))
        conn.execute(
            "UPDATE registry_entries SET nonce = ?, ciphertext = ? WHERE id = 1",
            (tampered_encrypted.nonce, tampered_encrypted.ciphertext),
        )
        conn.commit()
        conn.close()

        registry2 = DeviceRegistry(
            registry_path=registry_path, encryption_key=encryption_key
        )
        assert registry2.verify_chain(intermediate_pub) is False


# ---------------------------------------------------------------------------
# Adversarial — constructor
# ---------------------------------------------------------------------------

class TestAdversarialConstructor:
    def test_encryption_key_none_raises(self, tmp_path):
        with pytest.raises(InvalidKeyLengthError):
            DeviceRegistry(
                registry_path=tmp_path / "x.vtrdb", encryption_key=None
            )

    def test_encryption_key_non_bytes_raises(self, tmp_path):
        with pytest.raises(InvalidKeyLengthError):
            DeviceRegistry(
                registry_path=tmp_path / "x.vtrdb", encryption_key="not-bytes"
            )

    def test_encryption_key_wrong_length_raises(self, tmp_path):
        with pytest.raises(InvalidKeyLengthError):
            DeviceRegistry(
                registry_path=tmp_path / "x.vtrdb", encryption_key=b"corta"
            )

    def test_registry_path_empty_raises(self, encryption_key):
        with pytest.raises(InvalidKeyLengthError):
            DeviceRegistry(registry_path="", encryption_key=encryption_key)


# ---------------------------------------------------------------------------
# Adversarial — append()
# ---------------------------------------------------------------------------

class TestAdversarialAppend:
    def test_device_id_none_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        with pytest.raises(InvalidKeyLengthError):
            registry.append(None, device_pub, "INT-001", intermediate_priv)

    def test_device_id_non_string_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        with pytest.raises(InvalidKeyLengthError):
            registry.append(12345, device_pub, "INT-001", intermediate_priv)

    def test_device_id_empty_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        with pytest.raises(InvalidKeyLengthError):
            registry.append("   ", device_pub, "INT-001", intermediate_priv)

    def test_device_public_key_none_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        with pytest.raises(InvalidKeyLengthError):
            registry.append("device-001", None, "INT-001", intermediate_priv)

    def test_device_public_key_non_bytes_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        with pytest.raises(InvalidKeyLengthError):
            registry.append("device-001", "not-bytes", "INT-001", intermediate_priv)

    def test_device_public_key_wrong_length_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        with pytest.raises(InvalidKeyLengthError):
            registry.append("device-001", b"corta", "INT-001", intermediate_priv)

    def test_intermediate_serial_empty_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        with pytest.raises(InvalidKeyLengthError):
            registry.append("device-001", device_pub, "", intermediate_priv)

    def test_intermediate_serial_none_raises(self, registry, intermediate_keypair):
        intermediate_priv, _ = intermediate_keypair
        _, device_pub = _device_keypair()
        with pytest.raises(InvalidKeyLengthError):
            registry.append("device-001", device_pub, None, intermediate_priv)

    def test_intermediate_private_key_none_raises(self, registry):
        _, device_pub = _device_keypair()
        with pytest.raises(InvalidKeyLengthError):
            registry.append("device-001", device_pub, "INT-001", None)


# ---------------------------------------------------------------------------
# Adversarial — verify_chain()
# ---------------------------------------------------------------------------

class TestAdversarialVerifyChain:
    def test_public_key_none_raises(self, registry):
        with pytest.raises(InvalidKeyLengthError):
            registry.verify_chain(None)

    def test_public_key_non_bytes_raises(self, registry):
        with pytest.raises(InvalidKeyLengthError):
            registry.verify_chain("not-bytes")

    def test_public_key_wrong_length_raises(self, registry):
        with pytest.raises(InvalidKeyLengthError):
            registry.verify_chain(b"corta")

    def test_public_key_correct_length_confirmed(self):
        assert PUBLIC_KEY_LENGTH_BYTES == 32
