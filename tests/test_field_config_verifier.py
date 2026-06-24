"""
tests/test_field_config_verifier.py — Suite formal para
crypto_layer/field_config_verifier.py.

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5), implementa Q-03
(docs/VTR-ARCH-DECISIONS-001.md). Usa el rf_config.yaml REAL del
repositorio y la integración real con
crypto_layer.rf_config_loader.load_crypto_config() — no mocks — para
confirmar que el módulo nuevo se integra sin modificar el loader
existente, exactamente como exige la decisión de Q-03.

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

from pathlib import Path

import pytest

from crypto_layer.ed25519_sign import (
    PUBLIC_KEY_LENGTH_BYTES,
    SIGNATURE_LENGTH_BYTES,
    generate_keypair,
)
from crypto_layer.errors import InvalidKeyLengthError, SignatureVerificationError
from crypto_layer.field_config_verifier import (
    sign_field_config,
    verify_and_write_field_config,
    verify_field_config,
)
from crypto_layer.rf_config_loader import load_crypto_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def real_rf_config_bytes() -> bytes:
    """rf_config.yaml REAL del repositorio — no un YAML de prueba
    inventado, para confirmar la integración real con
    load_crypto_config()."""
    path = Path(__file__).parent.parent / "config" / "rf_config.yaml"
    return path.read_bytes()


@pytest.fixture
def signed_real_config(keypair, real_rf_config_bytes) -> tuple[bytes, bytes, bytes]:
    """Config real ya firmada. Retorna (signed_bytes, priv, pub)."""
    priv, pub = keypair
    signed = sign_field_config(real_rf_config_bytes, priv)
    return signed, priv, pub


# ---------------------------------------------------------------------------
# Tests felices — round-trip sign/verify
# ---------------------------------------------------------------------------

class TestSignVerifyHappy:
    def test_sign_returns_bytes(self, keypair, real_rf_config_bytes):
        priv, _pub = keypair
        signed = sign_field_config(real_rf_config_bytes, priv)
        assert isinstance(signed, bytes)

    def test_sign_output_length_is_signature_plus_payload(
        self, keypair, real_rf_config_bytes
    ):
        priv, _pub = keypair
        signed = sign_field_config(real_rf_config_bytes, priv)
        assert len(signed) == SIGNATURE_LENGTH_BYTES + len(real_rf_config_bytes)

    def test_verify_recovers_exact_yaml_bytes(self, signed_real_config, real_rf_config_bytes):
        signed, _priv, pub = signed_real_config
        recovered = verify_field_config(signed, pub)
        assert recovered == real_rf_config_bytes

    def test_verify_rejects_wrong_public_key(self, signed_real_config):
        signed, _priv, _pub = signed_real_config
        _other_priv, wrong_pub = generate_keypair()
        with pytest.raises(SignatureVerificationError):
            verify_field_config(signed, wrong_pub)

    def test_verify_rejects_tampered_payload(self, signed_real_config):
        signed, _priv, pub = signed_real_config
        tampered = bytearray(signed)
        tampered[SIGNATURE_LENGTH_BYTES] ^= 0xFF  # corromper primer byte del YAML
        with pytest.raises(SignatureVerificationError):
            verify_field_config(bytes(tampered), pub)

    def test_verify_rejects_tampered_signature(self, signed_real_config):
        signed, _priv, pub = signed_real_config
        tampered = bytearray(signed)
        tampered[0] ^= 0xFF  # corromper primer byte de la firma
        with pytest.raises(SignatureVerificationError):
            verify_field_config(bytes(tampered), pub)


# ---------------------------------------------------------------------------
# Tests felices — integración real con load_crypto_config existente
# ---------------------------------------------------------------------------

class TestRealLoaderIntegrationHappy:
    def test_verify_and_write_creates_file(self, signed_real_config, tmp_path):
        signed, _priv, pub = signed_real_config
        dest = tmp_path / "verified_rf_config.yaml"
        result_path = verify_and_write_field_config(signed, pub, dest)
        assert result_path == dest
        assert dest.exists()

    def test_written_file_loads_with_unmodified_loader(
        self, signed_real_config, tmp_path
    ):
        """Confirma que load_crypto_config() (no modificado por este
        trabajo) acepta el archivo escrito tras verificación exitosa."""
        signed, _priv, pub = signed_real_config
        dest = tmp_path / "verified_rf_config.yaml"
        verify_and_write_field_config(signed, pub, dest)

        crypto_config = load_crypto_config(dest)
        assert crypto_config is not None

    def test_loaded_config_matches_original_profile(
        self, signed_real_config, real_rf_config_bytes, tmp_path
    ):
        """El profile cargado tras verificación debe coincidir con el
        profile real del rf_config.yaml del repositorio (no un valor
        inventado por el test)."""
        signed, _priv, pub = signed_real_config
        dest = tmp_path / "verified_rf_config.yaml"
        verify_and_write_field_config(signed, pub, dest)

        crypto_config = load_crypto_config(dest)

        import yaml

        original = yaml.safe_load(real_rf_config_bytes)
        assert crypto_config.argon2id_profile == original["crypto"]["argon2id_profile"]

    def test_invalid_signature_never_writes_file(self, signed_real_config, tmp_path):
        """Caso central de Q-03: con firma inválida, el archivo de
        destino NUNCA se crea — el dispositivo no falla abierto a un
        default ni aplica una config sin verificar."""
        signed, _priv, _pub = signed_real_config
        _other_priv, wrong_pub = generate_keypair()
        dest = tmp_path / "should_not_exist.yaml"

        with pytest.raises(SignatureVerificationError):
            verify_and_write_field_config(signed, wrong_pub, dest)

        assert not dest.exists()

    def test_existing_config_preserved_when_signature_invalid(
        self, signed_real_config, tmp_path
    ):
        """Si ya existe una configuración previa en destination_path, y
        llega una config nueva con firma inválida, la configuración
        previa debe quedar intacta — no debe sobrescribirse ni
        borrarse."""
        signed, _priv, _pub = signed_real_config
        _other_priv, wrong_pub = generate_keypair()
        dest = tmp_path / "current_config.yaml"

        original_content = b"crypto:\n  argon2id_profile: desktop\n"
        dest.write_bytes(original_content)

        with pytest.raises(SignatureVerificationError):
            verify_and_write_field_config(signed, wrong_pub, dest)

        assert dest.read_bytes() == original_content


# ---------------------------------------------------------------------------
# Adversarial — sign_field_config
# ---------------------------------------------------------------------------

class TestAdversarialSign:
    def test_yaml_bytes_none_raises(self, keypair):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            sign_field_config(None, priv)

    def test_yaml_bytes_non_bytes_raises(self, keypair):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            sign_field_config("not-bytes", priv)

    def test_yaml_bytes_empty_raises(self, keypair):
        priv, _pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            sign_field_config(b"", priv)

    def test_private_key_none_raises(self):
        with pytest.raises(InvalidKeyLengthError):
            sign_field_config(b"data", None)

    def test_private_key_non_bytes_raises(self):
        with pytest.raises(InvalidKeyLengthError):
            sign_field_config(b"data", "not-bytes")


# ---------------------------------------------------------------------------
# Adversarial — verify_field_config
# ---------------------------------------------------------------------------

class TestAdversarialVerify:
    def test_signed_bytes_none_raises(self, keypair):
        _priv, pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            verify_field_config(None, pub)

    def test_signed_bytes_non_bytes_raises(self, keypair):
        _priv, pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            verify_field_config("not-bytes", pub)

    def test_signed_bytes_too_short_raises(self, keypair):
        _priv, pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            verify_field_config(b"corto", pub)

    def test_signed_bytes_exactly_signature_length_raises(self, keypair):
        """signed_bytes == SIGNATURE_LENGTH_BYTES exactos significa
        firma sin ningún payload — debe rechazarse explícitamente, no
        intentar verificar un YAML vacío."""
        _priv, pub = keypair
        with pytest.raises(InvalidKeyLengthError):
            verify_field_config(b"x" * SIGNATURE_LENGTH_BYTES, pub)

    def test_public_key_none_raises(self, signed_real_config):
        signed, _priv, _pub = signed_real_config
        with pytest.raises(InvalidKeyLengthError):
            verify_field_config(signed, None)

    def test_public_key_non_bytes_raises(self, signed_real_config):
        signed, _priv, _pub = signed_real_config
        with pytest.raises(InvalidKeyLengthError):
            verify_field_config(signed, "not-bytes")

    def test_public_key_wrong_length_raises(self, signed_real_config):
        signed, _priv, _pub = signed_real_config
        with pytest.raises(InvalidKeyLengthError):
            verify_field_config(signed, b"corta")

    def test_public_key_correct_length_confirmed(self):
        """Confirma que el test anterior realmente prueba una longitud
        incorrecta comparándola contra la constante real."""
        assert PUBLIC_KEY_LENGTH_BYTES == 32
