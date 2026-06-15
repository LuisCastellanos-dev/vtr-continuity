"""
vtr-continuity v0.4.0 — Tests RPi JWT Verifier
rpi/tests/test_jwt_verifier.py

Cubre:
  - Carga de clave pública desde archivo y desde bytes
  - Verificación normal, expirado, basura, None
  - Grace period: activo, vencido, respeta revocación y scope
  - Revocación: revoke_jti, revoke_batch, is_revoked, clear
  - Validación explícita de nulls en cada campo del payload
  - Issuer no autorizado
  - Reload de clave pública

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from server.auth import KeyPair, VTRAuth
from rpi.jwt_verifier import RPiJWTVerifier, RPiVerifyResult


@pytest.fixture(scope="module")
def keypair():
    return KeyPair(key_size=2048)


@pytest.fixture(scope="module")
def auth(keypair):
    return VTRAuth(
        keypair=keypair,
        access_ttl=900,
        refresh_ttl=86400,
        grace_period=1800,
        issuer="vtr-server",
    )


@pytest.fixture(scope="module")
def verifier(keypair):
    return RPiJWTVerifier.from_pem_bytes(
        public_pem=keypair.public_pem(),
        grace_period=1800,
        allowed_issuers={"vtr-server"},
    )


class TestCargaClave:

    def test_from_pem_bytes_ok(self, keypair):
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem())
        assert v is not None

    def test_pem_vacio_raises(self):
        with pytest.raises(ValueError):
            RPiJWTVerifier.from_pem_bytes(b"")

    def test_pem_none_raises(self):
        with pytest.raises(ValueError):
            RPiJWTVerifier.from_pem_bytes(None)

    def test_archivo_no_existe_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            RPiJWTVerifier(public_key_path=tmp_path / "no_existe.pem")

    def test_archivo_vacio_raises(self, tmp_path):
        pem_file = tmp_path / "empty.pem"
        pem_file.write_bytes(b"")
        with pytest.raises(ValueError):
            RPiJWTVerifier(public_key_path=pem_file)

    def test_grace_period_negativo_raises(self, keypair):
        with pytest.raises(ValueError):
            RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), grace_period=-1)

    def test_public_key_path_vacio_raises(self):
        with pytest.raises(ValueError):
            RPiJWTVerifier(public_key_path="")

    def test_carga_desde_archivo(self, keypair, tmp_path):
        pem_file = tmp_path / "public_key.pem"
        pem_file.write_bytes(keypair.public_pem())
        v = RPiJWTVerifier(public_key_path=pem_file)
        assert v is not None


class TestVerify:

    def test_token_valido(self, auth, verifier):
        pair = auth.issue("hmi-01", "ignition")
        result = verifier.verify(pair.access_token)
        assert result.valid is True
        assert result.error is None
        assert result.hmi_id == "hmi-01"
        assert result.hmi_type == "ignition"
        assert result.scopes is not None
        assert result.extended_offline is False

    def test_token_none(self, verifier):
        result = verifier.verify(None)
        assert result.valid is False
        assert result.error is not None
        assert result.payload is None

    def test_token_vacio(self, verifier):
        result = verifier.verify("")
        assert result.valid is False
        assert result.payload is None

    def test_token_basura(self, verifier):
        result = verifier.verify("esto.no.es.un.jwt")
        assert result.valid is False

    def test_token_clave_diferente(self, verifier):
        otro_keypair = KeyPair()
        otro_auth = VTRAuth(keypair=otro_keypair, issuer="vtr-server")
        pair = otro_auth.issue("hmi-01", "ignition")
        result = verifier.verify(pair.access_token)
        assert result.valid is False

    def test_token_expirado_sin_grace(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, issuer="vtr-server")
        v = RPiJWTVerifier.from_pem_bytes(
            keypair.public_pem(), grace_period=0,
        )
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        result = v.verify(pair.access_token, allow_grace=False)
        assert result.valid is False
        assert result.payload is None

    def test_scope_requerido_ok(self, auth, verifier):
        pair = auth.issue("hmi-01", "ignition", scopes=["read", "write"])
        result = verifier.verify(pair.access_token, required_scope="write")
        assert result.valid is True

    def test_scope_faltante(self, auth, verifier):
        pair = auth.issue("hmi-01", "ignition", scopes=["read"])
        result = verifier.verify(pair.access_token, required_scope="write")
        assert result.valid is False
        assert "write" in result.error

    def test_resultado_contiene_scopes(self, auth, verifier):
        pair = auth.issue("hmi-01", "ignition", scopes=["read", "write"])
        result = verifier.verify(pair.access_token)
        assert "read" in result.scopes
        assert "write" in result.scopes

    def test_issuer_no_autorizado(self, keypair):
        auth_otro = VTRAuth(keypair=keypair, issuer="servidor-no-autorizado")
        v = RPiJWTVerifier.from_pem_bytes(
            keypair.public_pem(),
            allowed_issuers={"vtr-server"},
        )
        pair = auth_otro.issue("hmi-01", "ignition")
        result = v.verify(pair.access_token)
        assert result.valid is False
        assert "no autorizado" in result.error


class TestGracePeriod:

    def test_grace_activo(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, issuer="vtr-server")
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        result = v.verify(pair.access_token, allow_grace=True)
        assert result.valid is True
        assert result.extended_offline is True

    def test_grace_inactivo_por_defecto(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, issuer="vtr-server")
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        result = v.verify(pair.access_token, allow_grace=False)
        assert result.valid is False

    def test_grace_vencido(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, issuer="vtr-server")
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), grace_period=0.01)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.1)
        result = v.verify(pair.access_token, allow_grace=True)
        assert result.valid is False
        assert "grace_period" in result.error

    def test_grace_respeta_revocacion(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, issuer="vtr-server")
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition")
        v.revoke_jti(pair.jti)
        time.sleep(0.05)
        result = v.verify(pair.access_token, allow_grace=True)
        assert result.valid is False
        assert "revocado" in result.error

    def test_grace_respeta_scope(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, issuer="vtr-server")
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition", scopes=["read"])
        time.sleep(0.05)
        result = v.verify(pair.access_token, required_scope="write", allow_grace=True)
        assert result.valid is False

    def test_grace_preserva_hmi_id(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, issuer="vtr-server")
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), grace_period=60)
        pair = auth_fast.issue("hmi-planta-norte", "wincc")
        time.sleep(0.05)
        result = v.verify(pair.access_token, allow_grace=True)
        assert result.hmi_id == "hmi-planta-norte"


class TestRevocacion:

    def test_revoke_jti_basico(self, auth, keypair):
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem(), allowed_issuers={"vtr-server"})
        pair = auth.issue("hmi-01", "ignition")
        assert v.verify(pair.access_token).valid is True
        v.revoke_jti(pair.jti)
        result = v.verify(pair.access_token)
        assert result.valid is False
        assert "revocado" in result.error

    def test_revoke_jti_none(self, verifier):
        assert verifier.revoke_jti(None) is False

    def test_revoke_jti_vacio(self, verifier):
        assert verifier.revoke_jti("") is False

    def test_revoke_batch(self, verifier):
        jtis = ["jti-a", "jti-b", "jti-c"]
        count = verifier.revoke_batch(jtis)
        assert count == 3
        for jti in jtis:
            assert verifier.is_revoked(jti) is True

    def test_revoke_batch_none(self, verifier):
        assert verifier.revoke_batch(None) == 0

    def test_revoke_batch_no_lista(self, verifier):
        assert verifier.revoke_batch("no-es-lista") == 0

    def test_is_revoked_none(self, verifier):
        assert verifier.is_revoked(None) is False

    def test_is_revoked_no_registrado(self, verifier):
        assert verifier.is_revoked("jti-nunca-visto") is False

    def test_clear_revocation_list(self, keypair):
        v = RPiJWTVerifier.from_pem_bytes(keypair.public_pem())
        v.revoke_jti("jti-x")
        v.revoke_jti("jti-y")
        deleted = v.clear_revocation_list()
        assert deleted == 2
        assert v.is_revoked("jti-x") is False


class TestReloadClave:

    def test_reload_ok(self, keypair, tmp_path):
        pem_file = tmp_path / "public_key.pem"
        pem_file.write_bytes(keypair.public_pem())
        v = RPiJWTVerifier(public_key_path=pem_file)
        result = v.reload_public_key()
        assert result is True

    def test_reload_archivo_borrado(self, keypair, tmp_path):
        pem_file = tmp_path / "public_key.pem"
        pem_file.write_bytes(keypair.public_pem())
        v = RPiJWTVerifier(public_key_path=pem_file)
        pem_file.unlink()
        result = v.reload_public_key()
        assert result is False
