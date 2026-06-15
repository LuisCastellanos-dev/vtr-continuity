"""
vtr-continuity v0.4.0 — Tests Server Auth
server/tests/test_auth.py

Cubre:
  - KeyPair: generación, exportación PEM, carga desde PEM
  - VTRAuth.issue(): validaciones, payload, refresh token
  - VTRAuth.refresh(): rotation, doble uso, expirado
  - VTRAuth.verify(): firma, expiración, revocación, scopes, nulls
  - VTRAuth.revoke(): por JTI
  - Grace period: token expirado dentro y fuera del margen
  - purge_expired_refresh(): limpieza de memoria

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import time

import pytest

from server.auth import KeyPair, VTRAuth, TokenPair, VerifyResult


@pytest.fixture(scope="module")
def keypair():
    return KeyPair(key_size=2048)


@pytest.fixture
def auth(keypair):
    return VTRAuth(
        keypair=keypair,
        access_ttl=900,
        refresh_ttl=86400,
        grace_period=1800,
        issuer="vtr-test",
    )


class TestKeyPair:

    def test_genera_claves(self, keypair):
        assert keypair.private_pem() is not None
        assert keypair.public_pem() is not None

    def test_pem_son_bytes(self, keypair):
        assert isinstance(keypair.private_pem(), bytes)
        assert isinstance(keypair.public_pem(), bytes)

    def test_private_pem_contiene_header(self, keypair):
        assert b"PRIVATE KEY" in keypair.private_pem()

    def test_public_pem_contiene_header(self, keypair):
        assert b"PUBLIC KEY" in keypair.public_pem()

    def test_carga_desde_pem(self, keypair):
        pem = keypair.private_pem()
        loaded = KeyPair.from_pem(pem)
        assert loaded.public_pem() == keypair.public_pem()

    def test_pem_vacio_raises(self):
        with pytest.raises(Exception):
            KeyPair.from_pem(b"")

    def test_key_size_minimo(self):
        with pytest.raises(ValueError):
            KeyPair(key_size=1024)


class TestIssue:

    def test_issue_basico(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        assert isinstance(pair, TokenPair)
        assert pair.access_token
        assert pair.refresh_token
        assert pair.hmi_id == "hmi-01"
        assert pair.expires_at > time.time()

    def test_issue_hmi_id_none_raises(self, auth):
        with pytest.raises(ValueError):
            auth.issue(None, "ignition")

    def test_issue_hmi_id_vacio_raises(self, auth):
        with pytest.raises(ValueError):
            auth.issue("", "ignition")

    def test_issue_hmi_type_none_raises(self, auth):
        with pytest.raises(ValueError):
            auth.issue("hmi-01", None)

    def test_issue_hmi_type_invalido_raises(self, auth):
        with pytest.raises(ValueError):
            auth.issue("hmi-01", "scada_desconocido")

    def test_issue_todos_hmi_types_validos(self, auth):
        for hmi_type in ["ignition", "wincc", "ifix", "generic"]:
            pair = auth.issue(f"hmi-{hmi_type}", hmi_type)
            assert pair.access_token

    def test_issue_scopes_default_es_read(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        result = auth.verify(pair.access_token)
        assert "read" in result.payload["scopes"]

    def test_issue_scopes_invalido_raises(self, auth):
        with pytest.raises(ValueError):
            auth.issue("hmi-01", "ignition", scopes="read")

    def test_issue_scopes_personalizados(self, auth):
        pair = auth.issue("hmi-01", "ignition", scopes=["read", "write"])
        result = auth.verify(pair.access_token)
        assert "write" in result.payload["scopes"]

    def test_issue_jti_unico(self, auth):
        p1 = auth.issue("hmi-01", "ignition")
        p2 = auth.issue("hmi-01", "ignition")
        assert p1.jti != p2.jti


class TestRefresh:

    def test_refresh_basico(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        new_pair = auth.refresh(pair.refresh_token)
        assert new_pair.access_token != pair.access_token
        assert new_pair.refresh_token != pair.refresh_token

    def test_refresh_token_anterior_invalido(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        old_rt = pair.refresh_token
        auth.refresh(old_rt)
        with pytest.raises(PermissionError):
            auth.refresh(old_rt)

    def test_refresh_doble_uso_raises(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        auth.refresh(pair.refresh_token)
        with pytest.raises(PermissionError):
            auth.refresh(pair.refresh_token)

    def test_refresh_token_none_raises(self, auth):
        with pytest.raises(ValueError):
            auth.refresh(None)

    def test_refresh_token_vacio_raises(self, auth):
        with pytest.raises(ValueError):
            auth.refresh("")

    def test_refresh_token_inexistente_raises(self, auth):
        with pytest.raises(PermissionError):
            auth.refresh("token-que-no-existe")

    def test_refresh_expirado_raises(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, refresh_ttl=0.01)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        with pytest.raises(PermissionError):
            auth_fast.refresh(pair.refresh_token)

    def test_refresh_preserva_hmi_id(self, auth):
        pair = auth.issue("hmi-especial", "wincc")
        new_pair = auth.refresh(pair.refresh_token)
        result = auth.verify(new_pair.access_token)
        assert result.payload["sub"] == "hmi-especial"


class TestVerify:

    def test_verify_token_valido(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        result = auth.verify(pair.access_token)
        assert result.valid is True
        assert result.error is None
        assert result.payload is not None

    def test_verify_token_none(self, auth):
        result = auth.verify(None)
        assert result.valid is False
        assert result.error is not None
        assert result.payload is None

    def test_verify_token_vacio(self, auth):
        result = auth.verify("")
        assert result.valid is False
        assert result.payload is None

    def test_verify_token_basura(self, auth):
        result = auth.verify("esto.no.es.jwt")
        assert result.valid is False

    def test_verify_token_expirado(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, grace_period=0)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        result = auth_fast.verify(pair.access_token)
        assert result.valid is False
        assert "expirado" in result.error

    def test_verify_scope_requerido_ok(self, auth):
        pair = auth.issue("hmi-01", "ignition", scopes=["read", "write"])
        result = auth.verify(pair.access_token, required_scope="write")
        assert result.valid is True

    def test_verify_scope_faltante(self, auth):
        pair = auth.issue("hmi-01", "ignition", scopes=["read"])
        result = auth.verify(pair.access_token, required_scope="write")
        assert result.valid is False
        assert "write" in result.error

    def test_verify_payload_contiene_hmi_type(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        result = auth.verify(pair.access_token)
        assert result.payload["hmi_type"] == "ignition"

    def test_verify_payload_contiene_sub(self, auth):
        pair = auth.issue("hmi-planta", "wincc")
        result = auth.verify(pair.access_token)
        assert result.payload["sub"] == "hmi-planta"

    def test_verify_token_clave_diferente_falla(self, auth):
        otra_keypair = KeyPair()
        otro_auth = VTRAuth(keypair=otra_keypair)
        pair = otro_auth.issue("hmi-01", "ignition")
        result = auth.verify(pair.access_token)
        assert result.valid is False


class TestRevoke:

    def test_revoke_token_valido(self, auth):
        pair = auth.issue("hmi-01", "ignition")
        assert auth.verify(pair.access_token).valid is True
        auth.revoke(pair.access_token)
        result = auth.verify(pair.access_token)
        assert result.valid is False
        assert "revocado" in result.error

    def test_revoke_token_none(self, auth):
        assert auth.revoke(None) is False

    def test_revoke_token_basura(self, auth):
        assert auth.revoke("basura") is False

    def test_revoke_token_expirado_ok(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, grace_period=0)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        result = auth_fast.revoke(pair.access_token)
        assert result is True


class TestGracePeriod:

    def test_grace_period_activo(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        result = auth_fast.verify(pair.access_token, allow_grace=True)
        assert result.valid is True
        assert result.extended_offline is True

    def test_grace_period_inactivo_por_defecto(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.05)
        result = auth_fast.verify(pair.access_token, allow_grace=False)
        assert result.valid is False

    def test_grace_period_vencido(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, grace_period=0.01)
        pair = auth_fast.issue("hmi-01", "ignition")
        time.sleep(0.1)
        result = auth_fast.verify(pair.access_token, allow_grace=True)
        assert result.valid is False
        assert "grace_period" in result.error

    def test_grace_period_respeta_revocacion(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition")
        auth_fast.revoke(pair.access_token)
        time.sleep(0.05)
        result = auth_fast.verify(pair.access_token, allow_grace=True)
        assert result.valid is False
        assert "revocado" in result.error

    def test_grace_period_respeta_scope(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, access_ttl=0.01, grace_period=60)
        pair = auth_fast.issue("hmi-01", "ignition", scopes=["read"])
        time.sleep(0.05)
        result = auth_fast.verify(pair.access_token, required_scope="write", allow_grace=True)
        assert result.valid is False


class TestPurgeRefresh:

    def test_purge_elimina_expirados(self, keypair):
        auth_fast = VTRAuth(keypair=keypair, refresh_ttl=0.01)
        auth_fast.issue("hmi-01", "ignition")
        auth_fast.issue("hmi-02", "wincc")
        time.sleep(0.05)
        deleted = auth_fast.purge_expired_refresh()
        assert deleted == 2

    def test_purge_mantiene_vigentes(self, auth):
        before = len(auth._refresh_tokens)
        auth.issue("hmi-purge-test", "generic")
        deleted = auth.purge_expired_refresh()
        assert deleted == 0
        assert len(auth._refresh_tokens) >= before + 1
