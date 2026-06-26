"""
vtr-continuity v0.5.0 — Tests rpi/proxy_auth.py
rpi/tests/test_proxy_auth.py

Cierra el hallazgo estructural de docs/VTR-THREAT-001.md
(S-3/T-3/R-3/D-3/I-3): POST /events, GET /health, GET /stats, y
DELETE /queue no tenían ningún mecanismo de autenticación.

Usa TestClient real de FastAPI contra la app real de rpi/proxy.py, con
tokens JWT reales firmados por server/auth.py::VTRAuth — no mocks de la
capa de autenticación. SyncManager corre en background tal como lo hace
en producción (sin servidor central real disponible en el entorno de
test, así que su estado natural es "OFFLINE" — exactamente el escenario
que activa el grace period, y se prueba explícitamente).

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import importlib
import os
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from server.auth import KeyPair, VTRAuth


@pytest.fixture(scope="module")
def keypair():
    return KeyPair(key_size=2048)


@pytest.fixture
def proxy_app(tmp_path, keypair, monkeypatch):
    """
    Configura el entorno real antes de importar/recargar rpi.proxy, para
    que lea VTR_JWT_PUBLIC_KEY_PATH, VTR_DB_PATH y VTR_CUSTODY_DB_PATH
    correctos. Recarga el módulo en cada test para aislar el estado
    global (_store, _sync, proxy_auth._verifier) entre tests — mismo
    problema de aislamiento real que ya se resolvió con fake-indexeddb
    en tests/e2e/session_guard.e2e.test.js, aquí resuelto con
    importlib.reload en vez de borrar una base de datos.

    HALLAZGO REAL al validar esta suite en un entorno sin privilegios de
    root: rpi/sync_manager.py::SyncConfig tenía custody_db_path como
    default FIJO en /var/lib/vtr-continuity/custody.db, sin ninguna
    variable de entorno que lo controlara — a diferencia de VTR_DB_PATH.
    El primer intento de arreglar esto con
    monkeypatch.setattr(SyncConfig, "custody_db_path", ...) NO funcionó:
    los defaults de un @dataclass se generan en el __init__ al momento
    de definir la clase, así que parchear el atributo de clase después
    no afecta a nuevas instancias — confirmado con una reproducción
    aislada antes de descartar ese enfoque. La corrección real fue
    agregar VTR_CUSTODY_DB_PATH como variable de entorno en
    rpi/proxy.py, que ahora pasa custody_db_path explícitamente a
    SyncConfig — esto mejora también el código de producción (antes no
    había forma de configurar esa ruta sin editar código fuente).
    """
    pubkey_path = tmp_path / "public_key.pem"
    pubkey_path.write_bytes(keypair.public_pem())

    monkeypatch.setenv("VTR_JWT_PUBLIC_KEY_PATH", str(pubkey_path))
    monkeypatch.setenv("VTR_DB_PATH", str(tmp_path / "queue.db"))
    monkeypatch.setenv("VTR_CUSTODY_DB_PATH", str(tmp_path / "custody.db"))

    from rpi import proxy as proxy_module

    importlib.reload(proxy_module)
    return proxy_module


@pytest.fixture
def auth(keypair):
    return VTRAuth(
        keypair=keypair,
        access_ttl=900,
        refresh_ttl=86400,
        grace_period=1800,
        issuer="vtr-server",
    )


@pytest.fixture
def write_headers(auth):
    tokens = auth.issue(hmi_id="hmi-test-write", hmi_type="generic", scopes=["write"])
    return {"Authorization": f"Bearer {tokens.access_token}"}


@pytest.fixture
def read_headers(auth):
    tokens = auth.issue(hmi_id="hmi-test-read", hmi_type="generic", scopes=["read"])
    return {"Authorization": f"Bearer {tokens.access_token}"}


# ---------------------------------------------------------------------------
# Sin token — los cuatro endpoints deben rechazar
# ---------------------------------------------------------------------------

class TestSinToken:
    def test_post_events_sin_token_401(self, proxy_app):
        with TestClient(proxy_app.app) as client:
            r = client.post("/events", json={"events": [{"event_type": "heartbeat"}]})
            assert r.status_code == 401

    def test_get_health_sin_token_401(self, proxy_app):
        with TestClient(proxy_app.app) as client:
            r = client.get("/health")
            assert r.status_code == 401

    def test_get_stats_sin_token_401(self, proxy_app):
        with TestClient(proxy_app.app) as client:
            r = client.get("/stats")
            assert r.status_code == 401

    def test_delete_queue_sin_token_401(self, proxy_app):
        with TestClient(proxy_app.app) as client:
            r = client.delete("/queue")
            assert r.status_code == 401


# ---------------------------------------------------------------------------
# Token válido con scope correcto — debe aceptar
# ---------------------------------------------------------------------------

class TestConScopeCorrecto:
    def test_post_events_con_write_202(self, proxy_app, write_headers):
        with TestClient(proxy_app.app) as client:
            r = client.post(
                "/events",
                json={"events": [{"event_type": "heartbeat"}]},
                headers=write_headers,
            )
            assert r.status_code == 202

    def test_get_health_con_read_200(self, proxy_app, read_headers):
        with TestClient(proxy_app.app) as client:
            r = client.get("/health", headers=read_headers)
            assert r.status_code == 200

    def test_get_stats_con_read_200(self, proxy_app, read_headers):
        with TestClient(proxy_app.app) as client:
            r = client.get("/stats", headers=read_headers)
            assert r.status_code == 200

    def test_scope_write_no_incluye_read_implicitamente(self, proxy_app, write_headers):
        """HALLAZGO REAL al desarrollar esta suite: VTRAuth.verify()
        usa pertenencia literal ('required_scope not in scopes'), sin
        ninguna jerarquía implícita de permisos. Un token con
        scopes=['write'] NO satisface required_scope='read' — la
        suposición inicial de que 'write implica read' era incorrecta
        y se corrigió aquí tras verificar el código real de
        server/auth.py::VTRAuth.verify() línea 345. Si en el futuro se
        quiere una jerarquía de scopes, es una decisión de diseño nueva
        y explícita en server/auth.py, no algo que deba asumirse."""
        with TestClient(proxy_app.app) as client:
            r = client.get("/health", headers=write_headers)
            assert r.status_code == 401


# ---------------------------------------------------------------------------
# Scope insuficiente — debe rechazar incluso con firma válida
# ---------------------------------------------------------------------------

class TestScopeInsuficiente:
    def test_post_events_con_solo_read_401(self, proxy_app, read_headers):
        with TestClient(proxy_app.app) as client:
            r = client.post(
                "/events",
                json={"events": [{"event_type": "heartbeat"}]},
                headers=read_headers,
            )
            assert r.status_code == 401

    def test_delete_queue_con_solo_read_401(self, proxy_app, read_headers):
        with TestClient(proxy_app.app) as client:
            r = client.delete("/queue", headers=read_headers)
            assert r.status_code == 401


# ---------------------------------------------------------------------------
# Token inválido / malformado
# ---------------------------------------------------------------------------

class TestTokenInvalido:
    def test_token_basura_401(self, proxy_app):
        with TestClient(proxy_app.app) as client:
            r = client.get(
                "/health",
                headers={"Authorization": "Bearer esto-no-es-un-jwt-valido"},
            )
            assert r.status_code == 401

    def test_token_firmado_con_otra_llave_401(self, proxy_app, read_headers):
        """Token estructuralmente válido pero firmado con una llave
        privada DISTINTA a la que el proxy verifica — debe rechazarse
        por firma inválida, no aceptarse por tener el formato correcto."""
        otro_keypair = KeyPair(key_size=2048)
        otro_auth = VTRAuth(
            keypair=otro_keypair,
            access_ttl=900,
            refresh_ttl=86400,
            grace_period=1800,
            issuer="vtr-server",
        )
        tokens = otro_auth.issue(hmi_id="atacante", hmi_type="generic", scopes=["read"])
        with TestClient(proxy_app.app) as client:
            r = client.get(
                "/health",
                headers={"Authorization": f"Bearer {tokens.access_token}"},
            )
            assert r.status_code == 401

    def test_header_authorization_ausente_pero_otros_headers_presentes_401(self, proxy_app):
        with TestClient(proxy_app.app) as client:
            r = client.get("/health", headers={"X-Custom-Header": "valor"})
            assert r.status_code == 401

    def test_authorization_sin_bearer_prefix_401(self, proxy_app, read_headers):
        """HTTPBearer de FastAPI exige el prefijo 'Bearer ' — un header
        Authorization mal formado (sin ese prefijo) no debe colarse."""
        token_crudo = read_headers["Authorization"].replace("Bearer ", "")
        with TestClient(proxy_app.app) as client:
            r = client.get("/health", headers={"Authorization": token_crudo})
            assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# DELETE /queue — ambas protecciones (JWT + DEBUG_MODE) son independientes
# ---------------------------------------------------------------------------

class TestDeleteQueueDobleProteccion:
    def test_token_valido_sin_debug_mode_403(self, proxy_app, write_headers, monkeypatch):
        """Token válido con scope write, pero VTR_DEBUG no está activo —
        debe rechazar con 403, NO con 401. El JWT pasó; lo que bloquea
        es la segunda protección independiente."""
        monkeypatch.setattr(proxy_app, "DEBUG_MODE", False)
        with TestClient(proxy_app.app) as client:
            r = client.delete("/queue", headers=write_headers)
            assert r.status_code == 403

    def test_sin_token_con_debug_mode_activo_sigue_siendo_401(
        self, proxy_app, monkeypatch
    ):
        """VTR_DEBUG=true NUNCA exime de la autenticación JWT — esta es
        la decisión de diseño central de este módulo (ver docstring de
        rpi/proxy_auth.py): sin excepción de modo debug."""
        monkeypatch.setattr(proxy_app, "DEBUG_MODE", True)
        with TestClient(proxy_app.app) as client:
            r = client.delete("/queue")
            assert r.status_code == 401

    def test_token_valido_y_debug_mode_activo_200(
        self, proxy_app, write_headers, monkeypatch
    ):
        """Solo cuando AMBAS protecciones se satisfacen (JWT válido con
        scope write, Y VTR_DEBUG=true) la operación procede."""
        monkeypatch.setattr(proxy_app, "DEBUG_MODE", True)
        with TestClient(proxy_app.app) as client:
            r = client.delete("/queue", headers=write_headers)
            assert r.status_code == 200


# ---------------------------------------------------------------------------
# Grace period offline — usa el estado real de SyncManager, no una bandera separada
# ---------------------------------------------------------------------------

class TestGracePeriodOffline:
    def test_token_expirado_con_sync_offline_pasa_con_grace(self, tmp_path, keypair, monkeypatch):
        """Reproduce el escenario real: SyncManager está OFFLINE
        (servidor central inalcanzable, estado natural en este entorno
        de test sin servidor real) y un token expira — debe aceptarse
        vía grace period, exactamente el comportamiento ya documentado
        en RPiJWTVerifier antes de esta integración."""
        pubkey_path = tmp_path / "public_key.pem"
        pubkey_path.write_bytes(keypair.public_pem())
        monkeypatch.setenv("VTR_JWT_PUBLIC_KEY_PATH", str(pubkey_path))
        monkeypatch.setenv("VTR_DB_PATH", str(tmp_path / "queue.db"))
        monkeypatch.setenv("VTR_CUSTODY_DB_PATH", str(tmp_path / "custody.db"))

        from rpi import proxy as proxy_module

        importlib.reload(proxy_module)

        auth = VTRAuth(
            keypair=keypair, access_ttl=1, refresh_ttl=86400,
            grace_period=1800, issuer="vtr-server",
        )
        tokens = auth.issue(hmi_id="hmi-grace", hmi_type="generic", scopes=["read"])
        headers = {"Authorization": f"Bearer {tokens.access_token}"}

        with TestClient(proxy_module.app) as client:
            time.sleep(2)  # esperar expiración real del token (ttl=1s)
            assert proxy_module._sync.state.status == "OFFLINE"

            r = client.get("/health", headers=headers)
            assert r.status_code == 200

    def test_token_expirado_con_sync_online_rechaza_sin_grace(
        self, tmp_path, keypair, monkeypatch
    ):
        """Mismo token expirado, pero con SyncManager forzado a ONLINE
        (servidor central disponible) — el grace period NO debe
        aplicarse, el token expirado se rechaza."""
        pubkey_path = tmp_path / "public_key.pem"
        pubkey_path.write_bytes(keypair.public_pem())
        monkeypatch.setenv("VTR_JWT_PUBLIC_KEY_PATH", str(pubkey_path))
        monkeypatch.setenv("VTR_DB_PATH", str(tmp_path / "queue.db"))
        monkeypatch.setenv("VTR_CUSTODY_DB_PATH", str(tmp_path / "custody.db"))

        from rpi import proxy as proxy_module

        importlib.reload(proxy_module)

        auth = VTRAuth(
            keypair=keypair, access_ttl=1, refresh_ttl=86400,
            grace_period=1800, issuer="vtr-server",
        )
        tokens = auth.issue(hmi_id="hmi-online", hmi_type="generic", scopes=["read"])
        headers = {"Authorization": f"Bearer {tokens.access_token}"}

        with TestClient(proxy_module.app) as client:
            time.sleep(2)
            proxy_module._sync._state.status = "ONLINE"

            r = client.get("/health", headers=headers)
            assert r.status_code == 401


# ---------------------------------------------------------------------------
# Arranque — fail-fast si la clave pública no existe
# ---------------------------------------------------------------------------

class TestArranqueFailFast:
    def test_proxy_falla_al_arrancar_sin_clave_publica(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "VTR_JWT_PUBLIC_KEY_PATH", str(tmp_path / "no_existe.pem")
        )
        monkeypatch.setenv("VTR_DB_PATH", str(tmp_path / "queue.db"))

        from rpi import proxy as proxy_module

        importlib.reload(proxy_module)

        with pytest.raises(FileNotFoundError):
            with TestClient(proxy_module.app):
                pass


# ---------------------------------------------------------------------------
# Ramas adicionales detectadas por coverage real (94% -> mejorar)
# Mismo criterio que el resto del proyecto: solo casos que ejercitan
# validación real ya existente, nunca relleno artificial.
# ---------------------------------------------------------------------------

class TestAdditionalCoverage:
    def test_get_verifier_sin_inicializar_503(self):
        """get_verifier() llamado directamente (no vía TestClient/lifespan)
        antes de que init_verifier() se ejecute — debe fallar con 503,
        no con un AttributeError ni devolver None silenciosamente."""
        import importlib as importlib_local

        from rpi import proxy_auth as proxy_auth_module

        importlib_local.reload(proxy_auth_module)

        with pytest.raises(HTTPException) as exc_info:
            proxy_auth_module.get_verifier()
        assert exc_info.value.status_code == 503

    def test_is_server_offline_sin_sync_inicializado_false(self):
        """_is_server_offline() debe retornar False (no lanzar) si
        proxy._sync todavía es None — escenario real durante el arranque,
        antes de que el lifespan complete la inicialización de
        SyncManager."""
        import importlib as importlib_local

        from rpi import proxy as proxy_module_local
        from rpi import proxy_auth as proxy_auth_module

        proxy_module_local._sync = None
        result = proxy_auth_module._is_server_offline()
        assert result is False
