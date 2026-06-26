"""
vtr-continuity v0.5.0 — RPi 4 OT Tier
rpi/proxy_auth.py

Conecta rpi/jwt_verifier.py::RPiJWTVerifier (existente desde v0.4.0,
nunca invocado desde ningún endpoint) con rpi/proxy.py.

Origen: docs/VTR-THREAT-001.md, amenazas S-3/T-3/R-3/D-3/I-3 — hallazgo
estructural de que POST /events, GET /health, GET /stats no tienen
ningún mecanismo de autenticación en su definición. La causa raíz no era
ausencia de infraestructura — RPiJWTVerifier ya existe completo, con
scopes, grace period offline, y revocación — sino que proxy.py nunca lo
importaba.

DECISIÓN DE DISEÑO (confirmada explícitamente, no asumida): sin bypass
de modo debug para esta autenticación. VTR_DEBUG=true sigue controlando
únicamente DELETE /queue (comportamiento ya existente, sin cambios) —
nunca se extendió a estos endpoints porque un bypass de autenticación
condicionado a una variable de entorno es exactamente el tipo de brecha
que un despliegue accidental (copiar un .env de desarrollo a producción)
deja abierta silenciosamente, sin ninguna señal de que algo está mal
configurado. El costo de no tener bypass (generar un token real con
VTRAuth.issue() en pruebas locales) es mínimo comparado con el riesgo de
una ventana de autenticación condicionalmente desactivable en un sistema
de infraestructura crítica air-gapped.

Convención de scopes reusada de server/auth.py (ya documentada ahí,
no inventada aquí): "read" para operaciones de consulta, "write" para
mutaciones.

NOTA PARA FUTUROS EMISORES DE TOKENS (vtr-provision.py, o el flujo de
aprovisionamiento de HMI que aún no existe): VTRAuth.verify() valida
scopes por pertenencia literal en la lista, sin jerarquía implícita —
un token con scopes=["write"] NO satisface required_scope="read".
Si un HMI necesita poder tanto consultar (GET /health, GET /stats) como
enviar eventos (POST /events), su token debe emitirse con
scopes=["read", "write"] explícitamente — no asumir que "write" ya
incluye "read". Esto se descubrió como hallazgo real al escribir los
tests de este módulo, no es una limitación inventada para este
docstring.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .jwt_verifier import DEFAULT_PUBLIC_KEY_PATH, RPiJWTVerifier, RPiVerifyResult

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(
    scheme_name="VTR-JWT",
    description="JWT RS256 emitido por server/auth.py::VTRAuth.issue()",
    auto_error=False,
)

_verifier: RPiJWTVerifier | None = None


def init_verifier(
    public_key_path: Path | str = DEFAULT_PUBLIC_KEY_PATH,
) -> RPiJWTVerifier:
    """
    Inicializa el verificador JWT del proxy — se llama una vez desde el
    lifespan de proxy.py, mismo patrón ya usado para _store y _sync.

    Falla inmediatamente si la clave pública no existe o está corrupta
    (comportamiento ya documentado en RPiJWTVerifier — "nunca opera sin
    clave pública válida") — el proxy NO debe arrancar silenciosamente
    sin poder verificar ningún token, porque eso dejaría todos los
    endpoints inalcanzables de forma confusa en vez de fallar con un
    error claro al inicio.

    Returns:
        La instancia de RPiJWTVerifier ya inicializada, para que el
        lifespan la asigne a la variable global del módulo.

    Raises:
        FileNotFoundError: si public_key_path no existe — mismo
            comportamiento que RPiJWTVerifier ya tiene, propagado sin
            capturar para que el proxy falle al arrancar, no en la
            primera request.
    """
    global _verifier
    _verifier = RPiJWTVerifier(public_key_path=public_key_path)
    logger.info(
        "[proxy_auth] RPiJWTVerifier inicializado — clave pública: %s",
        str(public_key_path),
    )
    return _verifier


def get_verifier() -> RPiJWTVerifier:
    if _verifier is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RPiJWTVerifier no inicializado — el proxy no completó su arranque",
        )
    return _verifier


def _is_server_offline() -> bool:
    """
    Determina si el grace period offline debe activarse, consultando el
    estado real de SyncManager (rpi/sync_manager.py) — no una variable
    de entorno separada. El estado "OFFLINE" ya es producido por
    SyncManager._sync_loop() cuando health_check() falla — esta función
    reusa esa señal existente, no introduce una nueva.

    Import diferido (no a nivel de módulo) para evitar import circular:
    proxy.py importa este módulo, y este módulo necesita el estado de
    _sync que vive en proxy.py.
    """
    from . import proxy as proxy_module

    if proxy_module._sync is None:
        return False
    return proxy_module._sync.state.status == "OFFLINE"


def require_scope(required_scope: str):
    """
    Factory de dependency de FastAPI — exige un JWT válido con el scope
    indicado. Uso: `Depends(require_scope("write"))`.

    Sin excepción de modo debug — ver docstring del módulo para la
    decisión y su razonamiento completo.

    Args:
        required_scope: "read" o "write", siguiendo la convención ya
            documentada en server/auth.py::VTRAuth.issue().

    Returns:
        Una función de dependency de FastAPI que retorna RPiVerifyResult
        en éxito, o lanza HTTPException 401 en cualquier fallo.
    """

    def _dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
        verifier: RPiJWTVerifier = Depends(get_verifier),
    ) -> RPiVerifyResult:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="falta header Authorization: Bearer <token>",
            )

        result = verifier.verify(
            credentials.credentials,
            required_scope=required_scope,
            allow_grace=_is_server_offline(),
        )

        if not result.valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"token inválido: {result.error}",
            )

        return result

    return _dependency
