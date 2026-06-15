"""
vtr-continuity v0.4.0 — RPi 4 OT Tier
rpi/jwt_verifier.py

Verificador JWT del lado RPi.

El RPi nunca ve la clave privada — solo verifica con la clave pública
distribuida desde el servidor central VTR.

Archivo esperado: /etc/vtr-continuity/public_key.pem

Principios de seguridad:
  - Solo clave pública — carga desde archivo, nunca hardcodeada
  - Validación explícita de nulls en cada campo del payload
  - Grace period configurable para entornos OT donde el servidor está offline
  - Tokens revocados se registran localmente hasta su expiración natural
  - Lista de revocación persiste en memoria — se limpia al reiniciar
    (en v0.5.0 se sincronizará via CustodyManager al reconectar)

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

DEFAULT_PUBLIC_KEY_PATH = Path("/etc/vtr-continuity/public_key.pem")
DEFAULT_ALGORITHM = "RS256"
DEFAULT_GRACE_PERIOD = 1800
DEFAULT_ALLOWED_ISSUERS = {"vtr-server"}


@dataclass
class RPiVerifyResult:
    """Resultado de verificación JWT en el RPi."""
    valid: bool
    payload: dict[str, Any] | None
    error: str | None
    extended_offline: bool = False
    hmi_id: str | None = None
    hmi_type: str | None = None
    scopes: list[str] | None = None


class RPiJWTVerifier:
    """
    Verificador JWT para el RPi 4.

    Carga la clave pública desde disco al iniciar.
    Si el archivo no existe o está corrupto, falla inmediatamente —
    nunca opera sin clave pública válida.

    Flujo normal (servidor online):
        HMI presenta JWT → RPi verifica firma y expiración → acceso OK

    Flujo offline (servidor no disponible):
        HMI presenta JWT expirado → RPi verifica firma → si está dentro
        del grace_period → acceso OK marcado como extended_offline

    Flujo de revocación:
        Servidor envía lista de JTIs revocados → RPi registra en memoria
        → tokens revocados rechazados aunque firma sea válida
    """

    def __init__(
        self,
        public_key_path: Path | str = DEFAULT_PUBLIC_KEY_PATH,
        grace_period: float = DEFAULT_GRACE_PERIOD,
        allowed_issuers: set[str] | None = None,
    ) -> None:
        if not public_key_path:
            raise ValueError("public_key_path no puede ser vacío")
        if grace_period < 0:
            raise ValueError("grace_period no puede ser negativo")

        self._public_key_path = Path(public_key_path)
        self._grace_period = grace_period
        self._allowed_issuers = allowed_issuers if allowed_issuers is not None else DEFAULT_ALLOWED_ISSUERS
        self._revoked_jtis: set[str] = set()
        self._public_key = self._load_public_key()

        logger.info(
            "[jwt_verifier] inicializado — key=%s grace=%.0fs issuers=%s",
            self._public_key_path,
            self._grace_period,
            self._allowed_issuers,
        )

    def _load_public_key(self):
        """
        Carga la clave pública desde PEM.
        Falla explícitamente si el archivo no existe o está corrupto.
        Nunca opera sin clave válida — es más seguro fallar que asumir.
        """
        if not self._public_key_path.exists():
            raise FileNotFoundError(
                f"Clave pública no encontrada: {self._public_key_path}\n"
                f"Copiar desde el servidor central: "
                f"scp vtr-server:/etc/vtr-continuity/public_key.pem "
                f"{self._public_key_path}"
            )

        try:
            pem_data = self._public_key_path.read_bytes()
            if not pem_data:
                raise ValueError("Archivo de clave pública está vacío")

            key = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend(),
            )
            logger.info("[jwt_verifier] clave pública cargada OK")
            return key

        except (ValueError, TypeError) as exc:
            raise ValueError(f"Clave pública inválida o corrupta: {exc}") from exc

    @classmethod
    def from_pem_bytes(
        cls,
        public_pem: bytes,
        grace_period: float = DEFAULT_GRACE_PERIOD,
        allowed_issuers: set[str] | None = None,
    ) -> "RPiJWTVerifier":
        """
        Crea un verificador desde bytes PEM directamente.
        Útil en tests y despliegues donde la clave viene de una variable
        de entorno en lugar de un archivo.
        """
        if not public_pem:
            raise ValueError("public_pem no puede ser vacío o None")
        if grace_period < 0:
            raise ValueError("grace_period no puede ser negativo")

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            tmp.write(public_pem)
            tmp_path = Path(tmp.name)

        instance = cls(
            public_key_path=tmp_path,
            grace_period=grace_period,
            allowed_issuers=allowed_issuers,
        )
        tmp_path.unlink(missing_ok=True)
        return instance

    def verify(
        self,
        token: str | None,
        required_scope: str | None = None,
        allow_grace: bool = False,
    ) -> RPiVerifyResult:
        """
        Verifica un JWT presentado por un HMI.

        Pasos en orden:
          1. Validar que token no es None ni vacío
          2. Verificar firma RS256 con clave pública local
          3. Verificar expiración (o grace period si allow_grace=True)
          4. Verificar issuer contra lista permitida
          5. Verificar JTI no revocado
          6. Verificar campos obligatorios: sub, hmi_type, jti
          7. Verificar scope si se requiere

        Args:
            token:          JWT presentado por el HMI
            required_scope: Scope mínimo requerido para esta operación
            allow_grace:    Activar grace period (cuando servidor está offline)

        Returns:
            RPiVerifyResult con valid, payload, error, hmi_id, hmi_type, scopes
        """
        if token is None:
            return RPiVerifyResult(valid=False, payload=None, error="token es None")

        if not isinstance(token, str) or not token.strip():
            return RPiVerifyResult(
                valid=False, payload=None,
                error="token vacío o tipo inválido",
            )

        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[DEFAULT_ALGORITHM],
                options={"verify_exp": True},
            )
        except jwt.ExpiredSignatureError:
            if allow_grace:
                return self._try_grace(token, required_scope)
            return RPiVerifyResult(
                valid=False, payload=None,
                error="token expirado — servidor offline y grace period desactivado",
            )
        except jwt.InvalidTokenError as exc:
            return RPiVerifyResult(
                valid=False, payload=None,
                error=f"token inválido: {exc}",
            )

        return self._validate_payload(payload, required_scope, extended_offline=False)

    def revoke_jti(self, jti: str | None) -> bool:
        """
        Registra un JTI como revocado.

        El servidor central envía JTIs a revocar cuando detecta
        compromiso de sesión. El RPi los registra en memoria y los
        rechaza aunque la firma sea válida.

        En v0.5.0 esta lista se sincronizará via CustodyManager
        al reconectar con el servidor central.
        """
        if jti is None or not isinstance(jti, str) or not jti.strip():
            return False

        self._revoked_jtis.add(jti.strip())
        logger.warning("[jwt_verifier] JTI revocado registrado: %s", jti)
        return True

    def revoke_batch(self, jtis: list[str] | None) -> int:
        """
        Registra múltiples JTIs revocados en una sola llamada.
        Usado cuando el servidor envía la lista completa al reconectar.
        """
        if jtis is None or not isinstance(jtis, list):
            return 0

        count = 0
        for jti in jtis:
            if self.revoke_jti(jti):
                count += 1
        return count

    def is_revoked(self, jti: str | None) -> bool:
        """Consulta si un JTI está en la lista de revocación local."""
        if jti is None or not isinstance(jti, str):
            return False
        return jti.strip() in self._revoked_jtis

    def clear_revocation_list(self) -> int:
        """
        Limpia la lista de revocación local.
        Llamar tras sincronización exitosa con el servidor central.
        Resource-constrained: evita que la lista crezca indefinidamente.
        """
        count = len(self._revoked_jtis)
        self._revoked_jtis.clear()
        logger.info("[jwt_verifier] lista de revocacion limpiada — %d entradas", count)
        return count

    def reload_public_key(self) -> bool:
        """
        Recarga la clave pública desde disco sin reiniciar el proceso.
        Útil para rotación de claves en producción.
        """
        try:
            self._public_key = self._load_public_key()
            logger.info("[jwt_verifier] clave pública recargada OK")
            return True
        except Exception as exc:
            logger.error("[jwt_verifier] error al recargar clave pública: %s", exc)
            return False

    def _validate_payload(
        self,
        payload: dict | None,
        required_scope: str | None,
        extended_offline: bool,
    ) -> RPiVerifyResult:
        """
        Valida todos los campos del payload con verificación explícita de nulls.
        Se aplica la regla del proyecto: nunca asumir que un campo existe.
        """
        if payload is None:
            return RPiVerifyResult(valid=False, payload=None, error="payload es None")

        if not isinstance(payload, dict):
            return RPiVerifyResult(
                valid=False, payload=None,
                error="payload no es un diccionario",
            )

        jti = payload.get("jti")
        if not jti or not isinstance(jti, str):
            return RPiVerifyResult(
                valid=False, payload=None,
                error="jti ausente o inválido en payload",
            )

        if jti in self._revoked_jtis:
            return RPiVerifyResult(
                valid=False, payload=None,
                error=f"token revocado — jti={jti}",
            )

        iss = payload.get("iss")
        if not iss or not isinstance(iss, str):
            return RPiVerifyResult(
                valid=False, payload=None,
                error="iss ausente o inválido en payload",
            )

        if iss not in self._allowed_issuers:
            return RPiVerifyResult(
                valid=False, payload=None,
                error=f"issuer '{iss}' no autorizado — permitidos: {self._allowed_issuers}",
            )

        sub = payload.get("sub")
        if not sub or not isinstance(sub, str):
            return RPiVerifyResult(
                valid=False, payload=None,
                error="sub ausente o inválido en payload",
            )

        hmi_type = payload.get("hmi_type")
        if not hmi_type or not isinstance(hmi_type, str):
            return RPiVerifyResult(
                valid=False, payload=None,
                error="hmi_type ausente o inválido en payload",
            )

        scopes = payload.get("scopes")
        if not isinstance(scopes, list):
            return RPiVerifyResult(
                valid=False, payload=None,
                error="scopes ausente o tipo inválido en payload",
            )

        if required_scope is not None:
            if required_scope not in scopes:
                return RPiVerifyResult(
                    valid=False, payload=None,
                    error=f"scope '{required_scope}' no autorizado para hmi_id={sub}",
                )

        return RPiVerifyResult(
            valid=True,
            payload=payload,
            error=None,
            extended_offline=extended_offline,
            hmi_id=sub,
            hmi_type=hmi_type,
            scopes=scopes,
        )

    def _try_grace(
        self,
        token: str,
        required_scope: str | None,
    ) -> RPiVerifyResult:
        """
        Intenta verificar un token expirado dentro del grace_period.

        Si el token venció pero todavía está dentro del margen de gracia,
        se acepta marcando extended_offline=True. Esto permite que los
        HMIs sigan operando cuando el servidor central no está disponible.
        """
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[DEFAULT_ALGORITHM],
                options={"verify_exp": False},
            )
        except jwt.InvalidTokenError as exc:
            return RPiVerifyResult(
                valid=False, payload=None,
                error=f"token inválido incluso sin verificar expiración: {exc}",
            )

        exp = payload.get("exp")
        if exp is None or not isinstance(exp, (int, float)):
            return RPiVerifyResult(
                valid=False, payload=None,
                error="campo exp ausente o inválido en payload",
            )

        tiempo_vencido = time.time() - exp
        if tiempo_vencido > self._grace_period:
            return RPiVerifyResult(
                valid=False, payload=None,
                error=(
                    f"token expirado hace {tiempo_vencido:.0f}s — "
                    f"fuera del grace_period ({self._grace_period:.0f}s)"
                ),
            )

        logger.warning(
            "[jwt_verifier] grace period activo — hmi=%s vencido_hace=%.0fs",
            payload.get("sub", "unknown"),
            tiempo_vencido,
        )

        return self._validate_payload(payload, required_scope, extended_offline=True)
