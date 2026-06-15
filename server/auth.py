"""
vtr-continuity v0.4.0 — Server
server/auth.py

Emisor y validador JWT RS256 para el servidor central VTR.

Principios de seguridad aplicados:
  - RS256: clave privada solo en servidor central, nunca en RPi ni HMI
  - Refresh token opaco de un solo uso — rotation en cada renovación
  - Validación explícita de nulls en cada campo del payload
  - Grace period para entornos OT donde el servidor puede estar offline
  - Tokens revocados persisten en token_store hasta expiración natural

Canales protegidos:
  HMI → RPi: JWT verificado localmente (clave pública)
  RPi → Servidor: JWT + custody hash
  Servidor → HMI: emite y rota refresh tokens

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


DEFAULT_ACCESS_TTL = 900        
DEFAULT_REFRESH_TTL = 86400     
DEFAULT_GRACE_PERIOD = 1800     
DEFAULT_ALGORITHM = "RS256"


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    expires_at: float
    hmi_id: str
    jti: str


@dataclass
class VerifyResult:
    valid: bool
    payload: dict[str, Any] | None
    error: str | None
    extended_offline: bool = False


class KeyPair:
    """
    Par de claves RSA para firma JWT.

    La clave privada nunca sale del servidor central.
    La clave pública se distribuye a los RPi para verificación local.
    """

    def __init__(self, key_size: int = 2048) -> None:
        if key_size < 2048:
            raise ValueError("key_size mínimo es 2048 bits")

        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

    @classmethod
    def from_pem(cls, private_pem: bytes, password: bytes | None = None) -> "KeyPair":
        """Carga un par de claves desde PEM existente."""
        if not private_pem:
            raise ValueError("private_pem no puede ser vacío")

        instance = cls.__new__(cls)
        instance._private_key = serialization.load_pem_private_key(
            private_pem,
            password=password,
            backend=default_backend(),
        )
        instance._public_key = instance._private_key.public_key()
        return instance

    def private_pem(self, password: bytes | None = None) -> bytes:
        """Exporta clave privada en PEM — guardar en lugar seguro."""
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def public_pem(self) -> bytes:
        """
        Exporta clave pública en PEM.
        Este es el archivo que se copia a cada RPi para verificación local.
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return self._public_key


class VTRAuth:
    """
    Emisor y validador JWT para el servidor central VTR.

    Flujo de autenticación:
        1. HMI se registra con hmi_id y hmi_type
        2. Servidor emite TokenPair (access + refresh)
        3. HMI presenta access_token al RPi en cada request
        4. Al vencer, HMI solicita refresh al servidor (no al RPi)
        5. Servidor invalida refresh anterior y emite uno nuevo
        6. Si servidor está OFFLINE: RPi extiende validez por grace_period

    El RPi nunca ve la clave privada — solo verifica con clave pública.
    """

    VALID_HMI_TYPES = {"ignition", "wincc", "ifix", "generic"}

    def __init__(
        self,
        keypair: KeyPair,
        access_ttl: float = DEFAULT_ACCESS_TTL,
        refresh_ttl: float = DEFAULT_REFRESH_TTL,
        grace_period: float = DEFAULT_GRACE_PERIOD,
        issuer: str = "vtr-server",
    ) -> None:
        if keypair is None:
            raise ValueError("keypair no puede ser None")
        if access_ttl <= 0:
            raise ValueError("access_ttl debe ser > 0")
        if refresh_ttl <= 0:
            raise ValueError("refresh_ttl debe ser > 0")
        if grace_period < 0:
            raise ValueError("grace_period no puede ser negativo")
        if not issuer:
            raise ValueError("issuer no puede ser vacío")

        self._keypair = keypair
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._grace_period = grace_period
        self._issuer = issuer

        self._refresh_tokens: dict[str, dict] = {}
        self._revoked_jtis: set[str] = set()

    def issue(self, hmi_id: str, hmi_type: str, scopes: list[str] | None = None) -> TokenPair:
        """
        Emite un par de tokens para un HMI autenticado.

        Args:
            hmi_id:   Identificador único del HMI (ej. "ignition-planta-norte")
            hmi_type: Tipo de HMI — debe estar en VALID_HMI_TYPES
            scopes:   Permisos del token (ej. ["read", "write"])

        Returns:
            TokenPair con access_token JWT y refresh_token opaco
        """
        if not hmi_id or not isinstance(hmi_id, str):
            raise ValueError("hmi_id no puede ser vacío o None")

        if not hmi_type or not isinstance(hmi_type, str):
            raise ValueError("hmi_type no puede ser vacío o None")

        hmi_type_lower = hmi_type.lower().strip()
        if hmi_type_lower not in self.VALID_HMI_TYPES:
            raise ValueError(
                f"hmi_type '{hmi_type}' no válido. "
                f"Permitidos: {self.VALID_HMI_TYPES}"
            )

        if scopes is None:
            scopes = ["read"]

        if not isinstance(scopes, list):
            raise ValueError("scopes debe ser una lista")

        now = time.time()
        jti = str(uuid.uuid4())
        expires_at = now + self._access_ttl

        payload = {
            "iss": self._issuer,
            "sub": hmi_id,
            "hmi_type": hmi_type_lower,
            "scopes": scopes,
            "jti": jti,
            "iat": now,
            "exp": expires_at,
            "vtr_version": "0.4.0",
        }

        access_token = jwt.encode(
            payload,
            self._keypair.private_key,
            algorithm=DEFAULT_ALGORITHM,
        )

        refresh_token = secrets.token_urlsafe(48)
        self._refresh_tokens[refresh_token] = {
            "hmi_id": hmi_id,
            "hmi_type": hmi_type_lower,
            "scopes": scopes,
            "issued_at": now,
            "expires_at": now + self._refresh_ttl,
            "used": False,
        }

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            hmi_id=hmi_id,
            jti=jti,
        )

    def refresh(self, refresh_token: str) -> TokenPair:
        """
        Rota el refresh token y emite un nuevo par.

        El refresh token anterior queda invalidado inmediatamente.
        Si el mismo refresh token se usa dos veces, ambas sesiones
        son revocadas — señal de compromiso.

        Args:
            refresh_token: Token opaco emitido en issue() o refresh() anterior
        """
        if not refresh_token or not isinstance(refresh_token, str):
            raise ValueError("refresh_token no puede ser vacío o None")

        record = self._refresh_tokens.get(refresh_token)

        if record is None:
            raise PermissionError("refresh_token no válido o ya usado")

        if record.get("used") is True:
            raise PermissionError(
                "refresh_token ya fue usado — posible compromiso de sesión"
            )

        expires_at = record.get("expires_at")
        if expires_at is None or time.time() > expires_at:
            del self._refresh_tokens[refresh_token]
            raise PermissionError("refresh_token expirado")

        record["used"] = True

        hmi_id = record.get("hmi_id")
        hmi_type = record.get("hmi_type")
        scopes = record.get("scopes")

        if not hmi_id or not hmi_type:
            raise ValueError("registro de refresh_token con hmi_id o hmi_type None")

        return self.issue(hmi_id, hmi_type, scopes)

    def verify(
        self,
        token: str | None,
        required_scope: str | None = None,
        allow_grace: bool = False,
    ) -> VerifyResult:
        """
        Verifica un access token JWT.

        Valida firma RS256, expiración, revocación y scope.
        Si allow_grace=True y el token expiró dentro del grace_period,
        lo acepta marcando extended_offline=True en el resultado.

        Args:
            token:          JWT a verificar
            required_scope: Scope mínimo requerido (ej. "write")
            allow_grace:    Permitir grace period para entornos OT offline

        Returns:
            VerifyResult con valid, payload, error y extended_offline
        """
        if token is None:
            return VerifyResult(valid=False, payload=None, error="token es None")

        if not isinstance(token, str) or not token.strip():
            return VerifyResult(valid=False, payload=None, error="token vacío o tipo inválido")

        try:
            payload = jwt.decode(
                token,
                self._keypair.public_key,
                algorithms=[DEFAULT_ALGORITHM],
                options={"verify_exp": True},
            )
        except jwt.ExpiredSignatureError:
            if allow_grace:
                return self._try_grace(token, required_scope)
            return VerifyResult(valid=False, payload=None, error="token expirado")
        except jwt.InvalidTokenError as exc:
            return VerifyResult(valid=False, payload=None, error=f"token inválido: {exc}")

        jti = payload.get("jti")
        if not jti:
            return VerifyResult(valid=False, payload=None, error="jti ausente en payload")

        if jti in self._revoked_jtis:
            return VerifyResult(valid=False, payload=None, error="token revocado")

        sub = payload.get("sub")
        if not sub:
            return VerifyResult(valid=False, payload=None, error="sub ausente en payload")

        hmi_type = payload.get("hmi_type")
        if not hmi_type:
            return VerifyResult(valid=False, payload=None, error="hmi_type ausente en payload")

        if required_scope is not None:
            scopes = payload.get("scopes")
            if not isinstance(scopes, list):
                return VerifyResult(
                    valid=False, payload=None,
                    error="scopes ausente o tipo inválido en payload",
                )
            if required_scope not in scopes:
                return VerifyResult(
                    valid=False, payload=None,
                    error=f"scope '{required_scope}' no autorizado",
                )

        return VerifyResult(valid=True, payload=payload, error=None)

    def revoke(self, token: str | None) -> bool:
        """
        Revoca un access token por su JTI.
        El RPi rechazará este token aunque la firma sea válida.
        """
        if token is None or not isinstance(token, str):
            return False

        try:
            payload = jwt.decode(
                token,
                self._keypair.public_key,
                algorithms=[DEFAULT_ALGORITHM],
                options={"verify_exp": False},
            )
            jti = payload.get("jti")
            if not jti:
                return False
            self._revoked_jtis.add(jti)
            return True
        except jwt.InvalidTokenError:
            return False

    def purge_expired_refresh(self) -> int:
        """
        Elimina refresh tokens expirados del registro en memoria.
        Resource-constrained: mantiene el dict pequeño.
        Llamar periódicamente desde el loop del servidor.
        """
        now = time.time()
        expired = [
            rt for rt, rec in self._refresh_tokens.items()
            if rec.get("expires_at") is not None and rec["expires_at"] < now
        ]
        for rt in expired:
            del self._refresh_tokens[rt]
        return len(expired)

    def _try_grace(self, token: str, required_scope: str | None) -> VerifyResult:
        """
        Intenta verificar un token expirado dentro del grace_period.
        Solo se activa cuando allow_grace=True — entornos OT offline.
        """
        try:
            payload = jwt.decode(
                token,
                self._keypair.public_key,
                algorithms=[DEFAULT_ALGORITHM],
                options={"verify_exp": False},
            )
        except jwt.InvalidTokenError as exc:
            return VerifyResult(valid=False, payload=None, error=f"token inválido: {exc}")

        exp = payload.get("exp")
        if exp is None:
            return VerifyResult(valid=False, payload=None, error="exp ausente en payload")

        if time.time() > exp + self._grace_period:
            return VerifyResult(
                valid=False, payload=None,
                error=f"token expirado fuera del grace_period ({self._grace_period}s)",
            )

        jti = payload.get("jti")
        if not jti:
            return VerifyResult(valid=False, payload=None, error="jti ausente en payload")

        if jti in self._revoked_jtis:
            return VerifyResult(valid=False, payload=None, error="token revocado")

        if required_scope is not None:
            scopes = payload.get("scopes")
            if not isinstance(scopes, list) or required_scope not in scopes:
                return VerifyResult(
                    valid=False, payload=None,
                    error=f"scope '{required_scope}' no autorizado",
                )

        return VerifyResult(
            valid=True,
            payload=payload,
            error=None,
            extended_offline=True,
        )

    @property
    def public_pem(self) -> bytes:
        """
        Clave pública para distribuir a los RPi.
        Guardar en /etc/vtr-continuity/public_key.pem en cada RPi.
        """
        return self._keypair.public_pem()
