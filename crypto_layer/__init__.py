"""
crypto_layer/__init__.py — API pública del módulo criptográfico.

Propuesta #4 de 10 — VTR Continuity v0.5.0.

Implementa el contrato de la decisión 1B (docs/DECISIONS-v0.5.0.md):
derive_device_key() y derive_operator_key() como métodos separados, con
capability separation explícita — un atacante con acceso físico al
dispositivo que obtiene device_key NO obtiene acceso a datos protegidos
con operator_key.

Toda validación de inputs ocurre ANTES de invocar PyNaCl/cryptography
(VTR-CRYPTO-003) — ver crypto_layer/errors.py para la jerarquía de
excepciones usada aquí.

NOTA DE ESTADO: el mecanismo que genera y almacena `device_secret` en una
partición read-only firmada por CA es diseño pendiente (VTR-CRYPTO-002,
VTR-CRYPTO-001 §8). Esta clase acepta `device_secret` como bytes ya
provistos por el caller — no lo genera, no lo busca en disco, no asume
que existe un mecanismo de almacenamiento real todavía.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Literal

from crypto_layer.errors import (
    InvalidPassphraseError,
    InvalidHardwareIDError,
    InvalidDeviceSecretError,
    InvalidKeyLengthError,
)

# Constantes de validación — ningún valor mágico disperso en el código.
DEVICE_SECRET_LENGTH_BYTES = 32
MIN_MASTER_KEY_LENGTH_BYTES = 32
MAX_PASSPHRASE_LENGTH_BYTES = 1024  # límite razonable contra DoS por input gigante

ArgonProfile = Literal["embedded", "desktop", "hardened"]


# ──────────────────────────────────────────────────────────────────────────
# Configuración — dataclass plano, sin parsing de YAML
# ──────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CryptoConfig:
    """Configuración de CryptoLayer.

    Deliberadamente un dataclass plano, sin método from_yaml() ni lógica de
    parsing de archivo. Razón de diseño: si esta clase supiera leer
    rf_config.yaml directamente, la validación del catálogo cerrado de
    profiles (embedded | desktop | hardened) y de rutas/tipos quedaría
    mezclada dentro de la capa criptográfica central, en lugar de vivir en
    una capa de configuración separada (propuesta #8) que valida y falla
    ANTES de que cualquier dato llegue aquí. CryptoLayer nunca parsea texto
    de un archivo de configuración que pudiera haber sido modificado por un
    actor con acceso al sistema de archivos — solo recibe un CryptoConfig
    ya validado por el llamador.

    `frozen=True` — una vez construido, no se puede mutar en caliente; un
    cambio de configuración requiere construir un CryptoConfig nuevo,
    nunca editar atributos de uno existente en memoria.
    """

    argon2id_profile: ArgonProfile = "desktop"
    session_cache_ttl_seconds: int = 3600
    derivation_async: bool = True

    def __post_init__(self) -> None:
        if self.argon2id_profile not in ("embedded", "desktop", "hardened"):
            # Import local para evitar ciclo de import en el módulo de errores
            from crypto_layer.errors import InvalidProfileError
            raise InvalidProfileError(
                f"argon2id_profile debe ser uno de embedded|desktop|hardened, "
                f"recibido: {self.argon2id_profile!r}"
            )
        if self.session_cache_ttl_seconds <= 0:
            from crypto_layer.errors import MissingConfigFieldError
            raise MissingConfigFieldError(
                f"session_cache_ttl_seconds debe ser positivo, "
                f"recibido: {self.session_cache_ttl_seconds}"
            )


# ──────────────────────────────────────────────────────────────────────────
# API pública
# ──────────────────────────────────────────────────────────────────────────

class CryptoLayer:
    """API pública de criptografía para VTR Continuity.

    Implementa la decisión 1B: dos métodos de derivación separados con
    capability separation, en vez de un único método con parámetro
    opcional de passphrase (ver docs/DECISIONS-v0.5.0.md, Decisión 1,
    para el análisis completo de por qué se rechazaron las opciones 1A
    y 1C).
    """

    def __init__(self, config: CryptoConfig) -> None:
        if config is None:
            raise InvalidHardwareIDError("config no puede ser None")
        self._config = config
        # Caché de sesión en memoria — nunca persistido a disco, nunca
        # serializado. Se invalida al cambiar de passphrase (ver nota en
        # tests/test_crypto_layer.py, propuesta #9, caso adversarial
        # test_session_cache_invalidated_on_passphrase_change).
        self._session_cache: dict[bytes, bytes] = {}

    # ── Validación interna compartida ──────────────────────────────────

    @staticmethod
    def _validate_hardware_id(hardware_id: bytes) -> None:
        if hardware_id is None:
            raise InvalidHardwareIDError("hardware_id no puede ser None")
        if not isinstance(hardware_id, bytes):
            raise InvalidHardwareIDError(
                f"hardware_id debe ser bytes, recibido {type(hardware_id).__name__}"
            )
        if len(hardware_id) == 0:
            raise InvalidHardwareIDError("hardware_id no puede estar vacío")

    @staticmethod
    def _validate_device_secret(device_secret: bytes) -> None:
        if device_secret is None:
            raise InvalidDeviceSecretError("device_secret no puede ser None")
        if not isinstance(device_secret, bytes):
            raise InvalidDeviceSecretError(
                f"device_secret debe ser bytes, recibido {type(device_secret).__name__}"
            )
        if len(device_secret) != DEVICE_SECRET_LENGTH_BYTES:
            raise InvalidDeviceSecretError(
                f"device_secret debe ser exactamente {DEVICE_SECRET_LENGTH_BYTES} "
                f"bytes, recibido {len(device_secret)}"
            )

    @staticmethod
    def _validate_passphrase(passphrase: bytes) -> None:
        if passphrase is None:
            raise InvalidPassphraseError("passphrase no puede ser None")
        if not isinstance(passphrase, bytes):
            raise InvalidPassphraseError(
                f"passphrase debe ser bytes, recibido {type(passphrase).__name__}"
            )
        if len(passphrase) == 0:
            raise InvalidPassphraseError("passphrase no puede estar vacía")
        if len(passphrase) > MAX_PASSPHRASE_LENGTH_BYTES:
            raise InvalidPassphraseError(
                f"passphrase excede el límite de {MAX_PASSPHRASE_LENGTH_BYTES} bytes "
                f"(recibida: {len(passphrase)} bytes) — posible intento de DoS"
            )

    # ── Derivación de claves (decisión 1B) ─────────────────────────────

    def derive_device_key(
        self,
        hardware_id: bytes,
        device_secret: bytes,
    ) -> bytes:
        """Deriva la device_key para servicios unattended (proxy DMZ).

        Nunca falla por falta de passphrase — no la requiere ni la acepta.
        Falla si hardware_id o device_secret están vacíos, son None, o
        device_secret no tiene exactamente 32 bytes (VTR-CRYPTO-001 §3,
        VTR-CRYPTO-002).

        Capability separation: la device_key resultante NO puede usarse
        para desbloquear datos protegidos con operator_key (snapshots de
        sesión sensibles, llaves de canal extremo, sneakernet). Un
        atacante con acceso físico al dispositivo que extrae
        device_secret obtiene device_key, pero no operator_key.
        """
        self._validate_hardware_id(hardware_id)
        self._validate_device_secret(device_secret)
        return self._argon2id_derive(
            salt=device_secret,
            info=hardware_id,
            context=b"vtr-device-key-v1",
        )

    def derive_operator_key(
        self,
        hardware_id: bytes,
        device_secret: bytes,
        passphrase: bytes,
    ) -> bytes:
        """Deriva la operator_key para sesión humana. Passphrase obligatoria.

        Falla si cualquier input es None o vacío — a diferencia de
        derive_device_key, aquí la ausencia de passphrase es un error,
        nunca un valor por defecto silencioso.
        """
        self._validate_hardware_id(hardware_id)
        self._validate_device_secret(device_secret)
        self._validate_passphrase(passphrase)
        # El salt combina device_secret (alta entropía) con la passphrase
        # humana (baja entropía) — Argon2id es la primitiva correcta aquí
        # precisamente porque uno de los dos factores es de baja entropía
        # (VTR-CRYPTO-001 regla 001).
        return self._argon2id_derive(
            salt=device_secret,
            info=hardware_id + passphrase,
            context=b"vtr-operator-key-v1",
        )

    async def derive_device_key_async(
        self,
        hardware_id: bytes,
        device_secret: bytes,
    ) -> bytes:
        """Versión async de derive_device_key — no bloquea el boot del proxy.

        Misma firma y misma validación que la versión síncrona, ejecutada
        en un thread aparte vía asyncio.to_thread(). Se mantienen los
        mismos parámetros explícitos (hardware_id, device_secret) en vez
        de leerlos desde un estado interno cacheado: los bytes sensibles
        viven en memoria solo durante la llamada, no como atributo mutable
        de la instancia, lo que limita la ventana de exposición y evita
        que un cambio de estado interno entre llamadas produzca resultados
        inconsistentes.

        Decisión 2D (docs/DECISIONS-v0.5.0.md): el proxy queda operativo
        en <2s mientras esta derivación corre en paralelo; la device_key
        está disponible ~200ms después, antes de que llegue la primera
        petición criptográfica real.
        """
        self._validate_hardware_id(hardware_id)
        self._validate_device_secret(device_secret)
        return await asyncio.to_thread(
            self._argon2id_derive,
            salt=device_secret,
            info=hardware_id,
            context=b"vtr-device-key-v1",
        )

    # ── Expansión de subclaves ──────────────────────────────────────────

    def expand_subkey(
        self,
        master_key: bytes,
        context: bytes,
        info: bytes,
        length: int = 32,
    ) -> bytes:
        """Expande subclaves desde una clave maestra de alta entropía.

        Usa HKDF-SHA256, no Argon2id — master_key ya tiene alta entropía
        (es resultado de una derivación previa o un secreto generado por
        CSPRNG), así que re-derivar con una función memory-hard sería
        costoso e innecesario (VTR-CRYPTO-001 §2, tabla de uso correcto).
        """
        if master_key is None:
            raise InvalidKeyLengthError("master_key no puede ser None")
        if not isinstance(master_key, bytes):
            raise InvalidKeyLengthError(
                f"master_key debe ser bytes, recibido {type(master_key).__name__}"
            )
        if len(master_key) < MIN_MASTER_KEY_LENGTH_BYTES:
            raise InvalidKeyLengthError(
                f"master_key debe tener al menos {MIN_MASTER_KEY_LENGTH_BYTES} "
                f"bytes, recibido {len(master_key)}"
            )
        if info is None or len(info) == 0:
            raise InvalidKeyLengthError("info no puede ser None ni vacío")
        if length <= 0:
            raise InvalidKeyLengthError(f"length debe ser positivo, recibido {length}")

        from crypto_layer.hkdf_expand import hkdf_expand  # propuesta #6
        return hkdf_expand(master_key=master_key, salt=context, info=info, length=length)

    # ── Firma y verificación de bundles .vtrc ──────────────────────────

    def sign_bundle(
        self,
        bundle_bytes: bytes,
        signing_key: bytes,
    ) -> bytes:
        """Firma un bundle .vtrc con Ed25519.

        Implementación delegada a crypto_layer/ed25519_sign.py (propuesta
        #7) — esta capa solo valida inputs antes de delegar (VTR-CRYPTO-003).
        """
        if bundle_bytes is None or len(bundle_bytes) == 0:
            raise InvalidKeyLengthError("bundle_bytes no puede ser None ni vacío")
        if signing_key is None:
            raise InvalidKeyLengthError("signing_key no puede ser None")

        from crypto_layer.ed25519_sign import sign  # propuesta #7
        return sign(message=bundle_bytes, private_key=signing_key)

    def verify_bundle(
        self,
        bundle_bytes: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Verifica firma Ed25519 de un bundle .vtrc.

        Contrato deliberado: retorna False si la firma no es válida, NO
        lanza SignatureVerificationError. Esa excepción existe para capas
        superiores que necesiten tratar una firma inválida como evento
        excepcional (p. ej. rechazar un bundle completo en el flujo de
        recepción), pero esta función de bajo nivel se mantiene como
        predicado puro — ver docstring de SignatureVerificationError en
        crypto_layer/errors.py.
        """
        if bundle_bytes is None or signature is None or public_key is None:
            # Inputs estructuralmente inválidos no son "firma incorrecta",
            # son un error de uso de la API — sí lanza excepción aquí.
            raise InvalidKeyLengthError(
                "bundle_bytes, signature y public_key no pueden ser None"
            )

        from crypto_layer.ed25519_sign import verify  # propuesta #7
        return verify(message=bundle_bytes, signature=signature, public_key=public_key)

    # ── Derivación interna (delegada a la propuesta #5) ────────────────

    def _argon2id_derive(self, salt: bytes, info: bytes, context: bytes) -> bytes:
        """Punto único de entrada a la derivación Argon2id real.

        Implementación completa (carga de profile, validación de catálogo,
        caché de sesión) vive en crypto_layer/argon2_derive.py (propuesta
        #5) — este método es el adaptador que CryptoLayer expone hacia
        afuera, manteniendo argon2_derive.py desacoplado de la API pública.
        """
        from crypto_layer.argon2_derive import derive  # propuesta #5
        return derive(
            salt=salt,
            info=info,
            context=context,
            profile=self._config.argon2id_profile,
        )
