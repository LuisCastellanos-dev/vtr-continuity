"""
crypto_layer/field_config_verifier.py — Verificación de firma para
configuración de campo (Q-03).

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5) — implementa la
decisión documentada en docs/VTR-ARCH-DECISIONS-001.md Q-03: el archivo
de configuración que llega por una vía física (USB, puerto serie) en
campo se trata como objeto firmado, no como confianza implícita por
ubicación. Sin firma válida de la clave `intermediate` de la PKI
(docs/VTR-PKI-001.md), el RPi conserva su configuración actual y
registra el intento — nunca falla abierto a un default.

DECISIÓN DE ALCANCE (igual patrón que crypto_layer/rf_config_loader.py):
este módulo es un archivo NUEVO y SEPARADO. No modifica
rf_config_loader.py — la verificación de firma ocurre ANTES de que el
YAML llegue a load_crypto_config(), como un paso de validación adicional
en el punto de entrada. rf_config_loader.py sigue sin saber nada sobre
firmas, exactamente como su propio docstring ya documentaba como
decisión de alcance cerrada.

DECISIÓN DE FORMATO (distinta de crypto_layer/vtrc_bundle.py
deliberadamente): el bundle .vtrc requiere (node_id, counter) en su
header porque protege contra replay de TRÁFICO OPERATIVO — un bundle de
datos repetido es una amenaza real (Q-02). Una configuración de campo no
tiene esa misma semántica: un atacante reproduciendo una config VIEJA
PERO LEGÍTIMAMENTE FIRMADA no es automáticamente un ataque — podría ser
un rollback intencional a una configuración anterior conocida y
aprobada. Forzar un campo `counter` aquí, sin una razón de seguridad
real que lo sostenga, sería agregar complejidad y una superficie de
fallo (¿qué counter usa el operador que firma una config nueva?) sin
beneficio de seguridad correspondiente. La propia decisión de Q-03
documentada habla de "reusar la misma primitiva de firma/verificación
de ed25519_sign.py" — no de reusar el formato de bundle .vtrc completo.
Por eso este módulo usa directamente sign()/verify(), con un formato
mínimo propio: signature (64 bytes) || yaml_bytes.

Si en el futuro se decide que las configs de campo SÍ necesitan
protección anti-rollback (ej. para prevenir que un atacante reinstale
una config vieja que tenía un profile Argon2id más débil), esa es una
decisión de seguridad nueva y explícita — no algo que deba colarse
implícitamente por reusar un formato diseñado para otro propósito.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
from pathlib import Path

from crypto_layer.ed25519_sign import (
    PUBLIC_KEY_LENGTH_BYTES,
    SIGNATURE_LENGTH_BYTES,
    sign,
    verify,
)
from crypto_layer.errors import (
    InvalidKeyLengthError,
    SignatureVerificationError,
)

logger = logging.getLogger(__name__)


def sign_field_config(yaml_bytes: bytes, intermediate_private_key: bytes) -> bytes:
    """
    Firma un archivo de configuración de campo con la clave privada de
    la `intermediate` CA.

    Esta función la ejecuta quien AUTORIZA una reconfiguración (con
    acceso a la clave privada de la `intermediate`, custodiada según
    docs/VTR-PKI-001.md) — nunca el RPi en campo, que solo tiene la
    llave pública para verificar.

    Args:
        yaml_bytes: contenido crudo del archivo rf_config.yaml a firmar,
            ya validado por quien lo autoriza (este módulo no valida el
            contenido del YAML — esa responsabilidad sigue siendo de
            crypto_layer/rf_config_loader.py, después de la verificación
            de firma).
        intermediate_private_key: 32 bytes, llave privada Ed25519 de la
            `intermediate` CA.

    Returns:
        bytes del archivo firmado, listo para escribir a USB:
        signature (64 bytes) || yaml_bytes.

    Raises:
        InvalidKeyLengthError: validación defensiva de inputs
            (VTR-CRYPTO-003) — None, tipo incorrecto, o yaml_bytes
            vacío.
    """
    if yaml_bytes is None:
        raise InvalidKeyLengthError("yaml_bytes no puede ser None")
    if not isinstance(yaml_bytes, bytes):
        raise InvalidKeyLengthError(
            f"yaml_bytes debe ser bytes, recibido {type(yaml_bytes).__name__}"
        )
    if len(yaml_bytes) == 0:
        raise InvalidKeyLengthError("yaml_bytes no puede ser vacío")

    if intermediate_private_key is None:
        raise InvalidKeyLengthError("intermediate_private_key no puede ser None")
    if not isinstance(intermediate_private_key, bytes):
        raise InvalidKeyLengthError(
            f"intermediate_private_key debe ser bytes, recibido "
            f"{type(intermediate_private_key).__name__}"
        )

    signature = sign(yaml_bytes, intermediate_private_key)
    return signature + yaml_bytes


def verify_field_config(
    signed_bytes: bytes, intermediate_public_key: bytes
) -> bytes:
    """
    Verifica la firma de un archivo de configuración de campo y, si es
    válida, retorna los bytes del YAML para pasar a
    crypto_layer.rf_config_loader.load_crypto_config().

    Este es el punto de entrada que la decisión de Q-03 describe: se
    ejecuta ANTES de que el YAML llegue al loader existente.
    load_crypto_config() no se modifica — sigue recibiendo una ruta de
    archivo YAML normal, ya verificado, exactamente como hoy.

    Args:
        signed_bytes: bytes leídos directamente del archivo en USB/puerto
            serie — formato signature (64 bytes) || yaml_bytes.
        intermediate_public_key: 32 bytes, llave pública Ed25519 de la
            `intermediate` CA esperada. El RPi en campo solo tiene esta
            llave pública — nunca la privada.

    Returns:
        Los yaml_bytes ya verificados, listos para escribirse a la ruta
        que rf_config_loader.load_crypto_config() espera, o para
        procesarse en memoria si el llamador lo prefiere.

    Raises:
        InvalidKeyLengthError: si los inputs son inválidos en tipo o
            longitud (None, tipo incorrecto, signed_bytes más corto que
            el tamaño mínimo de una firma) — error de uso de la API, no
            "firma incorrecta".
        SignatureVerificationError: si la firma no verifica contra
            intermediate_public_key. Este es el caso central de Q-03 —
            el RPi NO debe aplicar esta configuración. El llamador debe
            capturar esta excepción y conservar la configuración
            actual, registrando el intento (ver docstring del módulo:
            "nunca falla abierto a un default").
    """
    if signed_bytes is None:
        raise InvalidKeyLengthError("signed_bytes no puede ser None")
    if not isinstance(signed_bytes, bytes):
        raise InvalidKeyLengthError(
            f"signed_bytes debe ser bytes, recibido {type(signed_bytes).__name__}"
        )
    if len(signed_bytes) <= SIGNATURE_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"signed_bytes ({len(signed_bytes)} bytes) debe ser mayor que "
            f"SIGNATURE_LENGTH_BYTES ({SIGNATURE_LENGTH_BYTES}) — no contiene "
            f"un payload YAML después de la firma"
        )

    if intermediate_public_key is None:
        raise InvalidKeyLengthError("intermediate_public_key no puede ser None")
    if not isinstance(intermediate_public_key, bytes):
        raise InvalidKeyLengthError(
            f"intermediate_public_key debe ser bytes, recibido "
            f"{type(intermediate_public_key).__name__}"
        )
    if len(intermediate_public_key) != PUBLIC_KEY_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"intermediate_public_key debe ser exactamente "
            f"{PUBLIC_KEY_LENGTH_BYTES} bytes, recibido "
            f"{len(intermediate_public_key)}"
        )

    signature = signed_bytes[:SIGNATURE_LENGTH_BYTES]
    yaml_bytes = signed_bytes[SIGNATURE_LENGTH_BYTES:]

    is_valid = verify(yaml_bytes, signature, intermediate_public_key)

    if not is_valid:
        logger.error(
            "[field_config_verifier] firma inválida en configuración de "
            "campo — RECHAZADA. La configuración actual del dispositivo "
            "se conserva sin cambios. Esto puede indicar: (a) un archivo "
            "de configuración corrupto, (b) una clave pública configurada "
            "incorrectamente, o (c) un intento de reconfiguración no "
            "autorizada. Investigar antes de reintentar."
        )
        raise SignatureVerificationError(
            "Firma de configuración de campo inválida — configuración "
            "RECHAZADA, dispositivo conserva su configuración actual"
        )

    return yaml_bytes


def verify_and_write_field_config(
    signed_bytes: bytes,
    intermediate_public_key: bytes,
    destination_path: str | Path,
) -> Path:
    """
    Conveniencia: verifica la firma y, solo si es válida, escribe el
    YAML verificado a destination_path — la ruta que
    crypto_layer.rf_config_loader.load_crypto_config() espera leer
    después.

    Separado de verify_field_config() (que solo verifica y retorna
    bytes) para que el llamador pueda optar por procesar el YAML en
    memoria sin tocar disco, si su flujo de integración lo requiere —
    mismo principio de capability separation que el resto de
    crypto_layer ya aplica (ej. parse_bundle() vs. verify_bundle() en
    vtrc_bundle.py).

    Args:
        signed_bytes: ver verify_field_config().
        intermediate_public_key: ver verify_field_config().
        destination_path: ruta donde escribir el YAML verificado — debe
            ser la misma ruta que load_crypto_config() leerá después.

    Returns:
        Path de destination_path, para encadenar directamente con
        load_crypto_config(destination_path) si el llamador lo desea.

    Raises:
        Las mismas excepciones que verify_field_config() — si la firma
        es inválida, NUNCA se escribe a destination_path. El archivo
        existente en esa ruta (la configuración actual) queda intacto.
    """
    yaml_bytes = verify_field_config(signed_bytes, intermediate_public_key)

    path = Path(destination_path)
    path.write_bytes(yaml_bytes)

    logger.info(
        "[field_config_verifier] configuración de campo verificada y "
        "aplicada en %s",
        str(path),
    )

    return path
