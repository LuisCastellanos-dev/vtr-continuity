"""
crypto_layer/hkdf_expand.py — Expansión de subclaves vía HKDF-SHA256.

Propuesta #6 de 10 — VTR Continuity v0.5.0.

Implementa RFC 5869 HKDF-Expand. Usado para derivar subclaves desde una
clave maestra que YA tiene alta entropía (resultado de una derivación
Argon2id previa, o un device_secret generado por CSPRNG) — a diferencia de
argon2_derive.py, que existe específicamente para secretos de BAJA entropía
(VTR-CRYPTO-001 regla 001, tabla de uso correcto en §2).

Casos de uso reales en el proyecto:
- Derivación de session key desde device_key + nonce de sesión.
- Derivación de transport key desde device_key + tipo de canal
  (LoRa, BLE Mesh, Sneakernet) — cada canal de transporte obtiene una
  subclave distinta de la misma device_key, sin tener que volver a pasar
  por Argon2id (que sería costoso e innecesario, ver VTR-CRYPTO-001 §2).

Validación de longitud de master_key: este módulo valida de forma
INDEPENDIENTE de CryptoLayer.expand_subkey() (que ya valida antes de
llamar aquí) — mismo criterio de defensa en profundidad ya aplicado en
argon2_derive.py para la validación de profile.
"""

from __future__ import annotations

import hashlib
import hmac

from crypto_layer.errors import InvalidKeyLengthError

# RFC 5869 §2.2: la longitud del salt/PRK debe ser al menos la longitud del
# hash subyacente para no degradar la seguridad de la expansión. Con
# SHA-256, eso son 32 bytes — coincide además con el tamaño de
# device_secret y de las claves derivadas en todo el proyecto.
MIN_MASTER_KEY_LENGTH_BYTES = 32

# RFC 5869 §2.3: la longitud máxima de salida de HKDF-Expand es
# 255 * HashLen. Con SHA-256 (32 bytes de salida), el límite es 8160 bytes.
# VTR Continuity nunca necesita acercarse a ese límite (las subclaves son
# de 32 bytes), pero se valida explícitamente para no permitir un input
# de longitud que silenciosamente trunque o falle dentro de la librería.
MAX_OUTPUT_LENGTH_BYTES = 255 * hashlib.sha256().digest_size


def hkdf_expand(
    master_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """RFC 5869 HKDF-Expand con SHA-256.

    Nota de nomenclatura respecto al RFC: en la terminología oficial de
    RFC 5869, el parámetro que aquí se llama `master_key` corresponde al
    PRK (Pseudo-Random Key) del paso de Expand — es decir, se asume que
    master_key YA es una clave de alta entropía (producto de un HKDF-Extract
    previo, de Argon2id, o de un CSPRNG), no un secreto de baja entropía sin
    procesar. El parámetro `salt` aquí actúa como contexto adicional de
    binding (lo que el RFC llamaría parte del "info"), no como el salt del
    paso de Extract — esta capa no implementa Extract porque VTR Continuity
    siempre parte de un PRK ya derivado por otra vía (ver VTR-CRYPTO-001 §2,
    tabla de uso: HKDF se usa para EXPANSIÓN desde clave ya de alta entropía,
    nunca para procesar secretos crudos).

    Args:
        master_key: la clave de alta entropía desde la que expandir.
            Mínimo 32 bytes (RFC 5869 §2.2 — debe ser al menos la longitud
            del hash subyacente).
        salt: contexto de binding adicional (p. ej. b"vtr-session-key-v1",
            o el identificador del tipo de canal de transporte). Se
            concatena con `info` para formar el campo `info` real de
            HKDF-Expand, aplicando separación de dominio.
        info: material de binding específico del caso de uso (p. ej. un
            nonce de sesión, o un identificador de canal LoRa/BLE/Sneakernet).
        length: bytes de salida deseados. Default 32 (tamaño estándar de
            clave en todo el proyecto). Debe estar entre 1 y 8160 bytes
            (RFC 5869 §2.3: 255 * tamaño de hash).

    Returns:
        `length` bytes derivados.

    Raises:
        InvalidKeyLengthError: si master_key tiene menos de 32 bytes,
            si info está vacío o es None, o si length está fuera del
            rango permitido por el RFC.
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
            f"bytes (RFC 5869 §2.2), recibido {len(master_key)}"
        )

    if info is None:
        raise InvalidKeyLengthError("info no puede ser None")
    if not isinstance(info, bytes):
        raise InvalidKeyLengthError(
            f"info debe ser bytes, recibido {type(info).__name__}"
        )
    if len(info) == 0:
        raise InvalidKeyLengthError("info no puede estar vacío")

    if salt is None:
        raise InvalidKeyLengthError("salt no puede ser None")
    if not isinstance(salt, bytes):
        raise InvalidKeyLengthError(
            f"salt debe ser bytes, recibido {type(salt).__name__}"
        )

    if not isinstance(length, int) or length <= 0:
        raise InvalidKeyLengthError(
            f"length debe ser un entero positivo, recibido {length!r}"
        )
    if length > MAX_OUTPUT_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"length excede el máximo permitido por RFC 5869 "
            f"({MAX_OUTPUT_LENGTH_BYTES} bytes), recibido {length}"
        )

    return _hkdf_expand_raw(prk=master_key, info=salt + info, length=length)


def _hkdf_expand_raw(prk: bytes, info: bytes, length: int) -> bytes:
    """Implementación directa de HKDF-Expand (RFC 5869 §2.3), sin validación.

    Separada de hkdf_expand() para que los tests de vectores RFC 5869
    (propuesta #9) puedan ejercer la primitiva exacta del estándar sin
    pasar por la capa de validación de inputs específica de VTR — los
    vectores oficiales del RFC ya vienen con inputs válidos por
    construcción, así que esta separación evita que un futuro cambio en
    las reglas de validación de VTR rompa accidentalmente la conformidad
    con el vector de prueba oficial.
    """
    hash_len = hashlib.sha256().digest_size  # 32 bytes para SHA-256
    n = -(-length // hash_len)  # ceil(length / hash_len) sin usar floats

    t = b""
    okm = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:length]
