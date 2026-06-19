"""
crypto_layer/ed25519_sign.py — Firma y verificación Ed25519.

Propuesta #7 de 10 — VTR Continuity v0.5.0.

Implementa la primitiva de firma/verificación Ed25519 usada para integrar
bundles .vtrc (VTR-CRYPTO-001 regla 001) y para la cadena de confianza PKI
de dos niveles (VTR-PKI-001 §2: cryptography/pyca construye y firma
estructuras X.509, pero la firma subyacente Ed25519 en sí, cuando se firma
directamente un mensaje en bytes — no una estructura X.509 — pasa por
PyNaCl/libsodium, justificado por su mejor perfil de seguridad documentado
en uso asimétrico, ver VTR-CRYPTO-001 §1).

DESACOPLAMIENTO DELIBERADO — alcance de este módulo:
Este módulo es una primitiva CRIPTOGRÁFICA GENÉRICA: no conoce la
estructura de un bundle .vtrc, no sabe qué es un "header", un "payload",
ni una "metadata". La especificación original de esta propuesta menciona
el formato canonical de bundle .vtrc (header || payload || metadata, con
el campo signature relleno de ceros antes de firmar) — esa lógica de
canonicalización NO vive aquí. Razón: si la canonicalización de bundle se
mezclara en este módulo, cualquier otro consumidor de Ed25519 que no firme
bundles .vtrc (por ejemplo, VTR-PKI-001 firmando certificados X.509 o CRLs
distribuidas como bundle especial crl-update) quedaría acoplado a una
estructura que no le aplica — un cambio futuro en el formato del bundle
.vtrc obligaría a tocar el módulo criptográfico base que comparten PKI,
CRL y .vtrc por igual. La función de armar el formato canonical del bundle
.vtrc es DISEÑO PENDIENTE, responsabilidad de un módulo de formato de
bundle separado que no existe entre las 10 propuestas actuales — mismo
estado que device_secret (VTR-CRYPTO-002): no se asume su existencia.
"""

from __future__ import annotations

from crypto_layer.errors import InvalidKeyLengthError, SignatureVerificationError

# Ed25519: tamaños fijos según RFC 8032.
PRIVATE_KEY_LENGTH_BYTES = 32  # seed de la llave privada
PUBLIC_KEY_LENGTH_BYTES = 32
SIGNATURE_LENGTH_BYTES = 64


def generate_keypair() -> tuple[bytes, bytes]:
    """Genera un par de llaves Ed25519.

    Returns:
        Tupla (private_key, public_key), cada una de 32 bytes.
    """
    from nacl.signing import SigningKey

    signing_key = SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)
    return private_key, public_key


def sign(message: bytes, private_key: bytes) -> bytes:
    """Firma `message` con Ed25519. Retorna 64 bytes.

    Args:
        message: los bytes a firmar. Esta función no impone ninguna
            estructura sobre `message` — el llamador es responsable de
            construir el contenido exacto que debe firmarse (p. ej. un
            bundle .vtrc ya canonicalizado, o el TBSCertificate de un
            certificado X.509).
        private_key: 32 bytes, el seed de la llave privada Ed25519.

    Returns:
        Firma de 64 bytes (RFC 8032).

    Raises:
        InvalidKeyLengthError: si message es None, o private_key no tiene
            exactamente 32 bytes.
    """
    if message is None:
        raise InvalidKeyLengthError("message no puede ser None")
    if not isinstance(message, bytes):
        raise InvalidKeyLengthError(
            f"message debe ser bytes, recibido {type(message).__name__}"
        )
    if private_key is None:
        raise InvalidKeyLengthError("private_key no puede ser None")
    if not isinstance(private_key, bytes):
        raise InvalidKeyLengthError(
            f"private_key debe ser bytes, recibido {type(private_key).__name__}"
        )
    if len(private_key) != PRIVATE_KEY_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"private_key debe ser exactamente {PRIVATE_KEY_LENGTH_BYTES} "
            f"bytes, recibido {len(private_key)}"
        )

    from nacl.signing import SigningKey

    signing_key = SigningKey(private_key)
    signed = signing_key.sign(message)
    # PyNaCl antepone el mensaje a la firma en el objeto SignedMessage;
    # `signed.signature` aísla los 64 bytes de firma pura, sin el mensaje
    # concatenado — eso es lo que el contrato de esta función promete
    # retornar (64 bytes, no message+firma).
    return signed.signature


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verifica una firma Ed25519. NO lanza excepción si la firma es inválida.

    Contrato deliberado (ver SignatureVerificationError en
    crypto_layer/errors.py): esta función es un predicado puro. Una firma
    inválida es un resultado esperado y común (un bundle corrupto en
    tránsito, un atacante probando bundles falsos), no una condición
    excepcional — se modela como `False`, no como excepción. Las capas
    superiores (CryptoLayer.verify_bundle, o lógica de recepción de
    bundles) son responsables de decidir si una verificación fallida debe
    escalar a una excepción de dominio.

    Inputs estructuralmente inválidos (None, tipo incorrecto, longitud
    incorrecta de la llave pública) SÍ son un error de uso de la API, no
    "firma incorrecta" — esos casos lanzan InvalidKeyLengthError.

    Args:
        message: los bytes originales que se firmaron.
        signature: 64 bytes de firma a verificar.
        public_key: 32 bytes, la llave pública Ed25519 correspondiente.

    Returns:
        True si la firma es válida para ese message y esa public_key,
        False en cualquier otro caso (firma incorrecta, message modificado,
        llave pública equivocada).

    Raises:
        InvalidKeyLengthError: si algún input es None, de tipo incorrecto,
            o si signature/public_key no tienen la longitud esperada.
    """
    if message is None:
        raise InvalidKeyLengthError("message no puede ser None")
    if not isinstance(message, bytes):
        raise InvalidKeyLengthError(
            f"message debe ser bytes, recibido {type(message).__name__}"
        )
    if signature is None:
        raise InvalidKeyLengthError("signature no puede ser None")
    if not isinstance(signature, bytes):
        raise InvalidKeyLengthError(
            f"signature debe ser bytes, recibido {type(signature).__name__}"
        )
    if len(signature) != SIGNATURE_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"signature debe ser exactamente {SIGNATURE_LENGTH_BYTES} "
            f"bytes, recibido {len(signature)}"
        )
    if public_key is None:
        raise InvalidKeyLengthError("public_key no puede ser None")
    if not isinstance(public_key, bytes):
        raise InvalidKeyLengthError(
            f"public_key debe ser bytes, recibido {type(public_key).__name__}"
        )
    if len(public_key) != PUBLIC_KEY_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"public_key debe ser exactamente {PUBLIC_KEY_LENGTH_BYTES} "
            f"bytes, recibido {len(public_key)}"
        )

    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    try:
        verify_key = VerifyKey(public_key)
        # PyNaCl espera (signature + message) concatenados en verify(),
        # o signature como argumento separado vía smessage=... — se usa
        # la forma con argumento separado para mantener el contrato de
        # esta función (signature y message como parámetros distintos,
        # no concatenados por el llamador).
        verify_key.verify(message, signature)
        return True
    except BadSignatureError:
        return False
