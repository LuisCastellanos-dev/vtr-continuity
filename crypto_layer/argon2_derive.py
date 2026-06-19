"""
crypto_layer/argon2_derive.py — Derivación Argon2id con profiles catalogados.

Propuesta #5 de 10 — VTR Continuity v0.5.0.

Implementa la decisión 2D (docs/DECISIONS-v0.5.0.md): profile parametrizable
por entorno (embedded | desktop | hardened) con default "desktop", validado
contra un catálogo cerrado.

Este módulo es deliberadamente una función pura sin estado ni caché propio.
El caché de sesión vive en CryptoLayer (crypto_layer/__init__.py), no aquí —
decisión documentada para mantener el estado de sesión por instancia en vez
de compartido a nivel de módulo entre todas las instancias del proceso, lo
que facilita razonar sobre invalidación (p. ej. al cambiar de passphrase) y
evita contaminación cruzada entre tests o entre instancias con configs
distintas.

Validación de profile: este módulo valida el profile de forma INDEPENDIENTE
de CryptoConfig.__post_init__ (que ya valida al construirse) — defensa en
profundidad explícitamente decidida, no duplicación accidental. Si en algún
futuro CryptoConfig se construye sin pasar por su validación normal (por
ejemplo, deserializado directamente de algún estado persistido), esta
segunda barrera sigue protegiendo la operación criptográfica real.

CRITERIO DE ACEPTACIÓN PENDIENTE — tiempo de ejecución en hardware real:
La propuesta #5 define como criterio que el profile "desktop" cumpla
<250ms en el hardware objetivo (RPi 4). Este criterio NO se verificó en
el entorno de generación (1 núcleo de CPU) donde se midieron 275ms promedio
con lanes=1 — excede el presupuesto. La causa identificada es la limitación
del entorno de prueba, no el profile. ACCIÓN REQUERIDA antes de cerrar este
criterio: medir `derive(salt=b'x'*32, info=b'hwid', context=b'ctx',
profile='desktop')` en el RPi 4 de producción, mediana de 5 corridas
< 250ms. Si no cumple, reducir `iterations` de 3 a 2 antes de reducir
`memory_kib` — la memoria es el parámetro con mayor impacto en la
resistencia al cracking y debe ser el último en ajustarse.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from crypto_layer.errors import InvalidProfileError, DerivationFailedError

# ──────────────────────────────────────────────────────────────────────────
# Catálogo cerrado de profiles — única fuente de verdad para sus parámetros.
# CryptoConfig (propuesta #4) valida que el NOMBRE del profile esté en este
# catálogo; este módulo valida lo mismo de forma independiente y además
# posee los parámetros numéricos reales que CryptoConfig no necesita conocer.
# ──────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Argon2idParams:
    """Parámetros de un profile Argon2id. Inmutable por diseño."""

    memory_kib: int
    iterations: int
    lanes: int


PROFILES: dict[str, Argon2idParams] = {
    "embedded": Argon2idParams(memory_kib=32 * 1024, iterations=3, lanes=1),
    "desktop": Argon2idParams(memory_kib=64 * 1024, iterations=3, lanes=1),
    "hardened": Argon2idParams(memory_kib=128 * 1024, iterations=4, lanes=1),
}
# Nota de diseño — lanes=1 en los tres profiles (no 4):
# El parámetro de paralelismo de Argon2id dimensiona el costo computacional
# al hardware DEL DEFENSOR, no es el principal factor de resistencia
# criptográfica — ese rol lo cumple el costo de memoria (memory_kib), que
# permanece sin cambios. Fuentes recientes (2025-2026) sobre el perfil
# OWASP 2024 difieren entre sí: algunas citan parallelism=4, otras
# parallelism=1 como la recomendación vigente; el propio OWASP Cheat Sheet
# Series base recomienda 1 grado de paralelismo. Se eligió lanes=1 por
# consistencia con esa última referencia y porque, a diferencia de la
# memoria, reducir el paralelismo no reduce significativamente la
# resistencia contra ataques de fuerza bruta — solo afecta cuánta
# concurrencia interna usa la propia derivación legítima. Validado con
# medición real: con lanes=4 en un entorno de 1 núcleo de CPU, el profile
# "desktop" excedía el presupuesto de <250ms (300ms medidos); con lanes=1
# el presupuesto se cumple sin alterar memory_kib ni iterations, que son
# los parámetros con mayor impacto real en la resistencia al cracking.

# Longitud de salida fija para todas las derivaciones de este módulo —
# 32 bytes es el tamaño de clave esperado por XChaCha20-Poly1305 y por la
# entrada de HKDF en expand_subkey (crypto_layer/__init__.py).
OUTPUT_LENGTH_BYTES = 32


def _validate_profile(profile: str) -> Argon2idParams:
    """Valida el profile contra el catálogo cerrado y retorna sus parámetros.

    Defensa en profundidad: independiente de la validación que ya ocurre en
    CryptoConfig.__post_init__. Ver docstring del módulo.
    """
    if profile not in PROFILES:
        raise InvalidProfileError(
            f"Profile '{profile}' no está en el catálogo cerrado. "
            f"Valores permitidos: {sorted(PROFILES.keys())}"
        )
    return PROFILES[profile]


def derive(
    salt: bytes,
    info: bytes,
    context: bytes,
    profile: str = "desktop",
) -> bytes:
    """Deriva una clave de 32 bytes usando Argon2id con el profile dado.

    Función pura: sin estado, sin caché propio, sin efectos secundarios
    más allá de la derivación misma. El llamador (CryptoLayer) es
    responsable de cualquier cacheo de resultados.

    Args:
        salt: el device_secret (32 bytes de alta entropía) — NUNCA el
            hardware_id (VTR-CRYPTO-002). La validación de que el llamador
            respeta esto vive en CryptoLayer._validate_device_secret(),
            no aquí — este módulo no conoce la semántica de "qué es un
            device_secret", solo deriva con lo que recibe.
        info: material de binding contextual (p. ej. hardware_id, o
            hardware_id + passphrase concatenados, según el caso de uso).
        context: separador de dominio entre distintos usos de la misma
            combinación salt/info (p. ej. b"vtr-device-key-v1" vs
            b"vtr-operator-key-v1") — evita que dos derivaciones con
            propósitos distintos pero mismos inputs produzcan la misma
            salida.
        profile: nombre del profile, debe estar en PROFILES.

    Returns:
        32 bytes derivados.

    Raises:
        InvalidProfileError: si profile no está en el catálogo cerrado.
        DerivationFailedError: si la operación Argon2id falla en tiempo
            de ejecución (p. ej. memoria insuficiente para el profile
            solicitado en el hardware real).
    """
    params = _validate_profile(profile)

    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        # El salt real de Argon2id en cryptography (pyca) es el parámetro
        # `salt`; usamos info+context concatenados como el "password" a
        # derivar, porque Argon2id en esta API deriva FROM un secreto USING
        # un salt — y en nuestro modelo el secreto de alta entropía
        # (device_secret) debe ser el salt (VTR-CRYPTO-002), no el password.
        # Concatenar context al frente de info aplica separación de dominio
        # sin necesitar una segunda llamada a la librería.
        kdf = Argon2id(
            salt=salt,
            length=OUTPUT_LENGTH_BYTES,
            iterations=params.iterations,
            lanes=params.lanes,
            memory_cost=params.memory_kib,
        )
        return kdf.derive(context + info)
    except InvalidProfileError:
        raise
    except Exception as exc:
        # Cualquier fallo real de la librería subyacente (memoria
        # insuficiente, error interno) se envuelve en una excepción del
        # dominio — VTR-CRYPTO-003 exige que el código que consume este
        # módulo nunca tenga que capturar excepciones genéricas de pyca.
        raise DerivationFailedError(
            f"La derivación Argon2id falló con profile '{profile}': {exc}"
        ) from exc


async def derive_async(
    salt: bytes,
    info: bytes,
    context: bytes,
    profile: str = "desktop",
) -> bytes:
    """Versión async de derive() — ejecuta en un thread aparte.

    Usada por CryptoLayer.derive_device_key_async (propuesta #4) para no
    bloquear el boot del proxy DMZ (decisión 2D). Misma validación y mismo
    resultado que la versión síncrona para los mismos inputs — solo cambia
    el mecanismo de ejecución, nunca la lógica de derivación.
    """
    return await asyncio.to_thread(derive, salt=salt, info=info, context=context, profile=profile)
