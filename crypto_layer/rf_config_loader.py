"""
crypto_layer/rf_config_loader.py — Loader de rf_config.yaml hacia CryptoConfig.

Propuesta #8 de 10 (parte 2 de 2) — VTR Continuity v0.5.0.

DECISIÓN DE ALCANCE (consultada y confirmada explícitamente): este módulo
es un archivo NUEVO y SEPARADO de crypto_layer/__init__.py, no una
modificación de CryptoConfig. La propuesta #4 (ya generada, validada y
sincronizada en GitHub) decidió deliberadamente que CryptoConfig NO sabe
parsear YAML — esa decisión queda intacta. Este loader es un consumidor
nuevo de CryptoConfig, de la misma forma que argon2_derive.py o
hkdf_expand.py son consumidores de crypto_layer/errors.py: añade
funcionalidad sin reabrir ni contradecir un contrato ya cerrado.

Responsabilidad de este módulo: leer rf_config.yaml, validar tipos y
rangos de la sección `crypto:` (criterio de aceptación de la propuesta #8),
y construir un CryptoConfig ya validado. CryptoLayer nunca ve el YAML
crudo — solo recibe el CryptoConfig que este loader produce.
"""

from __future__ import annotations

from pathlib import Path

from crypto_layer import CryptoConfig
from crypto_layer.errors import (
    InvalidProfileError,
    MissingConfigFieldError,
)

REQUIRED_CRYPTO_FIELDS = (
    "argon2id_profile",
    "ed25519_public_key_path",
    "device_secret_path",
    "hardware_id_source",
    "session_cache_ttl_seconds",
    "derivation_async",
)

VALID_PROFILES = ("embedded", "desktop", "hardened")


def load_crypto_config(yaml_path: str | Path) -> CryptoConfig:
    """Carga la sección `crypto:` de rf_config.yaml y construye un CryptoConfig.

    Valida tipos y rangos ANTES de construir CryptoConfig — aunque
    CryptoConfig.__post_init__ también valida el profile (defensa en
    profundidad, mismo criterio ya aplicado en argon2_derive.py), este
    loader valida el resto de los campos que CryptoConfig no conoce
    (ed25519_public_key_path, device_secret_path, hardware_id_source no
    son atributos de CryptoConfig — son resueltos por capas que sí los
    necesitan en tiempo de uso, no en este loader).

    Args:
        yaml_path: ruta al archivo rf_config.yaml.

    Returns:
        CryptoConfig validado, listo para pasar a CryptoLayer.__init__().

    Raises:
        MissingConfigFieldError: si el archivo no existe, no es YAML
            válido, falta la sección `crypto:`, o falta algún campo
            requerido dentro de ella.
        InvalidProfileError: si `argon2id_profile` no está en el catálogo
            cerrado (embedded | desktop | hardened).
    """
    import yaml

    path = Path(yaml_path)
    if not path.exists():
        raise MissingConfigFieldError(
            f"No se encontró el archivo de configuración: {yaml_path}"
        )

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise MissingConfigFieldError(
            f"El archivo {yaml_path} no es YAML válido: {exc}"
        ) from exc

    if raw_config is None or "crypto" not in raw_config:
        raise MissingConfigFieldError(
            f"El archivo {yaml_path} no contiene la sección 'crypto:'"
        )

    crypto_section = raw_config["crypto"]

    missing_fields = [
        field for field in REQUIRED_CRYPTO_FIELDS if field not in crypto_section
    ]
    if missing_fields:
        raise MissingConfigFieldError(
            f"Faltan campos obligatorios en la sección crypto: "
            f"{', '.join(missing_fields)}"
        )

    profile = crypto_section["argon2id_profile"]
    if profile not in VALID_PROFILES:
        raise InvalidProfileError(
            f"argon2id_profile '{profile}' no está en el catálogo cerrado. "
            f"Valores permitidos: {VALID_PROFILES}"
        )

    ttl = crypto_section["session_cache_ttl_seconds"]
    if not isinstance(ttl, int) or ttl <= 0:
        raise MissingConfigFieldError(
            f"session_cache_ttl_seconds debe ser un entero positivo, "
            f"recibido: {ttl!r}"
        )

    derivation_async = crypto_section["derivation_async"]
    if not isinstance(derivation_async, bool):
        raise MissingConfigFieldError(
            f"derivation_async debe ser booleano (true/false), "
            f"recibido: {derivation_async!r}"
        )

    for path_field in ("ed25519_public_key_path", "device_secret_path", "hardware_id_source"):
        value = crypto_section[path_field]
        if not isinstance(value, str) or len(value) == 0:
            raise MissingConfigFieldError(
                f"{path_field} debe ser una ruta no vacía (string), "
                f"recibido: {value!r}"
            )
        # Nota deliberada: NO se valida aquí que el archivo en esa ruta
        # exista físicamente. device_secret_path en particular apunta a un
        # mecanismo de partición firmada que es diseño pendiente
        # (VTR-CRYPTO-002) — exigir su existencia en tiempo de carga de
        # configuración bloquearía el boot de cualquier despliegue antes
        # de que ese mecanismo esté implementado. La verificación de
        # existencia real ocurre en tiempo de uso (cuando CryptoLayer
        # efectivamente necesita leer ese archivo), no aquí.

    return CryptoConfig(
        argon2id_profile=profile,
        session_cache_ttl_seconds=ttl,
        derivation_async=derivation_async,
    )
