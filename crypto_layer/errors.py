"""
crypto_layer/errors.py — Jerarquía de excepciones del dominio criptográfico.

Propuesta #3 de 10 — VTR Continuity v0.5.0.

Implementa VTR-CRYPTO-003: validación defensiva antes de cualquier operación
criptográfica. Ningún input inválido (None, bytes vacíos, longitud incorrecta,
tipo inesperado) debe llegar a PyNaCl, cryptography (pyca), o PyCryptodome sin
pasar primero por una de estas excepciones específicas del dominio.

Ver docs/VTR-CRYPTO-001.md y docs/VTR-PKI-001.md para el contexto de diseño
de cada categoría.
"""

from __future__ import annotations


# ──────────────────────────────────────────────────────────────────────────
# Base
# ──────────────────────────────────────────────────────────────────────────

class CryptoError(Exception):
    """Base de todos los errores criptográficos del dominio VTR.

    Cualquier código que necesite capturar "algo salió mal en crypto_layer,
    sin importar qué" debe capturar esta clase, no Exception genérica.
    """


# ──────────────────────────────────────────────────────────────────────────
# Configuración
# ──────────────────────────────────────────────────────────────────────────

class ConfigError(CryptoError):
    """Errores de configuración (profile inválido, falta de campos).

    Corresponde a la validación de rf_config.yaml sección `crypto:`
    (VTR-CRYPTO-001 §1.2, propuesta #8) — el catálogo cerrado de profiles
    Argon2id (embedded | desktop | hardened) se valida al boot, no en cada
    derivación.
    """


class InvalidProfileError(ConfigError):
    """El profile especificado no existe en el catálogo cerrado.

    Disparada cuando rf_config.yaml contiene un valor de
    `crypto.argon2id_profile` distinto de "embedded", "desktop" o "hardened".
    Decisión 2D (docs/DECISIONS-v0.5.0.md): el catálogo es cerrado a propósito
    para que un operador no pueda configurar accidentalmente un profile
    débil en producción crítica.
    """


class MissingConfigFieldError(ConfigError):
    """Falta un campo obligatorio en la configuración cripto.

    Ejemplos: `ed25519_public_key_path`, `device_secret_path`, o
    `hardware_id_source` ausentes en rf_config.yaml.
    """


# ──────────────────────────────────────────────────────────────────────────
# Validación de inputs (VTR-CRYPTO-003 — primera línea de defensa)
# ──────────────────────────────────────────────────────────────────────────

class InputValidationError(CryptoError):
    """Errores en inputs de funciones criptográficas.

    Esta es la categoría que materializa VTR-CRYPTO-003: ninguna de estas
    excepciones debe originarse dentro de PyNaCl/cryptography/PyCryptodome —
    deben lanzarse ANTES de invocar esas librerías, desde validación explícita
    en crypto_layer/__init__.py.
    """


class InvalidPassphraseError(InputValidationError):
    """La passphrase es None, vacía, o excede un límite razonable de tamaño.

    Usada por derive_operator_key() (VTR-CRYPTO-001 — decisión 1B), donde la
    passphrase es obligatoria y nunca puede ser None silenciosamente
    aceptado como "sin passphrase".
    """


class InvalidHardwareIDError(InputValidationError):
    """El hardware_id es None, vacío, o de un tipo no esperado.

    Recordatorio de VTR-CRYPTO-002: el hardware_id es información pública,
    se usa únicamente como `info` field en HKDF (binding contextual), nunca
    como salt. Esta excepción valida su presencia/formato, no su secreto
    (no lo es).
    """


class InvalidDeviceSecretError(InputValidationError):
    """El device_secret es None, vacío, o no tiene exactamente 32 bytes.

    Recordatorio de estado (VTR-CRYPTO-001 §8, VTR-CRYPTO-002): el mecanismo
    que genera y almacena el device_secret en partición firmada es DISEÑO
    PENDIENTE — esta excepción ya puede y debe implementarse ahora (valida
    forma, no procedencia), pero ningún código de producción debe asumir que
    existe un device_secret real disponible hasta que la Épica C lo entregue.
    """


class InvalidKeyLengthError(InputValidationError):
    """Una llave (maestra, derivada, o de firma) no tiene la longitud esperada.

    Ejemplos: master_key de HKDF con menos de 32 bytes (VTR-PKI-001 §4.3 usa
    32 bytes para el HMAC de integridad de la CA root); llave Ed25519 que no
    son los 32 bytes estándar de seed.
    """


class InvalidNonceError(InputValidationError):
    """El nonce es None, de longitud incorrecta, o se detecta como reusado.

    Relevante para Q-02 (paradoja del RTC al reinicio, ver VTR-SEC-001):
    si el contador monotónico SQLite-persistido detecta un nonce ya usado
    tras un reinicio con reloj desconfigurado, esta excepción se dispara en
    vez de aceptar silenciosamente un nonce potencialmente repetido.
    """


# ──────────────────────────────────────────────────────────────────────────
# Operaciones criptográficas
# ──────────────────────────────────────────────────────────────────────────

class CryptoOperationError(CryptoError):
    """Errores durante la ejecución de una operación criptográfica.

    A diferencia de InputValidationError (que se dispara ANTES de tocar la
    librería subyacente), estas excepciones envuelven fallos que ocurren
    DURANTE la operación misma — la validación de inputs ya pasó, pero la
    operación no pudo completarse o su resultado no es válido.
    """


class DerivationFailedError(CryptoOperationError):
    """La derivación Argon2id o HKDF falló durante la ejecución.

    No cubre profile inválido (eso es ConfigError) ni inputs malformados
    (eso es InputValidationError) — cubre fallos genuinos de la operación
    en sí (ej. el profile "hardened" excede la memoria disponible en el
    hardware real al momento de ejecutar).
    """


class SignatureVerificationError(CryptoOperationError):
    """Una firma Ed25519 no pasó verificación.

    Nota de diseño (VTR-CRYPTO-001, propuesta #7): la función de bajo nivel
    `verify()` en ed25519_sign.py NO lanza esta excepción — retorna False
    según su contrato documentado. Esta excepción es para capas superiores
    que necesitan tratar una firma inválida como un evento excepcional (por
    ejemplo, al rechazar un bundle .vtrc completo en VTR-SEC-001 S#6).
    """


class BundleIntegrityError(CryptoOperationError):
    """Un bundle .vtrc falló su verificación de integridad estructural.

    Más amplio que SignatureVerificationError: cubre casos donde el bundle
    está corrupto, truncado, o no respeta el formato canónico documentado
    en VTR-CRYPTO-001 propuesta #7 (header || payload || metadata, campo
    signature rellenado con ceros antes de firmar).
    """


# ──────────────────────────────────────────────────────────────────────────
# Provisioning (operación rutinaria — bench, primer boot de dispositivo)
# ──────────────────────────────────────────────────────────────────────────

class ProvisioningError(CryptoError):
    """Errores durante el provisioning rutinario de un dispositivo.

    Alcance: emisión de certificado de dispositivo, generación de su par de
    llaves, registro en device_registry.vtrdb (VTR-PKI-001 §3.3). NO cubre
    errores de custodia/reconstrucción de la CA root — ver CustodyError más
    abajo, separada intencionalmente (ver justificación en §0 de este
    archivo y en el historial de decisiones del proyecto).
    """


class DeviceSecretNotFoundError(ProvisioningError):
    """No se encontró un device_secret en la ruta esperada del dispositivo.

    Dado que el mecanismo de partición firmada que almacena el device_secret
    es diseño pendiente (VTR-CRYPTO-002), esta excepción hoy se dispara en
    cualquier intento real de leer un device_secret de producción — es el
    comportamiento correcto mientras la Épica C no entregue el mecanismo.
    """


class CASignatureInvalidError(ProvisioningError):
    """La firma de la CA (Intermediate) sobre un certificado no es válida.

    Se dispara durante la emisión de certificado de dispositivo (VTR-PKI-001
    §3.3) si la firma resultante no verifica contra la llave pública de la
    Intermediate — indicaría una Intermediate corrupta o un bug en el
    proceso de firma, nunca debe ignorarse silenciosamente.
    """


# ──────────────────────────────────────────────────────────────────────────
# Custodia y recuperación de material criptográfico crítico (CA root)
# ──────────────────────────────────────────────────────────────────────────

class CustodyError(CryptoError):
    """Errores en la custodia distribuida o recuperación de la CA root.

    Categoría separada de ProvisioningError por decisión explícita: el
    provisioning de un dispositivo es una operación rutinaria de alta
    frecuencia (cada Heltec/RPi nuevo), mientras que la reconstrucción de la
    CA root vía Shamir's Secret Sharing (VTR-PKI-001 §4) es un evento de
    emergencia de baja frecuencia con un perfil de riesgo completamente
    distinto — mezclar ambas categorías arriesgaría que un `except
    ProvisioningError` genérico capture accidentalmente un fallo de
    reconstrucción de la llave raíz de toda la flota, o viceversa.
    """


class InsufficientSharesError(CustodyError):
    """Se intentó reconstruir la CA root con menos de 3 partes SSS.

    El esquema es estrictamente 3-de-5 (VTR-PKI-001 §4.3, Capa 3) — esta
    excepción es la barrera explícita contra cualquier intento de
    reconstrucción parcial o "mejor esfuerzo" con menos partes de las
    requeridas.
    """


class SSSIntegrityError(CustodyError):
    """La llave reconstruida desde partes SSS no coincide con su HMAC esperado.

    Corresponde a la Capa 2 de mitigación en VTR-PKI-001 §4.3: una o más
    partes presentadas están corruptas, fueron alteradas, o provienen de un
    participante no legítimo. Disparar esta excepción significa que la
    llave reconstruida NUNCA debe usarse para firmar nada — debe descartarse
    y reintentarse la recolección de partes válidas.
    """


class ShareGenerationError(CustodyError):
    """El proceso de fragmentación SSS no produjo partes con aleatoriedad real.

    Corresponde a la Capa 1 de mitigación en VTR-PKI-001 §4.3: si el test
    que compara dos fragmentaciones independientes del mismo secreto
    detecta partes idénticas, es la señal exacta del patrón de fallo que
    rompió las "Fragmented Backups" de Armory (coeficientes deterministas
    en vez de un RNG real). Esta excepción formaliza ese hallazgo como
    fallo bloqueante, no como advertencia.
    """
