# Especificación de las 10 propuestas pendientes

> Esta es la blueprint para generar el código y la documentación cuando
> retomes el proyecto. Cada propuesta tiene: alcance, contrato/API,
> dependencias y criterios de aceptación.

---

## #1 — `docs/VTR-CRYPTO-001.md` (Reglas cripto consolidadas)

**Alcance:**
- Reglas VTR-CRYPTO-001, 002, 003 con texto completo
- Tabla de uso: cuándo usar cada primitiva
- Ejemplos de código correctos e incorrectos
- Referencias a IEC 62443 y OWASP

**Contenido base:**
- **VTR-CRYPTO-001:** Nunca SHA-256 puro sobre secretos de baja entropía
- **VTR-CRYPTO-002:** Hardware ID público ≠ salt criptográfico
- **VTR-CRYPTO-003:** Validación defensiva antes de operación cripto

**Criterio aceptación:** Documento aprobado y commiteado en `docs/`.

---

## #2 — `docs/VTR-PKI-001.md` (Esquema PKI dos niveles)

**Alcance:**
- Diagrama de la jerarquía CA Root → Intermediate → Device
- Procedimiento de creación de CA root
- Procedimiento de ceremonia de firma intermediate
- Procedimiento de emisión de certificado de dispositivo
- Procedimiento de revocación (CRL distribuida vía bundle .vtrc)
- Política de períodos de validez

**Mínimos a documentar:**
- Algoritmo: Ed25519 (root e intermediate)
- Validez root: 10 años
- Validez intermediate: 2 años
- Validez device cert: 18 meses (alineado con rotación)
- Custodia root: USB cifrado LUKS, caja fuerte del bench
- Procedimientos OpenSSL/cryptography para creación

**Criterio aceptación:** Documento aprobado + CA root + intermediate creadas y operativas.

---

## #3 — `crypto_layer/errors.py` (Jerarquía de excepciones)

**API esperada:**
```python
class CryptoError(Exception):
    """Base de todos los errores cripto del dominio."""

class ConfigError(CryptoError):
    """Errores de configuración (profile inválido, falta de campos)."""

class InvalidProfileError(ConfigError): ...
class MissingConfigFieldError(ConfigError): ...

class InputValidationError(CryptoError):
    """Errores en inputs de funciones cripto."""

class InvalidPassphraseError(InputValidationError): ...
class InvalidHardwareIDError(InputValidationError): ...
class InvalidDeviceSecretError(InputValidationError): ...
class InvalidKeyLengthError(InputValidationError): ...
class InvalidNonceError(InputValidationError): ...

class CryptoOperationError(CryptoError):
    """Errores durante la operación cripto."""

class DerivationFailedError(CryptoOperationError): ...
class SignatureVerificationError(CryptoOperationError): ...
class BundleIntegrityError(CryptoOperationError): ...

class ProvisioningError(CryptoError):
    """Errores en provisioning."""

class DeviceSecretNotFoundError(ProvisioningError): ...
class CASignatureInvalidError(ProvisioningError): ...
```

**Criterio aceptación:** Jerarquía cubre todos los puntos de fallo identificados; cada error tiene mensaje claro de debugging.

---

## #4 — `crypto_layer/__init__.py` (API pública)

**API esperada:**
```python
class CryptoLayer:
    def __init__(self, config: CryptoConfig): ...

    def derive_device_key(
        self,
        hardware_id: bytes,
        device_secret: bytes,
    ) -> bytes:
        """Para servicios unattended (proxy DMZ).
        Nunca falla por falta de passphrase.
        Falla si hardware_id o device_secret están vacíos/None."""

    def derive_operator_key(
        self,
        hardware_id: bytes,
        device_secret: bytes,
        passphrase: bytes,
    ) -> bytes:
        """Para sesión humana. Passphrase obligatoria.
        Falla si cualquier input es None o vacío."""

    def expand_subkey(
        self,
        master_key: bytes,
        context: bytes,
        info: bytes,
        length: int = 32,
    ) -> bytes:
        """Expande subclaves desde una clave maestra de alta entropía."""

    def sign_bundle(
        self,
        bundle_bytes: bytes,
        signing_key: bytes,
    ) -> bytes:
        """Firma un bundle .vtrc con Ed25519."""

    def verify_bundle(
        self,
        bundle_bytes: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Verifica firma Ed25519 de un bundle .vtrc."""

    async def derive_device_key_async(self, ...) -> bytes:
        """Versión async para no bloquear el boot del proxy."""
```

**Criterio aceptación:** API completa, validación defensiva en cada método, type hints estrictos, docstrings con ejemplos.

---

## #5 — `crypto_layer/argon2_derive.py` (Derivación con profile + async)

**Responsabilidades:**
- Cargar profile desde config (`embedded | desktop | hardened`)
- Validar profile contra catálogo cerrado
- Ejecutar derivación Argon2id síncrona
- Ejecutar derivación Argon2id en thread aparte (async wrapper)
- Cachear resultados de derivación durante la sesión (memoria protegida)

**Profiles:**
```python
PROFILES = {
    "embedded": Argon2idParams(memory_kib=32*1024, iterations=3, lanes=4),
    "desktop":  Argon2idParams(memory_kib=64*1024, iterations=3, lanes=4),
    "hardened": Argon2idParams(memory_kib=128*1024, iterations=4, lanes=4),
}
```

**Criterio aceptación:** Tests miden tiempo en RPi 4 simulado y verifican que cumple budget (<250ms desktop).

---

## #6 — `crypto_layer/hkdf_expand.py` (Expansión de subclaves)

**Responsabilidades:**
- Implementar HKDF-SHA256 expand
- Validar inputs (master_key de longitud mínima 32 bytes, info no vacío)
- Soportar contexto + info para binding

**API:**
```python
def hkdf_expand(
    master_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """RFC 5869 HKDF-Expand con SHA-256."""
```

**Casos de uso típicos en el proyecto:**
- Derivación de session key desde device key + nonce de sesión
- Derivación de transport key desde device key + tipo de canal (LoRa, BLE, sneakernet)

**Criterio aceptación:** Tests con vectores oficiales de RFC 5869.

---

## #7 — `crypto_layer/ed25519_sign.py` (Firma/verificación de .vtrc)

**Responsabilidades:**
- Generar pares de claves Ed25519
- Firmar bundles `.vtrc`
- Verificar firmas con clave pública conocida
- Manejar formato canonical (bundle bytes → firma determinista)

**API:**
```python
def generate_keypair() -> tuple[bytes, bytes]:
    """Retorna (private_key, public_key) Ed25519."""

def sign(message: bytes, private_key: bytes) -> bytes:
    """Firma message. Retorna 64 bytes."""

def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verifica firma. NO lanza excepción si falla, retorna False."""
```

**Importante para `.vtrc`:**
- La firma cubre: `header || payload || metadata` (en orden canónico)
- El campo `signature` se ubica al final del bundle
- Antes de firmar, el campo `signature` se rellena con ceros

**Criterio aceptación:** Round-trip sign → verify funciona; verificación rechaza bundles modificados; tests con vectores RFC 8032.

---

## #8 — `config/rf_config.yaml` (Sección crypto: + RF)

**Estructura completa:**
```yaml
# VTR Continuity v0.5.0 — Runtime configuration
# Cambios aquí no requieren recompilación.

crypto:
  argon2id_profile: desktop        # embedded | desktop | hardened
  ed25519_public_key_path: /etc/vtr/ca_intermediate.pub
  device_secret_path: /etc/vtr/device_secret
  hardware_id_source: /proc/cpuinfo  # o eFuse path
  session_cache_ttl_seconds: 3600
  derivation_async: true             # async en boot

rf:
  lora:
    frequency_mhz: 915
    tx_power_dbm: 14
    spreading_factor: 9
    bandwidth_khz: 125
    duty_cycle_percent: 1.0          # ISM compliance
  ble:
    enabled: true
    mesh_role: relay
  sneakernet:
    enabled: true
    bundle_max_size_mb: 64

storage:
  guardian:
    warn_threshold_percent: 80
    purge_threshold_percent: 95
    purge_policy: fifo

dtn:
  bundle_protocol_version: 7         # RFC 9171
  max_bundle_size_kb: 1024
  max_ttl_seconds: 86400
  max_hop_count: 10
```

**Criterio aceptación:** YAML válido; loader valida tipos y rangos; profile fuera de catálogo → `InvalidProfileError`.

---

## #9 — `tests/test_crypto_layer.py` (Tests felices + ≥15 adversariales)

**Estructura:**
```python
class TestArgon2idHappy:
    def test_derive_device_key_returns_32_bytes(self): ...
    def test_same_inputs_produce_same_key(self): ...
    def test_different_passphrases_produce_different_keys(self): ...
    def test_profile_desktop_meets_time_budget(self): ...

class TestHKDFHappy:
    def test_rfc5869_test_vector_1(self): ...
    def test_rfc5869_test_vector_2(self): ...

class TestEd25519Happy:
    def test_keypair_generation(self): ...
    def test_sign_verify_roundtrip(self): ...
    def test_rfc8032_test_vector_1(self): ...

class TestAdversarial:  # ≥15 casos
    def test_none_passphrase_raises(self): ...
    def test_empty_passphrase_raises(self): ...
    def test_none_hardware_id_raises(self): ...
    def test_empty_hardware_id_raises(self): ...
    def test_short_device_secret_raises(self): ...
    def test_invalid_profile_raises(self): ...
    def test_modified_bundle_signature_fails(self): ...
    def test_replayed_nonce_detected(self): ...
    def test_truncated_signature_fails(self): ...
    def test_signature_with_wrong_pubkey_fails(self): ...
    def test_oversized_passphrase_handled(self): ...
    def test_non_bytes_input_raises_type_error(self): ...
    def test_concurrent_derivation_no_race(self): ...
    def test_async_derivation_does_not_block(self): ...
    def test_session_cache_invalidated_on_passphrase_change(self): ...
    def test_bundle_with_zero_payload_handled(self): ...
    def test_bundle_with_max_size_payload_handled(self): ...
```

**Criterio aceptación:** ≥15 tests adversariales pasando; coverage > 90% en `crypto_layer/`.

---

## #10 — `docs/DOD-v0.5.0.md` (Definition of Done + roadmap visible)

**Contenido:**
- Bloques del DoD (ver tabla en ROADMAP-v0.5.0.md)
- Estado de cada bloque (pendiente/en curso/completado)
- Mapeo a las épicas del roadmap
- Reglas VTR-CRYPTO-001/002/003 listadas
- Diferimientos explícitos a v0.6.0
- Checklist final pre-release

**Criterio aceptación:** Documento es la fuente de verdad del cierre de v0.5.0; cualquier item marcado completado debe tener evidencia (commit, test, documento).
