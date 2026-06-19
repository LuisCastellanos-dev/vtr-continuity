# VTR-CRYPTO-001 — Reglas Criptográficas Consolidadas

> **Documento:** VTR-CRYPTO-001
> **Versión:** v1.0
> **Fecha:** 2026-06-16
> **Estado:** APROBADO — regla de desarrollo permanente
> **Alcance:** VTR Continuity v0.5.0+ (crypto_layer.py, firmware Heltec, session_guard.js)
> **Precedencia:** Este documento tiene precedencia sobre cualquier decisión de
> implementación posterior. Ningún PR puede mergear código que lo contradiga sin
> primero modificar este documento y justificar el cambio.

---

## 0. Premisa de diseño

> "Más seguro" no significa "más restrictivo". En infraestructura OT/ICS, el
> criterio es minimizar el **riesgo total del sistema** — confidencialidad,
> integridad y disponibilidad balanceadas (los tres ejes de IEC 62443) — no
> maximizar la dificultad criptográfica a costa de la disponibilidad del canal
> alterno, que es exactamente el escenario que VTR Continuity existe para resolver.

Cada regla de este documento se justifica contra esa premisa, no contra "qué es
matemáticamente más fuerte" en abstracto.

---

## 1. Selección de librerías — justificación verificada

Antes de fijar qué librería implementa cada primitiva, se evaluó el estado de
vulnerabilidades conocidas de los dos candidatos principales en Python, en vez
de asumir una preferencia por reputación:

| Librería | Vulnerabilidad reciente conocida | Estado |
|---|---|---|
| **PyNaCl / libsodium** | CVE-2025-69277 — manejo incompleto de lista de puntos inválidos en `crypto_core_ed25519_is_valid_point`, permitía puntos fuera del grupo criptográfico principal en casos de uso atípicos con datos no confiables | Parchado en libsodium 1.6.2 / PyNaCl ≥1.6.2 |
| **cryptography (pyca)** | CVE-2026-26007 — falta de validación de subgrupo para curvas SECT, permitiendo ataques de subgrupo | Parchado; usar build posterior al parche |

**Ninguna librería está exenta de CVEs.** Ambas requieren pin de versión post-parche
y revisión trimestral de avisos de seguridad — no se elige "para siempre", se
fija con fecha de revisión.

Adicionalmente, un estudio académico de usabilidad de APIs criptográficas (IEEE
S&P 2017, con datos que siguen siendo el mejor proxy disponible de comportamiento
desarrollador-API) encontró que **PyNaCl obtuvo buenos resultados de seguridad en
general, mientras que `cryptography.io` mostró seguridad fuerte en tareas
simétricas pero débil en tareas asimétricas**. Como Ed25519 es asimétrico y es
la primitiva central de firma de bundles `.vtrc`, este dato pesa a favor de
PyNaCl específicamente para esa primitiva.

### 1.1 Asignación de librería por primitiva

| Primitiva | Librería elegida | Razón |
|---|---|---|
| **Ed25519** (firma/verificación `.vtrc`) | `PyNaCl` (libsodium) | Mejor perfil de seguridad documentado en uso asimétrico; implementación de referencia de libsodium ampliamente auditada |
| **XChaCha20-Poly1305** (AEAD, Capa 1) | `PyNaCl` (libsodium) | Misma familia de API, evita mezclar dos backends C distintos para primitivas relacionadas |
| **Argon2id** (derivación desde passphrase/hwid) | `cryptography` (pyca) ≥45.0 (post CVE-2026-26007) | Buen soporte de Argon2id, mantenimiento activo, no requiere la superficie asimétrica donde pyca es más débil |
| **HKDF-SHA256** (expansión de subclaves) | `cryptography` (pyca) ≥45.0 | Primitiva simétrica/hash — fortaleza documentada de pyca |

### 1.2 Regla de versión y revisión

```
# requirements.txt (sección crypto)
pynacl>=1.6.2          # post CVE-2025-69277
cryptography>=45.0     # post CVE-2026-26007
```

**Regla permanente:** revisión de CVEs de ambas librerías cada trimestre natural
(marzo, junio, septiembre, diciembre). Si aparece un CVE crítico fuera de ese
ciclo, el parche se aplica en ≤72 horas independientemente del calendario.

---

## 2. VTR-CRYPTO-001 — Nunca SHA-256 puro sobre secretos de baja entropía

**Regla:** Ningún secreto de baja entropía (passphrase humana, PIN, hardware ID,
número de serie) se procesa jamás con SHA-256 puro como mecanismo de derivación
o protección.

**Por qué:** SHA-256 puro no tiene función de "costo" — un atacante con GPU/ASIC
puede probar miles de millones de combinaciones por segundo contra un hash sin
memory-hardness. Los secretos de alta entropía (256 bits de un CSPRNG) no tienen
este problema porque no son adivinables por fuerza bruta práctica; los de baja
entropía sí.

**Uso correcto por escenario:**

| Escenario | Primitiva correcta | Primitiva prohibida |
|---|---|---|
| Derivar clave desde passphrase humana | Argon2id | SHA-256 puro, MD5, SHA-1 |
| Derivar clave desde hardware ID (público) | Argon2id, combinado con `device_secret` de alta entropía — ver regla 002 | SHA-256 puro |
| Expandir subclaves desde clave maestra ya de alta entropía | HKDF-SHA256 | Re-derivar con Argon2id (costoso e innecesario — la entropía ya existe) |
| Firmar/verificar integridad de bundle | Ed25519 | HMAC-SHA256 con clave de baja entropía |

**Ejemplo incorrecto:**
```python
# INCORRECTO — SHA-256 puro sobre passphrase humana
import hashlib
key = hashlib.sha256(passphrase.encode()).digest()  # vulnerable a rainbow tables / GPU brute-force
```

**Ejemplo correcto:**
```python
# CORRECTO — Argon2id con profile catalogado
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
kdf = Argon2id(salt=device_secret, length=32, iterations=3,
                lanes=1, memory_cost=64*1024)  # profile "desktop"
key = kdf.derive(passphrase.encode())
```

---

## 3. VTR-CRYPTO-002 — Hardware ID público ≠ salt criptográfico

**Regla:** El hardware ID (número de serie del RPi, MAC address, CPU serial de
`/proc/cpuinfo`) **nunca** se usa como salt criptográfico. Es información pública
o fácilmente extraíble por cualquiera con acceso físico breve al dispositivo.

**Estado de implementación:** El `device_secret` (32 bytes aleatorios generados
en bench, ver VTR-PKI-001) **es diseño pendiente — aún no implementado**. La
partición read-only firmada por CA que lo almacena no existe físicamente hoy;
es un entregable de la Épica C (C1/C2). Hasta que exista, ningún código de
producción debe asumir su disponibilidad — los tests deben usar un mock
explícito, nunca un valor hardcodeado que simule el secreto real.

**Uso correcto:**

| Campo | Rol permitido | Rol prohibido |
|---|---|---|
| Hardware ID (`/proc/cpuinfo`, MAC, serial) | `info` field en HKDF (binding contextual al hardware) | Salt en Argon2id/HKDF |
| `device_secret` (32 bytes random, generado en bench, partición firmada por CA) | Salt en Argon2id | — |

**Ejemplo incorrecto:**
```python
# INCORRECTO — hardware ID como salt
hw_id = open('/proc/cpuinfo').read()  # público, predecible, extraíble
salt = hashlib.sha256(hw_id.encode()).digest()
```

**Ejemplo correcto:**
```python
# CORRECTO — device_secret como salt, hardware ID solo como binding
key = argon2id_derive(passphrase, salt=device_secret)
session_key = hkdf_expand(key, info=hardware_id, context=b"session")
```

---

## 4. VTR-CRYPTO-003 — Validación defensiva antes de operación criptográfica

**Regla:** Toda función criptográfica valida sus inputs **antes** de invocar la
librería subyacente. Ningún `None`, bytes vacíos, longitud incorrecta, o tipo no
esperado llega a PyNaCl o `cryptography` sin pasar primero por una excepción
específica del dominio.

**Por qué:** Las librerías criptográficas están diseñadas para asumir inputs ya
validados; pasarles datos malformados puede producir comportamiento indefinido,
mensajes de error que filtran información (timing attacks de validación), o en
el peor caso, un fallback silencioso a un estado inseguro.

**Jerarquía de excepciones:** definida en `crypto_layer/errors.py` (propuesta #3).

**Ejemplo correcto:**
```python
def derive_device_key(hardware_id: bytes, device_secret: bytes) -> bytes:
    if hardware_id is None or device_secret is None:
        raise InvalidHardwareIDError("hardware_id y device_secret no pueden ser None")
    if len(device_secret) != 32:
        raise InvalidDeviceSecretError(f"device_secret debe ser 32 bytes, recibido {len(device_secret)}")
    if not isinstance(hardware_id, bytes) or not isinstance(device_secret, bytes):
        raise TypeError("hardware_id y device_secret deben ser bytes")
    # Solo aquí se invoca la librería subyacente
    return _argon2id_derive(salt=device_secret, info=hardware_id)
```

---

## 5. VTR-CRYPTO-004 — Protección de identidad de firmware en hardware ESP32-S3

> Regla nueva, derivada de la decisión documentada en esta sesión sobre el
> mecanismo de protección del Heltec WiFi LoRa 32 V3.

**Contexto:** El Heltec ejecuta firmware en C/C++ (Arduino o ESP-IDF) sobre un
ESP32-S3, no Python. Según la decisión de la Épica A (modos de derivación 1B
aplicada a firmware), el Heltec **no deriva claves en tiempo de ejecución** — el
eFuse guarda la clave maestra Ed25519 generada una sola vez en bench, sin
derivación posterior. Esta regla define cómo ese eFuse queda protegido contra
suplantación, captura o manipulación por personal no autorizado, usando
exclusivamente capacidades nativas del chip ya adquirido — sin hardware
adicional ni HSM externo.

**Hallazgo verificado:** el ESP32-S3 soporta nativamente, sin necesidad de chip
adicional, los siguientes mecanismos vía eFuse:

1. **Secure Boot V2** — el ROM bootloader verifica la firma RSA-3072 de cada
   imagen de bootloader y aplicación contra un digest SHA-256 guardado en eFuse,
   en cada arranque y en cada actualización OTA. Si la verificación falla,
   intenta la siguiente imagen firmada disponible; si ninguna es válida, aborta
   el arranque.
2. **Flash Encryption** — todo el contenido del flash queda cifrado con AES-XTS
   de 256 bits usando una llave generada en el propio eFuse, inaccesible por
   software una vez habilitada la protección de lectura.
3. **Deshabilitación de superficies de ataque físico** — al habilitar Secure
   Boot/Flash Encryption se deshabilita la pila USB-OTG en ROM (sin DFU/serial
   emulation), y se puede deshabilitar JTAG (`DIS_PAD_JTAG`, `SOFT_DIS_JTAG`) y
   el modo de descarga manual sin cifrar (`DIS_DOWNLOAD_MANUAL_ENCRYPT`).
4. **Irreversibilidad por diseño** — una vez habilitado Secure Boot, ya no es
   posible aplicar protección de lectura adicional sobre las eFuses que
   contienen el digest de la llave pública; esto es intencional, para que un
   atacante no pueda usar un downgrade de protección como vector de bypass de
   firma.

**Decisión fijada:**

VTR-CRYPTO-004: Todo Heltec WiFi LoRa 32 V3 desplegado en campo **debe** tener,
antes de salir del bench de provisioning:

- `SECURE_BOOT_EN` habilitado.
- Flash Encryption habilitado en modo `Release` (no `Development`), con llave
  generada por el propio eFuse en primer boot (no inyectada externamente).
- `DIS_PAD_JTAG`, `SOFT_DIS_JTAG`, `DIS_USB_JTAG` y
  `DIS_DOWNLOAD_MANUAL_ENCRYPT` habilitados.
- `ENABLE_SECURITY_DOWNLOAD` habilitado y `RD_DIS` aplicado sobre los bloques de
  llave (BLOCK4–BLOCK10), de forma que ningún bloque de llave quede legible por
  software tras el provisioning.

**Orden de quemado de eFuses (obligatorio, no intercambiable):**

Existe un conflicto de diseño entre Secure Boot V2 (su llave debe permanecer
legible) y Flash Encryption (su llave debe quedar protegida contra lectura). El
procedimiento correcto, a documentar en el SOP de provisioning (Épica C, tarea
C2/E11), sigue este orden:

1. Habilitar eFuses de hardening físico primero (`DIS_PAD_JTAG`,
   `DIS_DOWNLOAD_ICACHE`, `DIS_DOWNLOAD_DCACHE`, `DIS_DIRECT_BOOT`,
   `DIS_USB_JTAG`, `DIS_DOWNLOAD_MANUAL_ENCRYPT`) vía `espefuse burn_efuse`.
2. Quemar la llave de Secure Boot V2 en `BLOCK_KEY2` con propósito
   `SECURE_BOOT_DIGEST0` y habilitar `SECURE_BOOT_EN`.
3. Habilitar Flash Encryption en modo Release — el bootloader de segunda etapa
   genera su propia llave AES-XTS la primera vez que detecta
   `SPI_BOOT_CRYPT_CNT` en su valor por defecto.
4. Aplicar `RD_DIS` sobre los bloques de llave una vez confirmado que el
   dispositivo arranca correctamente con ambas protecciones activas.
5. Habilitar `ENABLE_SECURITY_DOWNLOAD` al final, como última eFuse irreversible
   del lote.

**Riesgo residual aceptado:** una vez quemadas estas eFuses, son irreversibles
por diseño del chip. Un error en el procedimiento de bench (ej. quemar
`RD_DIS` antes de confirmar que el dispositivo arranca) puede dejar un Heltec
inutilizable. **Mitigación:** el procedimiento de bench debe probarse primero
sobre al menos 1 unidad de descarte/desarrollo antes de aplicarse a los 2
Heltec de producción ya adquiridos.

**No cubierto por esta regla (queda fuera de alcance v0.5.0):** ataques de
inyección de fallos (fault injection) contra el propio mecanismo de verificación
de Secure Boot. Es un vector reconocido en la literatura de seguridad de
hardware, pero mitigarlo requiere medidas físicas (potting, blindaje) fuera del
alcance de software de esta fase. Se documenta como riesgo aceptado, no como
omisión silenciosa.

---

## 6. Resumen de las 4 reglas

| Regla | Enunciado breve | Aplica a |
|---|---|---|
| VTR-CRYPTO-001 | Nunca SHA-256 puro sobre secretos de baja entropía | crypto_layer.py |
| VTR-CRYPTO-002 | Hardware ID público ≠ salt criptográfico | crypto_layer.py |
| VTR-CRYPTO-003 | Validación defensiva antes de toda operación cripto | crypto_layer.py, firmware Heltec (versión C++) |
| VTR-CRYPTO-004 | Secure Boot V2 + Flash Encryption + hardening eFuse obligatorio | Firmware Heltec (ESP32-S3) |

---

## 7. Referencias

- OWASP Password Hashing Cheat Sheet 2024 (parámetros Argon2id)
- RFC 8032 (Ed25519), RFC 5869 (HKDF), RFC 8017 (RSA-PSS, usado por Secure Boot V2)
- IEC 62443-3-3 SR 1.1, 1.5, 1.8, 2.1
- Espressif ESP-IDF Programming Guide — Secure Boot V2 / Flash Encryption (ESP32-S3)
- CVE-2025-69277 (libsodium), CVE-2026-26007 (pyca/cryptography)

---

## 8. Pendientes que este documento NO resuelve (quedan en roadmap)

- Mecanismo exacto de generación y custodia de `device_secret` antes del primer
  boot (Épica C — diseño pendiente, confirmado en esta sesión).
- Procedimiento físico completo de bench para Secure Boot V2 + Flash Encryption
  del Heltec (Épica C2 / E11 — este documento fija QUÉ se habilita, no el SOP
  paso a paso con comandos exactos para el bench principal).
- Mitigación de fault injection contra Secure Boot (fuera de alcance v0.5.0,
  riesgo aceptado documentado en sección 5).
