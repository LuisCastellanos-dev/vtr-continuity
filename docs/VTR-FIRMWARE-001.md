# VTR-FIRMWARE-001 — Especificación de firmware Heltec: eFuse + Ed25519

> **Origen:** omisión O#6 (`docs/HANDOFF.md`), tarea E6
> (`docs/ROADMAP-v0.5.0.md`), checklist pre-release post-#10
> (`docs/DOD-v0.5.0.md` §5).
> **Relación con documentos existentes:** `docs/VTR-CRYPTO-001.md` §5
> (`VTR-CRYPTO-004`) ya define qué eFuses habilitar y en qué orden. Este
> documento **no repite eso** — extiende la pieza que faltaba: qué
> librería implementa Ed25519 en el firmware C/C++, y cómo esa firma se
> integra con el formato real de bundle `.vtrc`
> (`crypto_layer/vtrc_bundle.py`) que ya corre en el lado RPi/servidor.
> **Estado del código de firmware en el repo:** no existe ningún archivo
> `.ino`/`.cpp`/`.c`/`.h` en el repositorio todavía — esta es una
> especificación de diseño, sin implementación de referencia que
> verificar contra código real, a diferencia de los documentos previos
> de esta fase.

---

## 0. Corrección de alcance respecto al enunciado original

La tarea E6 nombra **"micro-ecc/libsodium"** como si fueran opciones
intercambiables para Ed25519. **Verificado contra documentación real del
ecosistema ESP32, esto es incorrecto:**

- **`micro-ecc` no implementa Ed25519.** Es una librería de curvas
  elípticas centrada en ECDSA/ECDH sobre curvas como secp256r1,
  secp256k1, P-256 — confirmado por múltiples proyectos del ecosistema
  ESP32/embedded que la usan exactamente para eso (ej. `esp8266ndn`:
  "ECDSA: P-256 curve only \[...\] Ed25519: no"). No es una alternativa
  válida a `libsodium` para esta tarea — es una librería para un
  problema distinto.
- La única opción real para Ed25519 nativo en C/C++ sobre ESP32 es
  **`libsodium`** (vía el componente oficial de ESP-IDF) o
  implementaciones de referencia más pequeñas y menos auditadas como
  `c25519` (dominio público, Daniel Beer) o `Ed25519ESP32`. Esta
  especificación fija `libsodium` como la decisión, no como una opción
  entre varias — ver §1.

Esta corrección se documenta explícitamente porque construir sobre el
enunciado original sin verificarlo habría llevado a especificar una
librería (`micro-ecc`) que físicamente no puede cumplir el requisito
pedido.

---

## 1. Librería elegida — justificación verificada

### 1.1 Comparación real de las opciones disponibles

| Librería | Soporta Ed25519 nativo | Auditoría/madurez | Aceleración por hardware ESP32 |
|---|---|---|---|
| `micro-ecc` | ❌ No (solo ECDSA/ECDH) | N/A para este caso | N/A para este caso |
| `libsodium` (componente ESP-IDF) | ✅ Sí, `crypto_sign` completo | Alta — implementación de referencia de libsodium, la misma familia ya elegida para `crypto_layer/ed25519_sign.py` (PyNaCl/libsodium) en el lado Python | ❌ No — corre en software puro; confirmado en foro oficial de Espressif: "right now libsodium use software implementations. Only mbedTLS can enable hardware acceleration" |
| `mbedTLS` (incluido en ESP-IDF) | ❌ No en build estándar — Ed25519/EdDSA queda "capability-gated to platform support" en wrappers de terceros que sí lo intentan exponer | Alta — es el stack TLS oficial de Espressif | ✅ Sí — AES, SHA, y operaciones RSA/bignum aceleradas por hardware |
| `c25519` (Daniel Beer, dominio público) | ✅ Sí | Baja — implementación de referencia, sin auditoría formal conocida, mantenida por comunidad pequeña | ❌ No |

**Decisión: `libsodium`**, vía el componente oficial de ESP-IDF
(`idf.py add-dependency` o el directorio `components/libsodium` del SDK,
según la versión).

**Por qué, a pesar de no tener aceleración por hardware:**

1. **Consistencia de familia criptográfica con el resto del proyecto.**
   `crypto_layer/ed25519_sign.py` ya usa PyNaCl (bindings Python sobre
   libsodium) para la misma operación en el lado RPi/servidor. Usar
   libsodium en el firmware significa que la **misma implementación de
   referencia** de Ed25519 firma y verifica en ambos extremos de la
   cadena de confianza — no dos implementaciones distintas de la misma
   primitiva que podrían, en teoría, tener semántica ligeramente
   distinta en casos de borde (ej. validación de puntos de baja orden,
   que fue precisamente el CVE-2025-69277 que `VTR-CRYPTO-001.md` ya
   evaluó para la versión Python).
2. **El costo de no tener aceleración por hardware es aceptable para
   este caso de uso.** La firma Ed25519 ocurre una vez por bundle
   `.vtrc` generado por el Heltec (no en un loop de alta frecuencia) —
   el presupuesto de tiempo relevante es el de transmisión LoRa (cientos
   de ms a segundos por frame, según `rf_config.yaml`: SF9/BW125), no el
   de la operación criptográfica en sí, que en software puro sobre un
   ESP32-S3 a 240MHz toma del orden de milisegundos para Ed25519
   (consistente con benchmarks públicos de µECC/Ed25519 en ESP32 a 240MHz
   reportando ~0.021-0.048s por operación de punto, para una librería
   *no* optimizada en ensamblador — libsodium en C puro está en ese
   rango o mejor).
3. **`mbedTLS` no es una alternativa real** porque su soporte de
   Ed25519/EdDSA no está expuesto de forma estable en el build estándar
   de ESP-IDF para firma de aplicación general (distinto de su uso
   interno en MCUboot/Secure Boot, que sí soporta Ed25519 como una de
   sus 4 opciones de firma de imagen — pero esa es una API interna del
   bootloader, no una librería de propósito general expuesta a la
   aplicación).

### 1.2 Riesgo de versión real, no genérico — verificado contra el chip exacto del proyecto

**Hallazgo de compatibilidad de versión:** Espressif movió `libsodium`
de componente incluido por defecto a **componente opcional** al pasar
de ESP-IDF 4.x a ESP-IDF 5.x. Esto tiene una consecuencia directa y
confirmada: **Arduino-ESP32 v3 (que usa ESP-IDF 5 internamente) ya no
incluye `libsodium`** — `#include <sodium.h>` falla en ese framework sin
agregar el componente manualmente. Esto importa para una decisión
operativa concreta de este proyecto:

**Decisión:** el firmware Heltec usa **ESP-IDF directamente, no el
framework Arduino**, y fija `libsodium` como dependencia explícita del
proyecto (vía `idf_component.yml` o como submódulo de
`components/libsodium`), nunca asumiendo que viene incluido por defecto
en ninguna versión del SDK. Esto es consistente con el patrón ya
establecido en `VTR-CRYPTO-001.md` §1.2 (pin de versión explícito,
revisión trimestral) — no se asume disponibilidad implícita de una
dependencia crítica de seguridad.

**Sobre el riesgo de PSRAM/heap-corruption — verificado y descartado
para este hardware exacto:** existe un issue documentado en el
repositorio oficial de `espressif/esp-idf` (#8742) sobre corrupción de
heap en `crypto_sign_ed25519_detached` específicamente cuando el chip
usa **PSRAM (SPI SRAM)** en variantes ESP32-S3. **Verificado contra la
especificación oficial del fabricante:** el Heltec WiFi LoRa 32 V3 usa
el `ESP32-S3FN8`, que **no tiene PSRAM externa** — confirmado
explícitamente en la FAQ oficial de Heltec ("No, the WiFi LoRa 32 don't
have an external PSRAM") y en la tabla de especificaciones (memoria:
384KB ROM, 512KB SRAM, 16KB RTC SRAM, 8MB Flash — sin PSRAM listada).
**Este riesgo específico no aplica a los 2 Heltec V3 ya adquiridos para
este proyecto.** Se documenta aquí explícitamente para que, si en algún
momento el proyecto migra al Heltec V4 (que sí usa `ESP32-S3R2` con 2MB
de PSRAM), este riesgo se reevalúe — no se asuma que sigue siendo
irrelevante solo porque lo era para el V3.

---

## 2. Integración con el formato de bundle `.vtrc` real

### 2.1 Qué firma el Heltec, y con qué formato

El Heltec no construye un bundle `.vtrc` completo en el sentido del
módulo `crypto_layer/vtrc_bundle.py` (ese formato — header con
`node_id`/`counter` fijos, metadata JSON, canonicalización
`header‖payload‖metadata` — es responsabilidad del lado que ya tiene
Python disponible: RPi o servidor). El Heltec firma su **payload de
telemetría/evento crudo** con su propia llave Ed25519 (generada una vez
en bench, según `VTR-CRYPTO-004`, sin derivación en tiempo de ejecución)
antes de transmitirlo por LoRa.

**Estructura mínima que el firmware produce, byte a byte:**

```
firma (64 bytes, Ed25519) || payload (N bytes, telemetría cruda)
```

Esta es **deliberadamente la misma estructura mínima** que
`crypto_layer/field_config_verifier.py` ya usa para configuración de
campo (`signature || yaml_bytes`) — no el formato completo de
`vtrc_bundle.py` con header de `node_id`/`counter`. La razón es la misma
que se documentó en ese módulo: el Heltec, como emisor de telemetría
cruda sobre LoRa, ya tiene su replay protegido por la Capa 1 existente
(`core/crypto_transport.py::NonceCounter`/`ReplayWindow`, que opera
sobre el `EncryptedBundle` completo, no sobre la firma Ed25519
individual del payload). Agregar un segundo mecanismo de
`node_id`/`counter` específico de esta firma sería duplicar protección
ya existente en una capa distinta — el mismo principio de "minimizar
superficie nueva, maximizar reuso" ya aplicado en cada decisión previa
de esta fase.

**Quién verifica esta firma:** el RPi, al recibir el frame LoRa
reensamblado (`core/dtn_fragmenter.py::BundleFragmenter.reassemble()`),
extrae los primeros 64 bytes como firma y el resto como payload, y
verifica contra la llave pública del Heltec emisor — la misma llave que
quedó registrada en su certificado de dispositivo al momento del
provisioning (`VTR-PKI-001.md` §3.3).

### 2.2 Pseudocódigo de la operación de firma en firmware (C, ESP-IDF)

```c
// Pseudocódigo de especificación — no implementación final.
// La llave privada vive únicamente en el eFuse (BLOCK_KEY,
// protegida con RD_DIS según VTR-CRYPTO-004), nunca en RAM
// más tiempo del estrictamente necesario para la operación de firma.

#include <sodium.h>

// Firma un payload de telemetría con la llave Ed25519 del dispositivo.
// Retorna 0 en éxito, distinto de 0 en error — el llamador NUNCA debe
// transmitir el payload si esta función no retorna éxito.
//
// Firma real confirmada de libsodium (no aproximada):
//   int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
//                             const unsigned char *m, unsigned long long mlen,
//                             const unsigned char *sk);
int vtr_sign_payload(
    const uint8_t *payload, unsigned long long payload_len,
    uint8_t *out_signed_buffer  // debe tener payload_len + 64 bytes
) {
    uint8_t device_private_key[64];  // formato libsodium: 32 bytes seed + 32 bytes pubkey

    // Leer la llave privada SOLO desde el eFuse protegido, nunca
    // hardcodeada ni almacenada en flash sin cifrar.
    if (vtr_efuse_read_device_key(device_private_key) != 0) {
        return -1;  // fallo de lectura del eFuse — abortar, no continuar
    }

    unsigned char signature[64];  // crypto_sign_BYTES == 64
    if (crypto_sign_detached(signature, NULL, payload, payload_len,
                              device_private_key) != 0) {
        sodium_memzero(device_private_key, sizeof(device_private_key));
        return -2;  // fallo de la operación de firma — abortar
    }

    // Limpieza explícita de la llave privada de RAM — mismo principio
    // que VTR-PKI-001.md §3.2 aplica a la llave Root reconstruida:
    // no depender del garbage collector ni de que el compilador no
    // optimice el zero-fill (sodium_memzero existe precisamente para
    // resistir esa optimización).
    sodium_memzero(device_private_key, sizeof(device_private_key));

    memcpy(out_signed_buffer, signature, 64);
    memcpy(out_signed_buffer + 64, payload, payload_len);
    return 0;
}
```

**Nota deliberada sobre `vtr_efuse_read_device_key`:** esta función no
se especifica en detalle aquí — su implementación exacta depende del
procedimiento de bench definido en `VTR-CRYPTO-004` (qué bloque de eFuse
exacto, con qué propósito de `BLOCK_KEYn` se quema la llave del
dispositivo) y queda como parte del SOP de provisioning ya identificado
como pendiente en ese documento (Épica C2/E11) — esta especificación no
inventa un procedimiento que el documento de referencia ya marcó como
no resuelto.

---

## 3. Manejo de errores y validación defensiva — consistente con VTR-CRYPTO-003

`VTR-CRYPTO-001.md` §4 (`VTR-CRYPTO-003`) fija como regla permanente que
"ningún `None`, bytes vacíos, longitud incorrecta, o tipo no esperado
llega a [la librería] sin pasar primero por una excepción específica del
dominio" — esa regla se escribió en términos de Python (excepciones),
pero el principio aplica igual en C, con el vocabulario de errores que
el lenguaje permite:

| Condición de entrada inválida | Comportamiento exigido |
|---|---|
| `payload` es `NULL` | `vtr_sign_payload` retorna error inmediatamente, sin tocar el eFuse |
| `payload_len` es 0 | Retorna error — un payload vacío no debe firmarse ni transmitirse |
| `payload_len` excede el tamaño máximo de fragmento LoRa (222 bytes según el diseño ya establecido de `BundleFragmenter`) | Retorna error — la fragmentación es responsabilidad de una capa distinta; esta función no fragmenta silenciosamente un payload que no le corresponde |
| Fallo de lectura del eFuse | Retorna error, **nunca** sustituye con una llave de respaldo o un valor por defecto — un dispositivo que no puede leer su llave real no debe poder firmar con ninguna otra |
| `crypto_sign_detached` retorna código de error de libsodium | Se propaga como error — nunca se asume éxito sin verificar el código de retorno explícitamente (omitir esa verificación es exactamente el tipo de bug que ha producido vulnerabilidades reales en código C que envuelve librerías criptográficas) |

---

## 4. Qué NO resuelve esta especificación — pendientes explícitos

- **Procedimiento exacto de bench para generar y quemar la llave Ed25519
  del dispositivo en el eFuse** — ya identificado como pendiente en
  `VTR-CRYPTO-001.md` §8 y `VTR-CRYPTO-004` (Épica C2/E11). Esta
  especificación asume que ese procedimiento existirá y que su
  resultado es una llave privada de 64 bytes en formato libsodium
  accesible solo vía `vtr_efuse_read_device_key()` — no define cómo esa
  función lee el eFuse internamente.
- **Build system completo del proyecto de firmware** (estructura de
  `CMakeLists.txt`, configuración de partición, integración con el
  proceso de Secure Boot V2/Flash Encryption ya definido en
  `VTR-CRYPTO-004`) — esta especificación cubre la operación
  criptográfica de firma, no el proyecto ESP-IDF completo.
- **Implementación real de `vtr_sign_payload`** — lo presentado en §2.2
  es pseudocódigo de especificación, escrito para fijar la interfaz y el
  manejo de errores, no código compilado ni probado contra hardware
  real. No existe ningún archivo `.c`/`.h` en el repositorio todavía.
- **Integración con `BundleFragmenter`/`GhostScheduler` del lado
  firmware** — cómo el Heltec decide cuándo transmitir un frame real
  versus esperar, y cómo coordina con el `NonceCounter` de Capa 1, es
  lógica que hoy solo existe en Python (`core/crypto_transport.py`,
  `core/dtn_fragmenter.py`) y que el firmware real necesitará replicar o
  invocar de alguna forma — esa integración completa queda fuera del
  alcance de esta especificación, que se limita a la operación de firma
  Ed25519 y su empaquetado mínimo.
