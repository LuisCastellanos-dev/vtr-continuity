# VTR Continuity — Estado del Proyecto v0.5.0

> **Estado:** 6 de 10 propuestas de la fase criptográfica generadas:
> `docs/VTR-CRYPTO-001.md`, `docs/VTR-PKI-001.md`, `crypto_layer/errors.py`,
> `crypto_layer/__init__.py`, `crypto_layer/argon2_derive.py`,
> `crypto_layer/hkdf_expand.py`. La #6 se validó contra 2 vectores
> oficiales de RFC 5869 (Apéndice A, Test Case 1 y 2 para SHA-256),
> coincidencia exacta byte por byte — no una aproximación. Integración
> end-to-end confirmada: derivación de session keys y transport keys por
> canal (LoRa, BLE) a través de la API pública completa. Siguiente
> entregable: propuesta #7 (`crypto_layer/ed25519_sign.py`).

---

## 1. Alcance del proyecto

VTR Continuity es la capa de continuidad de comunicación para entornos
OT/ICS-SCADA bajo condiciones adversas (jamming, pérdida de conectividad,
infraestructura industrial hostil). La v0.5.0 introduce el **Fallback Tier 2
RF**: transporte LoRa 915 MHz, BLE Mesh de corto alcance, DTN Bundle Protocol
(RFC 9171), y Sneakernet `.vtrc` como respaldo extremo.

Esta fase de trabajo cubre específicamente la **capa criptográfica** que
sostiene todo lo anterior: derivación de llaves, firma de bundles, PKI de dos
niveles, y la jerarquía de excepciones que materializa la validación
defensiva exigida por las reglas del proyecto.

---

## 2. Estructura de archivos del proyecto

```
vtr-continuity/
├── HANDOFF.md                          # Contexto técnico completo
├── README.md                           # Este archivo
├── docs/
│   ├── ROADMAP-v0.5.0.md              # Plan en 5 épicas con prioridades
│   ├── DECISIONS-v0.5.0.md            # Pro/cons de cada decisión técnica
│   ├── VTR-CRYPTO-001.md              # ✅ 4 reglas cripto + librerías verificadas
│   └── VTR-PKI-001.md                 # ✅ PKI dos niveles + custodia SSS 3-de-5
├── crypto_layer/
│   ├── errors.py                      # ✅ 21 excepciones, 5 categorías
│   ├── __init__.py                    # ✅ API pública — CryptoLayer, CryptoConfig
│   ├── argon2_derive.py               # ✅ Profiles embedded/desktop/hardened, lanes=1
│   └── hkdf_expand.py                 # ✅ RFC 5869 HKDF-Expand, validado con vectores oficiales
└── specs/
    └── PROPOSALS-10.md                # Especificación de las 10 propuestas
```

---

## 3. Decisiones técnicas aprobadas

| # | Decisión | Elegido | Por qué |
|---|---|---|---|
| 1 | Modos de derivación de clave | **1B** — `derive_device_key` + `derive_operator_key` separados | Capability separation + disponibilidad del proxy DMZ |
| 2 | Profile Argon2id | **2D** con default `desktop` (64 MiB, 3 iteraciones) + derivación async | Cumple OWASP 2024 sin bloquear el boot |
| 3 | Generación de `device_secret` | **3A** — bench air-gapped (3C diferido a v0.6) | Auditable y manejable a la escala actual del proyecto |
| 4 | Firma de provisioning | **4C** — CA de dos niveles, root offline + intermediate online | Trust anchor completo sin requerir HSM en v0.5.0 |
| 5 | Custodia de la CA root | **Shamir's Secret Sharing 3-de-5** (PyCryptodome), adelantado desde v0.6 | Elimina punto único de fallo ante pérdida total del bench físico |

Ver `docs/DECISIONS-v0.5.0.md` para el análisis completo de pros/contras de
cada opción evaluada.

---

## 4. Las 4 reglas criptográficas permanentes (VTR-CRYPTO-001)

- **VTR-CRYPTO-001:** nunca SHA-256 puro sobre secretos de baja entropía.
  Argon2id para derivación desde passphrase/hardware ID; HKDF-SHA256 para
  expansión de subclaves; Ed25519 para integridad de bundles.
- **VTR-CRYPTO-002:** el hardware ID (público, extraíble) nunca es salt
  criptográfico. El salt real es el `device_secret` (32 bytes aleatorios,
  partición read-only firmada por CA). **Estado: diseño pendiente, no
  implementado** — ningún código de producción debe asumir su existencia.
- **VTR-CRYPTO-003:** validación defensiva antes de cualquier operación
  criptográfica. Ningún input `None`, vacío, de longitud incorrecta, o de
  tipo inesperado llega a la librería subyacente sin pasar primero por una
  excepción específica del dominio (ver `crypto_layer/errors.py`).
- **VTR-CRYPTO-004:** todo nodo Heltec WiFi LoRa 32 V3 debe salir del bench
  con Secure Boot V2 + Flash Encryption (modo Release) + hardening de eFuse
  (JTAG/USB-OTG/descarga manual deshabilitados) antes de desplegarse en
  campo. Verificado contra documentación oficial de Espressif — el
  ESP32-S3 soporta esto nativamente, sin hardware adicional.

**Librerías fijadas, con justificación basada en CVEs verificados:**

| Primitiva | Librería | Versión mínima |
|---|---|---|
| Ed25519, XChaCha20-Poly1305 | PyNaCl (libsodium) | ≥1.6.2 (post CVE-2025-69277) |
| Argon2id, HKDF-SHA256 | cryptography (pyca) | ≥45.0 (post CVE-2026-26007) |
| Construcción/firma X.509 (CA) | cryptography (pyca) | ≥45.0 |
| Shamir's Secret Sharing | PyCryptodome | ≥3.20 |

Revisión de CVEs de estas librerías cada trimestre natural; parche crítico
fuera de ciclo en ≤72 horas.

---

## 5. Esquema PKI (VTR-PKI-001)

```
VTR-Root-CA (Ed25519, 10 años, offline)
  └── VTR-Provisioning-Intermediate (Ed25519, 2 años, online en bench)
         ├── device-001.vtr.local (18 meses)
         ├── device-002.vtr.local (18 meses)
         └── ...
```

**Custodia de la CA root — Shamir's Secret Sharing 3-de-5:**

El esquema matemático de Shamir es sólido; las implementaciones rotas en
producción (caso documentado: backups fragmentados de una wallet de
criptomonedas que usó hashing determinista en vez de un generador de
números aleatorios real para los coeficientes del polinomio, permitiendo
reconstrucción con solo 2 partes sin importar el umbral configurado) fallan
en la generación de aleatoriedad o en la falta de validación de integridad,
no en la teoría. El diseño aplicado aquí incluye 4 capas de mitigación
explícitas:

1. **Verificación de RNG** — test que confirma que dos fragmentaciones
   independientes del mismo secreto producen partes distintas.
2. **HMAC de integridad** — calculado sobre el secreto original antes de
   fragmentar, verificado tras cada reconstrucción; rechaza la
   reconstrucción si no coincide.
3. **Umbral estricto 3-de-5** — sin reconstrucción parcial con menos partes.
4. **Custodia distribuida** — sin concentración geográfica de las 5 partes.

**Estado de la distribución de custodios:** la parte 1 vive junto al bench
físico (caja fuerte). Las partes 2, 3, 4 y 5 — ubicación secundaria, persona
de confianza designada, backup fuera del sitio principal, y reserva de
emergencia — son **pendiente operativo**, sujetas a decisión y logística
propias del despliegue, no resueltas por este documento.

El procedimiento de recuperación ante pérdida total del bench está anclado a
NIST SP 800-57 (gestión de ciclo de vida de llaves criptográficas) e
ISO/IEC 27037 (cadena de custodia de evidencia digital).

---

## 6. Jerarquía de excepciones (`crypto_layer/errors.py`)

21 excepciones en 5 categorías, todas derivadas de `CryptoError`:

| Categoría | Cubre |
|---|---|
| `ConfigError` | Profile inválido, campos de configuración faltantes |
| `InputValidationError` | Passphrase, hardware ID, device_secret, longitud de llave, nonce — validados antes de tocar la librería subyacente |
| `CryptoOperationError` | Fallos durante la derivación, verificación de firma, o integridad de bundle |
| `ProvisioningError` | Emisión rutinaria de certificado de dispositivo |
| `CustodyError` | Reconstrucción de la CA root vía SSS — categoría separada de `ProvisioningError` porque son superficies de riesgo distintas: provisioning es operación de alto volumen y bajo riesgo individual, mientras que reconstruir la llave raíz de toda la flota es un evento de emergencia de bajo volumen y alto riesgo |

---

## 7. Las 10 propuestas de la fase criptográfica

| # | Entregable | Cubre | Estado |
|---|---|---|---|
| 1 | `docs/VTR-CRYPTO-001.md` | Reglas cripto consolidadas | ✅ Generado |
| 2 | `docs/VTR-PKI-001.md` | Esquema PKI + custodia SSS | ✅ Generado |
| 3 | `crypto_layer/errors.py` | Jerarquía de excepciones | ✅ Generado |
| 4 | `crypto_layer/__init__.py` | API pública (CryptoLayer + CryptoConfig) | ✅ Generado |
| 5 | `crypto_layer/argon2_derive.py` | Derivación con profile + async | ✅ Generado (tiempo pendiente de validar en RPi 4) |
| 6 | `crypto_layer/hkdf_expand.py` | Expansión de subclaves (RFC 5869) | ✅ Generado, validado contra vectores oficiales |
| 6 | `crypto_layer/hkdf_expand.py` | Expansión de subclaves | Pendiente |
| 7 | `crypto_layer/ed25519_sign.py` | Firma/verificación de `.vtrc` | Pendiente |
| 8 | `config/rf_config.yaml` | Sección `crypto:` parametrizada | Pendiente |
| 9 | `tests/test_crypto_layer.py` | Tests felices + ≥15 adversariales | Pendiente |
| 10 | `docs/DOD-v0.5.0.md` | Definition of Done actualizado | Pendiente |

El orden de generación sigue un criterio explícito: se prioriza lo que pueda
refinar o modificar cualquier fase previa y reduzca el riesgo del conjunto —
por eso las reglas (#1) y el esquema PKI (#2) preceden a cualquier código, y
la jerarquía de excepciones (#3) precede a la API pública (#4) que la
consume.

---

## 8. Pendientes explícitos — no resueltos por diseño, no por omisión

- `device_secret` (32 bytes aleatorios) y su partición read-only firmada por
  CA: **diseño pendiente**, no implementado. Ningún código de producción
  debe asumir su disponibilidad.
- Custodios de las partes SSS 2, 3, 4 y 5 de la CA root: **pendiente
  operativo**, depende de logística y decisiones propias del despliegue.
- Procedimiento detallado paso a paso de la ceremonia de firma de la CA con
  comandos exactos para el bench físico: queda para el SOP de provisioning
  (Épica C).
- Mitigación de ataques de inyección de fallos (fault injection) contra
  Secure Boot del Heltec: fuera de alcance de v0.5.0, riesgo aceptado y
  documentado, no una omisión silenciosa.

---

## 9. Empaquetar el estado actual para llevarlo a otro entorno

```bash
# Desde la raíz del repo vtr-continuity
git pull
mkdir -p ~/vtr_handoff_$(date +%Y%m%d)
cp -r docs/ specs/ crypto_layer/ HANDOFF.md README.md ~/vtr_handoff_$(date +%Y%m%d)/
cd ~ && tar czf vtr_handoff_$(date +%Y%m%d).tar.gz vtr_handoff_$(date +%Y%m%d)/
```
