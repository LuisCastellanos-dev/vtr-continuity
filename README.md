# VTR Continuity — Estado del Proyecto v0.5.0

> **Estado en GitHub (rama `main`):** 10 de 10 propuestas de la fase
> criptográfica generadas, validadas con tests reales, y sincronizadas en
> el repositorio. La suite formal de tests (`tests/test_crypto_layer.py`)
> ejecuta 70 casos (68 pasan, 2 documentados como skip explícito por
> ausencia de la lógica que prueban) con 95% de coverage real medido en
> `crypto_layer/` — ambos criterios de aceptación de la propuesta #9
> cumplidos con números verificados, no proyectados.
>
> **100% de la fase criptográfica ≠ v0.5.0 lista para piloto.** El cierre
> de las 10 propuestas certifica el código y los documentos que estaban
> dentro de su alcance original. El estado real frente al Definition of
> Done completo — incluyendo bloques pendientes fuera de esas 10
> propuestas (provisioning operativo, `storage_guardian.py`, modelo STRIDE,
> tests Jest del stack RF, site survey) — vive en
> `docs/DOD-v0.5.0.md`.

## 0. Avance verificable — propuestas vs. archivos en el repo

| # | Propuesta | Ruta en el repo | Validación aplicada |
|---|---|---|---|
| 1 | Reglas cripto consolidadas | `docs/VTR-CRYPTO-001.md` | 4 reglas, librerías justificadas por CVE |
| 2 | Esquema PKI dos niveles | `docs/VTR-PKI-001.md` | Custodia SSS 3-de-5, ancla NIST/ISO |
| 3 | Jerarquía de excepciones | `crypto_layer/errors.py` | 21 excepciones, 5 categorías, probado contra código de ejemplo de #1 y #2 |
| 4 | API pública | `crypto_layer/__init__.py` | 12 tests reales — capability separation confirmada |
| 5 | Derivación Argon2id | `crypto_layer/argon2_derive.py` | `lanes` corregido 4→1 tras medición real; tiempo <250ms pendiente de validar en RPi 4 |
| 6 | Expansión HKDF | `crypto_layer/hkdf_expand.py` | 2 vectores oficiales RFC 5869, coincidencia exacta |
| 7 | Firma Ed25519 | `crypto_layer/ed25519_sign.py` | 2 vectores oficiales RFC 8032, rechazo de bundle modificado confirmado |
| 8 | Config runtime + loader | `config/rf_config.yaml` + `crypto_layer/rf_config_loader.py` | 7 tests adversariales, integración end-to-end con #4-#7 |
| 9 | Suite de tests formal | `tests/test_crypto_layer.py` | 70 tests (68 pasan, 2 skip documentado), 95% coverage real en `crypto_layer/` |
| 10 | Definition of Done | `docs/DOD-v0.5.0.md` | 7 bloques completados, 4 parciales, 6 pendientes — ver §0 del documento |

**Progreso: 10/10 (100%) de la fase criptográfica.** Cada propuesta nueva se
validó contra las ya generadas antes de darse por cerrada — no son archivos
aislados, forman una cadena verificada (config → loader → CryptoConfig →
CryptoLayer → derivación/firma reales), con ejecución real en cada paso, no
solo revisión visual del código.

---

## 0.1 Avance del checklist pre-release (post-#10)

> El checklist completo de 14 puntos vive en `docs/DOD-v0.5.0.md` §5. Esta
> sección rastrea avance puntual a medida que se cierran ítems — no
> reemplaza al DOD, lo complementa.

| Ítem del checklist | Estado | Evidencia |
|---|---|---|
| Decisión arquitectónica Q-01/Q-02/Q-03 documentada | ✅ COMPLETADO | `docs/VTR-ARCH-DECISIONS-001.md` — heartbeat pasivo vía `NonceCounter` (Q-01), counter dentro del bundle `.vtrc` en vez de RTC (Q-02), config de campo firmada por PKI existente (Q-03). Ninguna introduce primitiva criptográfica nueva — las tres reusan `NonceCounter`, PKI de dos niveles, y `ed25519_sign.py` ya validados. |



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
│   ├── VTR-PKI-001.md                 # ✅ PKI dos niveles + custodia SSS 3-de-5
│   ├── DOD-v0.5.0.md                  # ✅ Definition of Done — propuesta #10
│   └── VTR-ARCH-DECISIONS-001.md      # ✅ Q-01/Q-02/Q-03 — decisiones documentadas
├── crypto_layer/
│   ├── errors.py                      # ✅ 21 excepciones, 5 categorías
│   ├── __init__.py                    # ✅ API pública — CryptoLayer, CryptoConfig
│   ├── argon2_derive.py               # ✅ Profiles embedded/desktop/hardened, lanes=1
│   ├── hkdf_expand.py                 # ✅ RFC 5869 HKDF-Expand, validado con vectores oficiales
│   ├── ed25519_sign.py                # ✅ RFC 8032 Ed25519, validado con vectores oficiales
│   └── rf_config_loader.py            # ✅ Loader que valida rf_config.yaml -> CryptoConfig
├── config/
│   └── rf_config.yaml                 # ✅ Sección crypto: + rf: + storage: + dtn:
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

## 7. Orden de generación de las propuestas — criterio aplicado

> El detalle completo de las 10 propuestas y su estado vive en la
> **sección 0** de este documento, sincronizada con lo que realmente
> existe en el repositorio. Esta sección documenta solo el *criterio* de
> orden, no repite la tabla.

El orden de generación sigue un criterio explícito: se prioriza lo que
pueda refinar o modificar cualquier fase previa y reduzca el riesgo del
conjunto — por eso las reglas (#1) y el esquema PKI (#2) preceden a
cualquier código, y la jerarquía de excepciones (#3) precede a la API
pública (#4) que la consume. Cada propuesta posterior se validó contra
las anteriores antes de cerrarse — no se generó código aislado sin probar
su integración con lo ya aprobado.

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
cp -r docs/ specs/ crypto_layer/ config/ HANDOFF.md README.md ~/vtr_handoff_$(date +%Y%m%d)/
cd ~ && tar czf vtr_handoff_$(date +%Y%m%d).tar.gz vtr_handoff_$(date +%Y%m%d)/
```

> **Nota operativa:** al copiar archivos individuales descargados hacia el
> repo, verificar siempre la ruta de destino completa (`docs/archivo.md`,
> no solo `archivo.md`) antes de `cp`. Un archivo copiado a la raíz del
> repo por error queda fácilmente sin detectar en `git status` si se hace
> `git add .` sin revisar la lista de archivos nuevos primero. El
> `.tar.gz` de empaquetado nunca debe copiarse hacia el repo — está
> bloqueado explícitamente en `.gitignore` (`*.tar.gz`) precisamente para
> evitar que quede versionado por accidente.
