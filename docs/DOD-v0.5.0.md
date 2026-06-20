# Definition of Done — VTR Continuity v0.5.0

> **Estado:** 10 de 10 propuestas de la fase criptográfica generadas.
> Este documento es la fuente de verdad del cierre de v0.5.0. Todo ítem
> marcado como completado tiene evidencia verificable (commit, test
> ejecutado, documento publicado). Ningún ítem se marca completado por
> proyección o intención — solo por resultado medido.

---

## 0. Cómo leer este documento

Cada bloque del DoD original (`ROADMAP-v0.5.0.md`) se reclasifica aquí en
tres estados:

- ✅ **COMPLETADO** — evidencia citada inline.
- 🟡 **PARCIAL** — parte de la evidencia existe, parte queda pendiente; se
  especifica exactamente qué falta.
- ⬜ **PENDIENTE** — no iniciado, o iniciado pero sin artefacto verificable.

La fase criptográfica (propuestas #1–#9) está cerrada. Eso **no** significa
que v0.5.0 esté lista para piloto — varios bloques del DoD original
dependen de trabajo fuera de las 10 propuestas (provisioning operativo,
STRIDE, tests Jest del stack RF, site survey). Este documento separa
ambas cosas explícitamente para no confundir "fase cripto cerrada" con
"v0.5.0 lista".

---

## 1. Definition of Done — bloque por bloque

| Bloque | Criterio | Estado | Evidencia |
|---|---|---|---|
| Cripto | `crypto_layer/` con Argon2id + HKDF + Ed25519 | ✅ COMPLETADO | `argon2_derive.py`, `hkdf_expand.py`, `ed25519_sign.py` — commiteados, validados contra vectores oficiales RFC 5869 y RFC 8032 |
| Cripto | Reglas VTR-CRYPTO-001/002/003/004 documentadas | ✅ COMPLETADO | `docs/VTR-CRYPTO-001.md`, 4 reglas con texto completo |
| Config | `rf_config.yaml` parametrizado | ✅ COMPLETADO | `config/rf_config.yaml`, 6 secciones (`crypto`, `rf`, `storage`, `dtn`) |
| Config | Sección `crypto:` con profile catalogado + loader que valida tipos/rangos | ✅ COMPLETADO | `crypto_layer/rf_config_loader.py` — `load_crypto_config()`, catálogo cerrado, 7 tests adversariales, cadena end-to-end YAML→loader→`CryptoConfig`→`CryptoLayer` validada con ejecución real |
| Tests | ≥15 tests adversariales pytest (`crypto_layer`) | ✅ COMPLETADO | `tests/test_crypto_layer.py` — 57 métodos en `TestAdversarial`, ampliamente por encima del mínimo |
| Tests | Coverage > 90% en `crypto_layer/` | ✅ COMPLETADO | 95% medido con `pytest-cov`, 68 passed / 2 skipped sobre 70 tests totales, 3 rondas de iteración (80%→87%→92%→95%) |
| Tests | ≥56 tests Jest pasando | ⬜ PENDIENTE | Solo existen 41 tests Jest, y corresponden al módulo browser-native de **v0.1.0** (`session_guard.js`), no al stack RF/cripto de v0.5.0. No hay tests Jest nuevos para esta fase. |
| PKI | CA root + intermediate operativas | 🟡 PARCIAL | Esquema documentado y aprobado en `docs/VTR-PKI-001.md` (decisión 4C). **No hay evidencia de que la CA root y la intermediate existan como artefactos reales** (claves generadas, certificados emitidos) — el documento especifica el procedimiento, no certifica su ejecución. |
| PKI | `docs/VTR-PKI-001.md` publicado | ✅ COMPLETADO | Commiteado, incluye esquema de dos niveles + custodia SSS 3-de-5 con 4 capas de mitigación |
| Bundle | `.vtrc` firmado obligatorio | 🟡 PARCIAL | `ed25519_sign.py` provee la primitiva de firma/verificación, validada byte a byte contra RFC 8032. La canonicalización real del bundle (`header‖payload‖metadata`, firma puesta a cero antes de firmar) está **definida en la spec** pero vive en un módulo de formato de bundle separado, fuera de las 10 propuestas — no implementado todavía. |
| Bundle | Verificación de firma `.vtrc` en lectura (sneakernet inbound) | ⬜ PENDIENTE | Depende del módulo de formato de bundle anterior; sin ese módulo no hay punto de entrada real que verificar. |
| Storage | `storage_guardian.py` (purga FIFO, umbrales 80%/95%) | ⬜ PENDIENTE | No existe en el repositorio. Parámetros ya están definidos en `rf_config.yaml` (`storage.guardian.warn_threshold_percent`, `purge_threshold_percent`, `purge_policy: fifo`), pero el módulo que los consume no se ha escrito. |
| Provisioning | Bench air-gapped funcional | ⬜ PENDIENTE | Decisión 3A aprobada (provisioning en bench, sin red). Es una decisión de diseño, no un bench físico operativo verificado. |
| Provisioning | `device_registry.vtrdb` con append-only log + cifrado LUKS | ⬜ PENDIENTE | No existe `vtr-provision.py` ni `device_registry.vtrdb` en el repositorio. |
| Preguntas | Q-01/Q-02/Q-03 con decisión documentada | ✅ COMPLETADO | `docs/VTR-ARCH-DECISIONS-001.md` — decisión documentada para las tres; ninguna implementada todavía como código |
| Documentación | STRIDE en `docs/VTR-THREAT-001.md` | ⬜ PENDIENTE | No existe en el repositorio. Omisión O#7 sigue sin cerrar. |
| Documentación | Mapeo a IEC 62443 / NERC CIP | 🟡 PARCIAL | Referencias puntuales ya citadas inline en `VTR-CRYPTO-001.md` y `VTR-PKI-001.md` (SR 1.1, 1.5, 1.8, 2.1, CR 1.5). Falta el documento consolidado de mapeo cláusula-por-cláusula (E9/E10/E11). |

**Resumen cuantitativo:** 8 ✅ completados / 4 🟡 parciales / 5 ⬜ pendientes,
de 17 bloques totales del DoD.

---

## 2. Las 10 propuestas — estado final verificado

| # | Propuesta | Archivo | Validación |
|---|---|---|---|
| 1 | Reglas cripto consolidadas | `docs/VTR-CRYPTO-001.md` | 4 reglas, librerías fijadas por revisión de CVE (PyNaCl ≥1.6.2 post CVE-2025-69277, pyca ≥45.0 post CVE-2026-26007) |
| 2 | Esquema PKI dos niveles | `docs/VTR-PKI-001.md` | Custodia SSS 3-de-5 con 4 mitigaciones explícitas, anclado a NIST SP 800-57 / ISO 27037 |
| 3 | Jerarquía de excepciones | `crypto_layer/errors.py` | 21 excepciones, 5 categorías (incluye `CustodyError`, añadida tras detectar referencia previa no resuelta en #2) |
| 4 | API pública | `crypto_layer/__init__.py` | `CryptoConfig` + `CryptoLayer`; capability separation `device_key`/`operator_key` confirmada por test (Decisión 1B) |
| 5 | Derivación Argon2id | `crypto_layer/argon2_derive.py` | `lanes` corregido de 4→1 tras medición real; presupuesto <250ms **pendiente de validar en RPi 4 real** (275ms medido en entorno de 1 núcleo) |
| 6 | Expansión HKDF | `crypto_layer/hkdf_expand.py` | RFC 5869 Apéndice A, Test Cases 1 y 2 — coincidencia exacta byte a byte |
| 7 | Firma Ed25519 | `crypto_layer/ed25519_sign.py` | RFC 8032 Apéndice 7.1, Test Cases 1 y 2 — coincidencia exacta byte a byte; rechazo de bundle modificado confirmado |
| 8 | Config runtime + loader | `config/rf_config.yaml` + `crypto_layer/rf_config_loader.py` | Loader en archivo separado (decisión consultada, para no reabrir #4 ya cerrado); 7 tests adversariales; integración end-to-end real |
| 9 | Suite de tests formal | `tests/test_crypto_layer.py` | 70 tests (68 pasan, 2 skip documentado), 95% coverage real medido con `pytest-cov` |
| 10 | Definition of Done | `docs/DOD-v0.5.0.md` | Este documento |

**Progreso: 10/10 (100%) de la fase criptográfica.** Esto cierra el alcance
original de las 10 propuestas — no cierra v0.5.0 como release. Ver §1 para
la distinción.

---

## 3. Preguntas abiertas — decisión documentada, implementación pendiente

Las tres preguntas arquitectónicas identificadas en el roadmap (E1/E2/E3,
prioridad P0) ya tienen **decisión documentada** en
`docs/VTR-ARCH-DECISIONS-001.md`. Ninguna está implementada como código
todavía — este documento registra el razonamiento y la decisión tomada,
no el artefacto final.

- **Q-01** — Detección de nodo muerto en red decentralizada. **Decisión:**
  heartbeat pasivo inferido de la progresión del `NonceCounter` ya
  existente en `core/crypto_transport.py`, sin mensaje dedicado (evita
  romper la propiedad de no-correlación temporal que `GhostScheduler` ya
  garantiza). Estado nuevo propuesto: `SUSPECTED_DOWN`, distinto de
  `DOWN` — el sistema notifica, no decide unilateralmente entre nodo
  apagado y nodo aislado por jamming, porque ambos son indistinguibles
  desde el observador remoto.
- **Q-02** — Paradoja de reset de RTC + replay de nonce. **Decisión:** el
  par `(node_id, counter)` viaja dentro del bundle `.vtrc` mismo; el
  receptor compara contra su propia tabla de "último counter visto", no
  contra el RTC del nodo. Extiende la misma lógica que `ReplayWindow` ya
  usa para sesiones en vivo al caso sneakernet sin sesión. Define un
  requisito concreto para el formato de bundle `.vtrc` (próximo punto del
  checklist): el header debe incluir ese campo desde el diseño inicial.
- **Q-03** — Interfaz de configuración en campo como superficie de
  ataque. **Decisión:** la configuración de campo se trata como un
  bundle firmado con la clave de la `intermediate` CA (la misma PKI de
  `VTR-PKI-001.md`), verificada antes de llegar a
  `crypto_layer/rf_config_loader.py` — no como confianza implícita por
  ubicación física o por PIN local.

Las tres decisiones comparten un principio explícito: ninguna introduce
una primitiva criptográfica o un mecanismo de confianza nuevo — las tres
reutilizan estructuras ya validadas en las propuestas #1–#9
(`NonceCounter`, PKI de dos niveles, `ed25519_sign.py`).

---

## 4. Diferido explícitamente a v0.6.0

Sin cambios respecto a lo aprobado en `DECISIONS-v0.5.0.md` y
`ROADMAP-v0.5.0.md`:

- Hardware HSM físico para la CA root (upgrade desde USB cifrado LUKS).
- Provisioning híbrido 3C (attestation al primer boot).
- M-of-N adicional para acceso a CA root más allá del SSS 3-de-5 ya
  adelantado a v0.5.0.
- Integración profunda con el módulo de monitoreo OT existente (Web SOC
  con visualización de certificados).
- Migración a OP-TEE / TPM 2.0 en hardware compatible.

Ninguno de estos diferimientos introduce deuda técnica de seguridad: las
decisiones 1B/2D/3A/4C ya aprobadas son evolutivas hacia v0.6, no requieren
rediseño retroactivo.

---

## 5. Checklist final pre-release v0.5.0

Esta lista es la condición real para considerar v0.5.0 lista para piloto
de campo — no para considerar cerrada la fase cripto, que ya lo está.

- [ ] Validar presupuesto de tiempo de Argon2id (<250ms, profile `desktop`)
  en hardware RPi 4 real con 4 núcleos — pendiente desde propuesta #5,
  medido solo en entorno de 1 núcleo hasta ahora.
- [ ] Diseñar e implementar el módulo de formato de bundle `.vtrc`
  (canonicalización `header‖payload‖metadata`, firma puesta a cero antes
  de firmar) — `ed25519_sign.py` provee la primitiva, no el formato.
- [ ] Implementar `storage_guardian.py` (purga FIFO, umbrales 80%/95%) —
  parámetros ya definidos en `rf_config.yaml`, módulo no escrito.
- [ ] Ejecutar el setup real de CA root + intermediate (no solo el
  procedimiento documentado en `VTR-PKI-001.md`).
- [ ] Resolver la distribución de los custodios 2–5 del esquema SSS 3-de-5
  (pendiente operativo, no técnico — depende de logística propia).
- [ ] Implementar `vtr-provision.py` + `device_registry.vtrdb` con
  append-only log y cifrado LUKS.
- [ ] Setup del bench air-gapped físico (decisión 3A ya aprobada, sin
  ejecución verificada).
- [x] ~~Documentar decisión arquitectónica para Q-01, Q-02 y Q-03.~~
  **COMPLETADO** — ver `docs/VTR-ARCH-DECISIONS-001.md`. Implementación
  real de cada decisión sigue pendiente y se desagrega en los tres puntos
  siguientes, no incluidos en el conteo original de 14:
  - [ ] Implementar máquina de estados de liveness (`ALIVE` /
    `SUSPECTED_DOWN`) y campo `heartbeat_timeout_seconds` en
    `rf_config.yaml` (Q-01).
  - [ ] Incluir campo `(node_id, counter)` en el header del formato de
    bundle `.vtrc` y tabla de verificación de "último counter visto"
    (Q-02) — requisito de entrada directa para el siguiente punto de este
    checklist.
  - [ ] Implementar paso de verificación de firma Ed25519 (clave
    `intermediate`) en el punto de entrada de configuración de campo,
    antes de `rf_config_loader.py` (Q-03).
- [ ] Generar `docs/VTR-THREAT-001.md` con modelo STRIDE completo.
- [ ] Sesión de fuzzing UART Heltec + LoRa simulado (`VTR-FUZ-001`).
- [ ] Site survey RF en ≥2 ubicaciones industriales/portuarias reales
  (RSSI/SNR/PER, link budget) — sin esto, el alcance real de LoRa en el
  corredor Tampico-Altamira-Madero sigue siendo teórico.
- [ ] Tests E2E browser ↔ backend para verificación de `.vtrc` en
  `session_guard.js` (omisión O#8).
- [ ] Mapeo consolidado decisión-por-decisión a cláusulas IEC 62443 /
  NERC CIP (omisiones O#10, tareas E9/E10/E11) — hoy solo existen
  referencias puntuales dispersas en `VTR-CRYPTO-001.md` y
  `VTR-PKI-001.md`.
- [ ] Especificación de firmware Heltec: eFuse + Ed25519 vía
  micro-ecc/libsodium (omisión O#6, tarea E6).

**Ninguno de estos catorce puntos estaba dentro del alcance de las 10
propuestas de la fase criptográfica.** Cerrar la fase cripto al 100% no
equivale a tener v0.5.0 lista para campo — este checklist es precisamente
la distancia entre ambos estados, y debe tratarse como el roadmap inmediato
post-#10, no como trabajo ya completado.
