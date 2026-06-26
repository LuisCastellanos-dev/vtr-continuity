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
| Bundle | `.vtrc` firmado obligatorio | ✅ COMPLETADO | `crypto_layer/vtrc_bundle.py` — `build_bundle()`/`parse_bundle()`/`verify_bundle()`, canonicalización `header‖payload‖metadata` con firma puesta a cero antes de firmar, exactamente como especificaba `specs/PROPOSALS-10.md` §7. 59 tests, 96% coverage real. Implementa Q-02: el par `(node_id, counter)` viaja dentro del header, nunca se infiere del RTC. |
| Bundle | Verificación de firma `.vtrc` en lectura (sneakernet inbound) | ✅ COMPLETADO | `verify_bundle()` en el mismo módulo — retorna `False` (no excepción) ante firma inválida o bundle corrupto, mismo contrato que `ed25519_sign.verify()`. `CounterVerificationStore` añade la verificación de replay sin sesión (tabla de "último counter visto", nunca el RTC). |
| Storage | `storage_guardian.py` (purga FIFO, umbrales 80%/95%) | ✅ COMPLETADO | `core/storage_guardian.py` — monitoreo por base SQLite individual (no disco total), purga FIFO solo en bases `TRANSIENT` (ej. `fragments.db`), bases `COUNTER` (`nonce_counter.db`, `vtrc_counter_seen.db`) protegidas explícitamente contra purga automática. 41 tests, 98% coverage real, incluye protección contra inyección SQL en nombres de tabla/columna interpolados. |
| Provisioning | Bench air-gapped funcional | ⬜ PENDIENTE | Decisión 3A aprobada (provisioning en bench, sin red). Es una decisión de diseño, no un bench físico operativo verificado. |
| Provisioning | `device_registry.vtrdb` con append-only log + cifrado LUKS | ✅ COMPLETADO | `core/device_registry.py` + `scripts/vtr-provision.py` (commit `7869ddf`). Hash chain real (no solo SHA-256 por entrada como `AuditLog`) — verificado contra manipulación directa de SQLite, dos escenarios distintos (borrado de fila, modificación de contenido sin romper enlace). Firma por la Intermediate confirmada explícitamente. Cifrado a nivel de aplicación con XChaCha20-Poly1305 real (`nacl.secret.Aead`) — decisión confirmada de no presumir LUKS del volumen. 30 tests, 98% coverage real. **Hallazgo:** el comentario de `core/crypto_transport.py` dice "XChaCha20-Poly1305" pero el código usa `nacl.secret.SecretBox` (XSalsa20-Poly1305 real, según documentación oficial de PyNaCl) — discrepancia de nomenclatura, no corregida en este trabajo (fuera de alcance), anotada para revisión futura. |
| Preguntas | Q-01/Q-02/Q-03 con decisión documentada | ✅ COMPLETADO | `docs/VTR-ARCH-DECISIONS-001.md` — decisión documentada para las tres; ninguna implementada todavía como código |
| Documentación | STRIDE en `docs/VTR-THREAT-001.md` | ✅ COMPLETADO | 27 amenazas catalogadas (5 Spoofing, 6 Tampering, 3 Repudiation, 4 Information Disclosure, 5 DoS, 4 Elevation of Privilege). **Hallazgo crítico CERRADO:** `rpi/proxy.py` sin autenticación en `POST /events`/`GET /health`/`GET /stats` — corregido con `rpi/proxy_auth.py` (commit `892c079`), conecta `RPiJWTVerifier` ya existente, 22 tests, 100% coverage, sin bypass de debug. Solo D-3 (rate limiting) sigue 🟡 parcial — ver `docs/VTR-THREAT-001.md` §8. Omisión O#7 cerrada. |
| Documentación | Mapeo a IEC 62443 / NERC CIP | ✅ COMPLETADO | `docs/VTR-COMPLIANCE-001.md` — 16 filas mapeadas (10 verificables por código en `server/compliance.py`, 2 diseño completo, 3 parciales, 1 no implementado). Dos brechas reales encontradas al consolidar: CIP-008-6 citado en docstring sin chequeo real; SR 2.1 conecta directamente con el hallazgo de `rpi/proxy.py` sin auth de STRIDE. Omisión O#10 cerrada. |

**Resumen cuantitativo:** 14 ✅ completados / 1 🟡 parcial / 2 ⬜ pendientes,
de 17 bloques totales del DoD.

---

## 2. Las 10 propuestas — estado final verificado

| # | Propuesta | Archivo | Validación |
|---|---|---|---|
| 1 | Reglas cripto consolidadas | `docs/VTR-CRYPTO-001.md` | 4 reglas, librerías fijadas por revisión de CVE (PyNaCl ≥1.6.2 post CVE-2025-69277, pyca ≥45.0 post CVE-2026-26007) |
| 2 | Esquema PKI dos niveles | `docs/VTR-PKI-001.md` | Custodia SSS 3-de-5 con 4 mitigaciones explícitas, anclado a NIST SP 800-57 / ISO 27037 |
| 3 | Jerarquía de excepciones | `crypto_layer/errors.py` | 21 excepciones, 5 categorías (incluye `CustodyError`, añadida tras detectar referencia previa no resuelta en #2). **Incidente post-cierre, ver §6**: este archivo nunca llegó a `git push` a pesar de estar marcado completado — quedó solo en disco local, rompiendo `import crypto_layer` en GitHub hasta su corrección. |
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
- [x] ~~Diseñar e implementar el módulo de formato de bundle `.vtrc`
  (canonicalización `header‖payload‖metadata`, firma puesta a cero antes
  de firmar) — `ed25519_sign.py` provee la primitiva, no el formato.~~
  **COMPLETADO** — `crypto_layer/vtrc_bundle.py`, 59 tests, 96% coverage.
- [x] ~~Implementar `storage_guardian.py` (purga FIFO, umbrales 80%/95%) —
  parámetros ya definidos en `rf_config.yaml`, módulo no escrito.~~
  **COMPLETADO** — `core/storage_guardian.py`, 41 tests, 98% coverage.
- [ ] Ejecutar el setup real de CA root + intermediate (no solo el
  procedimiento documentado en `VTR-PKI-001.md`).
- [ ] Resolver la distribución de los custodios 2–5 del esquema SSS 3-de-5
  (pendiente operativo, no técnico — depende de logística propia).
- [x] ~~Implementar `vtr-provision.py` + `device_registry.vtrdb` con
  append-only log y cifrado LUKS.~~ **COMPLETADO con corrección de
  alcance** — `core/device_registry.py` + `scripts/vtr-provision.py`
  (commit `7869ddf`). Decisión confirmada explícitamente: cifrado a
  nivel de aplicación (`nacl.secret.Aead`, XChaCha20-Poly1305 real) en
  vez de presumir que LUKS del volumen ya resuelve la confidencialidad
  — el código no puede verificar una garantía de otra capa que no
  controla. Firma de cada entrada con la Intermediate (misma llave que
  certificados de dispositivo, confirmado). Hash chain real, verificado
  contra manipulación directa de SQLite en dos escenarios (borrado de
  fila, modificación de contenido sin romper enlace) — garantía más
  fuerte que `AuditLog` existente. CLI probado como comandos de shell
  reales, exit codes correctos. 30 tests, 98% coverage real.
- [ ] Setup del bench air-gapped físico (decisión 3A ya aprobada, sin
  ejecución verificada).
- [x] ~~Documentar decisión arquitectónica para Q-01, Q-02 y Q-03.~~
  **COMPLETADO** — ver `docs/VTR-ARCH-DECISIONS-001.md`. Implementación
  real de cada decisión sigue pendiente y se desagrega en los tres puntos
  siguientes, no incluidos en el conteo original de 14:
  - [x] ~~Implementar máquina de estados de liveness (`ALIVE` /
    `SUSPECTED_DOWN`) y campo `heartbeat_timeout_seconds` en
    `rf_config.yaml` (Q-01).~~ **COMPLETADO** —
    `core/liveness.py` (`LivenessTracker`, 31 tests, 100% coverage). Lee
    `updated_at` de `nonce_counter.db` ya persistida por `NonceCounter`,
    sin tabla ni columna nueva. **Corrección aplicada durante esta
    implementación:** `docs/VTR-ARCH-DECISIONS-001.md` afirmaba que
    `GhostScheduler` mitigaba parcialmente el riesgo de nodo silencioso
    sin tráfico real — verificado contra `core/dtn_fragmenter.py` real y
    esa afirmación era incorrecta (el ghost traffic solo se dispara
    dentro de una fragmentación de bundle real ya en curso, nunca de
    forma autónoma). Corregido en ese documento; la limitación queda
    documentada como conocida y no resuelta, no oculta.
  - [x] ~~Incluir campo `(node_id, counter)` en el header del formato de
    bundle `.vtrc` y tabla de verificación de "último counter visto"
    (Q-02) — requisito de entrada directa para el siguiente punto de este
    checklist.~~ **COMPLETADO** — `crypto_layer/vtrc_bundle.py` (header
    con `node_id`/`counter` fijos) + `CounterVerificationStore` (tabla de
    verificación, estructuralmente paralela a `NonceCounter` pero en modo
    lectura).
  - [x] ~~Implementar paso de verificación de firma Ed25519 (clave
    `intermediate`) en el punto de entrada de configuración de campo,
    antes de `rf_config_loader.py` (Q-03).~~ **COMPLETADO** —
    `crypto_layer/field_config_verifier.py` (`sign_field_config`/
    `verify_field_config`/`verify_and_write_field_config`, 24 tests,
    100% coverage). Formato propio, distinto del bundle `.vtrc` —
    sin campo `counter` forzado (no aplica semánticamente a config).
    Confirmado contra `rf_config.yaml` real e integración real con
    `load_crypto_config()` sin modificarlo. **Trío Q-01/Q-02/Q-03
    cerrado por completo.**
- [x] ~~Generar `docs/VTR-THREAT-001.md` con modelo STRIDE completo.~~
  **COMPLETADO** — 27 amenazas catalogadas. Hallazgo crítico: ausencia
  estructural de autenticación en `rpi/proxy.py` (`POST /events`,
  `GET /health`, `GET /stats`).
- [ ] Sesión de fuzzing UART Heltec + LoRa simulado (`VTR-FUZ-001`).
- [ ] **[PRIORIDAD MÁXIMA]** Site survey RF en ≥2 ubicaciones
  industriales/portuarias reales (RSSI/SNR/PER, link budget) — sin esto,
  el alcance real de LoRa en el corredor Tampico-Altamira-Madero sigue
  siendo teórico (584 km en espacio libre vs. realidad industrial
  desconocida). **Protocolo de medición completo y listo para ejecución
  en `docs/VTR-SURVEY-001.md`** — hardware (2× Heltec) ya disponible,
  ejecución planeada para la siguiente sesión activa tras el break del
  20-jun-2026.
- [x] ~~Tests E2E browser ↔ backend para verificación de `.vtrc` en
  `session_guard.js` (omisión O#8).~~ **COMPLETADO con corrección de
  alcance** — `tests/e2e/session_guard.e2e.test.js` + `test_server.js`,
  18 tests E2E contra servidor HTTP real (no mock de función), 59/59
  passed incluyendo los 41 unitarios existentes, validado en Node
  18.19.1 real (no solo en el entorno de desarrollo Node 22). **Hallazgo
  de alcance:** `session_guard.js` (v0.1.0) no implementa ni referencia
  `.vtrc` en absoluto — es anterior a la fase criptográfica; la omisión
  tal como estaba redactada asumía una integración que no existe en el
  código. Documentado explícitamente, no asumido. **Tres hallazgos
  reales adicionales encontrados probando contra código real:** (1)
  `globalThis.crypto` no es nativo en Node < 19 — requirió polyfill en
  el arnés de pruebas, no en el código de producción; (2) el snapshot
  cifrado nunca sobrevive entre instancias distintas de `CryptoLayer`
  porque cada una genera una clave AES-GCM no exportable — mitigación de
  XSS funcionando como se diseñó, no un bug, pero significa que no hay
  persistencia real entre recargas de página; (3) el orden FIFO de
  `OfflineQueue` no es determinístico ante colisión de `Date.now()` en
  el mismo milisegundo, reproducido y documentado con test dedicado.
- [x] ~~Cerrar el hallazgo crítico de `docs/VTR-THREAT-001.md`
  (S-3/T-3/R-3/D-3/I-3): `rpi/proxy.py` sin autenticación estructural en
  `POST /events`, `GET /health`, `GET /stats`, `DELETE /queue`.~~
  **COMPLETADO** — `rpi/proxy_auth.py` (commit `892c079`), conecta
  `rpi/jwt_verifier.py::RPiJWTVerifier` (existente desde v0.4.0, nunca
  invocado por ningún endpoint) con los 4 endpoints vía
  `Depends(require_scope(...))`. **Decisión confirmada explícitamente:
  sin bypass de modo debug** — `VTR_DEBUG=true` solo controla la
  disponibilidad de `DELETE /queue` (sin cambios), nunca exime de la
  autenticación JWT. Grace period offline reusa el estado real de
  `SyncManager.state.status == "OFFLINE"`, no una bandera separada. 22
  tests, 100% coverage real, validado en usuario sin privilegios de
  root (encontró y corrigió un bug real de aislamiento: `custody_db_path`
  de `SyncConfig` no era configurable por variable de entorno —
  agregada `VTR_CUSTODY_DB_PATH`, mejora real de producción, no solo de
  test). D-3 (rate limiting) queda explícitamente fuera de este fix —
  sigue 🟡 parcial en `VTR-THREAT-001.md`.
- [x] ~~Mapeo consolidado decisión-por-decisión a cláusulas IEC 62443 /
  NERC CIP (omisiones O#10, tareas E9/E10/E11) — hoy solo existen
  referencias puntuales dispersas en `VTR-CRYPTO-001.md` y
  `VTR-PKI-001.md`.~~ **COMPLETADO** — `docs/VTR-COMPLIANCE-001.md`,
  16 filas mapeadas, citando archivo y línea real para cada una.
- [x] ~~Especificación de firmware Heltec: eFuse + Ed25519 vía
  micro-ecc/libsodium (omisión O#6, tarea E6).~~ **COMPLETADO con
  corrección de alcance** — `docs/VTR-FIRMWARE-001.md`. **Hallazgo:**
  `micro-ecc` no soporta Ed25519 (solo ECDSA/ECDH) — no era una opción
  real, no solo "la elegida". Decisión final: `libsodium` vía ESP-IDF
  puro (no Arduino, que ya no lo incluye por defecto desde IDF5).
  Riesgo de heap-corruption con PSRAM (issue esp-idf #8742) verificado
  y descartado para el Heltec V3 (sin PSRAM, confirmado contra
  especificación oficial del fabricante) — a reevaluar si se migra a
  V4.

**Ninguno de estos catorce puntos estaba dentro del alcance de las 10
propuestas de la fase criptográfica.** Cerrar la fase cripto al 100% no
equivale a tener v0.5.0 lista para campo — este checklist es precisamente
la distancia entre ambos estados, y debe tratarse como el roadmap inmediato
post-#10, no como trabajo ya completado.

---

## 5.1 Punto de continuidad — retomar aquí

> **Sábado 20-jun-2026, noche.** Sesión en pausa por break del proyecto
> (domingo 21-jun-2026 sin actividad). Próxima sesión activa: lunes.
>
> **Prioridad máxima al retomar:** ejecutar `docs/VTR-SURVEY-001.md` —
> protocolo de site survey RF, completo y listo, sin pasos pendientes de
> documentación. Hardware confirmado disponible (2× Heltec WiFi LoRa 32
> V3). Ningún otro punto del checklist depende de trabajo de esta sesión
> de pausa — el survey es autocontenido y ejecutable directamente al
> retomar.

---

## 6. Incidente post-cierre — `crypto_layer/errors.py` ausente de GitHub

Durante el trabajo en el formato de bundle `.vtrc` (este checklist, punto
ya cerrado), se detectó que `crypto_layer/errors.py` —la propuesta #3,
marcada ✅ completada desde antes del cierre de la fase cripto— **nunca
había sido subida a GitHub**. El repositorio remoto tenía
`crypto_layer/__init__.py` y `crypto_layer/ed25519_sign.py` importando
directamente de `crypto_layer.errors`, pero ese archivo no existía en
ningún commit del historial (`git log --all -- "**/errors.py"` vacío).
Resultado verificado en un clone limpio: `import crypto_layer` fallaba con
`ModuleNotFoundError`.

**Causa raíz:** el archivo existía y se había usado realmente — un
residuo `crypto_layer/__pycache__/__init__.cpython-312.pyc` confirmó que
el módulo se ejecutó localmente (es decir, los 68 passed / 2 skipped
reportados en la propuesta #9 son ejecuciones reales, no inventadas) —
pero el archivo fuente nunca pasó por `git add`. Se quedó en disco local
sin que ningún `git status` posterior lo marcara como pendiente, porque
nunca llegó a estar bajo control de versiones en primer lugar.

**Cómo se encontró:** no por una auditoría dedicada, sino como
consecuencia directa de intentar reusar `crypto_layer.errors` en el
módulo nuevo de bundle `.vtrc` — al clonar el repo limpio para verificar
contra qué excepciones reales debía construirse el módulo, el `import`
falló de inmediato.

**Corrección:** el archivo se localizó en disco local del usuario (dos
copias idénticas confirmadas por `diff`, 21 clases verificadas), se copió
a `crypto_layer/errors.py`, se confirmó `import crypto_layer` exitoso, se
re-ejecutó `tests/test_crypto_layer.py` completo (68 passed / 2 skipped,
idéntico a lo ya reportado) y se subió en un commit dedicado.

**Por qué esto importa para la integridad de este DoD:** este incidente
es la prueba de que el criterio de "todo ítem completado debe tener
evidencia verificable" (declarado en el encabezado de este documento) no
es un formalismo — fue precisamente la falta de una verificación de
"clone limpio + import real" lo que permitió que un módulo roto
permaneciera marcado como completado durante el resto de la fase
criptográfica sin que nadie lo notara. La lección operativa, ya aplicada
en los tres módulos posteriores (`vtrc_bundle.py`, `storage_guardian.py`,
`VTR-ARCH-DECISIONS-001.md`): cada entrega ahora se valida contra un
`git clone --depth 1` fresco, nunca contra el estado de un entorno de
trabajo que pudo acumular archivos no commiteados.

---

## 7. Reparación del CI — `tests/` nunca se ejecutaba en GitHub Actions

Al auditar el repositorio buscando trabajo pendiente, se encontró que
`.github/workflows/ci.yml` ejecutaba `pytest server/tests/ core/tests/
rpi/tests/` — **la carpeta `tests/` en la raíz, donde viven los 170
tests de toda la fase criptográfica (`test_crypto_layer.py`,
`test_vtrc_bundle.py`, `test_storage_guardian.py`), nunca estuvo incluida
en ese comando.** Desde que el CI existe, nunca ejecutó automáticamente
ni un solo test de las 10 propuestas cripto, del formato de bundle, ni
del storage guardian — solo corrían manualmente en la máquina de
desarrollo.

**Verificado, no solo corregido a ciegas:** se simuló el CI exacto en un
venv aislado (`python3 -m venv`, sin reusar paquetes ya instalados en el
entorno de desarrollo) con la línea de `pip install` original del
workflow. Resultado: **6 de 170 tests fallarían** con
`ModuleNotFoundError: No module named 'yaml'` —
`crypto_layer/rf_config_loader.py` hace `import yaml` en tiempo de
ejecución (no a nivel de módulo), y el `pip install` inline del CI nunca
incluía `PyYAML`. Confirmado con traceback real, reproducible.

**Corrección aplicada:**

1. **`requirements-crypto.txt`** (nuevo, raíz del repo) — fuente única de
   verdad para las dependencias de `crypto_layer/` +
   `core/storage_guardian.py`: `PyNaCl>=1.6.2`, `cryptography>=45.0`,
   `PyYAML>=6.0`, `lz4>=4.3`, `pytest>=8.3`, `pytest-asyncio>=0.24`,
   `pytest-cov>=5.0`. Confirmadas por inspección real de imports (grep
   línea por línea en todo lo que `tests/` ejercita), no por suposición.
2. **`.github/workflows/ci.yml`** actualizado — instala desde
   `requirements-crypto.txt` en vez de hardcodear inline, agrega el paso
   que faltaba (`pytest tests/ --cov=crypto_layer
   --cov=core.storage_guardian`), y agrega un gate de coverage mínimo
   (`--cov-fail-under=90`) para que una futura caída de coverage falle
   el CI en vez de descubrirse en revisión manual.
3. **Validado de extremo a extremo en venv aislado** antes de subir:
   481 passed (stack OT/RPi original, sin regresión) + 168 passed/2
   skipped (fase cripto, antes invisible al CI) + gate de coverage
   pasando con 96.24% agregado.

**Nota honesta sobre el gate de coverage:** mide el agregado de
`crypto_layer/` + `core/storage_guardian.py`, no cada archivo
individualmente. `argon2_derive.py` (85%) y `rf_config_loader.py` (89%)
están hoy por debajo del 90% documentado como criterio de aceptación de
sus propuestas originales — el agregado de 96% los compensa. Esto no es
una regresión introducida por este fix: nadie lo había medido en
conjunto hasta ahora, porque el CI nunca corría estos tests. Subir esos
dos módulos específicos a 90%+ individual queda registrado como mejora
futura, no como bloqueante de esta reparación.
