# VTR Continuity v0.5.0 — Documento de Estado Técnico

> **Versión objetivo:** v0.5.0 (Fallback Tier 2 RF)
> **Rama de trabajo:** `feature/crypto-layer-v0.5.0`

---

## 🎯 Estado del proyecto

### Completado (v0.1.0)
- Módulo browser-native `session_guard.js`
- 41 tests Jest pasando
- Componentes: SessionGuard, CryptoLayer (AES-GCM Web Crypto), StateSnapshot (IndexedDB), OfflineQueue (UUID v4), HeartbeatMonitor, SyncManager

### En curso (v0.5.0)
Stack RF + criptográfico para Fallback Tier 2:
- Protobuf + LZ4 (serialización)
- XChaCha20-Poly1305 + Ed25519 (criptografía)
- LoRa 915 MHz (transporte L1 primario)
- BLE 5.0 Mesh (corto alcance)
- DTN Bundle Protocol RFC 9171 (L2)
- Sneakernet `.vtrc` (fallback extremo)

### Hardware de referencia
- 2× Heltec WiFi LoRa 32 V3
- RPi 4 para proxy DMZ
- HSM para CA root: diferido a v0.6, no requerido en v0.5.0

---

## 🗺️ Roadmap consolidado v0.5.0 → v0.6.0

El roadmap completo en 5 épicas con priorización P0/P1/P2 está en:
- `docs/ROADMAP-v0.5.0.md` — épicas, tareas, dependencias
- `docs/DOD-v0.5.0.md` — Definition of Done actualizado

### Resumen de épicas

| Épica | Foco | Bloquea v0.5.0 |
|---|---|---|
| 🟢 A | Núcleo criptográfico (crypto_layer.py) | Sí |
| 🟡 B | Infraestructura PKI dos niveles | Sí |
| 🔵 C | Provisioning y bench air-gapped | Sí |
| 🟣 D | Resiliencia, validación y tests | Sí (parcial) |
| 🟠 E | Integraciones y preguntas abiertas | Mixto |

---

## ✅ Decisiones técnicas tomadas

Ver `docs/DECISIONS-v0.5.0.md` para el análisis completo de pros/contras de
cada opción evaluada. Resumen:

| # | Decisión | Elegido | Por qué |
|---|---|---|---|
| 1 | Modos de derivación | **1B** — `derive_device_key` + `derive_operator_key` separados | Capability separation + disponibilidad |
| 2 | Profile Argon2id | **2D** con default `desktop` (64 MiB, 3 it) + async | OWASP 2024 sin sacrificar boot time |
| 3 | `device_secret` | **3A** — bench air-gapped (3C diferido a v0.6) | Auditable y manejable a la escala actual del proyecto |
| 4 | Firma provisioning | **4C** — CA dos niveles, root offline + intermediate online | Trust anchor sin HSM en v0.5.0 |
| 5 | Custodia de la CA root | **PyCryptodome SSS 3-de-5**, adelantado desde v0.6 a v0.5.0 | Mitiga pérdida total del bench sin punto único de fallo — ver `docs/VTR-PKI-001.md` §4 |

> **Nota sobre la decisión 5:** antes de adoptar Shamir's Secret Sharing se
> verificó el historial real de fallas de este esquema en producción (caso
> documentado de una wallet de criptomonedas que rompió su sistema de
> backups fragmentados por usar coeficientes deterministas en vez de un RNG
> real, y hallazgos de auditoría sobre implementaciones de firma de umbral
> en el ecosistema cripto). El diseño en `VTR-PKI-001.md` incluye 4 capas de
> mitigación explícitas (verificación de RNG, HMAC de integridad, umbral
> estricto, custodia distribuida) precisamente para no repetir esos fallos.
> Los custodios específicos de 4 de las 5 partes quedan como **pendiente
> operativo**, sujeto a logística propia del despliegue — no resuelto por
> este documento.

> **Notas sobre el diseño de `crypto_layer/__init__.py`:** dos ambigüedades
> de la especificación original se resolvieron con criterio explícito de
> seguridad, no por conveniencia de implementación:
> - `derive_device_key_async` recibe `hardware_id` y `device_secret` como
>   parámetros explícitos en cada llamada (misma firma que la versión
>   síncrona), en vez de leerlos desde un estado interno cacheado — limita
>   la ventana de exposición de bytes sensibles en memoria y evita
>   resultados inconsistentes si el estado interno cambiara entre llamadas.
> - `CryptoConfig` es un dataclass plano sin método `from_yaml()` — la
>   validación del catálogo cerrado de profiles y el parsing de
>   `rf_config.yaml` quedan en una capa de configuración separada
>   (propuesta #8), de forma que `CryptoLayer` nunca procesa texto de un
>   archivo de configuración que pudiera haber sido modificado por un
>   actor con acceso al sistema de archivos.

---

## 🆕 Cuatro reglas de criptografía permanentes

Reglas de desarrollo fijas para VTR Continuity:

- **VTR-CRYPTO-001:** nunca SHA-256 puro sobre secretos de baja entropía. Argon2id para derivación desde passphrase/hardware ID; HKDF-SHA256 para expansión; Ed25519 para integridad de bundles.
- **VTR-CRYPTO-002:** el número de serie del hardware NO es salt criptográfico. El salt real proviene de `/etc/vtr/device_secret` (32 bytes aleatorios generados en bench, partición read-only firmada por CA). **Estado: diseño pendiente, aún no implementado** — ningún código de producción debe asumir su existencia.
- **VTR-CRYPTO-003:** validación defensiva ANTES de cualquier operación criptográfica. Inputs `None`, bytes vacíos, longitudes incorrectas, o tipos no esperados deben lanzar excepciones específicas del dominio (`InvalidPassphraseError`, etc.) antes de que la librería subyacente los toque.
- **VTR-CRYPTO-004:** todo Heltec WiFi LoRa 32 V3 debe salir del bench con Secure Boot V2 + Flash Encryption (modo Release) + hardening de eFuse (JTAG/USB-OTG/descarga manual deshabilitados) antes de desplegarse en campo. Verificado contra documentación oficial de Espressif — el ESP32-S3 soporta esto nativamente sin hardware adicional. Incluye orden obligatorio de quemado de eFuses por conflicto de legibilidad entre la llave de Secure Boot y la de Flash Encryption.

**Librerías fijadas, con justificación verificada (no por preferencia):**

| Primitiva | Librería | Versión mínima |
|---|---|---|
| Ed25519, XChaCha20-Poly1305 | PyNaCl (libsodium) | ≥1.6.2 (post CVE-2025-69277) |
| Argon2id, HKDF-SHA256 | cryptography (pyca) | ≥45.0 (post CVE-2026-26007) |

Revisión de CVEs de ambas librerías cada trimestre natural; parche crítico
fuera de ciclo en ≤72 horas.

Documento completo: `docs/VTR-CRYPTO-001.md` — generado y aprobado.

---

## 🔍 Omisiones detectadas (10 puntos)

Al consolidar el roadmap se detectaron 10 omisiones que forman parte del
backlog:

| ID | Omisión | Épica destino |
|---|---|---|
| O#1 | Procedimiento de rotación operacional de `device_secret` | B7 |
| O#2 | Custodia / backup / M-of-N de CA root | B4, B5, B6 |
| O#3 | Mecanismo de revocación efectivo (CRL/OCSP en air-gapped) | B8, B9 |
| O#4 | Cifrado en reposo de `device_registry.vtrdb` | C3, C5, C6 |
| O#5 | Coexistencia `crypto_layer.py` (backend) ↔ `session_guard.js` (frontend) | E4, E5 |
| O#6 | Firmware Heltec: especificación de eFuse + Ed25519 | E6 |
| O#7 | Modelo de amenaza explícito (STRIDE) documentado | D8 |
| O#8 | Tests E2E browser ↔ backend (verificación `.vtrc`) | D7 |
| O#9 | Coordinación con módulo de monitoreo OT existente (registro + Web SOC) | E7, E8 |
| O#10 | Documentación auditable para IEC 62443 / NERC CIP | E9, E10, E11 |

---

## 📦 Las 10 propuestas de la fase criptográfica

| # | Archivo | Cubre | Estado |
|---|---|---|---|
| 1 | `docs/VTR-CRYPTO-001.md` | Reglas cripto consolidadas (4, incluye VTR-CRYPTO-004) | ✅ Generado |
| 2 | `docs/VTR-PKI-001.md` | Esquema PKI dos niveles + custodia SSS 3-de-5 de la root | ✅ Generado |
| 3 | `crypto_layer/errors.py` | Jerarquía de excepciones (21 clases, incluye categoría CustodyError) | ✅ Generado |
| 4 | `crypto_layer/__init__.py` | API pública (CryptoLayer + CryptoConfig) | ✅ Generado |
| 5 | `crypto_layer/argon2_derive.py` | Derivación con profile + async | ✅ Generado (criterio de tiempo pendiente de validar en RPi 4 real) |
| 6 | `crypto_layer/hkdf_expand.py` | Expansión de subclaves (RFC 5869) | ✅ Generado, validado contra 2 vectores oficiales del RFC |
| 7 | `crypto_layer/ed25519_sign.py` | Firma/verificación de `.vtrc` | ✅ Generado, validado contra 2 vectores oficiales RFC 8032 |
| 8 | `config/rf_config.yaml` | Sección `crypto:` + RF + storage + DTN | ✅ Generado, junto con `crypto_layer/rf_config_loader.py` (loader separado) |
| 9 | `tests/test_crypto_layer.py` | Tests felices + ≥15 adversariales | ✅ Generado — 68 pasan, 2 skip documentado, 95% coverage |
| 10 | `docs/DOD-v0.5.0.md` | Definition of Done actualizado | ✅ Generado |

**Estado:** 10 de 10 propuestas generadas. Fase criptográfica cerrada al
100%.

> **Nota sobre el cierre de la fase:** 10/10 propuestas generadas no
> equivale a v0.5.0 lista para piloto de campo. `docs/DOD-v0.5.0.md`
> reclasifica el Definition of Done original bloque por bloque
> (✅ completado / 🟡 parcial / ⬜ pendiente) con evidencia real citada en
> cada caso, y deja un checklist de 14 puntos pre-release que nunca
> estuvieron dentro del alcance de estas 10 propuestas. De esos 14 puntos,
> tres ya están cerrados con código y tests reales: decisión documentada
> para Q-01/Q-02/Q-03, formato de bundle `.vtrc`, y `storage_guardian.py`
> — ver las secciones siguientes. Además, durante este trabajo se detectó
> y corrigió un incidente real: la propuesta #3 (`crypto_layer/errors.py`)
> nunca había llegado a GitHub a pesar de estar marcada completada — ver
> §🚨 más abajo.

### 🧭 Q-01/Q-02/Q-03 — decisión documentada (`docs/VTR-ARCH-DECISIONS-001.md`)

Las tres preguntas arquitectónicas del roadmap (E1/E2/E3) ya tienen
decisión documentada. Ninguna está implementada como código todavía —
el documento registra el razonamiento, no el artefacto final. Se
generaron leyendo completo el código real de Capa 1
(`core/crypto_transport.py`) y Capa 2 (`core/dtn_fragmenter.py`) para no
proponer nada que contradijera lo ya cerrado.

- **Q-01** (nodo muerto): heartbeat **pasivo** inferido de la progresión
  del `NonceCounter` ya existente, sin mensaje dedicado — un heartbeat
  explícito sería un patrón temporal predecible, justo lo que
  `GhostScheduler` ya existe para evitar. Estado nuevo: `SUSPECTED_DOWN`,
  no `DOWN` — nodo apagado y nodo aislado por jamming son indistinguibles
  desde el observador remoto, así que el sistema notifica en vez de
  decidir unilateralmente.
- **Q-02** (RTC + replay): el par `(node_id, counter)` viaja **dentro**
  del bundle `.vtrc`, no se infiere del receptor ni del RTC. El receptor
  compara contra su propia tabla de "último counter visto" — extiende la
  misma lógica que `ReplayWindow` ya usa en sesión viva al caso
  sneakernet sin sesión. **Define un requisito concreto para el formato
  de bundle `.vtrc`** (siguiente propuesta en el checklist): el header
  debe incluir ese campo desde el diseño inicial, no como adición
  posterior.
- **Q-03** (config en campo): la configuración de campo se trata como un
  bundle firmado con la clave de la `intermediate` CA — la misma PKI de
  `VTR-PKI-001.md` — verificado antes de llegar a
  `crypto_layer/rf_config_loader.py`. No se introduce un PIN/secreto
  local paralelo; se reutiliza la cadena de confianza ya validada.

Las tres decisiones comparten un criterio explícito: ninguna introduce
una primitiva criptográfica o mecanismo de confianza nuevo — las tres
reutilizan `NonceCounter`, la PKI de dos niveles, y `ed25519_sign.py` ya
validados en las propuestas #1–#9.

### 📦 Formato de bundle `.vtrc` (`crypto_layer/vtrc_bundle.py`)

Segundo punto del checklist post-#10 cerrado. Implementa la
canonicalización que la propuesta #7 dejó explícitamente fuera de
alcance (`header‖payload‖metadata`, firma puesta a cero antes de firmar)
y, directamente, la decisión de Q-02: el header incluye el par
`(node_id, counter)` de 8+8 bytes, generado por el `NonceCounter` del
emisor — nunca se infiere del RTC del receptor.

- `build_bundle()` / `parse_bundle()` / `verify_bundle()` — mismo
  contrato que `ed25519_sign.verify()`: `verify_bundle()` retorna `False`
  ante firma inválida o bundle corrupto, nunca lanza excepción por una
  firma simplemente incorrecta.
- `CounterVerificationStore` — estructuralmente paralela a
  `NonceCounter`, pero en modo verificación: mantiene "máximo counter
  visto por `node_id`" en SQLite, persistente entre reinicios, nunca
  contra reloj.
- 59 tests (`tests/test_vtrc_bundle.py`), 96% coverage real medido.
  Validado con round-trip real (no solo unitario): firma/verificación,
  rechazo de bundle modificado, rechazo de llave pública equivocada,
  persistencia del counter tras "reinicio" simulado (nueva instancia de
  `CounterVerificationStore` sobre la misma DB).
- Las 3 líneas sin cubrir del 96% son excepción genérica de la librería
  subyacente — mismo criterio que en la propuesta #9: forzarlas
  requeriría mockear, lo que se consideró relleno, no validación real.

### 🗄️ `storage_guardian.py` — monitoreo y purga FIFO (D1 del roadmap)

Tercer punto del checklist post-#10 cerrado. Origen: bloqueante S#2 de
`VTR-SEC-001` ("alerta antes de saturar SQLite"), parámetros ya definidos
en `rf_config.yaml` (`storage.guardian.warn_threshold_percent: 80`,
`purge_threshold_percent: 95`, `purge_policy: fifo`) desde antes de que
existiera el módulo que los consume.

**Decisión de diseño central — monitoreo por base SQLite individual, no
disco total.** Las bases del proyecto tienen roles distintos:
`nonce_counter.db` y `vtrc_counter_seen.db` son contadores monotónicos
(crecimiento acotado por tamaño de flota, **nunca purgables** sin romper
la garantía anti-replay de Q-02); `fragments.db` (Capa 2, DTN) es tráfico
en tránsito sin acotar, purgable FIFO sin riesgo. El guardian distingue
ambos roles explícitamente (`StorageRole.COUNTER` vs.
`StorageRole.TRANSIENT`) — una base `COUNTER` que excede el umbral nunca
se purga automáticamente, registra error y exige intervención humana.

**Dos bugs reales encontrados y corregidos durante el desarrollo, no
solo en el diseño teórico:**
1. La primera versión medía solo el archivo `.db` principal. Al probar
   contra una `FragmentStore` real con 300 inserts, el archivo `-wal`
   pesaba 4.1 MB contra 77 KB del `.db` — el guardian estaba
   completamente ciego al WAL, que en SQLite puede pesar órdenes de
   magnitud más que el archivo "principal" hasta el siguiente checkpoint.
   Corregido: `_file_size()` suma `.db` + `-wal` + `-shm`.
2. Un loop de "borra un lote, mide, repite" nunca terminaba, porque
   `DELETE` en SQLite no reduce el tamaño del archivo sin `VACUUM` — el
   loop vaciaba la tabla completa en vez de purgar solo lo necesario.
   Corregido: se estima bytes-por-fila a partir del tamaño y conteo
   actuales, se calcula cuántas filas hace falta eliminar en una sola
   pasada, y se hace un único `VACUUM` al final (no uno por lote — costoso
   en una SD de RPi/Heltec).

**Protección contra inyección SQL:** los nombres de tabla/columna
(`purge_table`, `purge_timestamp_column`) se interpolan en la query de
purga porque SQLite no soporta `?` para identificadores — se valida con
una whitelist regex (`^[A-Za-z_][A-Za-z0-9_]*$`) en construcción de
`WatchedDatabase`, antes de que el valor llegue a cualquier string SQL.
Tests explícitos prueban `"fragments; DROP TABLE fragments;--"` y
similares, todos rechazados. Las tres bases SQLite ya existentes en el
proyecto (`NonceCounter`, `FragmentStore`,
`CounterVerificationStore`) se revisaron como parte de este trabajo y
confirmaron parametrización correcta — ninguna concatena datos externos
en SQL.

41 tests (`tests/test_storage_guardian.py`), 98% coverage real medido,
contra instancias reales de `FragmentStore` y `NonceCounter` (no mocks)
— un mock de `sqlite3` no habría expuesto ninguno de los dos bugs
anteriores.

### 🚨 Incidente post-cierre — `crypto_layer/errors.py` ausente de GitHub

Detectado al intentar reusar las excepciones reales para
`vtrc_bundle.py`: un clone limpio del repositorio mostró
`ModuleNotFoundError: No module named 'crypto_layer.errors'` al ejecutar
`import crypto_layer`. La propuesta #3 estaba marcada ✅ completada desde
el cierre de la fase cripto, pero el archivo nunca había pasado por
`git add` — quedó solo en disco local (confirmado por un residuo
`__pycache__/__init__.cpython-312.pyc`, evidencia de que sí se ejecutó
localmente, así que los 68 passed / 2 skipped de la propuesta #9 son
reales). `git log --all -- "**/errors.py"` confirmó que el archivo nunca
estuvo en ningún commit.

Corrección: archivo localizado en disco local del usuario (dos copias
idénticas confirmadas por `diff`, 21 clases verificadas contra el
docstring documentado), copiado a `crypto_layer/errors.py`, `import
crypto_layer` reconfirmado exitoso, suite completa re-ejecutada (68
passed / 2 skipped, idéntico a lo reportado), subido en commit dedicado.

**Práctica adoptada a partir de este incidente:** cada entrega posterior
(`vtrc_bundle.py`, `storage_guardian.py`) se validó contra un
`git clone --depth 1` fresco antes de declararse completada, no contra
el estado acumulado de un entorno de trabajo local que puede tener
archivos sin commitear sin que ningún `git status` posterior lo detecte
retroactivamente. Detalle completo en `docs/DOD-v0.5.0.md` §6.

> **Nota sobre la propuesta #8:** la spec original exige que "el loader
> valide tipos y rangos", pero la propuesta #4 ya había decidido
> deliberadamente que `CryptoConfig` no sabe parsear YAML. Se consultó
> explícitamente entre dos opciones — meter el loader dentro de
> `crypto_layer/__init__.py` (reabriendo y contradiciendo un archivo ya
> cerrado y sincronizado en GitHub) vs. crear un archivo nuevo y separado
> (`crypto_layer/rf_config_loader.py`) que consume `CryptoConfig` sin
> modificarlo. Se eligió la segunda opción por menor superficie de
> conflicto: cero cambios a los 7 archivos ya aprobados. El loader valida
> presencia de todos los campos obligatorios, tipo correcto de cada uno
> (incluyendo el caso de `derivation_async` recibido como string en vez de
> booleano), y el profile contra el catálogo cerrado — disparando
> `InvalidProfileError` o `MissingConfigFieldError` según corresponda.
> Deliberadamente NO valida que los archivos referenciados por
> `device_secret_path` y similares existan físicamente en el sistema —
> esa verificación ocurre en tiempo de uso real, no en tiempo de carga de
> configuración, porque el mecanismo de partición firmada que contendría
> `device_secret` sigue siendo diseño pendiente (VTR-CRYPTO-002).
> Integración end-to-end validada: el `rf_config.yaml` real se carga,
> valida, y el `CryptoConfig` resultante funciona correctamente con
> `CryptoLayer` para derivación de claves y firma/verificación de bundles.

> **Nota sobre la propuesta #9:** dos de los 17 casos adversariales de la
> spec original (`test_replayed_nonce_detected`,
> `test_session_cache_invalidated_on_passphrase_change`) requerían lógica
> que ninguna propuesta cerrada implementa todavía — el manejo de nonces
> vive en el `NonceCounter` de Capa 1 (fuera de alcance), y
> `CryptoLayer._session_cache` existe como dict declarado pero ningún
> método lo usa aún. Se compararon 2 opciones (skip explícito documentado
> vs. reabrir `crypto_layer/__init__.py` para implementar la lógica real)
> bajo el criterio de "menor sobrescritura innecesaria, mentalidad byte
> por byte" — se eligió skip explícito: cero cambios a los 8 archivos ya
> cerrados, gap visible en cada corrida de `pytest` (reportado como
> SKIPPED con la razón inline), en vez de tomar ≥3 decisiones de diseño
> nuevas sin consultar. Sobre coverage: la primera corrida real midió 80%,
> por debajo del criterio de aceptación de >90%. Se decidió agregar más
> casos adversariales reales (no relleno artificial) — validaciones
> directas de la API pública y de las funciones de bajo nivel que ya
> existían pero no se ejercían vía tests — hasta alcanzar **95% de
> coverage real, medido, no proyectado**. La única rama sin cubrir que
> queda deliberadamente sin forzar es el manejo de excepciones genéricas
> de la librería subyacente en `argon2_derive.py` (líneas 160-167) —
> requeriría mockear la librería de forma artificial para provocarla, lo
> que se consideró relleno, no validación real.

> **Nota sobre la propuesta #5:** al validar contra la librería real
> (`cryptography` ≥45.0), se detectó que el catálogo de profiles original
> usaba `lanes=4` en los tres niveles, mismo valor que VTR-CRYPTO-001 ya
> tenía documentado como ejemplo "correcto". Una medición real de tiempo
> en el entorno de generación (1 núcleo de CPU) mostró 300ms para el
> profile "desktop" con `lanes=4` — por encima del presupuesto de <250ms
> que exige el criterio de aceptación de la propuesta. Investigación
> adicional mostró que fuentes recientes (2025-2026) sobre el perfil OWASP
> 2024 difieren entre sí, y que el propio OWASP Cheat Sheet Series base
> recomienda 1 grado de paralelismo, no 4. Se corrigió `lanes=1` en los
> tres profiles (embedded, desktop, hardened) — tanto en
> `argon2_derive.py` como en el ejemplo de código de VTR-CRYPTO-001 — por
> consistencia y porque el paralelismo dimensiona costo computacional al
> hardware del defensor, no es el principal factor de resistencia
> criptográfica (ese rol lo cumple `memory_kib`, sin cambios). Con
> `lanes=1` el tiempo medido mejoró a 275ms, **pero sigue sin cumplir el
> presupuesto de 250ms en este entorno de 1 núcleo**. La causa identificada
> es la limitación de hardware del entorno de prueba (Xeon de 1 núcleo),
> no necesariamente el profile — el RPi 4 objetivo tiene 4 núcleos físicos
> y podría comportarse distinto. **El criterio de aceptación de tiempo
> queda explícitamente como pendiente de validación en hardware RPi 4
> real**, documentado tanto en el código como aquí, no asumido como
> resuelto. Si en RPi 4 real tampoco cumple, la guía documentada en
> `argon2_derive.py` es reducir `iterations` de 3 a 2 antes de tocar
> `memory_kib`, ya que la memoria es el parámetro con mayor impacto real
> en la resistencia al cracking.

El orden de generación sigue un criterio explícito: se prioriza lo que pueda
refinar o modificar cualquier fase previa y reduzca el riesgo del conjunto.
Por eso las reglas (#1) y el esquema PKI (#2) preceden a cualquier código, y
la jerarquía de excepciones (#3) precede a la API pública (#4) que la
consume.

---

## 🔑 Referencias y estándares aplicables

- **IEC 62443-3-3** (System Security Requirements) — SR 1.1, 1.5, 1.8, 2.1 cubiertos por las decisiones cripto
- **IEC 62443-4-2** (Component Security Requirements) — CR 1.5 (autenticación de dispositivos) cubierto por decisiones 3A+4C
- **NERC CIP** (aplicable a sector eléctrico)
- **NIST SP 800-82 Rev 3** (Guide to OT Security)
- **NIST SP 800-57** (gestión de ciclo de vida de llaves criptográficas)
- **ISO/IEC 27037** (cadena de custodia de evidencia digital)
- **OWASP Password Hashing Cheat Sheet 2024** (parámetros Argon2id)
- **RFC 8032** Ed25519
- **RFC 5869** HKDF
- **RFC 8017** RSA-PSS (usado por Secure Boot V2)
- **RFC 9171** DTN Bundle Protocol v7

---

## 🧠 Principios de diseño establecidos

1. **"Más seguro" ≠ "más restrictivo" en OT.** La indisponibilidad del canal
   alterno en una crisis es exactamente el escenario que VTR Continuity
   existe para resolver. Criterio: minimizar el riesgo total del sistema
   (confidencialidad, integridad y disponibilidad balanceadas), no solo el
   riesgo criptográfico aislado.

2. **SHA-256 puro no tiene función de costo.** Las rainbow tables y el
   brute-force con GPU/ASIC solo amenazan inputs de baja entropía. Para
   passwords/passphrases/hardware ID → Argon2id (memory-hard). Para
   expansión desde claves ya de alta entropía → HKDF.

3. **Capability separation por encima de un diseño monolítico.** Dos
   métodos (`device_key` / `operator_key`) con contratos claros son más
   seguros y más testeables que un método único con parámetro opcional.

4. **El número de serie del hardware nunca es salt criptográfico.** Es
   información pública y predecible. Se usa como `info` field en HKDF
   (binding contextual al hardware), nunca como salt.

5. **Derivación asíncrona por encima de síncrona en el arranque.** Mover la
   derivación de claves a un thread aparte permite que el proxy esté
   operativo en menos de 2 segundos, con la clave disponible ~200ms después,
   sin bloquear el inicio del sistema.

6. **Un esquema criptográfico sólido en teoría puede estar roto en la
   práctica por la implementación, no por la matemática.** Shamir's Secret
   Sharing es un ejemplo documentado: una implementación de backups
   fragmentados rompió por completo su esquema usando hashing determinista
   en vez de un generador de números aleatorios real para los coeficientes
   del polinomio — el resultado fue que cualquier par de partes, sin
   importar el umbral configurado, reconstruía el secreto completo.
   **Principio aplicado:** antes de adoptar cualquier primitiva con
   historial de fallas de implementación conocidas, verificar el caso de
   falla real (no solo "es seguro en teoría") y diseñar la mitigación
   explícita contra ese caso específico, no contra una amenaza genérica.
