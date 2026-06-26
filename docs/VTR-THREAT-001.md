# VTR-THREAT-001 — Modelo de amenazas STRIDE

> **Origen:** omisión O#7 del roadmap (`docs/ROADMAP-v0.5.0.md`), checklist
> pre-release post-#10 (`docs/DOD-v0.5.0.md` §5).
> **Método:** cada superficie listada aquí se confirmó leyendo el código
> real del repositorio (commit `62d0925`), no se infirió de
> documentación de arquitectura. Donde el código todavía es un stub sin
> implementación (ej. `WinCCAdapter`), se marca explícitamente como tal
> — STRIDE no se aplica a código que no existe, y fingir cobertura ahí
> sería peor que dejarlo en blanco.
> **Alcance:** todo el sistema desde v0.1.0 hasta el estado actual de
> v0.5.0 (fase criptográfica + bundle `.vtrc` + storage guardian). No
> repite las amenazas ya mitigadas y documentadas en
> `docs/VTR-CRYPTO-001.md` y `docs/VTR-PKI-001.md` salvo donde una
> amenaza STRIDE las atraviesa de forma distinta a como esos documentos
> ya las trataron.

---

## 0. Cómo leer este documento

Cada amenaza tiene:
- **Componente** — el archivo/módulo real donde vive.
- **STRIDE** — una o más de las seis categorías (Spoofing, Tampering,
  Repudiation, Information Disclosure, Denial of Service, Elevation of
  Privilege).
- **Estado** — 🔴 sin mitigación / 🟡 mitigación parcial / ✅ mitigado.
- **Evidencia** — la línea o el comportamiento real del código que
  sustenta la clasificación, citado, no descrito de forma general.

No se incluyen amenazas teóricas sin anclaje en código real — si algo no
está implementado todavía (los adaptadores HMI stub, por ejemplo), se
nota como "no aplica — código no existe" en vez de inventarse un
escenario de ataque contra algo que no se puede atacar porque no corre.

---

## 1. Diagrama de superficies y límites de confianza

```
[HMI/PLC real]                [Operador con browser]
      │ Modbus/OPC-UA/etc.           │ JS (Modo A)
      ▼                              ▼
┌─────────────────────┐    ┌──────────────────────┐
│ rpi/hmi_adapter.py   │    │ src/session_guard.js │
│ (Ignition, OPC-UA    │    │ (IndexedDB, Web      │
│  reales; Modbus/     │    │  Crypto AES-GCM)     │
│  WinCC/iFIX/DNP3      │    └──────────┬───────────┘
│  = stub sin código)  │               │
└──────────┬───────────┘               │
           │ JWT verificado            │ HTTP
           ▼                           ▼
   ┌───────────────────────────────────────────┐
   │ rpi/proxy.py — FastAPI, SQLite local       │  ← LÍMITE 1
   │ POST /events  GET /health  DELETE /queue   │     (RPi físico,
   │ Sin auth en POST/GET; DELETE solo tras      │      planta OT)
   │ VTR_DEBUG=true (no es control de acceso)    │
   └──────────────────┬──────────────────────────┘
                       │ rpi/sync_manager.py + custody_manager.py
                       ▼
           ┌───────────────────────┐
           │ Capa 1/2 RF o HTTP    │  ← LÍMITE 2
           │ crypto_transport.py   │     (red, posible
           │ dtn_fragmenter.py     │      jamming/MITM)
           │ vtrc_bundle.py (USB)  │
           └──────────┬────────────┘
                       ▼
           ┌───────────────────────┐
           │ server/auth.py        │  ← LÍMITE 3
           │ server/compliance.py  │     (servidor central,
           │ (RS256, refresh       │      fuera de la planta)
           │  rotation)            │
           └───────────────────────┘
```

Tres límites de confianza cruzan el sistema: **LÍMITE 1** (planta OT
física, donde corre el RPi — asumido físicamente accesible a personal de
planta, no necesariamente confiable), **LÍMITE 2** (el medio de
transporte — RF, sneakernet, o red — donde un atacante externo puede
interceptar sin acceso físico), y **LÍMITE 3** (servidor central, fuera
del perímetro de la planta).

---

## 2. Spoofing — suplantación de identidad

| # | Componente | Amenaza | Estado | Evidencia |
|---|---|---|---|---|
| S-1 | `crypto_layer/vtrc_bundle.py` | Bundle `.vtrc` falsificado sin firma válida | ✅ Mitigado | `verify_bundle()` rechaza cualquier bundle sin firma Ed25519 válida del `node_id` declarado — 59 tests, incluye rechazo explícito de llave pública equivocada (`test_verify_bundle_rejects_wrong_public_key`). |
| S-2 | `rpi/jwt_verifier.py` | Token JWT falsificado en la verificación local del RPi | ✅ Mitigado | RS256 — el RPi solo tiene la clave **pública**, nunca la privada (docstring explícito: "el RPi nunca ve la clave privada"). Falsificar un token requeriría la clave privada del servidor. |
| S-3 | `rpi/proxy.py` | Suplantación del cliente que envía `POST /events` — el endpoint no requiere autenticación de ningún tipo | ✅ Mitigado | **Corregido** — `rpi/proxy_auth.py` (`require_scope("write")`, `Depends` en los 4 endpoints), conecta `rpi/jwt_verifier.py::RPiJWTVerifier` (existente desde v0.4.0, nunca usado) con `proxy.py`. Sin bypass de modo debug — decisión confirmada explícitamente. 22 tests, 100% coverage real, validado contra tokens JWT reales firmados por `server/auth.py::VTRAuth`. La nota de precisión sobre `VTR_API_KEY` (protege la sincronización saliente, no la entrada) sigue siendo cierta — la autenticación entrante ahora la provee el JWT, no esa variable. |
| S-4 | `rpi/agent.py` (`--mode socket`) | Suplantación de fuente de eventos vía el socket Unix/TCP de terceros | 🟡 Parcial | El socket escucha eventos de terceros sin un mecanismo de autenticación propio documentado en el módulo — la autenticación real ocurre más adelante en la cadena (`hmi_adapter.py` vía JWT), pero el primer punto de ingesta no valida quién conecta al socket. Mitigado solo si el socket está restringido a localhost/permsos de archivo a nivel de SO, lo cual no es parte del código, es configuración de despliegue. |
| S-5 | `crypto_layer/rf_config_loader.py` + config de campo (Q-03) | Suplantación de quien reconfigura un RPi en sitio sin acceso de red | 🟡 Decisión documentada, sin implementar | `docs/VTR-ARCH-DECISIONS-001.md` ya decidió que la config de campo debe firmarse con la clave `intermediate` de la PKI — pero esa verificación de firma no existe como código todavía (ver checklist pendiente). Hoy, cualquier archivo `rf_config.yaml` colocado en la ruta esperada se carga sin verificar su origen. |

---

## 3. Tampering — manipulación de datos

| # | Componente | Amenaza | Estado | Evidencia |
|---|---|---|---|---|
| T-1 | `crypto_layer/vtrc_bundle.py` | Modificación de un bundle `.vtrc` en tránsito (USB) | ✅ Mitigado | Canonicalización `header‖payload‖metadata` con firma puesta a cero antes de firmar; `verify_bundle()` confirmado que rechaza payload modificado y metadata modificada (`test_verify_bundle_rejects_tampered_payload`, `test_verify_bundle_rejects_tampered_metadata`). |
| T-2 | `core/crypto_transport.py` (`EncryptedBundle`) | Modificación de un bundle en tránsito LoRa/red en vivo | ✅ Mitigado | XChaCha20-Poly1305 es AEAD — cualquier modificación del ciphertext falla la verificación de tag de autenticación antes de descifrar. |
| T-3 | `rpi/proxy.py` (`DELETE /queue`) | Borrado/alteración no autorizada de la cola de eventos pendientes de sincronizar | ✅ Mitigado | **Corregido** — ahora exige *ambas* protecciones de forma independiente: JWT con scope `write` (nuevo) Y `VTR_DEBUG=true` (sin cambios). Verificado con test explícito: token válido sin `VTR_DEBUG` → 403, no 200 — confirma que ninguna protección sustituye a la otra. `VTR_DEBUG` mal dejado activo en producción ya no es suficiente por sí solo para vaciar la cola. |
| T-4 | `core/storage_guardian.py` | Manipulación de los umbrales de purga para forzar pérdida de datos | ✅ Mitigado | `WatchedDatabase.__post_init__` valida nombres de tabla/columna contra una whitelist regex antes de interpolarlos en SQL — confirmado contra inyección con tests explícitos (`test_malicious_table_name_raises`). Los umbrales (`warn_threshold_percent`, `purge_threshold_percent`) se validan en rango (0,100] y orden lógico en `StorageGuardian.__init__`. |
| T-5 | `core/storage_guardian.py` (bases `COUNTER`) | Forzar purga de `nonce_counter.db` o `vtrc_counter_seen.db` para abrir ventana de replay | ✅ Mitigado | Decisión de diseño explícita: `StorageRole.COUNTER` nunca se purga automáticamente sin importar el porcentaje de uso — `enforce()` retorna 0 y registra error en vez de ejecutar `_purge_fifo()` sobre esas bases. |
| T-6 | `src/session_guard.js` (fallback UUID) | Predicción/colisión de idempotency key cuando `crypto.randomUUID` no está disponible | 🟡 Parcial, severidad baja | El fallback usa `Math.random()` (línea ~40), que no es criptográficamente seguro — un atacante en el mismo origen podría en teoría predecir o forzar colisión de idempotency keys. Severidad baja porque el idempotency key no es un secreto de autenticación, solo previene duplicados; el daño práctico de una colisión sería un evento duplicado o ignorado, no una violación de confidencialidad. |

---

## 4. Repudiation — negación de una acción realizada

| # | Componente | Amenaza | Estado | Evidencia |
|---|---|---|---|---|
| R-1 | `rpi/jwt_verifier.py` | Operador niega haber enviado un evento tras revocación de su token | 🟡 Parcial | El docstring documenta explícitamente: "lista de revocación persiste en memoria — se limpia al reiniciar (en v0.5.0 se sincronizará vía CustodyManager al reconectar)". Si el RPi se reinicia (corte de energía, intencional o no) antes de que esa sincronización ocurra, un token ya revocado vuelve a aceptarse como válido durante el `DEFAULT_GRACE_PERIOD` (1800s) hasta su expiración natural — y el atacante que use ese token revocado-pero-temporalmente-válido tiene negación plausible, porque el sistema no tiene registro de que el token fue usado después de su revocación. |
| R-2 | `core/custody_manager.py` | Nodo niega haber recibido un bundle para evadir responsabilidad de reenvío | ✅ Mitigado por diseño | El propio principio del módulo ("ningún nodo borra un bundle hasta recibir confirmación explícita... la custodia es simétrica") significa que la ausencia de ACK deja el bundle en estado pendiente indefinidamente hasta timeout y reintento — el nodo que no confirma no puede "perder" el registro de que se le envió algo, porque el emisor lo sigue reteniendo. |
| R-3 | `rpi/proxy.py` | Ningún evento entrante queda atribuido a un emisor verificado | ✅ Mitigado | **Corregido junto con S-3** — cada request a `POST /events` ahora requiere un JWT válido con `hmi_id` verificable (`RPiVerifyResult.hmi_id`), restaurando la posibilidad de atribuir el origen real de un evento. |

---

## 5. Information Disclosure — exposición de información

| # | Componente | Amenaza | Estado | Evidencia |
|---|---|---|---|---|
| I-1 | `crypto_layer/__init__.py` | Exposición de `device_secret`/`passphrase` en memoria durante derivación async | ✅ Mitigado | Decisión de diseño documentada en memoria del proyecto: `derive_device_key_async` recibe secretos como **parámetros explícitos en cada llamada**, nunca de estado cacheado — limita la ventana de exposición en memoria. Confirmado por introspección de firma en los tests de la propuesta #4. |
| I-2 | `core/storage_guardian.py` | Filtración de tamaño/estructura de bases vía logs | 🟡 Severidad baja | Los logs de `enforce()` registran `db_path`, `percent_used`, y conteo de filas eliminadas — información operativa, no secretos, pero revela patrones de uso (ej. cuántos bundles procesa un nodo) a quien tenga acceso a los logs del sistema. Mitigación natural: control de acceso a logs es responsabilidad de despliegue, no de este módulo. |
| I-3 | `rpi/proxy.py` (`GET /stats`, `GET /health`) | Exposición de métricas operativas sin autenticación | ✅ Mitigado | **Corregido** — ambos endpoints ahora exigen JWT con scope `read` (`require_scope("read")`). Un observador no autenticado ya no puede consultar estado de cola, sincronización, ni salud del sistema. |
| I-4 | `docs/VTR-PKI-001.md` (ya documentado, referenciado aquí por completitud STRIDE) | CRL desactualizada durante jamming prolongado revela ventana de vulnerabilidad | 🟡 Ya documentado como limitación aceptada | No es una amenaza nueva — `VTR-PKI-001.md` ya reconoce esta limitación explícitamente. Se incluye aquí solo para que el modelo STRIDE esté completo sin necesitar que el lector cruce-referencie cada documento por separado. |

---

## 6. Denial of Service — denegación de servicio

| # | Componente | Amenaza | Estado | Evidencia |
|---|---|---|---|---|
| D-1 | `core/storage_guardian.py` | Llenado de `fragments.db` hasta agotar espacio de disco del RPi | ✅ Mitigado | Esto es exactamente el bloqueante S#2 de `VTR-SEC-001` que `storage_guardian.py` existe para resolver — purga FIFO automática al superar `purge_threshold_percent`, verificado con tests reales contra SQLite (incluyendo el bug real del archivo `-wal` encontrado y corregido durante el desarrollo). |
| D-2 | `crypto_layer/vtrc_bundle.py` | Bundle `.vtrc` de tamaño excesivo agota memoria al parsear | ✅ Mitigado | `MAX_BUNDLE_SIZE_BYTES` (alineado con `rf_config.yaml: sneakernet.bundle_max_size_mb: 64`) se valida tanto en `build_bundle()` como en `parse_bundle()` antes de procesar el contenido — confirmado con test (`test_oversized_bundle_raises`, `test_parse_oversized_raw_raises_bundle_integrity_error`). |
| D-3 | `rpi/proxy.py` | Inundación de `POST /events` sin rate limiting visible en el código | 🟡 Parcial | **Mitigado parcialmente por S-3** — ya no "cualquiera con acceso de red" puede inundar el endpoint, se requiere un JWT válido con scope `write`. Pero esto sigue sin ser una mitigación completa de DoS: un emisor legítimo con token válido (o un token comprometido/filtrado) puede seguir enviando volumen arbitrario — no existe ningún mecanismo de rate limiting, throttling, ni circuit breaker en `proxy.py`. Queda como pendiente real, distinto del problema de autenticación ya cerrado. |
| D-4 | `core/dtn_fragmenter.py` (`GhostScheduler`, fuera del alcance ya cerrado) | Saturación de ancho de banda LoRa por tráfico fantasma mal calibrado | 🟡 Riesgo de diseño, no de implementación | El propio mecanismo de `GhostScheduler` (tráfico fantasma para evitar correlación temporal) consume presupuesto de duty cycle real — si su calibración es agresiva, compite con tráfico legítimo por el 1% de duty cycle ISM ya ajustado. Esto es precisamente uno de los datos que el site survey RF (`docs/VTR-SURVEY-001.md`, prioridad máxima actual) debe informar antes de calibrar en campo real. |
| D-5 | `crypto_layer/argon2_derive.py` | Ataque de agotamiento de recursos forzando derivaciones repetidas con profile `hardened` (128MiB) | 🟡 Parcial | El catálogo cerrado de profiles (`embedded`/`desktop`/`hardened`) previene que un atacante eleve arbitrariamente el costo de memoria más allá de 128MiB por derivación, pero no hay límite de **tasa** de solicitudes de derivación visible en `crypto_layer/` — ese control, si existe, viviría en la capa de aplicación que invoca `CryptoLayer`, fuera del módulo mismo. |

---

## 7. Elevation of Privilege — escalación de privilegios

| # | Componente | Amenaza | Estado | Evidencia |
|---|---|---|---|---|
| E-1 | `rpi/hmi_adapter.py` | Adaptador HMI stub (Modbus/WinCC/iFIX/DNP3) ejecutándose con privilegios no verificados | ⚪ No aplica — código no existe | El propio docstring lista estos cuatro adaptadores como "stubs documentados (implementación pendiente)" — no hay código ejecutable que escalar. Se deja registrado aquí para que, cuando se implementen, el modelo STRIDE se actualice con la amenaza real en vez de asumir que ya fue considerada. |
| E-2 | `crypto_layer/argon2_derive.py` | Bypass del profile `embedded`/`desktop` para forzar derivación con parámetros arbitrarios | ✅ Mitigado | `_validate_profile()` valida contra catálogo cerrado (`InvalidProfileError` si el profile no está en la lista) — no hay ruta de código que acepte parámetros de memoria/iteraciones arbitrarios desde fuera del catálogo. |
| E-3 | `core/storage_guardian.py` | Escalación de un rol `TRANSIENT` a comportamiento de `COUNTER` (o viceversa) para forzar/evitar purga | ✅ Mitigado | `StorageRole` es un `Enum` de dos valores fijos asignado explícitamente al construir cada `WatchedDatabase` — no hay mecanismo para que una base cambie de rol en tiempo de ejecución sin reconstruir el `StorageGuardian` mismo, que es responsabilidad de quien lo instancia (fuera del módulo, decisión de configuración de despliegue). |
| E-4 | `server/auth.py` → `rpi/jwt_verifier.py` | Token de un rol de menor privilegio aceptado donde se requiere mayor privilegio | ⚪ Sin evidencia suficiente para clasificar | No se encontró en el código revisado un sistema de roles/scopes dentro del payload JWT más allá de validación de expiración y revocación — si existe diferenciación de privilegios por tipo de operador, vive en una capa no revisada en esta pasada. Se marca como pendiente de revisión específica, no como mitigado ni como vulnerable, para no afirmar algo sin evidencia directa. |

---

## 8. Resumen — qué requiere atención antes de v0.5.0 release

> **Actualización post-fix (commit `892c079`):** de las 5 amenazas que
> compartían el mismo origen estructural (S-3, T-3, R-3, D-3, I-3),
> **4 quedaron cerradas** con la integración de `rpi/proxy_auth.py` —
> S-3, R-3, I-3 marcadas ✅ completas; T-3 también ✅ (ahora exige doble
> protección independiente). Solo **D-3 sigue 🟡 parcial**: la
> autenticación eleva el costo del ataque (ya no "cualquiera en la red",
> se requiere un token válido), pero no implementa rate limiting en sí
> — un emisor legítimo o un token comprometido aún puede inundar el
> endpoint. El resto de este resumen documenta el estado original
> encontrado, conservado para trazabilidad histórica; ver las filas
> individuales de §2-§6 para el estado actual de cada amenaza.

De las 27 amenazas catalogadas (5 Spoofing, 6 Tampering, 3 Repudiation,
4 Information Disclosure, 5 Denial of Service, 4 Elevation of
Privilege), el patrón más repetido fue **el mismo gap apareciendo bajo
cuatro categorías STRIDE distintas**: `POST /events`, `GET /health`, y
`GET /stats` en `rpi/proxy.py` no tenían ningún mecanismo de
autenticación en su definición — no por una variable de entorno mal
configurada, sino porque la función `receive_events()` (y las dos de
solo lectura) simplemente no declaraban ningún parámetro, header, ni
dependency de FastAPI que verificara al emisor (S-3, T-3 parcialmente
relacionado, R-3, D-3, I-3 — cinco amenazas, un solo origen estructural).
Esto no era casualidad — un punto de ingesta sin autenticación
obligatoria abría simultáneamente spoofing, tampering, repudiation, DoS,
y disclosure, porque todas dependían de la misma garantía ausente: saber
quién está hablando con el proxy.

**Nota importante de esta revisión original:** `VTR_API_KEY` existe en
el código pero protege un canal distinto — la autenticación del *proxy
hacia el servidor central* al sincronizar (`SyncConfig(api_key=...)`),
no la ingesta de eventos entrantes. Esa distinción se mantuvo en la
corrección — la nueva autenticación JWT es un mecanismo independiente,
no una reutilización de `VTR_API_KEY`.

**Recomendaciones originales y su estado actual:**

1. ~~Agregar un mecanismo de autenticación real a `POST /events`,
   `GET /health`, y `GET /stats`~~ — **COMPLETADO**, `rpi/proxy_auth.py`,
   JWT con scopes, sin bypass de modo debug, 22 tests, 100% coverage.
2. **Rate limiting en `POST /events`** (D-3) — **sigue pendiente**, no
   se implementó como parte de este fix (estaba fuera del alcance
   acordado: cerrar el endpoint significaba autenticación, no rate
   limiting). Queda como ítem real distinto para una sesión futura.
3. **Sincronización de revocación de tokens tras reinicio** (R-1) — sin
   cambios, sigue pendiente, ver nota original más abajo.
4. ~~Verificación de firma en config de campo (S-5, Q-03)~~ —
   **COMPLETADO** en sesión separada, ver `docs/VTR-ARCH-DECISIONS-001.md`
   y `crypto_layer/field_config_verifier.py`.

**R-1 (revocación de tokens tras reinicio) sigue sin cambios:** la lista
de revocación de `jwt_verifier.py` persiste solo en memoria — un RPi que
se reinicia tras una revocación pierde ese registro hasta que
`CustodyManager` (ya existe como módulo) se integre explícitamente con
esa lista, lo cual no se confirmó como parte de este trabajo.
