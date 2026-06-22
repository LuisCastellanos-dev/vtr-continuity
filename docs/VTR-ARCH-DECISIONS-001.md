# Decisiones arquitectónicas — Q-01, Q-02, Q-03

> **Origen:** preguntas abiertas identificadas en `VTR-SEC-001` y heredadas
> al roadmap (`ROADMAP-v0.5.0.md`, tareas E1/E2/E3, prioridad P0).
> **Alcance:** estas tres preguntas viven en la frontera entre Capa 1
> (`core/crypto_transport.py`), Capa 2 (`core/dtn_fragmenter.py`) y el
> fallback sneakernet `.vtrc` — ninguna de las dos capas existentes las
> resuelve, porque ambas asumen una sesión RF activa entre nodos ya
> registrados. Las tres preguntas aparecen precisamente donde esa
> suposición deja de sostenerse.

---

## Q-01 — Detección de nodo muerto en red decentralizada

**El problema:** sin conectividad permanente, el sistema no puede asumir
que "no responde" significa "está caído". Un nodo puede estar:
(a) apagado, (b) vivo pero aislado por jamming activo, o (c) vivo,
recibiendo, pero con su canal de subida bloqueado. Las tres condiciones
producen el mismo síntoma observable — silencio — y requieren respuestas
operativas distintas (reemplazar el nodo vs. esperar vs. escalar el
fallback a sneakernet).

### Por qué el código existente no resuelve esto

`GhostScheduler` y `ReplayWindow` operan **dentro** de una sesión ya
establecida — su trabajo es ocultar patrones de tráfico y rechazar
replay, no decidir si la sesión sigue viva. `NodeRegistry` es una
whitelist estática (clave pública autorizada o no), no lleva estado de
"última vez visto". No hay ningún heartbeat ni temporizador de
liveness en ninguno de los dos módulos de Capa 1/2.

### Decisión

**Heartbeat pasivo basado en el propio NonceCounter, sin tráfico
dedicado.** En vez de un mensaje de heartbeat explícito (que añade
tráfico observable y consume presupuesto de ancho de banda LoRa ya
escaso — 222 bytes/frame), el estado de liveness de un nodo se infiere
de la progresión de su `counter` ya persistido en
`nonce_counter.db`:

- Cada nodo registrado tiene una **ventana de silencio tolerada**,
  configurable por tipo de nodo (`heartbeat_timeout_seconds` en
  `rf_config.yaml`, sección `rf:` — campo nuevo, no existe todavía).
- Mientras el `last_counter()` de un nodo avance dentro de esa ventana,
  se considera vivo — sin necesitar un mensaje dedicado, porque
  cualquier tráfico real (telemetría, ack, lo que sea) ya incrementa el
  counter.
- Si la ventana se agota sin avance, el nodo pasa a estado
  `SUSPECTED_DOWN` — no `DOWN`. La distinción importa: jamming activo y
  nodo apagado son indistinguibles desde el observador remoto, así que
  el sistema no debe actuar como si confirmara una falla que no puede
  confirmar.
- La escalación de `SUSPECTED_DOWN` a intervención humana (reemplazo de
  hardware, etc.) es una decisión operativa, no automática — el sistema
  notifica, no actúa unilateralmente.

**Por qué no un heartbeat dedicado:** un mensaje de heartbeat explícito
sería un patrón temporal predecible — exactamente lo que `GhostScheduler`
existe para evitar. Inferir liveness de tráfico real ya cifrado e
indistinguible de tráfico fantasma mantiene la propiedad de
no-correlación temporal sin gastar presupuesto de frame.

**Riesgo residual aceptado — y CORRECCIÓN sobre `GhostScheduler`:** un
nodo que genuinamente no tiene nada que transmitir durante la ventana
completa se ve idéntico a uno caído. La versión original de este
documento afirmaba que esto estaba "mitigado parcialmente por el propio
`GhostScheduler`, que ya inyecta tráfico fantasma periódico — un nodo
vivo genera frames fantasma aunque no tenga datos reales". **Esa
afirmación es incorrecta y se corrige aquí tras verificar el código real
de `core/dtn_fragmenter.py`** durante la implementación de
`core/liveness.py`: `BundleFragmenter.fragment()` solo invoca
`GhostScheduler.should_inject()`/`make_ghost(bundle_id)` **dentro** del
flujo de fragmentar un bundle real ya existente —
`make_ghost(bundle_id)` requiere un `bundle_id` real como parámetro. No
existe ninguna ruta de código donde el ghost traffic se dispare de forma
autónoma sin que ya haya tráfico real en curso. El riesgo residual
descrito al inicio de este párrafo **no está mitigado** en el estado
actual del código — un nodo genuinamente silencioso (sin tráfico real
que dispare ghost traffic) sí se ve idéntico a uno caído. Esto queda
documentado como limitación conocida, no resuelta, en
`core/liveness.py` (docstring del módulo).

**Implementado:** `core/liveness.py` — `LivenessTracker` con estados
`UNKNOWN`/`ALIVE`/`SUSPECTED_DOWN`, lee `updated_at` de la tabla
`nonce_counter` ya persistida por `NonceCounter` (ninguna columna ni
tabla nueva). 31 tests, 100% coverage real. El campo
`heartbeat_timeout_seconds` se implementó como parámetro del
constructor de `LivenessTracker` (no como campo de `rf_config.yaml`
todavía — esa integración de configuración queda como trabajo
posterior, separado de la máquina de estados misma).

---

## Q-02 — Paradoja de reset de RTC + replay de nonce

**El problema:** si un nodo pierde energía por tiempo prolongado, su reloj
de tiempo real (RTC) puede reiniciarse o desincronizarse — y NTP no está
disponible por definición en el escenario que VTR Continuity existe para
resolver (air-gapped, jamming). Si el sistema de detección de replay
dependiera del timestamp, un atacante con un bundle capturado podría
esperar a que el RTC se reinicie y reproducirlo como si fuera nuevo.

### Por qué esto ya está parcialmente resuelto — y dónde no

**Para tráfico en vivo entre sesión RF activa, esto ya está resuelto.**
`NonceCounter` (línea 82+ de `crypto_transport.py`) es explícitamente
monotónico y persistido en SQLite, no derivado del reloj del sistema —
el docstring de la clase lo dice sin ambigüedad: *"Nunca retrocede aunque
el proceso se reinicie."* `ReplayWindow` valida contra ese counter, no
contra tiempo. Un reset de RTC no afecta esta ruta porque nunca consultó
el RTC para empezar.

**El gap real está en el escenario sneakernet — bundles `.vtrc` sin
sesión.** El `NonceCounter` vive en `nonce_counter.db`, una base de datos
*local al nodo*. Dos nodos que nunca tuvieron sesión RF directa entre sí
(comunicándose solo vía USB `.vtrc` transportado por una persona) no
comparten ese estado. El `counter` de un nodo A no significa nada para
el `ReplayWindow` de un nodo B que nunca lo vio. Aquí es donde la pregunta
original tiene mordida real: si el mecanismo anti-replay no se puede
basar en RTC (no confiable) ni en un counter compartido (no existe canal
para sincronizarlo en air-gapped), ¿qué lo reemplaza?

### Decisión

**El `counter` persistido viaja DENTRO del bundle `.vtrc`, no se infiere
del receptor.** Cada bundle `.vtrc` incluye en su header el par
`(node_id, counter)` ya generado por el `NonceCounter` del nodo emisor al
momento de crear el bundle — el mismo valor que ya usa internamente para
el nonce XChaCha20-Poly1305. El nodo receptor mantiene su propia tabla
de "máximo counter visto por node_id" — estructuralmente idéntica a la
tabla `nonce_counter` que ya existe, pero usada en modo verificación en
vez de generación.

- Un bundle con `counter <= último_counter_visto[node_id]` se rechaza
  como replay, sin importar qué diga su timestamp o el RTC del receptor.
- Esto extiende el patrón ya validado de `ReplayWindow` (comparación
  contra estado persistido, no contra reloj) al caso sin sesión — es la
  misma lógica, aplicada a un canal asíncrono.
- El RTC deja de ser parte de la cadena de confianza para anti-replay en
  cualquier escenario, en vivo o sneakernet. Donde se necesite un
  timestamp (por ejemplo, para decidir si un bundle es demasiado viejo
  para ser útil operativamente), ese campo es informativo, no de
  seguridad — su falsificación no compromete el anti-replay.

**Por qué no usar el TTL de DTN Bundle Protocol (RFC 9171) para esto:**
el campo TTL de RFC 9171 mide vigencia operativa del mensaje, no
identidad. Dos bundles distintos pueden tener el mismo TTL; el ataque de
replay no se resuelve con vigencia, se resuelve con detección de
duplicado — que es exactamente lo que el par `(node_id, counter)` ya
hace.

**Riesgo residual aceptado:** si el receptor nunca antes vio a ese
`node_id`, no tiene un "último counter visto" contra el cual comparar —
acepta el primer bundle de un nodo nuevo sin poder detectar replay en
ese primer contacto. Esto es inherente a cualquier esquema basado en
estado del receptor, no específico de esta decisión. Mitigación: el
primer contacto de un nodo nuevo solo es válido si el nodo está en
`NodeRegistry` (whitelist por clave pública Ed25519) — un atacante sin
la clave privada correspondiente no puede producir un bundle que pase
verificación de firma, así que el riesgo de replay en primer contacto
se limita a un nodo legítimo cuyo primer bundle fue capturado y se
reproduce antes de que llegue el original. Ventana de explotación
estrecha y específica, no abierta.

**Pendiente de implementación:** el formato exacto del header de
`.vtrc` que transporta `(node_id, counter)` se define en la propuesta de
formato de bundle (siguiente paso de este checklist, después de esta
decisión). La tabla de "último counter visto" en modo verificación es
una extensión directa del esquema SQL ya usado por `NonceCounter` — no
requiere diseño nuevo, solo una segunda instancia de la misma estructura
operando en modo lectura/verificación.

---

## Q-03 — Interfaz de configuración en campo como superficie de ataque

**El problema:** un RPi desplegado en sitio industrial necesita poder
reconfigurarse sin acceso a la red (cambio de profile Argon2id, rotación
de parámetros RF, etc.). Cualquier interfaz que exponga esa capacidad —
puerto serie, botón físico, archivo de configuración leído de un USB — es
también la superficie por la que un atacante con acceso físico podría
inyectar configuración maliciosa.

### Por qué esto conecta directamente con código ya cerrado

`crypto_layer/rf_config_loader.py` (propuesta #8) ya valida tipos,
catálogo cerrado de profiles, y campos obligatorios de `rf_config.yaml`
— pero **deliberadamente no valida que los archivos existan en el
sistema** (nota ya documentada en `HANDOFF.md`: esa verificación es
"responsabilidad en tiempo de uso real, no en tiempo de carga"). Esa
decisión ya anticipaba que el archivo de configuración podría llegar por
una vía física (USB) distinta de la instalación inicial — exactamente
el vector que Q-03 pregunta cómo proteger.

### Decisión

**El archivo de configuración en campo se trata como un bundle más, no
como confianza implícita por ubicación.** En vez de que el RPi confíe en
cualquier `rf_config.yaml` que aparezca en una ruta predefinida o en un
USB insertado, el archivo de configuración de campo debe estar firmado
con la misma clave Ed25519 de provisioning (la `intermediate` de
`VTR-PKI-001.md`, no la clave del dispositivo) antes de que
`load_crypto_config()` lo acepte.

- Esto convierte la interfaz de configuración en campo de "cualquiera
  con acceso físico puede reconfigurar" a "solo alguien con acceso a la
  clave de provisioning puede reconfigurar" — la misma cadena de
  confianza que ya protege la emisión de certificados de dispositivo, sin
  introducir un mecanismo de autorización nuevo y paralelo.
- El loader ya existente (`rf_config_loader.py`) no necesita modificarse
  para esto — la verificación de firma ocurre **antes** de que el YAML
  llegue al loader, como un paso de validación adicional en el punto de
  entrada (lectura de USB / puerto serie), análogo a cómo
  `BundleFragmenter.reassemble()` ya rechaza fragmentos inconsistentes
  antes de pasarlos a capas superiores.
- Sin firma válida, el RPi conserva su configuración actual y registra
  el intento de reconfiguración no autorizada — no falla abierto a la
  configuración por defecto, que podría ser explotada para degradar
  parámetros de seguridad (ej. forzar profile `embedded` en vez de
  `desktop`).

**Por qué no un PIN/passphrase local en vez de firma criptográfica:** un
PIN es un secreto compartido que vive en el dispositivo y en la cabeza de
quien lo conoce — exactamente el patrón que `VTR-CRYPTO-002` ya prohíbe
para el `device_secret` (hardware ID público ≠ salt; aquí el equivalente
sería PIN local ≠ control de acceso real). Reusar la PKI ya existente
evita introducir una segunda jerarquía de secretos paralela a la que ya
se diseñó y validó en las propuestas #1–#9.

**Riesgo residual aceptado:** si la clave de la `intermediate` CA se
compromete, el atacante puede firmar configuración maliciosa para
cualquier dispositivo de la flota — mismo riesgo ya aceptado y mitigado
en `VTR-PKI-001.md` (rotación de 2 años, revocación vía CRL en bundle
`.vtrc`). No se introduce una superficie de riesgo nueva; se reutiliza
la existente en vez de duplicarla.

**Pendiente de implementación:** el paso de verificación de firma en el
punto de entrada de configuración de campo no existe como código
todavía. Depende del formato de bundle `.vtrc` (próximo paso) para
reusar la misma primitiva de firma/verificación de
`crypto_layer/ed25519_sign.py` en vez de inventar un formato de "config
firmada" distinto al de los bundles de datos.

---

## Resumen — impacto en el roadmap inmediato

| Pregunta | Decisión | Estado de implementación |
|---|---|---|
| Q-01 | Heartbeat pasivo vía progresión de `NonceCounter`, sin mensaje dedicado | ✅ Implementado — `core/liveness.py` (`LivenessTracker`, 31 tests, 100% coverage). Limitación conocida documentada arriba: sin `GhostScheduler` autónomo, un nodo genuinamente silencioso no se distingue de uno caído. |
| Q-02 | `(node_id, counter)` viaja dentro del bundle `.vtrc`; verificación contra tabla de "último counter visto", no contra RTC | ✅ Implementado — `crypto_layer/vtrc_bundle.py` (header con campos fijos, `CounterVerificationStore`, 59 tests, 96% coverage). |
| Q-03 | Configuración de campo firmada con clave de `intermediate` CA, verificada antes del loader existente | ⬜ Pendiente — reusa primitiva de `ed25519_sign.py`; el paso de verificación de firma en el punto de entrada de config de campo no existe como código todavía. |

Las tres decisiones comparten un principio: **ninguna introduce una
primitiva criptográfica o un mecanismo de confianza nuevo** — las tres
reutilizan estructuras ya validadas en las propuestas #1–#9
(`NonceCounter`, PKI de dos niveles, `ed25519_sign.py`). Esto es
consistente con el criterio aplicado durante toda la fase criptográfica:
minimizar superficie nueva, maximizar reuso de lo ya probado.

Q-01 y Q-02 ya están implementadas y verificadas con tests reales. Q-03
queda como el único punto pendiente de este trío — depende del formato
de bundle `.vtrc` (ya implementado en Q-02) para reusar la misma
primitiva de firma/verificación en vez de inventar un formato de "config
firmada" distinto.
