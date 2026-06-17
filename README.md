# Retomar VTR Continuity en otra máquina — Instrucciones rápidas

> **Estado al 2026-06-16:** Propuesta #1 (`docs/VTR-CRYPTO-001.md`) generada y
> aprobada. Incluye una 4ª regla (VTR-CRYPTO-004) no contemplada en el roadmap
> original, derivada de validar contra documentación oficial de Espressif el
> mecanismo de protección física del Heltec. Ver sección 7 de este README para
> el detalle de lo cerrado y lo que sigue abierto por diseño.

## 1. Sube los archivos a la nueva sesión de Claude

Cuando abras una nueva conversación en otra PC, sube **todos los archivos
de este paquete** y pega este prompt:

---

### Prompt para Claude (copiar tal cual)

```
Voy a retomar el proyecto VTR Continuity v0.5.0. Te adjunto los archivos
del handoff que generamos en la sesión anterior. Por favor:

1. Lee HANDOFF.md primero para tener el contexto completo del proyecto,
   las decisiones tomadas y las reglas de desarrollo permanentes.

2. Lee docs/ROADMAP-v0.5.0.md para el plan de trabajo en 5 épicas.

3. Lee docs/DECISIONS-v0.5.0.md para entender el pro/cons de cada decisión
   técnica aprobada.

4. Lee docs/VTR-CRYPTO-001.md — YA GENERADO. Contiene las 4 reglas
   criptográficas (incluye VTR-CRYPTO-004, nueva, sobre Secure Boot V2 +
   Flash Encryption del Heltec ESP32-S3) y la justificación verificada de
   qué librería usa cada primitiva (PyNaCl para Ed25519/XChaCha20-Poly1305,
   cryptography/pyca ≥45.0 para Argon2id/HKDF).

5. Lee specs/PROPOSALS-10.md para conocer las 10 propuestas, su contrato
   y criterios de aceptación. La #1 ya está cerrada; seguimos con la #2.

6. Confirma que tienes claras:
   - Las 4 decisiones aprobadas (1B, 2D-desktop-async, 3A, 4C)
   - Las 4 reglas VTR-CRYPTO-001/002/003/004
   - Las 10 omisiones detectadas (O#1 a O#10) integradas al roadmap
   - El Definition of Done v0.5.0 actualizado
   - Que `device_secret` y su partición read-only son DISEÑO PENDIENTE,
     no implementación existente — no asumir que el bench ya lo genera

7. Continuamos con la propuesta #2 (docs/VTR-PKI-001.md), aplicando cadena
   de custodia alineada a NIST SP 800-57 / ISO 27037 para el backup y
   recuperación de la CA root, según lo acordado.

Contexto adicional del proyecto:
- Soy Luis Castellanos, fundador de Vector Telemetry Research (VTR)
- Boutique B2B de ciberseguridad y OT/ICS-SCADA en Tampico, Tamaulipas
- Stack de desarrollo: Linux Mint, GitHub
- Org del repo: github.com/LuisCastellanos-dev/vtr-continuity
- Hardware ya adquirido: 2× Heltec WiFi LoRa 32 V3 + RPi 4
- Cliente objetivo: petroquímica, CFE, manufactura en Tampico
```

---

## 2. Archivos en este paquete

```
vtr_continuity_handoff/
├── HANDOFF.md                          # Lee esto primero
├── README.md                           # Este archivo
├── docs/
│   ├── ROADMAP-v0.5.0.md              # Plan en 5 épicas con prioridades
│   ├── DECISIONS-v0.5.0.md            # Pro/cons completos de las 4 decisiones
│   └── VTR-CRYPTO-001.md              # ✅ GENERADO — 4 reglas cripto + libs verificadas
└── specs/
    └── PROPOSALS-10.md                # Especificación de las 10 entregables
```

## 3. Checklist al iniciar en la nueva máquina

- [ ] Subí todos los archivos del handoff a la nueva sesión de Claude
- [ ] Pegué el prompt de retoma
- [ ] Claude confirmó que entiende las 4 decisiones y 3 reglas
- [ ] Cloné `github.com/LuisCastellanos-dev/vtr-continuity` en la nueva PC
- [ ] Creé la rama `feature/crypto-layer-v0.5.0`
- [ ] Instalé Python 3.11+ y `pip install cryptography>=42 pyyaml argon2-cffi`
- [ ] Verifiqué acceso al bench físico de Tampico (para épica C)

## 4. Orden de trabajo recomendado al retomar

Sigue el orden de las propuestas en `specs/PROPOSALS-10.md`. La selección del
orden de inicio se decidió con un criterio explícito: **se prioriza lo que
pueda refinar o modificar cualquier fase previa y garantice un vector más
seguro** — por eso #1 (las reglas) va antes que cualquier código, ya que un
cambio en las reglas después de generar #3–#9 obligaría a reescribirlos.

1. ~~**Propuesta #1** (`docs/VTR-CRYPTO-001.md`) — ✅ GENERADA.~~ Fija las 4 reglas
   y la librería exacta por primitiva (PyNaCl vs pyca, con justificación basada
   en CVEs verificados, no en preferencia).
2. **Propuesta #2** (`docs/VTR-PKI-001.md`) — siguiente. Debe alinear el
   procedimiento de backup/recuperación de la CA root a estándares
   internacionales de cadena de custodia (NIST SP 800-57, ISO/IEC 27037), no a
   una política improvisada — esto se acordó explícitamente para el escenario
   de pérdida total del bench de Tampico.
3. **Propuesta #3** (`errors.py`) — base de toda validación defensiva.
4. **Propuesta #4** (API pública) — define los contratos.
5. **Propuestas #5, #6, #7** (implementaciones) — en este orden.
6. **Propuesta #8** (config) — paralelo a #5.
7. **Propuesta #9** (tests) — al final, valida todo.
8. **Propuesta #10** (DoD) — cierre, marca el estado.

## 5. Si Claude pierde contexto

Si en algún punto Claude empieza a "alucinar" detalles diferentes a los
documentados aquí, dile:

```
Detente. Releé HANDOFF.md y docs/DECISIONS-v0.5.0.md. Verifica que estás
respetando las 4 decisiones aprobadas (1B, 2D-desktop-async, 3A, 4C) y
las 3 reglas VTR-CRYPTO-001/002/003. Si hay alguna duda, pregúntame antes
de avanzar.
```

## 6. Comando para empaquetar versión actualizada del handoff

Cuando termines una sesión de trabajo y quieras llevarte el estado
actualizado a otra máquina:

```bash
# En el repo vtr-continuity
git pull
mkdir -p ~/vtr_handoff_$(date +%Y%m%d)
cp -r docs/ specs/ HANDOFF.md README.md ~/vtr_handoff_$(date +%Y%m%d)/
cd ~ && tar czf vtr_handoff_$(date +%Y%m%d).tar.gz vtr_handoff_$(date +%Y%m%d)/
```

Sube ese `.tar.gz` (o sus archivos descomprimidos) a la siguiente sesión.

---

## 7. Decisiones cerradas en esta sesión (2026-06-16) — no asumidas, consultadas

Antes de generar la propuesta #1 se identificaron 3 ambigüedades bloqueantes en
el roadmap original. En vez de resolverlas por inferencia, se consultaron
explícitamente. Quedan registradas aquí para que cualquier persona o sesión que
retome el proyecto entienda el porqué, no solo el qué.

| Pregunta abierta | Respuesta obtenida | Efecto en el roadmap |
|---|---|---|
| ¿Con cuál propuesta empezar? | La que pueda refinar/modificar cualquier fase previa y dé un vector más seguro | Se confirmó #1 como punto de partida — ya generada |
| ¿`device_secret` y su partición ya existen en el RPi? | **No — es diseño pendiente**, aún no implementado | VTR-CRYPTO-001 §3 lo marca explícitamente como no-disponible; ningún código de producción puede asumir su existencia; tests deben usar mocks, no valores que simulen el secreto real |
| ¿Qué política aplica si el bench de Tampico se pierde completamente (incendio, robo) antes de que B5 (backup geográfico) exista? | Apegarse a mejores prácticas internacionales de cadena de custodia / manejo de información | Pendiente de aplicar en **propuesta #2** (`VTR-PKI-001.md`): anclar el procedimiento a NIST SP 800-57 (gestión de llaves) e ISO/IEC 27037 (cadena de custodia de evidencia digital) — no a una política inventada ad-hoc |
| ¿Qué librería implementa cada primitiva cripto? | La que garantice seguridad y no sea vulnerada como vector de ataque por terceros | Se investigaron CVEs recientes de PyNaCl/libsodium (CVE-2025-69277) y pyca/cryptography (CVE-2026-26007). Resultado: PyNaCl para Ed25519/XChaCha20-Poly1305 (mejor perfil en uso asimétrico según estudio IEEE S&P), pyca≥45.0 para Argon2id/HKDF. Documentado en VTR-CRYPTO-001 §1 |
| ¿Cómo protege el Heltec su clave maestra sin derivarla, garantizando "difícil suplantación/captura/manipulación"? | Investigar la opción de mecanismo seguro y documentado (no solo eFuse "pelón"), con la premisa de "cada byte vale" | Se verificó contra documentación oficial de Espressif que el ESP32-S3 soporta nativamente Secure Boot V2 + Flash Encryption + hardening de JTAG/USB-OTG vía eFuse — sin hardware adicional. Nueva regla **VTR-CRYPTO-004** documentada con el orden exacto de quemado de eFuses y el riesgo residual aceptado (irreversibilidad, fault injection fuera de alcance v0.5.0) |

**Principio aplicado en todas estas decisiones:** ninguna se fijó por inferencia
o "mejor práctica genérica" sin verificación. Las dos preguntas técnicas
(librería cripto, protección Heltec) se resolvieron con búsqueda activa de CVEs
y documentación oficial de hardware antes de escribir una sola línea de regla
permanente — siguiendo el principio de que cada byte de información debe
justificarse, no asumirse.
