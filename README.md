# Retomar VTR Continuity en otra máquina — Instrucciones rápidas

> **Estado al 2026-06-16:** Propuestas #1 (`docs/VTR-CRYPTO-001.md`) y #2
> (`docs/VTR-PKI-001.md`) generadas y aprobadas. La #2 introduce una decisión
> nueva no contemplada en el roadmap original: custodia de la CA root vía
> Shamir's Secret Sharing 3-de-5 (PyCryptodome), adelantada desde v0.6 a
> v0.5.0, con 4 capas de validación documentadas para mitigar el historial
> real de fallas de SSS en producción (ver sección 7 de este README).
> Siguiente paso: propuesta #3 (`crypto_layer/errors.py`).

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
   técnica aprobada, MÁS la decisión 5 (custodia SSS de la CA root) que
   se añadió en sesión posterior — ver HANDOFF.md.

4. Lee docs/VTR-CRYPTO-001.md — YA GENERADO. 4 reglas criptográficas
   (incluye VTR-CRYPTO-004 sobre Secure Boot V2 + Flash Encryption del
   Heltec ESP32-S3) con librería justificada por CVEs verificados.

5. Lee docs/VTR-PKI-001.md — YA GENERADO. Esquema PKI dos niveles (Root +
   Intermediate, Ed25519, cryptography/pyca ≥45.0) y custodia de la CA root
   vía Shamir's Secret Sharing 3-de-5 con 4 capas de validación (PyCryptodome).
   IMPORTANTE: los custodios de 4 de las 5 partes SSS siguen sin definir —
   es pendiente operativo de Luis, no inventar ubicaciones ni personas.

6. Lee specs/PROPOSALS-10.md para conocer las 10 propuestas, su contrato
   y criterios de aceptación. Las #1 y #2 ya están cerradas; seguimos con #3.

7. Confirma que tienes claras:
   - Las 5 decisiones aprobadas (1B, 2D-desktop-async, 3A, 4C, 5-SSS-3de5)
   - Las 4 reglas VTR-CRYPTO-001/002/003/004
   - Las 10 omisiones detectadas (O#1 a O#10) integradas al roadmap
   - El Definition of Done v0.5.0 actualizado
   - Que `device_secret` y su partición read-only son DISEÑO PENDIENTE
   - Que los custodios SSS 2,3,4,5 son PENDIENTE OPERATIVO de Luis

8. Continuamos con la propuesta #3 (crypto_layer/errors.py) — jerarquía de
   excepciones, base de toda validación defensiva según VTR-CRYPTO-003.

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
│   ├── DECISIONS-v0.5.0.md            # Pro/cons completos de las decisiones
│   ├── VTR-CRYPTO-001.md              # ✅ GENERADO — 4 reglas cripto + libs verificadas
│   └── VTR-PKI-001.md                 # ✅ GENERADO — PKI dos niveles + custodia SSS 3-de-5
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
2. ~~**Propuesta #2** (`docs/VTR-PKI-001.md`) — ✅ GENERADA.~~ Esquema PKI dos
   niveles + custodia de la CA root vía SSS 3-de-5, anclado a NIST SP 800-57 /
   ISO 27037. Los custodios específicos de 4 de las 5 partes quedan como
   pendiente operativo de Luis, documentado explícitamente en el archivo.
3. **Propuesta #3** (`errors.py`) — siguiente. Base de toda validación defensiva.
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
| ¿Qué herramienta genera y firma los certificados X.509 de la CA (root/intermediate)? | La librería más segura, menos propensa a vulnerabilidades | Se verificó que OpenSSL soporta Ed25519 nativamente vía PureEdDSA (RFC 8032/8410), pero se eligió `cryptography` (pyca) ≥45.0 para evitar invocar el binario OpenSSL vía subprocess (riesgo de shell injection) — misma librería ya fijada para Argon2id/HKDF, sin conflicto con PyNaCl que se reserva para firma directa de bundles `.vtrc` |
| ¿Adelantamos M-of-N (custodia distribuida de la CA root) a v0.5.0 en vez de diferirlo a v0.6? | Sí, usando Shamir's Secret Sharing — pero primero "ver el diseño exacto de cómo VTR validaría cada share antes de decidir" | Se investigó el historial real de fallas de SSS en producción **antes** de comprometerse: el caso Armory (coeficientes deterministas en vez de RNG real rompieron el esquema sin importar el umbral) y hallazgos de Trail of Bits en `tss-lib` de Binance. Se diseñaron 4 capas de mitigación explícitas (verificación de RNG, HMAC de integridad, umbral estricto sin reconstrucción parcial, custodia distribuida sin concentración geográfica) antes de fijar PyCryptodome SSS 3-de-5 como decisión final. Documentado en VTR-PKI-001 §4 |

**Principio aplicado en todas estas decisiones:** ninguna se fijó por inferencia
o "mejor práctica genérica" sin verificación. Las dos preguntas técnicas
(librería cripto, protección Heltec) se resolvieron con búsqueda activa de CVEs
y documentación oficial de hardware antes de escribir una sola línea de regla
permanente — siguiendo el principio de que cada byte de información debe
justificarse, no asumirse.
