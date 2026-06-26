# VTR-COMPLIANCE-001 — Mapeo consolidado a IEC 62443 / NERC CIP

> **Origen:** omisión O#10 (`docs/HANDOFF.md`), tareas E9/E10/E11
> (`docs/ROADMAP-v0.5.0.md`), checklist pre-release post-#10
> (`docs/DOD-v0.5.0.md` §5).
> **Método:** cada fila de este documento cita el archivo y línea (o
> sección) real donde la decisión/control vive — no se afirma
> cumplimiento sin señalar exactamente dónde está implementado o
> documentado. Donde el control existe solo como decisión documentada
> sin código todavía, se marca explícitamente como tal.
> **Por qué este documento existe:** antes de esta consolidación, las
> referencias a IEC 62443/NERC CIP estaban dispersas en 6 documentos
> distintos (`VTR-CRYPTO-001.md`, `DECISIONS-v0.5.0.md`,
> `server/compliance.py`, `ROADMAP-v0.5.0.md`, `HANDOFF.md`,
> `DOD-v0.5.0.md`) sin un mapeo cláusula-por-cláusula que las conectara
> entre sí — alguien revisando una sola cláusula tenía que buscar en los
> 6 documentos para saber qué cubre VTR Continuity sobre ella.

---

## 0. Alcance y limitación honesta

Este documento **no es una certificación de cumplimiento** ni sustituye
la evaluación de un auditor calificado en IEC 62443 o NERC CIP. Es el
mapeo técnico que un auditor o consultor de cumplimiento necesitaría
como punto de partida — conecta cada cláusula citada en algún lugar del
proyecto con la evidencia concreta (código ejecutable, decisión
documentada, o control pendiente) que la respalda.

**NERC CIP es un marco regulatorio del sector eléctrico de Norteamérica**
(NERC = North American Electric Reliability Corporation). VTR Continuity
no está diseñado exclusivamente para ese sector — el roadmap del
proyecto (`docs/ROADMAP-v0.5.0.md`) ya evaluó y descartó la nuclear
energy (Laguna Verde/CFE bajo CNSNS) como mercado no viable, e identificó
metalúrgica como el sector primario objetivo. Las citas a NERC CIP en
este documento reflejan que `server/compliance.py` ya implementa esos
controles (son aplicables y verificables independientemente del sector
final), no que VTR Continuity busque certificación NERC CIP como
objetivo de producto.

---

## 1. Mapeo por cláusula — IEC 62443-3-3 (System Security Requirements)

| Cláusula | Requisito | Estado | Evidencia |
|---|---|---|---|
| **SR 1.1** | Identificación y autenticación de usuarios humanos | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_access_ttl()` — verifica que el TTL de token de acceso esté configurado y acotado (≤3600s). Citado también en `VTR-CRYPTO-001.md` §7 (referencias) sin mapeo individual hasta este documento. |
| **SR 1.2** | Identificación y autenticación de software/procesos | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_revocation_list()` — verifica que la lista de revocación de tokens esté habilitada; sin ella, un proceso/token comprometido no puede invalidarse. |
| **SR 1.3** | Gestión de cuentas de usuario | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_refresh_rotation()` — verifica rotación de refresh tokens (cada uso invalida el anterior). |
| **SR 1.5** | Gestión de autenticadores | 🟡 Decisión documentada, parcialmente implementada | `VTR-CRYPTO-001.md` §7 cita esta cláusula en bloque. Cobertura real: rotación de `device_secret` cada 18 meses (`VTR-PKI-001.md` §5, alineado con validez de certificado de dispositivo) — pero el mecanismo de generación/custodia del `device_secret` sigue siendo **diseño pendiente** (`VTR-CRYPTO-002`, no implementado). No se puede marcar ✅ completo mientras ese pendiente exista. |
| **SR 1.8** | Infraestructura de llave pública (PKI) | ✅ Diseño completo, ejecución física pendiente | `VTR-PKI-001.md` completo — PKI de dos niveles (Root offline + Intermediate online), SSS 3-de-5 para custodia de Root con 4 capas de mitigación verificadas contra fallas históricas reales (Armory, tss-lib de Binance). Citado explícitamente como "cumple plenamente IEC 62443-3-3 SR 1.8" en `DECISIONS-v0.5.0.md` (Decisión 4, opción 4A). **Limitación honesta:** el diseño está completo y verificado; la ejecución real del setup de CA (generar la Root real, no solo el procedimiento) sigue pendiente — ver `docs/DOD-v0.5.0.md` §5. |
| **SR 2.1** | Control de autorización | 🟡 Parcial, gap real identificado | `VTR-CRYPTO-001.md` §7 cita esta cláusula. Cobertura real: `server/compliance.py::ComplianceChecker._check_grace_period()` acota el grace period offline. **Gap real encontrado en `docs/VTR-THREAT-001.md`** (modelo STRIDE, amenazas S-3/T-3/R-3/D-3/I-3): `rpi/proxy.py` no tiene ningún mecanismo de autorización en `POST /events`, `GET /health`, `GET /stats` — esto es un incumplimiento real y conocido de SR 2.1 en ese componente específico, no una omisión de este documento. |
| **SR 4.1** | Confidencialidad de información en tránsito | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_tls()` — verifica TLS habilitado en todos los canales servidor↔RPi. Para el canal RF (Capa 1 LoRa), la confidencialidad la provee XChaCha20-Poly1305 (`crypto_layer/`, no TLS — canal distinto, mismo objetivo de cláusula). |
| **SR 4.3** | Uso de criptografía | ✅ Verificable por código + diseño | `server/compliance.py::ComplianceChecker._check_key_size()` — tamaño mínimo de clave 2048 bits. `VTR-CRYPTO-001.md` completo — selección de librerías por CVE real, Ed25519/XChaCha20-Poly1305/Argon2id/HKDF-SHA256 con justificación verificada, no por reputación. |

---

## 2. Mapeo por cláusula — IEC 62443-2-1 (Programa de gestión de seguridad IACS) e IEC 62443-4-2 (Requisitos de componente)

| Cláusula | Requisito | Estado | Evidencia |
|---|---|---|---|
| **4.3.3.3** | Registro y monitoreo de eventos de seguridad | ✅ Verificable por código | `server/compliance.py::AuditLog` — registro inmutable con SHA-256 por entrada, verificado contra `_check_audit_log()`. Persiste en `compliance.db`, separado deliberadamente de `queue.db` y `custody.db` (decisión arquitectónica explícita en el docstring de la clase). |
| **4.3.3.6** | Gestión de tiempo de respuesta a eventos | 🟡 Parcial | `server/compliance.py::ComplianceChecker._check_custody_timeout()` — verifica timeout de custodia de mensajes acotado (≤1800s). Cubre el aspecto de mensajería; no cubre tiempo de respuesta a incidentes de seguridad en general (eso es proceso operativo, no algo que el código pueda verificar). |
| **CR 1.5** *(62443-4-2)* | Autenticación de dispositivos | ✅ Diseño completo | `DECISIONS-v0.5.0.md` Decisión 3 (provisioning 3A) — citado explícitamente: "Auditabilidad: cumple IEC 62443-4-2 CR 1.5". Respaldado por `VTR-PKI-001.md` §3.3 (emisión de certificado de dispositivo, validez 18 meses, almacenado en partición firmada). |

---

## 3. Mapeo por cláusula — NERC CIP

| Cláusula | Requisito | Estado | Evidencia |
|---|---|---|---|
| **CIP-005-6 R1** | Perímetro de seguridad electrónico — control de acceso | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_tls()` — mismo control que SR 4.1, doble cita porque ambos marcos exigen cifrado en tránsito. |
| **CIP-007-6 R4** | Gestión de seguridad de sistemas — parámetros criptográficos | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_key_size()` — mismo control que SR 4.3. |
| **CIP-007-6 R5** | Gestión de cuentas — auditoría de acceso | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_audit_log()` + `_check_revocation_list()` (R5.3 específicamente, ver fila siguiente). |
| **CIP-007-6 R5.3** | Revocación de credenciales comprometidas | ✅ Verificable por código | `server/compliance.py::ComplianceChecker._check_revocation_list()` — mismo control citado para SR 1.2, doble mapeo porque NERC CIP-007-6 R5.3 y IEC 62443-3-3 SR 1.2 exigen esencialmente el mismo control desde marcos distintos. |
| **CIP-008-6** | Reporte de incidentes de ciberseguridad | ⬜ No implementado | Citado en el docstring de `server/compliance.py` (línea 15) como estándar cubierto, pero **no existe ningún `_check_*` en `ComplianceChecker` que verifique un mecanismo de reporte de incidentes** — el módulo cubre auditoría y autenticación, no el flujo de reporte/escalación de incidentes que CIP-008-6 exige. Esta es una brecha real entre lo que el docstring del módulo afirma cubrir y lo que el código efectivamente verifica — se documenta aquí en vez de repetir la afirmación del docstring sin comprobarla. |

---

## 4. Marcos adicionales citados con el mismo rigor (fuera del alcance original IEC 62443/NERC CIP, incluidos por completitud)

| Marco | Aplicación en el proyecto | Evidencia |
|---|---|---|
| **NIST SP 800-57** | Gestión de ciclo de vida de llaves criptográficas, incluyendo recuperación ante pérdida | `VTR-PKI-001.md` §4.4 — escenario de recuperación de la CA Root tras pérdida del bench principal, citado explícitamente alineado a este marco. |
| **ISO/IEC 27037** | Preservación de cadena de custodia para evidencia digital, aplicado a material criptográfico crítico | `VTR-PKI-001.md` §4.4 — mismo escenario de recuperación, aplicando los principios de cadena de custodia digital a las partes SSS de la CA Root. |

---

## 5. Resumen cuantitativo

| Estado | Cantidad de filas | Cláusulas |
|---|---|---|
| ✅ Verificable por código (ejecutable, con test) | 10 | SR 1.1, SR 1.2, SR 1.3, SR 4.1, SR 4.3, 4.3.3.3, CIP-005-6 R1, CIP-007-6 R4, CIP-007-6 R5, CIP-007-6 R5.3 |
| ✅ Diseño completo (documentado y verificado, ejecución pendiente) | 2 | SR 1.8, CR 1.5 |
| 🟡 Parcial (cubre parte de la cláusula, gap real identificado) | 3 | SR 1.5, SR 2.1, 4.3.3.6 |
| ⬜ No implementado (citado pero sin control real) | 1 | CIP-008-6 |
| **Total de filas en las tres tablas (§1+§2+§3)** | **16** | — |

**El hallazgo más importante de esta consolidación:** dos brechas reales
que estaban ocultas por la dispersión de las referencias, visibles solo
al ponerlas todas juntas:

1. **CIP-008-6** (reporte de incidentes) está citado en el docstring de
   `server/compliance.py` como estándar cubierto, pero ningún chequeo
   real lo verifica. Antes de este documento, esa discrepancia entre lo
   que el módulo *dice* cubrir y lo que *efectivamente* verifica no era
   visible sin leer el código fuente completo.
2. **SR 2.1** (control de autorización) tiene cobertura parcial vía
   `compliance.py`, pero el hallazgo de STRIDE sobre `rpi/proxy.py` (sin
   autenticación en sus endpoints principales) es un incumplimiento real
   de esa misma cláusula en un componente específico — conectar ambos
   documentos (STRIDE y este mapeo) muestra que el problema no es
   abstracto, es localizable y corregible en un archivo concreto.

---

## 6. Qué NO cubre este documento — alcance explícito

- No cubre IEC 62443-4-1 (ciclo de vida de desarrollo seguro de
  productos) — ese estándar evalúa el *proceso* de desarrollo, no el
  producto resultante; está fuera del alcance de un mapeo técnico de
  controles.
- No cubre las cláusulas de NERC CIP-002 (clasificación de activos
  BES) ni CIP-003 (controles de gestión de seguridad) — son procesos
  organizacionales que VTR Continuity no implementa ni puede implementar
  como software, son responsabilidad del operador de la planta que
  despliega el sistema.
- No constituye evidencia de auditoría formal — es el mapeo técnico de
  partida; una auditoría real requiere evaluación independiente de un
  auditor certificado, revisión de evidencia operativa además de
  técnica, y entrevistas con personal — ninguna de esas tres cosas las
  puede producir un documento generado a partir del código fuente.
