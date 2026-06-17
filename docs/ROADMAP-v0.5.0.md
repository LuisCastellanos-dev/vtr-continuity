# Roadmap VTR Continuity v0.5.0 → v0.6.0

> **Última actualización:** 2026-06-03
> **Estado:** Roadmap consolidado, pendiente generación de los 10 entregables

---

## Origen del roadmap

Este roadmap consolida:
- Bloqueantes originales de VTR-SEC-001 (S#1, S#2, S#6, S#8)
- Arquitectura durante v0.5.0 (S#3, S#4, S#7)
- Pre-piloto (S#5)
- Preguntas abiertas (Q-01, Q-02, Q-03)
- 4 decisiones cripto aprobadas (ver DECISIONS-v0.5.0.md)
- 10 omisiones detectadas (O#1 a O#10)

---

## ÉPICA A — Núcleo criptográfico
*Bloqueante DoD v0.5.0*

| ID | Tarea | Origen | Prioridad |
|---|---|---|---|
| A1 | `crypto_layer.py` con primitivas Argon2id/HKDF/Ed25519 (decisión 1B) | S#1 + dec.1 | P0 |
| A2 | `errors.py` — jerarquía de excepciones del dominio (VTR-CRYPTO-003) | feedback | P0 |
| A3 | `rf_config.yaml` sección `crypto:` con profile catalogado (decisión 2D) | S#7 + dec.2 | P0 |
| A4 | Derivación async no-bloqueante en boot del proxy | dec.2 | P0 |
| A5 | Firma Ed25519 obligatoria en `.vtrc` antes de escritura USB | S#6 | P0 |
| A6 | Verificación de firma `.vtrc` en lectura (sneakernet inbound) | S#6 derivado | P0 |

---

## ÉPICA B — Infraestructura PKI
*Bloqueante DoD v0.5.0*

| ID | Tarea | Origen | Prioridad |
|---|---|---|---|
| B1 | Setup CA root offline (USB LUKS + caja fuerte del bench) | dec.4 | P0 |
| B2 | Setup CA intermediate online en bench | dec.4 | P0 |
| B3 | Documento `docs/VTR-PKI-001.md` con esquema y procedimientos | dec.4 + O#10 | P0 |
| B4 | Procedimiento de ceremonia de firma (root → intermediate) | O#2 | P1 |
| B5 | Backup geográficamente distribuido de la CA root | O#2 | P1 |
| B6 | Diseño de M-of-N para acceso a CA root (split de secreto) | O#2 | P2 (v0.6) |
| B7 | Procedimiento de rotación de `device_secret` (18 meses) | O#1 | P1 |
| B8 | Mecanismo de revocación: CRL distribuida vía bundle `.vtrc` | O#3 | P1 |
| B9 | Período de validez de certs alineado con rotación | O#3 | P1 |

---

## ÉPICA C — Provisioning y bench
*Bloqueante DoD v0.5.0*

| ID | Tarea | Origen | Prioridad |
|---|---|---|---|
| C1 | Setup bench air-gapped en el sitio principal | dec.3 | P0 |
| C2 | Script de provisioning `vtr-provision.py` | dec.3 | P0 |
| C3 | `device_registry.vtrdb` cifrado con LUKS | O#4 | P0 |
| C4 | Append-only log con hash chain del registro | dec.3 mitigación | P1 |
| C5 | Backup cifrado off-site del registro | O#4 | P1 |
| C6 | Política de acceso al registro descifrado documentada | O#4 + O#10 | P1 |

---

## ÉPICA D — Resiliencia y validación
*Bloqueante DoD v0.5.0 parcial*

| ID | Tarea | Origen | Prioridad |
|---|---|---|---|
| D1 | `storage_guardian.py` con purga FIFO (umbrales 80%/95%) | S#2 | P0 |
| D2 | Validación agresiva metadata DTN (tamaño, TTL, hop, origen) | S#3 | P0 |
| D3 | ≥15 tests adversariales Jest (frontend) | S#8 | P0 |
| D4 | ≥15 tests adversariales pytest (crypto_layer) | S#8 expandido | P0 |
| D5 | Sesión de fuzzing UART Heltec + LoRa simulado → VTR-FUZ-001 | S#4 | P1 |
| D6 | Site survey RF ≥2 ubicaciones (RSSI/SNR/PER, link budget) | S#5 | P1 |
| D7 | Tests E2E browser ↔ backend (verificación de `.vtrc` en navegador) | O#8 | P1 |
| D8 | STRIDE documentado en `docs/VTR-THREAT-001.md` | O#7 | P1 |

---

## ÉPICA E — Integraciones y preguntas abiertas
*Mixto v0.5.0 / v0.6.0*

| ID | Tarea | Origen | Prioridad |
|---|---|---|---|
| E1 | Decisión arquitectónica Q-01 (detección nodo muerto) documentada | Q-01 | P0 |
| E2 | Decisión arquitectónica Q-02 (RTC reset + replay nonce) documentada | Q-02 | P0 |
| E3 | Decisión arquitectónica Q-03 (interfaz config en campo) documentada | Q-03 | P0 |
| E4 | Especificación de coexistencia browser/backend cripto | O#5 | P1 |
| E5 | Verificación de firma `.vtrc` en `session_guard.js` (frontend) | O#5 + S#6 | P1 |
| E6 | Especificación firmware Heltec: eFuse + Ed25519 (micro-ecc/libsodium) | O#6 | P1 |
| E7 | Diseño de integración con módulo de monitoreo OT existente: registro compartido o federado | O#9 | P2 (v0.6) |
| E8 | Web SOC: visualización de estado de certificados | O#9 | P2 (v0.6) |
| E9 | Mapeo decisiones → cláusulas IEC 62443 / NERC CIP | O#10 | P1 |
| E10 | Política de Gestión de Claves (KMP) escrita y firmada | O#10 | P1 |
| E11 | SOP de provisioning operativo | O#10 | P1 |

---

## Diferido explícitamente a v0.6.0

- Hardware HSM físico (opción de upgrade desde CA en USB)
- Provisioning híbrido 3C (attestation al primer boot)
- M-of-N para acceso a CA root (split de secreto)
- Integración profunda con módulo de monitoreo OT existente (Web SOC con visualización de certs)
- Migración a OP-TEE / TPM 2.0 en hardware compatible

---

## Definition of Done v0.5.0 (actualizado)

| Bloque | Criterio | Nuevo en este DoD |
|---|---|---|
| Tests | ≥56 tests Jest pasando | — |
| Tests | ≥15 tests adversariales pytest (crypto_layer) | ✓ NUEVO |
| Storage | `storage_guardian.py` implementado | — |
| Bundle | `.vtrc` firmado obligatorio | — |
| Bundle | Verificación de firma `.vtrc` en lectura | ✓ NUEVO |
| Config | `rf_config.yaml` parametrizado | — |
| Config | Sección `crypto:` con profile catalogado | ✓ NUEVO |
| Cripto | `crypto_layer.py` con Argon2id + HKDF + Ed25519 | ✓ NUEVO |
| Cripto | Reglas VTR-CRYPTO-001, 002, 003 documentadas | ✓ NUEVO |
| PKI | CA root + intermediate operativas | ✓ NUEVO |
| PKI | `docs/VTR-PKI-001.md` publicado | ✓ NUEVO |
| Provisioning | Bench air-gapped funcional | ✓ NUEVO |
| Provisioning | `device_registry.vtrdb` con append-only log | ✓ NUEVO |
| Preguntas | Q-01/Q-02/Q-03 con decisión documentada | — |
| Documentación | STRIDE en `docs/VTR-THREAT-001.md` | ✓ NUEVO |
| Documentación | Mapeo a IEC 62443 / NERC CIP | ✓ NUEVO |
