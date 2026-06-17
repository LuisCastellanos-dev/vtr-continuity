# VTR Continuity v0.5.0 — Handoff Document

> **Propósito:** Documento de continuidad para retomar el proyecto en otra máquina
> sin perder contexto. Lee este archivo primero, después los específicos.
>
> **Fecha del snapshot:** 2026-06-03
> **Versión objetivo:** v0.5.0 (Fallback Tier 2 RF)
> **Repositorio:** `github.com/LuisCastellanos-dev/vtr-continuity`
> **Rama de trabajo sugerida:** `feature/crypto-layer-v0.5.0`

---

## 🎯 Estado del proyecto en este punto

### Lo que está hecho (v0.1.0 — shippeado)
- Módulo browser-native `session_guard.js`
- 41 tests Jest pasando
- Componentes: SessionGuard, CryptoLayer (AES-GCM Web Crypto), StateSnapshot (IndexedDB), OfflineQueue (UUID v4), HeartbeatMonitor, SyncManager

### Lo que está pendiente (v0.5.0 — en curso)
Stack RF + criptográfico para Fallback Tier 2:
- Protobuf + LZ4 (serialización)
- XChaCha20-Poly1305 + Ed25519 (criptografía)
- LoRa 915 MHz (transporte L1 primario)
- BLE 5.0 Mesh (corto alcance)
- DTN Bundle Protocol RFC 9171 (L2)
- Sneakernet `.vtrc` (fallback extremo)

### Hardware ya comprado
- 2× Heltec WiFi LoRa 32 V3 (vía AliExpress)
- RPi 4 para proxy DMZ
- Por confirmar: HSM para CA root (diferido a v0.6)

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

## ✅ Decisiones técnicas tomadas (con pro/cons documentado)

Ver `docs/DECISIONS-v0.5.0.md` para el análisis completo. Resumen:

| # | Decisión | Elegido | Por qué |
|---|---|---|---|
| 1 | Modos de derivación | **1B** — `derive_device_key` + `derive_operator_key` separados | Capability separation + disponibilidad |
| 2 | Profile Argon2id | **2D** con default `desktop` (64 MiB, 3 it) + async | OWASP 2024 sin sacrificar boot time |
| 3 | `device_secret` | **3A** — Bench Tampico air-gapped (3C en v0.6) | Auditable y manejable a tu escala |
| 4 | Firma provisioning | **4C** — CA dos niveles, root offline + intermediate online | Trust anchor sin HSM en v0.5.0 |

---

## 🆕 Cuatro reglas de criptografía permanentes

Quedan agregadas a las reglas de desarrollo de VTR Continuity:

- **VTR-CRYPTO-001:** Nunca SHA-256 puro sobre secretos de baja entropía. Argon2id para derivación desde passphrase/hwid; HKDF-SHA256 para expansión; Ed25519 para integridad de bundles.
- **VTR-CRYPTO-002:** El número de serie del RPi NO es salt criptográfico. Salt real proviene de `/etc/vtr/device_secret` (32 bytes random generados en bench, partición read-only firmada por CA). **Estado: diseño pendiente, aún no implementado** — confirmado explícitamente el 2026-06-16, no asumir su existencia en ningún código.
- **VTR-CRYPTO-003:** Validación defensiva ANTES de cualquier operación criptográfica. Inputs `None`, bytes vacíos, longitudes incorrectas, o tipos no esperados deben lanzar excepciones específicas del dominio (`InvalidPassphraseError`, etc.) antes de que `cryptography` los toque.
- **VTR-CRYPTO-004** *(nueva, 2026-06-16):* Todo Heltec WiFi LoRa 32 V3 debe salir del bench con Secure Boot V2 + Flash Encryption (modo Release) + hardening de eFuse (JTAG/USB-OTG/descarga manual deshabilitados) antes de desplegarse en campo. Verificado contra documentación oficial de Espressif — el ESP32-S3 soporta esto nativamente sin hardware adicional. Incluye orden obligatorio de quemado de eFuses por conflicto de legibilidad entre la llave de Secure Boot y la de Flash Encryption.

**Librerías fijadas (con justificación verificada, no por preferencia):**
- Ed25519 + XChaCha20-Poly1305 → **PyNaCl** (libsodium) ≥1.6.2 (post CVE-2025-69277)
- Argon2id + HKDF-SHA256 → **cryptography** (pyca) ≥45.0 (post CVE-2026-26007)
- Revisión de CVEs de ambas cada trimestre natural; parche crítico fuera de ciclo en ≤72h

Documento completo: `docs/VTR-CRYPTO-001.md` — **generado y aprobado el 2026-06-16.**

---

## 🔍 Omisiones detectadas (10 puntos)

Al consolidar el roadmap, detecté 10 omisiones que ahora forman parte del backlog:

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
| O#9 | Coordinación con Tampico Shield (registro + Web SOC) | E7, E8 |
| O#10 | Documentación auditable para IEC 62443 / NERC CIP | E9, E10, E11 |

---

## 📦 Las 10 propuestas pendientes de generar

Cuando estés listo para generar el código y la documentación, las 10 entregables son:

| # | Archivo | Cubre |
|---|---|---|
| 1 | `docs/VTR-CRYPTO-001.md` | Reglas cripto consolidadas |
| 2 | `docs/VTR-PKI-001.md` | Esquema PKI dos niveles |
| 3 | `crypto_layer/errors.py` | Jerarquía de excepciones |
| 4 | `crypto_layer/__init__.py` | API pública |
| 5 | `crypto_layer/argon2_derive.py` | Derivación con profile + async |
| 6 | `crypto_layer/hkdf_expand.py` | Expansión de subclaves |
| 7 | `crypto_layer/ed25519_sign.py` | Firma/verificación de `.vtrc` |
| 8 | `config/rf_config.yaml` | Sección `crypto:` |
| 9 | `tests/test_crypto_layer.py` | Tests felices + ≥15 adversariales |
| 10 | `docs/DOD-v0.5.0.md` | Definition of Done actualizado |

**Estado:** roadmap aprobado, falta confirmar y generar código.

---

## 📞 Para retomar en otra máquina

### Prompt sugerido para Claude
```
Voy a retomar el proyecto VTR Continuity v0.5.0. Adjunto los archivos del
handoff. Por favor:
1. Lee HANDOFF.md primero para tener el contexto completo.
2. Lee docs/ROADMAP-v0.5.0.md y docs/DECISIONS-v0.5.0.md.
3. Confirma que tienes claras las 4 decisiones aprobadas y las 3 reglas
   VTR-CRYPTO-001/002/003.
4. Estamos listos para generar las 10 propuestas. Comienza con #1
   (docs/VTR-CRYPTO-001.md) y avanza secuencialmente.
```

### Checklist al retomar
- [ ] He leído HANDOFF.md
- [ ] He revisado el roadmap completo
- [ ] He revisado las decisiones técnicas
- [ ] He clonado el repo `vtr-continuity` en la nueva máquina
- [ ] He creado la rama `feature/crypto-layer-v0.5.0`
- [ ] Tengo Python 3.11+ y `cryptography>=42` instalado
- [ ] Tengo acceso al bench de Tampico (para épica C)

---

## 🔑 Referencias y estándares aplicables

- **IEC 62443-3-3** (System Security Requirements)
  - SR 1.1, 1.5, 1.8, 2.1 cubiertos por las decisiones cripto
- **IEC 62443-4-2** (Component Security Requirements)
  - CR 1.5 (autenticación de dispositivos) cubierto por 3A+4C
- **NERC CIP** (aplicable a CFE / sector eléctrico)
- **NIST SP 800-82 Rev 3** (Guide to OT Security)
- **OWASP Password Hashing Cheat Sheet 2024** (parámetros Argon2id)
- **RFC 8032** Ed25519
- **RFC 5869** HKDF
- **RFC 9171** DTN Bundle Protocol v7

---

## 🧠 Aprendizajes de esta sesión

Lo que cristalicé en esta sesión y debe permanecer en memoria:

1. **"Más seguro" ≠ "más restrictivo"** en OT. La indisponibilidad del canal alterno
   en una crisis es exactamente el escenario que VTR Continuity existe para resolver.
   Criterio: minimizar el riesgo TOTAL del sistema (CIA balanceado), no solo el cripto.

2. **SHA-256 puro NO tiene salt.** Las rainbow tables solo amenazan inputs de baja
   entropía. Para passwords/passphrases/hwid → Argon2id (memory-hard). Para
   expansión desde claves de alta entropía → HKDF.

3. **Capability separation > monolítico.** Dos métodos (`device_key` / `operator_key`)
   con contratos claros son más seguros y más testeables que un método único con
   parámetro opcional.

4. **El número de serie del hardware NUNCA es salt criptográfico.** Es público,
   predecible. Usar como `info` field en HKDF (binding al hardware), nunca como salt.

5. **Async > síncrono en boot.** Derivación de claves en thread aparte = proxy
   arriba en <2s + clave disponible en ~200ms más, sin bloquear el inicio.
