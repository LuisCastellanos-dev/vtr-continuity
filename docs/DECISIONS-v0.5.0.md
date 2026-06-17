# Decisiones técnicas v0.5.0 — Pro/Cons y rationale

> Documento de las 4 decisiones criptográficas aprobadas el 2026-06-03 con
> el pro/cons completo de cada alternativa y la justificación de la elegida.

---

## Premisa de criterio

> En infraestructura crítica (OT/ICS), **"más seguro" = el camino que minimiza
> el riesgo total del sistema**, no solo el criptográfico. Una configuración
> cripto teóricamente impecable que rompe la disponibilidad durante un
> incidente es **menos segura** que una buena con disponibilidad robusta,
> porque la indisponibilidad del canal alterno cuando lo necesitas es
> exactamente el escenario que VTR Continuity existe para resolver.

Cada decisión balancea **confidencialidad, integridad y disponibilidad** —
los tres ejes de IEC 62443.

---

## Decisión 1 — Modos de derivación de clave

### Opción 1A: Solo `derive_operator_key` (passphrase siempre obligatoria)

**Pros:**
- Modelo de amenaza simple: sin operador presente, no hay clave
- Imposible montar un servicio "fantasma" comprometido sin que un humano lo note
- Cumple "Multi-Factor" de IEC 62443 SL-2 trivialmente

**Contras:**
- Bloquea v0.2.0 (proxy DMZ siempre arriba) — necesita reiniciar el modelo
- Si el operador no está disponible durante un incidente, el canal alterno no se abre → falla disponibilidad
- Obliga a almacenar la passphrase en algún sitio para reinicios automáticos (TPM, vault) → mueve el problema, no lo elimina

### Opción 1B: Dos métodos diferenciados (`derive_device_key` + `derive_operator_key`) ✅ ELEGIDA

**Pros:**
- Cada flujo tiene su contrato claro y no-ambiguo (filosofía "illegal states unrepresentable")
- Servicios unattended arrancan sin intervención humana
- Compatible con v0.2.0 (proxy automático) y v0.5.0 (sesión humana)
- Tests adversariales más simples (cada función tiene precondiciones definidas)

**Contras:**
- Más superficie de API que mantener y testear
- Hay que diseñar bien *qué puede hacer* `device_key` vs `operator_key` (capability separation)
- Si el atacante tiene el dispositivo + `device_secret`, obtiene `device_key` sin passphrase

### Opción 1C: Único método con `passphrase: Optional[bytes] = None`

**Pros:**
- API mínima — una sola función
- Flexible

**Contras:**
- Rompe la regla "make illegal states unrepresentable"
- Cada llamada necesita `if passphrase is None` esparcido por el código
- Tests adversariales tienen que cubrir todas las combinaciones de None/no-None
- Históricamente, las APIs cripto con parámetros opcionales producen vulnerabilidades por uso incorrecto

### Justificación de 1B

1. **No sacrifica disponibilidad** del proxy DMZ — crítico en v0.2.0
2. **Capabilities separation**: `device_key` puede operar el transporte LoRa y firmar bundles `.vtrc` rutinarios, pero **no** puede desbloquear datos cifrados con `operator_key` (snapshots de sesión sensibles, llaves de cifrado de canal extremo, sneakernet)
3. **Tests más rigurosos**: cada función con contrato claro, sin combinatoria
4. La regla "illegal states unrepresentable" reduce bugs reales (ver historial de OpenSSL)

**Riesgo residual aceptado:** atacante con acceso físico al RPi + extracción del `device_secret` puede operar como `device_key`. Mitigación en v0.6: integrar con TPM 2.0 / OP-TEE.

---

## Decisión 2 — Profile de Argon2id por defecto

### Opción 2A: `embedded` (memory=32 MiB, iterations=3)

**Pros:**
- ~80-100 ms en RPi 4 — boot rápido
- Funciona en Heltec V3 si alguna vez deriváramos ahí
- No bloquea hilo principal durante recuperación tras corte

**Contras:**
- Menor costo para atacante con GPU
- OWASP recomienda 64 MiB mínimo para nuevas aplicaciones

### Opción 2B: `desktop` (memory=64 MiB, iterations=3)

**Pros:**
- Cumple recomendación OWASP 2024 al pie de la letra
- Mejor margen contra ataques con farms de GPU/ASIC futuras

**Contras:**
- 150-200 ms de derivación → si bloquea boot del proxy DMZ, problema operativo
- Más memoria reservada durante derivación

### Opción 2C: `hardened` (memory=128 MiB, iterations=4)

**Pros:**
- Margen muy amplio incluso contra atacantes con presupuesto estatal

**Contras:**
- 300-500 ms en RPi 4 — bloquea boot perceptiblemente
- Boicotea la disponibilidad durante recuperación de incidentes
- Sin justificación de modelo de amenaza para CFE/PEMEX/petroquímica en este rango

### Opción 2D: Profile parametrizable por entorno, no hardcoded ✅ ELEGIDA (con default 2B + async)

**Pros:**
- Define el perfil en `rf_config.yaml` según deployment
- Permite escalado futuro sin tocar código

**Contras:**
- Operador puede configurar mal (riesgo de poner `embedded` en producción crítica)
- Necesita validación al boot: si profile fuera de catálogo, fallar

### Justificación de 2D + default desktop + derivación async

1. **Disponibilidad preservada**: derivación en thread aparte (no bloquea boot) elimina el contra principal de `desktop`
2. **Cumple OWASP 2024** por defecto
3. **Parametrizable**: si en v0.6+ migras a hardware más potente o el modelo de amenaza sube (contrato SEDENA), subes a `hardened` con un cambio de YAML, no de código
4. **Validación estricta del profile en boot**: catálogo cerrado (`embedded | desktop | hardened`), cualquier otro valor falla en `crypto_layer.init()`

**Implementación en `rf_config.yaml`:**
```yaml
crypto:
  argon2id_profile: desktop    # uno de: embedded | desktop | hardened
```

---

## Decisión 3 — Generación del `device_secret`

### Opción 3A: Provisioning en bench principal ✅ ELEGIDA para v0.5.0

**Pros:**
- Clave generada en máquina aislada, nunca toca red
- Auditable: registro firmado de qué clave fue a qué dispositivo
- Permite firma por CA VTR del paquete completo
- Modelo estándar en hardware HSM / TPM industrial

**Contras:**
- Operativa: cada dispositivo necesita pase por bench físico
- Si el bench se compromete, todas las claves emitidas quedan en riesgo
- Logística: cliente en Veracruz, dispositivo viaja con secreto preinstalado
- Inventario de claves a custodiar

### Opción 3B: First-boot self-provisioning (RPi genera su propia clave)

**Pros:**
- Cero logística de claves entre el bench y el sitio de despliegue
- Cada clave nace y muere en el dispositivo
- Más simple operativamente

**Contras:**
- RNG del RPi al boot tiene entropía limitada hasta que el kernel acumule jitter
- Imposible verificar que el dispositivo es genuino sin un trust anchor externo
- Imposible recuperar el dispositivo si se borra accidentalmente

### Opción 3C: Híbrido — bench provee "seed firmado" + first-boot deriva ✅ ELEGIDA para v0.6

**Pros:**
- Bench mantiene el trust anchor (firma de CA) pero no conoce la clave final
- Si el bench se compromete, no expone las claves derivadas (solo el seed firmado)
- Permite verificar autenticidad del dispositivo desde el SOC
- Modelo similar al de Apple "Activation Lock" o secure boot moderno

**Contras:**
- Más complejo: dos pasos en lugar de uno
- Necesita protocolo de "attestation" al primer boot
- El equipo de provisioning necesita más entrenamiento

### Justificación de 3A para v0.5.0

1. Suficientemente seguro para tu escala actual (despliegues piloto en el sector industrial objetivo)
2. Logística manejable: despliegues pocos y de alto valor
3. Auditabilidad: cumple IEC 62443-4-2 CR 1.5
4. Recuperación posible: bench tiene registro y puede reaprovisionar

**Mitigaciones para reducir el contra principal:**
- Bench air-gapped (sin red, ni Wi-Fi/BT desactivados por hardware)
- Registro firmado por CA VTR, almacenado en `device_registry.vtrdb` con backup off-site cifrado
- Rotación del `device_secret` cada 18 meses
- Logging append-only con hash chain

---

## Decisión 4 — Firma del provisioning por CA VTR

### Opción 4A: CA VTR completa desde v0.5.0

**Pros:**
- Trust anchor desde el principio
- Cumple plenamente IEC 62443-3-3 SR 1.8 (PKI)
- Permite revocar dispositivos comprometidos

**Contras:**
- Costo de arranque: CA root, custodia, procedimientos de revocación
- Para CA root real necesitas HSM (~$2-5K USD) o procedimientos manuales muy estrictos
- Sobrecarga operativa si tienes pocos dispositivos
- Si pierdes la clave CA root, pierdes la confianza de toda la flota

### Opción 4B: Sin CA, solo firma directa

**Pros:**
- Más simple operativamente

**Contras:**
- No tienes mecanismo de revocación claro
- No escala
- Si la clave de provisioning se compromete, toda la flota queda en riesgo
- No cumple SR 1.8 estricto

### Opción 4C: CA de dos niveles — Root + Intermediate ✅ ELEGIDA

**Pros:**
- Root puede vivir offline en caja fuerte (alta seguridad)
- Intermediate firma los certificados de dispositivo (operativa diaria)
- Si la intermediate se compromete, root la revoca sin colapsar la flota
- Estándar industrial (Let's Encrypt, DigiCert, etc.)

**Contras:**
- Setup inicial más complejo
- Necesita procedimientos claros de rotación de la intermediate

### Opción 4D: Diferido — TODO en v0.5.0-rc2

**Pros:**
- No bloquea shipping de v0.5.0
- Permite recolectar requisitos reales antes

**Contras:**
- Deuda técnica explícita en zona crítica
- Riesgo de que la deuda se quede más allá de rc2
- El protocolo que diseñes después podría no encajar con dispositivos ya provisionados

### Justificación de 4C con root offline + HSM diferido a v0.6

1. Trust anchor desde el principio: evitas el "lock-in" de la deuda técnica de 4D
2. Root offline manual viable sin HSM en tu escala actual: clave root en USB cifrado con LUKS, USB en caja fuerte física, solo se conecta para firmar/rotar la intermediate (1-2 veces por año)
3. Intermediate online maneja la operación diaria del bench
4. Cumple SR 1.8 de IEC 62443-3-3 con margen
5. HSM como roadmap a v0.6 cuando el volumen lo justifique
6. No bloquea v0.5.0: setup inicial es ~1 día

**Estructura:**
```
VTR-Root-CA (offline, USB cifrado LUKS, caja fuerte del bench)
   └── VTR-Provisioning-Intermediate (online en bench principal)
          ├── device-001.vtr.local
          ├── device-002.vtr.local
          └── ...
```

---

## Por qué este conjunto es coherentemente "lo más seguro"

Las cuatro decisiones no son independientes — están entretejidas:

- **1B + 3A + 4C** forman un *trust chain* completo desde la CA root hasta cada llave en operación. Cualquier llave puede ser auditada hasta su origen y revocada.

- **2D + derivación async** garantiza que las decisiones de seguridad **no degraden disponibilidad**, el atributo más vulnerable en OT.

- **Capability separation (1B)** + **provisioning trazable (3A)** + **PKI con revocación (4C)** = cumplimiento sólido de IEC 62443-3-3 SR 1.1, 1.5, 1.8 y 2.1.

- Ninguna decisión introduce **deuda técnica de seguridad** (todas son evolutivas hacia v0.6, no necesitan rediseño).

- **Costo operativo realista** para la escala actual: 1 día de setup PKI + ~5 minutos por dispositivo en bench.
