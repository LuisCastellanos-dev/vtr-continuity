[![VTR Continuity CI — Python](https://github.com/LuisCastellanos-dev/vtr-continuity/actions/workflows/ci.yml/badge.svg?job=pytest)](https://github.com/LuisCastellanos-dev/vtr-continuity/actions/workflows/ci.yml)
[![VTR Continuity CI — JavaScript](https://github.com/LuisCastellanos-dev/vtr-continuity/actions/workflows/ci.yml/badge.svg?job=jest)](https://github.com/LuisCastellanos-dev/vtr-continuity/actions/workflows/ci.yml)

# VTR Continuity — session_guard.js
Vector Telemetry Research © 2026

## Demo

![VTR Continuity Demo](docs/demo.gif)


## Roadmap

### v0.1.0 — Core (actual)
- [x] SessionGuard — orquestador principal
- [x] StateSnapshot — cifrado AES-GCM en IndexedDB
- [x] OfflineQueue — cola con idempotency keys UUID v4
- [x] HeartbeatMonitor — backoff exponencial
- [x] SyncManager — sincronización FIFO al reconectar
- [x] 41/41 tests — Jest
- [x] Demo interactiva

### v0.2.0 — RPi 4 OT Tier ✅ (implementado — pendiente despliegue en hardware)
- [x] `rpi/transport.py` — AbstractTransport + IPTransport; LoRaTransport stub documentado para v0.5.0 (Heltec LoRa 32 V3, SX1262, 915 MHz)
- [x] `rpi/queue_store.py` — SQLite WAL, thread-local por instancia, idempotency keys, FIFO, sync_log
- [x] `rpi/sync_manager.py` — heartbeat + flush FIFO, backoff exponencial, thread daemon
- [x] `rpi/proxy.py` — FastAPI puerto 7700, Modo A (browser) y Modo B (agentless)
- [x] `rpi/agent.py` — ingesta sin browser: stdin / file (tail-f) / socket TCP
- [x] 51/51 tests — pytest
- [ ] Despliegue fisico en RPi 4 — pendiente adquisicion de hardware

### v0.3.0 — Integración Tampico Shield ✅ (implementado)
- [x] `rpi/shield_bridge.py` — solo lectura ShieldDB, verificación SHA-256 por fila
- [x] Exporta alerts, netprobe_events, baseline_snapshots (outliers entropy>=0.7)
- [x] Idempotente — doble ejecución no duplica eventos
- [x] systemd timer cada 5 min con ProtectSystem=strict
- [x] 41/41 pytest

### v0.4.0 — Enterprise OT ✅ (implementado)
- [x] `core/custody_manager.py` — custodia DTN-inspired RFC 9171, grant→ack→delete
- [x] `rpi/sync_manager.py` — ciclo grant→send→ack→is_safe_to_delete
- [x] `server/auth.py` — JWT RS256, refresh rotation, grace period OT offline
- [x] `rpi/jwt_verifier.py` — verificador lado RPi, solo clave pública
- [x] `rpi/hmi_adapter.py` — Ignition + OPC-UA implementados, Modbus/WinCC/iFIX/DNP3 stubs
- [x] `server/compliance.py` — AuditLog SHA-256, ComplianceChecker NERC CIP / IEC 62443, EvidenceExport
- [x] 342/342 pytest — v0.4.0-final

### v0.5.0 — Fallback Tier 2 RF (en evaluacion)
- [ ] Ruta A: Banda ISM 915 MHz LoRa sin licencia — ESP32+SX1276, desplegable hoy
- [ ] Ruta B: Concesion IFT red privada — VTR opera RF como servicio administrado
- [ ] Serializacion Protobuf+LZ4
- [ ] Cifrado XChaCha20-Poly1305 + firma Ed25519
- [ ] LoRa L1 primario, BLE Mesh corto alcance
- [ ] DTN Bundle Protocol RFC 9171 capa L2
- [ ] UI: boton Abrir Canal Alterno tras 10min OFFLINE
- [ ] Sneakernet .vtrc como fallback extremo


## Filosofía de diseño — Resource-Constrained Architecture

VTR Continuity está diseñado bajo el principio de **resource-constrained design**:
hacer más con menos, con propósito explícito en cada decisión técnica.

Esta no es una limitación — es una ventaja competitiva en entornos OT reales
donde el hardware en campo es un RPi 4, no un rack de servidores, y donde
una red puede estar cortada por horas sin previo aviso.

Cada decisión del stack refleja esa premisa:

| Decisión | Alternativa descartada | Razón |
|---|---|---|
| SQLite WAL | PostgreSQL | Misma garantía ACID, cero footprint de servidor |
| Protobuf + LZ4 | JSON crudo | Payload mínimo para canal LoRa (≤222 bytes/frame) |
| Thread daemon explícito | Framework async pesado | Control total del ciclo de vida y predictibilidad, sin el overhead oculto de un loop de eventos cooperativo |
| DTN Bundle Protocol RFC 9171 | TCP/IP con reconexión simple | Tolerancia real a partición de red, no solo retry |
| AbstractTransport | Implementación única | Intercambiar canal sin reescribir el core |

### Inspiración: NASA Deep Space Network

El protocolo de capa L2 en v0.5.0 (DTN Bundle Protocol RFC 9171) es el mismo
estándar utilizado por NASA/JPL para comunicaciones con la Estación Espacial
Internacional y misiones interplanetarias — diseñado para enlaces con latencia
de minutos, pérdida de paquetes alta, y reconexiones intermitentes.

El AGC (Apollo Guidance Computer) aterrizó en la Luna con 4KB de RAM.
Los ingenieros que lo lograron no tenían recursos de sobra — tenían
claridad de propósito y disciplina de diseño.

VTR aplica esa misma disciplina a redes OT industriales en Tamaulipas:
*arquitectura tolerante a fallas basada en el mismo protocolo DTN de NASA,
adaptada para infraestructura crítica en campo.*


## Seguridad RF — Entropía Independiente por Dispositivo

### Por qué no entropía dual (RPi + Heltec combinados)

Durante el diseño de v0.5.0 se evaluó mezclar la entropía del RPi 4 con
la del Heltec LoRa 32 V3 en un handshake inicial para generar el jitter
de los frames fantasma. Esta opción fue descartada por crear una
dependencia circular crítica:

    Red IP caída → activar canal LoRa → Heltec no responde →
    no hay entropía dual → no se puede transmitir por LoRa

El canal de respaldo fallaría exactamente cuando más se necesita.
Adicionalmente, un Heltec comprometido físicamente revelaría el patrón
de jitter de ambos dispositivos simultáneamente.

### Por qué no QRNG en red (servicios cuánticos externos)

Los servicios QRNG (ANU, IBM Quantum) requieren conectividad a internet —
el mismo recurso que vtr-continuity reemplaza cuando falla. Consultar
una API cuántica para generar jitter revelaría además cuándo el sistema
está a punto de transmitir, introduciendo más vectores de los que mitiga.

### Solución: entropía independiente por dispositivo

Cada dispositivo genera su propia entropía desde su TRNG de hardware local:

| Dispositivo | Fuente de entropía | Mecanismo |
|---|---|---|
| RPi 4 | BCM2711 TRNG | secrets.token_bytes() vía /dev/urandom del kernel |
| Heltec LoRa 32 V3 | ESP32-S3 TRNG | esp_random() nativo del hardware |

Consecuencia de seguridad: comprometer una fuente no revela el patrón
de la otra. Son dos incógnitas independientes para cualquier atacante.
El jitter de los frames fantasma depende de ambas fuentes por separado —
sin handshake, sin dependencia cruzada, sin punto único de falla.

Esta decisión está validada con 63 tests de pentesting en core/tests/test_dtn_fragmenter.py.
