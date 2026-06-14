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

### v0.3.0 — Integracion VTR (planificado)
- [ ] Integracion nativa con Tampico Shield alerts
- [ ] Export de eventos de sesion a storage/db.py
- [ ] Dashboard en Web SOC de Tampico Shield

### v0.4.0 — Enterprise OT (planificado)
- [ ] Soporte multi-HMI (Ignition, WinCC OA, iFIX WebSpace)
- [ ] Autenticacion JWT con refresh token rotation
- [ ] Cifrado end-to-end entre HMI y RPi 4 tier
- [ ] Auditoria de sesiones para cumplimiento NERC CIP / IEC 62443

### v0.5.0 — Fallback Tier 2 RF (en evaluacion)
- [ ] Ruta A: Banda ISM 915 MHz LoRa sin licencia — ESP32+SX1276, desplegable hoy
- [ ] Ruta B: Concesion IFT red privada — VTR opera RF como servicio administrado
- [ ] Serializacion Protobuf+LZ4
- [ ] Cifrado XChaCha20-Poly1305 + firma Ed25519
- [ ] LoRa L1 primario, BLE Mesh corto alcance
- [ ] DTN Bundle Protocol RFC 9171 capa L2
- [ ] UI: boton Abrir Canal Alterno tras 10min OFFLINE
- [ ] Sneakernet .vtrc como fallback extremo
