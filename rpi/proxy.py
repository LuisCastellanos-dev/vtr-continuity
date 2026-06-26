"""
vtr-continuity v0.5.0 — RPi 4 OT Tier
rpi/proxy.py

Proxy HTTP local en el RPi 4.
Recibe eventos desde:
  - Modo A: frontend JS vtr-continuity corriendo en máquina OT (con browser)
  - Modo B: agente Python directo en máquina OT sin browser (agent.py)

El proxy persiste en SQLite y el SyncManager reenvía al servidor central.

Endpoints:
  POST /events          — recibir evento(s) OT — requiere JWT scope "write"
  GET  /health          — estado del proxy y SyncManager — requiere JWT scope "read"
  GET  /stats            — métricas de cola y sincronización — requiere JWT scope "read"
  DELETE /queue         — limpiar cola (solo modo debug) — requiere JWT scope "write"

Autenticación (v0.5.0, ver rpi/proxy_auth.py): todos los endpoints exigen
header `Authorization: Bearer <jwt>` verificado contra
rpi/jwt_verifier.py::RPiJWTVerifier — sin excepción de modo debug. Origen:
docs/VTR-THREAT-001.md S-3/T-3/R-3/D-3/I-3 (ausencia estructural de
autenticación). VTR_DEBUG=true sigue controlando únicamente la
disponibilidad de DELETE /queue, no la autenticación de ningún endpoint.

Variables de entorno relevantes (todas con default seguro para
desarrollo local, deben configurarse explícitamente en producción):
  VTR_JWT_PUBLIC_KEY_PATH  — clave pública RS256 (default: /etc/vtr-continuity/public_key.pem)
  VTR_DB_PATH              — ruta de queue.db (default: /var/lib/vtr-continuity/queue.db)
  VTR_CUSTODY_DB_PATH      — ruta de custody.db (default: /var/lib/vtr-continuity/custody.db).
                              Agregada en v0.5.0 — antes era una ruta fija
                              en SyncConfig sin forma de configurarla sin
                              editar código fuente.

Uso:
  uvicorn rpi.proxy:app --host 0.0.0.0 --port 7700

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from . import proxy_auth
from .jwt_verifier import RPiVerifyResult
from .queue_store import QueueStore, QueuedEvent
from .sync_manager import SyncManager, SyncConfig
from .transport import IPTransport, TransportConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuración desde entorno
# ---------------------------------------------------------------------------

SERVER_URL = os.environ.get("VTR_SERVER_URL", "http://localhost:8000")
API_KEY = os.environ.get("VTR_API_KEY", "")
DB_PATH = os.environ.get("VTR_DB_PATH", "/var/lib/vtr-continuity/queue.db")
CUSTODY_DB_PATH = os.environ.get(
    "VTR_CUSTODY_DB_PATH", "/var/lib/vtr-continuity/custody.db"
)
DEBUG_MODE = os.environ.get("VTR_DEBUG", "false").lower() == "true"
ALLOWED_ORIGINS = os.environ.get("VTR_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
JWT_PUBLIC_KEY_PATH = os.environ.get(
    "VTR_JWT_PUBLIC_KEY_PATH", "/etc/vtr-continuity/public_key.pem"
)

# ---------------------------------------------------------------------------
# Inicialización de servicios (lifespan)
# ---------------------------------------------------------------------------

_store: QueueStore | None = None
_sync: SyncManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store, _sync

    if not API_KEY:
        logger.warning(
            "[proxy] VTR_API_KEY no configurado — el proxy correrá pero no "
            "podrá sincronizar con el servidor central"
        )

    # Falla rápido y explícitamente si la clave pública JWT no existe —
    # mismo principio que RPiJWTVerifier ya documenta ("nunca opera sin
    # clave pública válida"): el proxy no debe arrancar silenciosamente
    # en un estado donde ningún endpoint puede autenticar nada.
    proxy_auth.init_verifier(public_key_path=JWT_PUBLIC_KEY_PATH)

    _store = QueueStore(db_path=DB_PATH)

    transport = IPTransport(
        server_url=SERVER_URL,
        api_key=API_KEY or "no-key",
        config=TransportConfig(timeout_seconds=10.0, max_retries=3),
    )

    _sync = SyncManager(
        transport=transport,
        store=_store,
        config=SyncConfig(
            heartbeat_interval_s=30.0,
            flush_batch_size=50,
            custody_db_path=CUSTODY_DB_PATH,
        ),
    )
    _sync.start()
    logger.info("[proxy] iniciado — server=%s db=%s", SERVER_URL, DB_PATH)

    yield

    if _sync:
        _sync.stop()
    logger.info("[proxy] detenido")


# ---------------------------------------------------------------------------
# App FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VTR Continuity — RPi OT Proxy",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Modelos de request/response
# ---------------------------------------------------------------------------

class EventPayload(BaseModel):
    """Evento individual desde frontend JS o agente Python."""
    event_type: str = Field(..., min_length=1, max_length=64)
    source: str = Field(default="browser", max_length=32)
    idempotency_key: str | None = Field(default=None)
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: float | None = Field(default=None)

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        allowed = {"api_call", "data_sync", "alert", "heartbeat", "agent_event"}
        if v not in allowed:
            raise ValueError(f"event_type '{v}' no válido. Permitidos: {allowed}")
        return v

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        allowed = {"browser", "agent", "modbus", "dnp3", "internal"}
        if v not in allowed:
            raise ValueError(f"source '{v}' no válido. Permitidos: {allowed}")
        return v


class BatchEventPayload(BaseModel):
    """Lote de eventos (el frontend v0.1.0 puede acumular varios offline)."""
    events: list[EventPayload] = Field(..., min_length=1, max_length=100)


class EventResponse(BaseModel):
    accepted: int
    duplicate: int
    rejected: int
    queue_depth: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_store() -> QueueStore:
    if _store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="QueueStore no inicializado",
        )
    return _store


def _get_sync() -> SyncManager:
    if _sync is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SyncManager no inicializado",
        )
    return _sync


def _event_to_queued(evt: EventPayload) -> QueuedEvent:
    key = evt.idempotency_key
    if not key:
        key = str(uuid.uuid4())

    return QueuedEvent(
        idempotency_key=key,
        event_type=evt.event_type,
        payload=evt.data if evt.data is not None else {},
        queued_at=evt.timestamp or time.time(),
        source=evt.source,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/events", response_model=EventResponse, status_code=status.HTTP_202_ACCEPTED)
async def receive_events(
    batch: BatchEventPayload,
    _auth: RPiVerifyResult = Depends(proxy_auth.require_scope("write")),
) -> EventResponse:
    """
    Recibe uno o más eventos OT y los encola en SQLite.

    Usado por:
    - Modo A: frontend JS via fetch() cuando detecta que está en red OT
    - Modo B: agente Python (agent.py) que envía eventos sin browser
    """
    store = _get_store()
    accepted = 0
    duplicate = 0
    rejected = 0

    for evt in batch.events:
        try:
            queued = _event_to_queued(evt)
            row_id = store.enqueue(queued)
            if row_id == -1:
                duplicate += 1
            else:
                accepted += 1
        except (ValueError, TypeError) as exc:
            logger.warning("[proxy] evento rechazado: %s", exc)
            rejected += 1
        except Exception as exc:
            logger.error("[proxy] error inesperado en enqueue: %s", exc)
            rejected += 1

    return EventResponse(
        accepted=accepted,
        duplicate=duplicate,
        rejected=rejected,
        queue_depth=store.depth(),
    )


@app.get("/health")
async def health(
    _auth: RPiVerifyResult = Depends(proxy_auth.require_scope("read")),
) -> dict[str, Any]:
    """
    Estado del proxy. Usado por:
    - Servidor central para verificar conectividad con el RPi
    - SyncManager del servidor para saber si el tier OT está vivo
    - Dashboard Tampico Shield (v0.3.0)
    """
    sync = _get_sync()
    state = sync.state

    return {
        "status": "ok",
        "proxy_version": "0.2.0",
        "sync_status": state.status,
        "queue_depth": state.queue_depth,
        "last_contact_at": state.last_contact_at,
        "consecutive_failures": state.consecutive_failures,
        "transport": sync._transport.transport_type,
        "uptime_since": time.time(),   # el cliente calcula el delta
    }


@app.get("/stats")
async def stats(
    _auth: RPiVerifyResult = Depends(proxy_auth.require_scope("read")),
) -> dict[str, Any]:
    """Métricas detalladas de cola y sincronización."""
    store = _get_store()
    sync = _get_sync()
    state = sync.state

    return {
        "queue": store.stats(),
        "sync": {
            "status": state.status,
            "total_sent": state.total_sent,
            "total_failed": state.total_failed,
            "consecutive_failures": state.consecutive_failures,
            "last_error": state.last_error,
        },
    }


@app.delete("/queue", status_code=status.HTTP_200_OK)
async def clear_queue(
    request: Request,
    _auth: RPiVerifyResult = Depends(proxy_auth.require_scope("write")),
) -> dict[str, Any]:
    """
    Vacía la cola completa.
    Solo disponible en modo DEBUG — nunca exponer en producción OT.
    Requiere JWT scope "write" — sin excepción de modo debug, ver
    rpi/proxy_auth.py.
    """
    if not DEBUG_MODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="DELETE /queue solo disponible con VTR_DEBUG=true",
        )
    store = _get_store()
    deleted = store.clear()
    return {"deleted": deleted}
