"""
vtr-continuity v0.2.0 — RPi 4 OT Tier
rpi/transport.py

Capa de transporte abstracta.
v0.2.0: IPTransport (HTTP hacia servidor central)
v0.5.0: LoRaTransport (Heltec LoRa 32 V3, SX1262, 915 MHz)

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tipos compartidos
# ---------------------------------------------------------------------------

@dataclass
class TransportResult:
    """Resultado de un intento de envío."""
    success: bool
    status_code: int | None = None
    error: str | None = None
    retries: int = 0
    transport_type: str = "unknown"


@dataclass
class TransportConfig:
    """Configuración base para cualquier transporte."""
    timeout_seconds: float = 10.0
    max_retries: int = 3
    retry_backoff_base: float = 2.0   # segundos, backoff exponencial
    retry_backoff_max: float = 60.0


# ---------------------------------------------------------------------------
# Interfaz abstracta
# ---------------------------------------------------------------------------

class AbstractTransport(ABC):
    """
    Contrato de transporte para vtr-continuity.

    Cualquier implementación (IP, LoRa, BLE Mesh, sneakernet) debe
    respetar esta interfaz. El SyncManager llama únicamente a send()
    sin conocer el transporte subyacente.

    v0.5.0 LoRa hook:
        class LoRaTransport(AbstractTransport):
            def send(self, payload: dict[str, Any]) -> TransportResult:
                # serializar con Protobuf+LZ4
                # cifrar con XChaCha20-Poly1305 + Ed25519
                # transmitir por SX1262 a 915 MHz
                ...
    """

    def __init__(self, config: TransportConfig | None = None) -> None:
        self.config = config or TransportConfig()

    @abstractmethod
    def send(self, payload: dict[str, Any]) -> TransportResult:
        """
        Envía un payload al destino del transporte.

        Args:
            payload: Diccionario serializable a JSON con los eventos
                     a entregar. Debe incluir 'idempotency_key'.

        Returns:
            TransportResult con resultado del intento.
        """

    @abstractmethod
    def health_check(self) -> bool:
        """
        Verifica si el transporte está disponible.
        Usado por HeartbeatMonitor para decidir flush vs. enqueue.
        """

    @property
    @abstractmethod
    def transport_type(self) -> str:
        """Identificador del transporte para logs y métricas."""

    # ------------------------------------------------------------------
    # Lógica de reintento compartida — no sobreescribir salvo necesidad
    # ------------------------------------------------------------------

    def send_with_retry(self, payload: dict[str, Any]) -> TransportResult:
        """
        Llama a send() con backoff exponencial hasta max_retries.
        Los transportes sin retries nativos (LoRa DTN) pueden
        sobreescribir este método.
        """
        last_result: TransportResult | None = None

        for attempt in range(self.config.max_retries + 1):
            last_result = self.send(payload)

            if last_result.success:
                last_result.retries = attempt
                return last_result

            if attempt < self.config.max_retries:
                wait = min(
                    self.config.retry_backoff_base ** attempt,
                    self.config.retry_backoff_max,
                )
                logger.warning(
                    "[%s] send falló (attempt %d/%d), reintento en %.1fs — %s",
                    self.transport_type,
                    attempt + 1,
                    self.config.max_retries,
                    wait,
                    last_result.error,
                )
                time.sleep(wait)

        if last_result is not None:
            last_result.retries = self.config.max_retries
        return last_result or TransportResult(
            success=False, error="max_retries agotados", transport_type=self.transport_type
        )


# ---------------------------------------------------------------------------
# IPTransport — v0.2.0, canal primario
# ---------------------------------------------------------------------------

class IPTransport(AbstractTransport):
    """
    Transporte HTTP hacia el servidor central VTR.

    Usa httpx con timeout configurable. En entornos OT donde el RPi
    actúa como gateway, este es el único canal disponible cuando la
    red IP está disponible.

    Cuando la red IP falla → el SyncManager encola en SQLite y espera
    a que health_check() regrese True antes de hacer flush.
    """

    def __init__(
        self,
        server_url: str,
        api_key: str,
        config: TransportConfig | None = None,
    ) -> None:
        super().__init__(config)

        if not server_url:
            raise ValueError("server_url no puede ser vacío")
        if not api_key:
            raise ValueError("api_key no puede ser vacío")

        self._server_url = server_url.rstrip("/")
        self._api_key = api_key
        self._headers = {
            "Content-Type": "application/json",
            "X-VTR-API-Key": self._api_key,
        }

    @property
    def transport_type(self) -> str:
        return "ip_http"

    def health_check(self) -> bool:
        """GET /health — espera 200 dentro del timeout."""
        try:
            url = f"{self._server_url}/health"
            with httpx.Client(timeout=self.config.timeout_seconds) as client:
                r = client.get(url, headers=self._headers)
            return r.status_code == 200
        except Exception as exc:
            logger.debug("[ip_http] health_check falló: %s", exc)
            return False

    def send(self, payload: dict[str, Any]) -> TransportResult:
        """POST /api/v1/events con el payload como JSON."""
        if payload is None:
            return TransportResult(
                success=False,
                error="payload es None",
                transport_type=self.transport_type,
            )

        # Validar idempotency_key presente
        if not payload.get("idempotency_key"):
            logger.warning("[ip_http] payload sin idempotency_key — riesgo de duplicados")

        url = f"{self._server_url}/api/v1/events"

        try:
            with httpx.Client(timeout=self.config.timeout_seconds) as client:
                r = client.post(url, json=payload, headers=self._headers)

            success = r.status_code in (200, 201, 202)
            return TransportResult(
                success=success,
                status_code=r.status_code,
                error=None if success else f"HTTP {r.status_code}: {r.text[:200]}",
                transport_type=self.transport_type,
            )

        except httpx.TimeoutException as exc:
            return TransportResult(
                success=False,
                error=f"timeout ({self.config.timeout_seconds}s): {exc}",
                transport_type=self.transport_type,
            )
        except httpx.RequestError as exc:
            return TransportResult(
                success=False,
                error=f"request error: {exc}",
                transport_type=self.transport_type,
            )
        except Exception as exc:
            logger.exception("[ip_http] error inesperado en send()")
            return TransportResult(
                success=False,
                error=f"unexpected: {exc}",
                transport_type=self.transport_type,
            )


# ---------------------------------------------------------------------------
# LoRaTransport stub — v0.5.0 placeholder documentado
# ---------------------------------------------------------------------------

class LoRaTransport(AbstractTransport):
    """
    [STUB — v0.5.0] Transporte LoRa 915 MHz via Heltec LoRa 32 V3 (SX1262).

    Este stub existe para:
    1. Documentar la interfaz que implementará v0.5.0
    2. Permitir tests de integración con mock desde ahora
    3. Forzar que el SyncManager sea agnóstico al transporte

    Implementación pendiente:
    - Serialización: Protobuf + LZ4 (payload ≤ 222 bytes por frame)
    - Cifrado: XChaCha20-Poly1305 + Ed25519 por paquete
    - L1: LoRa SF7-SF12, BW 125 kHz, 915 MHz ISM MX (sin licencia)
    - L2: DTN Bundle Protocol RFC 9171 para tolerancia a partición
    - Hardware: ESP32-S3 + SX1262, serial UART desde RPi 4
    - Fallback BLE Mesh: distancias < 1.4 km entre nodos VTR
    - UI trigger: botón "Abrir Canal Alterno" tras 10 min OFFLINE
    - Extremo: sneakernet .vtrc si LoRa también falla
    """

    def __init__(self, serial_port: str = "/dev/ttyUSB0") -> None:
        super().__init__()
        self._serial_port = serial_port
        logger.warning(
            "[lora] LoRaTransport es un stub — v0.5.0 pendiente. "
            "Puerto configurado: %s",
            self._serial_port,
        )

    @property
    def transport_type(self) -> str:
        return "lora_915mhz"

    def health_check(self) -> bool:
        # v0.5.0: ping al módulo Heltec por UART y verificar ACK
        raise NotImplementedError("LoRaTransport.health_check() — pendiente v0.5.0")

    def send(self, payload: dict[str, Any]) -> TransportResult:
        # v0.5.0: serializar → cifrar → fragmentar → transmitir → ACK
        raise NotImplementedError("LoRaTransport.send() — pendiente v0.5.0")
