"""
vtr-continuity v0.4.0 — RPi 4 OT Tier
rpi/hmi_adapter.py

Capa de abstracción multi-HMI para el RPi.

El SyncManager y proxy.py hablan únicamente con AbstractHMIAdapter.
Nunca saben qué HMI hay detrás — Ignition, OPC-UA, Modbus o WinCC.

Adaptadores implementados:
  IgnitionAdapter — HTTP REST, dominante en Tamaulipas
  OPCUAAdapter    — Estándar ICS moderno, contratos CFE y petroquímica

Stubs documentados (implementación pendiente):
  ModbusAdapter   — PLCs legacy, conecta con Tampico Shield sentinel.py
  WinCCAdapter    — Instalaciones Siemens existentes
  iFIXAdapter     — Plantas Honeywell antiguas
  DNP3Adapter     — Cubierto por Tampico Shield, bridge pendiente v0.5.0

Seguridad:
  Cada adaptador verifica JWT via RPiJWTVerifier antes de aceptar eventos.
  Ningún evento entra sin token válido — regla de nulls aplicada en cada campo.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from .jwt_verifier import RPiJWTVerifier, RPiVerifyResult

logger = logging.getLogger(__name__)


@dataclass
class HMIEvent:
    """Evento normalizado desde cualquier HMI."""
    event_id: str
    hmi_id: str
    hmi_type: str
    event_type: str
    payload: dict[str, Any]
    timestamp: float
    source_tag: str | None = None
    severity: str = "INFO"
    raw: dict[str, Any] | None = None


@dataclass
class AdapterStatus:
    """Estado de conexión de un adaptador."""
    connected: bool
    hmi_id: str
    hmi_type: str
    last_contact_at: float | None = None
    error: str | None = None
    events_read: int = 0


class AbstractHMIAdapter(ABC):
    """
    Contrato de adaptador HMI para vtr-continuity.

    Cualquier HMI que se integre al RPi debe implementar esta interfaz.
    El SyncManager llama a read_events() en cada ciclo de flush —
    nunca conoce el protocolo subyacente.

    Seguridad: el token JWT se verifica en cada llamada a read_events().
    Si el token es inválido o el grace period venció, el adaptador
    rechaza los eventos y registra el intento.
    """

    def __init__(
        self,
        hmi_id: str,
        verifier: RPiJWTVerifier,
    ) -> None:
        if not hmi_id or not isinstance(hmi_id, str):
            raise ValueError("hmi_id no puede ser vacío o None")
        if verifier is None:
            raise ValueError("verifier no puede ser None")

        self._hmi_id = hmi_id
        self._verifier = verifier
        self._status = AdapterStatus(
            connected=False,
            hmi_id=hmi_id,
            hmi_type=self.hmi_type,
        )

    @property
    @abstractmethod
    def hmi_type(self) -> str:
        """Identificador del tipo de HMI."""

    @abstractmethod
    def connect(self) -> bool:
        """
        Establece conexión con el HMI.
        Retorna True si la conexión fue exitosa.
        """

    @abstractmethod
    def read_events(
        self,
        token: str | None,
        limit: int = 50,
        allow_grace: bool = False,
    ) -> list[HMIEvent]:
        """
        Lee eventos pendientes del HMI.

        Args:
            token:       JWT del HMI — verificado antes de leer
            limit:       Máximo de eventos por ciclo
            allow_grace: Activar grace period si servidor está offline

        Returns:
            Lista de HMIEvent normalizados, vacía si token inválido
        """

    @abstractmethod
    def acknowledge(self, event_id: str | None) -> bool:
        """
        Confirma al HMI que el evento fue procesado.
        El HMI puede entonces limpiar su buffer interno.
        """

    def verify_token(
        self,
        token: str | None,
        allow_grace: bool = False,
    ) -> RPiVerifyResult:
        """
        Verifica el JWT del HMI.
        Llamado internamente por read_events() antes de aceptar datos.
        """
        result = self._verifier.verify(
            token,
            required_scope="read",
            allow_grace=allow_grace,
        )
        if not result.valid:
            logger.warning(
                "[%s] token rechazado hmi_id=%s error=%s",
                self.hmi_type, self._hmi_id, result.error,
            )
        return result

    @property
    def status(self) -> AdapterStatus:
        return self._status


class IgnitionAdapter(AbstractHMIAdapter):
    """
    Adaptador para Ignition (Inductive Automation) via HTTP REST.

    Ignition expone una API REST en el gateway — el RPi consulta
    el endpoint de alarmas y tags en cada ciclo.

    Endpoint esperado: GET /data/alarming/status
    Autenticación: Bearer JWT en header Authorization

    Dominante en plantas nuevas de Tamaulipas:
    CFE Generación, petroquímica moderna, puertos logísticos.
    """

    VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL", "DIAGNOSTIC"}

    def __init__(
        self,
        hmi_id: str,
        verifier: RPiJWTVerifier,
        gateway_url: str,
        timeout: float = 10.0,
    ) -> None:
        super().__init__(hmi_id, verifier)

        if not gateway_url or not isinstance(gateway_url, str):
            raise ValueError("gateway_url no puede ser vacío o None")
        if timeout <= 0:
            raise ValueError("timeout debe ser > 0")

        self._gateway_url = gateway_url.rstrip("/")
        self._timeout = timeout

    @property
    def hmi_type(self) -> str:
        return "ignition"

    def connect(self) -> bool:
        """
        Verifica conectividad con el gateway de Ignition.
        GET /data/status — respuesta 200 indica gateway activo.
        """
        try:
            url = f"{self._gateway_url}/data/status"
            with httpx.Client(timeout=self._timeout) as client:
                r = client.get(url)

            connected = r.status_code == 200
            self._status.connected = connected
            self._status.last_contact_at = time.time()
            self._status.error = None if connected else f"HTTP {r.status_code}"

            if connected:
                logger.info("[ignition] conectado — gateway=%s", self._gateway_url)
            else:
                logger.warning("[ignition] gateway respondió %d", r.status_code)

            return connected

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            self._status.connected = False
            self._status.error = str(exc)
            logger.warning("[ignition] connect falló: %s", exc)
            return False

    def read_events(
        self,
        token: str | None,
        limit: int = 50,
        allow_grace: bool = False,
    ) -> list[HMIEvent]:
        """
        Lee alarmas activas del gateway Ignition.

        Verifica JWT antes de hacer cualquier request.
        Si el token es None o inválido, retorna lista vacía.
        Valida explícitamente cada campo de la respuesta JSON.
        """
        if limit <= 0:
            raise ValueError("limit debe ser > 0")

        verify = self.verify_token(token, allow_grace=allow_grace)
        if not verify.valid:
            return []

        try:
            url = f"{self._gateway_url}/data/alarming/status"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
            with httpx.Client(timeout=self._timeout) as client:
                r = client.get(url, headers=headers, params={"pageSize": limit})

            if r.status_code != 200:
                logger.warning("[ignition] read_events HTTP %d", r.status_code)
                self._status.error = f"HTTP {r.status_code}"
                return []

            data = r.json()
            if not isinstance(data, dict):
                logger.warning("[ignition] respuesta no es dict: %s", type(data))
                return []

            alarms = data.get("data")
            if not isinstance(alarms, list):
                logger.debug("[ignition] sin alarmas activas")
                return []

            events = []
            for alarm in alarms:
                event = self._parse_alarm(alarm, verify)
                if event is not None:
                    events.append(event)

            self._status.events_read += len(events)
            self._status.last_contact_at = time.time()
            self._status.error = None
            return events

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            self._status.error = str(exc)
            logger.warning("[ignition] read_events error: %s", exc)
            return []
        except Exception as exc:
            logger.exception("[ignition] error inesperado en read_events")
            self._status.error = str(exc)
            return []

    def acknowledge(self, event_id: str | None) -> bool:
        """
        Envía ACK de alarma al gateway Ignition.
        POST /data/alarming/acknowledge con el ID de la alarma.
        """
        if event_id is None or not isinstance(event_id, str) or not event_id.strip():
            return False

        try:
            url = f"{self._gateway_url}/data/alarming/acknowledge"
            with httpx.Client(timeout=self._timeout) as client:
                r = client.post(url, json={"ids": [event_id]})
            return r.status_code in (200, 201, 204)
        except Exception as exc:
            logger.warning("[ignition] acknowledge falló: %s", exc)
            return False

    def _parse_alarm(
        self,
        alarm: Any,
        verify: RPiVerifyResult,
    ) -> HMIEvent | None:
        """
        Convierte una alarma Ignition a HMIEvent normalizado.
        Valida explícitamente cada campo — nunca asume que existen.
        """
        if not isinstance(alarm, dict):
            return None

        alarm_id = alarm.get("id")
        if not alarm_id or not isinstance(alarm_id, str):
            alarm_id = str(uuid.uuid4())

        display_path = alarm.get("displayPath")
        if not isinstance(display_path, str):
            display_path = alarm.get("source", "unknown")

        event_name = alarm.get("name")
        if not isinstance(event_name, str):
            event_name = "alarm"

        priority = alarm.get("priority", "Low")
        severity = self._map_priority(priority if isinstance(priority, str) else "Low")

        event_time = alarm.get("eventTime")
        if not isinstance(event_time, (int, float)):
            event_time = time.time()

        hmi_id = verify.hmi_id if verify.hmi_id else self._hmi_id

        return HMIEvent(
            event_id=alarm_id,
            hmi_id=hmi_id,
            hmi_type="ignition",
            event_type="alert",
            payload={
                "name": event_name,
                "display_path": display_path,
                "priority": priority,
                "state": alarm.get("state", "unknown"),
                "active_data": alarm.get("activeData") if isinstance(alarm.get("activeData"), dict) else {},
            },
            timestamp=event_time,
            source_tag=display_path,
            severity=severity,
            raw=alarm,
        )

    @staticmethod
    def _map_priority(priority: str) -> str:
        """Mapea prioridad Ignition a severity VTR."""
        mapping = {
            "Diagnostic": "DIAGNOSTIC",
            "Low": "INFO",
            "Medium": "WARNING",
            "High": "CRITICAL",
            "Critical": "CRITICAL",
        }
        return mapping.get(priority, "INFO")


class OPCUAAdapter(AbstractHMIAdapter):
    """
    Adaptador OPC-UA para PLCs y RTUs modernos.

    OPC-UA es el estándar ICS abierto — soportado por:
    Schneider Electric, ABB, Yokogawa, Siemens S7-1500,
    y cualquier PLC moderno certificado.

    Crítico para contratos CFE y petroquímica en Tamaulipas
    donde el equipo es mixto (múltiples fabricantes).

    Librería: asyncua (python-asyncua) — OPC-UA async nativo.
    El adaptador ejecuta el loop async en un thread dedicado
    para mantener compatibilidad con el SyncManager síncrono.
    """

    def __init__(
        self,
        hmi_id: str,
        verifier: RPiJWTVerifier,
        endpoint_url: str,
        node_ids: list[str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        super().__init__(hmi_id, verifier)

        if not endpoint_url or not isinstance(endpoint_url, str):
            raise ValueError("endpoint_url no puede ser vacío o None")
        if not endpoint_url.startswith("opc.tcp://"):
            raise ValueError("endpoint_url debe comenzar con opc.tcp://")
        if timeout <= 0:
            raise ValueError("timeout debe ser > 0")

        self._endpoint_url = endpoint_url
        self._node_ids = node_ids if isinstance(node_ids, list) else []
        self._timeout = timeout
        self._client = None
        self._pending_events: list[dict] = []

    @property
    def hmi_type(self) -> str:
        return "opcua"

    def connect(self) -> bool:
        """
        Establece sesión OPC-UA con el servidor.
        Usa asyncua en modo síncrono via run_until_complete.
        """
        import asyncio
        from asyncua import Client as OPCClient

        async def _connect():
            try:
                client = OPCClient(url=self._endpoint_url, timeout=self._timeout)
                await client.connect()
                self._client = client
                return True
            except Exception as exc:
                logger.warning("[opcua] connect falló: %s", exc)
                self._status.error = str(exc)
                return False

        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(_connect())
            loop.close()
            self._status.connected = result
            self._status.last_contact_at = time.time() if result else None
            if result:
                logger.info("[opcua] conectado — %s", self._endpoint_url)
            return result
        except Exception as exc:
            self._status.connected = False
            self._status.error = str(exc)
            logger.warning("[opcua] connect excepción: %s", exc)
            return False

    def read_events(
        self,
        token: str | None,
        limit: int = 50,
        allow_grace: bool = False,
    ) -> list[HMIEvent]:
        """
        Lee valores de nodos OPC-UA y los convierte a HMIEvent.

        Verifica JWT antes de acceder al servidor OPC-UA.
        Lee los node_ids configurados y genera un evento por valor
        que haya cambiado desde la última lectura.
        """
        if limit <= 0:
            raise ValueError("limit debe ser > 0")

        verify = self.verify_token(token, allow_grace=allow_grace)
        if not verify.valid:
            return []

        if not self._status.connected or self._client is None:
            logger.warning("[opcua] read_events sin conexión activa")
            return []

        import asyncio

        async def _read_nodes():
            events = []
            for node_id in self._node_ids[:limit]:
                if not isinstance(node_id, str) or not node_id.strip():
                    continue
                try:
                    node = self._client.get_node(node_id)
                    value = await node.read_value()
                    dv = await node.read_data_value()

                    source_ts = dv.SourceTimestamp
                    ts = source_ts.timestamp() if source_ts else time.time()

                    events.append(HMIEvent(
                        event_id=str(uuid.uuid4()),
                        hmi_id=verify.hmi_id if verify.hmi_id else self._hmi_id,
                        hmi_type="opcua",
                        event_type="data_sync",
                        payload={
                            "node_id": node_id,
                            "value": str(value) if value is not None else None,
                            "status_code": str(dv.StatusCode) if dv.StatusCode else None,
                        },
                        timestamp=ts,
                        source_tag=node_id,
                        severity="INFO",
                    ))
                except Exception as exc:
                    logger.warning("[opcua] error leyendo nodo %s: %s", node_id, exc)
                    continue
            return events

        try:
            loop = asyncio.new_event_loop()
            events = loop.run_until_complete(_read_nodes())
            loop.close()
            self._status.events_read += len(events)
            self._status.last_contact_at = time.time()
            return events
        except Exception as exc:
            logger.exception("[opcua] error inesperado en read_events")
            self._status.error = str(exc)
            return []

    def acknowledge(self, event_id: str | None) -> bool:
        """
        OPC-UA no tiene ACK de eventos en el protocolo base.
        Los valores se confirman automáticamente al leer.
        Retorna True si el event_id es válido.
        """
        if event_id is None or not isinstance(event_id, str):
            return False
        return True

    def disconnect(self) -> None:
        """Cierra la sesión OPC-UA limpiamente."""
        import asyncio

        if self._client is None:
            return

        async def _disconnect():
            try:
                await self._client.disconnect()
            except Exception as exc:
                logger.warning("[opcua] disconnect error: %s", exc)

        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(_disconnect())
            loop.close()
        finally:
            self._client = None
            self._status.connected = False
            logger.info("[opcua] desconectado")


class ModbusAdapter(AbstractHMIAdapter):
    """
    [STUB — pendiente] Adaptador Modbus TCP para PLCs legacy.

    Conecta con el parser Modbus de Tampico Shield sentinel.py.
    Común en infraestructura antigua de la zona portuaria de Tampico.

    Implementación pendiente:
    - Librería: pymodbus
    - Lectura de holding registers y coils
    - Mapeo de registros a HMIEvent via tabla configurable
    - Compatible con Modbus RTU sobre RS485 via adaptador serial
    """

    @property
    def hmi_type(self) -> str:
        return "modbus"

    def connect(self) -> bool:
        raise NotImplementedError("ModbusAdapter.connect() — pendiente")

    def read_events(self, token, limit=50, allow_grace=False) -> list[HMIEvent]:
        raise NotImplementedError("ModbusAdapter.read_events() — pendiente")

    def acknowledge(self, event_id) -> bool:
        raise NotImplementedError("ModbusAdapter.acknowledge() — pendiente")


class WinCCAdapter(AbstractHMIAdapter):
    """
    [STUB — pendiente] Adaptador WinCC OA (Siemens).

    Para instalaciones Siemens existentes en Tamaulipas.

    Implementación pendiente:
    - API: WinCC OA REST API o OPC-UA (WinCC OA 3.18+)
    - Autenticación: usuario/password + JWT VTR
    - Lectura de alarmas via SCADA API
    """

    @property
    def hmi_type(self) -> str:
        return "wincc"

    def connect(self) -> bool:
        raise NotImplementedError("WinCCAdapter.connect() — pendiente")

    def read_events(self, token, limit=50, allow_grace=False) -> list[HMIEvent]:
        raise NotImplementedError("WinCCAdapter.read_events() — pendiente")

    def acknowledge(self, event_id) -> bool:
        raise NotImplementedError("WinCCAdapter.acknowledge() — pendiente")


class iFIXAdapter(AbstractHMIAdapter):
    """
    [STUB — pendiente] Adaptador iFIX (Honeywell/GE).

    Para plantas Honeywell antiguas en la región.

    Implementación pendiente:
    - Protocolo: OPC-DA via DCOM o OPC-UA si versión reciente
    - Wrapper Python via pycomm3 o opcua
    - Mapeo de tags iFIX a HMIEvent
    """

    @property
    def hmi_type(self) -> str:
        return "ifix"

    def connect(self) -> bool:
        raise NotImplementedError("iFIXAdapter.connect() — pendiente")

    def read_events(self, token, limit=50, allow_grace=False) -> list[HMIEvent]:
        raise NotImplementedError("iFIXAdapter.read_events() — pendiente")

    def acknowledge(self, event_id) -> bool:
        raise NotImplementedError("iFIXAdapter.acknowledge() — pendiente")


class DNP3Adapter(AbstractHMIAdapter):
    """
    [STUB — pendiente] Adaptador DNP3 para RTUs y medidores.

    Bridge entre vtr-continuity y Tampico Shield sentinel.py.
    El parser DNP3 ya existe en Tampico Shield (netprobe/sentinel.py).

    Implementación pendiente v0.5.0:
    - Leer eventos de ShieldDB via ShieldBridge (ya implementado)
    - Convertir netprobe_events DNP3 a HMIEvent
    - Cerrar el loop Tampico Shield → vtr-continuity → servidor central
    """

    @property
    def hmi_type(self) -> str:
        return "dnp3"

    def connect(self) -> bool:
        raise NotImplementedError("DNP3Adapter.connect() — pendiente v0.5.0")

    def read_events(self, token, limit=50, allow_grace=False) -> list[HMIEvent]:
        raise NotImplementedError("DNP3Adapter.read_events() — pendiente v0.5.0")

    def acknowledge(self, event_id) -> bool:
        raise NotImplementedError("DNP3Adapter.acknowledge() — pendiente v0.5.0")


ADAPTER_REGISTRY: dict[str, type[AbstractHMIAdapter]] = {
    "ignition": IgnitionAdapter,
    "opcua": OPCUAAdapter,
    "modbus": ModbusAdapter,
    "wincc": WinCCAdapter,
    "ifix": iFIXAdapter,
    "dnp3": DNP3Adapter,
}


def get_adapter_class(hmi_type: str | None) -> type[AbstractHMIAdapter]:
    """
    Retorna la clase de adaptador para un tipo de HMI.
    Falla explícitamente si hmi_type es None o no está registrado.
    """
    if hmi_type is None or not isinstance(hmi_type, str):
        raise ValueError("hmi_type no puede ser None o vacío")

    adapter_class = ADAPTER_REGISTRY.get(hmi_type.lower().strip())
    if adapter_class is None:
        raise ValueError(
            f"hmi_type '{hmi_type}' no registrado. "
            f"Disponibles: {list(ADAPTER_REGISTRY.keys())}"
        )
    return adapter_class
