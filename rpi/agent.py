"""
vtr-continuity v0.2.0 — RPi 4 OT Tier
rpi/agent.py

Modo B: agente Python sin browser.
Para infraestructuras críticas donde no hay navegador en la máquina OT.

Fuentes de eventos soportadas:
  --mode stdin    Lee eventos JSON line-delimited desde stdin
  --mode file     Observa un archivo de log y envía nuevas líneas
  --mode socket   Escucha en un socket Unix/TCP para eventos de terceros

El agente envía eventos al proxy local (proxy.py) via HTTP.
Si el proxy no está disponible, encola localmente y reintenta.

Uso:
  python -m rpi.agent --mode stdin --proxy http://localhost:7700
  python -m rpi.agent --mode file --file /var/log/ot/events.jsonl
  python -m rpi.agent --mode socket --host 127.0.0.1 --port 7701

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import argparse
import json
import logging
import select
import socket
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Cliente HTTP hacia el proxy local
# ---------------------------------------------------------------------------

class ProxyClient:
    """
    Cliente HTTP liviano para enviar eventos al proxy local (proxy.py).
    Si el proxy no responde, el agente cae a una cola en memoria
    con reintento exponencial.
    """

    def __init__(self, proxy_url: str, timeout: float = 5.0) -> None:
        if not proxy_url:
            raise ValueError("proxy_url no puede ser vacío")
        self._url = proxy_url.rstrip("/") + "/events"
        self._timeout = timeout
        self._pending: list[dict[str, Any]] = []   # cola en memoria fallback

    def send(self, event: dict[str, Any]) -> bool:
        """
        Envía un evento al proxy. Si falla, encola en memoria.
        Returns True si fue aceptado por el proxy.
        """
        if event is None:
            logger.warning("[agent] intento de enviar evento None")
            return False

        payload = {"events": [event]}

        try:
            with httpx.Client(timeout=self._timeout) as client:
                r = client.post(self._url, json=payload)
            if r.status_code in (200, 201, 202):
                logger.debug("[agent] evento enviado OK — key=%s", event.get("idempotency_key"))
                self._flush_pending()   # si hay pendientes, intentar ahora
                return True
            else:
                logger.warning("[agent] proxy respondió %d — encolando", r.status_code)
                self._pending.append(event)
                return False
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            logger.warning("[agent] proxy no disponible: %s — encolando", exc)
            self._pending.append(event)
            return False

    def _flush_pending(self) -> None:
        """Intenta enviar eventos en cola de memoria al proxy."""
        if not self._pending:
            return

        still_pending = []
        for evt in self._pending:
            try:
                payload = {"events": [evt]}
                with httpx.Client(timeout=self._timeout) as client:
                    r = client.post(self._url, json=payload)
                if r.status_code not in (200, 201, 202):
                    still_pending.append(evt)
            except Exception:
                still_pending.append(evt)

        flushed = len(self._pending) - len(still_pending)
        if flushed > 0:
            logger.info("[agent] flush pendientes — %d enviados, %d restantes", flushed, len(still_pending))
        self._pending = still_pending

    @property
    def pending_count(self) -> int:
        return len(self._pending)


# ---------------------------------------------------------------------------
# Parseo de líneas de evento
# ---------------------------------------------------------------------------

VALID_EVENT_TYPES = {"api_call", "data_sync", "alert", "heartbeat", "agent_event"}
VALID_SOURCES = {"browser", "agent", "modbus", "dnp3", "internal"}


def parse_line(line: str) -> dict[str, Any] | None:
    """
    Parsea una línea JSON a un evento válido para el proxy.

    Formato esperado (mínimo):
        {"event_type": "agent_event", "data": {...}}

    Campos opcionales que se completan si faltan:
        idempotency_key — se genera UUID v4
        source          — default "agent"
        timestamp       — default now
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        logger.warning("[agent] línea JSON inválida: %s — %s", line[:80], exc)
        return None

    if not isinstance(obj, dict):
        logger.warning("[agent] línea no es un objeto JSON: %s", line[:80])
        return None

    event_type = obj.get("event_type")
    if not event_type:
        logger.warning("[agent] evento sin event_type: %s", line[:80])
        return None

    if event_type not in VALID_EVENT_TYPES:
        logger.warning("[agent] event_type '%s' no válido", event_type)
        return None

    source = obj.get("source", "agent")
    if source not in VALID_SOURCES:
        source = "agent"

    return {
        "event_type": event_type,
        "source": source,
        "idempotency_key": obj.get("idempotency_key") or str(uuid.uuid4()),
        "data": obj.get("data") if isinstance(obj.get("data"), dict) else {},
        "timestamp": obj.get("timestamp") or time.time(),
    }


# ---------------------------------------------------------------------------
# Modos de ingesta
# ---------------------------------------------------------------------------

def run_stdin(client: ProxyClient) -> None:
    """Lee eventos JSON line-delimited desde stdin (pipe o redirección)."""
    logger.info("[agent] modo stdin — esperando eventos (Ctrl+C para salir)...")
    try:
        for line in sys.stdin:
            event = parse_line(line)
            if event is not None:
                client.send(event)
    except KeyboardInterrupt:
        logger.info("[agent] interrumpido por usuario")
    finally:
        if client.pending_count > 0:
            logger.warning("[agent] %d eventos sin confirmar al salir", client.pending_count)


def run_file(client: ProxyClient, filepath: str, poll_interval: float = 1.0) -> None:
    """
    Observa un archivo JSONL y envía nuevas líneas al proxy.
    Comportamiento tipo 'tail -f': abre en posición final y lee incrementalmente.
    """
    path = Path(filepath)
    if not path.exists():
        logger.error("[agent] archivo no encontrado: %s", filepath)
        sys.exit(1)

    logger.info("[agent] modo file — observando %s (poll=%.1fs)", filepath, poll_interval)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)   # posicionarse al final

        try:
            while True:
                line = f.readline()
                if line:
                    event = parse_line(line)
                    if event is not None:
                        client.send(event)
                else:
                    time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("[agent] interrumpido por usuario")


def run_socket(client: ProxyClient, host: str, port: int) -> None:
    """
    Escucha en TCP y acepta eventos JSON line-delimited por conexión.
    Útil para que PLCs u otros procesos envíen eventos al agente.
    """
    logger.info("[agent] modo socket — escuchando en %s:%d", host, port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    server.setblocking(False)

    clients: list[socket.socket] = []
    buffers: dict[int, str] = {}

    try:
        while True:
            readable, _, _ = select.select([server] + clients, [], [], 1.0)
            for sock in readable:
                if sock is server:
                    conn, addr = server.accept()
                    conn.setblocking(False)
                    clients.append(conn)
                    buffers[conn.fileno()] = ""
                    logger.info("[agent] nueva conexión: %s", addr)
                else:
                    fd = sock.fileno()
                    try:
                        data = sock.recv(4096)
                        if not data:
                            clients.remove(sock)
                            buffers.pop(fd, None)
                            sock.close()
                            continue
                        buffers[fd] = buffers.get(fd, "") + data.decode("utf-8", errors="replace")
                        while "\n" in buffers[fd]:
                            line, buffers[fd] = buffers[fd].split("\n", 1)
                            event = parse_line(line)
                            if event is not None:
                                client.send(event)
                    except (ConnectionResetError, OSError):
                        clients.remove(sock)
                        buffers.pop(fd, None)
                        sock.close()
    except KeyboardInterrupt:
        logger.info("[agent] interrumpido por usuario")
    finally:
        server.close()
        for c in clients:
            c.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="VTR Continuity — Agente OT sin browser (v0.2.0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Leer eventos desde stdin (pipe desde proceso OT)
  cat eventos.jsonl | python -m rpi.agent --mode stdin

  # Observar archivo de log OT
  python -m rpi.agent --mode file --file /var/log/ot/events.jsonl

  # Escuchar en socket TCP para eventos de PLC
  python -m rpi.agent --mode socket --host 0.0.0.0 --port 7701

  # Proxy personalizado
  python -m rpi.agent --mode stdin --proxy http://192.168.1.100:7700
""",
    )
    parser.add_argument(
        "--mode",
        choices=["stdin", "file", "socket"],
        required=True,
        help="Fuente de eventos",
    )
    parser.add_argument(
        "--proxy",
        default="http://localhost:7700",
        help="URL del proxy local (default: http://localhost:7700)",
    )
    parser.add_argument(
        "--file",
        help="Ruta al archivo JSONL (modo file)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host para modo socket (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7701,
        help="Puerto para modo socket (default: 7701)",
    )
    parser.add_argument(
        "--poll",
        type=float,
        default=1.0,
        help="Intervalo de polling en segundos para modo file (default: 1.0)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout HTTP hacia el proxy en segundos (default: 5.0)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Logging DEBUG",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    client = ProxyClient(proxy_url=args.proxy, timeout=args.timeout)

    if args.mode == "stdin":
        run_stdin(client)
    elif args.mode == "file":
        if not args.file:
            parser.error("--file requerido para modo file")
        run_file(client, args.file, poll_interval=args.poll)
    elif args.mode == "socket":
        run_socket(client, args.host, args.port)


if __name__ == "__main__":
    main()
