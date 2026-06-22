"""
core/liveness.py — Detección de nodo muerto vs. aislado (Q-01).

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5) — implementa la
decisión documentada en docs/VTR-ARCH-DECISIONS-001.md Q-01: heartbeat
pasivo inferido de la progresión de NonceCounter, sin mensaje de
protocolo dedicado.

CORRECCIÓN respecto al texto original de Q-01 en
VTR-ARCH-DECISIONS-001.md: ese documento afirma que "GhostScheduler ya
inyecta tráfico fantasma periódico — un nodo vivo genera frames fantasma
aunque no tenga datos reales, así que su counter avanza igual". Al
construir este módulo se verificó el código real de
core/dtn_fragmenter.py y esa afirmación es INCORRECTA:
BundleFragmenter.fragment() solo invoca
GhostScheduler.should_inject()/make_ghost() DENTRO del flujo de
fragmentar un bundle real ya existente — make_ghost(bundle_id) requiere
un bundle_id real como parámetro. No existe ninguna ruta de código donde
el ghost traffic se dispare de forma autónoma sin que ya haya tráfico
real en curso.

Consecuencia honesta para este módulo: un nodo que genuinamente no tiene
NADA que transmitir (ni real ni ghost, porque no hay bundle real que
dispare ghost) no avanza su counter, y por lo tanto se verá idéntico a un
nodo apagado o aislado por jamming — exactamente el problema que Q-01
pregunta cómo resolver, no algo ya resuelto por GhostScheduler. Esta
limitación se documenta explícitamente en vez de asumir una garantía que
el código no cumple. Ver §3 de este docstring para el tratamiento.

Decisión de diseño (la parte de Q-01 que SÍ se sostiene con el código
real): liveness se infiere de la progresión de NonceCounter
(core/crypto_transport.py) — específicamente de la columna `updated_at`
de la tabla `nonce_counter`, que ya se actualiza en cada llamada a
next_nonce(), sin necesitar ninguna columna ni tabla nueva. No se agrega
ningún mensaje de heartbeat dedicado — eso introduciría un patrón
temporal predecible, justo lo que GhostScheduler existe para evitar en
el tráfico real.

Estado nuevo: SUSPECTED_DOWN, nunca DOWN — nodo apagado y nodo aislado
por jamming activo son indistinguibles desde el observador remoto
(mismo síntoma: silencio). El sistema notifica, no decide unilateralmente
entre ambos casos.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from crypto_layer.errors import ConfigError

logger = logging.getLogger(__name__)

# Alineado con core/crypto_transport.py — misma base de datos, mismo
# nombre de tabla. Este módulo LEE esa tabla, nunca la modifica
# (separación de responsabilidad: NonceCounter genera/avanza el
# counter, LivenessTracker solo lo consulta).
DEFAULT_COUNTER_DB = Path("/var/lib/vtr-continuity/nonce_counter.db")

# Default razonable documentado como punto de partida, no como valor
# validado en campo — el survey RF (docs/VTR-SURVEY-001.md) y el uso
# real en piloto deben ajustar este número por tipo de nodo.
DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 900


class LivenessState(str, Enum):
    """
    Estado de liveness de un nodo, inferido sin mensaje dedicado.

    UNKNOWN: nunca se vio counter alguno de este nodo — no hay base
        para inferir nada todavía. Distinto de ALIVE (que requiere al
        menos una observación) y distinto de SUSPECTED_DOWN (que
        requiere haber visto progresión y luego perderla).
    ALIVE: el counter avanzó dentro de la ventana de tolerancia.
    SUSPECTED_DOWN: el counter no avanzó dentro de la ventana — NO se
        afirma que el nodo esté apagado, solo que no hay evidencia
        reciente de actividad. Ver docstring del módulo: esto puede
        significar nodo apagado, nodo aislado por jamming, O nodo vivo
        sin nada que transmitir (limitación conocida, no resuelta por
        GhostScheduler en el estado actual del código).
    """

    UNKNOWN = "UNKNOWN"
    ALIVE = "ALIVE"
    SUSPECTED_DOWN = "SUSPECTED_DOWN"


@dataclass
class LivenessStatus:
    """Resultado de una consulta de liveness para un nodo específico."""

    node_id: bytes
    state: LivenessState
    last_counter: int
    last_updated_at: float | None
    seconds_since_update: float | None
    heartbeat_timeout_seconds: int


def _validate_node_id(node_id: bytes) -> None:
    if node_id is None:
        raise ConfigError("node_id no puede ser None")
    if not isinstance(node_id, bytes):
        raise ConfigError(
            f"node_id debe ser bytes, recibido {type(node_id).__name__}"
        )
    if len(node_id) == 0:
        raise ConfigError("node_id no puede ser vacío")


class LivenessTracker:
    """
    Consulta el estado de liveness de nodos a partir de la tabla
    `nonce_counter` ya persistida por core.crypto_transport.NonceCounter.

    Este tracker es deliberadamente de solo lectura sobre esa tabla —
    no la crea, no la modifica, no le agrega columnas. Si la tabla no
    existe todavía (ningún NonceCounter se ha inicializado en esa ruta
    de DB), todas las consultas devuelven LivenessState.UNKNOWN en vez
    de fallar, porque "nunca vi a este nodo" es un estado legítimo, no
    un error.
    """

    def __init__(
        self,
        db_path: Path | str = DEFAULT_COUNTER_DB,
        heartbeat_timeout_seconds: int = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
    ) -> None:
        if not db_path:
            raise ConfigError("db_path no puede ser vacío")
        if not isinstance(heartbeat_timeout_seconds, int) or isinstance(
            heartbeat_timeout_seconds, bool
        ):
            raise ConfigError(
                f"heartbeat_timeout_seconds debe ser int, recibido "
                f"{type(heartbeat_timeout_seconds).__name__}"
            )
        if heartbeat_timeout_seconds <= 0:
            raise ConfigError(
                f"heartbeat_timeout_seconds debe ser > 0, recibido "
                f"{heartbeat_timeout_seconds}"
            )

        self._db_path = Path(db_path)
        self._heartbeat_timeout_seconds = heartbeat_timeout_seconds

    def _table_exists(self, conn: sqlite3.Connection) -> bool:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='nonce_counter'"
        ).fetchone()
        return row is not None

    def check(self, node_id: bytes, now: float | None = None) -> LivenessStatus:
        """
        Consulta el estado de liveness de un nodo específico.

        Args:
            node_id: identificador del nodo (mismo bytes que
                NonceCounter usa internamente — este método hace
                node_id.hex() para buscar en la tabla, igual que
                NonceCounter._get_conn() ya hace).
            now: timestamp de referencia para el cálculo de
                "tiempo transcurrido". Si no se especifica, usa
                time.time(). Parametrizado explícitamente para que los
                tests puedan ser deterministas sin depender del reloj
                real — no para uso operativo normal.

        Returns:
            LivenessStatus con el estado inferido. Nunca lanza excepción
            por "nodo no encontrado" — eso es LivenessState.UNKNOWN, un
            resultado válido, no un error.

        Raises:
            ConfigError: si node_id es inválido (None, no bytes, vacío).
        """
        _validate_node_id(node_id)
        if now is None:
            now = time.time()

        if not self._db_path.exists():
            return LivenessStatus(
                node_id=node_id,
                state=LivenessState.UNKNOWN,
                last_counter=0,
                last_updated_at=None,
                seconds_since_update=None,
                heartbeat_timeout_seconds=self._heartbeat_timeout_seconds,
            )

        conn = sqlite3.connect(str(self._db_path))
        try:
            if not self._table_exists(conn):
                return LivenessStatus(
                    node_id=node_id,
                    state=LivenessState.UNKNOWN,
                    last_counter=0,
                    last_updated_at=None,
                    seconds_since_update=None,
                    heartbeat_timeout_seconds=self._heartbeat_timeout_seconds,
                )

            row = conn.execute(
                "SELECT counter, updated_at FROM nonce_counter WHERE node_id_hex = ?",
                (node_id.hex(),),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return LivenessStatus(
                node_id=node_id,
                state=LivenessState.UNKNOWN,
                last_counter=0,
                last_updated_at=None,
                seconds_since_update=None,
                heartbeat_timeout_seconds=self._heartbeat_timeout_seconds,
            )

        counter, updated_at = row
        elapsed = now - updated_at

        state = (
            LivenessState.ALIVE
            if elapsed <= self._heartbeat_timeout_seconds
            else LivenessState.SUSPECTED_DOWN
        )

        if state == LivenessState.SUSPECTED_DOWN:
            logger.warning(
                "[liveness] node_id=%s SUSPECTED_DOWN — sin actividad hace "
                "%.0fs (umbral %ds). No implica nodo apagado: puede ser "
                "jamming activo, o nodo vivo sin tráfico real que dispare "
                "ghost traffic (ver limitación documentada en el docstring "
                "de este módulo).",
                node_id.hex(),
                elapsed,
                self._heartbeat_timeout_seconds,
            )

        return LivenessStatus(
            node_id=node_id,
            state=state,
            last_counter=counter,
            last_updated_at=updated_at,
            seconds_since_update=elapsed,
            heartbeat_timeout_seconds=self._heartbeat_timeout_seconds,
        )

    def check_all(
        self, node_ids: list[bytes], now: float | None = None
    ) -> list[LivenessStatus]:
        """Consulta liveness de varios nodos. Conveniencia sobre check()."""
        if node_ids is None:
            raise ConfigError("node_ids no puede ser None")
        if not isinstance(node_ids, list):
            raise ConfigError(
                f"node_ids debe ser list, recibido {type(node_ids).__name__}"
            )
        return [self.check(nid, now=now) for nid in node_ids]
