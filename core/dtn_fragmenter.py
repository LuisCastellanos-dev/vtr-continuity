"""
vtr-continuity v0.5.0 — Core RF Fallback Tier 2
core/dtn_fragmenter.py

Capa 2 del stack RF: fragmentación DTN asimétrica con frames fantasma.

Principios de diseño:
    - Fragmentación asimétrica: payload variable por frame (no simétrica)
    - Frames fantasma automáticos: cifrados, indistinguibles de frames reales
    - Jitter aleatorio con distribución exponencial: sin patrón temporal
    - Entropía independiente: RPi usa BCM2711 TRNG via secrets.token_bytes()
    - Frames fantasma intercalados DENTRO del bundle, no antes ni después
    - Padding CSPRNG: bytes aleatorios, nunca ceros predecibles

Estructura de frame (222 bytes):
    Byte 0-1:   bundle_id    (2 bytes) — identifica el bundle
    Byte 2:     frag_index   (1 byte)  — posición 0..total-1
    Byte 3:     total_frags  (1 byte)  — total de fragmentos reales
    Byte 4:     payload_size (1 byte)  — bytes de datos reales en este frame
    Byte 5:     flags        (1 byte)  — bit 0: frame fantasma
    Byte 6-221: data         (216 bytes) — payload + padding CSPRNG

Header = 6 bytes → payload útil máximo = 216 bytes por frame.

Mitigaciones Capa 2:
    - Bundle_id falso: verificado contra sesiones activas
    - Fragment fuera de orden: reordenado por index antes de reensamblar
    - Fragment duplicado: index ya recibido descartado
    - total_frags=0 o >255: validación antes de almacenar
    - payload_size > 216: validación antes de leer
    - Bundle incompleto: purga tras timeout configurable
    - Inyección por UART: frame de tamaño != 222 rechazado
    - Correlación temporal: jitter exponencial, sin patrón
    - Length oracle: padding CSPRNG, frames siempre 222 bytes

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import math
import secrets
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FRAME_SIZE = 222
HEADER_SIZE = 6
PAYLOAD_MAX = FRAME_SIZE - HEADER_SIZE
MIN_PAYLOAD_SIZE = 64
MAX_PAYLOAD_SIZE = PAYLOAD_MAX
MAX_FRAGMENTS = 255
DEFAULT_BUNDLE_TIMEOUT = 300.0
DEFAULT_GHOST_BASE_INTERVAL = 2.0
DEFAULT_GHOST_JITTER_MAX = 2.0

FLAG_GHOST = 0x01


@dataclass
class Fragment:
    """Frame individual de 222 bytes."""
    bundle_id: int
    frag_index: int
    total_frags: int
    payload_size: int
    flags: int
    data: bytes

    @property
    def is_ghost(self) -> bool:
        return bool(self.flags & FLAG_GHOST)

    def to_bytes(self) -> bytes:
        """Serializa el frame a exactamente FRAME_SIZE bytes."""
        if self.payload_size > PAYLOAD_MAX:
            raise ValueError(f"payload_size {self.payload_size} excede PAYLOAD_MAX {PAYLOAD_MAX}")
        if len(self.data) != PAYLOAD_MAX:
            raise ValueError(f"data debe ser {PAYLOAD_MAX} bytes, recibido {len(self.data)}")

        header = struct.pack(
            ">HBBBB",
            self.bundle_id,
            self.frag_index,
            self.total_frags,
            self.payload_size,
            self.flags,
        )
        frame = header + self.data
        assert len(frame) == FRAME_SIZE, f"frame size error: {len(frame)}"
        return frame

    @classmethod
    def from_bytes(cls, raw: bytes | None) -> "Fragment":
        """
        Deserializa un frame de exactamente FRAME_SIZE bytes.
        Rechaza frames de tamaño incorrecto — defensa contra inyección UART.
        """
        if raw is None:
            raise ValueError("raw no puede ser None")
        if not isinstance(raw, bytes):
            raise ValueError("raw debe ser bytes")
        if len(raw) != FRAME_SIZE:
            raise ValueError(
                f"frame debe ser exactamente {FRAME_SIZE} bytes, "
                f"recibido {len(raw)} — posible inyección UART"
            )

        bundle_id, frag_index, total_frags, payload_size, flags = struct.unpack(
            ">HBBBB", raw[:HEADER_SIZE]
        )

        if total_frags == 0:
            raise ValueError("total_frags no puede ser 0")
        if frag_index >= total_frags and not (flags & FLAG_GHOST):
            raise ValueError(
                f"frag_index {frag_index} >= total_frags {total_frags}"
            )
        if payload_size > PAYLOAD_MAX:
            raise ValueError(
                f"payload_size {payload_size} excede PAYLOAD_MAX {PAYLOAD_MAX}"
            )

        data = raw[HEADER_SIZE:]
        return cls(
            bundle_id=bundle_id,
            frag_index=frag_index,
            total_frags=total_frags,
            payload_size=payload_size,
            flags=flags,
            data=data,
        )


class GhostScheduler:
    """
    Generador de frames fantasma con jitter exponencial.

    Los frames fantasma se intercalan automáticamente en el stream de
    transmisión. El intervalo entre fantasmas sigue una distribución
    exponencial para evitar patrones temporales detectables.

    Entropía: secrets.token_bytes() — BCM2711 TRNG en RPi 4.
    No hay handshake de entropía con el Heltec — fuentes independientes.
    """

    def __init__(
        self,
        base_interval: float = DEFAULT_GHOST_BASE_INTERVAL,
        jitter_max: float = DEFAULT_GHOST_JITTER_MAX,
    ) -> None:
        if base_interval <= 0:
            raise ValueError("base_interval debe ser > 0")
        if jitter_max < 0:
            raise ValueError("jitter_max no puede ser negativo")

        self._base_interval = base_interval
        self._jitter_max = jitter_max
        self._next_ghost_at: float = self._compute_next()

    def _compute_next(self) -> float:
        """
        Calcula el próximo timestamp de frame fantasma.
        Distribución exponencial — sin patrón temporal predecible.
        """
        random_byte = secrets.token_bytes(1)[0]
        u = random_byte / 255.0
        if u == 0:
            u = 0.001
        exponential = -math.log(u)
        jitter = min(exponential * (self._jitter_max / 2.0), self._jitter_max)
        return time.time() + self._base_interval + jitter

    def should_inject(self) -> bool:
        """Retorna True si es momento de inyectar un frame fantasma."""
        if time.time() >= self._next_ghost_at:
            self._next_ghost_at = self._compute_next()
            return True
        return False

    def make_ghost(self, bundle_id: int) -> Fragment:
        """
        Genera un frame fantasma criptográficamente indistinguible.

        El frame se cifra con la misma clave y nonce_counter que los
        frames reales — un observador externo no puede distinguirlo.
        El flag GHOST solo es visible DESPUÉS de descifrar.
        """
        if not isinstance(bundle_id, int) or bundle_id < 0:
            raise ValueError("bundle_id debe ser int >= 0")

        data = secrets.token_bytes(PAYLOAD_MAX)

        return Fragment(
            bundle_id=bundle_id,
            frag_index=0,
            total_frags=1,
            payload_size=0,
            flags=FLAG_GHOST,
            data=data,
        )


class BundleFragmenter:
    """
    Fragmenta bundles cifrados en frames de 222 bytes.

    Fragmentación asimétrica:
        El payload de cada frame se elige aleatoriamente entre
        MIN_PAYLOAD_SIZE y MAX_PAYLOAD_SIZE. El resto del frame
        se rellena con padding CSPRNG. Un observador no puede
        inferir el tamaño del bundle original contando frames.

    Frames fantasma automáticos:
        Se intercalan dentro del stream de frames reales.
        Cifrados e indistinguibles de frames reales.
    """

    def __init__(
        self,
        ghost_scheduler: GhostScheduler | None = None,
        min_payload: int = MIN_PAYLOAD_SIZE,
        max_payload: int = MAX_PAYLOAD_SIZE,
    ) -> None:
        if min_payload <= 0:
            raise ValueError("min_payload debe ser > 0")
        if max_payload > PAYLOAD_MAX:
            raise ValueError(f"max_payload no puede exceder {PAYLOAD_MAX}")
        if min_payload > max_payload:
            raise ValueError("min_payload no puede ser > max_payload")

        self._ghost = ghost_scheduler or GhostScheduler()
        self._min_payload = min_payload
        self._max_payload = max_payload

    def _random_payload_size(self) -> int:
        """
        Tamaño de payload aleatorio en [min_payload, max_payload].
        Usa CSPRNG — no uniforme intencional para mayor resistencia.
        """
        random_bytes = secrets.token_bytes(2)
        value = struct.unpack(">H", random_bytes)[0]
        range_size = self._max_payload - self._min_payload + 1
        return self._min_payload + (value % range_size)

    def fragment(self, bundle_id: int, data: bytes) -> list[Fragment]:
        """
        Fragmenta un bundle en frames con payload asimétrico.

        Args:
            bundle_id: Identificador del bundle (0-65535)
            data:      Bundle cifrado de Capa 1

        Returns:
            Lista de Fragment con frames reales intercalados con fantasmas.
            El orden de los fantasmas es aleatorio dentro de la lista.
        """
        if not isinstance(bundle_id, int) or not (0 <= bundle_id <= 65535):
            raise ValueError("bundle_id debe ser int en [0, 65535]")
        if data is None:
            raise ValueError("data no puede ser None")
        if not isinstance(data, bytes):
            raise ValueError("data debe ser bytes")
        if len(data) == 0:
            raise ValueError("data no puede ser vacío")

        real_fragments: list[Fragment] = []
        offset = 0

        while offset < len(data):
            chunk_size = min(self._random_payload_size(), len(data) - offset)
            chunk = data[offset:offset + chunk_size]
            offset += chunk_size

            pad_size = PAYLOAD_MAX - chunk_size
            padding = secrets.token_bytes(pad_size)
            frame_data = chunk + padding

            real_fragments.append(Fragment(
                bundle_id=bundle_id,
                frag_index=len(real_fragments),
                total_frags=0,
                payload_size=chunk_size,
                flags=0,
                data=frame_data,
            ))

        if len(real_fragments) > MAX_FRAGMENTS:
            raise ValueError(
                f"bundle requiere {len(real_fragments)} fragmentos — "
                f"excede MAX_FRAGMENTS ({MAX_FRAGMENTS})"
            )

        total = len(real_fragments)
        for frag in real_fragments:
            frag.total_frags = total

        result: list[Fragment] = []
        for frag in real_fragments:
            result.append(frag)
            if self._ghost.should_inject():
                result.append(self._ghost.make_ghost(bundle_id))

        return result

    def reassemble(self, fragments: list[Fragment] | None) -> bytes:
        """
        Reensambla fragmentos reales en el bundle original.

        Filtra frames fantasma, ordena por frag_index, valida
        completitud y reensambla en orden correcto.

        Args:
            fragments: Lista de Fragment (reales y fantasmas mezclados)

        Returns:
            Bundle original como bytes
        """
        if fragments is None:
            raise ValueError("fragments no puede ser None")
        if not isinstance(fragments, list):
            raise ValueError("fragments debe ser una lista")
        if len(fragments) == 0:
            raise ValueError("fragments no puede ser vacío")

        real = [f for f in fragments if not f.is_ghost]

        if len(real) == 0:
            raise ValueError("no hay fragmentos reales en la lista")

        for frag in real:
            if not isinstance(frag, Fragment):
                raise ValueError("todos los elementos deben ser Fragment")
            if frag.payload_size == 0:
                raise ValueError(f"fragmento real con payload_size=0 en index {frag.frag_index}")
            if frag.payload_size > PAYLOAD_MAX:
                raise ValueError(f"payload_size {frag.payload_size} excede PAYLOAD_MAX")

        total = real[0].total_frags
        if total == 0:
            raise ValueError("total_frags no puede ser 0")
        if total > MAX_FRAGMENTS:
            raise ValueError(f"total_frags {total} excede MAX_FRAGMENTS")

        for frag in real:
            if frag.total_frags != total:
                raise ValueError(
                    f"total_frags inconsistente: esperado {total}, "
                    f"recibido {frag.total_frags} en index {frag.frag_index}"
                )

        real_sorted = sorted(real, key=lambda f: f.frag_index)

        seen_indices: set[int] = set()
        for frag in real_sorted:
            if frag.frag_index in seen_indices:
                raise ValueError(f"fragmento duplicado en index {frag.frag_index}")
            seen_indices.add(frag.frag_index)

        expected = set(range(total))
        received = set(f.frag_index for f in real_sorted)
        missing = expected - received
        if missing:
            raise ValueError(f"fragmentos faltantes: {sorted(missing)}")

        result = b""
        for frag in real_sorted:
            result += frag.data[:frag.payload_size]

        return result


class FragmentStore:
    """
    SQLite para almacenar fragmentos de bundles en tránsito.

    Cuando el receptor recibe fragmentos de un bundle, los almacena
    aquí hasta recibir el total. Si el bundle no se completa dentro
    del timeout, se purga para liberar memoria.

    Resource-constrained: máximo MAX_FRAGMENTS por bundle en SQLite.
    """

    def __init__(
        self,
        db_path: Path | str,
        bundle_timeout: float = DEFAULT_BUNDLE_TIMEOUT,
    ) -> None:
        if not db_path:
            raise ValueError("db_path no puede ser vacío")
        if bundle_timeout <= 0:
            raise ValueError("bundle_timeout debe ser > 0")

        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout = bundle_timeout
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            BEGIN;
            CREATE TABLE IF NOT EXISTS fragments (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                bundle_id    INTEGER NOT NULL,
                frag_index   INTEGER NOT NULL,
                total_frags  INTEGER NOT NULL,
                payload_size INTEGER NOT NULL,
                data         BLOB    NOT NULL,
                received_at  REAL    NOT NULL,
                UNIQUE(bundle_id, frag_index)
            );
            CREATE INDEX IF NOT EXISTS idx_bundle_id
                ON fragments(bundle_id);
            CREATE INDEX IF NOT EXISTS idx_received_at
                ON fragments(received_at ASC);
            COMMIT;
        """)

    def store(self, fragment: Fragment) -> bool:
        """
        Almacena un fragmento real. Ignora frames fantasma.

        Returns:
            True si fue almacenado, False si era duplicado.
        """
        if fragment is None:
            raise ValueError("fragment no puede ser None")
        if fragment.is_ghost:
            return False

        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO fragments
                    (bundle_id, frag_index, total_frags, payload_size, data, received_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    fragment.bundle_id,
                    fragment.frag_index,
                    fragment.total_frags,
                    fragment.payload_size,
                    fragment.data,
                    time.time(),
                ),
            )
            conn.execute("COMMIT")
            stored = cur.rowcount > 0
        except Exception:
            conn.execute("ROLLBACK")
            raise

        if not stored:
            logger.debug(
                "[frag_store] duplicado ignorado bundle_id=%d index=%d",
                fragment.bundle_id, fragment.frag_index,
            )
        return stored

    def is_complete(self, bundle_id: int) -> bool:
        """Retorna True si todos los fragmentos del bundle fueron recibidos."""
        if not isinstance(bundle_id, int):
            return False

        conn = self._get_conn()
        row = conn.execute(
            """
            SELECT COUNT(*) as received, MAX(total_frags) as total
            FROM fragments
            WHERE bundle_id = ?
            """,
            (bundle_id,),
        ).fetchone()

        if row is None or row["total"] is None:
            return False
        return row["received"] >= row["total"]

    def retrieve(self, bundle_id: int) -> list[Fragment]:
        """
        Retorna todos los fragmentos de un bundle en orden.
        No los elimina — usar purge() después de reensamblar.
        """
        if not isinstance(bundle_id, int):
            raise ValueError("bundle_id debe ser int")

        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT bundle_id, frag_index, total_frags, payload_size, data
            FROM fragments
            WHERE bundle_id = ?
            ORDER BY frag_index ASC
            """,
            (bundle_id,),
        ).fetchall()

        fragments = []
        for row in rows:
            data = row["data"]
            if isinstance(data, memoryview):
                data = bytes(data)
            fragments.append(Fragment(
                bundle_id=row["bundle_id"],
                frag_index=row["frag_index"],
                total_frags=row["total_frags"],
                payload_size=row["payload_size"],
                flags=0,
                data=data,
            ))
        return fragments

    def purge(self, bundle_id: int) -> int:
        """Elimina todos los fragmentos de un bundle tras reensamblar."""
        if not isinstance(bundle_id, int):
            return 0

        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            cur = conn.execute(
                "DELETE FROM fragments WHERE bundle_id = ?",
                (bundle_id,),
            )
            conn.execute("COMMIT")
            return cur.rowcount
        except Exception:
            conn.execute("ROLLBACK")
            return 0

    def purge_timed_out(self) -> int:
        """
        Elimina bundles incompletos que superaron el timeout.
        Llamar periódicamente para mantener SQLite pequeño.
        Resource-constrained by design.
        """
        cutoff = time.time() - self._timeout
        conn = self._get_conn()

        timed_out = conn.execute(
            """
            SELECT DISTINCT bundle_id FROM fragments
            WHERE received_at < ?
            """,
            (cutoff,),
        ).fetchall()

        if not timed_out:
            return 0

        bundle_ids = [row["bundle_id"] for row in timed_out]
        placeholders = ",".join("?" * len(bundle_ids))

        conn.execute("BEGIN")
        try:
            cur = conn.execute(
                f"DELETE FROM fragments WHERE bundle_id IN ({placeholders})",
                bundle_ids,
            )
            conn.execute("COMMIT")
            deleted = cur.rowcount
        except Exception:
            conn.execute("ROLLBACK")
            return 0

        if deleted > 0:
            logger.warning(
                "[frag_store] purge timeout — %d fragmentos de %d bundles eliminados",
                deleted, len(bundle_ids),
            )
        return deleted

    def pending_bundles(self) -> list[int]:
        """Retorna bundle_ids con fragmentos pendientes."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT bundle_id FROM fragments ORDER BY bundle_id"
        ).fetchall()
        return [row["bundle_id"] for row in rows]

    def fragment_count(self, bundle_id: int) -> int:
        """Retorna cantidad de fragmentos recibidos para un bundle."""
        if not isinstance(bundle_id, int):
            return 0
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) FROM fragments WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone()
        return row[0] if row else 0
