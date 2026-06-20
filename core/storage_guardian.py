"""
core/storage_guardian.py — Monitoreo de espacio y purga FIFO por base.

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5) — bloqueante D1 del
roadmap (ROADMAP-v0.5.0.md, origen S#2 de VTR-SEC-001: "alerta antes de
saturar SQLite"). Parámetros ya definidos en config/rf_config.yaml sección
storage.guardian (warn_threshold_percent: 80, purge_threshold_percent: 95,
purge_policy: fifo) — este módulo es el consumidor que faltaba.

DECISIÓN DE DISEÑO — monitoreo por base individual, no disco total:
Las bases SQLite del proyecto tienen roles muy distintos:
    - nonce_counter.db        (NonceCounter, Capa 1)        — contador
      monotónico, una fila por nodo. Crecimiento acotado por el número de
      nodos de la flota, NUNCA por volumen de tráfico.
    - vtrc_counter_seen.db    (CounterVerificationStore)     — mismo perfil
      que nonce_counter.db: una fila por nodo remoto visto.
    - fragments.db            (FragmentStore, Capa 2)        — fragmentos
      DTN en tránsito. Crecimiento NO acotado por diseño — cada bundle sin
      reensamblar añade filas hasta que reasemble() o purge_timed_out() los
      elimine.

Monitorear "espacio de disco total" mezclaría estas tres bajo una sola
métrica y, ante presión de espacio, no hay forma segura de decidir QUÉ
purgar sin esa distinción. Las bases de contador (nonce_counter.db,
vtrc_counter_seen.db) son **no purgables por política de espacio** — su
pérdida rompe la garantía anti-replay que sostiene Q-02
(docs/VTR-ARCH-DECISIONS-001.md). Solo fragments.db tiene una política de
purga FIFO segura, porque sus filas son datos en tránsito, no estado de
seguridad.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from crypto_layer.errors import ConfigError

logger = logging.getLogger(__name__)

# Alineado con config/rf_config.yaml sección storage.guardian.
DEFAULT_WARN_THRESHOLD_PERCENT = 80
DEFAULT_PURGE_THRESHOLD_PERCENT = 95
SUPPORTED_PURGE_POLICIES = frozenset({"fifo"})

# Tablas no purgables por política de espacio — ver docstring del módulo.
# Intentar registrar una de estas como purgable es un error de
# configuración, no una operación silenciosamente ignorada.
NON_PURGEABLE_TABLE_ROLES = frozenset({"counter"})

# Whitelist estricta para cualquier identificador SQL interpolado en una
# query (nombre de tabla, nombre de columna). SQLite no soporta placeholders
# `?` para identificadores —solo para valores— así que esta es la única
# defensa posible contra inyección vía esos campos. Se aplica al construir
# WatchedDatabase (fail-fast en configuración), no en cada query, para que
# un valor inválido nunca llegue a la cadena SQL en primer lugar.
_SQL_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_sql_identifier(value: str, field_name: str) -> None:
    """
    Valida que `value` sea un identificador SQL seguro para interpolar
    directamente en una query (nombre de tabla o columna).

    SQLite no permite parametrizar identificadores con `?` — solo
    valores— así que cualquier nombre de tabla/columna que vaya a
    interpolarse en un string SQL debe pasar por esta whitelist antes.
    Acepta únicamente [A-Za-z_][A-Za-z0-9_]* (sin espacios, comillas,
    punto y coma, ni comentarios SQL) — suficiente para identificadores
    legítimos de este proyecto, e insuficiente para cualquier payload de
    inyección conocido.
    """
    if not isinstance(value, str):
        raise ConfigError(
            f"{field_name} debe ser str, recibido {type(value).__name__}"
        )
    if not _SQL_IDENTIFIER_PATTERN.match(value):
        raise ConfigError(
            f"{field_name} '{value}' no es un identificador SQL seguro — "
            f"solo se permiten letras, números y guion bajo, comenzando "
            f"con letra o guion bajo. Esto NO es una limitación arbitraria: "
            f"SQLite no soporta placeholders ? para nombres de tabla o "
            f"columna, así que esta validación es la única defensa contra "
            f"inyección SQL vía estos campos antes de interpolarlos en la "
            f"query de purga."
        )


class StorageRole(str, Enum):
    """Rol de una base SQLite frente a la política de purga por espacio."""

    COUNTER = "counter"  # nunca purgable por espacio (nonce/replay state)
    TRANSIENT = "transient"  # purgable FIFO (datos en tránsito)


@dataclass
class GuardianStatus:
    """Resultado de una verificación de espacio sobre una base."""

    db_path: Path
    role: StorageRole
    size_bytes: int
    max_size_bytes: int
    percent_used: float
    warn_threshold_percent: int
    purge_threshold_percent: int

    @property
    def is_warning(self) -> bool:
        return self.percent_used >= self.warn_threshold_percent

    @property
    def needs_purge(self) -> bool:
        return self.percent_used >= self.purge_threshold_percent


@dataclass
class WatchedDatabase:
    """
    Configuración de una base SQLite vigilada por el guardian.

    Args:
        db_path: ruta al archivo .db.
        role: StorageRole.COUNTER (nunca se purga por espacio) o
            StorageRole.TRANSIENT (purgable FIFO).
        max_size_bytes: tamaño máximo asumido para calcular percent_used.
            No es un límite impuesto por SQLite — es el techo operativo
            que este guardian usa como referencia (ej. tarjeta SD de la
            Heltec, o partición dedicada del RPi).
        purge_table: nombre de la tabla a purgar FIFO, solo relevante si
            role es TRANSIENT. None para bases COUNTER.
        purge_timestamp_column: columna usada para ordenar FIFO (la fila
            con el valor más antiguo se elimina primero). Solo relevante
            si role es TRANSIENT.
    """

    db_path: Path
    role: StorageRole
    max_size_bytes: int
    purge_table: str | None = None
    purge_timestamp_column: str | None = None

    def __post_init__(self) -> None:
        if self.role == StorageRole.TRANSIENT:
            if not self.purge_table:
                raise ConfigError(
                    "WatchedDatabase con role=TRANSIENT requiere "
                    "purge_table — sin tabla no hay qué purgar"
                )
            if not self.purge_timestamp_column:
                raise ConfigError(
                    "WatchedDatabase con role=TRANSIENT requiere "
                    "purge_timestamp_column — la purga FIFO necesita "
                    "saber qué columna define 'más antiguo'"
                )
            _validate_sql_identifier(self.purge_table, "purge_table")
            _validate_sql_identifier(
                self.purge_timestamp_column, "purge_timestamp_column"
            )


class StorageGuardian:
    """
    Vigila el tamaño de un conjunto de bases SQLite y aplica purga FIFO
    solo sobre las marcadas como StorageRole.TRANSIENT al alcanzar
    purge_threshold_percent.

    No vigila espacio de disco del sistema operativo — vigila el tamaño
    de archivo de cada base SQLite individualmente (ver docstring del
    módulo para la justificación de este diseño).
    """

    def __init__(
        self,
        databases: list[WatchedDatabase],
        warn_threshold_percent: int = DEFAULT_WARN_THRESHOLD_PERCENT,
        purge_threshold_percent: int = DEFAULT_PURGE_THRESHOLD_PERCENT,
        purge_policy: str = "fifo",
    ) -> None:
        if databases is None:
            raise ConfigError("databases no puede ser None")
        if not isinstance(databases, list):
            raise ConfigError(
                f"databases debe ser list, recibido {type(databases).__name__}"
            )
        if len(databases) == 0:
            raise ConfigError("databases no puede ser una lista vacía")
        for i, db in enumerate(databases):
            if not isinstance(db, WatchedDatabase):
                raise ConfigError(
                    f"databases[{i}] debe ser WatchedDatabase, "
                    f"recibido {type(db).__name__}"
                )

        if not isinstance(warn_threshold_percent, int):
            raise ConfigError("warn_threshold_percent debe ser int")
        if not (0 < warn_threshold_percent <= 100):
            raise ConfigError(
                f"warn_threshold_percent debe estar en (0, 100], "
                f"recibido {warn_threshold_percent}"
            )
        if not isinstance(purge_threshold_percent, int):
            raise ConfigError("purge_threshold_percent debe ser int")
        if not (0 < purge_threshold_percent <= 100):
            raise ConfigError(
                f"purge_threshold_percent debe estar en (0, 100], "
                f"recibido {purge_threshold_percent}"
            )
        if purge_threshold_percent < warn_threshold_percent:
            raise ConfigError(
                f"purge_threshold_percent ({purge_threshold_percent}) no "
                f"puede ser menor que warn_threshold_percent "
                f"({warn_threshold_percent}) — la purga debe ocurrir "
                f"después de la alerta, no antes"
            )
        if purge_policy not in SUPPORTED_PURGE_POLICIES:
            raise ConfigError(
                f"purge_policy '{purge_policy}' no soportada — únicamente "
                f"{sorted(SUPPORTED_PURGE_POLICIES)} en v0.5.0 "
                f"(config/rf_config.yaml: storage.guardian.purge_policy)"
            )

        self._databases = databases
        self._warn_threshold_percent = warn_threshold_percent
        self._purge_threshold_percent = purge_threshold_percent
        self._purge_policy = purge_policy

    def check(self, db_path: Path | str) -> GuardianStatus:
        """
        Verifica el estado de espacio de una base vigilada específica.

        Args:
            db_path: ruta de una de las bases registradas en `databases`
                al construir el guardian.

        Returns:
            GuardianStatus con el tamaño actual y si excede los umbrales
            de warning o purga.

        Raises:
            ConfigError: si db_path no corresponde a ninguna base
                registrada — el guardian solo reporta sobre bases que
                conoce explícitamente, nunca sobre rutas arbitrarias.
        """
        watched = self._find_watched(db_path)

        size_bytes = self._file_size(watched.db_path)
        percent_used = (
            (size_bytes / watched.max_size_bytes) * 100
            if watched.max_size_bytes > 0
            else 0.0
        )

        return GuardianStatus(
            db_path=watched.db_path,
            role=watched.role,
            size_bytes=size_bytes,
            max_size_bytes=watched.max_size_bytes,
            percent_used=percent_used,
            warn_threshold_percent=self._warn_threshold_percent,
            purge_threshold_percent=self._purge_threshold_percent,
        )

    def check_all(self) -> list[GuardianStatus]:
        """Verifica el estado de espacio de todas las bases registradas."""
        return [self.check(db.db_path) for db in self._databases]

    def enforce(self, db_path: Path | str) -> int:
        """
        Verifica una base y, si needs_purge es True, ejecuta purga FIFO —
        únicamente si su role es TRANSIENT.

        Si la base es COUNTER y excede el umbral de purga, NO purga —
        registra un error y retorna 0. Una base de contador llena indica
        un problema operativo distinto (flota más grande de lo
        dimensionado, ataque de inflado de registros) que debe escalar a
        intervención humana, no resolverse borrando estado de seguridad
        silenciosamente.

        Args:
            db_path: ruta de una de las bases registradas.

        Returns:
            Número de filas eliminadas. 0 si no se alcanzó el umbral de
            purga, o si la base es COUNTER (nunca se purga
            automáticamente sin importar el umbral).

        Raises:
            ConfigError: si db_path no corresponde a ninguna base
                registrada.
        """
        watched = self._find_watched(db_path)
        status = self.check(db_path)

        if not status.needs_purge:
            return 0

        if watched.role == StorageRole.COUNTER:
            logger.error(
                "[storage_guardian] %s (role=COUNTER) alcanzó %.1f%% — "
                "purga automática DENEGADA por diseño. Esta base contiene "
                "estado anti-replay (NonceCounter / CounterVerificationStore) "
                "— purgarla rompería garantías de seguridad ya validadas. "
                "Requiere intervención operativa (ej. aumentar "
                "max_size_bytes, o investigar crecimiento anómalo).",
                str(watched.db_path),
                status.percent_used,
            )
            return 0

        return self._purge_fifo(watched)

    def enforce_all(self) -> dict[str, int]:
        """
        Ejecuta enforce() sobre todas las bases registradas.

        Returns:
            Diccionario {ruta_db: filas_eliminadas}. Una entrada con
            valor 0 significa "no necesitaba purga" o "es COUNTER y se
            denegó" — para distinguir ambos casos, usar check() primero.
        """
        return {
            str(db.db_path): self.enforce(db.db_path) for db in self._databases
        }

    def _find_watched(self, db_path: Path | str) -> WatchedDatabase:
        if db_path is None:
            raise ConfigError("db_path no puede ser None")
        target = Path(db_path)
        for watched in self._databases:
            if watched.db_path == target:
                return watched
        raise ConfigError(
            f"'{target}' no está registrada en este StorageGuardian — "
            f"bases conocidas: {[str(d.db_path) for d in self._databases]}"
        )

    @staticmethod
    def _file_size(db_path: Path) -> int:
        """
        Tamaño total en bytes: archivo principal .db + sus archivos
        auxiliares -wal y -shm si el journal_mode es WAL (que es el modo
        que ya usan NonceCounter, FragmentStore y CounterVerificationStore
        en todo el proyecto).

        Medir solo el archivo .db principal es engañoso: en modo WAL,
        SQLite acumula los cambios en el archivo -wal hasta el siguiente
        checkpoint automático — ese archivo puede ser órdenes de magnitud
        más grande que el .db principal mientras tanto. Un guardian que
        solo mide el .db reportaría 80KB cuando el uso real de disco es
        varios MB, fallando exactamente en el escenario que existe para
        prevenir (saturar el disco sin que nadie lo note).
        """
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(db_path) + suffix)
            try:
                total += os.path.getsize(candidate)
            except OSError:
                pass  # el archivo auxiliar puede no existir — no es un error
        return total

    def _purge_fifo(self, watched: WatchedDatabase) -> int:
        """
        Elimina las filas más antiguas de watched.purge_table hasta
        estimar que el tamaño vuelve a estar por debajo de
        warn_threshold_percent (no solo de purge_threshold_percent —
        purgar justo hasta el límite de alerta evitaría purgas
        repetidas inmediatas en el próximo bundle recibido).

        DECISIÓN DE DISEÑO — por qué no un loop de "borra un lote, mide
        de nuevo, repite": SQLite con DELETE no reduce el tamaño del
        archivo .db hasta un VACUUM — las páginas liberadas se reutilizan
        internamente pero el archivo no se compacta solo. Un loop que
        depende de que current_size baje entre lotes sin VACUUM
        intermedio nunca termina hasta vaciar la tabla completa o agotar
        el límite de iteraciones — purgando muchas más filas de las
        necesarias. Hacer VACUUM en cada lote sí compactaría, pero
        VACUUM reescribe el archivo completo — costoso en cada lote sobre
        una tarjeta SD de RPi/Heltec, exactamente el tipo de desgaste que
        este guardian existe para evitar, no para producir.

        En su lugar: se calcula bytes-por-fila a partir del tamaño y
        conteo actuales, se estima cuántas filas hace falta eliminar para
        alcanzar el objetivo, se elimina ese número en una sola
        transacción, y se hace UN solo VACUUM al final — no uno por lote.
        """
        target_bytes = int(
            watched.max_size_bytes * (self._warn_threshold_percent / 100)
        )

        conn = sqlite3.connect(str(watched.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

            current_size = self._file_size(watched.db_path)
            row_count = conn.execute(
                f"SELECT COUNT(*) FROM {watched.purge_table}"
            ).fetchone()[0]

            if row_count == 0 or current_size <= target_bytes:
                return 0

            bytes_per_row = current_size / row_count
            excess_bytes = current_size - target_bytes
            rows_to_delete = min(
                row_count, max(1, int(excess_bytes / bytes_per_row) + 1)
            )

            conn.execute("BEGIN")
            try:
                cur = conn.execute(
                    f"""
                    DELETE FROM {watched.purge_table}
                    WHERE rowid IN (
                        SELECT rowid FROM {watched.purge_table}
                        ORDER BY {watched.purge_timestamp_column} ASC
                        LIMIT ?
                    )
                    """,
                    (rows_to_delete,),
                )
                conn.commit()
                deleted = cur.rowcount
            except Exception:
                conn.rollback()
                raise

            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()

        if deleted > 0:
            logger.warning(
                "[storage_guardian] purga FIFO en %s: %d filas eliminadas "
                "(tabla=%s, política=%s, estimado por %.1f bytes/fila)",
                str(watched.db_path),
                deleted,
                watched.purge_table,
                self._purge_policy,
                bytes_per_row,
            )

        return deleted
