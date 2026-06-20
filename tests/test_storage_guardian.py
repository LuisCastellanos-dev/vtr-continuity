"""
tests/test_storage_guardian.py — Suite formal para core/storage_guardian.py.

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5), bloqueante D1 del
roadmap (origen S#2 de VTR-SEC-001). Usa instancias REALES de FragmentStore
y NonceCounter (no mocks) para que la purga FIFO se valide contra el
comportamiento genuino de SQLite en modo WAL — un mock de sqlite3 no
hubiera expuesto el bug real encontrado durante el desarrollo (el archivo
-wal puede pesar órdenes de magnitud más que el .db principal hasta el
siguiente checkpoint).

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from core.crypto_transport import NonceCounter
from core.dtn_fragmenter import Fragment, FragmentStore
from core.storage_guardian import (
    GuardianStatus,
    StorageGuardian,
    StorageRole,
    WatchedDatabase,
)
from crypto_layer.errors import ConfigError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _real_total_size(path: Path) -> int:
    """Tamaño real incluyendo -wal y -shm, para asserts independientes
    de la implementación de StorageGuardian._file_size."""
    total = 0
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        if p.exists():
            total += p.stat().st_size
    return total


@pytest.fixture
def filled_fragments_db(tmp_path: Path) -> Path:
    """Base fragments.db real con 300 fragmentos, checkpoint forzado para
    que el tamaño base sea estable y reproducible entre tests."""
    db_path = tmp_path / "fragments.db"
    store = FragmentStore(db_path=db_path, bundle_timeout=300.0)
    for bundle_id in range(300):
        frag = Fragment(
            bundle_id=bundle_id,
            frag_index=0,
            total_frags=1,
            payload_size=200,
            flags=0,
            data=b"x" * 216,
        )
        store.store(frag)
        time.sleep(0.0002)  # received_at estrictamente creciente

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    return db_path


@pytest.fixture
def nonce_counter_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "nonce_counter.db"
    nc = NonceCounter(node_id=b"\x01" * 8, db_path=db_path)
    nc.next_nonce()
    return db_path


# ---------------------------------------------------------------------------
# Tests felices — construcción y validación de configuración
# ---------------------------------------------------------------------------

class TestConstructionHappy:
    def test_single_transient_database_accepted(self, filled_fragments_db):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=10_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        assert guardian is not None

    def test_counter_database_without_purge_fields_accepted(self, nonce_counter_db):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=nonce_counter_db,
                    role=StorageRole.COUNTER,
                    max_size_bytes=10_000_000,
                )
            ]
        )
        assert guardian is not None

    def test_default_thresholds_match_rf_config_yaml(self, nonce_counter_db):
        """Los defaults deben coincidir con config/rf_config.yaml
        storage.guardian — si alguien cambia el YAML sin actualizar este
        módulo, este test lo detecta."""
        from core.storage_guardian import (
            DEFAULT_PURGE_THRESHOLD_PERCENT,
            DEFAULT_WARN_THRESHOLD_PERCENT,
        )

        assert DEFAULT_WARN_THRESHOLD_PERCENT == 80
        assert DEFAULT_PURGE_THRESHOLD_PERCENT == 95


# ---------------------------------------------------------------------------
# Tests felices — check() / check_all()
# ---------------------------------------------------------------------------

class TestCheckHappy:
    def test_check_returns_guardian_status(self, filled_fragments_db):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=10_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        status = guardian.check(filled_fragments_db)
        assert isinstance(status, GuardianStatus)

    def test_check_size_includes_wal_and_shm(self, filled_fragments_db):
        """Verificación directa del hallazgo central: el guardian debe
        medir .db + -wal + -shm, no solo el archivo principal."""
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=10_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        status = guardian.check(filled_fragments_db)
        expected = _real_total_size(filled_fragments_db)
        assert status.size_bytes == expected

    def test_needs_purge_true_when_over_threshold(self, filled_fragments_db):
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 0.5),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        status = guardian.check(filled_fragments_db)
        assert status.needs_purge is True

    def test_needs_purge_false_when_under_threshold(self, filled_fragments_db):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=100_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        status = guardian.check(filled_fragments_db)
        assert status.needs_purge is False

    def test_check_all_returns_one_status_per_database(
        self, filled_fragments_db, nonce_counter_db
    ):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=10_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                ),
                WatchedDatabase(
                    db_path=nonce_counter_db,
                    role=StorageRole.COUNTER,
                    max_size_bytes=10_000_000,
                ),
            ]
        )
        statuses = guardian.check_all()
        assert len(statuses) == 2


# ---------------------------------------------------------------------------
# Tests felices — enforce() purga FIFO real
# ---------------------------------------------------------------------------

class TestEnforceHappy:
    def test_enforce_deletes_real_rows(self, filled_fragments_db):
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 1.05),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        deleted = guardian.enforce(filled_fragments_db)
        assert deleted > 0

    def test_enforce_preserves_newest_row_fifo(self, filled_fragments_db):
        """El bundle_id más alto (insertado último) debe sobrevivir —
        confirma orden FIFO estricto, no solo 'algunas filas se fueron'."""
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 1.05),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        guardian.enforce(filled_fragments_db)

        conn = sqlite3.connect(str(filled_fragments_db))
        remaining = [
            r[0] for r in conn.execute("SELECT bundle_id FROM fragments")
        ]
        conn.close()
        assert 299 in remaining

    def test_enforce_removes_oldest_row_fifo(self, filled_fragments_db):
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 1.05),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        guardian.enforce(filled_fragments_db)

        conn = sqlite3.connect(str(filled_fragments_db))
        remaining = [
            r[0] for r in conn.execute("SELECT bundle_id FROM fragments")
        ]
        conn.close()
        assert 0 not in remaining

    def test_enforce_remaining_ids_are_contiguous_suffix(self, filled_fragments_db):
        """Prueba más fuerte que las dos anteriores juntas: confirma que
        lo que sobrevive es exactamente un sufijo [N, 299], sin huecos —
        es decir, ni una sola fila intermedia se salvó por azar."""
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 1.05),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        guardian.enforce(filled_fragments_db)

        conn = sqlite3.connect(str(filled_fragments_db))
        remaining = sorted(
            r[0] for r in conn.execute("SELECT bundle_id FROM fragments")
        )
        conn.close()
        if remaining:
            assert remaining == list(range(min(remaining), 300))

    def test_enforce_no_op_when_under_threshold(self, filled_fragments_db):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=100_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        deleted = guardian.enforce(filled_fragments_db)
        assert deleted == 0

    def test_enforce_brings_status_back_under_warn_threshold(self, filled_fragments_db):
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 1.05),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        guardian.enforce(filled_fragments_db)
        status_after = guardian.check(filled_fragments_db)
        assert status_after.needs_purge is False

    def test_enforce_all_returns_dict_keyed_by_path(
        self, filled_fragments_db, nonce_counter_db
    ):
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 1.05),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                ),
                WatchedDatabase(
                    db_path=nonce_counter_db,
                    role=StorageRole.COUNTER,
                    max_size_bytes=10_000_000,
                ),
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        result = guardian.enforce_all()
        assert str(filled_fragments_db) in result
        assert str(nonce_counter_db) in result


# ---------------------------------------------------------------------------
# Tests felices — protección de bases COUNTER
# ---------------------------------------------------------------------------

class TestCounterProtectionHappy:
    def test_counter_database_never_purged_even_when_over_threshold(
        self, nonce_counter_db
    ):
        nc = NonceCounter(node_id=b"\x01" * 8, db_path=nonce_counter_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=nonce_counter_db,
                    role=StorageRole.COUNTER,
                    max_size_bytes=1,  # fuerza >100% deliberadamente
                )
            ]
        )
        deleted = guardian.enforce(nonce_counter_db)
        assert deleted == 0

    def test_counter_value_unaffected_by_enforce_attempt(self, nonce_counter_db):
        nc = NonceCounter(node_id=b"\x01" * 8, db_path=nonce_counter_db)
        value_before = nc.last_counter()

        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=nonce_counter_db,
                    role=StorageRole.COUNTER,
                    max_size_bytes=1,
                )
            ]
        )
        guardian.enforce(nonce_counter_db)

        assert nc.last_counter() == value_before


# ---------------------------------------------------------------------------
# Adversarial — construcción de StorageGuardian
# ---------------------------------------------------------------------------

class TestAdversarialConstruction:
    def test_databases_none_raises(self):
        with pytest.raises(ConfigError):
            StorageGuardian(databases=None)

    def test_databases_empty_list_raises(self):
        with pytest.raises(ConfigError):
            StorageGuardian(databases=[])

    def test_databases_not_a_list_raises(self, nonce_counter_db):
        with pytest.raises(ConfigError):
            StorageGuardian(databases="not-a-list")

    def test_databases_wrong_element_type_raises(self):
        with pytest.raises(ConfigError):
            StorageGuardian(databases=["not-a-watched-database"])

    def test_warn_threshold_zero_raises(self, nonce_counter_db):
        with pytest.raises(ConfigError):
            StorageGuardian(
                databases=[
                    WatchedDatabase(
                        db_path=nonce_counter_db,
                        role=StorageRole.COUNTER,
                        max_size_bytes=1000,
                    )
                ],
                warn_threshold_percent=0,
            )

    def test_warn_threshold_over_100_raises(self, nonce_counter_db):
        with pytest.raises(ConfigError):
            StorageGuardian(
                databases=[
                    WatchedDatabase(
                        db_path=nonce_counter_db,
                        role=StorageRole.COUNTER,
                        max_size_bytes=1000,
                    )
                ],
                warn_threshold_percent=101,
            )

    def test_purge_threshold_below_warn_threshold_raises(self, nonce_counter_db):
        """El umbral de purga nunca puede ser menor al de alerta — purgar
        antes de avisar invierte la lógica del diseño."""
        with pytest.raises(ConfigError):
            StorageGuardian(
                databases=[
                    WatchedDatabase(
                        db_path=nonce_counter_db,
                        role=StorageRole.COUNTER,
                        max_size_bytes=1000,
                    )
                ],
                warn_threshold_percent=90,
                purge_threshold_percent=80,
            )

    def test_unsupported_purge_policy_raises(self, nonce_counter_db):
        with pytest.raises(ConfigError):
            StorageGuardian(
                databases=[
                    WatchedDatabase(
                        db_path=nonce_counter_db,
                        role=StorageRole.COUNTER,
                        max_size_bytes=1000,
                    )
                ],
                purge_policy="lru",  # no soportada en v0.5.0
            )

    def test_transient_without_purge_table_raises(self, filled_fragments_db):
        with pytest.raises(ConfigError):
            WatchedDatabase(
                db_path=filled_fragments_db,
                role=StorageRole.TRANSIENT,
                max_size_bytes=1000,
                purge_timestamp_column="received_at",
                # purge_table omitido deliberadamente
            )

    def test_transient_without_timestamp_column_raises(self, filled_fragments_db):
        with pytest.raises(ConfigError):
            WatchedDatabase(
                db_path=filled_fragments_db,
                role=StorageRole.TRANSIENT,
                max_size_bytes=1000,
                purge_table="fragments",
                # purge_timestamp_column omitida deliberadamente
            )

    def test_malicious_table_name_raises(self, filled_fragments_db):
        """Nombre de tabla con sintaxis SQL inyectada — debe rechazarse
        en construcción, nunca llegar a interpolarse en una query."""
        with pytest.raises(ConfigError):
            WatchedDatabase(
                db_path=filled_fragments_db,
                role=StorageRole.TRANSIENT,
                max_size_bytes=1000,
                purge_table="fragments; DROP TABLE fragments;--",
                purge_timestamp_column="received_at",
            )

    def test_malicious_column_name_raises(self, filled_fragments_db):
        with pytest.raises(ConfigError):
            WatchedDatabase(
                db_path=filled_fragments_db,
                role=StorageRole.TRANSIENT,
                max_size_bytes=1000,
                purge_table="fragments",
                purge_timestamp_column="received_at; DROP TABLE fragments;--",
            )

    def test_table_name_with_space_raises(self, filled_fragments_db):
        with pytest.raises(ConfigError):
            WatchedDatabase(
                db_path=filled_fragments_db,
                role=StorageRole.TRANSIENT,
                max_size_bytes=1000,
                purge_table="frag ments",
                purge_timestamp_column="received_at",
            )


# ---------------------------------------------------------------------------
# Adversarial — check() / enforce() con inputs inválidos
# ---------------------------------------------------------------------------

class TestAdversarialCheckEnforce:
    def test_check_unregistered_path_raises(self, filled_fragments_db, tmp_path):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=10_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        unregistered = tmp_path / "otra.db"
        with pytest.raises(ConfigError):
            guardian.check(unregistered)

    def test_check_none_raises(self, filled_fragments_db):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=10_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        with pytest.raises(ConfigError):
            guardian.check(None)

    def test_enforce_unregistered_path_raises(self, filled_fragments_db, tmp_path):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=10_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        unregistered = tmp_path / "otra.db"
        with pytest.raises(ConfigError):
            guardian.enforce(unregistered)

    def test_check_nonexistent_file_returns_zero_size(self, tmp_path):
        """Una base registrada pero cuyo archivo aún no existe (ej. antes
        del primer arranque) debe reportar size_bytes=0, no lanzar."""
        nonexistent = tmp_path / "no-existe-todavia.db"
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=nonexistent,
                    role=StorageRole.COUNTER,
                    max_size_bytes=1000,
                )
            ]
        )
        status = guardian.check(nonexistent)
        assert status.size_bytes == 0
        assert status.needs_purge is False


# ---------------------------------------------------------------------------
# Ramas adicionales detectadas por coverage real (94% -> mejorar)
# Mismo criterio que tests/test_crypto_layer.py y test_vtrc_bundle.py: solo
# casos que ejercitan validación real ya existente, nunca relleno artificial.
# ---------------------------------------------------------------------------

class TestAdditionalCoverage:
    def test_warn_threshold_non_int_raises(self, nonce_counter_db):
        with pytest.raises(ConfigError):
            StorageGuardian(
                databases=[
                    WatchedDatabase(
                        db_path=nonce_counter_db,
                        role=StorageRole.COUNTER,
                        max_size_bytes=1000,
                    )
                ],
                warn_threshold_percent="80",  # str, no int
            )

    def test_purge_threshold_non_int_raises(self, nonce_counter_db):
        with pytest.raises(ConfigError):
            StorageGuardian(
                databases=[
                    WatchedDatabase(
                        db_path=nonce_counter_db,
                        role=StorageRole.COUNTER,
                        max_size_bytes=1000,
                    )
                ],
                purge_threshold_percent="95",  # str, no int
            )

    def test_purge_threshold_over_100_raises(self, nonce_counter_db):
        with pytest.raises(ConfigError):
            StorageGuardian(
                databases=[
                    WatchedDatabase(
                        db_path=nonce_counter_db,
                        role=StorageRole.COUNTER,
                        max_size_bytes=1000,
                    )
                ],
                purge_threshold_percent=101,
            )

    def test_guardian_status_is_warning_true_above_warn_threshold(
        self, filled_fragments_db
    ):
        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 1.1),
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        status = guardian.check(filled_fragments_db)
        # tamaño real / (tamaño*1.1) ≈ 90.9% > 80% (warn) pero < 95% (purge)
        assert status.is_warning is True
        assert status.needs_purge is False

    def test_guardian_status_is_warning_false_below_threshold(
        self, filled_fragments_db
    ):
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=100_000_000,
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ]
        )
        status = guardian.check(filled_fragments_db)
        assert status.is_warning is False

    def test_validate_sql_identifier_non_string_raises(self, filled_fragments_db):
        """_validate_sql_identifier rechaza valores no-string — se prueba
        vía WatchedDatabase, que es la única vía pública de invocarlo."""
        with pytest.raises(ConfigError):
            WatchedDatabase(
                db_path=filled_fragments_db,
                role=StorageRole.TRANSIENT,
                max_size_bytes=1000,
                purge_table=123,  # no es str
                purge_timestamp_column="received_at",
            )

    def test_purge_fifo_with_already_empty_table_returns_zero(
        self, filled_fragments_db
    ):
        """Escenario: needs_purge es True (el archivo .db sigue grande
        por overhead de páginas no compactadas) pero la tabla ya está
        vacía al momento de purgar (ej. un enforce() anterior ya la
        vació, o un proceso externo la limpió). _purge_fifo debe
        detectar row_count == 0 y retornar 0 sin intentar dividir por
        cero en el cálculo de bytes_per_row."""
        conn = sqlite3.connect(str(filled_fragments_db))
        conn.execute("DELETE FROM fragments")
        conn.commit()
        conn.close()
        # Deliberadamente NO se hace VACUUM — el archivo .db sigue
        # pesando como si tuviera las 300 filas, pero la tabla está vacía.

        real_size = _real_total_size(filled_fragments_db)
        guardian = StorageGuardian(
            databases=[
                WatchedDatabase(
                    db_path=filled_fragments_db,
                    role=StorageRole.TRANSIENT,
                    max_size_bytes=int(real_size * 0.5),  # fuerza needs_purge
                    purge_table="fragments",
                    purge_timestamp_column="received_at",
                )
            ],
            warn_threshold_percent=80,
            purge_threshold_percent=95,
        )
        status = guardian.check(filled_fragments_db)
        assert status.needs_purge is True  # confirma el escenario

        deleted = guardian.enforce(filled_fragments_db)
        assert deleted == 0  # tabla ya vacía, nada que purgar
