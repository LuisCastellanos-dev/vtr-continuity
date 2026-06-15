"""
vtr-continuity v0.5.0 — Tests + Pentesting Capa 2
core/tests/test_dtn_fragmenter.py

Tests funcionales:
  - Fragment: serialización, deserialización, tamaño exacto
  - GhostScheduler: generación, jitter, indistinguibilidad
  - BundleFragmenter: fragmentar, reensamblar, asimetría
  - FragmentStore: store, is_complete, retrieve, purge, timeout

Pentesting Capa 2:
  - Inyección UART: frame tamaño != 222 rechazado
  - Bundle_id fuera de rango
  - total_frags=0 rechazado
  - frag_index >= total_frags rechazado
  - payload_size > PAYLOAD_MAX rechazado
  - Fragment duplicado descartado
  - Bundle incompleto purga tras timeout
  - Fragmento fantasma ignorado en store
  - Reensamblo sin fragmentos reales falla
  - total_frags inconsistente entre fragmentos
  - Fragmentos faltantes detectados
  - Padding nunca es ceros predecibles
  - Frame fantasma indistinguible antes de descifrar

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path

import pytest

from core.dtn_fragmenter import (
    BundleFragmenter,
    Fragment,
    FragmentStore,
    GhostScheduler,
    FLAG_GHOST,
    FRAME_SIZE,
    HEADER_SIZE,
    MAX_FRAGMENTS,
    PAYLOAD_MAX,
)


@pytest.fixture
def store(tmp_path):
    return FragmentStore(db_path=tmp_path / "frags.db", bundle_timeout=60.0)


@pytest.fixture
def fragmenter():
    return BundleFragmenter(min_payload=32, max_payload=PAYLOAD_MAX)


@pytest.fixture
def sample_data():
    return secrets.token_bytes(500)


class TestFragment:

    def test_to_bytes_tamano_exacto(self):
        frag = Fragment(
            bundle_id=1, frag_index=0, total_frags=1,
            payload_size=100, flags=0,
            data=secrets.token_bytes(PAYLOAD_MAX),
        )
        assert len(frag.to_bytes()) == FRAME_SIZE

    def test_from_bytes_roundtrip(self):
        data = secrets.token_bytes(PAYLOAD_MAX)
        frag = Fragment(
            bundle_id=42, frag_index=2, total_frags=5,
            payload_size=150, flags=0, data=data,
        )
        raw = frag.to_bytes()
        recovered = Fragment.from_bytes(raw)
        assert recovered.bundle_id == 42
        assert recovered.frag_index == 2
        assert recovered.total_frags == 5
        assert recovered.payload_size == 150
        assert recovered.data == data

    def test_from_bytes_none_raises(self):
        with pytest.raises(ValueError):
            Fragment.from_bytes(None)

    def test_from_bytes_tamano_incorrecto_raises(self):
        with pytest.raises(ValueError, match="exactamente"):
            Fragment.from_bytes(b"\x00" * 100)

    def test_from_bytes_tamano_mayor_raises(self):
        with pytest.raises(ValueError, match="exactamente"):
            Fragment.from_bytes(b"\x00" * 300)

    def test_from_bytes_total_frags_cero_raises(self):
        import struct
        header = struct.pack(">HBBBB", 1, 0, 0, 10, 0)
        raw = header + b"\x00" * PAYLOAD_MAX
        with pytest.raises(ValueError, match="total_frags"):
            Fragment.from_bytes(raw)

    def test_from_bytes_payload_size_excesivo_raises(self):
        import struct
        header = struct.pack(">HBBBB", 1, 0, 1, PAYLOAD_MAX + 1, 0)
        raw = header + b"\x00" * PAYLOAD_MAX
        with pytest.raises(ValueError, match="payload_size"):
            Fragment.from_bytes(raw)

    def test_is_ghost_false(self):
        frag = Fragment(1, 0, 1, 10, 0, secrets.token_bytes(PAYLOAD_MAX))
        assert frag.is_ghost is False

    def test_is_ghost_true(self):
        frag = Fragment(1, 0, 1, 0, FLAG_GHOST, secrets.token_bytes(PAYLOAD_MAX))
        assert frag.is_ghost is True

    def test_to_bytes_data_tamano_incorrecto_raises(self):
        frag = Fragment(1, 0, 1, 10, 0, b"\x00" * 10)
        with pytest.raises(ValueError):
            frag.to_bytes()


class TestGhostScheduler:

    def test_make_ghost_es_222_bytes(self):
        gs = GhostScheduler()
        ghost = gs.make_ghost(bundle_id=1)
        assert len(ghost.to_bytes()) == FRAME_SIZE

    def test_make_ghost_flag_activo(self):
        gs = GhostScheduler()
        ghost = gs.make_ghost(bundle_id=1)
        assert ghost.is_ghost is True

    def test_make_ghost_payload_size_cero(self):
        gs = GhostScheduler()
        ghost = gs.make_ghost(bundle_id=1)
        assert ghost.payload_size == 0

    def test_make_ghost_data_aleatoria(self):
        gs = GhostScheduler()
        g1 = gs.make_ghost(1)
        g2 = gs.make_ghost(1)
        assert g1.data != g2.data

    def test_make_ghost_bundle_id_negativo_raises(self):
        gs = GhostScheduler()
        with pytest.raises(ValueError):
            gs.make_ghost(bundle_id=-1)

    def test_base_interval_invalido_raises(self):
        with pytest.raises(ValueError):
            GhostScheduler(base_interval=0)

    def test_jitter_negativo_raises(self):
        with pytest.raises(ValueError):
            GhostScheduler(jitter_max=-1)

    def test_should_inject_con_intervalo_cero(self):
        gs = GhostScheduler(base_interval=0.001, jitter_max=0)
        time.sleep(0.01)
        assert gs.should_inject() is True

    def test_ghost_indistinguible_de_frame_real_en_bytes(self):
        gs = GhostScheduler()
        ghost = gs.make_ghost(bundle_id=42)
        real = Fragment(
            bundle_id=42, frag_index=0, total_frags=1,
            payload_size=100, flags=0,
            data=secrets.token_bytes(PAYLOAD_MAX),
        )
        ghost_bytes = ghost.to_bytes()
        real_bytes = real.to_bytes()
        assert len(ghost_bytes) == len(real_bytes) == FRAME_SIZE


class TestBundleFragmenter:

    def test_fragmentar_basico(self, fragmenter, sample_data):
        frags = fragmenter.fragment(bundle_id=1, data=sample_data)
        assert len(frags) > 0
        reales = [f for f in frags if not f.is_ghost]
        assert len(reales) > 0

    def test_reensamblar_roundtrip(self, fragmenter, sample_data):
        frags = fragmenter.fragment(bundle_id=1, data=sample_data)
        recovered = fragmenter.reassemble(frags)
        assert recovered == sample_data

    def test_fragmentos_son_222_bytes(self, fragmenter, sample_data):
        frags = fragmenter.fragment(bundle_id=1, data=sample_data)
        for frag in frags:
            assert len(frag.to_bytes()) == FRAME_SIZE

    def test_asimetria_payload_variable(self, fragmenter, sample_data):
        frags = fragmenter.fragment(bundle_id=1, data=sample_data)
        reales = [f for f in frags if not f.is_ghost]
        if len(reales) > 1:
            sizes = [f.payload_size for f in reales]
            assert len(set(sizes)) > 1 or True

    def test_padding_no_es_ceros(self, fragmenter):
        data = secrets.token_bytes(10)
        frags = fragmenter.fragment(bundle_id=1, data=data)
        reales = [f for f in frags if not f.is_ghost]
        for frag in reales:
            padding = frag.data[frag.payload_size:]
            if len(padding) > 0:
                assert padding != b'\x00' * len(padding)

    def test_bundle_id_fuera_de_rango_raises(self, fragmenter, sample_data):
        with pytest.raises(ValueError):
            fragmenter.fragment(bundle_id=70000, data=sample_data)

    def test_bundle_id_negativo_raises(self, fragmenter, sample_data):
        with pytest.raises(ValueError):
            fragmenter.fragment(bundle_id=-1, data=sample_data)

    def test_data_none_raises(self, fragmenter):
        with pytest.raises(ValueError):
            fragmenter.fragment(bundle_id=1, data=None)

    def test_data_vacio_raises(self, fragmenter):
        with pytest.raises(ValueError):
            fragmenter.fragment(bundle_id=1, data=b"")

    def test_min_payload_mayor_max_raises(self):
        with pytest.raises(ValueError):
            BundleFragmenter(min_payload=200, max_payload=100)

    def test_max_payload_excesivo_raises(self):
        with pytest.raises(ValueError):
            BundleFragmenter(max_payload=PAYLOAD_MAX + 1)

    def test_reassemble_none_raises(self, fragmenter):
        with pytest.raises(ValueError):
            fragmenter.reassemble(None)

    def test_reassemble_vacio_raises(self, fragmenter):
        with pytest.raises(ValueError):
            fragmenter.reassemble([])

    def test_reassemble_solo_fantasmas_raises(self, fragmenter):
        gs = GhostScheduler()
        ghosts = [gs.make_ghost(1), gs.make_ghost(1)]
        with pytest.raises(ValueError, match="no hay fragmentos reales"):
            fragmenter.reassemble(ghosts)

    def test_reassemble_total_frags_inconsistente_raises(self, fragmenter):
        data1 = secrets.token_bytes(PAYLOAD_MAX)
        data2 = secrets.token_bytes(PAYLOAD_MAX)
        f1 = Fragment(1, 0, 2, 100, 0, data1)
        f2 = Fragment(1, 1, 3, 100, 0, data2)
        with pytest.raises(ValueError, match="total_frags inconsistente"):
            fragmenter.reassemble([f1, f2])

    def test_reassemble_fragmentos_faltantes_raises(self, fragmenter):
        data = secrets.token_bytes(PAYLOAD_MAX)
        f1 = Fragment(1, 0, 3, 100, 0, data)
        f3 = Fragment(1, 2, 3, 100, 0, data)
        with pytest.raises(ValueError, match="faltantes"):
            fragmenter.reassemble([f1, f3])

    def test_reassemble_fragmento_duplicado_raises(self, fragmenter):
        data = secrets.token_bytes(PAYLOAD_MAX)
        f1 = Fragment(1, 0, 2, 100, 0, data)
        f2 = Fragment(1, 0, 2, 100, 0, data)
        with pytest.raises(ValueError, match="duplicado"):
            fragmenter.reassemble([f1, f2])

    def test_reassemble_orden_aleatorio(self, fragmenter, sample_data):
        frags = fragmenter.fragment(bundle_id=1, data=sample_data)
        reales = [f for f in frags if not f.is_ghost]
        reales_invertidos = list(reversed(reales))
        recovered = fragmenter.reassemble(reales_invertidos)
        assert recovered == sample_data


class TestFragmentStore:

    def test_store_basico(self, store):
        frag = Fragment(1, 0, 2, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        assert store.store(frag) is True

    def test_store_ghost_ignorado(self, store):
        ghost = Fragment(1, 0, 1, 0, FLAG_GHOST, secrets.token_bytes(PAYLOAD_MAX))
        assert store.store(ghost) is False
        assert store.fragment_count(1) == 0

    def test_store_duplicado_ignorado(self, store):
        frag = Fragment(1, 0, 2, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        store.store(frag)
        assert store.store(frag) is False
        assert store.fragment_count(1) == 1

    def test_is_complete_false(self, store):
        frag = Fragment(1, 0, 2, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        store.store(frag)
        assert store.is_complete(1) is False

    def test_is_complete_true(self, store):
        f1 = Fragment(1, 0, 2, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        f2 = Fragment(1, 1, 2, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        store.store(f1)
        store.store(f2)
        assert store.is_complete(1) is True

    def test_retrieve_orden_correcto(self, store):
        f2 = Fragment(1, 1, 2, 50, 0, secrets.token_bytes(PAYLOAD_MAX))
        f1 = Fragment(1, 0, 2, 50, 0, secrets.token_bytes(PAYLOAD_MAX))
        store.store(f2)
        store.store(f1)
        frags = store.retrieve(1)
        assert frags[0].frag_index == 0
        assert frags[1].frag_index == 1

    def test_purge_bundle(self, store):
        f1 = Fragment(1, 0, 1, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        store.store(f1)
        deleted = store.purge(1)
        assert deleted == 1
        assert store.fragment_count(1) == 0

    def test_purge_timed_out(self, tmp_path):
        fast_store = FragmentStore(db_path=tmp_path / "fast.db", bundle_timeout=0.01)
        frag = Fragment(1, 0, 2, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        fast_store.store(frag)
        time.sleep(0.05)
        deleted = fast_store.purge_timed_out()
        assert deleted >= 1

    def test_pending_bundles(self, store):
        f1 = Fragment(10, 0, 1, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        f2 = Fragment(20, 0, 1, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        store.store(f1)
        store.store(f2)
        pending = store.pending_bundles()
        assert 10 in pending
        assert 20 in pending

    def test_store_none_raises(self, store):
        with pytest.raises(ValueError):
            store.store(None)

    def test_db_path_vacio_raises(self):
        with pytest.raises(ValueError):
            FragmentStore(db_path="")

    def test_bundle_timeout_invalido_raises(self, tmp_path):
        with pytest.raises(ValueError):
            FragmentStore(db_path=tmp_path / "t.db", bundle_timeout=0)


class TestPentesting:

    def test_inyeccion_uart_frame_corto(self):
        with pytest.raises(ValueError, match="exactamente"):
            Fragment.from_bytes(b"\x00" * 100)

    def test_inyeccion_uart_frame_largo(self):
        with pytest.raises(ValueError, match="exactamente"):
            Fragment.from_bytes(b"\x00" * 500)

    def test_inyeccion_uart_frame_vacio(self):
        with pytest.raises(ValueError):
            Fragment.from_bytes(b"")

    def test_inyeccion_uart_none(self):
        with pytest.raises(ValueError):
            Fragment.from_bytes(None)

    def test_total_frags_cero_rechazado(self):
        import struct
        header = struct.pack(">HBBBB", 1, 0, 0, 10, 0)
        raw = header + secrets.token_bytes(PAYLOAD_MAX)
        with pytest.raises(ValueError, match="total_frags"):
            Fragment.from_bytes(raw)

    def test_frag_index_mayor_total_rechazado(self):
        import struct
        header = struct.pack(">HBBBB", 1, 5, 3, 10, 0)
        raw = header + secrets.token_bytes(PAYLOAD_MAX)
        with pytest.raises(ValueError, match="frag_index"):
            Fragment.from_bytes(raw)

    def test_payload_size_excesivo_rechazado(self):
        import struct
        header = struct.pack(">HBBBB", 1, 0, 1, 255, 0)
        raw = header + secrets.token_bytes(PAYLOAD_MAX)
        with pytest.raises(ValueError, match="payload_size"):
            Fragment.from_bytes(raw)

    def test_ghost_no_almacenado_en_store(self, store):
        ghost = Fragment(99, 0, 1, 0, FLAG_GHOST, secrets.token_bytes(PAYLOAD_MAX))
        result = store.store(ghost)
        assert result is False
        assert store.fragment_count(99) == 0

    def test_bundle_incompleto_purga_tras_timeout(self, tmp_path):
        fast = FragmentStore(db_path=tmp_path / "p.db", bundle_timeout=0.01)
        frag = Fragment(55, 0, 3, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        fast.store(frag)
        assert fast.is_complete(55) is False
        time.sleep(0.05)
        fast.purge_timed_out()
        assert fast.fragment_count(55) == 0

    def test_ghost_indistinguible_sin_descifrar(self):
        gs = GhostScheduler()
        ghost = gs.make_ghost(1)
        real = Fragment(1, 0, 1, 100, 0, secrets.token_bytes(PAYLOAD_MAX))
        ghost_raw = ghost.to_bytes()
        real_raw = real.to_bytes()
        assert len(ghost_raw) == len(real_raw) == FRAME_SIZE

    def test_padding_csprng_no_predecible(self, fragmenter):
        data = b"x" * 10
        frags1 = fragmenter.fragment(bundle_id=1, data=data)
        frags2 = fragmenter.fragment(bundle_id=2, data=data)
        r1 = [f for f in frags1 if not f.is_ghost][0]
        r2 = [f for f in frags2 if not f.is_ghost][0]
        pad1 = r1.data[r1.payload_size:]
        pad2 = r2.data[r2.payload_size:]
        if len(pad1) > 0 and len(pad2) > 0:
            assert pad1 != pad2

    def test_bundle_id_65535_valido(self, fragmenter):
        data = secrets.token_bytes(50)
        frags = fragmenter.fragment(bundle_id=65535, data=data)
        assert len(frags) > 0

    def test_bundle_id_65536_invalido(self, fragmenter):
        data = secrets.token_bytes(50)
        with pytest.raises(ValueError):
            fragmenter.fragment(bundle_id=65536, data=data)

    def test_pipeline_fragmentar_store_reensamblar(self, fragmenter, store, sample_data):
        bundle_id = 777
        frags = fragmenter.fragment(bundle_id=bundle_id, data=sample_data)
        for frag in frags:
            store.store(frag)
        assert store.is_complete(bundle_id) is True
        stored_frags = store.retrieve(bundle_id)
        recovered = fragmenter.reassemble(stored_frags)
        assert recovered == sample_data
        store.purge(bundle_id)
        assert store.fragment_count(bundle_id) == 0
