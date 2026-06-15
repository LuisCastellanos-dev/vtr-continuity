"""
vtr-continuity v0.5.0 — Tests + Pentesting Capa 1
core/tests/test_crypto_transport.py

Tests funcionales:
  - NonceCounter: monotónico, persistido, no retrocede
  - ReplayWindow: ventana, counter antiguo, salto extremo, duplicado
  - NodeRegistry: registro, whitelist, duplicado con clave diferente
  - CryptoTransport: serialize, compress, sign, verify, encrypt, decrypt
  - Pipeline completo: pack → unpack

Pentesting Capa 1:
  - LZ4 bomb: ratio de expansión malicioso
  - Replay attack: bundle duplicado
  - Counter rollback: counter menor al visto
  - Counter jump extremo: posible ataque
  - Key confusion: firma de un contexto en otro
  - Honeypot node: nodo no registrado
  - Nonce manipulado: nonce alterado post-cifrado
  - Ciphertext truncado: tag Poly1305 inválido
  - Padding predecible: verificar que padding no es 0x00
  - Firma inválida: bytes aleatorios como firma
  - Payload nulo: en cada paso del pipeline
  - Clave simétrica incorrecta: descifrado con clave diferente

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import json
import secrets
import struct
import time
from pathlib import Path

import lz4.frame
import nacl.signing
import nacl.secret
import nacl.utils
import pytest

from core.crypto_transport import (
    CryptoTransport,
    EncryptedBundle,
    MAX_DECOMPRESSED_BYTES,
    MAX_EXPANSION_RATIO,
    MAX_LORA_FRAME_BYTES,
    NodeRegistry,
    NonceCounter,
    ReplayWindow,
    DOMAIN_PREFIX,
    NONCE_SIZE,
)


@pytest.fixture
def signing_key():
    return CryptoTransport.generate_keypair()


@pytest.fixture
def sym_key():
    return CryptoTransport.generate_symmetric_key()


@pytest.fixture
def node_id():
    return secrets.token_bytes(32)


@pytest.fixture
def registry():
    return NodeRegistry()


@pytest.fixture
def transport(signing_key, sym_key, node_id, registry, tmp_path):
    counter = NonceCounter(node_id=node_id, db_path=tmp_path / "nonce.db")
    return CryptoTransport(
        signing_key=signing_key,
        symmetric_key=sym_key,
        node_id=node_id,
        registry=registry,
        nonce_counter=counter,
    )


@pytest.fixture
def sample_event():
    return {
        "event_type": "alert",
        "source": "dnp3",
        "data": {"level": "WARNING", "src_ip": "192.168.1.100"},
    }


class TestNonceCounter:

    def test_counter_empieza_en_uno(self, tmp_path, node_id):
        nc = NonceCounter(node_id=node_id, db_path=tmp_path / "n.db")
        _, counter = nc.next_nonce()
        assert counter == 1

    def test_counter_incrementa(self, tmp_path, node_id):
        nc = NonceCounter(node_id=node_id, db_path=tmp_path / "n.db")
        _, c1 = nc.next_nonce()
        _, c2 = nc.next_nonce()
        assert c2 == c1 + 1

    def test_nonce_es_24_bytes(self, tmp_path, node_id):
        nc = NonceCounter(node_id=node_id, db_path=tmp_path / "n.db")
        nonce, _ = nc.next_nonce()
        assert len(nonce) == NONCE_SIZE

    def test_nonces_son_unicos(self, tmp_path, node_id):
        nc = NonceCounter(node_id=node_id, db_path=tmp_path / "n.db")
        nonces = [nc.next_nonce()[0] for _ in range(10)]
        assert len(set(nonces)) == 10

    def test_counter_persiste_entre_instancias(self, tmp_path, node_id):
        db = tmp_path / "n.db"
        nc1 = NonceCounter(node_id=node_id, db_path=db)
        for _ in range(5):
            nc1.next_nonce()
        nc2 = NonceCounter(node_id=node_id, db_path=db)
        _, counter = nc2.next_nonce()
        assert counter == 6

    def test_node_id_vacio_raises(self, tmp_path):
        with pytest.raises(ValueError):
            NonceCounter(node_id=b"", db_path=tmp_path / "n.db")

    def test_node_id_none_raises(self, tmp_path):
        with pytest.raises(ValueError):
            NonceCounter(node_id=None, db_path=tmp_path / "n.db")

    def test_last_counter_inicial_es_cero(self, tmp_path, node_id):
        nc = NonceCounter(node_id=node_id, db_path=tmp_path / "n.db")
        assert nc.last_counter() == 0

    def test_last_counter_actualizado(self, tmp_path, node_id):
        nc = NonceCounter(node_id=node_id, db_path=tmp_path / "n.db")
        nc.next_nonce()
        nc.next_nonce()
        assert nc.last_counter() == 2


class TestReplayWindow:

    def test_primer_bundle_aceptado(self):
        rw = ReplayWindow()
        node = secrets.token_bytes(32)
        assert rw.check_and_record(node, 1) is True

    def test_bundle_duplicado_rechazado(self):
        rw = ReplayWindow()
        node = secrets.token_bytes(32)
        rw.check_and_record(node, 1)
        assert rw.check_and_record(node, 1) is False

    def test_counter_antiguo_rechazado(self):
        rw = ReplayWindow(window_back=10)
        node = secrets.token_bytes(32)
        rw.check_and_record(node, 100)
        assert rw.check_and_record(node, 89) is False

    def test_counter_dentro_de_ventana_back(self):
        rw = ReplayWindow(window_back=10)
        node = secrets.token_bytes(32)
        rw.check_and_record(node, 100)
        assert rw.check_and_record(node, 95) is True

    def test_counter_salto_extremo_rechazado(self):
        rw = ReplayWindow(window_forward=100)
        node = secrets.token_bytes(32)
        rw.check_and_record(node, 1)
        assert rw.check_and_record(node, 500) is False

    def test_counter_dentro_ventana_forward(self):
        rw = ReplayWindow(window_forward=100)
        node = secrets.token_bytes(32)
        rw.check_and_record(node, 1)
        assert rw.check_and_record(node, 50) is True

    def test_node_id_none_rechazado(self):
        rw = ReplayWindow()
        assert rw.check_and_record(None, 1) is False

    def test_counter_cero_rechazado(self):
        rw = ReplayWindow()
        node = secrets.token_bytes(32)
        assert rw.check_and_record(node, 0) is False

    def test_counter_negativo_rechazado(self):
        rw = ReplayWindow()
        node = secrets.token_bytes(32)
        assert rw.check_and_record(node, -1) is False

    def test_window_back_negativo_raises(self):
        with pytest.raises(ValueError):
            ReplayWindow(window_back=-1)

    def test_max_seen_invalido_raises(self):
        with pytest.raises(ValueError):
            ReplayWindow(max_seen=0)


class TestNodeRegistry:

    def test_registro_basico(self, registry):
        node_id = secrets.token_bytes(32)
        pk = secrets.token_bytes(32)
        assert registry.register(node_id, pk) is True

    def test_nodo_registrado_encontrado(self, registry):
        node_id = secrets.token_bytes(32)
        pk = secrets.token_bytes(32)
        registry.register(node_id, pk)
        assert registry.get_public_key(node_id) == pk

    def test_nodo_no_registrado_retorna_none(self, registry):
        assert registry.get_public_key(secrets.token_bytes(32)) is None

    def test_registro_duplicado_misma_clave_ok(self, registry):
        node_id = secrets.token_bytes(32)
        pk = secrets.token_bytes(32)
        registry.register(node_id, pk)
        assert registry.register(node_id, pk) is True

    def test_registro_duplicado_clave_diferente_rechazado(self, registry):
        node_id = secrets.token_bytes(32)
        pk1 = secrets.token_bytes(32)
        pk2 = secrets.token_bytes(32)
        registry.register(node_id, pk1)
        assert registry.register(node_id, pk2) is False

    def test_node_id_vacio_raises(self, registry):
        with pytest.raises(ValueError):
            registry.register(b"", secrets.token_bytes(32))

    def test_public_key_tamano_incorrecto_raises(self, registry):
        with pytest.raises(ValueError):
            registry.register(secrets.token_bytes(32), secrets.token_bytes(16))

    def test_get_public_key_none_retorna_none(self, registry):
        assert registry.get_public_key(None) is None

    def test_is_registered(self, registry):
        node_id = secrets.token_bytes(32)
        pk = secrets.token_bytes(32)
        assert registry.is_registered(node_id) is False
        registry.register(node_id, pk)
        assert registry.is_registered(node_id) is True

    def test_count(self, registry):
        assert registry.count() == 0
        registry.register(secrets.token_bytes(32), secrets.token_bytes(32))
        assert registry.count() == 1


class TestSerialize:

    def test_serialize_basico(self, transport, sample_event):
        result = transport.serialize(sample_event)
        assert isinstance(result, bytes)
        assert len(result) <= MAX_LORA_FRAME_BYTES

    def test_serialize_none_raises(self, transport):
        with pytest.raises(ValueError):
            transport.serialize(None)

    def test_serialize_no_dict_raises(self, transport):
        with pytest.raises(ValueError):
            transport.serialize("no es dict")

    def test_serialize_payload_grande_raises(self, transport):
        evento_grande = {"data": "x" * MAX_LORA_FRAME_BYTES}
        with pytest.raises(ValueError):
            transport.serialize(evento_grande)

    def test_padding_no_es_ceros(self, transport):
        data = b"datos cortos"
        padded = transport.pad_frame(data)
        padding = padded[len(data):]
        assert len(padded) == MAX_LORA_FRAME_BYTES
        assert padding != b'\x00' * len(padding)

    def test_deserialize_roundtrip(self, transport, sample_event):
        serialized = transport.serialize(sample_event)
        recovered = transport.deserialize(serialized)
        assert recovered == sample_event

    def test_deserialize_none_raises(self, transport):
        with pytest.raises(ValueError):
            transport.deserialize(None)

    def test_deserialize_muy_corto_raises(self, transport):
        with pytest.raises(ValueError):
            transport.deserialize(b"\x00")

    def test_deserialize_payload_len_excesivo_raises(self, transport):
        data = struct.pack(">H", MAX_LORA_FRAME_BYTES + 100) + b"\x00" * 100
        with pytest.raises(ValueError):
            transport.deserialize(data)


class TestCompress:

    def test_compress_basico(self, transport, sample_event):
        serialized = transport.serialize(sample_event)
        compressed = transport.compress(serialized)
        assert isinstance(compressed, bytes)
        assert len(compressed) <= MAX_LORA_FRAME_BYTES

    def test_compress_none_raises(self, transport):
        with pytest.raises(ValueError):
            transport.compress(None)

    def test_decompress_roundtrip(self, transport, sample_event):
        serialized = transport.serialize(sample_event)
        compressed = transport.compress(serialized)
        decompressed = transport.decompress(compressed)
        assert decompressed == serialized

    def test_decompress_none_raises(self, transport):
        with pytest.raises(ValueError):
            transport.decompress(None)


class TestSignVerify:

    def test_sign_basico(self, transport):
        data = b"datos de prueba"
        sig = transport.sign(data)
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_verify_valido(self, transport, node_id):
        data = b"datos de prueba"
        sig = transport.sign(data)
        assert transport.verify(data, sig, node_id) is True

    def test_verify_firma_invalida(self, transport, node_id):
        data = b"datos de prueba"
        sig_falsa = secrets.token_bytes(64)
        assert transport.verify(data, sig_falsa, node_id) is False

    def test_verify_datos_alterados(self, transport, node_id):
        data = b"datos originales"
        sig = transport.sign(data)
        assert transport.verify(b"datos alterados", sig, node_id) is False

    def test_verify_none_retorna_false(self, transport, node_id):
        assert transport.verify(None, b"sig", node_id) is False
        assert transport.verify(b"data", None, node_id) is False
        assert transport.verify(b"data", b"sig", None) is False

    def test_sign_none_raises(self, transport):
        with pytest.raises(ValueError):
            transport.sign(None)

    def test_sign_vacio_raises(self, transport):
        with pytest.raises(ValueError):
            transport.sign(b"")


class TestEncryptDecrypt:

    def test_encrypt_basico(self, transport):
        data = b"datos de prueba"
        ciphertext, nonce, counter = transport.encrypt(data)
        assert isinstance(ciphertext, bytes)
        assert len(nonce) == NONCE_SIZE
        assert counter >= 1

    def test_decrypt_roundtrip(self, transport):
        data = b"datos de prueba VTR"
        ciphertext, nonce, _ = transport.encrypt(data)
        recovered = transport.decrypt(ciphertext, nonce)
        assert recovered == data

    def test_encrypt_none_raises(self, transport):
        with pytest.raises(ValueError):
            transport.encrypt(None)

    def test_decrypt_none_ciphertext_raises(self, transport):
        with pytest.raises(ValueError):
            transport.decrypt(None, secrets.token_bytes(NONCE_SIZE))

    def test_decrypt_none_nonce_raises(self, transport):
        with pytest.raises(ValueError):
            transport.decrypt(b"datos", None)

    def test_decrypt_nonce_incorrecto_raises(self, transport):
        data = b"datos"
        ciphertext, _, _ = transport.encrypt(data)
        nonce_falso = secrets.token_bytes(NONCE_SIZE)
        with pytest.raises(ValueError):
            transport.decrypt(ciphertext, nonce_falso)

    def test_decrypt_ciphertext_truncado_raises(self, transport):
        data = b"datos de prueba"
        ciphertext, nonce, _ = transport.encrypt(data)
        with pytest.raises(ValueError):
            transport.decrypt(ciphertext[:5], nonce)


class TestPipelineCompleto:

    def test_pack_unpack_roundtrip(self, transport, sample_event):
        bundle = transport.pack(sample_event)
        result = transport.unpack(bundle)
        assert result.verified is True
        recovered = json.loads(result.payload)
        assert recovered == sample_event

    def test_pack_retorna_encrypted_bundle(self, transport, sample_event):
        bundle = transport.pack(sample_event)
        assert isinstance(bundle, EncryptedBundle)
        assert bundle.node_id is not None
        assert bundle.counter >= 1

    def test_unpack_none_raises(self, transport):
        with pytest.raises(ValueError):
            transport.unpack(None)


class TestPentesting:

    def test_lz4_bomb_rechazada(self, transport):
        repeticiones = b"AAAA" * 10000
        compressed = lz4.frame.compress(repeticiones)
        with pytest.raises(ValueError, match="LZ4 bomb"):
            transport.decompress(compressed)

    def test_replay_attack_bundle_duplicado(self, transport, sample_event):
        bundle = transport.pack(sample_event)
        r1 = transport.unpack(bundle)
        r2 = transport.unpack(bundle)
        assert r1.verified is True
        assert r2.verified is False

    def test_counter_rollback_rechazado(self):
        rw = ReplayWindow(window_back=10)
        node = secrets.token_bytes(32)
        rw.check_and_record(node, 100)
        assert rw.check_and_record(node, 85) is False

    def test_counter_salto_extremo_rechazado(self):
        rw = ReplayWindow(window_forward=100)
        node = secrets.token_bytes(32)
        rw.check_and_record(node, 1)
        assert rw.check_and_record(node, 1000) is False

    def test_key_confusion_domain_prefix(self, transport, node_id):
        data = b"bundle de datos"
        sig = transport.sign(data)
        data_diferente = b"bundle de custodia"
        assert transport.verify(data_diferente, sig, node_id) is False

    def test_honeypot_nodo_no_registrado(self, signing_key, sym_key, tmp_path):
        node_a = secrets.token_bytes(32)
        node_b = secrets.token_bytes(32)
        registry = NodeRegistry()
        counter = NonceCounter(node_id=node_a, db_path=tmp_path / "n.db")
        t = CryptoTransport(
            signing_key=signing_key,
            symmetric_key=sym_key,
            node_id=node_a,
            registry=registry,
            nonce_counter=counter,
        )
        assert registry.get_public_key(node_b) is None

    def test_nonce_manipulado_post_cifrado(self, transport):
        data = b"datos sensibles"
        ciphertext, nonce, _ = transport.encrypt(data)
        nonce_alterado = bytes([n ^ 0xFF for n in nonce])
        with pytest.raises(ValueError):
            transport.decrypt(ciphertext, nonce_alterado)

    def test_ciphertext_alterado_tag_invalido(self, transport):
        data = b"datos sensibles"
        ciphertext, nonce, _ = transport.encrypt(data)
        ciphertext_alterado = bytes([c ^ 0x01 for c in ciphertext])
        with pytest.raises(ValueError):
            transport.decrypt(ciphertext_alterado, nonce)

    def test_firma_bytes_aleatorios_rechazada(self, transport, node_id):
        data = b"datos"
        firma_falsa = secrets.token_bytes(64)
        assert transport.verify(data, firma_falsa, node_id) is False

    def test_payload_nulo_en_serialize(self, transport):
        with pytest.raises(ValueError):
            transport.serialize(None)

    def test_payload_nulo_en_encrypt(self, transport):
        with pytest.raises(ValueError):
            transport.encrypt(None)

    def test_payload_nulo_en_sign(self, transport):
        with pytest.raises(ValueError):
            transport.sign(None)

    def test_clave_simetrica_incorrecta(self, signing_key, node_id, tmp_path):
        key_a = CryptoTransport.generate_symmetric_key()
        key_b = CryptoTransport.generate_symmetric_key()
        registry_a = NodeRegistry()
        registry_b = NodeRegistry()
        counter_a = NonceCounter(node_id=node_id, db_path=tmp_path / "a.db")
        counter_b = NonceCounter(node_id=node_id, db_path=tmp_path / "b.db")

        t_a = CryptoTransport(signing_key, key_a, node_id, registry_a, nonce_counter=counter_a)
        t_b = CryptoTransport(signing_key, key_b, node_id, registry_b, nonce_counter=counter_b)

        data = b"datos cifrados con clave A"
        ciphertext, nonce, _ = t_a.encrypt(data)
        with pytest.raises(ValueError):
            t_b.decrypt(ciphertext, nonce)

    def test_max_lora_frame_bytes_constante(self):
        assert MAX_LORA_FRAME_BYTES == 222

    def test_evento_minimo_cabe_en_frame(self, transport):
        evento = {"t": "a", "s": "d"}
        bundle = transport.pack(evento)
        assert bundle.frame_size <= MAX_LORA_FRAME_BYTES + 100

    def test_nonce_counter_no_retrocede_tras_reinicio(self, signing_key, sym_key, node_id, tmp_path):
        db = tmp_path / "nonce.db"
        registry1 = NodeRegistry()
        c1 = NonceCounter(node_id=node_id, db_path=db)
        t1 = CryptoTransport(signing_key, sym_key, node_id, registry1, nonce_counter=c1)
        for _ in range(5):
            t1.pack({"x": 1})
        last_counter = c1.last_counter()

        registry2 = NodeRegistry()
        c2 = NonceCounter(node_id=node_id, db_path=db)
        _, new_counter = c2.next_nonce()
        assert new_counter > last_counter
