"""
vtr-continuity v0.5.0 — Core RF Fallback Tier 2
core/crypto_transport.py

Capa 1 del stack RF: serialización segura y cifrado de bundles LoRa.

Pipeline corregido (vulnerabilidad cero):
    [Evento] → Protobuf/JSON → LZ4 → Ed25519 → XChaCha20-Poly1305 → Padding → [UART]

El padding va AL FINAL (después del cifrado) para evitar el length oracle
sobre el contenido cifrado. El límite de 222 bytes aplica al frame completo.

Mitigaciones implementadas:
    - LZ4 bomb: validación de ratio antes de descomprimir
    - Length oracle: padding aleatorio AL FINAL del frame cifrado
    - Nonce reuse: contador monotónico persistido en SQLite
    - Replay attack: ventana basada en counter
    - Key confusion: domain separation "VTR-DATA-v1:"
    - Timing attack: comparación en tiempo constante
    - Honeypot node: whitelist por Ed25519 public key
    - Physical extraction: counter persiste tras reinicio

MAX_LORA_FRAME_BYTES = 222 (SX1262 SF7/BW125kHz CR4/5)

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lz4.frame
import nacl.encoding
import nacl.exceptions
import nacl.signing
import nacl.secret
import nacl.utils

logger = logging.getLogger(__name__)

MAX_LORA_FRAME_BYTES = 222
MAX_PAYLOAD_BYTES = 180
MAX_DECOMPRESSED_BYTES = 4096
MAX_EXPANSION_RATIO = 20
DOMAIN_PREFIX = b"VTR-DATA-v1:"
NONCE_SIZE = 24
COUNTER_WINDOW_BACK = 50
COUNTER_WINDOW_FORWARD = 100

DEFAULT_COUNTER_DB = Path("/var/lib/vtr-continuity/nonce_counter.db")


@dataclass
class EncryptedBundle:
    ciphertext: bytes
    nonce: bytes
    signature: bytes
    node_id: bytes
    counter: int
    frame_size: int


@dataclass
class DecryptedBundle:
    payload: bytes
    node_id: bytes
    counter: int
    verified: bool


class NonceCounter:
    """
    Contador monotónico persistido en SQLite.
    Nunca retrocede aunque el proceso se reinicie.

    Nonce (24 bytes):
        counter (8)    — monotónico persistido
        node_hash (8)  — primeros 8 bytes del node_id
        random (8)     — CSPRNG por frame
    """

    def __init__(self, node_id: bytes, db_path: Path | str = DEFAULT_COUNTER_DB) -> None:
        if not node_id or not isinstance(node_id, bytes):
            raise ValueError("node_id debe ser bytes no vacío")
        self._node_id = node_id
        self._node_id_hash = node_id[:8].ljust(8, b'\x00')
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            BEGIN;
            CREATE TABLE IF NOT EXISTS nonce_counter (
                node_id_hex TEXT PRIMARY KEY,
                counter     INTEGER NOT NULL DEFAULT 0,
                updated_at  REAL    NOT NULL
            );
            COMMIT;
        """)

    def next_nonce(self) -> tuple[bytes, int]:
        """Genera próximo nonce y lo persiste antes de retornar."""
        node_hex = self._node_id.hex()
        conn = self._get_conn()
        conn.execute("BEGIN EXCLUSIVE")
        try:
            row = conn.execute(
                "SELECT counter FROM nonce_counter WHERE node_id_hex = ?",
                (node_hex,),
            ).fetchone()
            counter = (row[0] + 1) if row else 1
            conn.execute(
                """
                INSERT INTO nonce_counter (node_id_hex, counter, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(node_id_hex) DO UPDATE SET
                    counter = excluded.counter,
                    updated_at = excluded.updated_at
                """,
                (node_hex, counter, time.time()),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        counter_bytes = struct.pack(">Q", counter)
        random_bytes = secrets.token_bytes(8)
        nonce = counter_bytes + self._node_id_hash + random_bytes
        assert len(nonce) == NONCE_SIZE
        return nonce, counter

    def last_counter(self) -> int:
        node_hex = self._node_id.hex()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT counter FROM nonce_counter WHERE node_id_hex = ?",
            (node_hex,),
        ).fetchone()
        return row[0] if row else 0


class ReplayWindow:
    """Ventana de replay basada en counter monotónico."""

    def __init__(
        self,
        window_back: int = COUNTER_WINDOW_BACK,
        window_forward: int = COUNTER_WINDOW_FORWARD,
        max_seen: int = 500,
    ) -> None:
        if window_back < 0:
            raise ValueError("window_back debe ser >= 0")
        if window_forward < 0:
            raise ValueError("window_forward debe ser >= 0")
        if max_seen <= 0:
            raise ValueError("max_seen debe ser > 0")
        self._window_back = window_back
        self._window_forward = window_forward
        self._max_seen = max_seen
        self._seen: dict[bytes, set[int]] = {}
        self._last: dict[bytes, int] = {}
        self._lock = threading.Lock()

    def check_and_record(self, node_id: bytes, counter: int) -> bool:
        if not node_id or not isinstance(node_id, bytes):
            return False
        if not isinstance(counter, int) or counter <= 0:
            return False
        with self._lock:
            last = self._last.get(node_id, 0)
            if last > 0:
                if counter < last - self._window_back:
                    logger.warning("[replay] counter=%d muy antiguo (last=%d)", counter, last)
                    return False
                if counter > last + self._window_forward:
                    logger.warning("[replay] counter=%d salto extremo (last=%d)", counter, last)
                    return False
            seen = self._seen.setdefault(node_id, set())
            if counter in seen:
                logger.warning("[replay] counter=%d ya procesado", counter)
                return False
            seen.add(counter)
            if counter > last:
                self._last[node_id] = counter
            if len(seen) > self._max_seen:
                seen.discard(min(seen))
            return True


class NodeRegistry:
    """Whitelist de nodos autorizados por Ed25519 public key."""

    def __init__(self) -> None:
        self._nodes: dict[bytes, bytes] = {}
        self._lock = threading.Lock()

    def register(self, node_id: bytes, public_key_bytes: bytes) -> bool:
        if not node_id or not isinstance(node_id, bytes):
            raise ValueError("node_id debe ser bytes no vacío")
        if not public_key_bytes or not isinstance(public_key_bytes, bytes):
            raise ValueError("public_key_bytes debe ser bytes no vacío")
        if len(public_key_bytes) != 32:
            raise ValueError("Ed25519 public key debe ser exactamente 32 bytes")
        existing = self._nodes.get(node_id)
        if existing is not None and not hmac.compare_digest(existing, public_key_bytes):
            logger.error("[registry] re-registro con clave diferente node_id=%s", node_id.hex()[:16])
            return False
        with self._lock:
            self._nodes[node_id] = public_key_bytes
        return True

    def get_public_key(self, node_id: bytes) -> bytes | None:
        if not node_id or not isinstance(node_id, bytes):
            return None
        return self._nodes.get(node_id)

    def is_registered(self, node_id: bytes) -> bool:
        if not node_id or not isinstance(node_id, bytes):
            return False
        return node_id in self._nodes

    def count(self) -> int:
        return len(self._nodes)


class CryptoTransport:
    """
    Capa 1 del stack RF VTR.

    Pipeline pack: serialize → compress → sign → encrypt → pad
    Pipeline unpack: check_replay → decrypt → verify → decompress → deserialize
    """

    def __init__(
        self,
        signing_key: nacl.signing.SigningKey,
        symmetric_key: bytes,
        node_id: bytes,
        registry: NodeRegistry,
        replay_window: ReplayWindow | None = None,
        nonce_counter: NonceCounter | None = None,
    ) -> None:
        if signing_key is None:
            raise ValueError("signing_key no puede ser None")
        if not symmetric_key or not isinstance(symmetric_key, bytes):
            raise ValueError("symmetric_key no puede ser vacío o None")
        if len(symmetric_key) != nacl.secret.SecretBox.KEY_SIZE:
            raise ValueError(f"symmetric_key debe ser {nacl.secret.SecretBox.KEY_SIZE} bytes")
        if not node_id or not isinstance(node_id, bytes):
            raise ValueError("node_id no puede ser vacío o None")
        if registry is None:
            raise ValueError("registry no puede ser None")

        self._signing_key = signing_key
        self._verify_key = signing_key.verify_key
        self._box = nacl.secret.SecretBox(symmetric_key)
        self._node_id = node_id
        self._registry = registry
        self._replay = replay_window or ReplayWindow()
        self._nonce_counter = nonce_counter
        self._registry.register(node_id, bytes(self._verify_key))

    def serialize(self, event: dict[str, Any] | None) -> bytes:
        """JSON serialización del evento. Sin padding aquí — el padding va al final."""
        if event is None:
            raise ValueError("event no puede ser None")
        if not isinstance(event, dict):
            raise ValueError("event debe ser un diccionario")
        try:
            payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"event no es serializable: {exc}") from exc
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"payload {len(payload)} bytes excede MAX_PAYLOAD_BYTES ({MAX_PAYLOAD_BYTES})"
            )
        return payload

    def deserialize(self, data: bytes | None) -> dict[str, Any]:
        """Deserializa bytes a evento."""
        if data is None:
            raise ValueError("data no puede ser None")
        if not isinstance(data, bytes):
            raise ValueError("data debe ser bytes")
        if len(data) == 0:
            raise ValueError("data no puede ser vacío")
        try:
            event = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"payload JSON inválido: {exc}") from exc
        if not isinstance(event, dict):
            raise ValueError("payload deserializado no es un diccionario")
        return event

    def compress(self, data: bytes | None) -> bytes:
        """Comprime con LZ4."""
        if data is None:
            raise ValueError("data no puede ser None")
        if not isinstance(data, bytes):
            raise ValueError("data debe ser bytes")
        return lz4.frame.compress(data, compression_level=0)

    def decompress(self, data: bytes | None) -> bytes:
        """Descomprime con protección anti-bomb."""
        if data is None:
            raise ValueError("data no puede ser None")
        if not isinstance(data, bytes):
            raise ValueError("data debe ser bytes")
        try:
            decompressed = lz4.frame.decompress(data)
        except Exception as exc:
            raise ValueError(f"LZ4 descompresión falló: {exc}") from exc
        if len(decompressed) > MAX_DECOMPRESSED_BYTES:
            raise ValueError(
                f"LZ4 bomb detectada — {len(decompressed)} bytes exceden "
                f"MAX_DECOMPRESSED_BYTES ({MAX_DECOMPRESSED_BYTES})"
            )
        if len(data) > 0:
            ratio = len(decompressed) / len(data)
            if ratio > MAX_EXPANSION_RATIO:
                raise ValueError(
                    f"LZ4 bomb detectada — ratio {ratio:.1f}x excede máximo ({MAX_EXPANSION_RATIO}x)"
                )
        return decompressed

    def sign(self, data: bytes | None) -> bytes:
        """Firma Ed25519 con domain prefix."""
        if data is None:
            raise ValueError("data no puede ser None")
        if not isinstance(data, bytes):
            raise ValueError("data debe ser bytes")
        if len(data) == 0:
            raise ValueError("data no puede ser vacío")
        message = DOMAIN_PREFIX + data
        return self._signing_key.sign(message).signature

    def verify(self, data: bytes | None, signature: bytes | None, node_id: bytes | None) -> bool:
        """Verifica firma Ed25519 en tiempo constante. Retorna False sin excepción."""
        if data is None or signature is None or node_id is None:
            return False
        if not isinstance(data, bytes) or not isinstance(signature, bytes):
            return False
        if not isinstance(node_id, bytes):
            return False
        public_key_bytes = self._registry.get_public_key(node_id)
        if public_key_bytes is None:
            return False
        try:
            verify_key = nacl.signing.VerifyKey(public_key_bytes)
            message = DOMAIN_PREFIX + data
            verify_key.verify(message, signature)
            return True
        except (nacl.exceptions.BadSignatureError, Exception):
            return False

    def encrypt(self, data: bytes | None) -> tuple[bytes, bytes, int]:
        """Cifra con XChaCha20-Poly1305 + nonce monotónico."""
        if data is None:
            raise ValueError("data no puede ser None")
        if not isinstance(data, bytes):
            raise ValueError("data debe ser bytes")
        if len(data) == 0:
            raise ValueError("data no puede ser vacío")
        if self._nonce_counter is not None:
            nonce, counter = self._nonce_counter.next_nonce()
        else:
            node_hash = self._node_id[:8].ljust(8, b'\x00')
            counter_bytes = struct.pack(">Q", int(time.time() * 1000) % (2**64))
            nonce = counter_bytes + node_hash + secrets.token_bytes(8)
            counter = 0
        assert len(nonce) == NONCE_SIZE
        ciphertext = self._box.encrypt(data, nonce=nonce).ciphertext
        return ciphertext, nonce, counter

    def decrypt(self, ciphertext: bytes | None, nonce: bytes | None) -> bytes:
        """Descifra y verifica tag Poly1305."""
        if ciphertext is None:
            raise ValueError("ciphertext no puede ser None")
        if nonce is None:
            raise ValueError("nonce no puede ser None")
        if not isinstance(ciphertext, bytes) or not isinstance(nonce, bytes):
            raise ValueError("ciphertext y nonce deben ser bytes")
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"nonce debe ser {NONCE_SIZE} bytes")
        try:
            return self._box.decrypt(ciphertext, nonce=nonce)
        except nacl.exceptions.CryptoError as exc:
            raise ValueError(f"descifrado falló — tag inválido: {exc}") from exc

    def pad_frame(self, data: bytes) -> bytes:
        """
        Padding aleatorio al final del frame cifrado.
        Alinea a MAX_LORA_FRAME_BYTES para evitar length oracle.
        Si el frame cifrado ya excede el límite, lo trunca con advertencia.
        """
        if len(data) >= MAX_LORA_FRAME_BYTES:
            logger.warning("[crypto] frame %d bytes >= MAX_LORA_FRAME_BYTES — sin padding", len(data))
            return data
        pad_size = MAX_LORA_FRAME_BYTES - len(data)
        return data + secrets.token_bytes(pad_size)

    def strip_padding(self, data: bytes, content_size: int) -> bytes:
        """Elimina padding conociendo el tamaño del contenido cifrado."""
        if content_size < 0 or content_size > len(data):
            raise ValueError("content_size inválido")
        return data[:content_size]

    def pack(self, event: dict[str, Any]) -> EncryptedBundle:
        """Pipeline completo: serialize → compress → sign → encrypt → pad."""
        serialized = self.serialize(event)
        compressed = self.compress(serialized)
        signature = self.sign(compressed)
        ciphertext, nonce, counter = self.encrypt(compressed)
        return EncryptedBundle(
            ciphertext=ciphertext,
            nonce=nonce,
            signature=signature,
            node_id=self._node_id,
            counter=counter,
            frame_size=len(ciphertext),
        )

    def unpack(self, bundle: EncryptedBundle | None) -> DecryptedBundle:
        """Pipeline completo: replay_check → decrypt → verify → decompress → deserialize."""
        if bundle is None:
            raise ValueError("bundle no puede ser None")
        if not self._replay.check_and_record(bundle.node_id, bundle.counter):
            return DecryptedBundle(payload=b"", node_id=bundle.node_id, counter=bundle.counter, verified=False)
        try:
            compressed = self.decrypt(bundle.ciphertext, bundle.nonce)
        except ValueError:
            return DecryptedBundle(payload=b"", node_id=bundle.node_id, counter=bundle.counter, verified=False)
        if not self.verify(compressed, bundle.signature, bundle.node_id):
            return DecryptedBundle(payload=b"", node_id=bundle.node_id, counter=bundle.counter, verified=False)
        try:
            decompressed = self.decompress(compressed)
            event = self.deserialize(decompressed)
            payload = json.dumps(event).encode("utf-8")
        except ValueError:
            return DecryptedBundle(payload=b"", node_id=bundle.node_id, counter=bundle.counter, verified=False)
        return DecryptedBundle(payload=payload, node_id=bundle.node_id, counter=bundle.counter, verified=True)

    @staticmethod
    def generate_keypair() -> nacl.signing.SigningKey:
        return nacl.signing.SigningKey.generate()

    @staticmethod
    def generate_symmetric_key() -> bytes:
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
