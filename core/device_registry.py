"""
vtr-continuity v0.5.0 — Provisioning
core/device_registry.py

Implementa `device_registry.vtrdb` — el registro de dispositivos
provisionados, según docs/VTR-PKI-001.md §3.3 y
docs/DECISIONS-v0.5.0.md Decisión 3 (Opción 3A elegida).

Requisitos de la decisión ya aprobada, implementados aquí:
  - "Registro firmado por CA VTR" — cada entrada se firma con la llave
    privada de la Intermediate (la misma que firma certificados de
    dispositivo en la operación diaria, confirmado explícitamente).
  - "Logging append-only con hash chain" — cada entrada incluye el hash
    de la entrada anterior, formando una cadena verificable; borrar o
    reordenar una entrada rompe la cadena de forma detectable. Esto es
    una garantía MÁS FUERTE que server/compliance.py::AuditLog, que
    calcula SHA-256 por entrada de forma independiente (protege contra
    modificación de una fila, no contra borrado/reordenamiento — ver
    docstring de ese módulo, no se duplica aquí, se construye lo que
    falta).
  - Cifrado en reposo: decisión explícita confirmada (no asumir que
    LUKS del volumen ya resuelve esto — XChaCha20-Poly1305 a nivel de
    aplicación, independiente del cifrado de filesystem subyacente).

CORRECCIÓN DE NOMENCLATURA encontrada al implementar esto: el comentario
de core/crypto_transport.py describe su cifrado como "XChaCha20-Poly1305"
pero el código real usa nacl.secret.SecretBox, que según la
documentación oficial de PyNaCl implementa XSalsa20-Poly1305, no
XChaCha20-Poly1305 — son primitivas distintas (mismo tamaño de nonce de
24 bytes, mismo Poly1305, pero distinto stream cipher: XSalsa20 vs.
XChaCha20). Este módulo usa la primitiva correcta para XChaCha20-Poly1305
real: nacl.secret.Aead (confirmado contra la documentación oficial:
"Encryption for Aead: XChaCha20 stream cipher"). No se modifica
crypto_transport.py como parte de este trabajo — queda anotado aquí
como hallazgo a revisar en una sesión futura, fuera del alcance acordado
de hoy (vtr-provision.py).

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import nacl.secret
import nacl.utils

from crypto_layer.ed25519_sign import PUBLIC_KEY_LENGTH_BYTES, sign, verify
from crypto_layer.errors import (
    BundleIntegrityError,
    InvalidKeyLengthError,
    ProvisioningError,
)

logger = logging.getLogger(__name__)

GENESIS_HASH = b"\x00" * 32  # hash "anterior" de la primera entrada de la cadena
AEAD_KEY_SIZE = nacl.secret.Aead.KEY_SIZE  # 32 bytes
AEAD_NONCE_SIZE = nacl.secret.Aead.NONCE_SIZE  # 24 bytes

DEFAULT_REGISTRY_PATH = Path("/var/lib/vtr-continuity/device_registry.vtrdb")


class HashChainBrokenError(ProvisioningError):
    """
    La cadena de hashes del registro está rota — una entrada no enlaza
    correctamente con el hash de la entrada anterior.

    Esto indica borrado, reordenamiento, o modificación de una entrada
    — exactamente lo que el hash chain existe para detectar. Nunca se
    debe ignorar ni intentar "repararse" automáticamente: la respuesta
    correcta es investigación manual del registro y del bench.
    """


class RegistryEntrySignatureError(ProvisioningError):
    """
    La firma de una entrada del registro no verifica contra la llave
    pública de la Intermediate esperada.

    Puede indicar: (a) la entrada se firmó con una llave distinta a la
    Intermediate configurada para esta verificación, o (b) el contenido
    de la entrada fue modificado después de firmarse (lo cual también
    rompería el hash chain — ambos mecanismos se refuerzan entre sí,
    no son redundantes: el hash chain detecta orden/borrado, la firma
    detecta modificación de contenido incluso si alguien reconstruyera
    una cadena de hashes consistente).
    """


@dataclass
class DeviceRegistryEntry:
    """Una entrada ya escrita y verificada del registro."""

    device_id: str
    device_public_key: bytes
    provisioned_at: float
    intermediate_serial: str
    entry_hash: str
    previous_hash: str
    signature: bytes


def _canonical_entry_bytes(
    device_id: str,
    device_public_key: bytes,
    provisioned_at: float,
    intermediate_serial: str,
    previous_hash: str,
) -> bytes:
    """
    Serialización canónica de una entrada, usada tanto para calcular su
    hash como para firmarla — mismo principio de canonicalización fija
    ya aplicado en crypto_layer/vtrc_bundle.py (orden de campos fijo,
    nunca depende del orden de inserción de un dict).
    """
    canonical = json.dumps(
        {
            "device_id": device_id,
            "device_public_key": device_public_key.hex(),
            "provisioned_at": provisioned_at,
            "intermediate_serial": intermediate_serial,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return canonical.encode("utf-8")


def _validate_device_id(device_id: str) -> None:
    if device_id is None:
        raise InvalidKeyLengthError("device_id no puede ser None")
    if not isinstance(device_id, str):
        raise InvalidKeyLengthError(
            f"device_id debe ser str, recibido {type(device_id).__name__}"
        )
    if not device_id.strip():
        raise InvalidKeyLengthError("device_id no puede ser vacío")


def _validate_device_public_key(device_public_key: bytes) -> None:
    if device_public_key is None:
        raise InvalidKeyLengthError("device_public_key no puede ser None")
    if not isinstance(device_public_key, bytes):
        raise InvalidKeyLengthError(
            f"device_public_key debe ser bytes, recibido "
            f"{type(device_public_key).__name__}"
        )
    if len(device_public_key) != PUBLIC_KEY_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"device_public_key debe ser exactamente "
            f"{PUBLIC_KEY_LENGTH_BYTES} bytes, recibido "
            f"{len(device_public_key)}"
        )


class DeviceRegistry:
    """
    Registro append-only, cifrado, con hash chain y firma de cada
    entrada por la Intermediate — `device_registry.vtrdb`.

    Modelo de amenaza que este diseño cubre explícitamente:
      - Confidencialidad en reposo: XChaCha20-Poly1305 (nacl.secret.Aead)
        sobre cada entrada antes de escribir a SQLite — independiente
        de si el volumen subyacente tiene LUKS activo o no.
      - Integridad de orden/completitud: hash chain — cada entrada
        incluye SHA-256(entrada_anterior_completa), detectando
        borrado o reordenamiento de cualquier entrada previa.
      - Autenticidad de origen: firma Ed25519 de cada entrada con la
        llave privada de la Intermediate — detecta modificación de
        contenido incluso si alguien reconstruyera una cadena de
        hashes consistente desde cero.

    Estas tres propiedades son independientes y se verifican por
    separado en verify_chain() — un registro puede fallar una sin
    fallar las otras dos, y el código lo distingue explícitamente.
    """

    def __init__(
        self,
        registry_path: Path | str = DEFAULT_REGISTRY_PATH,
        encryption_key: bytes | None = None,
    ) -> None:
        if not registry_path:
            raise InvalidKeyLengthError("registry_path no puede ser vacío")

        if encryption_key is None:
            raise InvalidKeyLengthError(
                "encryption_key no puede ser None — DeviceRegistry nunca "
                "opera sin clave de cifrado explícita (mismo principio ya "
                "aplicado en RPiJWTVerifier: nunca operar sin material "
                "criptográfico válido cargado)"
            )
        if not isinstance(encryption_key, bytes):
            raise InvalidKeyLengthError(
                f"encryption_key debe ser bytes, recibido "
                f"{type(encryption_key).__name__}"
            )
        if len(encryption_key) != AEAD_KEY_SIZE:
            raise InvalidKeyLengthError(
                f"encryption_key debe ser exactamente {AEAD_KEY_SIZE} bytes, "
                f"recibido {len(encryption_key)}"
            )

        self._registry_path = Path(registry_path)
        self._registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._aead = nacl.secret.Aead(encryption_key)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self._registry_path),
                check_same_thread=False,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(
            """
            BEGIN;
            CREATE TABLE IF NOT EXISTS registry_entries (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_hash      TEXT    NOT NULL UNIQUE,
                previous_hash   TEXT    NOT NULL,
                nonce           BLOB    NOT NULL,
                ciphertext      BLOB    NOT NULL,
                created_at      REAL    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_registry_created_at
                ON registry_entries(created_at ASC);
            COMMIT;
            """
        )

    def _last_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT entry_hash FROM registry_entries ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else GENESIS_HASH.hex()

    def append(
        self,
        device_id: str,
        device_public_key: bytes,
        intermediate_serial: str,
        intermediate_private_key: bytes,
    ) -> DeviceRegistryEntry:
        """
        Agrega una nueva entrada al registro — la única forma de
        escribir; no existe ningún método update/delete, por diseño
        (append-only real, no solo por convención de nombres).

        Args:
            device_id: identificador lógico del dispositivo
                (`device-NNN.vtr.local`, según VTR-PKI-001 §3.3).
            device_public_key: 32 bytes, llave pública Ed25519 del
                dispositivo recién provisionado.
            intermediate_serial: identificador/serial de la
                Intermediate que firma esta entrada — permite, en el
                futuro, detectar entradas firmadas por una Intermediate
                ya rotada/revocada sin ambigüedad.
            intermediate_private_key: 32 bytes, llave privada Ed25519
                de la Intermediate — la misma que firma certificados de
                dispositivo en la operación diaria (decisión confirmada
                explícitamente, no una llave separada del bench).

        Returns:
            La entrada ya escrita, con su hash y firma calculados.

        Raises:
            InvalidKeyLengthError: validación defensiva de inputs.
        """
        _validate_device_id(device_id)
        _validate_device_public_key(device_public_key)
        if not intermediate_serial or not isinstance(intermediate_serial, str):
            raise InvalidKeyLengthError(
                "intermediate_serial debe ser str no vacío"
            )
        if intermediate_private_key is None or not isinstance(
            intermediate_private_key, bytes
        ):
            raise InvalidKeyLengthError(
                "intermediate_private_key debe ser bytes no None"
            )

        provisioned_at = time.time()
        conn = self._get_conn()

        conn.execute("BEGIN")
        try:
            previous_hash = self._last_hash(conn)

            entry_bytes = _canonical_entry_bytes(
                device_id,
                device_public_key,
                provisioned_at,
                intermediate_serial,
                previous_hash,
            )
            entry_hash = hashlib.sha256(entry_bytes).hexdigest()
            signature = sign(entry_bytes, intermediate_private_key)

            plaintext_record = json.dumps(
                {
                    "device_id": device_id,
                    "device_public_key": device_public_key.hex(),
                    "provisioned_at": provisioned_at,
                    "intermediate_serial": intermediate_serial,
                    "previous_hash": previous_hash,
                    "entry_hash": entry_hash,
                    "signature": signature.hex(),
                },
                sort_keys=True,
                ensure_ascii=False,
            ).encode("utf-8")

            encrypted = self._aead.encrypt(plaintext_record)

            conn.execute(
                """
                INSERT INTO registry_entries
                    (entry_hash, previous_hash, nonce, ciphertext, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    entry_hash,
                    previous_hash,
                    encrypted.nonce,
                    encrypted.ciphertext,
                    provisioned_at,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        logger.info(
            "[device_registry] entrada agregada — device_id=%s entry_hash=%s",
            device_id,
            entry_hash[:16],
        )

        return DeviceRegistryEntry(
            device_id=device_id,
            device_public_key=device_public_key,
            provisioned_at=provisioned_at,
            intermediate_serial=intermediate_serial,
            entry_hash=entry_hash,
            previous_hash=previous_hash,
            signature=signature,
        )

    def _decrypt_entry(self, row: sqlite3.Row) -> dict[str, Any]:
        plaintext = self._aead.decrypt(row["ciphertext"], nonce=row["nonce"])
        return json.loads(plaintext.decode("utf-8"))

    def get_all(self) -> list[DeviceRegistryEntry]:
        """Lee y descifra todas las entradas, en orden de inserción."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM registry_entries ORDER BY id ASC"
        ).fetchall()

        entries = []
        for row in rows:
            data = self._decrypt_entry(row)
            entries.append(
                DeviceRegistryEntry(
                    device_id=data["device_id"],
                    device_public_key=bytes.fromhex(data["device_public_key"]),
                    provisioned_at=data["provisioned_at"],
                    intermediate_serial=data["intermediate_serial"],
                    entry_hash=data["entry_hash"],
                    previous_hash=data["previous_hash"],
                    signature=bytes.fromhex(data["signature"]),
                )
            )
        return entries

    def verify_chain(self, intermediate_public_key: bytes) -> bool:
        """
        Verifica las tres propiedades del registro completo:
        (1) la cadena de hashes es consistente desde el génesis,
        (2) cada entry_hash coincide con el hash recalculado de su
            propio contenido canónico, y
        (3) cada firma verifica contra intermediate_public_key.

        Returns:
            True si las tres verificaciones pasan para TODAS las
            entradas. False si cualquiera falla en cualquier entrada —
            no se distingue cuál falló en el valor de retorno (usar
            verify_chain_detailed() — no implementado en esta versión,
            ver §4 de la especificación — para diagnóstico granular).

        Raises:
            InvalidKeyLengthError: si intermediate_public_key es
                inválida en tipo o longitud.
        """
        if intermediate_public_key is None:
            raise InvalidKeyLengthError("intermediate_public_key no puede ser None")
        if not isinstance(intermediate_public_key, bytes):
            raise InvalidKeyLengthError(
                f"intermediate_public_key debe ser bytes, recibido "
                f"{type(intermediate_public_key).__name__}"
            )
        if len(intermediate_public_key) != PUBLIC_KEY_LENGTH_BYTES:
            raise InvalidKeyLengthError(
                f"intermediate_public_key debe ser exactamente "
                f"{PUBLIC_KEY_LENGTH_BYTES} bytes, recibido "
                f"{len(intermediate_public_key)}"
            )

        entries = self.get_all()
        expected_previous = GENESIS_HASH.hex()

        for entry in entries:
            if entry.previous_hash != expected_previous:
                logger.error(
                    "[device_registry] cadena rota en device_id=%s — "
                    "previous_hash no coincide con la entrada anterior",
                    entry.device_id,
                )
                return False

            recomputed_bytes = _canonical_entry_bytes(
                entry.device_id,
                entry.device_public_key,
                entry.provisioned_at,
                entry.intermediate_serial,
                entry.previous_hash,
            )
            recomputed_hash = hashlib.sha256(recomputed_bytes).hexdigest()
            if recomputed_hash != entry.entry_hash:
                logger.error(
                    "[device_registry] hash de contenido no coincide en "
                    "device_id=%s — entrada modificada después de escrita",
                    entry.device_id,
                )
                return False

            if not verify(recomputed_bytes, entry.signature, intermediate_public_key):
                logger.error(
                    "[device_registry] firma inválida en device_id=%s",
                    entry.device_id,
                )
                return False

            expected_previous = entry.entry_hash

        return True
