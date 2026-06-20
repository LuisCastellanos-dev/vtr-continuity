"""
crypto_layer/vtrc_bundle.py — Formato canonical del bundle .vtrc.

Checklist pre-release post-#10 (docs/DOD-v0.5.0.md §5) — módulo de
formato de bundle, explícitamente fuera de alcance de la propuesta #7
(ver docstring de crypto_layer/ed25519_sign.py, sección
"DESACOPLAMIENTO DELIBERADO"): ese módulo es una primitiva genérica que
no conoce qué es un "header", un "payload" ni una "metadata" — esa
estructura vive aquí.

Implementa la decisión de Q-02 (docs/VTR-ARCH-DECISIONS-001.md): el par
(node_id, counter) viaja DENTRO del bundle, no se infiere del RTC del
receptor ni de un canal de sincronización que no existe en air-gapped.

Formato canonical (orden fijo, según specs/PROPOSALS-10.md §7):
    bytes_a_firmar = header || payload || metadata
    (con el campo signature del header puesto a cero antes de firmar)

Estructura del bundle serializado (todos los campos en orden fijo):

    HEADER (longitud fija, ver HEADER_FORMAT):
        magic           (4 bytes)  — b"VTRC", identifica el formato
        format_version  (1 byte)   — 1 para esta versión
        node_id         (8 bytes)  — identificador del nodo emisor
        counter         (8 bytes)  — NonceCounter del emisor (Q-02)
        payload_length  (4 bytes)  — bytes exactos del payload que sigue
        metadata_length (2 bytes)  — bytes exactos de la metadata que sigue
        created_at_hint (8 bytes)  — timestamp informativo, NUNCA usado
                                      para anti-replay (ver Q-02:
                                      el RTC no es parte de la cadena
                                      de confianza)
        signature       (64 bytes) — Ed25519, puesta a cero antes de firmar

    PAYLOAD (longitud variable, payload_length bytes):
        bytes ya cifrados por Capa 1 (core.crypto_transport.EncryptedBundle
        serializado) — este módulo no descifra ni interpreta el payload,
        solo lo transporta firmado. Mismo principio de desacoplamiento que
        ed25519_sign.py: cada capa resuelve un problema, no todos a la vez.

    METADATA (longitud variable, metadata_length bytes):
        JSON UTF-8 con campos operativos no críticos para seguridad
        (ej. {"origin_hint": "bench-tampico", "purpose": "telemetry"}).
        Nunca contiene secretos ni material criptográfico — viaja en claro
        dentro del bundle firmado, solo para trazabilidad operativa.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import json
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crypto_layer.ed25519_sign import (
    PUBLIC_KEY_LENGTH_BYTES,
    SIGNATURE_LENGTH_BYTES,
    sign,
    verify,
)
from crypto_layer.errors import (
    BundleIntegrityError,
    InvalidKeyLengthError,
    SignatureVerificationError,
)

MAGIC = b"VTRC"
FORMAT_VERSION = 1

# Tamaños fijos de cada campo del header, en bytes.
MAGIC_SIZE = 4
FORMAT_VERSION_SIZE = 1
NODE_ID_SIZE = 8
COUNTER_SIZE = 8
PAYLOAD_LENGTH_SIZE = 4
METADATA_LENGTH_SIZE = 2
CREATED_AT_HINT_SIZE = 8
SIGNATURE_SIZE = SIGNATURE_LENGTH_BYTES  # 64, reusa la constante de ed25519_sign

HEADER_SIZE = (
    MAGIC_SIZE
    + FORMAT_VERSION_SIZE
    + NODE_ID_SIZE
    + COUNTER_SIZE
    + PAYLOAD_LENGTH_SIZE
    + METADATA_LENGTH_SIZE
    + CREATED_AT_HINT_SIZE
    + SIGNATURE_SIZE
)

# struct format string para el header SIN la firma (esa va al final,
# se empaqueta aparte porque se pone a cero antes de firmar y se
# reemplaza después — empaquetarla junto complicaría esa sustitución).
_HEADER_STRUCT_NO_SIG = ">4sBQQIHQ"  # magic, version, node_id, counter, payload_len, metadata_len, created_at_hint

# Alineado con config/rf_config.yaml sección sneakernet:
#   bundle_max_size_mb: 64
MAX_BUNDLE_SIZE_BYTES = 64 * 1024 * 1024

DEFAULT_COUNTER_VERIFICATION_DB = Path("/var/lib/vtr-continuity/vtrc_counter_seen.db")


@dataclass
class VtrcBundle:
    """Bundle .vtrc ya parseado, antes o después de verificar firma."""

    node_id: bytes
    counter: int
    payload: bytes
    metadata: dict[str, Any]
    created_at_hint: float
    signature: bytes
    format_version: int = FORMAT_VERSION


def _validate_node_id(node_id: bytes) -> None:
    if node_id is None:
        raise InvalidKeyLengthError("node_id no puede ser None")
    if not isinstance(node_id, bytes):
        raise InvalidKeyLengthError(
            f"node_id debe ser bytes, recibido {type(node_id).__name__}"
        )
    if len(node_id) != NODE_ID_SIZE:
        raise InvalidKeyLengthError(
            f"node_id debe ser exactamente {NODE_ID_SIZE} bytes, "
            f"recibido {len(node_id)}"
        )


def _validate_counter(counter: int) -> None:
    if counter is None:
        raise InvalidKeyLengthError("counter no puede ser None")
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise InvalidKeyLengthError(
            f"counter debe ser int, recibido {type(counter).__name__}"
        )
    if counter <= 0:
        raise InvalidKeyLengthError("counter debe ser > 0 (NonceCounter empieza en 1)")
    if counter > (2**64 - 1):
        raise InvalidKeyLengthError("counter excede el rango de 8 bytes sin signo")


def _validate_payload(payload: bytes) -> None:
    if payload is None:
        raise InvalidKeyLengthError("payload no puede ser None")
    if not isinstance(payload, bytes):
        raise InvalidKeyLengthError(
            f"payload debe ser bytes, recibido {type(payload).__name__}"
        )
    if len(payload) == 0:
        raise InvalidKeyLengthError("payload no puede ser vacío")
    if len(payload) > (2**32 - 1):
        raise InvalidKeyLengthError("payload excede el rango de 4 bytes sin signo")


def _validate_metadata(metadata: dict[str, Any]) -> bytes:
    """Valida y serializa metadata a JSON UTF-8. Retorna los bytes."""
    if metadata is None:
        raise InvalidKeyLengthError("metadata no puede ser None")
    if not isinstance(metadata, dict):
        raise InvalidKeyLengthError(
            f"metadata debe ser dict, recibido {type(metadata).__name__}"
        )
    try:
        metadata_bytes = json.dumps(
            metadata, separators=(",", ":"), ensure_ascii=False, sort_keys=True
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvalidKeyLengthError(f"metadata no es serializable a JSON: {exc}") from exc
    if len(metadata_bytes) > (2**16 - 1):
        raise InvalidKeyLengthError(
            f"metadata serializada ({len(metadata_bytes)} bytes) excede "
            f"el rango de 2 bytes sin signo (máx {2**16 - 1})"
        )
    return metadata_bytes


def _pack_header(
    node_id: bytes,
    counter: int,
    payload_length: int,
    metadata_length: int,
    created_at_hint: float,
    signature: bytes,
) -> bytes:
    """Empaqueta el header completo, incluyendo la firma (real o ceros)."""
    fixed = struct.pack(
        _HEADER_STRUCT_NO_SIG,
        MAGIC,
        FORMAT_VERSION,
        int.from_bytes(node_id, "big"),
        counter,
        payload_length,
        metadata_length,
        int(created_at_hint),
    )
    return fixed + signature


def _canonical_bytes(
    node_id: bytes,
    counter: int,
    payload: bytes,
    metadata_bytes: bytes,
    created_at_hint: float,
    signature_placeholder: bytes,
) -> bytes:
    """
    Construye header||payload||metadata con la firma puesta a cero,
    exactamente como especifica specs/PROPOSALS-10.md §7 para la
    propuesta #7 (canonicalización que ese módulo dejó pendiente).
    """
    header = _pack_header(
        node_id=node_id,
        counter=counter,
        payload_length=len(payload),
        metadata_length=len(metadata_bytes),
        created_at_hint=created_at_hint,
        signature=signature_placeholder,
    )
    return header + payload + metadata_bytes


def build_bundle(
    node_id: bytes,
    counter: int,
    payload: bytes,
    private_key: bytes,
    metadata: dict[str, Any] | None = None,
    created_at_hint: float | None = None,
) -> bytes:
    """
    Construye un bundle .vtrc firmado, listo para escribir a disco/USB.

    Args:
        node_id: 8 bytes, identificador del nodo emisor. Debe coincidir
            con el node_id que el NonceCounter del emisor ya usa
            internamente — este módulo no genera node_id, lo recibe.
        counter: el counter que el NonceCounter del emisor ya generó
            para este envío (mismo valor que el nonce de Capa 1 ya usa).
            No es responsabilidad de este módulo avanzar el counter —
            solo lo transporta.
        payload: bytes ya procesados por Capa 1
            (core.crypto_transport.EncryptedBundle serializado, o
            cualquier blob ya cifrado). Este módulo no interpreta el
            contenido.
        private_key: 32 bytes, llave privada Ed25519 del nodo emisor
            (la misma usada por CryptoTransport para firmar tráfico en
            vivo — ver VTR-PKI-001 para la jerarquía de llaves).
        metadata: diccionario JSON-serializable con información operativa
            no sensible (ej. {"purpose": "telemetry"}). Default {} si
            no se especifica.
        created_at_hint: timestamp Unix informativo. Si no se especifica,
            usa time.time(). NUNCA se usa para anti-replay — ver Q-02.

    Returns:
        bytes del bundle .vtrc completo, serializado y firmado, listo
        para escribir a un archivo .vtrc.

    Raises:
        InvalidKeyLengthError: validación defensiva de cualquier input
            (VTR-CRYPTO-003) — None, tipo incorrecto, longitud incorrecta,
            o tamaño que excede el bundle máximo configurado.
    """
    _validate_node_id(node_id)
    _validate_counter(counter)
    _validate_payload(payload)
    metadata_bytes = _validate_metadata(metadata or {})

    if created_at_hint is None:
        created_at_hint = time.time()
    if not isinstance(created_at_hint, (int, float)):
        raise InvalidKeyLengthError("created_at_hint debe ser numérico")

    if private_key is None:
        raise InvalidKeyLengthError("private_key no puede ser None")
    if not isinstance(private_key, bytes):
        raise InvalidKeyLengthError(
            f"private_key debe ser bytes, recibido {type(private_key).__name__}"
        )

    zero_signature = b"\x00" * SIGNATURE_SIZE
    to_sign = _canonical_bytes(
        node_id, counter, payload, metadata_bytes, created_at_hint, zero_signature
    )

    estimated_size = len(to_sign) + SIGNATURE_SIZE
    if estimated_size > MAX_BUNDLE_SIZE_BYTES:
        raise InvalidKeyLengthError(
            f"bundle resultante ({estimated_size} bytes) excede "
            f"MAX_BUNDLE_SIZE_BYTES ({MAX_BUNDLE_SIZE_BYTES}) — "
            f"alineado con rf_config.yaml sneakernet.bundle_max_size_mb"
        )

    signature = sign(to_sign, private_key)

    return _canonical_bytes(
        node_id, counter, payload, metadata_bytes, created_at_hint, signature
    )


def parse_bundle(raw: bytes) -> VtrcBundle:
    """
    Parsea un bundle .vtrc SIN verificar su firma.

    Separado deliberadamente de verify_bundle(): parsear estructura y
    verificar autenticidad son operaciones distintas (mismo principio de
    capability separation que crypto_layer/__init__.py ya aplica para
    derive_device_key/derive_operator_key). Un bundle puede parsearse
    para inspección/debugging sin necesitar la llave pública del emisor
    a mano.

    Args:
        raw: bytes del bundle .vtrc completo.

    Returns:
        VtrcBundle con los campos extraídos. El campo `signature` queda
        disponible para que verify_bundle() la use después.

    Raises:
        BundleIntegrityError: si el bundle está truncado, tiene magic
            number incorrecto, format_version no reconocida, o las
            longitudes declaradas en el header no coinciden con los
            bytes realmente presentes.
    """
    if raw is None:
        raise InvalidKeyLengthError("raw no puede ser None")
    if not isinstance(raw, bytes):
        raise InvalidKeyLengthError(
            f"raw debe ser bytes, recibido {type(raw).__name__}"
        )
    if len(raw) < HEADER_SIZE:
        raise BundleIntegrityError(
            f"bundle truncado: {len(raw)} bytes, mínimo {HEADER_SIZE} "
            f"(header completo)"
        )
    if len(raw) > MAX_BUNDLE_SIZE_BYTES:
        raise BundleIntegrityError(
            f"bundle ({len(raw)} bytes) excede MAX_BUNDLE_SIZE_BYTES "
            f"({MAX_BUNDLE_SIZE_BYTES})"
        )

    fixed_size = HEADER_SIZE - SIGNATURE_SIZE
    fixed_part = raw[:fixed_size]
    signature = raw[fixed_size:HEADER_SIZE]

    try:
        (
            magic,
            format_version,
            node_id_int,
            counter,
            payload_length,
            metadata_length,
            created_at_hint_int,
        ) = struct.unpack(_HEADER_STRUCT_NO_SIG, fixed_part)
    except struct.error as exc:
        raise BundleIntegrityError(f"header malformado: {exc}") from exc

    if magic != MAGIC:
        raise BundleIntegrityError(
            f"magic number incorrecto: esperado {MAGIC!r}, recibido {magic!r} — "
            f"no es un bundle .vtrc válido"
        )
    if format_version != FORMAT_VERSION:
        raise BundleIntegrityError(
            f"format_version no reconocida: {format_version} "
            f"(esta versión del parser solo soporta {FORMAT_VERSION})"
        )

    node_id = node_id_int.to_bytes(NODE_ID_SIZE, "big")

    expected_total = HEADER_SIZE + payload_length + metadata_length
    if len(raw) != expected_total:
        raise BundleIntegrityError(
            f"longitud declarada en header ({expected_total} bytes) no "
            f"coincide con bytes recibidos ({len(raw)}) — bundle corrupto "
            f"o truncado"
        )

    payload_start = HEADER_SIZE
    payload_end = payload_start + payload_length
    payload = raw[payload_start:payload_end]

    metadata_start = payload_end
    metadata_end = metadata_start + metadata_length
    metadata_bytes = raw[metadata_start:metadata_end]

    try:
        metadata = json.loads(metadata_bytes.decode("utf-8")) if metadata_bytes else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BundleIntegrityError(f"metadata JSON inválida: {exc}") from exc
    if not isinstance(metadata, dict):
        raise BundleIntegrityError("metadata deserializada no es un diccionario")

    return VtrcBundle(
        node_id=node_id,
        counter=counter,
        payload=payload,
        metadata=metadata,
        created_at_hint=float(created_at_hint_int),
        signature=signature,
        format_version=format_version,
    )


def verify_bundle(raw: bytes, public_key: bytes) -> bool:
    """
    Verifica la firma Ed25519 de un bundle .vtrc completo.

    NO verifica replay (eso es responsabilidad de
    CounterVerificationStore.check_and_record, ver más abajo — mismo
    principio de capability separation: una función verifica
    autenticidad, otra verifica unicidad). NO lanza excepción si la
    firma es inválida ni si el bundle está corrupto — ambos casos
    retornan False, siguiendo el contrato ya establecido por
    ed25519_sign.verify() (una firma inválida es un resultado esperado,
    no una condición excepcional).

    Args:
        raw: bytes del bundle .vtrc completo.
        public_key: 32 bytes, llave pública Ed25519 del nodo emisor
            esperado.

    Returns:
        True si el bundle es estructuralmente válido Y su firma es
        correcta para el contenido y la llave pública dados.
        False en cualquier otro caso — bundle corrupto, magic
        incorrecto, firma inválida, o llave pública equivocada.

    Raises:
        InvalidKeyLengthError: si raw o public_key son None, de tipo
            incorrecto, o public_key no tiene 32 bytes — estos son
            errores de uso de la API, no "firma incorrecta".
    """
    if public_key is None:
        raise InvalidKeyLengthError("public_key no puede ser None")
    if not isinstance(public_key, bytes):
        raise InvalidKeyLengthError(
            f"public_key debe ser bytes, recibido {type(public_key).__name__}"
        )
    if len(public_key) != PUBLIC_KEY_LENGTH_BYTES:
        raise InvalidKeyLengthError(
            f"public_key debe ser exactamente {PUBLIC_KEY_LENGTH_BYTES} "
            f"bytes, recibido {len(public_key)}"
        )

    try:
        bundle = parse_bundle(raw)
    except BundleIntegrityError:
        return False
    except InvalidKeyLengthError:
        raise

    metadata_bytes = json.dumps(
        bundle.metadata, separators=(",", ":"), ensure_ascii=False, sort_keys=True
    ).encode("utf-8")

    zero_signature = b"\x00" * SIGNATURE_SIZE
    to_verify = _canonical_bytes(
        bundle.node_id,
        bundle.counter,
        bundle.payload,
        metadata_bytes,
        bundle.created_at_hint,
        zero_signature,
    )

    try:
        return verify(to_verify, bundle.signature, public_key)
    except (InvalidKeyLengthError, SignatureVerificationError):
        return False


class CounterVerificationStore:
    """
    Verificación de replay para bundles .vtrc sin sesión (Q-02).

    Estructura SQL deliberadamente paralela a
    core.crypto_transport.NonceCounter — mismo patrón (persistencia
    monotónica, nunca el RTC), aplicado en modo VERIFICACIÓN en vez de
    GENERACIÓN. Un emisor usa NonceCounter para producir su propio
    counter; un receptor usa esta clase para recordar el counter más
    alto que ya vio de cada node_id remoto.

    No comparte tabla ni base de datos con NonceCounter — son procesos
    distintos en máquinas distintas (NonceCounter vive en el emisor,
    esto vive en el receptor) — pero si en algún momento ambos
    coexistieran en el mismo proceso, deben usar archivos .db separados
    para no mezclar "mi counter" con "el counter más alto que vi de
    otros".
    """

    def __init__(
        self, db_path: Path | str = DEFAULT_COUNTER_VERIFICATION_DB
    ) -> None:
        if not db_path:
            raise InvalidKeyLengthError("db_path no puede ser vacío")
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self._db_path), check_same_thread=False, isolation_level=None
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(
            """
            BEGIN;
            CREATE TABLE IF NOT EXISTS counter_seen (
                node_id_hex   TEXT PRIMARY KEY,
                max_counter   INTEGER NOT NULL DEFAULT 0,
                updated_at    REAL    NOT NULL
            );
            COMMIT;
            """
        )

    def check_and_record(self, node_id: bytes, counter: int) -> bool:
        """
        Verifica que counter sea mayor que el máximo ya visto para este
        node_id, y si es así, lo registra como el nuevo máximo.

        Returns:
            True si el counter es nuevo (no es replay) y fue registrado.
            False si counter <= max_counter ya visto — replay detectado,
            el bundle debe rechazarse sin importar su created_at_hint.

        Nota sobre primer contacto: si node_id nunca se vio antes,
        cualquier counter > 0 se acepta y se registra — riesgo residual
        documentado explícitamente en VTR-ARCH-DECISIONS-001.md Q-02
        (ventana de explotación estrecha: requiere que el atacante
        capture y reproduzca el PRIMER bundle de un nodo legítimo antes
        de que el original llegue, y aun así necesita pasar
        verify_bundle() con la firma real del emisor).
        """
        if not node_id or not isinstance(node_id, bytes):
            return False
        if not isinstance(counter, int) or isinstance(counter, bool) or counter <= 0:
            return False

        node_hex = node_id.hex()
        conn = self._get_conn()
        conn.execute("BEGIN EXCLUSIVE")
        try:
            row = conn.execute(
                "SELECT max_counter FROM counter_seen WHERE node_id_hex = ?",
                (node_hex,),
            ).fetchone()
            max_counter = row[0] if row else 0

            if counter <= max_counter:
                conn.execute("ROLLBACK")
                return False

            conn.execute(
                """
                INSERT INTO counter_seen (node_id_hex, max_counter, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(node_id_hex) DO UPDATE SET
                    max_counter = excluded.max_counter,
                    updated_at = excluded.updated_at
                """,
                (node_hex, counter, time.time()),
            )
            conn.execute("COMMIT")
            return True
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def max_counter_seen(self, node_id: bytes) -> int:
        """Retorna el counter más alto visto para node_id, o 0 si nunca se vio."""
        if not node_id or not isinstance(node_id, bytes):
            return 0
        node_hex = node_id.hex()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT max_counter FROM counter_seen WHERE node_id_hex = ?",
            (node_hex,),
        ).fetchone()
        return row[0] if row else 0
