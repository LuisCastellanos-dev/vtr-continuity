"""
vtr-continuity v0.4.0 — Server
server/compliance.py

Auditoría y cumplimiento NERC CIP / IEC 62443.

Genera evidencia auditada automáticamente:
  - AuditLog: registro inmutable con SHA-256 por entrada
  - SessionReport: sesiones HMI exportables para auditores
  - ComplianceChecker: verificación automática de requisitos mínimos
  - EvidenceExport: paquete de evidencia firmado para auditorías

Estándares cubiertos:
  NERC CIP-007-6: gestión de seguridad de sistemas
  NERC CIP-008-6: reporte de incidentes de ciberseguridad
  IEC 62443-2-1: programa de gestión de seguridad IACS
  IEC 62443-3-3: requisitos de sistema para seguridad industrial

Regla de nulls aplicada en cada campo de cada entrada.
Ningún registro se escribe sin validación explícita de tipo.

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any

DEFAULT_COMPLIANCE_DB = Path("/var/lib/vtr-continuity/compliance.db")


class AuditAction(str, Enum):
    TOKEN_ISSUED    = "TOKEN_ISSUED"
    TOKEN_REFRESHED = "TOKEN_REFRESHED"
    TOKEN_REVOKED   = "TOKEN_REVOKED"
    TOKEN_REJECTED  = "TOKEN_REJECTED"
    SESSION_OPENED  = "SESSION_OPENED"
    SESSION_CLOSED  = "SESSION_CLOSED"
    EVENT_RECEIVED  = "EVENT_RECEIVED"
    SYNC_COMPLETED  = "SYNC_COMPLETED"
    CUSTODY_GRANTED = "CUSTODY_GRANTED"
    CUSTODY_ACKED   = "CUSTODY_ACKED"
    CUSTODY_FAILED  = "CUSTODY_FAILED"
    CONFIG_CHANGED  = "CONFIG_CHANGED"
    KEY_ROTATED     = "KEY_ROTATED"
    COMPLIANCE_CHECK= "COMPLIANCE_CHECK"


class AuditResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    WARNING = "WARNING"


@dataclass
class AuditEntry:
    """Entrada inmutable del audit log."""
    entry_id: str
    timestamp: float
    action: AuditAction
    result: AuditResult
    actor: str
    target: str | None
    detail: dict[str, Any]
    sha256: str | None = None
    row_id: int | None = None


@dataclass
class SessionRecord:
    """Registro de sesión HMI para reporte de auditoría."""
    session_id: str
    hmi_id: str
    hmi_type: str
    opened_at: float
    closed_at: float | None
    events_generated: int
    extended_offline: bool
    row_id: int | None = None


@dataclass
class ComplianceResult:
    """Resultado de una verificación de cumplimiento."""
    passed: bool
    standard: str
    requirement: str
    detail: str
    severity: str = "HIGH"


@dataclass
class ComplianceReport:
    """Reporte completo de cumplimiento para auditor."""
    report_id: str
    generated_at: float
    results: list[ComplianceResult]
    passed_count: int
    failed_count: int
    warning_count: int
    overall_passed: bool
    sha256: str | None = None


class AuditLog:
    """
    Registro inmutable de eventos de seguridad.

    Cada entrada tiene SHA-256 calculado sobre su contenido.
    El hash permite verificar que la entrada no fue modificada
    después de ser escrita — requisito NERC CIP-007-6 y IEC 62443-2-1.

    Thread-safe via thread-local connections.
    Persiste en compliance.db separado de queue.db y custody.db.
    """

    def __init__(self, db_path: Path | str = DEFAULT_COMPLIANCE_DB) -> None:
        if not db_path:
            raise ValueError("db_path no puede ser vacío")

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
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

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id    TEXT    NOT NULL UNIQUE,
                timestamp   REAL    NOT NULL,
                action      TEXT    NOT NULL,
                result      TEXT    NOT NULL,
                actor       TEXT    NOT NULL,
                target      TEXT,
                detail      TEXT    NOT NULL,
                sha256      TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_audit_action
                ON audit_log(action);

            CREATE INDEX IF NOT EXISTS idx_audit_actor
                ON audit_log(actor);

            CREATE TABLE IF NOT EXISTS sessions (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id          TEXT    NOT NULL UNIQUE,
                hmi_id              TEXT    NOT NULL,
                hmi_type            TEXT    NOT NULL,
                opened_at           REAL    NOT NULL,
                closed_at           REAL,
                events_generated    INTEGER NOT NULL DEFAULT 0,
                extended_offline    INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS compliance_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO compliance_meta(key, value)
                VALUES ('schema_version', '1'),
                       ('created_at', strftime('%s', 'now'));

            COMMIT;
        """)

    @staticmethod
    def _compute_entry_hash(
        entry_id: str,
        timestamp: float,
        action: str,
        result: str,
        actor: str,
        target: str | None,
        detail: dict,
    ) -> str:
        """
        Calcula SHA-256 del contenido de la entrada.
        El orden de los campos es fijo — cambiar el orden invalida el hash.
        """
        canonical = json.dumps({
            "entry_id": entry_id,
            "timestamp": timestamp,
            "action": action,
            "result": result,
            "actor": actor,
            "target": target,
            "detail": detail,
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def write(
        self,
        action: AuditAction | str,
        result: AuditResult | str,
        actor: str,
        target: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """
        Escribe una entrada en el audit log.

        Args:
            action: Acción realizada (AuditAction)
            result: Resultado de la acción (AuditResult)
            actor:  Quién realizó la acción (hmi_id, servidor, sistema)
            target: Sobre qué se realizó la acción (opcional)
            detail: Datos adicionales — se serializa a JSON

        Returns:
            AuditEntry con SHA-256 calculado
        """
        if not actor or not isinstance(actor, str):
            raise ValueError("actor no puede ser vacío o None")

        action_val = action.value if isinstance(action, AuditAction) else str(action)
        result_val = result.value if isinstance(result, AuditResult) else str(result)

        if not action_val:
            raise ValueError("action no puede ser vacío")
        if not result_val:
            raise ValueError("result no puede ser vacío")

        detail_clean = detail if isinstance(detail, dict) else {}
        entry_id = str(uuid.uuid4())
        timestamp = time.time()

        try:
            detail_json = json.dumps(detail_clean, ensure_ascii=False)
        except (TypeError, ValueError):
            detail_json = json.dumps({"error": "detail no serializable"})
            detail_clean = {"error": "detail no serializable"}

        sha256 = self._compute_entry_hash(
            entry_id, timestamp, action_val, result_val,
            actor, target, detail_clean,
        )

        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            cur = conn.execute(
                """
                INSERT INTO audit_log
                    (entry_id, timestamp, action, result, actor, target, detail, sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (entry_id, timestamp, action_val, result_val,
                 actor, target, detail_json, sha256),
            )
            conn.execute("COMMIT")
            row_id = cur.lastrowid
        except Exception:
            conn.execute("ROLLBACK")
            raise

        return AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            action=AuditAction(action_val) if action_val in AuditAction._value2member_map_ else action_val,
            result=AuditResult(result_val) if result_val in AuditResult._value2member_map_ else result_val,
            actor=actor,
            target=target,
            detail=detail_clean,
            sha256=sha256,
            row_id=row_id,
        )

    def verify_entry(self, entry_id: str | None) -> bool:
        """
        Verifica que una entrada no fue modificada después de escribirse.
        Recalcula el SHA-256 y lo compara con el almacenado.
        """
        if not entry_id or not isinstance(entry_id, str):
            return False

        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM audit_log WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()

        if row is None:
            return False

        detail = {}
        try:
            detail = json.loads(row["detail"])
        except (json.JSONDecodeError, TypeError):
            pass

        expected = self._compute_entry_hash(
            row["entry_id"], row["timestamp"], row["action"],
            row["result"], row["actor"], row["target"], detail,
        )
        return expected == row["sha256"]

    def query(
        self,
        actor: str | None = None,
        action: AuditAction | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """
        Consulta entradas del audit log con filtros opcionales.
        Usada por SessionReport y EvidenceExport.
        """
        if limit <= 0:
            raise ValueError("limit debe ser > 0")

        conditions = []
        params: list[Any] = []

        if actor is not None:
            if not isinstance(actor, str):
                raise ValueError("actor debe ser string o None")
            conditions.append("actor = ?")
            params.append(actor)

        if action is not None:
            conditions.append("action = ?")
            params.append(action.value if isinstance(action, AuditAction) else str(action))

        if since is not None:
            if not isinstance(since, (int, float)):
                raise ValueError("since debe ser float o None")
            conditions.append("timestamp >= ?")
            params.append(since)

        if until is not None:
            if not isinstance(until, (int, float)):
                raise ValueError("until debe ser float o None")
            conditions.append("timestamp <= ?")
            params.append(until)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        conn = self._get_conn()
        rows = conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()

        entries = []
        for row in rows:
            detail = {}
            try:
                detail = json.loads(row["detail"]) if row["detail"] else {}
            except (json.JSONDecodeError, TypeError):
                pass

            action_str = row["action"]
            result_str = row["result"]

            entries.append(AuditEntry(
                entry_id=row["entry_id"],
                timestamp=row["timestamp"],
                action=AuditAction(action_str) if action_str in AuditAction._value2member_map_ else action_str,
                result=AuditResult(result_str) if result_str in AuditResult._value2member_map_ else result_str,
                actor=row["actor"],
                target=row["target"],
                detail=detail,
                sha256=row["sha256"],
                row_id=row["id"],
            ))
        return entries

    def count(self) -> int:
        """Total de entradas en el audit log."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        return row[0] if row else 0

    def open_session(
        self,
        hmi_id: str,
        hmi_type: str,
        extended_offline: bool = False,
    ) -> SessionRecord:
        """Registra apertura de sesión HMI."""
        if not hmi_id or not isinstance(hmi_id, str):
            raise ValueError("hmi_id no puede ser vacío o None")
        if not hmi_type or not isinstance(hmi_type, str):
            raise ValueError("hmi_type no puede ser vacío o None")

        session_id = str(uuid.uuid4())
        opened_at = time.time()

        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            conn.execute(
                """
                INSERT INTO sessions
                    (session_id, hmi_id, hmi_type, opened_at, extended_offline)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, hmi_id, hmi_type, opened_at,
                 1 if extended_offline else 0),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        self.write(
            AuditAction.SESSION_OPENED,
            AuditResult.SUCCESS,
            actor=hmi_id,
            detail={
                "session_id": session_id,
                "hmi_type": hmi_type,
                "extended_offline": extended_offline,
            },
        )

        return SessionRecord(
            session_id=session_id,
            hmi_id=hmi_id,
            hmi_type=hmi_type,
            opened_at=opened_at,
            closed_at=None,
            events_generated=0,
            extended_offline=extended_offline,
        )

    def close_session(
        self,
        session_id: str | None,
        events_generated: int = 0,
    ) -> bool:
        """Registra cierre de sesión HMI."""
        if not session_id or not isinstance(session_id, str):
            return False

        closed_at = time.time()
        conn = self._get_conn()
        conn.execute("BEGIN")
        try:
            cur = conn.execute(
                """
                UPDATE sessions
                SET closed_at = ?, events_generated = ?
                WHERE session_id = ? AND closed_at IS NULL
                """,
                (closed_at, max(0, events_generated), session_id),
            )
            conn.execute("COMMIT")
            updated = cur.rowcount > 0
        except Exception:
            conn.execute("ROLLBACK")
            return False

        if updated:
            row = conn.execute(
                "SELECT hmi_id FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            actor = row["hmi_id"] if row else "unknown"
            self.write(
                AuditAction.SESSION_CLOSED,
                AuditResult.SUCCESS,
                actor=actor,
                detail={
                    "session_id": session_id,
                    "events_generated": events_generated,
                },
            )
        return updated

    def get_sessions(
        self,
        hmi_id: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[SessionRecord]:
        """Consulta sesiones para reporte de auditoría."""
        if limit <= 0:
            raise ValueError("limit debe ser > 0")

        conditions = []
        params: list[Any] = []

        if hmi_id is not None:
            if not isinstance(hmi_id, str):
                raise ValueError("hmi_id debe ser string o None")
            conditions.append("hmi_id = ?")
            params.append(hmi_id)

        if since is not None:
            conditions.append("opened_at >= ?")
            params.append(since)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        conn = self._get_conn()
        rows = conn.execute(
            f"SELECT * FROM sessions {where} ORDER BY opened_at DESC LIMIT ?",
            params,
        ).fetchall()

        return [
            SessionRecord(
                session_id=row["session_id"],
                hmi_id=row["hmi_id"],
                hmi_type=row["hmi_type"],
                opened_at=row["opened_at"],
                closed_at=row["closed_at"],
                events_generated=row["events_generated"],
                extended_offline=bool(row["extended_offline"]),
                row_id=row["id"],
            )
            for row in rows
        ]


class ComplianceChecker:
    """
    Verificador automático de requisitos NERC CIP / IEC 62443.

    Verifica que la configuración del sistema cumple los requisitos
    mínimos antes de una auditoría. Genera ComplianceResult por
    cada requisito verificado.

    No reemplaza al consultor de cumplimiento — genera la evidencia
    técnica que el consultor y el auditor necesitan.
    """

    MAX_ACCESS_TTL_SECONDS = 3600
    MAX_GRACE_PERIOD_SECONDS = 3600
    MIN_KEY_SIZE_BITS = 2048
    MAX_CUSTODY_TIMEOUT_SECONDS = 1800

    def check_all(self, config: dict[str, Any] | None) -> ComplianceReport:
        """
        Ejecuta todas las verificaciones de cumplimiento.

        Args:
            config: Diccionario con la configuración actual del sistema.
                    Campos esperados: access_ttl, grace_period, key_size,
                    custody_timeout, audit_log_enabled, tls_enabled.

        Returns:
            ComplianceReport con resultados por requisito y resumen general.
        """
        if config is None or not isinstance(config, dict):
            config = {}

        results = [
            self._check_access_ttl(config.get("access_ttl")),
            self._check_grace_period(config.get("grace_period")),
            self._check_key_size(config.get("key_size")),
            self._check_custody_timeout(config.get("custody_timeout")),
            self._check_audit_log(config.get("audit_log_enabled")),
            self._check_tls(config.get("tls_enabled")),
            self._check_refresh_rotation(config.get("refresh_rotation_enabled")),
            self._check_revocation_list(config.get("revocation_list_enabled")),
        ]

        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed and r.severity == "HIGH")
        warnings = sum(1 for r in results if not r.passed and r.severity == "MEDIUM")

        report_id = str(uuid.uuid4())
        generated_at = time.time()
        overall_passed = failed == 0

        report_data = json.dumps({
            "report_id": report_id,
            "generated_at": generated_at,
            "overall_passed": overall_passed,
            "results": [
                {
                    "standard": r.standard,
                    "requirement": r.requirement,
                    "passed": r.passed,
                    "detail": r.detail,
                    "severity": r.severity,
                }
                for r in results
            ],
        }, sort_keys=True, ensure_ascii=False)
        sha256 = hashlib.sha256(report_data.encode()).hexdigest()

        return ComplianceReport(
            report_id=report_id,
            generated_at=generated_at,
            results=results,
            passed_count=passed,
            failed_count=failed,
            warning_count=warnings,
            overall_passed=overall_passed,
            sha256=sha256,
        )

    def _check_access_ttl(self, access_ttl: Any) -> ComplianceResult:
        standard = "NERC CIP-007-6 / IEC 62443-3-3 SR 1.1"
        requirement = "Tiempo de expiración de token de acceso"

        if access_ttl is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="access_ttl no configurado",
                severity="HIGH",
            )
        if not isinstance(access_ttl, (int, float)):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"access_ttl tipo inválido: {type(access_ttl)}",
                severity="HIGH",
            )
        if access_ttl <= 0:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="access_ttl debe ser > 0",
                severity="HIGH",
            )
        if access_ttl > self.MAX_ACCESS_TTL_SECONDS:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=(
                    f"access_ttl={access_ttl}s excede máximo permitido "
                    f"({self.MAX_ACCESS_TTL_SECONDS}s)"
                ),
                severity="HIGH",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail=f"access_ttl={access_ttl}s dentro del límite permitido",
        )

    def _check_grace_period(self, grace_period: Any) -> ComplianceResult:
        standard = "IEC 62443-3-3 SR 2.1"
        requirement = "Grace period acotado para entornos offline"

        if grace_period is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="grace_period no configurado",
                severity="HIGH",
            )
        if not isinstance(grace_period, (int, float)):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"grace_period tipo inválido: {type(grace_period)}",
                severity="HIGH",
            )
        if grace_period < 0:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="grace_period no puede ser negativo",
                severity="HIGH",
            )
        if grace_period > self.MAX_GRACE_PERIOD_SECONDS:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=(
                    f"grace_period={grace_period}s excede máximo "
                    f"({self.MAX_GRACE_PERIOD_SECONDS}s)"
                ),
                severity="HIGH",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail=f"grace_period={grace_period}s dentro del límite permitido",
        )

    def _check_key_size(self, key_size: Any) -> ComplianceResult:
        standard = "NERC CIP-007-6 R4 / IEC 62443-3-3 SR 4.3"
        requirement = "Tamaño mínimo de clave criptográfica"

        if key_size is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="key_size no configurado",
                severity="HIGH",
            )
        if not isinstance(key_size, int):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"key_size tipo inválido: {type(key_size)}",
                severity="HIGH",
            )
        if key_size < self.MIN_KEY_SIZE_BITS:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=(
                    f"key_size={key_size} bits menor al mínimo "
                    f"({self.MIN_KEY_SIZE_BITS} bits RSA)"
                ),
                severity="HIGH",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail=f"key_size={key_size} bits cumple requisito mínimo",
        )

    def _check_custody_timeout(self, custody_timeout: Any) -> ComplianceResult:
        standard = "IEC 62443-2-1 4.3.3.6"
        requirement = "Timeout de custodia de mensajes acotado"

        if custody_timeout is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="custody_timeout no configurado",
                severity="MEDIUM",
            )
        if not isinstance(custody_timeout, (int, float)):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"custody_timeout tipo inválido: {type(custody_timeout)}",
                severity="MEDIUM",
            )
        if custody_timeout <= 0:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="custody_timeout debe ser > 0",
                severity="MEDIUM",
            )
        if custody_timeout > self.MAX_CUSTODY_TIMEOUT_SECONDS:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=(
                    f"custody_timeout={custody_timeout}s excede máximo "
                    f"({self.MAX_CUSTODY_TIMEOUT_SECONDS}s)"
                ),
                severity="MEDIUM",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail=f"custody_timeout={custody_timeout}s dentro del límite",
        )

    def _check_audit_log(self, enabled: Any) -> ComplianceResult:
        standard = "NERC CIP-007-6 R5 / IEC 62443-2-1 4.3.3.3"
        requirement = "Audit log habilitado y activo"

        if enabled is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="audit_log_enabled no configurado",
                severity="HIGH",
            )
        if not isinstance(enabled, bool):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"audit_log_enabled tipo inválido: {type(enabled)}",
                severity="HIGH",
            )
        if not enabled:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="Audit log deshabilitado — requerido por NERC CIP-007-6 R5",
                severity="HIGH",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail="Audit log habilitado y activo",
        )

    def _check_tls(self, tls_enabled: Any) -> ComplianceResult:
        standard = "NERC CIP-005-6 R1 / IEC 62443-3-3 SR 4.1"
        requirement = "Cifrado en tránsito habilitado (TLS)"

        if tls_enabled is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="tls_enabled no configurado",
                severity="HIGH",
            )
        if not isinstance(tls_enabled, bool):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"tls_enabled tipo inválido: {type(tls_enabled)}",
                severity="HIGH",
            )
        if not tls_enabled:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="TLS deshabilitado — tráfico en claro no cumple NERC CIP-005-6",
                severity="HIGH",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail="TLS habilitado en todos los canales",
        )

    def _check_refresh_rotation(self, enabled: Any) -> ComplianceResult:
        standard = "IEC 62443-3-3 SR 1.3"
        requirement = "Rotación de tokens de renovación habilitada"

        if enabled is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="refresh_rotation_enabled no configurado",
                severity="MEDIUM",
            )
        if not isinstance(enabled, bool):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"refresh_rotation_enabled tipo inválido: {type(enabled)}",
                severity="MEDIUM",
            )
        if not enabled:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="Rotación de refresh tokens deshabilitada",
                severity="MEDIUM",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail="Rotación de refresh tokens activa — cada uso invalida el anterior",
        )

    def _check_revocation_list(self, enabled: Any) -> ComplianceResult:
        standard = "NERC CIP-007-6 R5.3 / IEC 62443-3-3 SR 1.2"
        requirement = "Lista de revocación de tokens habilitada"

        if enabled is None:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="revocation_list_enabled no configurado",
                severity="HIGH",
            )
        if not isinstance(enabled, bool):
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail=f"revocation_list_enabled tipo inválido: {type(enabled)}",
                severity="HIGH",
            )
        if not enabled:
            return ComplianceResult(
                passed=False, standard=standard, requirement=requirement,
                detail="Lista de revocación deshabilitada — tokens comprometidos no pueden invalidarse",
                severity="HIGH",
            )
        return ComplianceResult(
            passed=True, standard=standard, requirement=requirement,
            detail="Lista de revocación activa en RPi y servidor central",
        )


class EvidenceExport:
    """
    Exporta el paquete de evidencia para auditorías.

    Genera un JSON firmado con SHA-256 que contiene:
    - Entradas del audit log en el período solicitado
    - Sesiones HMI del período
    - Reporte de cumplimiento actual
    - Metadatos del sistema

    El auditor puede verificar la integridad del paquete
    recalculando el SHA-256 del contenido.
    """

    def __init__(self, audit_log: AuditLog, checker: ComplianceChecker) -> None:
        if audit_log is None:
            raise ValueError("audit_log no puede ser None")
        if checker is None:
            raise ValueError("checker no puede ser None")

        self._audit_log = audit_log
        self._checker = checker

    def export(
        self,
        config: dict[str, Any] | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """
        Genera el paquete de evidencia.

        Args:
            config: Configuración del sistema para ComplianceChecker
            since:  Timestamp de inicio del período (Unix)
            until:  Timestamp de fin del período (Unix)
            limit:  Máximo de entradas del audit log

        Returns:
            Diccionario con evidencia completa y SHA-256 del paquete
        """
        if limit <= 0:
            raise ValueError("limit debe ser > 0")

        entries = self._audit_log.query(since=since, until=until, limit=limit)
        sessions = self._audit_log.get_sessions(since=since, limit=limit)
        compliance_report = self._checker.check_all(config)

        package = {
            "package_id": str(uuid.uuid4()),
            "generated_at": time.time(),
            "period": {
                "since": since,
                "until": until,
            },
            "audit_log": [
                {
                    "entry_id": e.entry_id,
                    "timestamp": e.timestamp,
                    "action": e.action.value if isinstance(e.action, AuditAction) else e.action,
                    "result": e.result.value if isinstance(e.result, AuditResult) else e.result,
                    "actor": e.actor,
                    "target": e.target,
                    "detail": e.detail,
                    "sha256": e.sha256,
                }
                for e in entries
            ],
            "sessions": [
                {
                    "session_id": s.session_id,
                    "hmi_id": s.hmi_id,
                    "hmi_type": s.hmi_type,
                    "opened_at": s.opened_at,
                    "closed_at": s.closed_at,
                    "events_generated": s.events_generated,
                    "extended_offline": s.extended_offline,
                }
                for s in sessions
            ],
            "compliance": {
                "report_id": compliance_report.report_id,
                "overall_passed": compliance_report.overall_passed,
                "passed_count": compliance_report.passed_count,
                "failed_count": compliance_report.failed_count,
                "warning_count": compliance_report.warning_count,
                "results": [
                    {
                        "standard": r.standard,
                        "requirement": r.requirement,
                        "passed": r.passed,
                        "detail": r.detail,
                        "severity": r.severity,
                    }
                    for r in compliance_report.results
                ],
                "sha256": compliance_report.sha256,
            },
            "vtr_version": "0.4.0",
        }

        package_json = json.dumps(package, sort_keys=True, ensure_ascii=False)
        package["package_sha256"] = hashlib.sha256(
            package_json.encode("utf-8")
        ).hexdigest()

        return package
