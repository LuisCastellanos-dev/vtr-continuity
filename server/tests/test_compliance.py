"""
vtr-continuity v0.4.0 — Tests Compliance
server/tests/test_compliance.py

Cubre:
  - AuditLog: write, verify_entry, query, count
  - AuditLog sesiones: open_session, close_session, get_sessions
  - ComplianceChecker: cada requisito con configuración válida e inválida
  - EvidenceExport: paquete completo, SHA-256, períodos
  - Validación de nulls en todos los campos

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from server.compliance import (
    AuditLog,
    AuditAction,
    AuditResult,
    ComplianceChecker,
    EvidenceExport,
)


@pytest.fixture
def audit(tmp_path):
    return AuditLog(db_path=tmp_path / "compliance.db")


@pytest.fixture
def checker():
    return ComplianceChecker()


@pytest.fixture
def exporter(audit, checker):
    return EvidenceExport(audit_log=audit, checker=checker)


VALID_CONFIG = {
    "access_ttl": 900,
    "grace_period": 1800,
    "key_size": 2048,
    "custody_timeout": 300,
    "audit_log_enabled": True,
    "tls_enabled": True,
    "refresh_rotation_enabled": True,
    "revocation_list_enabled": True,
}


class TestAuditLogInit:

    def test_db_path_vacio_raises(self):
        with pytest.raises(ValueError):
            AuditLog(db_path="")

    def test_crea_archivo_db(self, tmp_path):
        db = tmp_path / "test.db"
        AuditLog(db_path=db)
        assert db.exists()


class TestAuditLogWrite:

    def test_write_basico(self, audit):
        entry = audit.write(
            AuditAction.TOKEN_ISSUED,
            AuditResult.SUCCESS,
            actor="hmi-01",
        )
        assert entry.entry_id is not None
        assert entry.sha256 is not None
        assert entry.actor == "hmi-01"

    def test_write_actor_none_raises(self, audit):
        with pytest.raises(ValueError):
            audit.write(AuditAction.TOKEN_ISSUED, AuditResult.SUCCESS, actor=None)

    def test_write_actor_vacio_raises(self, audit):
        with pytest.raises(ValueError):
            audit.write(AuditAction.TOKEN_ISSUED, AuditResult.SUCCESS, actor="")

    def test_write_con_detail(self, audit):
        entry = audit.write(
            AuditAction.TOKEN_REJECTED,
            AuditResult.FAILURE,
            actor="hmi-02",
            detail={"reason": "token expirado", "hmi_type": "ignition"},
        )
        assert entry.detail["reason"] == "token expirado"

    def test_write_con_target(self, audit):
        entry = audit.write(
            AuditAction.CUSTODY_GRANTED,
            AuditResult.SUCCESS,
            actor="rpi-norte",
            target="bundle-abc-123",
        )
        assert entry.target == "bundle-abc-123"

    def test_write_incrementa_count(self, audit):
        before = audit.count()
        audit.write(AuditAction.SYNC_COMPLETED, AuditResult.SUCCESS, actor="rpi-01")
        assert audit.count() == before + 1

    def test_write_sha256_no_vacio(self, audit):
        entry = audit.write(AuditAction.KEY_ROTATED, AuditResult.SUCCESS, actor="server")
        assert entry.sha256
        assert len(entry.sha256) == 64


class TestAuditLogVerify:

    def test_verify_entrada_valida(self, audit):
        entry = audit.write(AuditAction.TOKEN_ISSUED, AuditResult.SUCCESS, actor="hmi-01")
        assert audit.verify_entry(entry.entry_id) is True

    def test_verify_entry_id_none(self, audit):
        assert audit.verify_entry(None) is False

    def test_verify_entry_id_vacio(self, audit):
        assert audit.verify_entry("") is False

    def test_verify_entry_id_inexistente(self, audit):
        assert audit.verify_entry("no-existe") is False


class TestAuditLogQuery:

    def test_query_todas(self, audit):
        audit.write(AuditAction.TOKEN_ISSUED, AuditResult.SUCCESS, actor="hmi-a")
        audit.write(AuditAction.TOKEN_REJECTED, AuditResult.FAILURE, actor="hmi-b")
        entries = audit.query(limit=100)
        assert len(entries) >= 2

    def test_query_por_actor(self, audit):
        audit.write(AuditAction.TOKEN_ISSUED, AuditResult.SUCCESS, actor="hmi-filtro")
        entries = audit.query(actor="hmi-filtro")
        assert all(e.actor == "hmi-filtro" for e in entries)

    def test_query_por_action(self, audit):
        audit.write(AuditAction.KEY_ROTATED, AuditResult.SUCCESS, actor="server")
        entries = audit.query(action=AuditAction.KEY_ROTATED)
        assert all(
            (e.action == AuditAction.KEY_ROTATED or e.action == "KEY_ROTATED")
            for e in entries
        )

    def test_query_por_since(self, audit):
        before = time.time()
        audit.write(AuditAction.SYNC_COMPLETED, AuditResult.SUCCESS, actor="rpi-01")
        entries = audit.query(since=before)
        assert len(entries) >= 1

    def test_query_limit_invalido_raises(self, audit):
        with pytest.raises(ValueError):
            audit.query(limit=0)

    def test_query_actor_tipo_invalido_raises(self, audit):
        with pytest.raises(ValueError):
            audit.query(actor=123)

    def test_query_since_tipo_invalido_raises(self, audit):
        with pytest.raises(ValueError):
            audit.query(since="no-es-float")


class TestSesiones:

    def test_open_session_basico(self, audit):
        session = audit.open_session("hmi-01", "ignition")
        assert session.session_id is not None
        assert session.hmi_id == "hmi-01"
        assert session.hmi_type == "ignition"
        assert session.closed_at is None

    def test_open_session_hmi_id_none_raises(self, audit):
        with pytest.raises(ValueError):
            audit.open_session(None, "ignition")

    def test_open_session_hmi_type_none_raises(self, audit):
        with pytest.raises(ValueError):
            audit.open_session("hmi-01", None)

    def test_open_session_extended_offline(self, audit):
        session = audit.open_session("hmi-01", "ignition", extended_offline=True)
        assert session.extended_offline is True

    def test_close_session(self, audit):
        session = audit.open_session("hmi-02", "opcua")
        result = audit.close_session(session.session_id, events_generated=5)
        assert result is True
        sessions = audit.get_sessions(hmi_id="hmi-02")
        closed = next((s for s in sessions if s.session_id == session.session_id), None)
        assert closed is not None
        assert closed.closed_at is not None
        assert closed.events_generated == 5

    def test_close_session_none(self, audit):
        assert audit.close_session(None) is False

    def test_close_session_vacio(self, audit):
        assert audit.close_session("") is False

    def test_close_session_doble(self, audit):
        session = audit.open_session("hmi-03", "ignition")
        audit.close_session(session.session_id)
        result = audit.close_session(session.session_id)
        assert result is False

    def test_get_sessions_por_hmi(self, audit):
        audit.open_session("hmi-unico", "wincc")
        sessions = audit.get_sessions(hmi_id="hmi-unico")
        assert len(sessions) >= 1
        assert all(s.hmi_id == "hmi-unico" for s in sessions)

    def test_get_sessions_limit_invalido_raises(self, audit):
        with pytest.raises(ValueError):
            audit.get_sessions(limit=0)


class TestComplianceChecker:

    def test_config_valida_pasa_todo(self, checker):
        report = checker.check_all(VALID_CONFIG)
        assert report.overall_passed is True
        assert report.failed_count == 0

    def test_config_none_falla(self, checker):
        report = checker.check_all(None)
        assert report.overall_passed is False

    def test_config_vacia_falla(self, checker):
        report = checker.check_all({})
        assert report.overall_passed is False

    def test_access_ttl_excesivo_falla(self, checker):
        config = {**VALID_CONFIG, "access_ttl": 7200}
        report = checker.check_all(config)
        assert any(
            not r.passed and "access_ttl" in r.detail
            for r in report.results
        )

    def test_access_ttl_none_falla(self, checker):
        config = {**VALID_CONFIG, "access_ttl": None}
        report = checker.check_all(config)
        assert any(not r.passed and "access_ttl" in r.requirement.lower() or
                  not r.passed and "access_ttl" in r.detail
                  for r in report.results)

    def test_key_size_insuficiente_falla(self, checker):
        config = {**VALID_CONFIG, "key_size": 1024}
        report = checker.check_all(config)
        assert any(not r.passed and "1024" in r.detail for r in report.results)

    def test_audit_log_deshabilitado_falla(self, checker):
        config = {**VALID_CONFIG, "audit_log_enabled": False}
        report = checker.check_all(config)
        assert any(not r.passed and "Audit log" in r.detail for r in report.results)

    def test_tls_deshabilitado_falla(self, checker):
        config = {**VALID_CONFIG, "tls_enabled": False}
        report = checker.check_all(config)
        assert any(not r.passed and "TLS" in r.detail for r in report.results)

    def test_report_tiene_sha256(self, checker):
        report = checker.check_all(VALID_CONFIG)
        assert report.sha256 is not None
        assert len(report.sha256) == 64

    def test_report_tiene_id(self, checker):
        report = checker.check_all(VALID_CONFIG)
        assert report.report_id is not None

    def test_grace_period_excesivo_falla(self, checker):
        config = {**VALID_CONFIG, "grace_period": 7200}
        report = checker.check_all(config)
        assert any(not r.passed and "grace_period" in r.detail for r in report.results)

    def test_revocation_list_deshabilitada_falla(self, checker):
        config = {**VALID_CONFIG, "revocation_list_enabled": False}
        report = checker.check_all(config)
        assert any(not r.passed and "revocación" in r.detail for r in report.results)


class TestEvidenceExport:

    def test_export_init_audit_none_raises(self, checker):
        with pytest.raises(ValueError):
            EvidenceExport(audit_log=None, checker=checker)

    def test_export_init_checker_none_raises(self, audit):
        with pytest.raises(ValueError):
            EvidenceExport(audit_log=audit, checker=None)

    def test_export_basico(self, exporter):
        package = exporter.export(config=VALID_CONFIG)
        assert package["package_id"] is not None
        assert "audit_log" in package
        assert "sessions" in package
        assert "compliance" in package
        assert "package_sha256" in package

    def test_export_sha256_presente(self, exporter):
        package = exporter.export(config=VALID_CONFIG)
        assert len(package["package_sha256"]) == 64

    def test_export_incluye_entradas_audit(self, audit, checker):
        audit.write(AuditAction.TOKEN_ISSUED, AuditResult.SUCCESS, actor="hmi-export")
        exp = EvidenceExport(audit_log=audit, checker=checker)
        package = exp.export(config=VALID_CONFIG)
        assert len(package["audit_log"]) >= 1

    def test_export_incluye_sesiones(self, audit, checker):
        audit.open_session("hmi-export-s", "ignition")
        exp = EvidenceExport(audit_log=audit, checker=checker)
        package = exp.export(config=VALID_CONFIG)
        assert len(package["sessions"]) >= 1

    def test_export_limit_invalido_raises(self, exporter):
        with pytest.raises(ValueError):
            exporter.export(limit=0)

    def test_export_config_none(self, exporter):
        package = exporter.export(config=None)
        assert package["compliance"]["overall_passed"] is False

    def test_export_por_periodo(self, audit, checker):
        before = time.time()
        audit.write(AuditAction.SYNC_COMPLETED, AuditResult.SUCCESS, actor="rpi-01")
        after = time.time()
        exp = EvidenceExport(audit_log=audit, checker=checker)
        package = exp.export(config=VALID_CONFIG, since=before, until=after)
        assert all(
            before <= e["timestamp"] <= after
            for e in package["audit_log"]
        )

    def test_export_vtr_version(self, exporter):
        package = exporter.export(config=VALID_CONFIG)
        assert package["vtr_version"] == "0.4.0"
