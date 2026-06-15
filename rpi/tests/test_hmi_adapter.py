"""
vtr-continuity v0.4.0 — Tests HMI Adapter
rpi/tests/test_hmi_adapter.py

Cubre:
  - AbstractHMIAdapter: validaciones de init
  - IgnitionAdapter: connect, read_events con JWT, _parse_alarm, acknowledge
  - OPCUAAdapter: validaciones de init, endpoint_url
  - Stubs: ModbusAdapter, WinCCAdapter, iFIXAdapter, DNP3Adapter
  - get_adapter_class: registry, tipo None, tipo desconocido
  - HMIEvent: campos obligatorios, normalización
  - Verificación JWT integrada: token None, token inválido, token válido

VTR — Vector Telemetry Research © 2026
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from server.auth import KeyPair, VTRAuth
from rpi.jwt_verifier import RPiJWTVerifier
from rpi.hmi_adapter import (
    AbstractHMIAdapter,
    HMIEvent,
    IgnitionAdapter,
    OPCUAAdapter,
    ModbusAdapter,
    WinCCAdapter,
    iFIXAdapter,
    DNP3Adapter,
    get_adapter_class,
    ADAPTER_REGISTRY,
)


@pytest.fixture(scope="module")
def keypair():
    return KeyPair(key_size=2048)


@pytest.fixture(scope="module")
def auth(keypair):
    return VTRAuth(keypair=keypair, access_ttl=900, issuer="vtr-server")


@pytest.fixture(scope="module")
def verifier(keypair):
    return RPiJWTVerifier.from_pem_bytes(
        public_pem=keypair.public_pem(),
        grace_period=1800,
        allowed_issuers={"vtr-server"},
    )


@pytest.fixture
def token(auth):
    return auth.issue("hmi-test", "ignition", scopes=["read", "write"]).access_token


@pytest.fixture
def ignition(verifier):
    return IgnitionAdapter(
        hmi_id="ignition-planta-norte",
        verifier=verifier,
        gateway_url="http://localhost:8088",
        timeout=5.0,
    )


class TestAbstractAdapter:

    def test_hmi_id_none_raises(self, verifier):
        with pytest.raises(ValueError):
            IgnitionAdapter(hmi_id=None, verifier=verifier, gateway_url="http://localhost")

    def test_hmi_id_vacio_raises(self, verifier):
        with pytest.raises(ValueError):
            IgnitionAdapter(hmi_id="", verifier=verifier, gateway_url="http://localhost")

    def test_verifier_none_raises(self):
        with pytest.raises(ValueError):
            IgnitionAdapter(hmi_id="hmi-01", verifier=None, gateway_url="http://localhost")

    def test_verify_token_none_retorna_invalido(self, ignition):
        result = ignition.verify_token(None)
        assert result.valid is False

    def test_verify_token_vacio_retorna_invalido(self, ignition):
        result = ignition.verify_token("")
        assert result.valid is False

    def test_verify_token_valido(self, ignition, token):
        result = ignition.verify_token(token)
        assert result.valid is True

    def test_status_inicial_desconectado(self, ignition):
        assert ignition.status.connected is False
        assert ignition.status.hmi_type == "ignition"


class TestIgnitionAdapter:

    def test_init_gateway_url_none_raises(self, verifier):
        with pytest.raises(ValueError):
            IgnitionAdapter(hmi_id="hmi-01", verifier=verifier, gateway_url=None)

    def test_init_gateway_url_vacio_raises(self, verifier):
        with pytest.raises(ValueError):
            IgnitionAdapter(hmi_id="hmi-01", verifier=verifier, gateway_url="")

    def test_init_timeout_invalido_raises(self, verifier):
        with pytest.raises(ValueError):
            IgnitionAdapter(hmi_id="hmi-01", verifier=verifier,
                          gateway_url="http://localhost", timeout=0)

    def test_hmi_type(self, ignition):
        assert ignition.hmi_type == "ignition"

    def test_connect_ok(self, ignition):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            result = ignition.connect()
        assert result is True
        assert ignition.status.connected is True

    def test_connect_falla_http(self, ignition):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            result = ignition.connect()
        assert result is False
        assert ignition.status.connected is False

    def test_connect_falla_network(self, ignition):
        import httpx
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = \
                httpx.RequestError("sin red")
            result = ignition.connect()
        assert result is False

    def test_read_events_token_none_retorna_vacio(self, ignition):
        events = ignition.read_events(token=None)
        assert events == []

    def test_read_events_token_invalido_retorna_vacio(self, ignition):
        events = ignition.read_events(token="token.invalido.xxx")
        assert events == []

    def test_read_events_limit_invalido_raises(self, ignition, token):
        with pytest.raises(ValueError):
            ignition.read_events(token=token, limit=0)

    def test_read_events_con_alarmas(self, ignition, token):
        alarmas_mock = {
            "data": [
                {
                    "id": "alarm-001",
                    "name": "High Pressure",
                    "displayPath": "Plant/Tag1",
                    "priority": "High",
                    "state": "ActiveUnacked",
                    "eventTime": time.time(),
                    "activeData": {"value": 150.5},
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = alarmas_mock
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            events = ignition.read_events(token=token)

        assert len(events) == 1
        assert events[0].event_id == "alarm-001"
        assert events[0].hmi_type == "ignition"
        assert events[0].severity == "CRITICAL"
        assert events[0].source_tag == "Plant/Tag1"
        assert events[0].payload["name"] == "High Pressure"

    def test_read_events_respuesta_vacia(self, ignition, token):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": []}
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            events = ignition.read_events(token=token)
        assert events == []

    def test_read_events_respuesta_sin_data(self, ignition, token):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            events = ignition.read_events(token=token)
        assert events == []

    def test_read_events_http_error(self, ignition, token):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            events = ignition.read_events(token=token)
        assert events == []

    def test_parse_alarm_sin_id_genera_uuid(self, ignition, token):
        alarmas_mock = {
            "data": [{"name": "Sin ID", "priority": "Low"}]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = alarmas_mock
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            events = ignition.read_events(token=token)
        assert len(events) == 1
        assert events[0].event_id is not None

    def test_parse_alarm_sin_timestamp_usa_now(self, ignition, token):
        before = time.time()
        alarmas_mock = {"data": [{"id": "a1", "name": "Test"}]}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = alarmas_mock
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_resp
            events = ignition.read_events(token=token)
        after = time.time()
        assert before <= events[0].timestamp <= after

    def test_map_priority(self):
        assert IgnitionAdapter._map_priority("Critical") == "CRITICAL"
        assert IgnitionAdapter._map_priority("High") == "CRITICAL"
        assert IgnitionAdapter._map_priority("Medium") == "WARNING"
        assert IgnitionAdapter._map_priority("Low") == "INFO"
        assert IgnitionAdapter._map_priority("Diagnostic") == "DIAGNOSTIC"
        assert IgnitionAdapter._map_priority("Desconocido") == "INFO"

    def test_acknowledge_ok(self, ignition):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            result = ignition.acknowledge("alarm-001")
        assert result is True

    def test_acknowledge_none(self, ignition):
        assert ignition.acknowledge(None) is False

    def test_acknowledge_vacio(self, ignition):
        assert ignition.acknowledge("") is False


class TestOPCUAAdapter:

    def test_init_endpoint_none_raises(self, verifier):
        with pytest.raises(ValueError):
            OPCUAAdapter(hmi_id="opc-01", verifier=verifier, endpoint_url=None)

    def test_init_endpoint_sin_prefijo_raises(self, verifier):
        with pytest.raises(ValueError):
            OPCUAAdapter(hmi_id="opc-01", verifier=verifier,
                        endpoint_url="http://localhost:4840")

    def test_init_timeout_invalido_raises(self, verifier):
        with pytest.raises(ValueError):
            OPCUAAdapter(hmi_id="opc-01", verifier=verifier,
                        endpoint_url="opc.tcp://localhost:4840", timeout=0)

    def test_hmi_type(self, verifier):
        adapter = OPCUAAdapter(
            hmi_id="opc-01", verifier=verifier,
            endpoint_url="opc.tcp://localhost:4840",
        )
        assert adapter.hmi_type == "opcua"

    def test_read_events_token_none_retorna_vacio(self, verifier):
        adapter = OPCUAAdapter(
            hmi_id="opc-01", verifier=verifier,
            endpoint_url="opc.tcp://localhost:4840",
        )
        events = adapter.read_events(token=None)
        assert events == []

    def test_read_events_limit_invalido_raises(self, verifier, token):
        adapter = OPCUAAdapter(
            hmi_id="opc-01", verifier=verifier,
            endpoint_url="opc.tcp://localhost:4840",
        )
        with pytest.raises(ValueError):
            adapter.read_events(token=token, limit=0)

    def test_acknowledge_retorna_true_con_id_valido(self, verifier):
        adapter = OPCUAAdapter(
            hmi_id="opc-01", verifier=verifier,
            endpoint_url="opc.tcp://localhost:4840",
        )
        assert adapter.acknowledge("event-123") is True

    def test_acknowledge_none_retorna_false(self, verifier):
        adapter = OPCUAAdapter(
            hmi_id="opc-01", verifier=verifier,
            endpoint_url="opc.tcp://localhost:4840",
        )
        assert adapter.acknowledge(None) is False


class TestStubs:

    def test_modbus_connect_raises(self, verifier):
        a = ModbusAdapter(hmi_id="mb-01", verifier=verifier)
        with pytest.raises(NotImplementedError):
            a.connect()

    def test_wincc_connect_raises(self, verifier):
        a = WinCCAdapter(hmi_id="wc-01", verifier=verifier)
        with pytest.raises(NotImplementedError):
            a.connect()

    def test_ifix_connect_raises(self, verifier):
        a = iFIXAdapter(hmi_id="if-01", verifier=verifier)
        with pytest.raises(NotImplementedError):
            a.connect()

    def test_dnp3_connect_raises(self, verifier):
        a = DNP3Adapter(hmi_id="dnp-01", verifier=verifier)
        with pytest.raises(NotImplementedError):
            a.connect()

    def test_modbus_hmi_type(self, verifier):
        assert ModbusAdapter(hmi_id="mb-01", verifier=verifier).hmi_type == "modbus"

    def test_wincc_hmi_type(self, verifier):
        assert WinCCAdapter(hmi_id="wc-01", verifier=verifier).hmi_type == "wincc"

    def test_ifix_hmi_type(self, verifier):
        assert iFIXAdapter(hmi_id="if-01", verifier=verifier).hmi_type == "ifix"

    def test_dnp3_hmi_type(self, verifier):
        assert DNP3Adapter(hmi_id="dnp-01", verifier=verifier).hmi_type == "dnp3"


class TestRegistry:

    def test_get_adapter_ignition(self):
        cls = get_adapter_class("ignition")
        assert cls is IgnitionAdapter

    def test_get_adapter_opcua(self):
        cls = get_adapter_class("opcua")
        assert cls is OPCUAAdapter

    def test_get_adapter_modbus(self):
        cls = get_adapter_class("modbus")
        assert cls is ModbusAdapter

    def test_get_adapter_wincc(self):
        cls = get_adapter_class("wincc")
        assert cls is WinCCAdapter

    def test_get_adapter_ifix(self):
        cls = get_adapter_class("ifix")
        assert cls is iFIXAdapter

    def test_get_adapter_dnp3(self):
        cls = get_adapter_class("dnp3")
        assert cls is DNP3Adapter

    def test_get_adapter_none_raises(self):
        with pytest.raises(ValueError):
            get_adapter_class(None)

    def test_get_adapter_desconocido_raises(self):
        with pytest.raises(ValueError):
            get_adapter_class("hmi_desconocido")

    def test_get_adapter_case_insensitive(self):
        assert get_adapter_class("Ignition") is IgnitionAdapter
        assert get_adapter_class("OPCUA") is OPCUAAdapter

    def test_registry_cubre_todos_los_tipos(self):
        tipos_esperados = {"ignition", "opcua", "modbus", "wincc", "ifix", "dnp3"}
        assert tipos_esperados == set(ADAPTER_REGISTRY.keys())
