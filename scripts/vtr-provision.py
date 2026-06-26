#!/usr/bin/env python3
"""
vtr-continuity v0.5.0 — Provisioning
scripts/vtr-provision.py

Script de bench para provisionar un dispositivo (RPi o Heltec) según el
procedimiento de docs/VTR-PKI-001.md §3.3 — implementación de la Épica
C2 (docs/ROADMAP-v0.5.0.md) y la Opción 3A de
docs/DECISIONS-v0.5.0.md (Decisión 3, ya aprobada).

Procedimiento implementado, paso a paso (mismo orden que VTR-PKI-001
§3.3, sin reordenar):
  1. El dispositivo ya generó su par de llaves Ed25519 en el bench —
     este script NO genera la llave del dispositivo, la recibe como
     input (--device-public-key). Generar la llave del dispositivo es
     responsabilidad del firmware/proceso que corre en el RPi/Heltec
     mismo (ver docs/VTR-FIRMWARE-001.md para el caso Heltec) — este
     script orquesta el registro del bench, no la generación de la
     llave del dispositivo.
  2. Construcción del "CSR equivalente" — en este flujo simplificado de
     v0.5.0 (sin X.509 real, ver nota de alcance más abajo), el CSR
     equivalente es simplemente (device_id, device_public_key)
     presentados a este script.
  3. La Intermediate firma — implementado en core/device_registry.py,
     reusando la misma llave que firma certificados de dispositivo en
     la operación diaria (decisión confirmada explícitamente, no una
     llave separada del bench).
  4. Almacenamiento — el registro firmado se escribe en
     device_registry.vtrdb (core/device_registry.py), append-only,
     cifrado, con hash chain. El certificado de dispositivo resultante
     se imprime a stdout para que el operador del bench lo copie a la
     partición firmada del dispositivo (esa partición es diseño
     pendiente de VTR-CRYPTO-002 — este script no asume que existe).

NOTA DE ALCANCE — qué este script NO hace:
  - No genera ni almacena la llave PRIVADA del dispositivo — esa llave
    nunca debe pasar por el bench en texto plano; el dispositivo la
    genera y la conserva localmente (eFuse en Heltec, partición
    firmada pendiente en RPi).
  - No implementa X.509 real — "CSR" y "certificado" aquí son
    estructuras JSON firmadas con Ed25519, no certificados X.509
    estándar. VTR-PKI-001 no especifica X.509 como requisito — usa el
    vocabulario de PKI de forma genérica, y este script sigue esa misma
    decisión implícita.
  - No implementa el bench air-gapped físico en sí (aislamiento de red,
    Wi-Fi/BT desactivado por hardware) — eso es procedimiento operativo
    del equipo de bench, no algo que un script Python pueda forzar.

Uso:
    python3 vtr-provision.py provision \\
        --device-id device-001.vtr.local \\
        --device-public-key-file device_001_pubkey.bin \\
        --intermediate-key-file intermediate_private.pem \\
        --intermediate-serial INT-2026-001 \\
        --registry-path /var/lib/vtr-continuity/device_registry.vtrdb \\
        --registry-key-file registry_encryption.key

    python3 vtr-provision.py verify \\
        --registry-path /var/lib/vtr-continuity/device_registry.vtrdb \\
        --registry-key-file registry_encryption.key \\
        --intermediate-public-key-file intermediate_public.bin

VTR — Vector Telemetry Research © 2026
SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Permite ejecutar este script directamente desde scripts/ sin instalar
# el paquete — busca la raíz del repo (un nivel arriba de scripts/) e
# inserta en sys.path, mismo patrón que otros scripts standalone del
# proyecto.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.device_registry import DeviceRegistry, DEFAULT_REGISTRY_PATH
from crypto_layer.ed25519_sign import (
    PRIVATE_KEY_LENGTH_BYTES,
    PUBLIC_KEY_LENGTH_BYTES,
    verify,
)
from crypto_layer.errors import CryptoError


def _read_key_file(path: str, expected_size: int | None = None) -> bytes:
    """Lee un archivo de llave binaria, con mensaje de error claro si
    el tamaño no coincide — evita el error confuso que produciría
    pasar, por ejemplo, una llave en formato PEM/texto donde se espera
    bytes crudos."""
    key_path = Path(path)
    if not key_path.exists():
        print(f"ERROR: archivo de llave no encontrado: {path}", file=sys.stderr)
        sys.exit(1)
    data = key_path.read_bytes()
    if expected_size is not None and len(data) != expected_size:
        print(
            f"ERROR: {path} tiene {len(data)} bytes, se esperaban "
            f"{expected_size} — ¿es un archivo de llave binaria cruda, "
            f"no PEM/base64?",
            file=sys.stderr,
        )
        sys.exit(1)
    return data


def cmd_provision(args: argparse.Namespace) -> int:
    device_public_key = _read_key_file(
        args.device_public_key_file, expected_size=PUBLIC_KEY_LENGTH_BYTES
    )
    intermediate_private_key = _read_key_file(
        args.intermediate_key_file, expected_size=PRIVATE_KEY_LENGTH_BYTES
    )
    registry_encryption_key = _read_key_file(args.registry_key_file, expected_size=32)

    try:
        registry = DeviceRegistry(
            registry_path=args.registry_path,
            encryption_key=registry_encryption_key,
        )
        entry = registry.append(
            device_id=args.device_id,
            device_public_key=device_public_key,
            intermediate_serial=args.intermediate_serial,
            intermediate_private_key=intermediate_private_key,
        )
    except CryptoError as exc:
        print(f"ERROR durante provisioning: {exc}", file=sys.stderr)
        return 1

    # Certificado de dispositivo resultante — JSON firmado, para que el
    # operador del bench lo copie a la partición firmada del
    # dispositivo (VTR-CRYPTO-002, diseño pendiente — este script no
    # asume su existencia, solo produce el artefacto que esa partición
    # eventualmente almacenará).
    certificate = {
        "device_id": entry.device_id,
        "device_public_key": entry.device_public_key.hex(),
        "provisioned_at": entry.provisioned_at,
        "intermediate_serial": entry.intermediate_serial,
        "entry_hash": entry.entry_hash,
        "signature": entry.signature.hex(),
    }

    print(json.dumps(certificate, indent=2, sort_keys=True))
    print(
        f"\n[vtr-provision] dispositivo '{args.device_id}' registrado — "
        f"entry_hash={entry.entry_hash[:16]}...",
        file=sys.stderr,
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    registry_encryption_key = _read_key_file(args.registry_key_file, expected_size=32)
    intermediate_public_key = _read_key_file(
        args.intermediate_public_key_file, expected_size=PUBLIC_KEY_LENGTH_BYTES
    )

    try:
        registry = DeviceRegistry(
            registry_path=args.registry_path,
            encryption_key=registry_encryption_key,
        )
        entries = registry.get_all()
        valid = registry.verify_chain(intermediate_public_key)
    except CryptoError as exc:
        print(f"ERROR al verificar el registro: {exc}", file=sys.stderr)
        return 1

    print(f"Entradas en el registro: {len(entries)}")
    for entry in entries:
        ts = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(entry.provisioned_at)
        )
        print(f"  - {entry.device_id} (provisionado {ts})")

    if valid:
        print("\nVERIFICACIÓN: cadena íntegra — hash chain y firmas OK.")
        return 0
    else:
        print(
            "\nVERIFICACIÓN: FALLÓ — la cadena de hashes está rota o "
            "alguna firma no verifica. Ver logs para el device_id "
            "específico donde falló. NO continuar usando este registro "
            "sin investigar manualmente.",
            file=sys.stderr,
        )
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="vtr-provision — bench de provisioning de dispositivos VTR Continuity"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_provision = subparsers.add_parser(
        "provision", help="Registrar un dispositivo recién provisionado"
    )
    p_provision.add_argument("--device-id", required=True)
    p_provision.add_argument("--device-public-key-file", required=True)
    p_provision.add_argument("--intermediate-key-file", required=True)
    p_provision.add_argument("--intermediate-serial", required=True)
    p_provision.add_argument(
        "--registry-path", default=str(DEFAULT_REGISTRY_PATH)
    )
    p_provision.add_argument("--registry-key-file", required=True)
    p_provision.set_defaults(func=cmd_provision)

    p_verify = subparsers.add_parser(
        "verify", help="Verificar la integridad completa del registro"
    )
    p_verify.add_argument(
        "--registry-path", default=str(DEFAULT_REGISTRY_PATH)
    )
    p_verify.add_argument("--registry-key-file", required=True)
    p_verify.add_argument("--intermediate-public-key-file", required=True)
    p_verify.set_defaults(func=cmd_verify)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
