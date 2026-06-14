"""
vtr-continuity v0.4.0 — Core
Módulos compartidos por todos los tiers (RPi, servidor central, nodos LoRa).

VTR — Vector Telemetry Research © 2026
"""
from .custody_manager import CustodyManager, CustodyBundle, CustodyStatus, MAX_LORA_FRAME_BYTES

__all__ = [
    "CustodyManager",
    "CustodyBundle",
    "CustodyStatus",
    "MAX_LORA_FRAME_BYTES",
]
