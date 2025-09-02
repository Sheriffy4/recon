"""
Модуль для побайтовой обработки пакетов.
Замена Scapy на нативную обработку для повышения производительности.
"""

from .raw_packet_engine import RawPacketEngine
from .scapy_compatibility import ScapyCompatibilityLayer
from .migration_tool import ScapyMigrationTool
from .packet_models import *

__all__ = [
    "RawPacketEngine",
    "ScapyCompatibilityLayer", 
    "ScapyMigrationTool",
]
