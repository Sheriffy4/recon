"""
Модуль для побайтовой обработки пакетов.
Замена Scapy на нативную обработку для повышения производительности.
"""

from .raw_packet_engine import RawPacketEngine
from .packet_parser import PacketParser
from .packet_builder import PacketBuilder
from .scapy_compatibility import ScapyCompatibilityLayer
from .migration_tool import ScapyMigrationTool

__all__ = [
    'RawPacketEngine',
    'PacketParser', 
    'PacketBuilder',
    'ScapyCompatibilityLayer',
    'ScapyMigrationTool'
]