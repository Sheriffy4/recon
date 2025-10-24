"""
Модуль для побайтовой обработки пакетов.
Замена Scapy на нативную обработку для повышения производительности.
"""

from .raw_packet_engine import RawPacketEngine
from .scapy_compatibility import ScapyCompatibilityLayer
from .migration_tool import ScapyMigrationTool
from .packet_models import (
    ProtocolType,
    PacketDirection,
    IPHeader,
    TCPHeader,
    UDPHeader,
    RawPacket,
    PacketFragment,
    BypassTechnique,
    LayerInfo,
    ParsedPacket,
    TCPPacket,
    PacketStatistics,
)

__all__ = [
    "RawPacketEngine",
    "ScapyCompatibilityLayer",
    "ScapyMigrationTool",
    "ProtocolType",
    "PacketDirection",
    "IPHeader",
    "TCPHeader",
    "UDPHeader",
    "RawPacket",
    "PacketFragment",
    "BypassTechnique",
    "LayerInfo",
    "ParsedPacket",
    "TCPPacket",
    "PacketStatistics",
]
