"""
Модуль для побайтовой обработки пакетов.
Замена Scapy на нативную обработку для повышения производительности.
"""

from .raw_packet_engine import RawPacketEngine
from .raw_pcap_reader import RawPCAPReader, PCAPHeader, PCAPPacketHeader, read_pcap, iterate_pcap
from .scapy_compatibility import ScapyCompatibilityLayer
from .migration_tool import ScapyMigrationTool
from .modifier import PacketModifier
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
    "RawPCAPReader",
    "PCAPHeader",
    "PCAPPacketHeader",
    "read_pcap",
    "iterate_pcap",
    "ScapyCompatibilityLayer",
    "ScapyMigrationTool",
    "PacketModifier",
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
