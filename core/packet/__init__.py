"""
Модуль для побайтовой обработки пакетов.
Замена Scapy на нативную обработку для повышения производительности.
"""

from .raw_packet_engine import RawPacketEngine

# Optional submodules (may be absent in some deployments/builds).
try:
    from .raw_pcap_reader import (
        RawPCAPReader,
        PCAPHeader,
        PCAPPacketHeader,
        read_pcap,
        iterate_pcap,
    )
except Exception:  # pragma: no cover
    RawPCAPReader = None
    PCAPHeader = None
    PCAPPacketHeader = None
    read_pcap = None
    iterate_pcap = None

try:
    from .scapy_compatibility import ScapyCompatibilityLayer
except Exception:  # pragma: no cover
    ScapyCompatibilityLayer = None

try:
    from .migration_tool import ScapyMigrationTool
except Exception:  # pragma: no cover
    ScapyMigrationTool = None

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
