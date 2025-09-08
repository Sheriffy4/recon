"""
Unified packet converter for different packet formats.
Converts pydivert, scapy, and other packet formats to unified PacketInfo.
"""

import socket
import struct
from typing import Optional, Union, Any, Dict
from core.bypass.types import PacketInfo, PacketDirection, ProtocolType

try:
    import pydivert

    HAS_PYDIVERT = True
except ImportError:
    HAS_PYDIVERT = False
    pydivert = None
try:
    from scapy.all import IP, TCP, UDP, Raw

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class PacketConverter:
    """Convert various packet formats to unified PacketInfo."""

    def _build_packet_info(
        packet: "pydivert.Packet", protocol_specific_data: Dict[str, Any]
    ) -> PacketInfo:
        """Вспомогательный метод для создания объекта PacketInfo, чтобы избежать дублирования."""
        ttl = (
            packet.ipv4.ttl
            if packet.ipv4
            else packet.ipv6.hop_limit if packet.ipv6 else 64
        )
        base_data = {
            "src_ip": packet.src_addr,
            "dst_ip": packet.dst_addr,
            "direction": (
                PacketDirection.OUTBOUND
                if packet.is_outbound
                else PacketDirection.INBOUND
            ),
            "ip_ttl": ttl,
            "raw_data": bytes(packet.raw),
            "interface": packet.interface,
            "metadata": {"source": "pydivert", "original_packet": packet},
        }
        all_data = {**base_data, **protocol_specific_data}
        all_data["payload_size"] = len(all_data.get("payload", b""))
        return PacketInfo(**all_data)

    @staticmethod
    def from_pydivert(packet: "pydivert.Packet") -> Optional[PacketInfo]:
        """Convert PyDivert packet to PacketInfo."""
        if not HAS_PYDIVERT or not packet:
            return None
        try:
            protocol_specific_data = {}
            protocol = ProtocolType.OTHER
            payload = b""
            if packet.tcp:
                protocol = ProtocolType.TCP
                payload = bytes(packet.tcp.payload) if packet.tcp.payload else b""
                protocol_specific_data = {
                    "src_port": packet.tcp.src_port,
                    "dst_port": packet.tcp.dst_port,
                    "tcp_seq": packet.tcp.seq_num,
                    "tcp_ack": packet.tcp.ack_num,
                    "tcp_window": packet.tcp.window_size,
                    "tcp_urgent": packet.tcp.urg_ptr,
                    "tcp_flags": PacketConverter._get_tcp_flags_string(packet.tcp),
                    "payload": payload,
                    "protocol": protocol,
                }
            elif packet.udp:
                protocol = ProtocolType.UDP
                payload = bytes(packet.udp.payload) if packet.udp.payload else b""
                protocol_specific_data = {
                    "src_port": packet.udp.src_port,
                    "dst_port": packet.udp.dst_port,
                    "payload": payload,
                    "protocol": protocol,
                }
            else:
                return None
            base_data = {
                "src_ip": packet.src_addr,
                "dst_ip": packet.dst_addr,
                "direction": (
                    PacketDirection.OUTBOUND
                    if packet.is_outbound
                    else PacketDirection.INBOUND
                ),
                "ip_ttl": (
                    packet.ipv4.ttl
                    if packet.ipv4
                    else packet.ipv6.hop_limit if packet.ipv6 else 64
                ),
                "raw_data": bytes(packet.raw),
                "interface": packet.interface,
                "payload_size": len(payload),
                "metadata": {
                    "source_lib": "pydivert",
                    "original_packet_ref": id(packet),
                },
            }
            all_data = {**base_data, **protocol_specific_data}
            return PacketInfo(**all_data)
        except Exception as e:
            import logging

            logging.getLogger("PacketConverter").error(
                f"Error converting PyDivert packet: {e}"
            )
            return None

    @staticmethod
    def from_scapy(packet: Any) -> Optional[PacketInfo]:
        """Convert Scapy packet to PacketInfo."""
        if not HAS_SCAPY:
            return None
        try:
            if not packet.haslayer("IP"):
                return None
            ip_layer = packet["IP"]
            if packet.haslayer("TCP"):
                protocol = ProtocolType.TCP
                tcp_layer = packet["TCP"]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_seq = tcp_layer.seq
                tcp_ack = tcp_layer.ack
                tcp_flags = PacketConverter._scapy_flags_to_string(tcp_layer.flags)
                tcp_window = tcp_layer.window
                tcp_urgent = tcp_layer.urgptr
                tcp_options = bytes(tcp_layer.options) if tcp_layer.options else None
                payload = bytes(packet["Raw"]) if packet.haslayer("Raw") else b""
            elif packet.haslayer("UDP"):
                protocol = ProtocolType.UDP
                udp_layer = packet["UDP"]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                tcp_seq = tcp_ack = tcp_flags = tcp_window = tcp_urgent = (
                    tcp_options
                ) = None
                payload = bytes(packet["Raw"]) if packet.haslayer("Raw") else b""
            else:
                return None
            direction = PacketDirection.OUTBOUND
            return PacketInfo(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                ip_version=ip_layer.version,
                ip_ttl=ip_layer.ttl,
                ip_id=ip_layer.id,
                ip_flags=ip_layer.flags,
                ip_options=bytes(ip_layer.options) if ip_layer.options else b"",
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                tcp_seq=tcp_seq,
                tcp_ack=tcp_ack,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
                tcp_urgent=tcp_urgent,
                tcp_options=tcp_options,
                direction=direction,
                payload=payload,
                payload_size=len(payload),
                raw_data=bytes(packet),
                metadata={"original_packet": packet, "packet_type": "scapy"},
            )
        except Exception as e:
            import logging

            logging.error(f"Error converting Scapy packet: {e}")
            return None

    @staticmethod
    def from_raw_bytes(
        data: bytes, direction: PacketDirection = PacketDirection.OUTBOUND
    ) -> Optional[PacketInfo]:
        """Convert raw packet bytes to PacketInfo."""
        try:
            if len(data) < 20:
                return None
            ip_version = data[0] >> 4 & 15
            if ip_version != 4:
                return None
            ip_hlen = (data[0] & 15) * 4
            ip_total_len = struct.unpack("!H", data[2:4])[0]
            ip_id = struct.unpack("!H", data[4:6])[0]
            ip_flags_frag = struct.unpack("!H", data[6:8])[0]
            ip_flags = ip_flags_frag >> 13
            ip_ttl = data[8]
            ip_protocol = data[9]
            src_ip = socket.inet_ntoa(data[12:16])
            dst_ip = socket.inet_ntoa(data[16:20])
            if ip_protocol == 6:
                if len(data) < ip_hlen + 20:
                    return None
                tcp_data = data[ip_hlen:]
                src_port = struct.unpack("!H", tcp_data[0:2])[0]
                dst_port = struct.unpack("!H", tcp_data[2:4])[0]
                tcp_seq = struct.unpack("!I", tcp_data[4:8])[0]
                tcp_ack = struct.unpack("!I", tcp_data[8:12])[0]
                tcp_hlen = (tcp_data[12] >> 4 & 15) * 4
                tcp_flags_byte = tcp_data[13]
                tcp_window = struct.unpack("!H", tcp_data[14:16])[0]
                tcp_urgent = struct.unpack("!H", tcp_data[18:20])[0]
                tcp_flags = ""
                if tcp_flags_byte & 1:
                    tcp_flags += "F"
                if tcp_flags_byte & 2:
                    tcp_flags += "S"
                if tcp_flags_byte & 4:
                    tcp_flags += "R"
                if tcp_flags_byte & 8:
                    tcp_flags += "P"
                if tcp_flags_byte & 16:
                    tcp_flags += "A"
                if tcp_flags_byte & 32:
                    tcp_flags += "U"
                payload_start = ip_hlen + tcp_hlen
                payload = data[payload_start:] if len(data) > payload_start else b""
                return PacketInfo(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ip_version=4,
                    ip_ttl=ip_ttl,
                    ip_id=ip_id,
                    ip_flags=ip_flags,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=ProtocolType.TCP,
                    tcp_seq=tcp_seq,
                    tcp_ack=tcp_ack,
                    tcp_flags=tcp_flags,
                    tcp_window=tcp_window,
                    tcp_urgent=tcp_urgent,
                    direction=direction,
                    payload=payload,
                    payload_size=len(payload),
                    raw_data=data,
                    metadata={"packet_type": "raw"},
                )
            elif ip_protocol == 17:
                if len(data) < ip_hlen + 8:
                    return None
                udp_data = data[ip_hlen:]
                src_port = struct.unpack("!H", udp_data[0:2])[0]
                dst_port = struct.unpack("!H", udp_data[2:4])[0]
                payload_start = ip_hlen + 8
                payload = data[payload_start:] if len(data) > payload_start else b""
                return PacketInfo(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ip_version=4,
                    ip_ttl=ip_ttl,
                    ip_id=ip_id,
                    ip_flags=ip_flags,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=ProtocolType.UDP,
                    direction=direction,
                    payload=payload,
                    payload_size=len(payload),
                    raw_data=data,
                    metadata={"packet_type": "raw"},
                )
            else:
                return None
        except Exception as e:
            import logging

            logging.error(f"Error converting raw bytes: {e}")
            return None

    @staticmethod
    def _get_tcp_flags_string(tcp_header) -> str:
        """Преобразует флаги TCP из PyDivert в строку (C, E, U, A, P, R, S, F)."""
        flags = []
        flag_map = [
            ("C", "cwr"),
            ("E", "ece"),
            ("U", "urg"),
            ("A", "ack"),
            ("P", "psh"),
            ("R", "rst"),
            ("S", "syn"),
            ("F", "fin"),
        ]
        for char, attr in flag_map:
            if getattr(tcp_header, attr, False):
                flags.append(char)
        return "".join(flags)

    @staticmethod
    def _scapy_flags_to_string(flags: Union[int, str]) -> str:
        """Convert Scapy TCP flags to string."""
        if isinstance(flags, str):
            return flags
        flag_str = ""
        if flags & 1:
            flag_str += "F"
        if flags & 2:
            flag_str += "S"
        if flags & 4:
            flag_str += "R"
        if flags & 8:
            flag_str += "P"
        if flags & 16:
            flag_str += "A"
        if flags & 32:
            flag_str += "U"
        return flag_str

    @staticmethod
    def to_attack_context(packet_info: PacketInfo) -> "AttackContext":
        """Convert PacketInfo to AttackContext."""
        from recon.bypass.attacks.base import AttackContext

        return AttackContext(
            dst_ip=packet_info.dst_ip,
            dst_port=packet_info.dst_port,
            src_ip=packet_info.src_ip,
            src_port=packet_info.src_port,
            seq=packet_info.tcp_seq,
            ack=packet_info.tcp_ack,
            flags=packet_info.tcp_flags or "PA",
            payload=packet_info.payload,
            protocol="tcp" if packet_info.is_tcp else "udp",
            engine_type="native_pydivert",
        )
