"""Scapy packet building utilities."""

import logging
from typing import Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from core.packet_builder import PacketParams

try:
    from scapy.all import IP, IPv6, TCP, UDP, Raw, Packet

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = IPv6 = TCP = UDP = Raw = Packet = None


class ScapyPacketBuilder:
    """Builder for Scapy-based packets."""

    @staticmethod
    def create_ip_layer(params: "PacketParams") -> Union["IP", "IPv6"]:
        """
        Create IP layer for Scapy packet.

        Args:
            params: Packet parameters

        Returns:
            Scapy IP or IPv6 layer
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is not available")

        if ":" in params.dst_ip:
            ip_layer = IPv6(dst=params.dst_ip)
        else:
            ip_layer = IP(dst=params.dst_ip)

        if params.src_ip:
            ip_layer.src = params.src_ip

        if params.ttl:
            if hasattr(ip_layer, "ttl"):
                ip_layer.ttl = params.ttl
            else:
                ip_layer.hlim = params.ttl

        return ip_layer

    @staticmethod
    def create_tcp_packet(params: "PacketParams") -> Optional["Packet"]:
        """
        Create TCP packet using Scapy.

        Args:
            params: Packet parameters

        Returns:
            Scapy Packet or None on error
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            ip_layer = ScapyPacketBuilder.create_ip_layer(params)
            tcp_layer = TCP(
                sport=params.src_port,
                dport=params.dst_port,
                seq=params.seq,
                ack=params.ack,
                flags=params.flags,
                window=params.window,
            )
            if params.options:
                tcp_layer.options = params.options

            packet = ip_layer / tcp_layer
            if params.payload:
                packet = packet / Raw(load=params.payload)

            return packet
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to create TCP packet with Scapy: {e}")
            return None

    @staticmethod
    def create_udp_packet(params: "PacketParams") -> Optional["Packet"]:
        """
        Create UDP packet using Scapy.

        Args:
            params: Packet parameters

        Returns:
            Scapy Packet or None on error
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            ip_layer = ScapyPacketBuilder.create_ip_layer(params)
            udp_layer = UDP(sport=params.src_port, dport=params.dst_port)

            packet = ip_layer / udp_layer
            if params.payload:
                packet = packet / Raw(load=params.payload)

            return packet
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to create UDP packet with Scapy: {e}")
            return None
