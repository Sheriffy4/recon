"""
Protocol-specific handlers for raw packet processing.
"""

import struct
import socket
from typing import Dict, Tuple, Any

from .packet_models import (
    EthernetHeader,
    IPv4Header,
    IPv6Header,
    TCPHeader,
    UDPHeader,
    ICMPHeader,
    DNSHeader,
    HTTPHeader,
)


class ProtocolHandler:
    """Base class for protocol handlers."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[Any, int]:
        """Parse protocol data and return header object and new offset."""
        raise NotImplementedError

    def build(self, header: Any) -> bytes:
        """Build protocol data from header object."""
        raise NotImplementedError

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify protocol data with given modifications."""
        raise NotImplementedError


class EthernetHandler(ProtocolHandler):
    """Ethernet frame handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[EthernetHeader, int]:
        """Parse Ethernet header."""
        if len(data) < offset + 14:
            raise ValueError("Insufficient data for Ethernet header")

        eth_data = data[offset : offset + 14]
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", eth_data)

        header = EthernetHeader(
            dst_mac=dst_mac.hex(":"), src_mac=src_mac.hex(":"), ethertype=ethertype
        )

        return header, offset + 14

    def build(self, header: EthernetHeader) -> bytes:
        """Build Ethernet header."""
        dst_mac = bytes.fromhex(header.dst_mac.replace(":", ""))
        src_mac = bytes.fromhex(header.src_mac.replace(":", ""))

        return struct.pack("!6s6sH", dst_mac, src_mac, header.ethertype)

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify Ethernet header."""
        header, _ = self.parse(data)

        for field, value in modifications.items():
            if hasattr(header, field):
                setattr(header, field, value)

        new_header = self.build(header)
        return new_header + data[14:]


class IPv4Handler(ProtocolHandler):
    """IPv4 packet handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[IPv4Header, int]:
        """Parse IPv4 header."""
        if len(data) < offset + 20:
            raise ValueError("Insufficient data for IPv4 header")

        ip_data = data[offset : offset + 20]

        # Parse fixed part of IPv4 header
        (
            version_ihl,
            tos,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
        ) = struct.unpack("!BBHHHBBH4s4s", ip_data)

        version = (version_ihl >> 4) & 0xF
        ihl = version_ihl & 0xF
        header_length = ihl * 4

        # Parse options if present
        options = b""
        if header_length > 20:
            if len(data) < offset + header_length:
                raise ValueError("Insufficient data for IPv4 options")
            options = data[offset + 20 : offset + header_length]

        header = IPv4Header(
            version=version,
            ihl=ihl,
            tos=tos,
            total_length=total_length,
            identification=identification,
            flags=(flags_fragment >> 13) & 0x7,
            fragment_offset=flags_fragment & 0x1FFF,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            src_ip=socket.inet_ntoa(src_ip),
            dst_ip=socket.inet_ntoa(dst_ip),
            options=options,
        )

        return header, offset + header_length

    def build(self, header: IPv4Header) -> bytes:
        """Build IPv4 header."""
        version_ihl = (header.version << 4) | header.ihl
        flags_fragment = (header.flags << 13) | header.fragment_offset

        src_ip = socket.inet_aton(header.src_ip)
        dst_ip = socket.inet_aton(header.dst_ip)

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            header.tos,
            header.total_length,
            header.identification,
            flags_fragment,
            header.ttl,
            header.protocol,
            header.checksum,
            src_ip,
            dst_ip,
        )

        return ip_header + header.options

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify IPv4 header."""
        header, header_end = self.parse(data)

        for field, value in modifications.items():
            if hasattr(header, field):
                setattr(header, field, value)

        # Recalculate header length if options changed
        if "options" in modifications:
            options_len = len(header.options)
            padding = (4 - (options_len % 4)) % 4
            header.options += b"\x00" * padding
            header.ihl = (20 + len(header.options)) // 4

        # Recalculate checksum if needed
        if "checksum" not in modifications:
            header.checksum = 0
            temp_header = self.build(header)
            header.checksum = self._calculate_ipv4_checksum(temp_header)

        new_header = self.build(header)
        return new_header + data[header_end:]

    def _calculate_ipv4_checksum(self, header: bytes) -> int:
        """Calculate IPv4 header checksum."""
        checksum = 0

        # Sum all 16-bit words
        for i in range(0, len(header), 2):
            if i + 1 < len(header):
                word = (header[i] << 8) + header[i + 1]
            else:
                word = header[i] << 8
            checksum += word

        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return ~checksum & 0xFFFF


class IPv6Handler(ProtocolHandler):
    """IPv6 packet handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[IPv6Header, int]:
        """Parse IPv6 header."""
        if len(data) < offset + 40:
            raise ValueError("Insufficient data for IPv6 header")

        ipv6_data = data[offset : offset + 40]

        version_class_label, payload_length, next_header, hop_limit = struct.unpack(
            "!IHBB", ipv6_data[:8]
        )

        src_ip = ipv6_data[8:24]
        dst_ip = ipv6_data[24:40]

        version = (version_class_label >> 28) & 0xF
        traffic_class = (version_class_label >> 20) & 0xFF
        flow_label = version_class_label & 0xFFFFF

        header = IPv6Header(
            version=version,
            traffic_class=traffic_class,
            flow_label=flow_label,
            payload_length=payload_length,
            next_header=next_header,
            hop_limit=hop_limit,
            src_ip=socket.inet_ntop(socket.AF_INET6, src_ip),
            dst_ip=socket.inet_ntop(socket.AF_INET6, dst_ip),
        )

        return header, offset + 40

    def build(self, header: IPv6Header) -> bytes:
        """Build IPv6 header."""
        version_class_label = (
            (header.version << 28) | (header.traffic_class << 20) | header.flow_label
        )

        src_ip = socket.inet_pton(socket.AF_INET6, header.src_ip)
        dst_ip = socket.inet_pton(socket.AF_INET6, header.dst_ip)

        return struct.pack(
            "!IHBB16s16s",
            version_class_label,
            header.payload_length,
            header.next_header,
            header.hop_limit,
            src_ip,
            dst_ip,
        )

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify IPv6 header."""
        header, header_end = self.parse(data)

        for field, value in modifications.items():
            if hasattr(header, field):
                setattr(header, field, value)

        new_header = self.build(header)
        return new_header + data[header_end:]


class TCPHandler(ProtocolHandler):
    """TCP segment handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[TCPHeader, int]:
        """Parse TCP header."""
        if len(data) < offset + 20:
            raise ValueError("Insufficient data for TCP header")

        tcp_data = data[offset : offset + 20]

        src_port, dst_port, seq_num, ack_num, offset_flags, window, checksum, urgent = (
            struct.unpack("!HHIIHHH H", tcp_data)
        )

        data_offset = (offset_flags >> 12) & 0xF
        header_length = data_offset * 4

        flags = offset_flags & 0x1FF

        # Parse options if present
        options = b""
        if header_length > 20:
            if len(data) < offset + header_length:
                raise ValueError("Insufficient data for TCP options")
            options = data[offset + 20 : offset + header_length]

        header = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            data_offset=data_offset,
            flags=flags,
            window=window,
            checksum=checksum,
            urgent=urgent,
            options=options,
        )

        return header, offset + header_length

    def build(self, header: TCPHeader) -> bytes:
        """Build TCP header."""
        offset_flags = (header.data_offset << 12) | header.flags

        tcp_header = struct.pack(
            "!HHIIHHH H",
            header.src_port,
            header.dst_port,
            header.seq_num,
            header.ack_num,
            offset_flags,
            header.window,
            header.checksum,
            header.urgent,
        )

        return tcp_header + header.options

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify TCP header."""
        header, header_end = self.parse(data)

        for field, value in modifications.items():
            if hasattr(header, field):
                setattr(header, field, value)

        # Recalculate data offset if options changed
        if "options" in modifications:
            options_len = len(header.options)
            padding = (4 - (options_len % 4)) % 4
            header.options += b"\x00" * padding
            header.data_offset = (20 + len(header.options)) // 4

        new_header = self.build(header)
        return new_header + data[header_end:]


class UDPHandler(ProtocolHandler):
    """UDP datagram handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[UDPHeader, int]:
        """Parse UDP header."""
        if len(data) < offset + 8:
            raise ValueError("Insufficient data for UDP header")

        udp_data = data[offset : offset + 8]
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", udp_data)

        header = UDPHeader(src_port=src_port, dst_port=dst_port, length=length, checksum=checksum)

        return header, offset + 8

    def build(self, header: UDPHeader) -> bytes:
        """Build UDP header."""
        return struct.pack(
            "!HHHH", header.src_port, header.dst_port, header.length, header.checksum
        )

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify UDP header."""
        header, header_end = self.parse(data)

        for field, value in modifications.items():
            if hasattr(header, field):
                setattr(header, field, value)

        new_header = self.build(header)
        return new_header + data[header_end:]


class ICMPHandler(ProtocolHandler):
    """ICMP message handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[ICMPHeader, int]:
        """Parse ICMP header."""
        if len(data) < offset + 8:
            raise ValueError("Insufficient data for ICMP header")

        icmp_data = data[offset : offset + 8]
        msg_type, code, checksum, rest = struct.unpack("!BBHI", icmp_data)

        header = ICMPHeader(type=msg_type, code=code, checksum=checksum, rest=rest)

        return header, offset + 8

    def build(self, header: ICMPHeader) -> bytes:
        """Build ICMP header."""
        return struct.pack("!BBHI", header.type, header.code, header.checksum, header.rest)

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify ICMP header."""
        header, header_end = self.parse(data)

        for field, value in modifications.items():
            if hasattr(header, field):
                setattr(header, field, value)

        new_header = self.build(header)
        return new_header + data[header_end:]


class DNSHandler(ProtocolHandler):
    """DNS message handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[DNSHeader, int]:
        """Parse DNS header."""
        if len(data) < offset + 12:
            raise ValueError("Insufficient data for DNS header")

        dns_data = data[offset : offset + 12]
        transaction_id, flags, questions, answers, authority, additional = struct.unpack(
            "!HHHHHH", dns_data
        )

        header = DNSHeader(
            transaction_id=transaction_id,
            flags=flags,
            questions=questions,
            answers=answers,
            authority=authority,
            additional=additional,
        )

        return header, offset + 12

    def build(self, header: DNSHeader) -> bytes:
        """Build DNS header."""
        return struct.pack(
            "!HHHHHH",
            header.transaction_id,
            header.flags,
            header.questions,
            header.answers,
            header.authority,
            header.additional,
        )

    def modify(self, data: bytes, modifications: Dict[str, Any]) -> bytes:
        """Modify DNS header."""
        header, header_end = self.parse(data)

        for field, value in modifications.items():
            if hasattr(header, field):
                setattr(header, field, value)

        new_header = self.build(header)
        return new_header + data[header_end:]


class HTTPHandler(ProtocolHandler):
    """HTTP message handler."""

    def parse(self, data: bytes, offset: int = 0) -> Tuple[HTTPHeader, int]:
        """Parse HTTP header."""
        try:
            http_data = data[offset:].decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            http_data = data[offset:].decode("latin-1")

        lines = http_data.split("\r\n")
        if not lines:
            raise ValueError("Invalid HTTP data")

        # Parse request/response line
        first_line = lines[0]
        if first_line.startswith("HTTP/"):
            # Response
            parts = first_line.split(" ", 2)
            version = parts[0] if len(parts) > 0 else "HTTP/1.1"
            status_code = int(parts[1]) if len(parts) > 1 else 200
            reason_phrase = parts[2] if len(parts) > 2 else "OK"
            method = None
            path = None
        else:
            # Request
            parts = first_line.split(" ", 2)
            method = parts[0] if len(parts) > 0 else "GET"
            path = parts[1] if len(parts) > 1 else "/"
            version = parts[2] if len(parts) > 2 else "HTTP/1.1"
            status_code = None
            reason_phrase = None

        # Parse headers
        headers = {}
        header_end_idx = 1
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                header_end_idx = i + 1
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        # Calculate header length in bytes
        header_text = "\r\n".join(lines[:header_end_idx]) + "\r\n"
        header_length = len(header_text.encode("utf-8"))

        header = HTTPHeader(
            method=method,
            path=path,
            version=version,
            headers=headers,
            length=header_length,
        )

        return header
