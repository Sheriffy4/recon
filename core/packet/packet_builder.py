"""
Packet builder for creating network packets from raw bytes.
Replaces Scapy packet construction functionality.
"""

import struct
import socket
import random
from typing import Dict, List, Optional, Tuple
from .packet_models import (
    EthernetHeader,
    IPv4Header,
    IPv6Header,
    TCPHeader,
    UDPHeader,
    ICMPHeader,
    DNSHeader,
    HTTPHeader,
    TLSHeader,
)


class PacketBuilder:
    """Builder for constructing network packets from raw bytes."""

    def __init__(self):
        self.layers = []
        self.payload = b""

    @staticmethod
    def _internet_checksum(data: bytes) -> int:
        """Compute RFC1071 checksum."""
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    @staticmethod
    def _detect_ip_offset(packet_data: bytes) -> Tuple[Optional[int], Optional[int]]:
        """Return (ip_offset, ip_version) for Ethernet-less or Ethernet packets."""
        if len(packet_data) >= 1 and (packet_data[0] >> 4) in (4, 6):
            return 0, (packet_data[0] >> 4)
        if len(packet_data) >= 15 and (packet_data[14] >> 4) in (4, 6):
            return 14, (packet_data[14] >> 4)
        return None, None

    def ethernet(
        self,
        dst_mac: str = "00:00:00:00:00:00",
        src_mac: str = "00:00:00:00:00:00",
        ethertype: int = 0x0800,
    ) -> "PacketBuilder":
        """Add Ethernet header."""
        header = EthernetHeader(dst_mac=dst_mac, src_mac=src_mac, ethertype=ethertype)
        self.layers.append(("ethernet", header))
        return self

    def ipv4(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int = 6,
        ttl: int = 64,
        flags: int = 0x4000,
        identification: Optional[int] = None,
        fragment_offset: int = 0,
    ) -> "PacketBuilder":
        """Add IPv4 header."""
        if identification is None:
            identification = random.randint(1, 65535)

        header = IPv4Header(
            version=4,
            ihl=5,
            tos=0,
            total_length=0,  # Will be calculated
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=0,  # Will be calculated
            src_ip=src_ip,
            dst_ip=dst_ip,
        )
        self.layers.append(("ipv4", header))
        return self

    def ipv6(
        self, src_ip: str, dst_ip: str, next_header: int = 6, hop_limit: int = 64
    ) -> "PacketBuilder":
        """Add IPv6 header."""
        header = IPv6Header(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=0,  # Will be calculated
            next_header=next_header,
            hop_limit=hop_limit,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )
        self.layers.append(("ipv6", header))
        return self

    def tcp(
        self,
        src_port: int,
        dst_port: int,
        seq: Optional[int] = None,
        ack: Optional[int] = None,
        flags: int = 0x18,
        window: int = 8192,
    ) -> "PacketBuilder":
        """Add TCP header."""
        if seq is None:
            seq = random.randint(1, 2**32 - 1)
        if ack is None:
            ack = 0

        header = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            data_offset=5,
            reserved=0,
            flags=flags,
            window=window,
            checksum=0,  # Will be calculated
            urgent_ptr=0,
            options=b"",
        )
        self.layers.append(("tcp", header))
        return self

    def udp(self, src_port: int, dst_port: int) -> "PacketBuilder":
        """Add UDP header."""
        header = UDPHeader(
            src_port=src_port,
            dst_port=dst_port,
            length=0,  # Will be calculated
            checksum=0,  # Will be calculated
        )
        self.layers.append(("udp", header))
        return self

    def icmp(
        self,
        icmp_type: int = 8,
        code: int = 0,
        identification: Optional[int] = None,
        sequence: Optional[int] = None,
    ) -> "PacketBuilder":
        """Add ICMP header."""
        if identification is None:
            identification = random.randint(1, 65535)
        if sequence is None:
            sequence = 1

        header = ICMPHeader(
            icmp_type=icmp_type,
            code=code,
            checksum=0,  # Will be calculated
            identification=identification,
            sequence=sequence,
        )
        self.layers.append(("icmp", header))
        return self

    def dns(
        self,
        transaction_id: Optional[int] = None,
        flags: int = 0x0100,
        questions: int = 1,
        answers: int = 0,
    ) -> "PacketBuilder":
        """Add DNS header."""
        if transaction_id is None:
            transaction_id = random.randint(1, 65535)

        header = DNSHeader(
            transaction_id=transaction_id,
            flags=flags,
            questions=questions,
            answer_rrs=answers,
            authority_rrs=0,
            additional_rrs=0,
        )
        self.layers.append(("dns", header))
        return self

    def http(
        self,
        method: str = "GET",
        path: str = "/",
        version: str = "HTTP/1.1",
        headers: Optional[Dict[str, str]] = None,
    ) -> "PacketBuilder":
        """Add HTTP header."""
        if headers is None:
            headers = {}

        header = HTTPHeader(method=method, path=path, version=version, headers=headers, body=b"")
        self.layers.append(("http", header))
        return self

    def tls(
        self, content_type: int = 22, version: int = 0x0303, length: int = 0
    ) -> "PacketBuilder":
        """Add TLS header."""
        header = TLSHeader(content_type=content_type, version=version, length=length)
        self.layers.append(("tls", header))
        return self

    def add_payload(self, data: bytes) -> "PacketBuilder":
        """Add payload data."""
        self.payload = data
        return self

    def build(self) -> bytes:
        """Build the complete packet."""
        packet_data = b""

        # Build headers in order
        for layer_type, header in self.layers:
            if layer_type == "ethernet":
                packet_data += self._build_ethernet(header)
            elif layer_type == "ipv4":
                packet_data += self._build_ipv4(header)
            elif layer_type == "ipv6":
                packet_data += self._build_ipv6(header)
            elif layer_type == "tcp":
                packet_data += self._build_tcp(header)
            elif layer_type == "udp":
                packet_data += self._build_udp(header)
            elif layer_type == "icmp":
                packet_data += self._build_icmp(header)
            elif layer_type == "dns":
                packet_data += self._build_dns(header)
            elif layer_type == "http":
                packet_data += self._build_http(header)
            elif layer_type == "tls":
                packet_data += self._build_tls(header)

        # Add payload
        packet_data += self.payload

        # Calculate and update checksums
        packet_data = self._update_checksums(packet_data)

        return packet_data

    def _build_ethernet(self, header: EthernetHeader) -> bytes:
        """Build Ethernet header."""
        dst_mac = bytes.fromhex(header.dst_mac.replace(":", ""))
        src_mac = bytes.fromhex(header.src_mac.replace(":", ""))
        return dst_mac + src_mac + struct.pack("!H", header.ethertype)

    def _build_ipv4(self, header: IPv4Header) -> bytes:
        """Build IPv4 header."""
        version_ihl = (header.version << 4) | header.ihl

        # Backward-compatible flags handling:
        # some callers pass raw 0x4000/0x2000 (already shifted), others pass 0..7 bits.
        flags_value = int(header.flags or 0)
        if flags_value > 0x7:
            flags_bits = (flags_value & 0xE000) >> 13
        else:
            flags_bits = flags_value & 0x7

        frag_off = int(header.fragment_offset or 0) & 0x1FFF
        flags_frag = (flags_bits << 13) | frag_off

        src_ip = socket.inet_aton(header.src_ip)
        dst_ip = socket.inet_aton(header.dst_ip)

        return struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            header.tos,
            header.total_length,
            header.identification,
            flags_frag,
            header.ttl,
            header.protocol,
            header.checksum,
            src_ip,
            dst_ip,
        )

    def _build_ipv6(self, header: IPv6Header) -> bytes:
        """Build IPv6 header."""
        version_tc_fl = (header.version << 28) | (header.traffic_class << 20) | header.flow_label

        src_ip = socket.inet_pton(socket.AF_INET6, header.src_ip)
        dst_ip = socket.inet_pton(socket.AF_INET6, header.dst_ip)

        return struct.pack(
            "!IHBB16s16s",
            version_tc_fl,
            header.payload_length,
            header.next_header,
            header.hop_limit,
            src_ip,
            dst_ip,
        )

    def _build_tcp(self, header: TCPHeader) -> bytes:
        """Build TCP header."""
        options = header.options or b""
        # TCP options must be padded to 4-byte alignment
        if len(options) % 4:
            options += b"\x00" * (4 - (len(options) % 4))
        data_offset_words = 5 + (len(options) // 4)
        data_offset_flags = (data_offset_words << 12) | (header.reserved << 6) | header.flags

        tcp_header = struct.pack(
            "!HHLLHHHH",
            header.src_port,
            header.dst_port,
            header.seq,
            header.ack,
            data_offset_flags,
            header.window,
            header.checksum,
            header.urgent_ptr,
        )

        return tcp_header + options

    def _build_udp(self, header: UDPHeader) -> bytes:
        """Build UDP header."""
        return struct.pack(
            "!HHHH", header.src_port, header.dst_port, header.length, header.checksum
        )

    def _build_icmp(self, header: ICMPHeader) -> bytes:
        """Build ICMP header."""
        return struct.pack(
            "!BBHHH",
            header.icmp_type,
            header.code,
            header.checksum,
            header.identification,
            header.sequence,
        )

    def _build_dns(self, header: DNSHeader) -> bytes:
        """Build DNS header."""
        return struct.pack(
            "!HHHHHH",
            header.transaction_id,
            header.flags,
            header.questions,
            header.answer_rrs,
            header.authority_rrs,
            header.additional_rrs,
        )

    def _build_http(self, header: HTTPHeader) -> bytes:
        """Build HTTP header."""
        http_line = f"{header.method} {header.path} {header.version}\r\n"

        header_lines = []
        for name, value in header.headers.items():
            header_lines.append(f"{name}: {value}\r\n")

        http_data = http_line + "".join(header_lines) + "\r\n"
        return http_data.encode("utf-8") + header.body

    def _build_tls(self, header: TLSHeader) -> bytes:
        """Build TLS header."""
        return struct.pack("!BHH", header.content_type, header.version, header.length)

    def _update_checksums(self, packet_data: bytes) -> bytes:
        """Update checksums in the packet."""
        ip_offset, ip_version = self._detect_ip_offset(packet_data)
        if ip_offset is None or ip_version is None:
            return packet_data

        buf = bytearray(packet_data)

        if ip_version == 4:
            if len(buf) < ip_offset + 20:
                return packet_data

            ihl = (buf[ip_offset] & 0x0F) * 4
            if ihl < 20 or len(buf) < ip_offset + ihl:
                return packet_data

            total_len = len(buf) - ip_offset
            struct.pack_into("!H", buf, ip_offset + 2, total_len)

            # IPv4 header checksum
            struct.pack_into("!H", buf, ip_offset + 10, 0)
            csum = self._internet_checksum(bytes(buf[ip_offset : ip_offset + ihl]))
            struct.pack_into("!H", buf, ip_offset + 10, csum)

            proto = buf[ip_offset + 9]
            src_ip = bytes(buf[ip_offset + 12 : ip_offset + 16])
            dst_ip = bytes(buf[ip_offset + 16 : ip_offset + 20])
            l4_offset = ip_offset + ihl
            if len(buf) < l4_offset:
                return bytes(buf)
            l4_len = len(buf) - l4_offset

            if proto == 6 and len(buf) >= l4_offset + 20:
                # TCP checksum
                struct.pack_into("!H", buf, l4_offset + 16, 0)
                pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, proto, l4_len)
                tcp_seg = bytes(buf[l4_offset:])
                tcp_csum = self._internet_checksum(pseudo + tcp_seg)
                struct.pack_into("!H", buf, l4_offset + 16, tcp_csum)

            elif proto == 17 and len(buf) >= l4_offset + 8:
                # UDP length + checksum
                struct.pack_into("!H", buf, l4_offset + 4, l4_len)
                struct.pack_into("!H", buf, l4_offset + 6, 0)
                pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, proto, l4_len)
                udp_seg = bytes(buf[l4_offset:])
                udp_csum = self._internet_checksum(pseudo + udp_seg)
                # UDP checksum of 0 means "not used" in IPv4; keep computed value unless it's 0.
                struct.pack_into("!H", buf, l4_offset + 6, udp_csum)

            elif proto == 1 and len(buf) >= l4_offset + 4:
                # ICMP checksum
                struct.pack_into("!H", buf, l4_offset + 2, 0)
                icmp_seg = bytes(buf[l4_offset:])
                icmp_csum = self._internet_checksum(icmp_seg)
                struct.pack_into("!H", buf, l4_offset + 2, icmp_csum)

            return bytes(buf)

        if ip_version == 6:
            if len(buf) < ip_offset + 40:
                return packet_data

            payload_len = len(buf) - ip_offset - 40
            struct.pack_into("!H", buf, ip_offset + 4, payload_len)

            next_header = buf[ip_offset + 6]
            src_ip = bytes(buf[ip_offset + 8 : ip_offset + 24])
            dst_ip = bytes(buf[ip_offset + 24 : ip_offset + 40])
            l4_offset = ip_offset + 40
            l4_len = len(buf) - l4_offset

            # Pseudo header for IPv6: src(16)+dst(16)+len(4)+zeros(3)+next(1)
            pseudo = src_ip + dst_ip + struct.pack("!I", l4_len) + b"\x00" * 3 + bytes([next_header])

            if next_header == 6 and len(buf) >= l4_offset + 20:
                struct.pack_into("!H", buf, l4_offset + 16, 0)
                tcp_seg = bytes(buf[l4_offset:])
                tcp_csum = self._internet_checksum(pseudo + tcp_seg)
                struct.pack_into("!H", buf, l4_offset + 16, tcp_csum)

            elif next_header == 17 and len(buf) >= l4_offset + 8:
                struct.pack_into("!H", buf, l4_offset + 4, l4_len)
                struct.pack_into("!H", buf, l4_offset + 6, 0)
                udp_seg = bytes(buf[l4_offset:])
                udp_csum = self._internet_checksum(pseudo + udp_seg)
                # In IPv6 UDP checksum must not be 0; represent 0 as 0xFFFF
                if udp_csum == 0:
                    udp_csum = 0xFFFF
                struct.pack_into("!H", buf, l4_offset + 6, udp_csum)

            return bytes(buf)

        return packet_data

    def reset(self) -> "PacketBuilder":
        """Reset the builder for reuse."""
        self.layers.clear()
        self.payload = b""
        return self


class FragmentedPacketBuilder:
    """Builder for creating fragmented packets."""

    def __init__(self, packet_builder: PacketBuilder, mtu: int = 1500):
        self.packet_builder = packet_builder
        self.mtu = mtu

    def fragment(self) -> List[bytes]:
        """Fragment the packet into multiple packets."""
        original_packet = self.packet_builder.build()

        # Best-effort IPv4 fragmentation for packets built by PacketBuilder.
        fragments = []
        fragment_id = random.randint(1, 65535)

        ip_offset, ip_version = PacketBuilder._detect_ip_offset(original_packet)
        if ip_offset is None or ip_version != 4 or len(original_packet) < ip_offset + 20:
            return [original_packet]

        ihl = (original_packet[ip_offset] & 0x0F) * 4
        if ihl < 20 or len(original_packet) < ip_offset + ihl:
            return [original_packet]

        ip_payload = original_packet[ip_offset + ihl :]
        if not ip_payload:
            return [original_packet]

        # Determine if Ethernet header should be replicated
        has_eth = (ip_offset == 14)

        # Max payload per fragment must be multiple of 8 bytes (except last)
        max_payload = max(8, self.mtu - ihl - (14 if has_eth else 0))
        max_payload_aligned = (max_payload // 8) * 8
        if max_payload_aligned <= 0:
            return [original_packet]

        # Find original IPv4 layer params
        src_ip = dst_ip = None
        proto = 6
        ttl = 64
        for layer_type, header in self.packet_builder.layers:
            if layer_type == "ipv4":
                src_ip = header.src_ip
                dst_ip = header.dst_ip
                proto = header.protocol
                ttl = header.ttl
                break
        if not src_ip or not dst_ip:
            # Fallback to parsing raw header
            src_ip = socket.inet_ntoa(original_packet[ip_offset + 12 : ip_offset + 16])
            dst_ip = socket.inet_ntoa(original_packet[ip_offset + 16 : ip_offset + 20])
            proto = original_packet[ip_offset + 9]
            ttl = original_packet[ip_offset + 8]

        offset_bytes = 0
        while offset_bytes < len(ip_payload):
            is_last = (offset_bytes + max_payload_aligned) >= len(ip_payload)
            frag_payload = (
                ip_payload[offset_bytes:] if is_last else ip_payload[offset_bytes : offset_bytes + max_payload_aligned]
            )

            # MF flag if not last
            flags = 0x2000 if not is_last else 0x0000

            fragment_builder = PacketBuilder()

            # Replicate Ethernet header if present in the original builder
            if has_eth:
                for layer_type, header in self.packet_builder.layers:
                    if layer_type == "ethernet":
                        fragment_builder.ethernet(
                            dst_mac=header.dst_mac,
                            src_mac=header.src_mac,
                            ethertype=header.ethertype,
                        )
                        break

            fragment_builder.ipv4(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto,
                ttl=ttl,
                flags=flags,
                identification=fragment_id,
                fragment_offset=(offset_bytes // 8),
            )

            fragment_builder.add_payload(frag_payload)
            fragments.append(fragment_builder.build())

            offset_bytes += len(frag_payload)

        return fragments


class PacketModifier:
    """Modifier for altering existing packets."""

    @staticmethod
    def modify_tcp_flags(packet_data: bytes, new_flags: int) -> bytes:
        """Modify TCP flags in a packet."""
        ip_offset, ip_version = PacketBuilder._detect_ip_offset(packet_data)
        if ip_offset is None or ip_version != 4 or len(packet_data) < ip_offset + 20:
            return packet_data

        ihl = (packet_data[ip_offset] & 0x0F) * 4
        tcp_offset = ip_offset + ihl

        if len(packet_data) < tcp_offset + 13:
            return packet_data

        # Modify flags (byte 13 of TCP header)
        packet_list = bytearray(packet_data)
        packet_list[tcp_offset + 13] = new_flags

        return bytes(packet_list)

    @staticmethod
    def modify_ip_ttl(packet_data: bytes, new_ttl: int) -> bytes:
        """Modify IP TTL in a packet."""
        ip_offset, ip_version = PacketBuilder._detect_ip_offset(packet_data)
        if ip_offset is None or ip_version != 4:
            return packet_data

        if len(packet_data) < ip_offset + 9:
            return packet_data

        packet_list = bytearray(packet_data)
        packet_list[ip_offset + 8] = new_ttl

        return bytes(packet_list)

    @staticmethod
    def modify_tcp_window(packet_data: bytes, new_window: int) -> bytes:
        """Modify TCP window size in a packet."""
        ip_offset, ip_version = PacketBuilder._detect_ip_offset(packet_data)
        if ip_offset is None or ip_version != 4 or len(packet_data) < ip_offset + 20:
            return packet_data

        ihl = (packet_data[ip_offset] & 0x0F) * 4
        tcp_offset = ip_offset + ihl

        if len(packet_data) < tcp_offset + 16:
            return packet_data

        packet_list = bytearray(packet_data)
        struct.pack_into("!H", packet_list, tcp_offset + 14, new_window)

        return bytes(packet_list)

    @staticmethod
    def add_tcp_options(packet_data: bytes, options: bytes) -> bytes:
        """Add TCP options to a packet."""
        # This is a simplified implementation
        # In practice, you'd need to:
        # 1. Parse the existing TCP header
        # 2. Adjust the data offset
        # 3. Insert options
        # 4. Recalculate checksums

        return packet_data + options

    @staticmethod
    def modify_payload(packet_data: bytes, new_payload: bytes, payload_offset: int) -> bytes:
        """Replace payload in a packet."""
        if payload_offset >= len(packet_data):
            return packet_data

        return packet_data[:payload_offset] + new_payload


# Convenience functions for common packet types
def create_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Create a TCP SYN packet."""
    return (
        PacketBuilder()
        .ipv4(src_ip=src_ip, dst_ip=dst_ip, protocol=6)
        .tcp(src_port=src_port, dst_port=dst_port, flags=0x02)
        .build()
    )


def create_http_request(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    method: str = "GET",
    path: str = "/",
    headers: Optional[Dict[str, str]] = None,
) -> bytes:
    """Create an HTTP request packet."""
    if headers is None:
        headers = {"Host": dst_ip, "User-Agent": "PacketBuilder/1.0"}

    return (
        PacketBuilder()
        .ipv4(src_ip=src_ip, dst_ip=dst_ip, protocol=6)
        .tcp(src_port=src_port, dst_port=dst_port, flags=0x18)
        .http(method=method, path=path, headers=headers)
        .build()
    )


def create_dns_query(src_ip: str, dst_ip: str, src_port: int, dst_port: int, domain: str) -> bytes:
    """Create a DNS query packet."""
    # Simple DNS query payload
    query_payload = _build_dns_query(domain)

    return (
        PacketBuilder()
        .ipv4(src_ip=src_ip, dst_ip=dst_ip, protocol=17)
        .udp(src_port=src_port, dst_port=dst_port)
        .dns()
        .add_payload(query_payload)
        .build()
    )


def _build_dns_query(domain: str) -> bytes:
    """Build DNS query payload."""
    query = b""

    # Encode domain name
    for part in domain.split("."):
        query += bytes([len(part)]) + part.encode("ascii")
    query += b"\x00"  # End of domain name

    # Query type (A record) and class (IN)
    query += struct.pack("!HH", 1, 1)

    return query
