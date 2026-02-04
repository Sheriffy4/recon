"""
PCAP file parsing utilities.

This module provides functions for parsing PCAP files and extracting packet data,
extracted from PacketValidator to eliminate duplication with SimplePacketValidator.
"""

import struct
import socket
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field

from .checksum_utils import validate_tcp_checksum


@dataclass
class PacketData:
    """Parsed packet data for validation."""

    index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sequence_num: int
    ack_num: int
    ttl: int
    flags: List[str]
    window_size: int
    checksum: int
    checksum_valid: bool
    payload: bytes
    payload_length: int
    raw_data: bytes
    tcp_header_length: int = 20
    tcp_flags_bits: int = 0
    tcp_options: dict = field(default_factory=dict)
    tcp_options_valid: bool = True
    tcp_options_raw: bytes = b""

    def is_fake_packet(self) -> bool:
        """Detect if this is likely a fake packet."""
        # Allow validator to override classification without changing public interfaces.
        # PacketValidator may set `_fake_override` dynamically based on attack params.
        override = getattr(self, "_fake_override", None)
        if override is not None:
            return bool(override)

        # Fallback heuristic (kept for backward compatibility)
        return self.ttl <= 3 or not self.checksum_valid

    @property
    def is_fake(self) -> bool:
        """Alias for YAML/spec rules compatibility (packets[0].is_fake)."""
        return self.is_fake_packet()

    @property
    def tcp_flags(self) -> int:
        """Integer TCP flags (e.g., 0x18 for PSH+ACK) for YAML/spec rules."""
        return int(self.tcp_flags_bits)

    @property
    def seq(self) -> int:
        """Alias for YAML/spec rules compatibility."""
        return self.sequence_num

    @property
    def ack(self) -> int:
        """Alias for YAML/spec rules compatibility."""
        return self.ack_num

    @property
    def payload_len(self) -> int:
        """Alias for YAML/spec rules compatibility."""
        return self.payload_length

    def has_flag(self, flag: str) -> bool:
        """Check if packet has specific TCP flag."""
        return flag in self.flags


def _parse_tcp_options(options: bytes) -> tuple[dict, bool, int]:
    """
    Parse TCP options bytes (20..tcp_header_len).
    Returns: (options_dict, valid, nop_count)
    """
    opts: dict = {}
    i = 0
    valid = True
    nop_count = 0

    while i < len(options):
        kind = options[i]
        if kind == 0:  # EOL
            break
        if kind == 1:  # NOP
            nop_count += 1
            i += 1
            continue
        if i + 1 >= len(options):
            valid = False
            break
        length = options[i + 1]
        if length < 2 or (i + length) > len(options):
            valid = False
            break
        data = options[i + 2 : i + length]

        if kind == 2 and length == 4:  # MSS
            opts["mss"] = struct.unpack(">H", data)[0]
        elif kind == 3 and length == 3:  # Window Scale
            opts["window_scale"] = data[0]
        elif kind == 4 and length == 2:  # SACK permitted
            opts["sack_permitted"] = True
        elif kind == 8 and length == 10:  # Timestamp
            tsval = struct.unpack(">I", data[0:4])[0]
            tsecr = struct.unpack(">I", data[4:8])[0]
            opts["timestamp"] = [tsval, tsecr]
        elif kind == 19 and length == 18:  # MD5Sig
            opts["md5sig"] = data.hex()
        else:
            # Keep unknown options as hex blobs keyed by kind
            opts[f"opt_{kind}"] = data.hex()

        i += length

    # Store nop count if present
    if nop_count:
        opts["nop"] = nop_count

    return opts, valid, nop_count


def parse_pcap_file(
    pcap_file: str, max_packets: int = 10000, debug: bool = False
) -> List[PacketData]:
    """
    Parse PCAP file and extract packet data.

    Args:
        pcap_file: Path to PCAP file
        max_packets: Maximum number of packets to parse
        debug: Enable debug output

    Returns:
        List of PacketData objects
    """
    packets = []

    try:
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            if debug:
                print(f"PCAP file not found: {pcap_file}")
            return packets

        with open(pcap_file, "rb") as f:
            # Read PCAP global header
            global_header = f.read(24)
            if len(global_header) < 24:
                return packets

            # Check magic number
            magic = struct.unpack("<I", global_header[:4])[0]
            if magic not in [0xA1B2C3D4, 0xD4C3B2A1]:
                if debug:
                    print(f"Invalid PCAP magic number: {hex(magic)}")
                return packets

            # Determine byte order
            little_endian = magic == 0xA1B2C3D4
            endian = "<" if little_endian else ">"

            packet_index = 0
            while packet_index < max_packets:
                # Read packet record header
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break

                # Parse packet header
                ts_sec, ts_usec, caplen, origlen = struct.unpack(f"{endian}IIII", packet_header)
                timestamp = ts_sec + ts_usec / 1000000.0

                # Read packet data
                packet_data = f.read(caplen)
                if len(packet_data) < caplen:
                    break

                # Parse packet
                packet = parse_single_packet(packet_data, packet_index, timestamp, debug)
                if packet:
                    packets.append(packet)

                packet_index += 1

    except (OSError, struct.error) as e:
        if debug:
            print(f"Error parsing PCAP {pcap_file}: {e}")

    return packets


def _parse_ipv4_tcp_from_ip_bytes(
    ip_data: bytes, raw_data: bytes, index: int, timestamp: float, debug: bool = False
) -> Optional[PacketData]:
    """
    Parse IPv4+TCP packet where ip_data starts at the IP header (no ethernet).
    Used for raw IP packets from WinDivert/PacketBuilder.
    """
    try:
        if len(ip_data) < 20:
            return None

        version_ihl = ip_data[0]
        version = (version_ihl >> 4) & 0xF
        if version != 4:
            return None

        ihl = (version_ihl & 0xF) * 4
        if len(ip_data) < ihl:
            return None

        ttl = ip_data[8]
        protocol = ip_data[9]
        if protocol != 6:
            return None

        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        tcp_data = ip_data[ihl:]
        if len(tcp_data) < 20:
            return None

        src_port = struct.unpack(">H", tcp_data[0:2])[0]
        dst_port = struct.unpack(">H", tcp_data[2:4])[0]
        seq_num = struct.unpack(">I", tcp_data[4:8])[0]
        ack_num = struct.unpack(">I", tcp_data[8:12])[0]

        tcp_header_len = ((tcp_data[12] >> 4) & 0xF) * 4
        if tcp_header_len < 20 or len(tcp_data) < tcp_header_len:
            return None

        flags_byte = tcp_data[13]
        flags = []
        flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        for i, flag_name in enumerate(flag_names):
            if flags_byte & (1 << i):
                flags.append(flag_name)

        window_size = struct.unpack(">H", tcp_data[14:16])[0]
        checksum = struct.unpack(">H", tcp_data[16:18])[0]

        # TCP options (if any)
        options_raw = b""
        tcp_options = {}
        tcp_options_valid = True
        if tcp_header_len > 20 and len(tcp_data) >= tcp_header_len:
            options_raw = tcp_data[20:tcp_header_len]
            tcp_options, tcp_options_valid, _ = _parse_tcp_options(options_raw)

        payload = tcp_data[tcp_header_len:] if tcp_header_len < len(tcp_data) else b""
        checksum_valid = validate_tcp_checksum(ip_data[:ihl], tcp_data[:tcp_header_len], payload)

        return PacketData(
            index=index,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            sequence_num=seq_num,
            ack_num=ack_num,
            ttl=ttl,
            flags=flags,
            window_size=window_size,
            checksum=checksum,
            checksum_valid=checksum_valid,
            payload=payload,
            payload_length=len(payload),
            raw_data=raw_data,
            tcp_header_length=tcp_header_len,
            tcp_flags_bits=flags_byte,
            tcp_options=tcp_options,
            tcp_options_valid=tcp_options_valid,
            tcp_options_raw=options_raw,
        )
    except (struct.error, OSError) as e:
        if debug:
            print(f"Error parsing raw ip/tcp packet {index}: {e}")
        return None


def parse_network_packet(
    raw_data: bytes, index: int, timestamp: float, debug: bool = False
) -> Optional[PacketData]:
    """
    Parse packet bytes from either:
      - Ethernet frame (pcap style), or
      - Raw IPv4 packet (WinDivert/raw builder style).

    This is the universal parser that handles both PCAP and raw IP packets.
    """
    if not raw_data:
        return None

    # Raw IPv4 starts with 0x4? in high nibble.
    if (raw_data[0] >> 4) == 4:
        return _parse_ipv4_tcp_from_ip_bytes(raw_data, raw_data, index, timestamp, debug)

    # Ethernet path: existing assumption (14 bytes).
    if len(raw_data) >= 34:
        # EtherType check (best-effort)
        ethertype = raw_data[12:14]
        if ethertype in (b"\x08\x00", b"\x81\x00"):  # IPv4 or VLAN
            ip_offset = 14
            # VLAN adds 4 bytes header, EtherType after VLAN tag
            if ethertype == b"\x81\x00" and len(raw_data) >= 38:
                ip_offset = 18
            ip_data = raw_data[ip_offset:]
            if ip_data and (ip_data[0] >> 4) == 4:
                return _parse_ipv4_tcp_from_ip_bytes(ip_data, raw_data, index, timestamp, debug)

    return None


def parse_single_packet(
    raw_data: bytes, index: int, timestamp: float, debug: bool = False
) -> Optional[PacketData]:
    """
    Parse raw packet data into PacketData object.

    This function now delegates to parse_network_packet for unified parsing logic.

    Args:
        raw_data: Raw packet bytes
        index: Packet index in sequence
        timestamp: Packet timestamp
        debug: Enable debug output

    Returns:
        PacketData object or None if parsing fails
    """
    try:
        # Keep old function for PCAP paths, but delegate to generic parser.
        return parse_network_packet(raw_data, index, timestamp, debug)

    except (struct.error, OSError) as e:
        if debug:
            print(f"Error parsing packet {index}: {e}")
        return None
