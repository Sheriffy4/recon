"""Low-level packet building functions."""

import struct
import logging
from typing import Tuple, Optional, Dict, Any
from .types import TCPSegmentSpec, UDPDatagramSpec, PacketMetadata


class PacketBuilder:
    """
    Responsible for low-level assembly of IPv4/TCP/UDP packet bytes.
    Contains only pure functions without side effects.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger(self.__class__.__name__)

    @staticmethod
    def extract_metadata(raw: bytes) -> PacketMetadata:
        """Extract metadata from raw packet bytes."""
        ip_hl = (raw[0] & 0x0F) * 4
        tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4 if len(raw) > ip_hl + 12 else 20
        if tcp_hl < 20:
            tcp_hl = 20

        return PacketMetadata(
            ip_header_len=ip_hl,
            tcp_header_len=tcp_hl,
            base_seq=struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0] if len(raw) > ip_hl+8 else 0,
            base_ack=struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0] if len(raw) > ip_hl+12 else 0,
            base_win=struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0] if len(raw) > ip_hl+16 else 65535,
            base_ttl=raw[8] if len(raw) > 8 else 64,
            base_ip_id=struct.unpack("!H", raw[4:6])[0] if len(raw) > 6 else 0,
            src_ip=raw[12:16] if len(raw) > 16 else b'\x00'*4,
            dst_ip=raw[16:20] if len(raw) > 20 else b'\x00'*4,
            src_port=struct.unpack("!H", raw[ip_hl:ip_hl+2])[0] if len(raw) > ip_hl+2 else 0,
            dst_port=struct.unpack("!H", raw[ip_hl+2:ip_hl+4])[0] if len(raw) > ip_hl+4 else 0
        )

    @staticmethod
    def _ones_complement_sum(data: bytes) -> int:
        """Calculate ones complement sum for checksum."""
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return s

    @classmethod
    def _checksum16(cls, data: bytes) -> int:
        """Calculate 16-bit checksum."""
        return (~cls._ones_complement_sum(data)) & 0xFFFF

    @classmethod
    def _build_pseudo_header(cls, ip_hdr: bytes, transport_len: int, proto: int = 6) -> bytes:
        """Build pseudo header for TCP/UDP checksum."""
        src_ip = ip_hdr[12:16]
        dst_ip = ip_hdr[16:20]
        return src_ip + dst_ip + b'\x00' + bytes([proto]) + struct.pack('!H', transport_len)

    @classmethod
    def build_tcp_segment(cls, original_raw: bytes, spec: TCPSegmentSpec,
                         window_div: int = 8, ip_id: int = 0) -> bytes:
        """
        Build a complete TCP/IP packet from specification.

        Args:
            original_raw: Original packet bytes to use as template
            spec: TCP segment specification
            window_div: Window division factor
            ip_id: IP identification field value

        Returns:
            Complete packet bytes ready for transmission
        """
        try:
            raw = bytearray(original_raw)
            meta = cls.extract_metadata(original_raw)

            # Build IP header
            ip_hdr = bytearray(raw[:meta.ip_header_len])

            # Build TCP header
            tcp_hdr = bytearray(raw[meta.ip_header_len:meta.ip_header_len + meta.tcp_header_len])

            # Set sequence number
            seq = (meta.base_seq + spec.rel_seq + spec.seq_extra) & 0xFFFFFFFF
            tcp_hdr[4:8] = struct.pack("!I", seq)

            # Set acknowledgment number
            tcp_hdr[8:12] = struct.pack("!I", meta.base_ack)

            # Set flags
            if spec.flags is not None:
                tcp_hdr[13] = spec.flags & 0xFF

            # Set window
            if spec.window_override is not None:
                window = spec.window_override
            else:
                window = max(meta.base_win // max(1, window_div), 1024)
            tcp_hdr[14:16] = struct.pack("!H", window)

            # Set TTL
            if spec.ttl is not None:
                ip_hdr[8] = max(1, min(255, spec.ttl))
            else:
                ip_hdr[8] = meta.base_ttl

            # Set IP ID
            ip_hdr[4:6] = struct.pack("!H", ip_id & 0xFFFF)

            # Add MD5SIG option if requested
            if spec.add_md5sig_option:
                tcp_hdr = bytearray(cls._inject_md5sig_option(bytes(tcp_hdr)))

            # Verify TCP header length
            tcp_hl_new = ((tcp_hdr[12] >> 4) & 0x0F) * 4
            if tcp_hl_new < 20:
                tcp_hl_new = 20
                tcp_hdr[12] = (5 << 4) | (tcp_hdr[12] & 0x0F)
            if tcp_hl_new > 60:
                # Revert to original if too long
                tcp_hdr = bytearray(raw[meta.ip_header_len:meta.ip_header_len + meta.tcp_header_len])
                tcp_hl_new = meta.tcp_header_len

            # Assemble packet
            seg_raw = bytearray(ip_hdr + tcp_hdr + spec.payload)

            # Update IP total length
            seg_raw[2:4] = struct.pack("!H", len(seg_raw))

            # Calculate IP checksum
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = cls._checksum16(seg_raw[:meta.ip_header_len])
            seg_raw[10:12] = struct.pack("!H", ip_csum)

            # Calculate TCP checksum
            tcp_part = seg_raw[meta.ip_header_len:meta.ip_header_len + tcp_hl_new]
            payload_part = seg_raw[meta.ip_header_len + tcp_hl_new:]

            # Zero out checksum field
            tcp_part_copy = bytearray(tcp_part)
            tcp_part_copy[16:18] = b"\x00\x00"

            # Build pseudo header and calculate checksum
            pseudo = cls._build_pseudo_header(seg_raw[:meta.ip_header_len],
                                             len(tcp_part) + len(payload_part))
            csum = cls._checksum16(pseudo + tcp_part_copy + payload_part)

            # Corrupt checksum if requested
            if spec.corrupt_tcp_checksum:
                csum ^= 0xFFFF

            seg_raw[meta.ip_header_len + 16:meta.ip_header_len + 18] = struct.pack("!H", csum)

            return bytes(seg_raw)

        except Exception as e:
            logging.getLogger("PacketBuilder").error(f"Error building TCP segment: {e}")
            raise

    @classmethod
    def build_udp_datagram(cls, original_raw: bytes, spec: UDPDatagramSpec,
                          ip_id: int = 0) -> bytes:
        """Build a complete UDP/IP packet from specification."""
        try:
            raw = bytearray(original_raw)
            ip_hl = (raw[0] & 0x0F) * 4

            # Build IP header
            ip_hdr = bytearray(raw[:ip_hl])

            # Build UDP header (8 bytes)
            udp_hdr = bytearray(raw[ip_hl:ip_hl + 8])

            # Set TTL
            if spec.ttl is not None:
                ip_hdr[8] = max(1, min(255, spec.ttl))
            else:
                ip_hdr[8] = raw[8]  # Use original TTL

            # Set IP ID
            ip_hdr[4:6] = struct.pack("!H", ip_id & 0xFFFF)

            # Update UDP length
            udp_len = 8 + len(spec.payload)
            udp_hdr[4:6] = struct.pack("!H", udp_len)

            # Assemble packet
            seg_raw = bytearray(ip_hdr + udp_hdr + spec.payload)

            # Update IP total length
            seg_raw[2:4] = struct.pack("!H", len(seg_raw))

            # Calculate IP checksum
            seg_raw[10:12] = b"\x00\x00"
            ip_csum = cls._checksum16(seg_raw[:ip_hl])
            seg_raw[10:12] = struct.pack("!H", ip_csum)

            # Calculate UDP checksum
            udp_part = seg_raw[ip_hl:ip_hl + 8]
            payload_part = seg_raw[ip_hl + 8:]

            # Zero out checksum field
            udp_part_copy = bytearray(udp_part)
            udp_part_copy[6:8] = b"\x00\x00"

            # Build pseudo header and calculate checksum
            pseudo = cls._build_pseudo_header(seg_raw[:ip_hl],
                                             len(udp_part) + len(payload_part),
                                             proto=17)  # UDP protocol number
            csum = cls._checksum16(pseudo + udp_part_copy + payload_part)

            # UDP checksum 0 means no checksum, so use 0xFFFF instead
            if csum == 0:
                csum = 0xFFFF

            # Corrupt checksum if requested
            if spec.corrupt_checksum:
                csum ^= 0xFFFF

            seg_raw[ip_hl + 6:ip_hl + 8] = struct.pack("!H", csum)

            return bytes(seg_raw)

        except Exception as e:
            logging.getLogger("PacketBuilder").error(f"Error building UDP datagram: {e}")
            raise

    @staticmethod
    def _inject_md5sig_option(tcp_hdr: bytes) -> bytes:
        """Inject TCP MD5SIG option (kind=19, len=18) into header."""
        MAX_TCP_HDR = 60
        hdr = bytearray(tcp_hdr)
        data_offset_words = (hdr[12] >> 4) & 0x0F
        base_len = max(20, data_offset_words * 4)

        # Normalize if incorrect length
        if base_len > MAX_TCP_HDR:
            base_len = MAX_TCP_HDR
            hdr = hdr[:MAX_TCP_HDR]
            hdr[12] = ((MAX_TCP_HDR // 4) << 4) | (hdr[12] & 0x0F)

        # Extract existing options
        fixed = hdr[:20]
        opts = hdr[20:base_len]

        # MD5SIG option
        md5opt = b"\x13\x12" + b"\x00" * 16  # kind=19, len=18
        new_opts = bytes(opts) + md5opt

        # Add padding
        pad_len = (4 - ((20 + len(new_opts)) % 4)) % 4
        new_total_len = 20 + len(new_opts) + pad_len

        # Check if fits
        if new_total_len > MAX_TCP_HDR:
            return bytes(hdr[:base_len])  # Return original if doesn't fit

        new_opts += b"\x01" * pad_len  # NOP padding
        new_hdr = bytearray(fixed + new_opts)

        # Update data offset
        new_hdr[12] = ((new_total_len // 4) << 4) | (new_hdr[12] & 0x0F)

        return bytes(new_hdr)

    @staticmethod
    def is_tls_clienthello(payload: Optional[bytes]) -> bool:
        """Check if payload is TLS ClientHello."""
        return (
            payload
            and len(payload) > 6
            and payload[0] == 22  # Handshake
            and payload[5] == 1   # ClientHello
        )

    @staticmethod
    def is_tls_serverhello(payload: Optional[bytes]) -> bool:
        """Check if payload is TLS ServerHello."""
        return (
            payload
            and len(payload) > 6
            and payload[0] == 22  # Handshake
            and payload[5] == 2   # ServerHello
        )

    @staticmethod
    def extract_sni(payload: bytes) -> Optional[str]:
        """Extract SNI from TLS ClientHello."""
        if not PacketBuilder.is_tls_clienthello(payload):
            return None

        try:
            # Skip to extensions
            pos = 43  # Min position after fixed fields
            if pos >= len(payload):
                return None

            # Session ID length
            sid_len = payload[pos]
            pos += 1 + sid_len

            # Cipher suites length
            if pos + 2 > len(payload):
                return None
            cs_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2 + cs_len

            # Compression methods length
            if pos >= len(payload):
                return None
            comp_len = payload[pos]
            pos += 1 + comp_len

            # Extensions length
            if pos + 2 > len(payload):
                return None
            ext_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2

            ext_end = min(pos + ext_len, len(payload))

            # Find SNI extension (type 0)
            while pos + 4 <= ext_end:
                ext_type = int.from_bytes(payload[pos:pos+2], "big")
                ext_data_len = int.from_bytes(payload[pos+2:pos+4], "big")
                pos += 4

                if ext_type == 0 and pos + ext_data_len <= len(payload):  # SNI extension
                    # Skip list length
                    if pos + 2 > len(payload):
                        break
                    pos += 2
                    # Skip name type
                    if pos + 1 > len(payload):
                        break
                    pos += 1
                    # Get name length
                    if pos + 2 > len(payload):
                        break
                    name_len = int.from_bytes(payload[pos:pos+2], "big")
                    pos += 2
                    # Extract name
                    if pos + name_len <= len(payload):
                        name = payload[pos:pos+name_len]
                        return name.decode('ascii', errors='ignore')

                pos += ext_data_len

        except Exception:
            pass

        return None
