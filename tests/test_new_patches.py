import unittest
import struct
from unittest.mock import MagicMock, Mock, patch

# This is a mock for the PacketBuilder that would be in core.packet_builder
# The test is written against the new PacketBuilder, but the old one is
# still in the codebase and might be imported. This mock ensures that
# the test uses the new PacketBuilder's interface.
class MockPacketBuilder:
    def build_tcp_segment(self, original_raw, spec, window_div=1, ip_id=0):
        return b"built_packet"

from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.sender import PacketSender
from core.bypass.packet.types import TCPSegmentSpec

class TestNewPatches(unittest.TestCase):
    def setUp(self):
        self.logger = Mock()
        self.builder = PacketBuilder()

    def test_packet_builder_ttl_flags_seq(self):
        original_raw = bytearray(b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x7c\xb0\x7f\x00\x00\x01\x7f\x00\x00\x01\xc0\x12\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\xbe\xef\x00\x00')
        spec = TCPSegmentSpec(
            payload=b'test',
            rel_seq=100,
            seq_extra=5,
            flags=0x18,
            ttl=123
        )

        # The IP header is 20 bytes, TCP header starts at byte 20
        ip_header_len = 20
        tcp_header_len = 20 # Assuming a basic TCP header

        built_packet = self.builder.build_tcp_segment(original_raw, spec, window_div=1, ip_id=0)

        self.assertEqual(built_packet[8], 123) # TTL

        # Flags are at offset 13 of the TCP header
        tcp_flags_offset = ip_header_len + 13
        self.assertEqual(built_packet[tcp_flags_offset], 0x18) # Flags

        original_seq = struct.unpack('!I', original_raw[ip_header_len + 4 : ip_header_len + 8])[0]
        built_seq = struct.unpack('!I', built_packet[ip_header_len + 4 : ip_header_len + 8])[0]
        self.assertEqual(built_seq, (original_seq + 100 + 5) & 0xFFFFFFFF)

    def test_packet_builder_badsum(self):
        original_raw = bytearray(b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x7c\xb0\x7f\x00\x00\x01\x7f\x00\x00\x01\xc0\x12\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\xbe\xef\x00\x00')
        spec = TCPSegmentSpec(
            payload=b'test',
            corrupt_tcp_checksum=True
        )

        ip_header_len = 20
        tcp_checksum_offset = ip_header_len + 16

        built_packet = self.builder.build_tcp_segment(original_raw, spec, window_div=1, ip_id=0)

        tcp_checksum = struct.unpack('!H', built_packet[tcp_checksum_offset : tcp_checksum_offset + 2])[0]
        self.assertEqual(tcp_checksum, 0xDEAD)

    def test_packet_builder_md5sig(self):
        original_raw = bytearray(b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x7c\xb0\x7f\x00\x00\x01\x7f\x00\x00\x01\xc0\x12\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\xbe\xef\x00\x00')
        spec = TCPSegmentSpec(
            payload=b'test',
            add_md5sig_option=True
        )

        ip_header_len = 20
        tcp_checksum_offset = ip_header_len + 16
        tcp_header_len_offset = ip_header_len + 12

        built_packet = self.builder.build_tcp_segment(original_raw, spec, window_div=1, ip_id=0)

        tcp_checksum = struct.unpack('!H', built_packet[tcp_checksum_offset : tcp_checksum_offset + 2])[0]
        self.assertEqual(tcp_checksum, 0xBEEF)

        tcp_hl = (built_packet[tcp_header_len_offset] >> 4) * 4
        self.assertGreater(tcp_hl, 20)

if __name__ == '__main__':
    unittest.main()
