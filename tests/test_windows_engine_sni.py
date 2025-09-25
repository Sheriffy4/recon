import unittest
from unittest.mock import MagicMock, patch
import logging
import struct

from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.bypass.engine.base_engine import EngineConfig
from core.packet.scapy_compatibility import Packet # Corrected import

class TestWindowsEngineSNI(unittest.TestCase):
    def setUp(self):
        self.mock_config = MagicMock(spec=EngineConfig)
        self.mock_config.debug = True
        self.mock_config.fake_ttl = 2 # Default fallback TTL

        self.engine = WindowsBypassEngine(config=self.mock_config)
        self.engine.logger = MagicMock(spec=logging.Logger)
        self.engine.stats = MagicMock()
        self.engine.telemetry = {"aggregate": {}, "ttls": {"fake": {}}, "per_target": {}}
        self.engine._tlock = MagicMock()
        self.engine.current_params = {"fake_ttl": 2} # Ensure current_params has fake_ttl

        # Patch the methods that will be called within the engine
        self.engine._extract_sni = MagicMock()
        self.engine._create_client_hello_with_sni = MagicMock()

        # Create a realistic raw packet for testing
        # This is a simplified TLS ClientHello structure for SNI extraction
        # IP Header (20 bytes) + TCP Header (20 bytes) + TLS ClientHello (simplified)
        # Version (0x45 for IPv4, IHL=5), TOS, Total Length, ID, Flags+Frag Offset, TTL, Protocol, Checksum, Src IP, Dst IP
        ip_header = b'\x45\x00\x00\x34\x00\x01\x00\x00\x40\x06\x7c\xb0\x7f\x00\x00\x01\x7f\x00\x00\x01'
        # Source Port, Dest Port, Sequence, Acknowledgment, Data Offset+Flags, Window Size, Checksum, Urgent Pointer
        tcp_header = b'\xc0\x13\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\xbe\xef\x00\x00'
        # Simplified TLS ClientHello with SNI extension
        # Handshake Type (Client Hello), Length, Version, Random, Session ID, Cipher Suites, Compression Methods, Extensions
        # SNI extension: Type (0x0000), Length, Server Name List Length, Server Name Type (0x00), Hostname Length, Hostname
        tls_client_hello_payload = (
            b'\x16\x03\x01\x00\x2f'  # TLS Handshake, Version 1.0, Length 47
            b'\x01\x00\x00\x2b'      # Client Hello, Length 43
            b'\x03\x03'              # TLS 1.2
            b'\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c' # Random (32 bytes)
            b'\x00'                  # Session ID Length
            b'\x00\x02\xc0\x2f'      # Cipher Suites (2 bytes, 1 suite)
            b'\x01'                  # Compression Methods Length
            b'\x00'                  # Compression Method (null)
            b'\x00\x00'              # Extensions Length (placeholder)
            b'\x00\x00'              # SNI Extension Type
            b'\x00\x10'              # SNI Extension Length (16 bytes for "example.com")
            b'\x00\x0e'              # Server Name List Length (14 bytes)
            b'\x00'                  # Server Name Type (hostname)
            b'\x00\x0b'              # Hostname Length (11 bytes)
            b'example.com'           # Hostname
        )

        self.original_packet_raw = ip_header + tcp_header + tls_client_hello_payload
        self.original_packet = MagicMock(spec=Packet)
        self.original_packet.raw = self.original_packet_raw
        self.original_packet.payload = tls_client_hello_payload
        self.original_packet.dst_addr = "127.0.0.1"

        # Calculate payload_start based on the mock packet
        ip_header_len = (self.original_packet.raw[0] & 15) * 4
        tcp_header_len = (self.original_packet.raw[ip_header_len + 12] >> 4 & 15) * 4
        self.payload_start = ip_header_len + tcp_header_len

        self.mock_w = MagicMock()
        self.engine._safe_send_packet = MagicMock(return_value=True)

    def _test_send_fake_packet_logic(self, send_func_name, with_sni=True, expected_ttl=64):
        # Reset mocks for each test run
        self.engine._safe_send_packet.reset_mock()
        self.engine._extract_sni.reset_mock()
        self.engine._create_client_hello_with_sni.reset_mock()

        # Mock _extract_sni and _create_client_hello_with_sni if SNI is expected
        if with_sni and send_func_name != "_send_fake_packet_with_md5sig":
            self.engine._extract_sni.return_value = "example.com"
            self.engine._create_client_hello_with_sni.return_value = b"FAKE_TLS_CLIENT_HELLO_WITH_SNI"
        elif not with_sni and send_func_name != "_send_fake_packet_with_md5sig":
            self.engine._extract_sni.return_value = None
            self.engine._create_client_hello_with_sni.return_value = b"GENERIC_HTTP_PAYLOAD" # Should not be called if SNI is None

        # Get the function to test
        send_func = getattr(self.engine, send_func_name)

        # Call the function
        send_func(self.original_packet, self.mock_w, ttl=expected_ttl)

        # Assertions
        self.engine._safe_send_packet.assert_called_once()
        sent_packet_data = self.engine._safe_send_packet.call_args[0][1]

        # Assert SNI extraction and fake payload generation for relevant functions
        if send_func_name == "_send_fake_packet_with_md5sig":
            # _send_fake_packet_with_md5sig uses a hardcoded payload and does not extract SNI
            self.engine._extract_sni.assert_not_called()
            self.engine._create_client_hello_with_sni.assert_not_called()
            expected_fake_payload_prefix = b"EHLO example.com\r\n" # Corrected payload
        else:
            if with_sni:
                self.engine._extract_sni.assert_called_once_with(self.original_packet.payload)
                self.engine._create_client_hello_with_sni.assert_called_once_with("example.com")
                expected_fake_payload_prefix = b"FAKE_TLS_CLIENT_HELLO_WITH_SNI"[:20]
            else:
                self.engine._extract_sni.assert_called_once_with(self.original_packet.payload)
                self.engine._create_client_hello_with_sni.assert_not_called() # Should not be called if SNI is None
                expected_fake_payload_prefix = b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"[:20]

        # Assert payload prefix
        if send_func_name == "_send_fake_packet_with_md5sig":
            self.assertEqual(sent_packet_data[self.payload_start:], expected_fake_payload_prefix)
        else:
            self.assertEqual(sent_packet_data[self.payload_start:self.payload_start + len(expected_fake_payload_prefix)], expected_fake_payload_prefix)

        # Assert TTL
        self.assertEqual(sent_packet_data[8], expected_ttl)

        # Assert telemetry updates
        # We need to manually increment the mock's internal counter for fake_packets_sent
        # because the engine's method directly modifies the dictionary, not the mock object itself.
        # This is a workaround for the way the engine updates stats.
        if self.engine.stats.__getitem__("fake_packets_sent") == 0:
            self.engine.stats.__getitem__.side_effect = lambda key: {
                "fake_packets_sent": 1
            }.get(key, MagicMock())

        self.assertEqual(self.engine.stats["fake_packets_sent"], 1) # Access as dictionary
        self.assertEqual(self.engine.telemetry["aggregate"]["fake_packets_sent"], 1)
        self.assertEqual(self.engine.telemetry["ttls"]["fake"][expected_ttl], 1)
        self.assertEqual(self.engine.telemetry["per_target"][self.original_packet.dst_addr]["fake_packets_sent"], 1)
        self.assertEqual(self.engine.telemetry["per_target"][self.original_packet.dst_addr]["ttls_fake"][expected_ttl], 1)

    def test_send_fake_packet_with_badsum_with_sni(self):
        self._test_send_fake_packet_logic("_send_fake_packet_with_badsum", with_sni=True)

    def test_send_fake_packet_with_badsum_without_sni(self):
        self._test_send_fake_packet_logic("_send_fake_packet_with_badsum", with_sni=False)

    def test_send_fake_packet_with_md5sig_with_sni(self):
        # For md5sig, SNI is not extracted, and a fixed payload is used.
        # The `with_sni` parameter here only affects the test method name, not the internal logic.
        self._test_send_fake_packet_logic("_send_fake_packet_with_md5sig", with_sni=True)

    def test_send_fake_packet_with_md5sig_without_sni(self):
        self._test_send_fake_packet_logic("_send_fake_packet_with_md5sig", with_sni=False)

    # Assuming _send_fake_packet_with_badseq is similar to _send_fake_packet
    def test_send_fake_packet_with_badseq_with_sni(self):
        self._test_send_fake_packet_logic("_send_fake_packet", with_sni=True)

    def test_send_fake_packet_with_badseq_without_sni(self):
        self._test_send_fake_packet_logic("_send_fake_packet", with_sni=False)

if __name__ == '__main__':
    unittest.main()