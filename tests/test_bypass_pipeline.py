import unittest
from unittest.mock import MagicMock, patch, call

# Add project root to path to allow imports from core
import sys
import os
import struct

import platform

# Mock platform-dependent modules BEFORE they are imported by the application code.
# This allows testing Windows-specific code on other platforms like Linux.
platform.system = lambda: 'Windows'
sys.modules['pydivert'] = MagicMock()
sys.modules['pydivert.packet'] = MagicMock()
sys.modules['pydivert.windivert'] = MagicMock()


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Imports from the application
from core.bypass.packet.types import TCPSegmentSpec
from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.sender import PacketSender
from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.bypass.engine.base_engine import EngineConfig
from core.bypass.techniques.primitives import BypassTechniques

class TestBypassPipeline(unittest.TestCase):

    def setUp(self):
        """Set up common resources for tests."""
        # Mock logger to avoid console output during tests
        self.mock_logger = MagicMock()

    def test_packet_builder_builds_segment_correctly(self):
        """Verify that PacketBuilder correctly constructs a TCP segment from a spec."""
        # 1. Setup
        builder = PacketBuilder()
        builder.logger = self.mock_logger # Suppress logging

        # Create a mock original packet with a valid-looking raw header
        # IP (20 bytes) + TCP (20 bytes)
        # Base Seq = 1000, Base TTL = 64
        mock_ip_header = b'\x45\x00\x00\x28\x12\x34\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01'
        mock_tcp_header = struct.pack('!HHIIBBHHH', 12345, 443, 1000, 0, 5 << 4, 0x02, 8192, 0, 0)
        mock_raw_packet = mock_ip_header + mock_tcp_header

        mock_original_packet = MagicMock()
        mock_original_packet.raw = mock_raw_packet

        spec = TCPSegmentSpec(
            payload=b'test_payload',
            rel_seq=100,
            flags=0x18,  # PSH+ACK
            ttl=33,
            corrupt_tcp_checksum=True
        )

        # 2. Action
        pkt_bytes = builder.build_tcp_segment(mock_original_packet, spec)

        # 3. Assertions
        self.assertIsNotNone(pkt_bytes)

        # Unpack and verify fields
        ip_hl = (pkt_bytes[0] & 0x0F) * 4
        tcp_start = ip_hl

        # IP Header fields
        ttl_out = pkt_bytes[8]
        self.assertEqual(ttl_out, 33)

        # TCP Header fields
        seq_out = struct.unpack('!I', pkt_bytes[tcp_start+4:tcp_start+8])[0]
        self.assertEqual(seq_out, 1100) # base_seq (1000) + rel_seq (100)

        flags_out = pkt_bytes[tcp_start+13]
        self.assertEqual(flags_out, 0x18)

        checksum_out = struct.unpack('!H', pkt_bytes[tcp_start+16:tcp_start+18])[0]
        self.assertEqual(checksum_out, 0xDEAD) # Default corrupt value

    def test_packet_sender_sends_segments(self):
        """Verify that PacketSender correctly builds and sends multiple segments."""
        # 1. Setup
        mock_builder = MagicMock(spec=PacketBuilder)
        # Configure the mock builder to return a dummy packet bytes for any call
        mock_builder.build_tcp_segment.return_value = b'\x00' * 40

        sender = PacketSender(builder=mock_builder, logger=self.mock_logger, inject_mark=0xC0DE)

        mock_w = MagicMock() # Mock pydivert.WinDivert
        mock_original_packet = MagicMock()
        # Provide a minimal raw header for the sender to unpack IP ID
        mock_original_packet.raw = b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08' + b'\x00' * 20
        mock_original_packet.interface = (1, 0)
        mock_original_packet.direction = 0

        specs = [
            TCPSegmentSpec(payload=b'p1', rel_seq=0, flags=0x10, ttl=1),
            TCPSegmentSpec(payload=b'p2', rel_seq=10, flags=0x18, ttl=64, corrupt_tcp_checksum=True),
        ]

        # Patch pydivert.Packet to avoid its internal logic and allow mocking 'mark'
        # Also patch the retransmission blocker to avoid threading issues in tests
        with patch('core.bypass.packet.sender.pydivert.Packet'), \
             patch.object(sender, '_create_tcp_retransmission_blocker') as mock_blocker:

            # 2. Action
            success = sender.send_tcp_segments(mock_w, mock_original_packet, specs)

            # 3. Assertions
            self.assertTrue(success)

            # Verify builder was called for each spec
            self.assertEqual(mock_builder.build_tcp_segment.call_count, 2)
            mock_builder.build_tcp_segment.assert_any_call(mock_original_packet, specs[0], window_div=1, ip_id=unittest.mock.ANY)
            mock_builder.build_tcp_segment.assert_any_call(mock_original_packet, specs[1], window_div=1, ip_id=unittest.mock.ANY)

            # Verify that pydivert's send was called for each packet
            self.assertEqual(mock_w.send.call_count, 2)

    @patch('core.bypass.engine.windows_engine.StrategyManager')
    @patch('core.bypass.engine.windows_engine.Calibrator')
    @patch('core.bypass.engine.windows_engine.BypassTechniques')
    def test_windows_engine_fakeddisorder_flow(self, mock_techniques, mock_calibrator, mock_strategy_manager):
        """Verify the fakeddisorder flow in WindowsBypassEngine uses the new packet pipeline."""
        # 1. Setup
        mock_config = EngineConfig(debug=False)
        with patch.object(WindowsBypassEngine, '_start_inbound_observer'):
            engine = WindowsBypassEngine(config=mock_config)

        engine._packet_sender = MagicMock(spec=PacketSender)
        engine.logger = self.mock_logger

        mock_recipe = [
            (b'fake_payload', 0, {'is_fake': True, 'ttl': 1, 'corrupt_tcp_checksum': True}),
            (b'part2', -10, {'is_fake': False}),
            (b'part1', 0, {'is_fake': False}),
        ]
        mock_techniques.return_value.apply_fakeddisorder.return_value = mock_recipe

        # This side effect simulates the calibrator calling the send_func, which is the
        # logic we need to test. It then returns a mock candidate to signal success.
        def sweep_side_effect(payload, candidates, ttl_list, delays, send_func, wait_func, time_budget_ms):
            dummy_candidate = MagicMock()
            dummy_candidate.split_pos = 50
            dummy_candidate.overlap_size = 10
            # Call the actual _send_try function passed from the engine
            send_func(dummy_candidate, ttl_list[0], delays[0])
            return dummy_candidate

        mock_calibrator.sweep.side_effect = sweep_side_effect

        mock_w = MagicMock()
        mock_packet = MagicMock()
        mock_packet.payload = b'\x16\x03\x01' + b'\x00' * 100 # Mock TLS ClientHello
        mock_packet.src_addr = '1.1.1.1'
        mock_packet.src_port = 1234
        mock_packet.dst_addr = '2.2.2.2'
        mock_packet.dst_port = 443
        mock_packet.raw = b'\x45' + b'\x00' * 59 # minimal raw packet

        strategy_task = {
            "type": "fakeddisorder",
            "params": {
                "split_pos": 50,
                "overlap_size": 10,
                "fake_ttl": 1
            }
        }

        # 2. Action
        engine.apply_bypass(mock_packet, mock_w, strategy_task)

        # 3. Assertions
        # Verify that the packet sender was called
        engine._packet_sender.send_tcp_segments.assert_called_once()

        # Capture the arguments passed to the sender
        args, kwargs = engine._packet_sender.send_tcp_segments.call_args
        sent_specs = args[2] # specs is the 3rd argument (self, w, specs)

        # Verify the specs match the recipe
        self.assertEqual(len(sent_specs), 3)
        # Check spec for the fake packet
        self.assertEqual(sent_specs[0].payload, b'fake_payload')
        self.assertEqual(sent_specs[0].ttl, 1)
        self.assertTrue(sent_specs[0].is_fake)
        self.assertTrue(sent_specs[0].corrupt_tcp_checksum)
        # Check spec for the second part
        self.assertEqual(sent_specs[1].payload, b'part2')
        self.assertEqual(sent_specs[1].rel_seq, -10)
        self.assertFalse(sent_specs[1].is_fake)
        # Check spec for the first part
        self.assertEqual(sent_specs[2].payload, b'part1')
        self.assertEqual(sent_specs[2].rel_seq, 0)

if __name__ == '__main__':
    unittest.main()