#!/usr/bin/env python3
"""
Test packet building error handling for task 11.4.
def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    # Добавляем forced параметры
    if len(args) > 1 and isinstance(args[1], dict):
        # Второй аргумент - стратегия
        strategy = args[1].copy()
        strategy['no_fallbacks'] = True
        strategy['forced'] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")
    
    return original_func(*args, **kwargs)



This test verifies that:
1. Invalid parameters are caught and handled gracefully
2. Errors are logged with detailed information
3. Original packet is sent when packet building fails
4. System continues operating after packet building errors

Requirements: 3.6 - IF strategy application fails THEN the system SHALL log detailed error information
"""

import sys
import os
import unittest
import logging
import struct
import time
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

try:
    from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig
    from core.bypass.packet.builder import PacketBuilder
    from core.bypass.packet.sender import PacketSender
    from core.bypass.packet.types import TCPSegmentSpec
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running this from the recon directory")
    sys.exit(1)

# Mock pydivert for testing
class MockPacket:
    def __init__(self, raw_data=None, src_addr="192.168.1.100", dst_addr="172.66.0.227", 
                 src_port=12345, dst_port=443, payload=None):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload or b""
        self.interface = 1
        self.direction = 0
        self.mark = 0
        
        # Create a minimal TCP packet structure if raw_data not provided
        if raw_data is None:
            # IP header (20 bytes) + TCP header (20 bytes) + payload
            src_ip_bytes = bytes(map(int, src_addr.split('.')))
            dst_ip_bytes = bytes(map(int, dst_addr.split('.')))
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45,  # Version + IHL
                0,     # TOS
                40 + len(self.payload),  # Total length
                0x1234,  # ID
                0,     # Flags + Fragment offset
                64,    # TTL
                6,     # Protocol (TCP)
                0,     # Checksum (will be calculated)
                src_ip_bytes,  # Source IP
                dst_ip_bytes   # Dest IP
            )
            
            tcp_header = struct.pack('!HHLLBBHHH',
                src_port,    # Source port
                dst_port,    # Dest port
                0x12345678,  # Sequence number
                0x87654321,  # Acknowledgment number
                0x50,        # Data offset (5 * 4 = 20 bytes)
                0x18,        # Flags (PSH + ACK)
                8192,        # Window size
                0,           # Checksum
                0            # Urgent pointer
            )
            
            self.raw = ip_header + tcp_header + self.payload
        else:
            self.raw = raw_data

class MockWinDivert:
    def __init__(self):
        self.sent_packets = []
        self.should_fail = False
        self.fail_with_error = None
        
    def send(self, packet, flags=None):
        if self.should_fail:
            if self.fail_with_error:
                raise self.fail_with_error
            else:
                raise OSError("Mock send failure")
        self.sent_packets.append(packet)

class TestPacketBuildingErrorHandling(unittest.TestCase):
    """Test packet building error handling implementation."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a string buffer to capture log output
        self.log_buffer = StringIO()
        
        # Set up logging to capture to our buffer
        self.logger = logging.getLogger("BypassEngine")
        self.logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            
        # Add our test handler
        self.handler = logging.StreamHandler(self.log_buffer)
        self.handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        
        # Create test components
        self.builder = PacketBuilder()
        self.sender = PacketSender(self.builder, self.logger, 0xC0DE)
        self.mock_w = MockWinDivert()
        
        # Create a test packet
        self.test_packet = MockPacket(
            payload=b"\x16\x03\x01\x00\x20" + b"\x01" + b"\x00\x00\x1c" + b"\x03\x03" + b"\x00" * 32 + 
                   b"\x00" + b"\x00\x02\x00\x35" + b"\x01\x00" + b"\x00\x00"  # Minimal ClientHello
        )
        
    def tearDown(self):
        """Clean up test environment."""
        self.logger.removeHandler(self.handler)
        self.handler.close()
        
    def get_log_output(self):
        """Get the captured log output."""
        return self.log_buffer.getvalue()
        
    def test_invalid_ttl_parameter(self):
        """Test handling of invalid TTL parameter."""
        print("Testing invalid TTL parameter handling...")
        
        # Create a spec with invalid TTL
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=b"test",
            ttl="invalid_ttl",  # Invalid TTL (should be int)
            flags=0x18
        )
        
        # Try to build packet - should handle error gracefully
        result = self.builder.build_tcp_segment(self.test_packet, spec)
        
        # Should return None due to error
        self.assertIsNone(result)
        
        # Should log error
        log_output = self.get_log_output()
        self.assertIn("build_tcp_segment:", log_output)
        self.assertIn("ERROR", log_output)
        
        print("✅ Invalid TTL parameter handled correctly")
        
    def test_invalid_payload_parameter(self):
        """Test handling of invalid payload parameter."""
        print("Testing invalid payload parameter handling...")
        
        # Create a spec with invalid payload
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=12345,  # Invalid payload (should be bytes)
            ttl=64,
            flags=0x18
        )
        
        # Try to build packet - should handle error gracefully
        result = self.builder.build_tcp_segment(self.test_packet, spec)
        
        # Should return None due to error
        self.assertIsNone(result)
        
        # Should log error
        log_output = self.get_log_output()
        self.assertIn("build_tcp_segment:", log_output)
        self.assertIn("ERROR", log_output)
        
        print("✅ Invalid payload parameter handled correctly")
        
    def test_corrupted_original_packet(self):
        """Test handling of corrupted original packet data."""
        print("Testing corrupted original packet handling...")
        
        # Create a packet with corrupted raw data
        corrupted_packet = MockPacket(raw_data=b"corrupted_data_too_short")
        
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=b"test",
            ttl=64,
            flags=0x18
        )
        
        # Try to build packet - should handle error gracefully
        result = self.builder.build_tcp_segment(corrupted_packet, spec)
        
        # Should return None due to error
        self.assertIsNone(result)
        
        # Should log error
        log_output = self.get_log_output()
        self.assertIn("build_tcp_segment:", log_output)
        self.assertIn("ERROR", log_output)
        
        print("✅ Corrupted original packet handled correctly")
        
    def test_packet_send_failure(self):
        """Test handling of packet send failures."""
        print("Testing packet send failure handling...")
        
        # Configure mock to fail
        self.mock_w.should_fail = True
        self.mock_w.fail_with_error = OSError("Network interface error")
        
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=b"test",
            ttl=64,
            flags=0x18
        )
        
        # Try to send packet - should handle error gracefully
        result = self.sender.send_tcp_segments(self.mock_w, self.test_packet, [spec])
        
        # Should return False due to send failure
        self.assertFalse(result)
        
        # Should log error
        log_output = self.get_log_output()
        self.assertIn("send error", log_output.lower())
        self.assertIn("ERROR", log_output)
        
        print("✅ Packet send failure handled correctly")
        
    def test_sni_replacement_error(self):
        """Test handling of SNI replacement errors."""
        print("Testing SNI replacement error handling...")
        
        # Create a spec with invalid SNI
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=b"invalid_tls_data",  # Not a valid TLS ClientHello
            ttl=64,
            flags=0x18,
            fooling_sni="test.example.com"  # Try to replace SNI in invalid data
        )
        
        # Try to build packet - should handle SNI error gracefully
        result = self.builder.build_tcp_segment(self.test_packet, spec)
        
        # Should still build packet (with original payload)
        self.assertIsNotNone(result)
        
        # Should log SNI replacement failure
        log_output = self.get_log_output()
        self.assertIn("SNI replacement failed", log_output)
        self.assertIn("WARNING", log_output)
        
        print("✅ SNI replacement error handled correctly")
        
    def test_tcp_options_extraction_error(self):
        """Test handling of TCP options extraction errors."""
        print("Testing TCP options extraction error handling...")
        
        # Create a packet with malformed TCP header
        malformed_packet = MockPacket()
        # Corrupt the TCP header length field
        raw_data = bytearray(malformed_packet.raw)
        raw_data[32] = 0xFF  # Invalid TCP header length
        malformed_packet.raw = bytes(raw_data)
        
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=b"test",
            ttl=64,
            flags=0x18
        )
        
        # Try to build packet - should handle error gracefully
        result = self.builder.build_tcp_segment(malformed_packet, spec)
        
        # Should return None due to error
        self.assertIsNone(result)
        
        # Should log error
        log_output = self.get_log_output()
        self.assertIn("build_tcp_segment:", log_output)
        self.assertIn("ERROR", log_output)
        
        print("✅ TCP options extraction error handled correctly")
        
    def test_checksum_calculation_error(self):
        """Test handling of checksum calculation errors."""
        print("Testing checksum calculation error handling...")
        
        # Mock the checksum calculation to raise an exception
        with patch.object(self.builder, '_tcp_checksum', side_effect=Exception("Checksum calculation failed")):
            spec = TCPSegmentSpec(
                rel_seq=0,
                payload=b"test",
                ttl=64,
                flags=0x18
            )
            
            # Try to build packet - should handle error gracefully
            result = self.builder.build_tcp_segment(self.test_packet, spec)
            
            # Should return None due to error
            self.assertIsNone(result)
            
            # Should log error
            log_output = self.get_log_output()
            self.assertIn("build_tcp_segment:", log_output)
            self.assertIn("ERROR", log_output)
            
        print("✅ Checksum calculation error handled correctly")
        
    def test_original_packet_forwarding_on_error(self):
        """Test that original packet is forwarded when packet building fails."""
        print("Testing original packet forwarding on error...")
        
        # Create a mock engine to test apply_bypass behavior
        config = EngineConfig(debug=True)
        
        # Mock pydivert to avoid import issues
        with patch('core.bypass.engine.base_engine.pydivert') as mock_pydivert:
            mock_pydivert.Packet = MockPacket
            
            engine = WindowsBypassEngine(config)
            
            # Mock the packet builder to always fail
            with patch.object(engine._packet_builder, 'build_tcp_segment', return_value=None):
                # Mock WinDivert send method
                mock_w = Mock()
                sent_packets = []
                mock_w.send = Mock(side_effect=lambda p: sent_packets.append(p))
                
                # Create a strategy that should trigger packet building
                strategy_task = {
                    "type": "fakeddisorder",
                    "params": {
                        "ttl": 2,
                        "split_pos": 76,
                        "fooling": ["badsum"]
                    , "no_fallbacks": True, "forced": True}
                }
                
                # Apply bypass - should fail to build packets and forward original
                engine.apply_bypass(self.test_packet, mock_w, strategy_task, forced=True)
                
                # Should have sent the original packet
                self.assertEqual(len(sent_packets), 1)
                self.assertEqual(sent_packets[0], self.test_packet)
                
                # Should log error about packet building failure
                log_output = self.get_log_output()
                self.assertIn("build failed", log_output)
                
        print("✅ Original packet forwarded correctly on error")
        
    def test_detailed_error_logging(self):
        """Test that detailed error information is logged."""
        print("Testing detailed error logging...")
        
        # Create a spec that will cause multiple types of errors
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=None,  # Invalid payload
            ttl="invalid",  # Invalid TTL
            flags=0x18,
            fooling_sni="invalid\x00sni"  # Invalid SNI with null byte
        )
        
        # Try to build packet
        result = self.builder.build_tcp_segment(self.test_packet, spec)
        
        # Should return None due to errors
        self.assertIsNone(result)
        
        # Check that detailed error information is logged
        log_output = self.get_log_output()
        
        # Should contain error level logging
        self.assertIn("ERROR", log_output)
        
        # Should contain the method name where error occurred
        self.assertIn("build_tcp_segment:", log_output)
        
        # Should contain exception details (when debug logging is enabled)
        self.assertTrue(len(log_output) > 50)  # Should be detailed
        
        print("✅ Detailed error logging verified")
        
    def test_error_recovery_and_continuation(self):
        """Test that system continues operating after packet building errors."""
        print("Testing error recovery and continuation...")
        
        # Create multiple specs, some valid and some invalid
        specs = [
            TCPSegmentSpec(rel_seq=0, payload=b"valid1", ttl=64, flags=0x18),
            TCPSegmentSpec(rel_seq=10, payload="invalid", ttl=64, flags=0x18),  # Invalid payload
            TCPSegmentSpec(rel_seq=20, payload=b"valid2", ttl=64, flags=0x18),
        ]
        
        # Try to send all segments
        result = self.sender.send_tcp_segments(self.mock_w, self.test_packet, specs)
        
        # Should fail due to invalid spec in the middle
        self.assertFalse(result)
        
        # But should log the error and continue
        log_output = self.get_log_output()
        self.assertIn("build failed", log_output.lower())
        
        # System should still be operational for subsequent calls
        valid_spec = TCPSegmentSpec(rel_seq=0, payload=b"test", ttl=64, flags=0x18)
        result2 = self.sender.send_tcp_segments(self.mock_w, self.test_packet, [valid_spec])
        
        # Should succeed with valid spec
        self.assertTrue(result2)
        
        print("✅ Error recovery and continuation verified")
        
    def test_memory_cleanup_on_error(self):
        """Test that memory is properly cleaned up when errors occur."""
        print("Testing memory cleanup on error...")
        
        # Create a large payload to test memory handling
        large_payload = b"X" * 10000
        
        # Create a spec that will fail during processing
        spec = TCPSegmentSpec(
            rel_seq=0,
            payload=large_payload,
            ttl="invalid_ttl",  # This will cause an error
            flags=0x18
        )
        
        # Monitor memory usage (simplified check)
        import gc
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Try to build packet multiple times
        for i in range(10):
            result = self.builder.build_tcp_segment(self.test_packet, spec)
            self.assertIsNone(result)
        
        # Force garbage collection
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # Should not have significant memory leak
        # Allow some variance for test infrastructure
        self.assertLess(final_objects - initial_objects, 100)
        
        print("✅ Memory cleanup on error verified")

def run_packet_building_error_tests():
    """Run all packet building error handling tests."""
    print("=" * 60)
    print("PACKET BUILDING ERROR HANDLING TESTS")
    print("=" * 60)
    print()
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPacketBuildingErrorHandling)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    
    if success:
        print("\n✅ ALL PACKET BUILDING ERROR HANDLING TESTS PASSED!")
        print("\nTask 11.4 Implementation Summary:")
        print("- ✅ Invalid parameters are caught and handled gracefully")
        print("- ✅ Detailed error information is logged")
        print("- ✅ Original packet is sent when packet building fails")
        print("- ✅ System continues operating after errors")
        print("- ✅ Memory is properly cleaned up on errors")
        print("- ✅ Error recovery and continuation works correctly")
    else:
        print("\n❌ SOME TESTS FAILED!")
        return False
    
    return success

if __name__ == "__main__":
    success = run_packet_building_error_tests()
    sys.exit(0 if success else 1)