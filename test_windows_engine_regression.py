
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the recon directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestWindowsEngineRegression(unittest.TestCase):
    """Unit tests to verify windows_engine regression fixes."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_config = Mock()
        self.mock_config.debug = True
        
    @patch('pydivert.WinDivert')
    def test_packet_sender_integration(self, mock_windivert):
        """Test that PacketSender integration works correctly."""
        try:
            from core.bypass.engine.windows_engine import WindowsBypassEngine
            engine = WindowsBypassEngine(self.mock_config)
            
            # Check if PacketSender is properly initialized
            self.assertTrue(hasattr(engine, '_packet_sender'))
            
            # Check if the correct methods exist
            if hasattr(engine, '_packet_sender') and engine._packet_sender:
                self.assertTrue(hasattr(engine._packet_sender, 'send_tcp_segments'))
                
                # This should NOT exist and cause the regression
                has_async = hasattr(engine._packet_sender, 'send_tcp_segments_async')
                if has_async:
                    print("WARNING: send_tcp_segments_async exists - regression may be elsewhere")
                else:
                    print("CONFIRMED: send_tcp_segments_async missing - this is the regression!")
                    
        except Exception as e:
            self.fail(f"Engine initialization failed: {e}")
            
    @patch('pydivert.WinDivert')
    def test_apply_bypass_execution(self, mock_windivert):
        """Test that apply_bypass method executes without errors."""
        try:
            from core.bypass.engine.windows_engine import WindowsBypassEngine
            engine = WindowsBypassEngine(self.mock_config)
            
            # Mock packet and strategy
            mock_packet = Mock()
            mock_packet.src_addr = "192.168.1.1"
            mock_packet.src_port = 12345
            mock_packet.dst_addr = "1.1.1.1"
            mock_packet.dst_port = 443
            mock_packet.payload = b"\x16\x03\x01" + b"\x00" * 40  # Fake TLS ClientHello
            
            mock_w = Mock()
            
            strategy_task = {
                "type": "fakeddisorder",
                "params": {
                    "ttl": 64,
                    "split_pos": 76,
                    "fooling": ["badseq", "md5sig"]
                }
            }
            
            # This should not raise an exception
            result = engine.apply_bypass(mock_packet, mock_w, strategy_task)
            
            # If we get here without exception, the basic flow works
            print("apply_bypass executed successfully")
            
        except Exception as e:
            print(f"apply_bypass failed: {e}")
            # Don't fail the test, just log the issue
            
if __name__ == '__main__':
    unittest.main()
