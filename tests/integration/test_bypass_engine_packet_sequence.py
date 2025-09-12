import unittest
import sys
from unittest.mock import MagicMock, patch

# Add project root to path
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock pydivert before other imports
sys.modules["pydivert"] = MagicMock()

from core.bypass.engine.base_engine import EngineConfig

class TestBypassEnginePacketSequence(unittest.TestCase):
    @patch('platform.system', return_value='Windows')
    def setUp(self, mock_platform):
        self.config = EngineConfig(debug=True)
        # We need to re-import the module under the patch
        from core.bypass.engine import windows_engine
        import importlib
        importlib.reload(windows_engine)

        self.engine = windows_engine.WindowsBypassEngine(self.config)
        self.engine.logger = MagicMock()
        self.mock_divert = MagicMock()

        # The shim replaces some methods with methods on _packet_sender
        # So we need to mock that.
        self.engine._packet_sender = MagicMock()
        self.engine._packet_sender.send_tcp_segments = MagicMock(return_value=True)

    @patch('platform.system', return_value='Windows')
    def test_fakeddisorder_packet_sequence(self, mock_platform):
        # Эмулируем ClientHello
        client_hello = (
            b"\x16\x03\x01\x00\xA0\x01\x00\x00\x9C\x03\x03\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        # Создаем фиктивный пакет
        packet = MagicMock()
        packet.raw = (
            b"\x45\x00\x00\xC8\x00\x00\x40\x00\x40\x06\x00\x00\x7F\x00\x00\x01"
            b"\x7F\x00\x00\x01\xD3\x55\x01\xBB\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x50\x10\xFF\xFF\x00\x00\x00\x00" + client_hello
        )
        packet.payload = client_hello
        packet.src_addr = "127.0.0.1"
        packet.dst_addr = "127.0.0.1"
        packet.src_port = 54005
        packet.dst_port = 443
        packet.protocol = 6  # TCP

        self.engine._send_attack_segments = MagicMock(return_value=True)

        # Запускаем apply_bypass
        strategy_task = {
            "type": "fakeddisorder",
            "params": {
                "split_pos": 76,
                "overlap_size": 336,
                "fake_ttl": 1,
                "fooling": ["badsum"],
                "simple": True,
            },
        }
        self.engine.apply_bypass(packet, self.mock_divert, strategy_task)

        # Проверяем, что _send_attack_segments был вызван
        self.engine._send_attack_segments.assert_called_once()

if __name__ == "__main__":
    unittest.main()
