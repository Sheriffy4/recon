import unittest
from unittest.mock import MagicMock, patch
from core.bypass.engine.windows_engine import WindowsBypassEngine
from core.bypass.engine.base_engine import EngineConfig

class TestBypassEnginePacketSequence(unittest.TestCase):
    def setUp(self):
        self.config = EngineConfig(debug=True)
        self.engine = WindowsBypassEngine(self.config)
        self.engine.logger = MagicMock()
        self.mock_divert = MagicMock()
        self.mock_divert.send = MagicMock()

    def test_fakeddisorder_packet_sequence(self):
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

        # Запускаем apply_bypass
        strategy_task = {
            "type": "fakeddisorder",
            "params": {
                "split_pos": 76,
                "overlap_size": 336,
                "fake_ttl": 1,
                "fooling": ["badsum"],
                "simple": True,  # Add this line to force the simple path
            },
        }
        self.engine.apply_bypass(packet, self.mock_divert, strategy_task)

        # Проверяем, что send был вызван дважды (для фейкового и реального сегментов)
        self.assertEqual(self.mock_divert.send.call_count, 2)

        # Проверяем порядок и метаданные пакетов
        args, _ = self.mock_divert.send.call_args_list[0]
        fake_packet = args[0].raw
        self.assertIn(b"\xDE\xAD\xBE\xEF", fake_packet)  # Маркер инъекции
        self.assertEqual(fake_packet[8], 1)  # TTL фейкового пакета

        args, _ = self.mock_divert.send.call_args_list[1]
        real_packet = args[0].raw
        self.assertEqual(real_packet[8], 64)  # TTL реального пакета

if __name__ == "__main__":
    unittest.main()