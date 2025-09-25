import unittest
import pydivert
import struct
from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.types import TCPSegmentSpec

# Создаем "болванку" оригинального пакета для тестов
# Это реальный TLS ClientHello, захваченный ранее
RAW_CLIENT_HELLO = bytes.fromhex(
    "45000205000100008006743dc0a812bc8efaf42a0fe301bb"
    "99999999999999995018fffffe34000016030101fa010001"
    "f60303" + "0" * 1000 # Добавим нулей для длины
)

class TestPacketBuilder(unittest.TestCase):

    def setUp(self):
        self.builder = PacketBuilder()
        # Создаем mock pydivert.Packet
        self.original_packet = pydivert.Packet(RAW_CLIENT_HELLO, (0,0), 0)

    def _recalculate_correct_checksum(self, pkt_bytes: bytes) -> int:
        # Вспомогательная функция для пересчета правильной суммы
        raw = bytearray(pkt_bytes)
        ip_hl = (raw[0] & 0x0F) * 4
        tcp_start = ip_hl
        tcp_hl = ((raw[tcp_start + 12] >> 4) & 0x0F) * 4
        
        # Обнуляем checksum в пакете перед пересчетом
        raw[tcp_start + 16 : tcp_start + 18] = b'\x00\x00'
        
        return self.builder._tcp_checksum(
            bytes(raw[:ip_hl]),
            bytes(raw[tcp_start : tcp_start + tcp_hl]),
            bytes(raw[tcp_start + tcp_hl:])
        )

    def test_build_segment_with_corrupt_checksum(self):
        """
        Тест: Убедиться, что PacketBuilder портит checksum, когда corrupt_tcp_checksum=True.
        """
        print("\n--- Running test_build_segment_with_corrupt_checksum ---")
        
        spec = TCPSegmentSpec(
            payload=b'test_payload',
            rel_seq=0,
            flags=0x18, # PSH|ACK
            corrupt_tcp_checksum=True # <-- Ключевой флаг
        )
        
        # Собираем пакет
        pkt_bytes = self.builder.build_tcp_segment(self.original_packet, spec)
        
        self.assertIsNotNone(pkt_bytes, "PacketBuilder не должен возвращать None")
        
        # Извлекаем checksum из собранного пакета
        ip_hl = (pkt_bytes[0] & 0x0F) * 4
        tcp_start = ip_hl
        csum_in_packet = struct.unpack("!H", pkt_bytes[tcp_start + 16 : tcp_start + 18])[0]
        
        # Пересчитываем правильный checksum
        correct_csum = self._recalculate_correct_checksum(pkt_bytes)
        
        print(f"  Checksum в пакете: 0x{csum_in_packet:04x}")
        print(f"  Правильный checksum: 0x{correct_csum:04x}")
        
        # Проверяем, что они НЕ равны
        self.assertNotEqual(csum_in_packet, correct_csum, "Checksum не был испорчен!")
        
        # Проверяем, что он равен одному из наших "магических" значений
        self.assertIn(csum_in_packet, [0xDEAD, 0xBEEF], "Испорченный checksum имеет неправильное значение!")
        
        print("--- Test PASSED ---")

# Запуск теста
if __name__ == '__main__':
    unittest.main()