# test_windows_engine.py
import unittest
import struct
from unittest.mock import MagicMock

# Убедитесь, что путь к вашему проекту находится в PYTHONPATH,
# чтобы этот импорт сработал.
from core.bypass.engine.windows_engine import WindowsBypassEngine, EngineConfig

class MockPacket:
    """Простая имитация объекта pydivert.Packet для тестов."""
    def __init__(self, raw_bytes, src_addr='192.168.1.10', src_port=12345, dst_addr='157.240.245.174', dst_port=443):
        ip_header_len = (raw_bytes[0] & 0x0F) * 4
        # Проверка, что TCP заголовок присутствует
        if len(raw_bytes) > ip_header_len + 12:
            tcp_header_len = ((raw_bytes[ip_header_len + 12] >> 4) & 0x0F) * 4
            self.payload = raw_bytes[ip_header_len + tcp_header_len:]
        else:
            self.payload = b''
        self.raw = raw_bytes
        self.src_addr = src_addr
        self.src_port = src_port
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.interface = (1, 0)
        self.direction = 0
        # Добавим атрибут tcp для совместимости с кодом, который может его использовать
        self.tcp = MagicMock()
        self.tcp.rst = False


    def __repr__(self):
        return f"MockPacket(dst_addr='{self.dst_addr}')"

class TestZapretLogic(unittest.TestCase):

    def setUp(self):
        """Настраиваем окружение для каждого теста."""
        config = EngineConfig(debug=False)
        self.engine = WindowsBypassEngine(config)
        
        # --- Создаем пакет с известными, контролируемыми значениями ---
        self.base_seq = 1000000
        self.base_ack = 2000000
        
        ip_header = bytearray(b'\x45\x00\x00\x00\x12\x34\x00\x00\x80\x06\x00\x00\xc0\xa8\x01\x0a\x9d\xf0\xf5\xae')
        
        # Собираем TCP заголовок с нашими SEQ/ACK
        tcp_header = bytearray(20)
        struct.pack_into('!HHIIBBHHH', tcp_header, 0,
            12345,              # src_port
            443,                # dst_port
            self.base_seq,      # seq
            self.base_ack,      # ack
            (5 << 4),           # data_offset (5 * 4 = 20 bytes)
            0x18,               # flags (PSH, ACK)
            8192,               # window_size
            0,                  # checksum (placeholder)
            0                   # urgent_pointer
        )
        
        payload = b'\x16\x03\x01' + b'\x00' * 514
        
        # Собираем пакет и вычисляем правильные checksum
        raw_packet = bytearray(ip_header + tcp_header + payload)
        
        # Обновляем длину в IP заголовке
        struct.pack_into('!H', raw_packet, 2, len(raw_packet))
        
        # Вычисляем IP checksum
        ip_hl = (raw_packet[0] & 0x0F) * 4
        ip_csum = self.engine._ip_header_checksum(raw_packet[:ip_hl])
        struct.pack_into('!H', raw_packet, 10, ip_csum)
        
        # Вычисляем TCP checksum
        tcp_start = ip_hl
        tcp_hl = ((raw_packet[tcp_start + 12] >> 4) & 0x0F) * 4
        tcp_csum = self.engine._tcp_checksum(raw_packet[:ip_hl], raw_packet[tcp_start:tcp_start+tcp_hl], raw_packet[tcp_start+tcp_hl:])
        struct.pack_into('!H', raw_packet, tcp_start + 16, tcp_csum)

        self.original_packet_raw = bytes(raw_packet)
        self.mock_packet = MockPacket(self.original_packet_raw)

    def get_tcp_fields(self, raw_pkt):
        """Вспомогательная функция для извлечения полей из сырого пакета."""
        ip_hl = (raw_pkt[0] & 0x0F) * 4
        ttl = raw_pkt[8]
        tcp_start = ip_hl
        seq = struct.unpack('!I', raw_pkt[tcp_start+4:tcp_start+8])[0]
        csum = struct.unpack('!H', raw_pkt[tcp_start+16:tcp_start+18])[0]
        return ttl, seq, csum

    def test_zapret_fake_fakeddisorder_badsum_badseq(self):
        """
        Тестирует стратегию fake,fakeddisorder с fooling=badsum,badseq.
        """
        strategy = {
            'type': 'fakeddisorder', 
            'params': {
                'split_pos': 3, 
                'ttl': 3, 
                'fooling': ['badsum', 'badseq']
            }
        }
        
        sent_packets_raw = []
        mock_w = MagicMock()
        mock_w.send.side_effect = lambda pkt: sent_packets_raw.append(pkt.raw)

        # Патчим новый метод отправки через сырой сокет и старый метод для реальных пакетов
        with patch.object(self.engine, '_send_raw_socket', side_effect=lambda raw, ip, port: sent_packets_raw.append(raw)) as mock_raw_socket:
            with patch.object(self.engine, '_safe_send_packet', side_effect=lambda w, raw, pkt: sent_packets_raw.append(raw)) as mock_safe_send:
                self.engine.apply_bypass(self.mock_packet, mock_w, strategy)

        # --- Проверки ---
        self.assertEqual(len(sent_packets_raw), 3, "Должно быть отправлено ровно 3 пакета")
        
        # Проверяем, что для фейкового пакета был вызван _send_raw_socket
        mock_raw_socket.assert_called_once()
        # Проверяем, что для реальных пакетов был вызван _safe_send_packet
        self.assertEqual(mock_safe_send.call_count, 2)

        fake_pkt = mock_raw_socket.call_args[0][0]
        real_pkts = [call[0][1] for call in mock_safe_send.call_args_list]
        
        real_pkts.sort(key=lambda p: struct.unpack('!I', p[24:28])[0])
        real_pkt1, real_pkt2 = real_pkts

        # ... (остальные assert'ы остаются без изменений) ...
        # 1. Проверяем фейковый пакет
        fake_ttl, fake_seq, fake_csum = self.get_tcp_fields(fake_pkt)
        
        self.assertEqual(fake_ttl, 3, "TTL фейкового пакета должен быть 3")
        self.assertEqual(fake_csum, 0xDEAD, f"Checksum фейкового пакета должен быть 0xDEAD, а не {hex(fake_csum)}")
        self.assertEqual(fake_seq, (self.base_seq - 1) & 0xFFFFFFFF, "SEQ фейкового пакета должен быть base_seq - 1")

        # 2. Проверяем первый реальный сегмент
        real1_ttl, real1_seq, csum_in_pkt1 = self.get_tcp_fields(real_pkt1)
        
        self.assertEqual(real1_ttl, 3, "TTL первого реального сегмента должен быть 3")
        self.assertEqual(real1_seq, self.base_seq, "SEQ первого реального сегмента должен быть base_seq")
        
        ip_hl1 = (real_pkt1[0] & 0x0F) * 4
        tcp_hl1 = ((real_pkt1[ip_hl1 + 12] >> 4) & 0x0F) * 4
        correct_csum1 = self.engine._tcp_checksum(real_pkt1[:ip_hl1], real_pkt1[ip_hl1:ip_hl1+tcp_hl1], real_pkt1[ip_hl1+tcp_hl1:])
        self.assertEqual(csum_in_pkt1, correct_csum1, "Checksum первого реального сегмента должен быть корректным")

        # 3. Проверяем второй реальный сегмент
        real2_ttl, real2_seq, csum_in_pkt2 = self.get_tcp_fields(real_pkt2)
        
        self.assertEqual(real2_ttl, 3, "TTL второго реального сегмента должен быть 3")
        self.assertEqual(real2_seq, self.base_seq + 3, "SEQ второго реального сегмента должен быть base_seq + 3")
        
        ip_hl2 = (real_pkt2[0] & 0x0F) * 4
        tcp_hl2 = ((real_pkt2[ip_hl2 + 12] >> 4) & 0x0F) * 4
        correct_csum2 = self.engine._tcp_checksum(real_pkt2[:ip_hl2], real_pkt2[ip_hl2:ip_hl2+tcp_hl2], real_pkt2[ip_hl2+tcp_hl2:])
        self.assertEqual(csum_in_pkt2, correct_csum2, "Checksum второго реального сегмента должен быть корректным")

if __name__ == '__main__':
    unittest.main()