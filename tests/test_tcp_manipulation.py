import unittest
from core.net.packet_engine import PacketEngine
from core.net.byte_packet import IPv4Packet, TCPPacket
from core.net.tcp_manipulator import SegmentConfig
from core.net.tcp_options import TCPOptions


class TestTCPManipulation(unittest.TestCase):
    def setUp(self):
        self.packet_engine = PacketEngine()

    def create_test_packet(self):
        """Создать тестовый TCP пакет"""
        tcp = TCPPacket(
            src_port=12345,
            dst_port=80,
            seq_num=1000,
            ack_num=2000,
            flags=0x10,  # ACK
            payload=b"Test payload for manipulation",
        )

        ip = IPv4Packet(
            src_addr="192.168.1.1",
            dst_addr="10.0.0.1",
            ttl=64,
            protocol=6,
            payload=tcp.serialize(),
        )

        return ip, tcp

    def test_tcp_options(self):
        """Тест создания и обработки TCP options"""
        # Создаем пакет с MSS option
        mss_option = self.packet_engine.create_tcp_option(TCPOptions.MSS, mss=1460)

        # Создаем пакет с window scale option
        ws_option = self.packet_engine.create_tcp_option(
            TCPOptions.WINDOW_SCALE, shift_count=7
        )

        # Создаем пакет с timestamp option
        ts_option = self.packet_engine.create_tcp_option(
            TCPOptions.TIMESTAMP, ts_val=123456, ts_echo=654321
        )

        ip, tcp = self.create_test_packet()
        tcp.options = [mss_option, ws_option, ts_option]

        # Сериализуем и парсим обратно
        raw = tcp.serialize()
        parsed = TCPPacket.parse(raw)

        # Проверяем, что options сохранились
        self.assertEqual(len(parsed.options), 3)
        self.assertEqual(parsed.options[0].kind, TCPOptions.MSS)
        self.assertEqual(parsed.options[1].kind, TCPOptions.WINDOW_SCALE)
        self.assertEqual(parsed.options[2].kind, TCPOptions.TIMESTAMP)

    def test_multisplit_attack(self):
        """Тест создания multisplit атаки"""
        ip, tcp = self.create_test_packet()

        config = SegmentConfig(
            min_size=5,
            max_size=10,
            overlap_size=3,
            duplicate_chance=1.0,  # Гарантированное создание дубликатов
        )

        packets = self.packet_engine.create_multisplit_attack(ip, tcp, config)

        # Проверяем, что пакеты разделены
        self.assertGreater(len(packets), 1)

        # Проверяем, что все пакеты имеют корректные IP/TCP заголовки
        for packet in packets:
            self.assertIsInstance(packet, IPv4Packet)
            tcp_data = TCPPacket.parse(packet.payload)
            self.assertEqual(tcp_data.src_port, tcp.src_port)
            self.assertEqual(tcp_data.dst_port, tcp.dst_port)

    def test_overlap_attack(self):
        """Тест создания overlap атаки"""
        ip, tcp = self.create_test_packet()

        # Создаем перекрывающиеся данные
        overlap_data = b"OVERLAPPED"
        offset = 5

        packets = self.packet_engine.create_overlap_attack(
            ip, tcp, overlap_data, offset
        )

        # Проверяем, что создано два пакета
        self.assertEqual(len(packets), 2)

        # Проверяем второй пакет (с перекрытием)
        tcp_overlap = TCPPacket.parse(packets[1].payload)
        self.assertEqual(tcp_overlap.seq_num, tcp.seq_num + offset)
        self.assertEqual(tcp_overlap.payload, overlap_data)

    def test_segment_reassembly(self):
        """Тест пересборки сегментированных данных"""
        ip, tcp = self.create_test_packet()
        original_payload = tcp.payload

        # Разбиваем на сегменты
        config = SegmentConfig(
            min_size=5,
            max_size=10,
            overlap_size=0,  # Без перекрытия для простоты теста
            duplicate_chance=0.0,
        )

        packets = self.packet_engine.create_multisplit_attack(ip, tcp, config)

        # Собираем payload из всех сегментов
        reassembled = b""
        for packet in sorted(packets, key=lambda p: TCPPacket.parse(p.payload).seq_num):
            tcp_seg = TCPPacket.parse(packet.payload)
            reassembled += tcp_seg.payload

        # Проверяем, что данные собрались корректно
        self.assertEqual(reassembled, original_payload)


if __name__ == "__main__":
    unittest.main()
