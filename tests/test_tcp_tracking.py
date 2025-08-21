import unittest
from core.net.packet_engine import PacketEngine
from core.net.byte_packet import IPv4Packet, TCPPacket
from core.net.tcp_tracker import TCPState


class TestTCPTracking(unittest.TestCase):
    def setUp(self):
        self.packet_engine = PacketEngine()

    def create_tcp_packet(
        self,
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        seq_num,
        ack_num,
        flags,
        payload=b"",
    ):
        """Вспомогательный метод для создания тестовых пакетов"""
        tcp = TCPPacket(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            payload=payload,
        )

        ip = IPv4Packet(
            src_addr=src_addr,
            dst_addr=dst_addr,
            ttl=64,
            protocol=6,
            payload=tcp.serialize(),
        )

        tcp.update_checksum(ip)
        ip.update_checksum()
        return ip, tcp

    def test_tcp_handshake(self):
        """Тест на корректное отслеживание TCP handshake"""
        # SYN
        ip1, tcp1 = self.create_tcp_packet(
            "192.168.1.1", 12345, "10.0.0.1", 80, 1000, 0, 0x02  # SYN
        )

        # Проверяем обработку SYN пакета
        self.assertTrue(self.packet_engine.process_tcp_packet(ip1, tcp1))
        self.assertEqual(
            self.packet_engine.get_connection_state(ip1, tcp1), TCPState.SYN_SENT
        )

        # SYN-ACK
        ip2, tcp2 = self.create_tcp_packet(
            "10.0.0.1", 80, "192.168.1.1", 12345, 2000, 1001, 0x12  # SYN-ACK
        )

        # Проверяем обработку SYN-ACK
        self.assertTrue(self.packet_engine.process_tcp_packet(ip2, tcp2))
        self.assertEqual(
            self.packet_engine.get_connection_state(ip2, tcp2), TCPState.SYN_RECEIVED
        )

        # ACK
        ip3, tcp3 = self.create_tcp_packet(
            "192.168.1.1", 12345, "10.0.0.1", 80, 1001, 2001, 0x10  # ACK
        )

        # Проверяем обработку ACK
        self.assertTrue(self.packet_engine.process_tcp_packet(ip3, tcp3))
        self.assertEqual(
            self.packet_engine.get_connection_state(ip3, tcp3), TCPState.ESTABLISHED
        )

    def test_tcp_fragmentation(self):
        """Тест на корректную фрагментацию TCP пакетов"""
        # Создаем большой пакет
        ip, tcp = self.create_tcp_packet(
            "192.168.1.1",
            12345,
            "10.0.0.1",
            80,
            1000,
            0,
            0x10,  # ACK
            payload=b"A" * 100,
        )

        # Фрагментируем пакет
        fragments = self.packet_engine.fragment_tcp_packet(ip, tcp, fragment_size=30)

        # Проверяем количество фрагментов
        self.assertGreater(len(fragments), 1)

        # Проверяем, что все фрагменты имеют корректные смещения
        for i, fragment in enumerate(fragments):
            self.assertEqual(fragment.frag_offset, i * 30 // 8)

    def test_retransmission_detection(self):
        """Тест на определение ретрансмиссий"""
        # Отправляем оригинальный пакет
        ip1, tcp1 = self.create_tcp_packet(
            "192.168.1.1",
            12345,
            "10.0.0.1",
            80,
            1000,
            0,
            0x10,  # ACK
            payload=b"Original",
        )
        self.assertTrue(self.packet_engine.process_tcp_packet(ip1, tcp1))

        # Отправляем ретрансмиссию (тот же sequence number)
        ip2, tcp2 = self.create_tcp_packet(
            "192.168.1.1",
            12345,
            "10.0.0.1",
            80,
            1000,
            0,
            0x10,  # ACK
            payload=b"Original",
        )

        # Проверяем, что ретрансмиссия определена корректно
        conn = self.packet_engine.tcp_tracker.get_connection(ip2, tcp2)
        self.assertTrue(
            self.packet_engine.tcp_tracker.handle_retransmission(ip2, tcp2, conn)
        )


if __name__ == "__main__":
    unittest.main()
