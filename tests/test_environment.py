import threading
from queue import Queue
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass
from recon.core.net.packet_engine import PacketEngine
from recon.core.net.byte_packet import IPv4Packet, TCPPacket, UDPPacket

@dataclass
class TestConnection:
    """Информация о тестовом соединении"""
    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    protocol: str
    state: str = 'NEW'
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

class PacketCapture:
    """Захват и анализ пакетов для тестирования"""

    def __init__(self):
        self.packets: List[bytes] = []
        self.connections: Dict[Tuple[str, int, str, int], TestConnection] = {}

    def add_packet(self, packet: bytes):
        """Добавить пакет в захват"""
        self.packets.append(packet)

    def get_connection(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int) -> Optional[TestConnection]:
        """Получить информацию о соединении"""
        conn_id = (src_addr, src_port, dst_addr, dst_port)
        return self.connections.get(conn_id)

    def analyze_packets(self) -> Dict[str, int]:
        """Анализ захваченных пакетов"""
        stats = {'total': len(self.packets), 'tcp': 0, 'udp': 0, 'quic': 0, 'other': 0}
        engine = PacketEngine()
        for raw_packet in self.packets:
            try:
                ip_packet = IPv4Packet.parse(raw_packet)
                if ip_packet.protocol == 6:
                    tcp_packet = TCPPacket.parse(ip_packet.payload)
                    stats['tcp'] += 1
                    self._update_connection_stats(ip_packet, tcp_packet, 'TCP')
                elif ip_packet.protocol == 17:
                    udp_packet = UDPPacket.parse(ip_packet.payload)
                    if udp_packet.dst_port in [443, 80] and len(udp_packet.payload) > 0:
                        try:
                            quic_packet = engine.parse_quic_packet(udp_packet.payload)
                            if quic_packet:
                                stats['quic'] += 1
                                self._update_connection_stats(ip_packet, udp_packet, 'QUIC')
                                continue
                        except:
                            pass
                    stats['udp'] += 1
                    self._update_connection_stats(ip_packet, udp_packet, 'UDP')
                else:
                    stats['other'] += 1
            except Exception:
                stats['other'] += 1
        return stats

    def _update_connection_stats(self, ip_packet: IPv4Packet, transport_packet: any, protocol: str):
        """Обновить статистику соединения"""
        conn_id = (ip_packet.src_addr, transport_packet.src_port, ip_packet.dst_addr, transport_packet.dst_port)
        if conn_id not in self.connections:
            self.connections[conn_id] = TestConnection(src_addr=ip_packet.src_addr, src_port=transport_packet.src_port, dst_addr=ip_packet.dst_addr, dst_port=transport_packet.dst_port, protocol=protocol)
        conn = self.connections[conn_id]
        conn.packets_sent += 1
        conn.bytes_sent += len(ip_packet.payload)
        if protocol == 'TCP':
            tcp_packet = transport_packet
            if tcp_packet.flags & 2:
                conn.state = 'SYN_SENT'
            elif tcp_packet.flags & 18 == 18:
                conn.state = 'SYN_RECEIVED'
            elif tcp_packet.flags & 16:
                if conn.state in ['SYN_RECEIVED', 'SYN_SENT']:
                    conn.state = 'ESTABLISHED'

class TestEnvironment:
    """Тестовое окружение для PacketEngine"""

    def __init__(self):
        self.packet_engine = PacketEngine()
        self.capture = PacketCapture()
        self.running = False
        self.packet_queue = Queue()

    def start(self):
        """Запуск тестового окружения"""
        self.running = True
        self.process_thread = threading.Thread(target=self._process_packets)
        self.process_thread.start()

    def stop(self):
        """Остановка тестового окружения"""
        self.running = False
        self.packet_queue.put(None)
        self.process_thread.join()

    def inject_packet(self, packet: bytes):
        """Добавить пакет в очередь обработки"""
        self.packet_queue.put(packet)

    def _process_packets(self):
        """Обработка пакетов в отдельном потоке"""
        while self.running:
            packet = self.packet_queue.get()
            if packet is None:
                break
            self.capture.add_packet(packet)
            try:
                ip_packet = IPv4Packet.parse(packet)
                if ip_packet.protocol == 6:
                    tcp_packet = TCPPacket.parse(ip_packet.payload)
                    modified = self.packet_engine.process_tcp_packet(ip_packet, tcp_packet)
                elif ip_packet.protocol == 17:
                    udp_packet = UDPPacket.parse(ip_packet.payload)
                    if udp_packet.dst_port in [443, 80]:
                        try:
                            quic_packet = self.packet_engine.parse_quic_packet(udp_packet.payload)
                            if quic_packet:
                                modified = self.packet_engine.process_quic_initial(quic_packet)
                        except:
                            pass
            except Exception as e:
                print(f'Error processing packet: {e}')

    def get_stats(self) -> Dict[str, int]:
        """Получить статистику обработки пакетов"""
        return self.capture.analyze_packets()

    def get_connections(self) -> List[TestConnection]:
        """Получить список активных соединений"""
        return list(self.capture.connections.values())