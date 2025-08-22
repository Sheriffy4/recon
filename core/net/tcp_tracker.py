from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Tuple, Optional
import time
from recon.core.net.byte_packet import TCPPacket, IPv4Packet

class TCPState(Enum):
    """Состояния TCP-соединения"""
    CLOSED = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    CLOSING = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()

@dataclass
class TCPConnection:
    """Информация о TCP-соединении"""
    client_addr: str
    client_port: int
    server_addr: str
    server_port: int
    client_seq: int = 0
    server_seq: int = 0
    client_window: int = 0
    server_window: int = 0
    state: TCPState = TCPState.CLOSED
    last_seen: float = 0.0

    @property
    def connection_id(self) -> Tuple[str, int, str, int]:
        """Уникальный идентификатор соединения"""
        return (self.client_addr, self.client_port, self.server_addr, self.server_port)

class TCPTracker:
    """Отслеживание TCP-соединений"""

    def __init__(self, timeout: float=300.0):
        self.connections: Dict[Tuple[str, int, str, int], TCPConnection] = {}
        self.timeout = timeout

    def _cleanup_old_connections(self):
        """Удаление устаревших соединений"""
        current_time = time.time()
        to_remove = []
        for conn_id, conn in self.connections.items():
            if current_time - conn.last_seen > self.timeout:
                to_remove.append(conn_id)
        for conn_id in to_remove:
            del self.connections[conn_id]

    def get_connection(self, ip: IPv4Packet, tcp: TCPPacket) -> Optional[TCPConnection]:
        """Получить существующее соединение или создать новое"""
        forward_id = (ip.src_addr, tcp.src_port, ip.dst_addr, tcp.dst_port)
        reverse_id = (ip.dst_addr, tcp.dst_port, ip.src_addr, tcp.src_port)
        conn = self.connections.get(forward_id) or self.connections.get(reverse_id)
        if not conn:
            if tcp.flags & 2:
                conn = TCPConnection(client_addr=ip.src_addr, client_port=tcp.src_port, server_addr=ip.dst_addr, server_port=tcp.dst_port, client_seq=tcp.seq_num, client_window=tcp.window, state=TCPState.SYN_SENT)
                self.connections[forward_id] = conn
        return conn

    def update_connection(self, ip: IPv4Packet, tcp: TCPPacket, conn: TCPConnection):
        """Обновить состояние соединения на основе пакета"""
        is_client = ip.src_addr == conn.client_addr and tcp.src_port == conn.client_port
        conn.last_seen = time.time()
        if is_client:
            conn.client_seq = tcp.seq_num
            conn.client_window = tcp.window
        else:
            conn.server_seq = tcp.seq_num
            conn.server_window = tcp.window
        if tcp.flags & 2:
            if conn.state == TCPState.CLOSED:
                conn.state = TCPState.SYN_SENT
            elif conn.state == TCPState.SYN_SENT and (not is_client):
                conn.state = TCPState.SYN_RECEIVED
        elif tcp.flags & 16:
            if conn.state == TCPState.SYN_RECEIVED and is_client:
                conn.state = TCPState.ESTABLISHED
            elif conn.state == TCPState.LAST_ACK:
                conn.state = TCPState.CLOSED
                self._remove_connection(conn)
        elif tcp.flags & 1:
            if conn.state == TCPState.ESTABLISHED:
                conn.state = TCPState.FIN_WAIT_1 if is_client else TCPState.CLOSE_WAIT
            elif conn.state == TCPState.CLOSE_WAIT and is_client:
                conn.state = TCPState.LAST_ACK
        elif tcp.flags & 4:
            conn.state = TCPState.CLOSED
            self._remove_connection(conn)

    def _remove_connection(self, conn: TCPConnection):
        """Удалить соединение из трекера"""
        conn_id = conn.connection_id
        if conn_id in self.connections:
            del self.connections[conn_id]

    def handle_retransmission(self, ip: IPv4Packet, tcp: TCPPacket, conn: TCPConnection) -> bool:
        """Проверить, является ли пакет ретрансмиссией"""
        is_client = ip.src_addr == conn.client_addr and tcp.src_port == conn.client_port
        expected_seq = conn.client_seq if is_client else conn.server_seq
        return tcp.seq_num < expected_seq

    def verify_packet(self, ip: IPv4Packet, tcp: TCPPacket) -> bool:
        """Проверить корректность пакета относительно состояния соединения"""
        conn = self.get_connection(ip, tcp)
        if not conn:
            return tcp.flags & 2 != 0
        is_client = ip.src_addr == conn.client_addr and tcp.src_port == conn.client_port
        if is_client:
            if tcp.seq_num < conn.client_seq:
                return self.handle_retransmission(ip, tcp, conn)
        elif tcp.seq_num < conn.server_seq:
            return self.handle_retransmission(ip, tcp, conn)
        if conn.state == TCPState.CLOSED:
            return False
        elif conn.state == TCPState.SYN_SENT:
            return not is_client and tcp.flags & 18
        elif conn.state == TCPState.ESTABLISHED:
            return True
        self.update_connection(ip, tcp, conn)
        return True