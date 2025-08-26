"""
Адаптер совместимости для замены Scapy на побайтовую обработку.
Предоставляет API, совместимый с существующим кодом, использующим Scapy.
"""

import socket
import struct
import logging
import random
import time
from typing import Optional, Dict, Any, List, Union, Tuple, Callable
from dataclasses import dataclass

from .raw_packet_engine import RawPacketEngine, RawPacket, TCPHeader, ProtocolType


class ScapyCompatibilityError(Exception):
    """Исключение для ошибок совместимости."""
    pass


@dataclass
class PacketLayer:
    """Базовый класс для слоев пакета (аналог Scapy layers)."""
    pass


class IP(PacketLayer):
    """Эмуляция IP слоя Scapy."""

    def __init__(self, dst: str = "127.0.0.1", src: str = "127.0.0.1",
                 ttl: int = 64, proto: int = 6, **kwargs):
        super().__init__()
        self.dst = dst
        self.src = src
        self.ttl = ttl
        self.proto = proto
        self.len = None
        self.id = random.randint(1, 65535)
        self.flags = 0
        self.frag = 0
        self.tos = 0
        self.version = 4
        self.ihl = 5
        self.chksum = None

        # Обработка дополнительных параметров
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __bytes__(self) -> bytes:
        """Конвертирует в байты."""
        engine = RawPacketEngine()
        # Создаем минимальный пакет для получения IP заголовка
        packet = engine.create_tcp_packet(
            self.src, self.dst, 0, 0, ttl=self.ttl
        )
        return packet.data[:20]  # Только IP заголовок

    def __truediv__(self, other):
        """Оператор / для комбинирования слоев."""
        if isinstance(other, TCP):
            return IPTCPPacket(self, other)
        elif isinstance(other, Raw):
            return IPRawPacket(self, other)
        else:
            raise ScapyCompatibilityError(f"Unsupported layer combination: IP / {type(other)}")


class TCP(PacketLayer):
    """Эмуляция TCP слоя Scapy."""

    def __init__(self, sport: int = 0, dport: int = 0, seq: int = 0,
                 ack: int = 0, flags: Union[int, str] = 0, window: int = 8192,
                 **kwargs):
        super().__init__()
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.window = window
        self.chksum = None
        self.urgptr = 0
        self.dataofs = 5
        self.reserved = 0
        self.options = []

        # Обработка флагов
        if isinstance(flags, str):
            self.flags = self._parse_flags_string(flags)
        else:
            self.flags = flags

        # Обработка дополнительных параметров
        for key, value in kwargs.items():
            setattr(self, key, value)

    def _parse_flags_string(self, flags_str: str) -> int:
        """Парсит строку флагов в число."""
        flags = 0
        flag_map = {
            'F': TCPHeader.FLAG_FIN,
            'S': TCPHeader.FLAG_SYN,
            'R': TCPHeader.FLAG_RST,
            'P': TCPHeader.FLAG_PSH,
            'A': TCPHeader.FLAG_ACK,
            'U': TCPHeader.FLAG_URG,
            'E': TCPHeader.FLAG_ECE,
            'C': TCPHeader.FLAG_CWR
        }

        for char in flags_str.upper():
            if char in flag_map:
                flags |= flag_map[char]

        return flags

    def __bytes__(self) -> bytes:
        """Конвертирует в байты."""
        header = TCPHeader()
        header.src_port = self.sport
        header.dst_port = self.dport
        header.seq_num = self.seq
        header.ack_num = self.ack
        header.flags = self.flags
        header.window_size = self.window
        header.data_offset = self.dataofs
        return header.pack()


class Raw(PacketLayer):
    """Эмуляция Raw слоя Scapy."""

    def __init__(self, load: bytes = b'', **kwargs):
        super().__init__()
        self.load = load if isinstance(load, bytes) else str(load).encode()

        # Обработка дополнительных параметров
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __bytes__(self) -> bytes:
        """Конвертирует в байты."""
        return self.load

    def __len__(self) -> int:
        """Возвращает длину данных."""
        return len(self.load)


class IPTCPPacket:
    """Комбинированный IP+TCP пакет."""

    def __init__(self, ip_layer: IP, tcp_layer: TCP, payload: Optional[Raw] = None):
        self.ip = ip_layer
        self.tcp = tcp_layer
        self.payload = payload
        self._raw_packet = None

    def __truediv__(self, other):
        """Добавление payload."""
        if isinstance(other, Raw):
            return IPTCPPacket(self.ip, self.tcp, other)
        else:
            raise ScapyCompatibilityError(f"Unsupported payload type: {type(other)}")

    def __bytes__(self) -> bytes:
        """Конвертирует в байты."""
        if self._raw_packet is None:
            self._build_packet()
        return self._raw_packet.data

    def _build_packet(self):
        """Строит сырой пакет."""
        engine = RawPacketEngine()
        payload_data = self.payload.load if self.payload else b''

        self._raw_packet = engine.create_tcp_packet(
            src_ip=self.ip.src,
            dst_ip=self.ip.dst,
            src_port=self.tcp.sport,
            dst_port=self.tcp.dport,
            seq_num=self.tcp.seq,
            ack_num=self.tcp.ack,
            flags=self.tcp.flags,
            payload=payload_data,
            ttl=self.ip.ttl,
            window_size=self.tcp.window
        )

    def show(self):
        """Показывает информацию о пакете (аналог Scapy show())."""
        if self._raw_packet is None:
            self._build_packet()

        engine = RawPacketEngine()
        info = engine.get_packet_info(self._raw_packet)

        print("###[ IP ]###")
        print(f"  version   = {info.get('version', 4)}")
        print(f"  src       = {self.ip.src}")
        print(f"  dst       = {self.ip.dst}")
        print(f"  ttl       = {self.ip.ttl}")
        print(f"  proto     = tcp")
        print("###[ TCP ]###")
        print(f"  sport     = {self.tcp.sport}")
        print(f"  dport     = {self.tcp.dport}")
        print(f"  seq       = {self.tcp.seq}")
        print(f"  ack       = {self.tcp.ack}")
        print(f"  flags     = {self.tcp.flags}")
        print(f"  window    = {self.tcp.window}")

        if self.payload:
            print("###[ Raw ]###")
            print(f"  load      = {repr(self.payload.load[:50])}")


class IPRawPacket:
    """Комбинированный IP+Raw пакет."""

    def __init__(self, ip_layer: IP, raw_layer: Raw):
        self.ip = ip_layer
        self.raw = raw_layer
        self._raw_packet = None

    def __bytes__(self) -> bytes:
        """Конвертирует в байты."""
        if self._raw_packet is None:
            self._build_packet()
        return self._raw_packet.data

    def _build_packet(self):
        """Строит сырой пакет."""
        engine = RawPacketEngine()
        # Для Raw пакетов создаем TCP пакет с данными
        self._raw_packet = engine.create_tcp_packet(
            src_ip=self.ip.src,
            dst_ip=self.ip.dst,
            src_port=0,
            dst_port=0,
            payload=self.raw.load,
            ttl=self.ip.ttl
        )


# Эмуляция функций Scapy
def RandShort() -> int:
    """Генерирует случайный короткий номер (аналог Scapy RandShort)."""
    return random.randint(1024, 65535)


def fragment(packet, fragsize: int = 8) -> List[bytes]:
    """Фрагментирует пакет (аналог Scapy fragment)."""
    if isinstance(packet, (IPTCPPacket, IPRawPacket)):
        packet_bytes = bytes(packet)
    else:
        packet_bytes = bytes(packet)

    engine = RawPacketEngine()
    raw_packet = engine.parse_packet(packet_bytes)
    fragments = engine.fragment_packet(raw_packet, fragsize)

    return [frag.data for frag in fragments]


class ScapySocket:
    """Эмуляция сокета Scapy для отправки пакетов."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._socket = None
        self._setup_socket()

    def _setup_socket(self):
        """Настраивает сырой сокет."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            self.logger.error("Raw socket requires administrator privileges")
            raise
        except Exception as e:
            self.logger.error(f"Failed to create raw socket: {e}")
            raise

    def send(self, packet) -> int:
        """Отправляет пакет."""
        try:
            if isinstance(packet, (IPTCPPacket, IPRawPacket)):
                packet_bytes = bytes(packet)
            else:
                packet_bytes = bytes(packet)

            # Извлекаем адрес назначения
            if hasattr(packet, 'ip'):
                dst_addr = packet.ip.dst
            else:
                # Парсим IP заголовок для получения адреса
                engine = RawPacketEngine()
                parsed = engine.parse_packet(packet_bytes)
                dst_addr = parsed.dst_ip

            sent = self._socket.sendto(packet_bytes, (dst_addr, 0))
            return sent

        except Exception as e:
            self.logger.error(f"Failed to send packet: {e}")
            raise

    def close(self):
        """Закрывает сокет."""
        if self._socket:
            self._socket.close()
            self._socket = None


# Глобальный сокет для совместимости
_global_socket = None


def send(packet, verbose: bool = False) -> int:
    """Отправляет пакет (аналог Scapy send)."""
    global _global_socket

    if _global_socket is None:
        _global_socket = ScapySocket()

    if verbose:
        print(f"Sending packet to {getattr(packet, 'ip', {}).get('dst', 'unknown')}")

    return _global_socket.send(packet)


def sr1(packet, timeout: float = 2, verbose: bool = False) -> Optional[bytes]:
    """
    Отправляет пакет и ждет ответ (упрощенная версия Scapy sr1).
    Возвращает сырые байты ответа или None.
    """
    try:
        # Отправляем пакет
        send(packet, verbose=verbose)

        # Создаем сокет для получения ответа
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_socket.settimeout(timeout)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = recv_socket.recvfrom(65535)
                # Простая проверка - это ответ на наш пакет?
                if addr[0] == getattr(packet, 'ip', {}).get('dst', ''):
                    recv_socket.close()
                    return data
            except socket.timeout:
                break
            except Exception:
                continue

        recv_socket.close()
        return None

    except Exception as e:
        logging.getLogger(__name__).error(f"sr1 failed: {e}")
        return None


# Дополнительные утилиты для совместимости
class Packet:
    """Базовый класс пакета для совместимости."""

    def __init__(self, data: bytes = b''):
        self._data = data
        self.payload = None

    def __bytes__(self) -> bytes:
        return self._data

    def __len__(self) -> int:
        return len(self._data)

    def show(self):
        """Показывает информацию о пакете."""
        engine = RawPacketEngine()
        try:
            parsed = engine.parse_packet(self._data)
            info = engine.get_packet_info(parsed)

            for key, value in info.items():
                print(f"{key}: {value}")
        except Exception as e:
            print(f"Error parsing packet: {e}")


def wrpcap(filename: str, packets: List, append: bool = False):
    """
    Записывает пакеты в файл (упрощенная версия).
    Сохраняет как бинарные данные.
    """
    mode = 'ab' if append else 'wb'

    with open(filename, mode) as f:
        for packet in packets:
            if isinstance(packet, (IPTCPPacket, IPRawPacket, Packet)):
                data = bytes(packet)
            else:
                data = bytes(packet)

            # Записываем длину пакета и сами данные
            f.write(struct.pack('!I', len(data)))
            f.write(data)


def rdpcap(filename: str) -> List[Packet]:
    """
    Читает пакеты из файла (упрощенная версия).
    """
    packets = []

    try:
        with open(filename, 'rb') as f:
            while True:
                # Читаем длину пакета
                length_data = f.read(4)
                if len(length_data) < 4:
                    break

                length = struct.unpack('!I', length_data)[0]

                # Читаем данные пакета
                packet_data = f.read(length)
                if len(packet_data) < length:
                    break

                packets.append(Packet(packet_data))

    except Exception as e:
        logging.getLogger(__name__).error(f"Error reading pcap file: {e}")

    return packets


def sniff(count: int = 0, timeout: Optional[float] = None,
          filter: Optional[str] = None, prn: Optional[Callable] = None) -> List[Packet]:
    """
    Упрощенная версия sniff для захвата пакетов.
    """
    packets = []

    try:
        # Создаем сырой сокет для захвата
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        if timeout:
            sock.settimeout(timeout)

        start_time = time.time()
        captured = 0

        while True:
            if count > 0 and captured >= count:
                break

            if timeout and time.time() - start_time > timeout:
                break

            try:
                data, addr = sock.recvfrom(65535)
                packet = Packet(data)
                packets.append(packet)
                captured += 1

                if prn:
                    prn(packet)

            except socket.timeout:
                break
            except Exception:
                continue

        sock.close()

    except Exception as e:
        logging.getLogger(__name__).error(f"Sniff failed: {e}")

    return packets


# Константы для совместимости
class conf:
    """Конфигурация (аналог Scapy conf)."""
    verb = 1
    L3socket = None
    use_pcap = False


# Экспорт основных классов и функций для совместимости
__all__ = [
    'IP', 'TCP', 'Raw', 'RandShort', 'fragment', 'send', 'sr1',
    'Packet', 'wrpcap', 'rdpcap', 'sniff', 'conf',
    'ScapySocket', 'ScapyCompatibilityError'
]