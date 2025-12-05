"""
Raw packet engine - замена Scapy на побайтовую обработку пакетов.
Высокопроизводительная система для создания и парсинга сетевых пакетов.
"""

import struct
import socket
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class ProtocolType(Enum):
    """Типы протоколов."""

    TCP = 6
    UDP = 17
    ICMP = 1


@dataclass
class RawPacket:
    """Представление сырого пакета."""

    data: bytes
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[ProtocolType] = None
    payload: Optional[bytes] = None
    timestamp: Optional[float] = None  # Unix timestamp from PCAP


@dataclass
class TLSInfo:
    """Информация о TLS соединении."""

    sni: Optional[str] = None
    is_client_hello: bool = False
    is_server_hello: bool = False
    tls_version: Optional[str] = None


@dataclass
class PacketInfo:
    """Детальная информация о пакете для совместимости с анализаторами."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sequence_num: int
    ack_num: int
    ttl: int
    flags: List[str]  # ['SYN', 'ACK', etc.]
    payload_length: int
    payload_hex: str
    checksum: int
    checksum_valid: bool
    is_client_hello: bool
    tls_info: Optional[TLSInfo] = None


class IPHeader:
    """Класс для работы с IP заголовками."""

    def __init__(self):
        self.version = 4
        self.ihl = 5  # Internet Header Length (в 32-битных словах)
        self.tos = 0  # Type of Service
        self.total_length = 0
        self.identification = 0
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = 64
        self.protocol = 6  # TCP по умолчанию
        self.checksum = 0
        self.src_ip = "0.0.0.0"
        self.dst_ip = "0.0.0.0"

    def pack(self) -> bytes:
        """Упаковывает IP заголовок в байты."""
        # Конвертируем IP адреса в 32-битные числа
        src_ip_int = struct.unpack("!I", socket.inet_aton(self.src_ip))[0]
        dst_ip_int = struct.unpack("!I", socket.inet_aton(self.dst_ip))[0]

        # Упаковываем заголовок
        version_ihl = (self.version << 4) | self.ihl
        flags_fragment = (self.flags << 13) | self.fragment_offset

        header = struct.pack(
            "!BBHHHBBHII",
            version_ihl,
            self.tos,
            self.total_length,
            self.identification,
            flags_fragment,
            self.ttl,
            self.protocol,
            self.checksum,
            src_ip_int,
            dst_ip_int,
        )

        return header

    @classmethod
    def unpack(cls, data: bytes) -> "IPHeader":
        """Распаковывает IP заголовок из байтов."""
        if len(data) < 20:
            raise ValueError("IP header too short")

        header = cls()

        # Распаковываем основные поля
        unpacked = struct.unpack("!BBHHHBBHII", data[:20])

        version_ihl = unpacked[0]
        header.version = (version_ihl >> 4) & 0xF
        header.ihl = version_ihl & 0xF
        header.tos = unpacked[1]
        header.total_length = unpacked[2]
        header.identification = unpacked[3]

        flags_fragment = unpacked[4]
        header.flags = (flags_fragment >> 13) & 0x7
        header.fragment_offset = flags_fragment & 0x1FFF

        header.ttl = unpacked[5]
        header.protocol = unpacked[6]
        header.checksum = unpacked[7]

        # Конвертируем IP адреса обратно в строки
        header.src_ip = socket.inet_ntoa(struct.pack("!I", unpacked[8]))
        header.dst_ip = socket.inet_ntoa(struct.pack("!I", unpacked[9]))

        return header

    def calculate_checksum(self, data: bytes) -> int:
        """Вычисляет контрольную сумму IP заголовка."""
        # Обнуляем поле checksum для вычисления
        checksum_data = bytearray(data)
        checksum_data[10:12] = b"\x00\x00"

        # Вычисляем контрольную сумму
        checksum = 0
        for i in range(0, len(checksum_data), 2):
            if i + 1 < len(checksum_data):
                word = (checksum_data[i] << 8) + checksum_data[i + 1]
            else:
                word = checksum_data[i] << 8
            checksum += word

        # Складываем старшие и младшие биты
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # Инвертируем результат
        return (~checksum) & 0xFFFF


class TCPHeader:
    """Класс для работы с TCP заголовками."""

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 5  # В 32-битных словах
        self.reserved = 0
        self.flags = 0
        self.window_size = 65535
        self.checksum = 0
        self.urgent_pointer = 0
        self.options = b""

    # TCP флаги
    FLAG_FIN = 0x01
    FLAG_SYN = 0x02
    FLAG_RST = 0x04
    FLAG_PSH = 0x08
    FLAG_ACK = 0x10
    FLAG_URG = 0x20
    FLAG_ECE = 0x40
    FLAG_CWR = 0x80

    def pack(self) -> bytes:
        """Упаковывает TCP заголовок в байты."""
        # Формируем поле data_offset + reserved + flags
        offset_reserved_flags = (
            (self.data_offset << 12) | (self.reserved << 6) | self.flags
        )

        header = struct.pack(
            "!HHLLHHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            offset_reserved_flags,
            self.window_size,
            self.checksum,
            self.urgent_pointer,
        )

        return header + self.options

    @classmethod
    def unpack(cls, data: bytes) -> "TCPHeader":
        """Распаковывает TCP заголовок из байтов."""
        if len(data) < 20:
            raise ValueError("TCP header too short")

        header = cls()

        # Распаковываем основные поля
        unpacked = struct.unpack("!HHLLHHHH", data[:20])

        header.src_port = unpacked[0]
        header.dst_port = unpacked[1]
        header.seq_num = unpacked[2]
        header.ack_num = unpacked[3]

        offset_reserved_flags = unpacked[4]
        header.data_offset = (offset_reserved_flags >> 12) & 0xF
        header.reserved = (offset_reserved_flags >> 6) & 0x3F
        header.flags = offset_reserved_flags & 0xFF

        header.window_size = unpacked[5]
        header.checksum = unpacked[6]
        header.urgent_pointer = unpacked[7]

        # Извлекаем опции, если есть
        options_length = (header.data_offset - 5) * 4
        if options_length > 0 and len(data) >= 20 + options_length:
            header.options = data[20 : 20 + options_length]

        return header

    def calculate_checksum(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> int:
        """Вычисляет контрольную сумму TCP заголовка."""
        # Создаем псевдо-заголовок
        src_ip_int = struct.unpack("!I", socket.inet_aton(src_ip))[0]
        dst_ip_int = struct.unpack("!I", socket.inet_aton(dst_ip))[0]

        tcp_length = len(self.pack()) + len(payload)
        pseudo_header = struct.pack("!IIBBH", src_ip_int, dst_ip_int, 0, 6, tcp_length)

        # Объединяем псевдо-заголовок, TCP заголовок и данные
        tcp_header_data = bytearray(self.pack())
        tcp_header_data[16:18] = b"\x00\x00"  # Обнуляем checksum

        checksum_data = pseudo_header + tcp_header_data + payload

        # Вычисляем контрольную сумму
        checksum = 0
        for i in range(0, len(checksum_data), 2):
            if i + 1 < len(checksum_data):
                word = (checksum_data[i] << 8) + checksum_data[i + 1]
            else:
                word = checksum_data[i] << 8
            checksum += word

        # Складываем старшие и младшие биты
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # Инвертируем результат
        return (~checksum) & 0xFFFF


class RawPacketEngine:
    """Основной класс для работы с сырыми пакетами."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def create_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int = 0,
        ack_num: int = 0,
        flags: int = 0,
        payload: bytes = b"",
        ttl: int = 64,
        window_size: int = 65535,
    ) -> RawPacket:
        """Создает TCP пакет."""
        try:
            # Создаем IP заголовок
            ip_header = IPHeader()
            ip_header.src_ip = src_ip
            ip_header.dst_ip = dst_ip
            ip_header.protocol = ProtocolType.TCP.value
            ip_header.ttl = ttl

            # Создаем TCP заголовок
            tcp_header = TCPHeader()
            tcp_header.src_port = src_port
            tcp_header.dst_port = dst_port
            tcp_header.seq_num = seq_num
            tcp_header.ack_num = ack_num
            tcp_header.flags = flags
            tcp_header.window_size = window_size

            # Вычисляем контрольные суммы
            tcp_header.checksum = tcp_header.calculate_checksum(src_ip, dst_ip, payload)

            # Упаковываем заголовки
            tcp_data = tcp_header.pack() + payload
            ip_header.total_length = 20 + len(tcp_data)
            ip_header_data = ip_header.pack()
            ip_header.checksum = ip_header.calculate_checksum(ip_header_data)

            # Пересоздаем IP заголовок с правильной контрольной суммой
            ip_header_data = ip_header.pack()

            # Создаем финальный пакет
            packet_data = ip_header_data + tcp_data

            return RawPacket(
                data=packet_data,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=ProtocolType.TCP,
                payload=payload,
            )

        except Exception as e:
            self.logger.error(f"Error creating TCP packet: {e}")
            raise

    def create_syn_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int = 0,
        ttl: int = 64,
    ) -> RawPacket:
        """Создает TCP SYN пакет."""
        return self.create_tcp_packet(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq_num=seq_num,
            flags=TCPHeader.FLAG_SYN,
            ttl=ttl,
        )

    def create_syn_ack_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int = 0,
        ack_num: int = 0,
        ttl: int = 64,
    ) -> RawPacket:
        """Создает TCP SYN-ACK пакет."""
        return self.create_tcp_packet(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=TCPHeader.FLAG_SYN | TCPHeader.FLAG_ACK,
            ttl=ttl,
        )

    def create_ack_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int = 0,
        ack_num: int = 0,
        ttl: int = 64,
    ) -> RawPacket:
        """Создает TCP ACK пакет."""
        return self.create_tcp_packet(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=TCPHeader.FLAG_ACK,
            ttl=ttl,
        )

    def create_psh_ack_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int = 0,
        ack_num: int = 0,
        payload: bytes = b"",
        ttl: int = 64,
    ) -> RawPacket:
        """Создает TCP PSH-ACK пакет с данными."""
        return self.create_tcp_packet(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=TCPHeader.FLAG_PSH | TCPHeader.FLAG_ACK,
            payload=payload,
            ttl=ttl,
        )

    def _parse_packet_internal(self, data: bytes) -> RawPacket:
        """Парсит сырой пакет."""
        try:
            if len(data) < 20:
                raise ValueError("Packet too short for IP header")

            # Парсим IP заголовок
            ip_header = IPHeader.unpack(data)

            # Определяем размер IP заголовка
            ip_header_size = ip_header.ihl * 4

            if len(data) < ip_header_size:
                raise ValueError("Packet too short for complete IP header")

            # Извлекаем данные после IP заголовка
            payload_data = data[ip_header_size:]

            packet = RawPacket(
                data=data,
                src_ip=ip_header.src_ip,
                dst_ip=ip_header.dst_ip,
                protocol=(
                    ProtocolType(ip_header.protocol)
                    if ip_header.protocol in [1, 6, 17]
                    else None
                ),
            )

            # Парсим TCP заголовок, если это TCP пакет
            if ip_header.protocol == ProtocolType.TCP.value and len(payload_data) >= 20:
                tcp_header = TCPHeader.unpack(payload_data)
                packet.src_port = tcp_header.src_port
                packet.dst_port = tcp_header.dst_port

                # Извлекаем TCP payload
                tcp_header_size = tcp_header.data_offset * 4
                if len(payload_data) > tcp_header_size:
                    packet.payload = payload_data[tcp_header_size:]

            return packet

        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")
            raise

    def _fragment_packet_internal(
        self, packet: RawPacket, fragment_size: int
    ) -> List[RawPacket]:
        """Фрагментирует пакет на части."""
        try:
            if len(packet.data) <= fragment_size:
                return [packet]

            fragments = []
            ip_header = IPHeader.unpack(packet.data[:20])
            ip_header_size = ip_header.ihl * 4

            # Данные для фрагментации (без IP заголовка)
            payload_data = packet.data[ip_header_size:]

            # Размер данных в каждом фрагменте (должен быть кратен 8)
            fragment_data_size = (fragment_size - ip_header_size) & ~7

            offset = 0
            fragment_id = ip_header.identification

            while offset < len(payload_data):
                # Создаем новый IP заголовок для фрагмента
                frag_header = IPHeader()
                frag_header.version = ip_header.version
                frag_header.ihl = ip_header.ihl
                frag_header.tos = ip_header.tos
                frag_header.identification = fragment_id
                frag_header.ttl = ip_header.ttl
                frag_header.protocol = ip_header.protocol
                frag_header.src_ip = ip_header.src_ip
                frag_header.dst_ip = ip_header.dst_ip

                # Определяем размер данных в этом фрагменте
                remaining = len(payload_data) - offset
                current_fragment_size = min(fragment_data_size, remaining)

                # Устанавливаем флаги и смещение
                frag_header.fragment_offset = offset // 8
                if offset + current_fragment_size < len(payload_data):
                    frag_header.flags = 1  # More Fragments flag
                else:
                    frag_header.flags = 0  # Last fragment

                # Данные фрагмента
                fragment_data = payload_data[offset : offset + current_fragment_size]
                frag_header.total_length = ip_header_size + len(fragment_data)

                # Создаем пакет фрагмента
                frag_header_data = frag_header.pack()
                frag_header.checksum = frag_header.calculate_checksum(frag_header_data)
                frag_header_data = frag_header.pack()

                fragment_packet_data = frag_header_data + fragment_data

                fragment = RawPacket(
                    data=fragment_packet_data,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    payload=(
                        fragment_data if offset == 0 else None
                    ),  # Payload только в первом фрагменте
                )

                fragments.append(fragment)
                offset += current_fragment_size

            return fragments

        except Exception as e:
            self.logger.error(f"Error fragmenting packet: {e}")
            raise

    def modify_ttl(self, packet: RawPacket, new_ttl: int) -> RawPacket:
        """Изменяет TTL в пакете."""
        try:
            # Парсим IP заголовок
            ip_header = IPHeader.unpack(packet.data[:20])
            ip_header.ttl = new_ttl

            # Пересчитываем контрольную сумму
            ip_header_data = ip_header.pack()
            ip_header.checksum = ip_header.calculate_checksum(ip_header_data)
            new_ip_header_data = ip_header.pack()

            # Создаем новый пакет с измененным TTL
            new_packet_data = new_ip_header_data + packet.data[20:]

            return RawPacket(
                data=new_packet_data,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                payload=packet.payload,
            )

        except Exception as e:
            self.logger.error(f"Error modifying TTL: {e}")
            raise

    async def build_tcp_packet(
        self,
        source_port: int,
        dest_port: int,
        seq_num: int = 0,
        ack_num: int = 0,
        flags: int = 0,
        payload: bytes = b"",
        source_ip: str = "192.168.1.100",
        dest_ip: str = "192.168.1.1",
        ttl: int = 64,
        window_size: int = 65535,
    ) -> "TCPPacket":
        """Создает TCP пакет (async версия для совместимости)."""
        try:
            raw_packet = self.create_tcp_packet(
                source_ip,
                dest_ip,
                source_port,
                dest_port,
                seq_num,
                ack_num,
                flags,
                payload,
                ttl,
                window_size,
            )

            # Импортируем TCPPacket локально
            from .packet_models import TCPPacket

            # Создаем объект TCPPacket для совместимости
            tcp_packet = TCPPacket(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                seq_num=seq_num,
                ack_num=ack_num,
                flags=flags,
                payload=payload,
                raw_data=raw_packet.data,
            )

            return tcp_packet

        except Exception as e:
            self.logger.error(f"Error building TCP packet: {e}")
            raise

    async def parse_packet(self, packet_data: bytes) -> Optional["ParsedPacket"]:
        """Парсит пакет из байтов (async версия)."""
        try:
            raw_packet = self._parse_packet_internal(packet_data)

            # Импортируем ParsedPacket локально чтобы избежать циклических импортов
            from .packet_models import (
                ParsedPacket,
                ProtocolType as ModelProtocolType,
            )

            # Создаем объект ParsedPacket для совместимости
            parsed = ParsedPacket(
                protocol_type=(
                    ModelProtocolType.TCP
                    if raw_packet.protocol == ProtocolType.TCP
                    else ModelProtocolType.IP
                ),
                source_ip=raw_packet.src_ip,
                dest_ip=raw_packet.dst_ip,
                source_port=raw_packet.src_port or 0,
                dest_port=raw_packet.dst_port or 0,
                payload=raw_packet.payload or b"",
                raw_data=raw_packet.data,
            )

            return parsed

        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")
            return None

    def parse_packet_sync(self, data: bytes) -> RawPacket:
        """Синхронная версия parse_packet."""
        # Переименовываем оригинальный метод
        return self._parse_packet_internal(data)

    async def fragment_packet(self, packet_data: bytes, mtu: int = 1500) -> List[bytes]:
        """Фрагментирует пакет (async версия)."""
        try:
            # Создаем временный RawPacket для фрагментации
            temp_packet = RawPacket(
                data=packet_data, src_ip="0.0.0.0", dst_ip="0.0.0.0"
            )

            fragments = self.fragment_packet_sync(temp_packet, mtu)
            return [frag.data for frag in fragments]

        except Exception as e:
            self.logger.error(f"Error fragmenting packet: {e}")
            return [packet_data]

    def fragment_packet_sync(
        self, packet: RawPacket, fragment_size: int
    ) -> List[RawPacket]:
        """Синхронная версия fragment_packet."""
        return self._fragment_packet_internal(packet, fragment_size)

    def is_client_hello(self, payload: bytes) -> bool:
        """
        Проверяет, является ли payload TLS ClientHello.
        
        TLS Record Header:
        - Byte 0: Content Type (0x16 = Handshake)
        - Bytes 1-2: TLS Version
        - Bytes 3-4: Record Length
        
        Handshake Header:
        - Byte 5: Handshake Type (0x01 = ClientHello)
        """
        if not payload or len(payload) < 6:
            return False
        
        # Проверяем TLS Record Type (0x16 = Handshake)
        if payload[0] != 0x16:
            return False
        
        # Проверяем Handshake Type (0x01 = ClientHello)
        if payload[5] != 0x01:
            return False
        
        return True

    def is_server_hello(self, payload: bytes) -> bool:
        """
        Проверяет, является ли payload TLS ServerHello.
        
        Handshake Type для ServerHello: 0x02
        """
        if not payload or len(payload) < 6:
            return False
        
        # Проверяем TLS Record Type (0x16 = Handshake)
        if payload[0] != 0x16:
            return False
        
        # Проверяем Handshake Type (0x02 = ServerHello)
        if payload[5] != 0x02:
            return False
        
        return True

    def extract_tls_sni(self, payload: bytes) -> Optional[str]:
        """
        Извлекает SNI из TLS ClientHello payload.
        
        Algorithm:
        1. Проверить TLS Record Header (offset 0)
        2. Проверить Handshake Type = ClientHello (offset 5)
        3. Пропустить Session ID, Cipher Suites, Compression Methods
        4. Найти Extensions
        5. Итерировать по Extensions, найти SNI (type 0x0000)
        6. Извлечь hostname из SNI extension
        """
        if not self.is_client_hello(payload):
            return None
        
        try:
            # Начинаем после Handshake Type
            offset = 6  # После TLS Record (5 bytes) + Handshake Type (1 byte)
            
            # Пропускаем: Handshake Length (3), TLS Version (2), Random (32)
            offset += 3 + 2 + 32
            
            if offset >= len(payload):
                return None
            
            # Session ID Length
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            
            if offset + 2 > len(payload):
                return None
            
            # Cipher Suites Length
            cipher_suites_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2 + cipher_suites_len
            
            if offset >= len(payload):
                return None
            
            # Compression Methods Length
            compression_len = payload[offset]
            offset += 1 + compression_len
            
            if offset + 2 > len(payload):
                return None
            
            # Extensions Length
            extensions_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            
            # Парсим Extensions
            extensions_end = offset + extensions_len
            while offset + 4 <= extensions_end and offset + 4 <= len(payload):
                ext_type = struct.unpack('!H', payload[offset:offset+2])[0]
                ext_len = struct.unpack('!H', payload[offset+2:offset+4])[0]
                offset += 4
                
                if ext_type == 0x0000:  # SNI Extension
                    # Парсим SNI
                    if offset + 5 <= len(payload):
                        name_list_len = struct.unpack('!H', payload[offset:offset+2])[0]
                        name_type = payload[offset+2]
                        name_len = struct.unpack('!H', payload[offset+3:offset+5])[0]
                        
                        if name_type == 0x00 and offset + 5 + name_len <= len(payload):
                            sni = payload[offset+5:offset+5+name_len].decode('utf-8', errors='ignore')
                            return sni
                
                offset += ext_len
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error extracting SNI: {e}")
            return None

    def get_packet_info(self, packet: RawPacket) -> Dict[str, Any]:
        """Получает информацию о пакете."""
        try:
            info = {
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "protocol": packet.protocol.name if packet.protocol else "Unknown",
                "size": len(packet.data),
            }

            if packet.src_port is not None:
                info["src_port"] = packet.src_port
            if packet.dst_port is not None:
                info["dst_port"] = packet.dst_port
            if packet.payload:
                info["payload_size"] = len(packet.payload)

            # Парсим дополнительную информацию из заголовков
            if len(packet.data) >= 20:
                ip_header = IPHeader.unpack(packet.data[:20])
                info.update(
                    {
                        "ttl": ip_header.ttl,
                        "identification": ip_header.identification,
                        "flags": ip_header.flags,
                        "fragment_offset": ip_header.fragment_offset,
                    }
                )

                # TCP информация
                if packet.protocol == ProtocolType.TCP and len(packet.data) >= 40:
                    tcp_header = TCPHeader.unpack(packet.data[20:])
                    info.update(
                        {
                            "seq_num": tcp_header.seq_num,
                            "ack_num": tcp_header.ack_num,
                            "tcp_flags": tcp_header.flags,
                            "window_size": tcp_header.window_size,
                        }
                    )

            return info

        except Exception as e:
            self.logger.error(f"Error getting packet info: {e}")
            return {"error": str(e)}


def raw_packet_to_packet_info(raw_packet: RawPacket, timestamp: float = 0.0) -> PacketInfo:
    """
    Конвертирует RawPacket в PacketInfo для совместимости с анализаторами.
    
    Args:
        raw_packet: Сырой пакет для конвертации
        timestamp: Временная метка пакета (по умолчанию 0.0)
    
    Returns:
        PacketInfo с детальной информацией о пакете
    """
    # Парсим IP заголовок
    ip_header = IPHeader.unpack(raw_packet.data[:20])
    ip_header_size = ip_header.ihl * 4
    
    # Инициализируем значения по умолчанию
    sequence_num = 0
    ack_num = 0
    tcp_flags_int = 0
    checksum = 0
    
    # Парсим TCP заголовок если это TCP пакет
    if raw_packet.protocol == ProtocolType.TCP and len(raw_packet.data) >= ip_header_size + 20:
        tcp_data = raw_packet.data[ip_header_size:]
        tcp_header = TCPHeader.unpack(tcp_data)
        
        sequence_num = tcp_header.seq_num
        ack_num = tcp_header.ack_num
        tcp_flags_int = tcp_header.flags
        checksum = tcp_header.checksum
    
    # Определяем флаги
    flags = []
    if tcp_flags_int & TCPHeader.FLAG_FIN:
        flags.append('FIN')
    if tcp_flags_int & TCPHeader.FLAG_SYN:
        flags.append('SYN')
    if tcp_flags_int & TCPHeader.FLAG_RST:
        flags.append('RST')
    if tcp_flags_int & TCPHeader.FLAG_PSH:
        flags.append('PSH')
    if tcp_flags_int & TCPHeader.FLAG_ACK:
        flags.append('ACK')
    if tcp_flags_int & TCPHeader.FLAG_URG:
        flags.append('URG')
    if tcp_flags_int & TCPHeader.FLAG_ECE:
        flags.append('ECE')
    if tcp_flags_int & TCPHeader.FLAG_CWR:
        flags.append('CWR')
    
    # Проверяем payload на TLS
    payload = raw_packet.payload or b""
    is_client_hello_flag = False
    tls_info = None
    
    if payload:
        engine = RawPacketEngine()
        is_client_hello_flag = engine.is_client_hello(payload)
        
        if is_client_hello_flag:
            sni = engine.extract_tls_sni(payload)
            tls_version = None
            
            # Извлекаем TLS версию из Record Header
            if len(payload) >= 3:
                version_bytes = struct.unpack('!H', payload[1:3])[0]
                version_map = {
                    0x0301: "TLS 1.0",
                    0x0302: "TLS 1.1",
                    0x0303: "TLS 1.2",
                    0x0304: "TLS 1.3",
                }
                tls_version = version_map.get(version_bytes, f"Unknown (0x{version_bytes:04x})")
            
            tls_info = TLSInfo(
                sni=sni,
                is_client_hello=True,
                is_server_hello=False,
                tls_version=tls_version
            )
        elif engine.is_server_hello(payload):
            tls_info = TLSInfo(
                sni=None,
                is_client_hello=False,
                is_server_hello=True,
                tls_version=None
            )
    
    # Валидация checksum
    checksum_valid = True
    if raw_packet.protocol == ProtocolType.TCP and checksum != 0:
        try:
            tcp_data = raw_packet.data[ip_header_size:]
            tcp_header = TCPHeader.unpack(tcp_data)
            tcp_header_size = tcp_header.data_offset * 4
            tcp_payload = tcp_data[tcp_header_size:] if len(tcp_data) > tcp_header_size else b""
            
            calculated_checksum = tcp_header.calculate_checksum(
                raw_packet.src_ip,
                raw_packet.dst_ip,
                tcp_payload
            )
            checksum_valid = (calculated_checksum == checksum)
        except Exception:
            checksum_valid = False
    
    return PacketInfo(
        timestamp=timestamp,
        src_ip=raw_packet.src_ip,
        dst_ip=raw_packet.dst_ip,
        src_port=raw_packet.src_port or 0,
        dst_port=raw_packet.dst_port or 0,
        sequence_num=sequence_num,
        ack_num=ack_num,
        ttl=ip_header.ttl,
        flags=flags,
        payload_length=len(payload),
        payload_hex=payload.hex() if payload else "",
        checksum=checksum,
        checksum_valid=checksum_valid,
        is_client_hello=is_client_hello_flag,
        tls_info=tls_info
    )


# Утилитарные функции для совместимости
def create_tcp_syn(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq_num: int = 0,
    ttl: int = 64,
) -> RawPacket:
    """Создает TCP SYN пакет (совместимость с существующим кодом)."""
    engine = RawPacketEngine()
    return engine.create_syn_packet(src_ip, dst_ip, src_port, dst_port, seq_num, ttl)


def create_tcp_packet_with_payload(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    seq_num: int = 0,
    ack_num: int = 0,
    ttl: int = 64,
) -> RawPacket:
    """Создает TCP пакет с данными (совместимость с существующим кодом)."""
    engine = RawPacketEngine()
    return engine.create_psh_ack_packet(
        src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, payload, ttl
    )


def fragment_tcp_packet(packet: RawPacket, fragment_size: int) -> List[RawPacket]:
    """Фрагментирует TCP пакет (совместимость с существующим кодом)."""
    engine = RawPacketEngine()
    return engine.fragment_packet(packet, fragment_size)


@dataclass
class TCPPacket:
    """TCP пакет для совместимости с тестами."""

    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    seq_num: int = 0
    ack_num: int = 0
    flags: int = 0
    payload: bytes = b""
    raw_data: bytes = b""

    def to_bytes(self) -> bytes:
        """Конвертирует пакет в байты."""
        return self.raw_data


@dataclass
class ParsedPacket:
    """Распарсенный пакет для совместимости с тестами."""

    protocol: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    payload: bytes = b""
    raw_data: bytes = b""
