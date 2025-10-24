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
