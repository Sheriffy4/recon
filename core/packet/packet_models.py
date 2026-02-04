"""
Модели данных для побайтовой обработки пакетов.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import struct


class ProtocolType(Enum):
    """Типы протоколов."""

    IP = 4
    IPv6 = 6
    TCP = 6
    UDP = 17
    ICMP = 1
    TLS = 443
    HTTP = 80
    QUIC = 443


class PacketDirection(Enum):
    """Направление пакета."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


@dataclass
class IPHeader:
    """IP заголовок."""

    version: int = 4
    header_length: int = 20
    type_of_service: int = 0
    total_length: int = 0
    identification: int = 0
    flags: int = 0
    fragment_offset: int = 0
    ttl: int = 64
    protocol: int = 6
    checksum: int = 0
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    options: bytes = b""

    def to_bytes(self) -> bytes:
        """Конвертирует IP заголовок в байты."""
        # Версия и длина заголовка
        version_ihl = (self.version << 4) | (self.header_length // 4)

        # Флаги и смещение фрагмента
        flags_fragment = (self.flags << 13) | self.fragment_offset

        # Конвертируем IP адреса
        src_ip_bytes = struct.pack("!I", self._ip_to_int(self.source_ip))
        dst_ip_bytes = struct.pack("!I", self._ip_to_int(self.destination_ip))

        # Собираем заголовок
        header = struct.pack(
            "!BBHHHBBH",
            version_ihl,
            self.type_of_service,
            self.total_length,
            self.identification,
            flags_fragment,
            self.ttl,
            self.protocol,
            self.checksum,
        )

        return header + src_ip_bytes + dst_ip_bytes + self.options

    @classmethod
    def from_bytes(cls, data: bytes) -> "IPHeader":
        """Создает IP заголовок из байтов."""
        if len(data) < 20:
            raise ValueError("IP header too short")

        # Распаковываем основную часть заголовка
        (
            version_ihl,
            tos,
            total_len,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum,
        ) = struct.unpack("!BBHHHBBH", data[:12])

        version = version_ihl >> 4
        header_length = (version_ihl & 0xF) * 4
        flags = flags_fragment >> 13
        fragment_offset = flags_fragment & 0x1FFF

        # IP адреса
        src_ip = cls._int_to_ip(struct.unpack("!I", data[12:16])[0])
        dst_ip = cls._int_to_ip(struct.unpack("!I", data[16:20])[0])

        # Опции (если есть)
        options = data[20:header_length] if header_length > 20 else b""

        return cls(
            version=version,
            header_length=header_length,
            type_of_service=tos,
            total_length=total_len,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            source_ip=src_ip,
            destination_ip=dst_ip,
            options=options,
        )

    @staticmethod
    def _ip_to_int(ip_str: str) -> int:
        """Конвертирует IP строку в int."""
        parts = ip_str.split(".")
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

    @staticmethod
    def _int_to_ip(ip_int: int) -> str:
        """Конвертирует int в IP строку."""
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


@dataclass
class TCPHeader:
    """TCP заголовок."""

    source_port: int = 0
    destination_port: int = 0
    sequence_number: int = 0
    acknowledgment_number: int = 0
    header_length: int = 20
    flags: int = 0
    window_size: int = 65535
    checksum: int = 0
    urgent_pointer: int = 0
    options: bytes = b""

    # TCP флаги
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def to_bytes(self) -> bytes:
        """Конвертирует TCP заголовок в байты."""
        # Длина заголовка и флаги
        header_len_flags = ((self.header_length // 4) << 12) | self.flags

        # Собираем заголовок
        header = struct.pack(
            "!HHLLHHHH",
            self.source_port,
            self.destination_port,
            self.sequence_number,
            self.acknowledgment_number,
            header_len_flags,
            self.window_size,
            self.checksum,
            self.urgent_pointer,
        )

        return header + self.options

    @classmethod
    def from_bytes(cls, data: bytes) -> "TCPHeader":
        """Создает TCP заголовок из байтов."""
        if len(data) < 20:
            raise ValueError("TCP header too short")

        # Распаковываем заголовок
        src_port, dst_port, seq, ack, header_len_flags, window, checksum, urgent = struct.unpack(
            "!HHLLHHHH", data[:20]
        )

        header_length = (header_len_flags >> 12) * 4
        flags = header_len_flags & 0xFFF

        # Опции (если есть)
        options = data[20:header_length] if header_length > 20 else b""

        return cls(
            source_port=src_port,
            destination_port=dst_port,
            sequence_number=seq,
            acknowledgment_number=ack,
            header_length=header_length,
            flags=flags,
            window_size=window,
            checksum=checksum,
            urgent_pointer=urgent,
            options=options,
        )

    def has_flag(self, flag: int) -> bool:
        """Проверяет наличие флага."""
        return bool(self.flags & flag)

    def set_flag(self, flag: int) -> None:
        """Устанавливает флаг."""
        self.flags |= flag

    def clear_flag(self, flag: int) -> None:
        """Очищает флаг."""
        self.flags &= ~flag


@dataclass
class UDPHeader:
    """UDP заголовок."""

    source_port: int = 0
    destination_port: int = 0
    length: int = 8
    checksum: int = 0

    def to_bytes(self) -> bytes:
        """Конвертирует UDP заголовок в байты."""
        return struct.pack(
            "!HHHH", self.source_port, self.destination_port, self.length, self.checksum
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "UDPHeader":
        """Создает UDP заголовок из байтов."""
        if len(data) < 8:
            raise ValueError("UDP header too short")

        src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])

        return cls(
            source_port=src_port,
            destination_port=dst_port,
            length=length,
            checksum=checksum,
        )


@dataclass
class RawPacket:
    """Представление сырого пакета."""

    raw_data: bytes
    ip_header: Optional[IPHeader] = None
    tcp_header: Optional[TCPHeader] = None
    udp_header: Optional[UDPHeader] = None
    payload: bytes = b""
    direction: PacketDirection = PacketDirection.OUTBOUND
    interface: Optional[str] = None
    timestamp: Optional[float] = None

    @property
    def protocol(self) -> int:
        """Возвращает протокол пакета."""
        if self.ip_header:
            return self.ip_header.protocol
        return 0

    @property
    def source_ip(self) -> str:
        """Возвращает IP источника."""
        if self.ip_header:
            return self.ip_header.source_ip
        return "0.0.0.0"

    @property
    def destination_ip(self) -> str:
        """Возвращает IP назначения."""
        if self.ip_header:
            return self.ip_header.destination_ip
        return "0.0.0.0"

    @property
    def source_port(self) -> int:
        """Возвращает порт источника."""
        if self.tcp_header:
            return self.tcp_header.source_port
        elif self.udp_header:
            return self.udp_header.source_port
        return 0

    @property
    def destination_port(self) -> int:
        """Возвращает порт назначения."""
        if self.tcp_header:
            return self.tcp_header.destination_port
        elif self.udp_header:
            return self.udp_header.destination_port
        return 0

    @property
    def is_tcp(self) -> bool:
        """Проверяет, является ли пакет TCP."""
        return self.protocol == 6

    @property
    def is_udp(self) -> bool:
        """Проверяет, является ли пакет UDP."""
        return self.protocol == 17

    @property
    def is_tls(self) -> bool:
        """Проверяет, является ли пакет TLS."""
        return (
            self.is_tcp
            and self.destination_port == 443
            and len(self.payload) > 6
            and self.payload[0] == 0x16
        )

    @property
    def is_http(self) -> bool:
        """Проверяет, является ли пакет HTTP."""
        return (
            self.is_tcp
            and self.destination_port == 80
            and self.payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD "))
        )

    @property
    def is_quic(self) -> bool:
        """Проверяет, является ли пакет QUIC."""
        return (
            self.is_udp
            and self.destination_port == 443
            and len(self.payload) > 1
            and (self.payload[0] & 0x80) != 0
        )

    def get_header_length(self) -> int:
        """Возвращает общую длину заголовков."""
        length = 0
        if self.ip_header:
            length += self.ip_header.header_length
        if self.tcp_header:
            length += self.tcp_header.header_length
        elif self.udp_header:
            length += 8  # UDP header is always 8 bytes
        return length

    def rebuild(self) -> bytes:
        """Пересобирает пакет из компонентов."""
        packet_data = b""

        if self.ip_header:
            packet_data += self.ip_header.to_bytes()

        if self.tcp_header:
            packet_data += self.tcp_header.to_bytes()
        elif self.udp_header:
            packet_data += self.udp_header.to_bytes()

        packet_data += self.payload

        # Обновляем длину в IP заголовке
        if self.ip_header:
            self.ip_header.total_length = len(packet_data)
            # Пересобираем с правильной длиной
            packet_data = self.ip_header.to_bytes()
            if self.tcp_header:
                packet_data += self.tcp_header.to_bytes()
            elif self.udp_header:
                packet_data += self.udp_header.to_bytes()
            packet_data += self.payload

        return packet_data


@dataclass
class PacketFragment:
    """Фрагмент пакета для техник обхода."""

    data: bytes
    sequence_offset: int = 0
    delay_ms: float = 0.0
    ttl_override: Optional[int] = None
    flags_override: Optional[int] = None
    window_size_override: Optional[int] = None

    def apply_to_packet(self, base_packet: RawPacket) -> RawPacket:
        """Применяет фрагмент к базовому пакету."""
        new_packet = RawPacket(
            raw_data=base_packet.raw_data,
            ip_header=base_packet.ip_header,
            tcp_header=base_packet.tcp_header,
            udp_header=base_packet.udp_header,
            payload=self.data,
            direction=base_packet.direction,
            interface=base_packet.interface,
            timestamp=base_packet.timestamp,
        )

        # Применяем переопределения
        if self.ttl_override is not None and new_packet.ip_header:
            new_packet.ip_header.ttl = self.ttl_override

        if self.flags_override is not None and new_packet.tcp_header:
            new_packet.tcp_header.flags = self.flags_override

        if self.window_size_override is not None and new_packet.tcp_header:
            new_packet.tcp_header.window_size = self.window_size_override

        # Обновляем sequence number
        if new_packet.tcp_header:
            new_packet.tcp_header.sequence_number += self.sequence_offset

        return new_packet


@dataclass
class BypassTechnique:
    """Техника обхода DPI."""

    name: str
    description: str
    fragments: List[PacketFragment] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def apply(self, packet: RawPacket) -> List[RawPacket]:
        """Применяет технику к пакету."""
        result_packets = []

        for fragment in self.fragments:
            new_packet = fragment.apply_to_packet(packet)
            result_packets.append(new_packet)

        return result_packets


@dataclass
class LayerInfo:
    """Информация о слое пакета."""

    protocol_type: ProtocolType
    data: bytes
    fields: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Пост-инициализация для валидации."""
        if not isinstance(self.data, bytes):
            self.data = bytes(self.data) if self.data else b""


@dataclass
class ParsedPacket:
    """Распарсенный пакет для совместимости."""

    protocol_type: ProtocolType
    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    source_port: int = 0
    dest_port: int = 0
    payload: bytes = b""
    raw_data: bytes = b""
    layers: List[LayerInfo] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Конвертирует в байты."""
        if self.raw_data:
            return self.raw_data

        # Простая сериализация для тестов
        result = b""
        for layer in self.layers:
            result += layer.data
        return result + self.payload


@dataclass
class TCPPacket:
    """TCP пакет для совместимости."""

    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    source_port: int = 0
    dest_port: int = 0
    seq_num: int = 0
    ack_num: int = 0
    flags: int = 0
    payload: bytes = b""
    raw_data: bytes = b""

    def to_bytes(self) -> bytes:
        """Конвертирует в байты."""
        return self.raw_data if self.raw_data else b""


@dataclass
class PacketStatistics:
    """Статистика обработки пакетов."""

    packets_processed: int = 0
    packets_modified: int = 0
    bytes_processed: int = 0
    techniques_applied: int = 0
    errors_count: int = 0
    processing_time_ms: float = 0.0

    def add_packet(
        self, packet_size: int, modified: bool = False, technique_applied: bool = False
    ) -> None:
        """Добавляет статистику по пакету."""
        self.packets_processed += 1
        self.bytes_processed += packet_size

        if modified:
            self.packets_modified += 1

        if technique_applied:
            self.techniques_applied += 1

    def add_error(self) -> None:
        """Добавляет ошибку в статистику."""
        self.errors_count += 1

    def get_success_rate(self) -> float:
        """Возвращает процент успешной обработки."""
        if self.packets_processed == 0:
            return 0.0
        return (self.packets_processed - self.errors_count) / self.packets_processed * 100.0
