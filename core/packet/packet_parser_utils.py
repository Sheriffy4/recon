"""
Packet Parser Utilities - утилиты для парсинга сетевых пакетов.

Этот модуль предоставляет переиспользуемые функции для парсинга IP и TCP заголовков
из RawPacket объектов, устраняя дублирование кода.
"""

import logging
from typing import List, Tuple, Optional

from core.packet.raw_packet_engine import RawPacket, IPHeader, TCPHeader

LOG = logging.getLogger("PacketParserUtils")


def parse_tcp_packet_headers(packet: RawPacket) -> Optional[Tuple[IPHeader, TCPHeader, int]]:
    """
    Парсинг IP и TCP заголовков из RawPacket.

    Args:
        packet: RawPacket объект для парсинга

    Returns:
        Tuple[IPHeader, TCPHeader, int] - IP заголовок, TCP заголовок, размер IP заголовка
        None если пакет слишком мал или парсинг не удался
    """
    try:
        data = packet.data or b""
        # Минимальный размер: 20 байт IP + 20 байт TCP
        if len(data) < 40:
            return None

        # Парсинг IP заголовка
        ip_header = IPHeader.unpack(data[:20])
        ip_header_size = int(ip_header.ihl) * 4

        # Проверка корректности размера IP заголовка
        if ip_header_size < 20 or ip_header_size > len(data):
            return None
        # Должно хватать хотя бы на минимальный TCP заголовок
        if len(data) - ip_header_size < 20:
            return None

        # Парсинг TCP заголовка
        tcp_header = TCPHeader.unpack(data[ip_header_size:])

        return ip_header, tcp_header, ip_header_size

    except Exception:
        LOG.debug("Ошибка парсинга пакета", exc_info=True)
        return None


def extract_rst_packets(tcp_packets: List[RawPacket]) -> List[RawPacket]:
    """
    Извлечение RST пакетов из списка TCP пакетов.

    Args:
        tcp_packets: Список TCP пакетов (RawPacket)

    Returns:
        List[RawPacket] - список пакетов с установленным флагом RST
    """
    rst_packets = []

    for packet in tcp_packets:
        headers = parse_tcp_packet_headers(packet)
        if headers is None:
            continue

        _, tcp_header, _ = headers

        # Проверка флага RST
        if tcp_header.flags & TCPHeader.FLAG_RST:
            rst_packets.append(packet)

    return rst_packets


def has_tcp_flag(packet: RawPacket, flag: int) -> bool:
    """
    Проверка наличия TCP флага в пакете.

    Args:
        packet: RawPacket объект
        flag: TCP флаг для проверки (например, TCPHeader.FLAG_RST)

    Returns:
        bool - True если флаг установлен
    """
    headers = parse_tcp_packet_headers(packet)
    if headers is None:
        return False

    _, tcp_header, _ = headers
    return bool(tcp_header.flags & flag)


def get_tcp_flags(packet: RawPacket) -> Optional[int]:
    """
    Получение TCP флагов из пакета.

    Args:
        packet: RawPacket объект

    Returns:
        int - значение TCP флагов или None если парсинг не удался
    """
    headers = parse_tcp_packet_headers(packet)
    if headers is None:
        return None

    _, tcp_header, _ = headers
    return tcp_header.flags


def get_tcp_sequence_numbers(packet: RawPacket) -> Optional[Tuple[int, int]]:
    """
    Получение sequence и acknowledgment номеров из TCP пакета.

    Args:
        packet: RawPacket объект

    Returns:
        Tuple[int, int] - (seq_num, ack_num) или None если парсинг не удался
    """
    headers = parse_tcp_packet_headers(packet)
    if headers is None:
        return None

    _, tcp_header, _ = headers
    return tcp_header.seq_num, tcp_header.ack_num


def get_ip_ttl(packet: RawPacket) -> Optional[int]:
    """
    Получение TTL значения из IP заголовка.

    Args:
        packet: RawPacket объект

    Returns:
        int - TTL значение или None если парсинг не удался
    """
    headers = parse_tcp_packet_headers(packet)
    if headers is None:
        return None

    ip_header, _, _ = headers
    return ip_header.ttl
