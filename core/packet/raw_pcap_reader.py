"""
Raw PCAP Reader - чтение PCAP файлов без зависимости от Scapy.
Использует RawPacketEngine для побайтовой обработки пакетов.
"""

import struct
import logging
from pathlib import Path
from typing import List, Optional, Iterator
from dataclasses import dataclass

from .raw_packet_engine import RawPacketEngine, RawPacket


@dataclass
class PCAPHeader:
    """PCAP global header."""
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int
    byte_order: str  # 'little' or 'big'


@dataclass
class PCAPPacketHeader:
    """PCAP packet header."""
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


class CorruptedPacketError(Exception):
    """Исключение для поврежденных пакетов."""
    pass


class RawPCAPReader:
    """Читает PCAP файлы без использования Scapy."""
    
    # PCAP magic numbers
    PCAP_MAGIC_LE = 0xA1B2C3D4  # Little endian
    PCAP_MAGIC_BE = 0xD4C3B2A1  # Big endian
    PCAP_MAGIC_NS_LE = 0xA1B23C4D  # Nanosecond resolution, little endian
    PCAP_MAGIC_NS_BE = 0x4D3CB2A1  # Nanosecond resolution, big endian
    PCAPNG_MAGIC = 0x0A0D0D0A  # PCAPNG format
    
    # Limits for safety
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
    MAX_PACKET_SIZE = 65535  # Maximum IP packet size
    MAX_PACKETS_IN_MEMORY = 10000  # Use streaming for larger files
    
    def __init__(self, engine: Optional[RawPacketEngine] = None):
        """
        Инициализация RawPCAPReader.
        
        Args:
            engine: Опциональный RawPacketEngine для парсинга пакетов
        """
        self.engine = engine or RawPacketEngine()
        self.logger = logging.getLogger(__name__)
        self.logger.info("ℹ️ Используется RawPCAPReader для анализа PCAP")
    
    def detect_pcap_format(self, filepath: str) -> str:
        """
        Определяет формат PCAP файла.
        
        Args:
            filepath: Путь к PCAP файлу
            
        Returns:
            Формат файла: 'pcap', 'pcap_ns', 'pcapng', или 'unknown'
        """
        try:
            with open(filepath, 'rb') as f:
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    return 'unknown'
                
                magic = struct.unpack('I', magic_bytes)[0]
                
                if magic == self.PCAP_MAGIC_LE or magic == self.PCAP_MAGIC_BE:
                    format_type = 'pcap'
                elif magic == self.PCAP_MAGIC_NS_LE or magic == self.PCAP_MAGIC_NS_BE:
                    format_type = 'pcap_ns'
                elif magic == self.PCAPNG_MAGIC:
                    format_type = 'pcapng'
                else:
                    format_type = 'unknown'
                
                self.logger.debug(f"🔍 Обнаружен формат PCAP: {format_type}")
                return format_type
                
        except Exception as e:
            self.logger.error(f"❌ Ошибка определения формата PCAP: {e}")
            return 'unknown'
    
    def parse_pcap_header(self, file_handle) -> PCAPHeader:
        """
        Парсит PCAP global header.
        
        Args:
            file_handle: Открытый файловый дескриптор
            
        Returns:
            PCAPHeader с информацией о файле
            
        Raises:
            ValueError: Если заголовок невалиден
        """
        header_data = file_handle.read(24)
        if len(header_data) < 24:
            raise ValueError("PCAP header too short")
        
        # Читаем magic number для определения byte order
        magic = struct.unpack('I', header_data[:4])[0]
        
        if magic == self.PCAP_MAGIC_LE or magic == self.PCAP_MAGIC_NS_LE:
            byte_order = 'little'
            endian = '<'
        elif magic == self.PCAP_MAGIC_BE or magic == self.PCAP_MAGIC_NS_BE:
            byte_order = 'big'
            endian = '>'
        else:
            raise ValueError(f"Invalid PCAP magic number: 0x{magic:08X}")
        
        # Парсим остальные поля заголовка
        format_str = f'{endian}IHHIIII'
        unpacked = struct.unpack(format_str, header_data)
        
        return PCAPHeader(
            magic_number=unpacked[0],
            version_major=unpacked[1],
            version_minor=unpacked[2],
            thiszone=unpacked[3],
            sigfigs=unpacked[4],
            snaplen=unpacked[5],
            network=unpacked[6],
            byte_order=byte_order
        )

    def _read_next_packet(self, file_handle, header: PCAPHeader) -> Optional[RawPacket]:
        """
        Читает следующий пакет из PCAP файла.
        
        Args:
            file_handle: Открытый файловый дескриптор
            header: PCAP global header
            
        Returns:
            RawPacket или None если достигнут конец файла
            
        Raises:
            CorruptedPacketError: Если пакет поврежден
        """
        endian = '<' if header.byte_order == 'little' else '>'
        
        # Читаем packet header (16 bytes)
        packet_header_data = file_handle.read(16)
        if len(packet_header_data) == 0:
            return None  # EOF
        
        if len(packet_header_data) < 16:
            raise CorruptedPacketError("Incomplete packet header")
        
        # Парсим packet header
        format_str = f'{endian}IIII'
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(format_str, packet_header_data)
        
        # Валидация размера пакета
        if incl_len > self.MAX_PACKET_SIZE:
            raise CorruptedPacketError(f"Packet size too large: {incl_len}")
        
        if incl_len > header.snaplen:
            raise CorruptedPacketError(f"Packet size exceeds snaplen: {incl_len} > {header.snaplen}")
        
        # Читаем данные пакета
        packet_data = file_handle.read(incl_len)
        if len(packet_data) < incl_len:
            raise CorruptedPacketError(f"Incomplete packet data: expected {incl_len}, got {len(packet_data)}")
        
        # Calculate Unix timestamp from PCAP timestamp
        packet_timestamp = float(ts_sec) + (float(ts_usec) / 1000000.0)
        
        # Парсим пакет используя RawPacketEngine
        try:
            # ИСПРАВЛЕНИЕ: Пропускаем Ethernet заголовок (14 байт) если он есть
            # PCAP файлы обычно содержат Ethernet frames (DLT_EN10MB = 1)
            # Ethernet: Dst MAC (6) + Src MAC (6) + EtherType (2) = 14 bytes
            
            # Проверяем, есть ли Ethernet заголовок
            if len(packet_data) >= 14:
                # Проверяем EtherType (offset 12-13)
                eth_type = (packet_data[12] << 8) | packet_data[13]
                
                # 0x0800 = IPv4, 0x86DD = IPv6
                if eth_type == 0x0800 or eth_type == 0x86DD:
                    # Пропускаем Ethernet заголовок, передаем только IP пакет
                    ip_packet_data = packet_data[14:]
                    raw_packet = self.engine.parse_packet_sync(ip_packet_data)
                    if raw_packet:
                        raw_packet.timestamp = packet_timestamp
                    return raw_packet
            
            # Если не удалось определить Ethernet, пробуем парсить как есть
            raw_packet = self.engine.parse_packet_sync(packet_data)
            if raw_packet:
                raw_packet.timestamp = packet_timestamp
            return raw_packet
        except Exception as e:
            raise CorruptedPacketError(f"Failed to parse packet: {e}")
    
    def read_pcap_file(self, filepath: str) -> List[RawPacket]:
        """
        Читает весь PCAP файл и возвращает список пакетов.
        
        Args:
            filepath: Путь к PCAP файлу
            
        Returns:
            Список RawPacket объектов
        """
        try:
            # Проверяем существование файла
            if not Path(filepath).exists():
                self.logger.warning(f"⚠️ PCAP файл не найден: {filepath}")
                return []
            
            # Проверяем размер файла
            file_size = Path(filepath).stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                self.logger.warning(f"⚠️ PCAP файл слишком большой ({file_size} bytes), используется потоковая обработка")
                return list(self.iterate_packets(filepath))
            
            # Проверяем формат
            pcap_format = self.detect_pcap_format(filepath)
            if pcap_format == 'pcapng':
                self.logger.warning("⚠️ PCAPNG формат пока не полностью поддерживается, используется базовый парсинг")
                # Для PCAPNG используем упрощенный подход
                return self._read_pcapng_file(filepath)
            elif pcap_format == 'unknown':
                self.logger.error(f"❌ Неподдерживаемый формат PCAP: {pcap_format}")
                return []
            
            # Читаем PCAP файл
            with open(filepath, 'rb') as f:
                header = self.parse_pcap_header(f)
                packets = []
                packet_count = 0
                skipped_count = 0
                
                while True:
                    try:
                        packet = self._read_next_packet(f, header)
                        if packet is None:
                            break
                        packets.append(packet)
                        packet_count += 1
                        
                        # Проверка лимита пакетов в памяти
                        if packet_count >= self.MAX_PACKETS_IN_MEMORY:
                            self.logger.info(f"ℹ️ Достигнут лимит пакетов в памяти ({self.MAX_PACKETS_IN_MEMORY}), используется потоковая обработка")
                            # Дочитываем остальные пакеты через streaming
                            for remaining_packet in self.iterate_packets(filepath):
                                packets.append(remaining_packet)
                            break
                            
                    except CorruptedPacketError as e:
                        skipped_count += 1
                        self.logger.warning(f"⚠️ Пропущен поврежденный пакет #{packet_count + skipped_count}: {e}")
                        continue
                    except EOFError:
                        break
                
                self.logger.info(f"📦 Загружено {packet_count} пакетов из {filepath}")
                if skipped_count > 0:
                    self.logger.warning(f"⚠️ Пропущено {skipped_count} поврежденных пакетов")
                
                return packets
                
        except Exception as e:
            self.logger.error(f"❌ Ошибка чтения PCAP: {e}", exc_info=True)
            return []
    
    def _read_pcapng_file(self, filepath: str) -> List[RawPacket]:
        """
        Упрощенное чтение PCAPNG файлов.
        
        Args:
            filepath: Путь к PCAPNG файлу
            
        Returns:
            Список RawPacket объектов
        """
        # PCAPNG имеет более сложную структуру с блоками
        # Для базовой поддержки пытаемся найти Enhanced Packet Blocks
        self.logger.warning("⚠️ PCAPNG поддержка ограничена, некоторые пакеты могут быть пропущены")
        packets = []
        
        try:
            with open(filepath, 'rb') as f:
                # Пропускаем Section Header Block (минимум 28 bytes)
                f.read(28)
                
                # Пытаемся читать блоки
                while True:
                    block_type_data = f.read(4)
                    if len(block_type_data) < 4:
                        break
                    
                    block_type = struct.unpack('<I', block_type_data)[0]
                    block_len_data = f.read(4)
                    if len(block_len_data) < 4:
                        break
                    
                    block_len = struct.unpack('<I', block_len_data)[0]
                    
                    # Enhanced Packet Block (type 6)
                    if block_type == 6:
                        # Читаем данные блока
                        block_data = f.read(block_len - 12)  # -12 для type, len, и trailing len
                        if len(block_data) < block_len - 12:
                            break
                        
                        # Пропускаем trailing block length
                        f.read(4)
                        
                        # Извлекаем packet data из блока (упрощенно)
                        # Enhanced Packet Block: interface_id(4) + timestamp(8) + captured_len(4) + packet_len(4) + data
                        if len(block_data) >= 20:
                            captured_len = struct.unpack('<I', block_data[16:20])[0]
                            packet_data = block_data[20:20+captured_len]
                            
                            try:
                                # ИСПРАВЛЕНИЕ: Пропускаем Ethernet заголовок для PCAPNG
                                if len(packet_data) >= 14:
                                    eth_type = (packet_data[12] << 8) | packet_data[13]
                                    if eth_type == 0x0800 or eth_type == 0x86DD:
                                        packet_data = packet_data[14:]
                                
                                packet = self.engine.parse_packet_sync(packet_data)
                                packets.append(packet)
                            except Exception:
                                continue
                    else:
                        # Пропускаем другие типы блоков
                        f.read(block_len - 8)
                
        except Exception as e:
            self.logger.error(f"❌ Ошибка чтения PCAPNG: {e}")
        
        self.logger.info(f"📦 Загружено {len(packets)} пакетов из PCAPNG файла")
        return packets

    def iterate_packets(self, filepath: str) -> Iterator[RawPacket]:
        """
        Потоковая итерация по пакетам (для больших файлов).
        Использует генератор для минимизации использования памяти.
        
        Args:
            filepath: Путь к PCAP файлу
            
        Yields:
            RawPacket объекты по одному
        """
        try:
            # Проверяем существование файла
            if not Path(filepath).exists():
                self.logger.warning(f"⚠️ PCAP файл не найден: {filepath}")
                return
            
            # Проверяем формат
            pcap_format = self.detect_pcap_format(filepath)
            if pcap_format == 'pcapng':
                self.logger.warning("⚠️ PCAPNG формат не поддерживается для потоковой обработки")
                # Fallback на обычное чтение
                for packet in self._read_pcapng_file(filepath):
                    yield packet
                return
            elif pcap_format == 'unknown':
                self.logger.error(f"❌ Неподдерживаемый формат PCAP: {pcap_format}")
                return
            
            # Проверяем размер файла
            file_size = Path(filepath).stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                self.logger.info(f"ℹ️ Большой PCAP файл ({file_size} bytes), используется потоковая обработка")
            
            # Потоковое чтение PCAP файла
            with open(filepath, 'rb') as f:
                header = self.parse_pcap_header(f)
                packet_count = 0
                skipped_count = 0
                
                while True:
                    try:
                        packet = self._read_next_packet(f, header)
                        if packet is None:
                            break
                        
                        yield packet
                        packet_count += 1
                        
                    except CorruptedPacketError as e:
                        skipped_count += 1
                        self.logger.debug(f"⚠️ Пропущен поврежденный пакет #{packet_count + skipped_count}: {e}")
                        continue
                    except EOFError:
                        break
                
                self.logger.debug(f"✅ Обработано {packet_count} пакетов (пропущено {skipped_count})")
                
        except Exception as e:
            self.logger.error(f"❌ Ошибка потоковой обработки PCAP: {e}", exc_info=True)
            return
    
    def extract_packet_info(self, raw_packet: RawPacket) -> dict:
        """
        Извлекает информацию из пакета (wrapper для RawPacketEngine).
        
        Args:
            raw_packet: RawPacket объект
            
        Returns:
            Словарь с информацией о пакете
        """
        return self.engine.get_packet_info(raw_packet)



# Утилитарные функции для совместимости с существующим кодом

def read_pcap(filepath: str) -> List[RawPacket]:
    """
    Читает PCAP файл и возвращает список пакетов.
    Утилитарная функция для совместимости.
    
    Args:
        filepath: Путь к PCAP файлу
        
    Returns:
        Список RawPacket объектов
    """
    reader = RawPCAPReader()
    return reader.read_pcap_file(filepath)


def iterate_pcap(filepath: str) -> Iterator[RawPacket]:
    """
    Потоковая итерация по пакетам PCAP файла.
    Утилитарная функция для совместимости.
    
    Args:
        filepath: Путь к PCAP файлу
        
    Yields:
        RawPacket объекты
    """
    reader = RawPCAPReader()
    yield from reader.iterate_packets(filepath)
