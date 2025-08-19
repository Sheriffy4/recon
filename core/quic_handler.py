"""
Модуль для обработки QUIC-пакетов в системе обхода DPI.
"""

import logging
from typing import Optional, Tuple, List
import struct

class QuicHandler:
    """
    Обработчик QUIC-пакетов для системы обхода DPI.
    Поддерживает различные версии QUIC и форматы Initial пакетов.
    """

    def __init__(self, debug=False):
        self.logger = logging.getLogger("QuicHandler")
        if debug:
            self.logger.setLevel(logging.DEBUG)
            if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s')

    def is_quic_initial(self, payload: bytes) -> bool:
        """
        Проверяет, является ли UDP пакет QUIC Initial пакетом.
        
        Args:
            payload (bytes): Содержимое UDP пакета
        
        Returns:
            bool: True если это QUIC Initial пакет, иначе False
        """
        try:
            # QUIC пакеты начинаются с Header Form бита (1 для long header)
            if not payload or len(payload) < 5:
                return False
            
            # Проверяем Header Form bit (должен быть 1 для Initial)
            header_form = (payload[0] & 0x80) >> 7
            if header_form != 1:
                return False
                
            # Проверяем Fixed Bit (должен быть 1)
            fixed_bit = (payload[0] & 0x40) >> 6
            if fixed_bit != 1:
                return False
                
            # Проверяем Long Packet Type (0x00 для Initial)
            packet_type = (payload[0] & 0x30) >> 4
            return packet_type == 0
            
        except Exception as e:
            self.logger.debug(f"Ошибка при проверке QUIC пакета: {e}")
            return False

    def split_quic_initial(self, payload: bytes, positions: List[int]) -> List[Tuple[bytes, int]]:
        """
        Разделяет QUIC Initial пакет на несколько частей для обхода DPI.
        
        Args:
            payload (bytes): Исходный QUIC пакет
            positions (List[int]): Позиции для разделения
            
        Returns:
            List[Tuple[bytes, int]]: Список кортежей (фрагмент, смещение)
        """
        if not positions:
            return [(payload, 0)]
            
        try:
            # Находим начало Protected Payload
            header_len = self._get_header_length(payload)
            if not header_len:
                return [(payload, 0)]
                
            # Разделяем Protected Payload по указанным позициям
            segments = []
            last_pos = header_len
            
            # Сохраняем заголовок
            segments.append((payload[:header_len], 0))
            
            # Разделяем зашифрованную часть
            for pos in sorted(positions):
                if pos > last_pos and pos < len(payload):
                    segments.append((payload[last_pos:pos], last_pos))
                    last_pos = pos
                    
            if last_pos < len(payload):
                segments.append((payload[last_pos:], last_pos))
                
            return segments
            
        except Exception as e:
            self.logger.error(f"Ошибка при разделении QUIC пакета: {e}")
            return [(payload, 0)]

    def _get_header_length(self, payload: bytes) -> Optional[int]:
        """
        Определяет длину заголовка QUIC Initial пакета.
        
        Args:
            payload (bytes): Содержимое QUIC пакета
            
        Returns:
            Optional[int]: Длина заголовка или None в случае ошибки
        """
        try:
            if len(payload) < 5:
                return None
                
            # Пропускаем первый байт (flags)
            pos = 1
            
            # Пропускаем Version (4 bytes)
            pos += 4
            
            # Destination Connection ID Length
            if pos >= len(payload):
                return None
            dcid_len = payload[pos]
            pos += 1 + dcid_len
            
            # Source Connection ID Length
            if pos >= len(payload):
                return None
            scid_len = payload[pos]
            pos += 1 + scid_len
            
            # Token Length (variable-length integer)
            if pos >= len(payload):
                return None
            token_len, bytes_read = self._decode_varint(payload[pos:])
            pos += bytes_read + token_len
            
            # Length of the rest of the packet (variable-length integer)
            if pos >= len(payload):
                return None
            _, bytes_read = self._decode_varint(payload[pos:])
            pos += bytes_read
            
            return pos
            
        except Exception as e:
            self.logger.debug(f"Ошибка при определении длины заголовка: {e}")
            return None

    def _decode_varint(self, data: bytes) -> Tuple[int, int]:
        """
        Декодирует QUIC variable-length integer.
        
        Args:
            data (bytes): Байты для декодирования
            
        Returns:
            Tuple[int, int]: (значение, количество прочитанных байт)
        """
        if not data:
            raise ValueError("Empty data for varint")
            
        first_byte = data[0]
        prefix = first_byte >> 6
        length = 1 << prefix
        
        if len(data) < length:
            raise ValueError("Incomplete varint")
            
        value = first_byte & 0x3F
        for i in range(1, length):
            value = (value << 8) + data[i]
            
        return value, length
