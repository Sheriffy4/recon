"""
Модуль для обработки QUIC-пакетов в системе обхода DPI.
"""

import logging
from typing import Optional, Tuple, List


class QuicHandler:
    """
    Обработчик QUIC-пакетов для системы обхода DPI.
    Поддерживает различные версии QUIC и форматы Initial пакетов.
    """

    def __init__(self, debug=False):
        self.logger = logging.getLogger("QuicHandler")
        if debug:
            self.logger.setLevel(logging.DEBUG)
            if not any(
                isinstance(h, logging.StreamHandler) for h in self.logger.handlers
            ):
                logging.basicConfig(
                    level=logging.DEBUG,
                    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                )

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

    def split_quic_initial(
        self, payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        """
        Разделяет QUIC Initial пакет на несколько частей.
        Попытка «осмысленной» сегментации по границам фреймов (CRYPTO/STREAM/PADDING),
        если распознаются (актуально для синтетических пакетов наших атак).

        Args:
            payload (bytes): Исходный QUIC пакет
            positions (List[int]): Позиции для разделения

        Returns:
            List[Tuple[bytes, int]]: Список кортежей (фрагмент, смещение)
        """
        try:
            header_len = self._get_header_length(payload)
            if not header_len:
                return [(payload, 0)]
            # Попробуем найти границы фреймов (актуально для синтетики: фреймы незашифрованы)
            frames = self._scan_frames(payload, header_len)
            if frames:
                segs: List[Tuple[bytes, int]] = []
                # заголовок отдельным сегментом
                segs.append((payload[:header_len], 0))
                for (start, end, _ftype) in frames:
                    segs.append((payload[start:end], start))
                return segs
            # Иначе — fallback к старой логике с positions
            if not positions:
                return [(payload, 0)]
            segments = []
            last_pos = header_len
            segments.append((payload[:header_len], 0))
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
            token_len, tl = self._decode_varint(payload[pos:])
            pos += tl + token_len

            # Length of the rest of the packet (variable-length integer)
            if pos >= len(payload):
                return None
            _, ll = self._decode_varint(payload[pos:])
            pos += ll

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

    def _scan_frames(self, payload: bytes, start: int) -> List[Tuple[int, int, str]]:
        """
        Простая эвристика: пытаемся распознать фреймы CRYPTO(0x06)/PADDING(0x00)/STREAM(0x08..0x0F)
        для синтетических Initial (настоящие Initial зашифрованы и здесь не распознаются).
        Возвращает список (start, end, type_name) границ фреймов внутри payload.
        """
        frames = []
        pos = start
        n = len(payload)
        try:
            while pos < n:
                ftype = payload[pos]
                # PADDING (0x00): может тянуться подряд
                if ftype == 0x00:
                    end = pos + 1
                    while end < n and payload[end] == 0x00:
                        end += 1
                    frames.append((pos, end, "PADDING"))
                    pos = end
                    continue
                # CRYPTO (0x06): varint offset + varint length + data
                if ftype == 0x06:
                    p = pos + 1
                    off, l1 = self._decode_varint(payload[p:])
                    p += l1
                    ln, l2 = self._decode_varint(payload[p:])
                    p += l2
                    end = min(n, p + ln)
                    frames.append((pos, end, "CRYPTO"))
                    pos = end
                    continue
                # STREAM (0x08..0x0f) — упрощённо считаем формат с length
                if 0x08 <= ftype <= 0x0F:
                    p = pos + 1
                    # stream id
                    _, lsid = self._decode_varint(payload[p:])
                    p += lsid
                    # offset (может быть 0)
                    _, loff = self._decode_varint(payload[p:])
                    p += loff
                    # length
                    ln, llen = self._decode_varint(payload[p:])
                    p += llen
                    end = min(n, p + ln)
                    frames.append((pos, end, "STREAM"))
                    pos = end
                    continue
                # прочее — завершаем сканирование
                break
        except Exception:
            # На любом сбое — кадрируется то, что успели собрать
            pass
        return frames
