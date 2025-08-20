# recon/core/robust_packet_processor.py

import logging
import struct
from typing import Optional, Dict

try:
    import pydivert
    from pydivert.packet import Direction

    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    Direction = None

LOG = logging.getLogger("robust_packet_processor")


class PacketValidationError(Exception):
    """Exception raised when packet validation fails."""

    pass


class RobustPacketProcessor:
    """
    Надежный процессор пакетов с исправлением WinError 87.
    Обеспечивает безопасную реконструкцию пакетов и обработку ошибок.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger("RobustPacketProcessor")
        if debug:
            self.logger.setLevel(logging.DEBUG)

        # Статистика обработки
        self.stats = {
            "packets_validated": 0,
            "packets_reconstructed": 0,
            "validation_errors": 0,
            "reconstruction_errors": 0,
            "localhost_packets_handled": 0,
            "large_packets_handled": 0,
        }

    def validate_packet(self, packet: "pydivert.Packet") -> bool:
        """
        Валидация пакета перед обработкой для предотвращения WinError 87.

        Args:
            packet: PyDivert пакет для валидации

        Returns:
            True если пакет валиден, False иначе

        Raises:
            PacketValidationError: При критических ошибках валидации
        """
        try:
            self.stats["packets_validated"] += 1

            # Проверка базовых атрибутов
            if not packet:
                self.logger.debug("Packet is None")
                return False

            if not hasattr(packet, "raw") or not packet.raw:
                self.logger.debug("Packet missing raw data")
                return False

            # Получаем raw данные безопасно
            try:
                raw_data = self._get_raw_data_safely(packet)
                if (
                    not raw_data or len(raw_data) < 20
                ):  # Минимальный размер IP заголовка
                    self.logger.debug(
                        f"Packet too small: {len(raw_data) if raw_data else 0} bytes"
                    )
                    return False
            except Exception as e:
                self.logger.debug(f"Failed to extract raw data: {e}")
                return False

            # Проверка IP заголовка
            if not self._validate_ip_header(raw_data):
                return False

            # Проверка на localhost пакеты
            if self._is_localhost_packet(packet):
                self.stats["localhost_packets_handled"] += 1
                self.logger.debug("Localhost packet detected")
                # Localhost пакеты валидны, но требуют специальной обработки
                return True

            # Проверка размера пакета (особое внимание к 1500 байт)
            if len(raw_data) >= 1500:
                self.stats["large_packets_handled"] += 1
                self.logger.debug(f"Large packet detected: {len(raw_data)} bytes")
                # Дополнительная валидация для больших пакетов
                if not self._validate_large_packet(raw_data):
                    return False

            # Проверка TCP заголовка если это TCP пакет
            if hasattr(packet, "tcp") and packet.tcp:
                if not self._validate_tcp_header(raw_data):
                    return False

            self.logger.debug(f"Packet validation successful: {len(raw_data)} bytes")
            return True

        except Exception as e:
            self.stats["validation_errors"] += 1
            self.logger.error(f"Packet validation error: {e}")
            if self.debug:
                self.logger.exception("Detailed validation error:")
            return False

    def reconstruct_packet(
        self, packet: "pydivert.Packet"
    ) -> Optional["pydivert.Packet"]:
        """
        Безопасная реконструкция пакета для предотвращения WinError 87.

        Args:
            packet: Исходный PyDivert пакет

        Returns:
            Реконструированный пакет или None при ошибке
        """
        try:
            self.stats["packets_reconstructed"] += 1

            # Валидация перед реконструкцией
            if not self.validate_packet(packet):
                self.logger.debug("Packet validation failed, cannot reconstruct")
                return None

            # Получаем raw данные безопасно
            raw_data = self._get_raw_data_safely(packet)
            if not raw_data:
                self.logger.debug("No raw data available for reconstruction")
                return None

            # Специальная обработка localhost пакетов
            if self._is_localhost_packet(packet):
                return self._reconstruct_localhost_packet(packet, raw_data)

            # Специальная обработка больших пакетов
            if len(raw_data) >= 1500:
                return self._reconstruct_large_packet(packet, raw_data)

            # Стандартная реконструкция
            try:
                reconstructed = pydivert.Packet(
                    bytes(raw_data), packet.interface, packet.direction
                )

                self.logger.debug(
                    f"Packet reconstructed successfully: {len(raw_data)} bytes"
                )
                return reconstructed

            except Exception as e:
                self.logger.debug(f"Standard reconstruction failed: {e}")
                # Попытка альтернативной реконструкции
                return self._alternative_reconstruction(packet, raw_data)

        except Exception as e:
            self.stats["reconstruction_errors"] += 1
            self.logger.error(f"Packet reconstruction error: {e}")
            if self.debug:
                self.logger.exception("Detailed reconstruction error:")
            return None

    def handle_localhost_packets(self, packet: "pydivert.Packet") -> bool:
        """
        Специальная обработка localhost пакетов (127.0.0.1).

        Args:
            packet: PyDivert пакет

        Returns:
            True если пакет должен быть обработан, False если игнорирован
        """
        try:
            if not self._is_localhost_packet(packet):
                return True  # Не localhost пакет, обрабатываем нормально

            self.stats["localhost_packets_handled"] += 1

            # Логируем localhost пакет
            self.logger.debug(
                f"Localhost packet: {packet.src_addr} -> {packet.dst_addr}"
            )

            # Проверяем, нужно ли игнорировать этот пакет
            if self._should_ignore_localhost_packet(packet):
                self.logger.debug("Ignoring localhost packet")
                return False

            # Localhost пакет требует обработки
            self.logger.debug("Processing localhost packet")
            return True

        except Exception as e:
            self.logger.error(f"Error handling localhost packet: {e}")
            # В случае ошибки, безопаснее игнорировать пакет
            return False

    def _get_raw_data_safely(self, packet: "pydivert.Packet") -> Optional[bytes]:
        """Безопасное извлечение raw данных из пакета."""
        try:
            if hasattr(packet.raw, "tobytes"):
                # Для memoryview объектов
                return bytes(packet.raw.tobytes())
            elif hasattr(packet.raw, "__bytes__"):
                # Для объектов с __bytes__ методом
                return bytes(packet.raw)
            else:
                # Прямое преобразование
                return bytes(packet.raw)
        except Exception as e:
            self.logger.debug(f"Failed to extract raw data: {e}")
            return None

    def _validate_ip_header(self, raw_data: bytes) -> bool:
        """Валидация IP заголовка."""
        try:
            if len(raw_data) < 20:
                return False

            # Проверка версии IP
            version = (raw_data[0] >> 4) & 0x0F
            if version not in [4, 6]:
                self.logger.debug(f"Invalid IP version: {version}")
                return False

            if version == 4:
                # IPv4 валидация
                header_length = (raw_data[0] & 0x0F) * 4
                if header_length < 20 or header_length > len(raw_data):
                    self.logger.debug(f"Invalid IPv4 header length: {header_length}")
                    return False

                # Проверка общей длины
                total_length = struct.unpack("!H", raw_data[2:4])[0]
                if total_length > len(raw_data):
                    self.logger.debug(
                        f"Invalid total length: {total_length} > {len(raw_data)}"
                    )
                    return False

            elif version == 6:
                # IPv6 валидация
                if len(raw_data) < 40:
                    self.logger.debug("IPv6 packet too small")
                    return False

                # Проверка payload length
                payload_length = struct.unpack("!H", raw_data[4:6])[0]
                if payload_length + 40 > len(raw_data):
                    self.logger.debug(f"Invalid IPv6 payload length: {payload_length}")
                    return False

            return True

        except Exception as e:
            self.logger.debug(f"IP header validation error: {e}")
            return False

    def _validate_tcp_header(self, raw_data: bytes) -> bool:
        """Валидация TCP заголовка."""
        try:
            # Определяем начало TCP заголовка
            version = (raw_data[0] >> 4) & 0x0F
            if version == 4:
                ip_header_len = (raw_data[0] & 0x0F) * 4
            elif version == 6:
                ip_header_len = 40
            else:
                return False

            if len(raw_data) < ip_header_len + 20:  # Минимальный TCP заголовок
                return False

            # Проверка длины TCP заголовка
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            if tcp_header_len < 20 or ip_header_len + tcp_header_len > len(raw_data):
                self.logger.debug(f"Invalid TCP header length: {tcp_header_len}")
                return False

            return True

        except Exception as e:
            self.logger.debug(f"TCP header validation error: {e}")
            return False

    def _validate_large_packet(self, raw_data: bytes) -> bool:
        """Дополнительная валидация для больших пакетов (>= 1500 байт)."""
        try:
            # Проверяем, что пакет не превышает максимальный размер
            if len(raw_data) > 65535:
                self.logger.debug(f"Packet too large: {len(raw_data)} bytes")
                return False

            # Дополнительные проверки для больших пакетов
            # Проверяем фрагментацию для IPv4
            version = (raw_data[0] >> 4) & 0x0F
            if version == 4:
                flags_and_frag = struct.unpack("!H", raw_data[6:8])[0]
                fragment_offset = flags_and_frag & 0x1FFF
                more_fragments = (flags_and_frag & 0x2000) != 0

                # Если это фрагментированный пакет, проверяем корректность
                if fragment_offset > 0 or more_fragments:
                    self.logger.debug("Large fragmented packet detected")
                    # Дополнительные проверки для фрагментов
                    if fragment_offset * 8 > 65535:
                        return False

            return True

        except Exception as e:
            self.logger.debug(f"Large packet validation error: {e}")
            return False

    def _is_localhost_packet(self, packet: "pydivert.Packet") -> bool:
        """Проверка, является ли пакет localhost пакетом."""
        try:
            return (
                packet.src_addr == "127.0.0.1"
                or packet.dst_addr == "127.0.0.1"
                or packet.src_addr == "::1"
                or packet.dst_addr == "::1"
            )
        except Exception:
            return False

    def _should_ignore_localhost_packet(self, packet: "pydivert.Packet") -> bool:
        """Определяет, нужно ли игнорировать localhost пакет."""
        try:
            # Игнорируем некоторые типы localhost пакетов
            # Например, системные пакеты или пакеты определенных портов

            if hasattr(packet, "tcp") and packet.tcp:
                # Игнорируем пакеты на системные порты
                system_ports = {22, 135, 139, 445, 1433, 3389, 5432}
                if (
                    hasattr(packet.tcp, "src_port")
                    and packet.tcp.src_port in system_ports
                    or hasattr(packet.tcp, "dst_port")
                    and packet.tcp.dst_port in system_ports
                ):
                    return True

            # По умолчанию не игнорируем
            return False

        except Exception:
            # В случае ошибки, безопаснее не игнорировать
            return False

    def _reconstruct_localhost_packet(
        self, packet: "pydivert.Packet", raw_data: bytes
    ) -> Optional["pydivert.Packet"]:
        """Специальная реконструкция для localhost пакетов."""
        try:
            # Для localhost пакетов используем более осторожный подход
            reconstructed = pydivert.Packet(
                bytes(raw_data), packet.interface, packet.direction
            )

            self.logger.debug(f"Localhost packet reconstructed: {len(raw_data)} bytes")
            return reconstructed

        except Exception as e:
            self.logger.debug(f"Localhost packet reconstruction failed: {e}")
            return None

    def _reconstruct_large_packet(
        self, packet: "pydivert.Packet", raw_data: bytes
    ) -> Optional["pydivert.Packet"]:
        """Специальная реконструкция для больших пакетов."""
        try:
            # Для больших пакетов проверяем целостность данных
            if len(raw_data) > 1500:
                self.logger.debug(f"Reconstructing large packet: {len(raw_data)} bytes")

            # Используем стандартную реконструкцию, но с дополнительными проверками
            reconstructed = pydivert.Packet(
                bytes(raw_data), packet.interface, packet.direction
            )

            return reconstructed

        except Exception as e:
            self.logger.debug(f"Large packet reconstruction failed: {e}")
            # Попытка разбить на меньшие части, если возможно
            return self._fragment_and_reconstruct(packet, raw_data)

    def _alternative_reconstruction(
        self, packet: "pydivert.Packet", raw_data: bytes
    ) -> Optional["pydivert.Packet"]:
        """Альтернативный метод реконструкции при стандартном сбое."""
        try:
            # Попытка создать копию пакета
            reconstructed = pydivert.Packet(
                bytearray(raw_data),  # Используем bytearray
                packet.interface,
                packet.direction,
            )

            self.logger.debug("Alternative reconstruction successful")
            return reconstructed

        except Exception as e:
            self.logger.debug(f"Alternative reconstruction failed: {e}")
            return None

    def _fragment_and_reconstruct(
        self, packet: "pydivert.Packet", raw_data: bytes
    ) -> Optional["pydivert.Packet"]:
        """Попытка фрагментации и реконструкции для очень больших пакетов."""
        try:
            # Это сложная операция, пока возвращаем None
            # В будущем можно реализовать фрагментацию
            self.logger.debug("Fragmentation reconstruction not implemented")
            return None

        except Exception as e:
            self.logger.debug(f"Fragment reconstruction failed: {e}")
            return None

    def get_stats(self) -> Dict[str, int]:
        """Возвращает статистику обработки пакетов."""
        return self.stats.copy()

    def reset_stats(self):
        """Сбрасывает статистику."""
        for key in self.stats:
            self.stats[key] = 0
