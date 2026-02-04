"""
Unified SNI Manipulator for TLS ClientHello packets.

This module provides a centralized implementation for SNI manipulation
operations used across both testing and service modes.
"""

import struct
import logging
from typing import Optional, Tuple, List
from dataclasses import dataclass

from core.protocols.tls import TLSParser, TLSExtensionType, ClientHelloInfo

LOG = logging.getLogger(__name__)


@dataclass
class SNIPosition:
    """Represents the position of SNI in a TLS ClientHello packet."""

    extension_start: int  # Start of SNI extension (type field)
    extension_end: int  # End of SNI extension
    sni_value_start: int  # Start of actual SNI string
    sni_value_end: int  # End of actual SNI string
    sni_value: str  # The SNI value itself


class SNIManipulator:
    """
    Унифицированный манипулятор SNI для всех attack типов.

    Provides static methods for SNI operations:
    - Finding SNI position in TLS ClientHello
    - Splitting packets at SNI boundaries
    - Changing SNI values
    - Validating TLS structure
    """

    @staticmethod
    def find_sni_position(packet: bytes) -> Optional[SNIPosition]:
        """
        Находит позицию SNI extension в TLS ClientHello.

        Поддерживает:
        - TLS 1.2 (0x0303)
        - TLS 1.3 (0x0304)
        - Edge cases: отсутствие SNI, множественные SNI (берется первый)

        Args:
            packet: Байты пакета (TLS ClientHello)

        Returns:
            SNIPosition object или None если SNI не найден
        """
        try:
            # Validate TLS record structure first
            if len(packet) < 9:
                LOG.debug("Packet too short to be valid TLS ClientHello")
                return None

            # Check TLS record type (0x16 = Handshake)
            if packet[0] != 0x16:
                LOG.debug(f"Not a TLS handshake record: {packet[0]:02x}")
                return None

            # Check TLS version (0x03 = SSL 3.0/TLS family)
            if packet[1] != 0x03:
                LOG.debug(f"Not a TLS record: version byte {packet[1]:02x}")
                return None

            # TLS version minor (0x01=TLS1.0, 0x02=TLS1.1, 0x03=TLS1.2, 0x04=TLS1.3)
            tls_version = packet[2]
            if tls_version < 0x01 or tls_version > 0x04:
                LOG.debug(f"Unsupported TLS version: 0x03{tls_version:02x}")
                return None

            LOG.debug(f"Detected TLS version: 1.{tls_version - 1}")

            # Check handshake type (0x01 = ClientHello)
            if packet[5] != 0x01:
                LOG.debug(f"Not a ClientHello: handshake type {packet[5]:02x}")
                return None

            # Parse ClientHello to find SNI extension
            sni_ext = TLSParser.find_extension(packet, TLSExtensionType.SERVER_NAME)
            if not sni_ext:
                LOG.debug("SNI extension not found in packet")
                return None

            # Extract SNI value
            sni_value = TLSParser.get_sni(packet)
            if not sni_value:
                LOG.debug("SNI value could not be extracted")
                return None

            # Validate SNI extension data structure
            ext_data = sni_ext.data
            if len(ext_data) < 5:
                LOG.debug(f"SNI extension data too short: {len(ext_data)} bytes")
                return None

            # Check server name list length
            list_len = struct.unpack("!H", ext_data[0:2])[0]
            if list_len > len(ext_data) - 2:
                LOG.debug(f"Invalid server name list length: {list_len}")
                return None

            # Check name type (0 = host_name)
            name_type = ext_data[2]
            if name_type != 0:
                LOG.debug(f"Unsupported name type: {name_type}")
                return None

            # Check name length
            name_len = struct.unpack("!H", ext_data[3:5])[0]
            if name_len != len(sni_value):
                LOG.warning(f"Name length mismatch: {name_len} != {len(sni_value)}")

            # Calculate positions
            # SNI extension structure:
            # [2 bytes: extension type] [2 bytes: extension length] [extension data]
            # Extension data for SNI:
            # [2 bytes: server name list length] [1 byte: name type (0)] [2 bytes: name length] [name]

            extension_start = sni_ext.start_pos
            extension_end = sni_ext.end_pos

            # SNI value starts after: type(2) + length(2) + list_length(2) + name_type(1) + name_length(2) = 9 bytes
            sni_value_start = extension_start + 9
            sni_value_end = sni_value_start + len(sni_value)

            # Validate calculated positions
            if sni_value_end > extension_end:
                LOG.error(
                    f"SNI value end position {sni_value_end} exceeds extension end {extension_end}"
                )
                return None

            position = SNIPosition(
                extension_start=extension_start,
                extension_end=extension_end,
                sni_value_start=sni_value_start,
                sni_value_end=sni_value_end,
                sni_value=sni_value,
            )

            LOG.debug(
                f"Found SNI '{sni_value}' at position {sni_value_start}-{sni_value_end} (TLS 1.{tls_version - 1})"
            )
            return position

        except struct.error as e:
            LOG.error(f"Struct unpacking error while finding SNI: {e}")
            return None
        except Exception as e:
            LOG.error(f"Error finding SNI position: {e}", exc_info=True)
            return None

    @staticmethod
    def split_at_sni(
        packet: bytes, mode: str = "sni", position: Optional[int] = None
    ) -> Tuple[bytes, bytes]:
        """
        Разделяет пакет на позиции SNI.

        Args:
            packet: Байты пакета (TLS payload)
            mode: "sni" (начало SNI), "midsni" (середина SNI), или "position" (конкретная позиция)
            position: Конкретная позиция для split (используется если mode="position")

        Returns:
            Кортеж (первая_часть, вторая_часть)

        Raises:
            ValueError: Если mode невалиден или SNI не найден
        """
        try:
            # Determine split position
            if mode == "position" and position is not None:
                # Split at specific position
                if position < 0 or position > len(packet):
                    raise ValueError(
                        f"Invalid split position: {position} (packet length: {len(packet)})"
                    )
                split_pos = position
            else:
                # Find SNI position for mode-based splitting
                sni_pos = SNIManipulator.find_sni_position(packet)
                if not sni_pos:
                    raise ValueError("SNI not found in packet, cannot split")

                if mode == "sni":
                    # Split at the beginning of SNI value
                    split_pos = sni_pos.sni_value_start
                elif mode == "midsni":
                    # Split in the middle of SNI value
                    sni_length = len(sni_pos.sni_value)
                    split_pos = sni_pos.sni_value_start + (sni_length // 2)
                else:
                    raise ValueError(
                        f"Invalid split mode: {mode}. Use 'sni', 'midsni', or 'position'"
                    )

            # Perform split
            first_part = packet[:split_pos]
            second_part = packet[split_pos:]

            # Validate split result
            if not SNIManipulator._validate_split_result(first_part, second_part, packet):
                LOG.warning("Split validation failed, but returning result anyway")

            LOG.debug(
                f"Split packet at {mode} (position {split_pos}): {len(first_part)} + {len(second_part)} bytes"
            )
            return (first_part, second_part)

        except Exception as e:
            LOG.error(f"Error splitting packet: {e}", exc_info=True)
            raise

    @staticmethod
    def _validate_split_result(first_part: bytes, second_part: bytes, original: bytes) -> bool:
        """
        Валидирует результат split операции.

        Args:
            first_part: Первая часть после split
            second_part: Вторая часть после split
            original: Оригинальный пакет

        Returns:
            True если split корректен
        """
        try:
            # Check that parts can be recombined to original
            if first_part + second_part != original:
                LOG.error("Split parts do not recombine to original packet")
                return False

            # Check that both parts are non-empty
            if len(first_part) == 0:
                LOG.warning("First part is empty after split")
                return False

            if len(second_part) == 0:
                LOG.warning("Second part is empty after split")
                return False

            # Check that first part is valid TLS record start
            if len(first_part) >= 5:
                if first_part[0] != 0x16 or first_part[1] != 0x03:
                    LOG.warning("First part does not start with valid TLS record header")
                    return False

            LOG.debug("Split validation passed")
            return True

        except Exception as e:
            LOG.error(f"Error validating split result: {e}")
            return False

    @staticmethod
    def split_with_tcp_update(
        packet_with_tcp: bytes,
        mode: str = "sni",
        position: Optional[int] = None,
        tcp_header_len: int = 20,
    ) -> Tuple[bytes, bytes]:
        """
        Разделяет пакет с TCP заголовком и корректно обновляет TCP sequence numbers.

        Args:
            packet_with_tcp: Полный пакет с TCP заголовком и TLS payload
            mode: Режим split ("sni", "midsni", или "position")
            position: Конкретная позиция для split (если mode="position")
            tcp_header_len: Длина TCP заголовка в байтах (обычно 20)

        Returns:
            Кортеж (первый_пакет_с_tcp, второй_пакет_с_tcp)

        Raises:
            ValueError: Если пакет слишком короткий или невалиден
        """
        try:
            # Validate packet length
            if len(packet_with_tcp) < tcp_header_len + 9:
                raise ValueError(f"Packet too short: {len(packet_with_tcp)} bytes")

            # Extract TCP header and TLS payload
            tcp_header = packet_with_tcp[:tcp_header_len]
            tls_payload = packet_with_tcp[tcp_header_len:]

            # Split TLS payload
            tls_first, tls_second = SNIManipulator.split_at_sni(tls_payload, mode, position)

            # Extract original sequence number from TCP header
            # TCP sequence number is at offset 4-7 (4 bytes)
            if len(tcp_header) < 8:
                raise ValueError("TCP header too short to extract sequence number")

            original_seq = struct.unpack("!I", tcp_header[4:8])[0]

            # Create first packet (TCP header + first TLS part)
            first_packet = tcp_header + tls_first

            # Create second packet with updated sequence number
            # New sequence = original_seq + len(first_tls_part)
            new_seq = (original_seq + len(tls_first)) & 0xFFFFFFFF  # Keep within 32-bit range

            # Update sequence number in TCP header copy
            second_tcp_header = bytearray(tcp_header)
            struct.pack_into("!I", second_tcp_header, 4, new_seq)

            # Create second packet
            second_packet = bytes(second_tcp_header) + tls_second

            LOG.debug(
                f"Split with TCP update: seq {original_seq} -> {new_seq} (offset: {len(tls_first)})"
            )
            LOG.debug(
                f"First packet: {len(first_packet)} bytes, Second packet: {len(second_packet)} bytes"
            )

            return (first_packet, second_packet)

        except Exception as e:
            LOG.error(f"Error splitting packet with TCP update: {e}", exc_info=True)
            raise

    @staticmethod
    def split_at_position_list(packet: bytes, positions: List[int]) -> List[bytes]:
        """
        Разделяет пакет на несколько частей по списку позиций.

        Args:
            packet: Байты пакета
            positions: Список позиций для split (должны быть отсортированы)

        Returns:
            Список частей пакета

        Raises:
            ValueError: Если позиции невалидны
        """
        try:
            if not positions:
                return [packet]

            # Validate and sort positions
            positions = sorted(set(positions))

            for pos in positions:
                if pos < 0 or pos > len(packet):
                    raise ValueError(f"Invalid position: {pos} (packet length: {len(packet)})")

            # Split packet
            parts = []
            prev_pos = 0

            for pos in positions:
                if pos > prev_pos:
                    parts.append(packet[prev_pos:pos])
                    prev_pos = pos

            # Add remaining part
            if prev_pos < len(packet):
                parts.append(packet[prev_pos:])

            LOG.debug(f"Split packet into {len(parts)} parts at positions {positions}")
            return parts

        except Exception as e:
            LOG.error(f"Error splitting packet at position list: {e}", exc_info=True)
            raise

    @staticmethod
    def change_sni(packet: bytes, new_sni: str, validate: bool = True) -> bytes:
        """
        Изменяет SNI в пакете.

        Args:
            packet: Байты пакета (TLS payload)
            new_sni: Новое значение SNI
            validate: Валидировать TLS структуру после изменения

        Returns:
            Модифицированный пакет

        Raises:
            ValueError: Если SNI не найден или новое значение невалидно
        """
        try:
            # Validate new SNI
            if not new_sni or not isinstance(new_sni, str):
                raise ValueError("Invalid new SNI value")

            # Validate SNI format (basic check)
            if not SNIManipulator._is_valid_sni_format(new_sni):
                LOG.warning(f"SNI format may be invalid: {new_sni}")

            # Find current SNI position
            sni_pos = SNIManipulator.find_sni_position(packet)
            if not sni_pos:
                raise ValueError("SNI not found in packet, cannot change")

            # Check if SNI is already the same
            if sni_pos.sni_value == new_sni:
                LOG.debug(f"SNI already set to '{new_sni}', no change needed")
                return packet

            # Encode new SNI
            new_sni_bytes = new_sni.encode("utf-8")
            old_sni_bytes = sni_pos.sni_value.encode("utf-8")

            # Calculate length difference
            length_diff = len(new_sni_bytes) - len(old_sni_bytes)

            # Build new packet
            # Part 1: Everything before SNI value
            part1 = packet[: sni_pos.sni_value_start]

            # Part 2: New SNI value
            part2 = new_sni_bytes

            # Part 3: Everything after SNI value
            part3 = packet[sni_pos.sni_value_end :]

            # Combine parts
            new_packet = part1 + part2 + part3

            # Update lengths if there's a difference
            if length_diff != 0:
                new_packet = SNIManipulator._update_tls_lengths(new_packet, sni_pos, length_diff)

            # Validate result if requested
            if validate:
                if not SNIManipulator.validate_tls_structure(new_packet):
                    LOG.error("TLS structure validation failed after SNI change")
                    raise ValueError("Modified packet has invalid TLS structure")

                # Verify the new SNI was set correctly
                new_sni_pos = SNIManipulator.find_sni_position(new_packet)
                if not new_sni_pos or new_sni_pos.sni_value != new_sni:
                    LOG.error(
                        f"SNI verification failed: expected '{new_sni}', got '{new_sni_pos.sni_value if new_sni_pos else None}'"
                    )
                    raise ValueError("SNI change verification failed")

            LOG.debug(
                f"Changed SNI from '{sni_pos.sni_value}' to '{new_sni}' (length diff: {length_diff})"
            )
            return new_packet

        except Exception as e:
            LOG.error(f"Error changing SNI: {e}", exc_info=True)
            raise

    @staticmethod
    def _is_valid_sni_format(sni: str) -> bool:
        """
        Проверяет базовый формат SNI (доменное имя).

        Args:
            sni: SNI значение

        Returns:
            True если формат валиден
        """
        try:
            # Basic checks
            if not sni or len(sni) > 255:
                return False

            # Check for valid characters (alphanumeric, dots, hyphens)
            import re

            pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$"
            if not re.match(pattern, sni):
                return False

            # Check label lengths (each part between dots should be <= 63 chars)
            labels = sni.split(".")
            for label in labels:
                if not label or len(label) > 63:
                    return False

            return True

        except Exception:
            return False

    @staticmethod
    def change_sni_with_tcp(
        packet_with_tcp: bytes,
        new_sni: str,
        tcp_header_len: int = 20,
        recalculate_checksum: bool = False,
    ) -> bytes:
        """
        Изменяет SNI в пакете с TCP заголовком и опционально пересчитывает TCP checksum.

        Args:
            packet_with_tcp: Полный пакет с TCP заголовком и TLS payload
            new_sni: Новое значение SNI
            tcp_header_len: Длина TCP заголовка в байтах
            recalculate_checksum: Пересчитать TCP checksum (требует IP информации)

        Returns:
            Модифицированный пакет с TCP заголовком

        Raises:
            ValueError: Если пакет невалиден
        """
        try:
            # Validate packet length
            if len(packet_with_tcp) < tcp_header_len + 9:
                raise ValueError(f"Packet too short: {len(packet_with_tcp)} bytes")

            # Extract TCP header and TLS payload
            tcp_header = packet_with_tcp[:tcp_header_len]
            tls_payload = packet_with_tcp[tcp_header_len:]

            # Change SNI in TLS payload
            new_tls_payload = SNIManipulator.change_sni(tls_payload, new_sni)

            # Combine with TCP header
            new_packet = tcp_header + new_tls_payload

            # Recalculate TCP checksum if requested
            if recalculate_checksum:
                LOG.warning("TCP checksum recalculation requires IP header information, skipping")
                # Note: Full checksum recalculation would require IP addresses from IP header
                # This is typically handled by the network stack or WinDivert

            LOG.debug(
                f"Changed SNI in TCP packet: {len(packet_with_tcp)} -> {len(new_packet)} bytes"
            )
            return new_packet

        except Exception as e:
            LOG.error(f"Error changing SNI with TCP: {e}", exc_info=True)
            raise

    @staticmethod
    def obfuscate_sni(packet: bytes, obfuscation_type: str = "reverse") -> bytes:
        """
        Обфусцирует SNI различными методами (для тестирования обхода).

        Args:
            packet: Байты пакета
            obfuscation_type: Тип обфускации ("reverse", "uppercase", "fake")

        Returns:
            Пакет с обфусцированным SNI

        Raises:
            ValueError: Если SNI не найден или тип обфускации невалиден
        """
        try:
            sni_pos = SNIManipulator.find_sni_position(packet)
            if not sni_pos:
                raise ValueError("SNI not found in packet")

            original_sni = sni_pos.sni_value

            if obfuscation_type == "reverse":
                # Reverse the SNI
                new_sni = original_sni[::-1]
            elif obfuscation_type == "uppercase":
                # Convert to uppercase
                new_sni = original_sni.upper()
            elif obfuscation_type == "fake":
                # Replace with fake domain
                new_sni = "www.example.com"
            else:
                raise ValueError(f"Unknown obfuscation type: {obfuscation_type}")

            result = SNIManipulator.change_sni(packet, new_sni)
            LOG.debug(f"Obfuscated SNI '{original_sni}' -> '{new_sni}' (type: {obfuscation_type})")
            return result

        except Exception as e:
            LOG.error(f"Error obfuscating SNI: {e}", exc_info=True)
            raise

    @staticmethod
    def _update_tls_lengths(packet: bytes, sni_pos: SNIPosition, length_diff: int) -> bytes:
        """
        Обновляет длины в TLS структуре после изменения SNI.

        Args:
            packet: Модифицированный пакет
            sni_pos: Позиция SNI (до модификации)
            length_diff: Разница в длине SNI

        Returns:
            Пакет с обновленными длинами
        """
        packet_array = bytearray(packet)

        try:
            # Update SNI name length (2 bytes at extension_start + 7)
            name_len_pos = sni_pos.extension_start + 7
            old_name_len = struct.unpack("!H", packet_array[name_len_pos : name_len_pos + 2])[0]
            new_name_len = old_name_len + length_diff
            struct.pack_into("!H", packet_array, name_len_pos, new_name_len)

            # Update server name list length (2 bytes at extension_start + 4)
            list_len_pos = sni_pos.extension_start + 4
            old_list_len = struct.unpack("!H", packet_array[list_len_pos : list_len_pos + 2])[0]
            new_list_len = old_list_len + length_diff
            struct.pack_into("!H", packet_array, list_len_pos, new_list_len)

            # Update SNI extension length (2 bytes at extension_start + 2)
            ext_len_pos = sni_pos.extension_start + 2
            old_ext_len = struct.unpack("!H", packet_array[ext_len_pos : ext_len_pos + 2])[0]
            new_ext_len = old_ext_len + length_diff
            struct.pack_into("!H", packet_array, ext_len_pos, new_ext_len)

            # Update total extensions length (2 bytes before first extension)
            # Need to find extensions start position
            info = TLSParser.parse_client_hello(bytes(packet_array))
            if info and info.extensions_start_pos > 0:
                exts_len_pos = info.extensions_start_pos
                old_exts_len = struct.unpack("!H", packet_array[exts_len_pos : exts_len_pos + 2])[0]
                new_exts_len = old_exts_len + length_diff
                struct.pack_into("!H", packet_array, exts_len_pos, new_exts_len)

            # Update ClientHello length (3 bytes at position 6-8)
            hello_len_pos = 6
            old_hello_len = struct.unpack(
                "!I", b"\x00" + packet_array[hello_len_pos : hello_len_pos + 3]
            )[0]
            new_hello_len = old_hello_len + length_diff
            hello_len_bytes = struct.pack("!I", new_hello_len)[1:]  # Take last 3 bytes
            packet_array[hello_len_pos : hello_len_pos + 3] = hello_len_bytes

            # Update TLS record length (2 bytes at position 3-4)
            record_len_pos = 3
            old_record_len = struct.unpack("!H", packet_array[record_len_pos : record_len_pos + 2])[
                0
            ]
            new_record_len = old_record_len + length_diff
            struct.pack_into("!H", packet_array, record_len_pos, new_record_len)

            LOG.debug(f"Updated TLS lengths with diff {length_diff}")
            return bytes(packet_array)

        except Exception as e:
            LOG.error(f"Error updating TLS lengths: {e}", exc_info=True)
            # Return packet as-is if update fails
            return bytes(packet_array)

    @staticmethod
    def validate_tls_structure(packet: bytes) -> bool:
        """
        Валидирует TLS структуру после манипуляций.

        Args:
            packet: Байты пакета

        Returns:
            True если структура валидна
        """
        try:
            # Try to parse the packet
            info = TLSParser.parse_client_hello(packet)
            if not info:
                LOG.debug("TLS structure validation failed: cannot parse ClientHello")
                return False

            # Check basic structure
            if len(packet) < 9:
                LOG.debug("TLS structure validation failed: packet too short")
                return False

            # Verify TLS record header
            if not packet.startswith(b"\x16\x03"):
                LOG.debug("TLS structure validation failed: invalid record header")
                return False

            # Verify handshake type (ClientHello = 0x01)
            if packet[5] != 0x01:
                LOG.debug("TLS structure validation failed: not a ClientHello")
                return False

            # Verify lengths are consistent
            record_len = struct.unpack("!H", packet[3:5])[0]
            if record_len + 5 != len(packet):
                LOG.debug(
                    f"TLS structure validation failed: record length mismatch ({record_len + 5} != {len(packet)})"
                )
                return False

            # If SNI exists, verify it can be extracted
            sni_ext = TLSParser.find_extension(packet, TLSExtensionType.SERVER_NAME)
            if sni_ext:
                sni_value = TLSParser.get_sni(packet)
                if not sni_value:
                    LOG.debug(
                        "TLS structure validation failed: SNI extension exists but value cannot be extracted"
                    )
                    return False

            LOG.debug("TLS structure validation passed")
            return True

        except Exception as e:
            LOG.error(f"TLS structure validation error: {e}", exc_info=True)
            return False

    @staticmethod
    def find_all_sni_positions(packet: bytes) -> List[SNIPosition]:
        """
        Находит все SNI extensions в TLS ClientHello (edge case: множественные SNI).

        В большинстве случаев будет только один SNI, но спецификация допускает несколько.

        Args:
            packet: Байты пакета (TLS ClientHello)

        Returns:
            Список SNIPosition objects (может быть пустым)
        """
        positions = []

        try:
            # Parse ClientHello
            info = TLSParser.parse_client_hello(packet)
            if not info:
                LOG.debug("Cannot parse ClientHello for multiple SNI search")
                return positions

            # Check if SNI extension exists
            if TLSExtensionType.SERVER_NAME not in info.extensions:
                LOG.debug("No SNI extension found")
                return positions

            sni_ext = info.extensions[TLSExtensionType.SERVER_NAME]
            ext_data = sni_ext.data

            if len(ext_data) < 5:
                LOG.debug("SNI extension data too short")
                return positions

            # Parse server name list
            list_len = struct.unpack("!H", ext_data[0:2])[0]
            pos = 2

            while pos < list_len + 2 and pos + 3 <= len(ext_data):
                name_type = ext_data[pos]
                pos += 1

                if pos + 2 > len(ext_data):
                    break

                name_len = struct.unpack("!H", ext_data[pos : pos + 2])[0]
                pos += 2

                if pos + name_len > len(ext_data):
                    LOG.warning(f"Invalid name length: {name_len}")
                    break

                if name_type == 0:  # host_name
                    sni_value = ext_data[pos : pos + name_len].decode("utf-8", errors="ignore")

                    # Calculate absolute positions in packet
                    extension_start = sni_ext.start_pos
                    extension_end = sni_ext.end_pos
                    sni_value_start = extension_start + 4 + (pos - 2)  # 4 = type(2) + length(2)
                    sni_value_end = sni_value_start + name_len

                    position = SNIPosition(
                        extension_start=extension_start,
                        extension_end=extension_end,
                        sni_value_start=sni_value_start,
                        sni_value_end=sni_value_end,
                        sni_value=sni_value,
                    )
                    positions.append(position)
                    LOG.debug(f"Found SNI #{len(positions)}: '{sni_value}'")

                pos += name_len

            if len(positions) > 1:
                LOG.info(f"Found {len(positions)} SNI values in packet (unusual)")

        except Exception as e:
            LOG.error(f"Error finding all SNI positions: {e}", exc_info=True)

        return positions

    @staticmethod
    def has_sni(packet: bytes) -> bool:
        """
        Быстрая проверка наличия SNI extension в пакете.

        Args:
            packet: Байты пакета

        Returns:
            True если SNI extension присутствует
        """
        try:
            if len(packet) < 9:
                return False

            # Quick check for TLS handshake
            if packet[0] != 0x16 or packet[1] != 0x03 or packet[5] != 0x01:
                return False

            # Use TLSParser to check for SNI extension
            sni_ext = TLSParser.find_extension(packet, TLSExtensionType.SERVER_NAME)
            return sni_ext is not None

        except Exception:
            return False

    @staticmethod
    def get_split_position(packet: bytes, split_mode: str) -> Optional[int]:
        """
        Получает позицию split без фактического разделения пакета.

        Args:
            packet: Байты пакета
            split_mode: Режим split ("sni", "midsni", или число)

        Returns:
            Позиция split или None если не удалось определить
        """
        try:
            # If split_mode is a number, return it directly
            if split_mode.isdigit():
                position = int(split_mode)
                if 0 <= position <= len(packet):
                    return position
                else:
                    LOG.warning(
                        f"Split position {position} out of range for packet length {len(packet)}"
                    )
                    return None

            # Find SNI position
            sni_pos = SNIManipulator.find_sni_position(packet)
            if not sni_pos:
                LOG.debug("Cannot determine split position: SNI not found")
                return None

            if split_mode == "sni":
                return sni_pos.sni_value_start
            elif split_mode == "midsni":
                sni_length = len(sni_pos.sni_value)
                return sni_pos.sni_value_start + (sni_length // 2)
            else:
                LOG.warning(f"Unknown split mode: {split_mode}")
                return None

        except Exception as e:
            LOG.error(f"Error getting split position: {e}", exc_info=True)
            return None
