# recon/core/protocols/tls.py (исправленная версия)

import struct
import logging
from typing import Dict, Optional, List
from dataclasses import dataclass
from enum import IntEnum

LOG = logging.getLogger("TLSProtocol")


class TLSExtensionType(IntEnum):
    """TLS Extension Types"""

    SERVER_NAME = 0x0000
    MAX_FRAGMENT_LENGTH = 0x0001
    STATUS_REQUEST = 0x0005
    SUPPORTED_GROUPS = 0x000A
    SIGNATURE_ALGORITHMS = 0x000D
    USE_SRTP = 0x000E
    HEARTBEAT = 0x000F
    ALPN = 0x0010
    SIGNED_CERTIFICATE_TIMESTAMP = 0x0012
    CLIENT_CERTIFICATE_TYPE = 0x0013
    SERVER_CERTIFICATE_TYPE = 0x0014
    PADDING = 0x0015
    ENCRYPT_THEN_MAC = 0x0016
    EXTENDED_MASTER_SECRET = 0x0017
    SESSION_TICKET = 0x0023
    PRE_SHARED_KEY = 0x0029
    EARLY_DATA = 0x002A
    SUPPORTED_VERSIONS = 0x002B
    COOKIE = 0x002C
    PSK_KEY_EXCHANGE_MODES = 0x002D
    CERTIFICATE_AUTHORITIES = 0x002F
    OID_FILTERS = 0x0030
    POST_HANDSHAKE_AUTH = 0x0031
    SIGNATURE_ALGORITHMS_CERT = 0x0032
    KEY_SHARE = 0x0033


@dataclass
class TLSExtension:
    """Represents a TLS extension"""

    type: int
    data: bytes
    start_pos: int
    end_pos: int


@dataclass
class ClientHelloInfo:
    """Parsed ClientHello information"""

    version: bytes
    random: bytes
    session_id: bytes
    cipher_suites: List[bytes]
    compression_methods: List[int]
    extensions: Dict[int, TLSExtension]
    extensions_start_pos: int = 0  # Добавлено поле


class TLSParser:
    """
    Централизованный парсер и билдер для TLS пакетов.
    Объединяет функциональность создания и модификации TLS сообщений.
    """

    @staticmethod
    def parse_client_hello(payload: bytes) -> Optional[ClientHelloInfo]:
        """
        Полностью парсит TLS ClientHello.

        Args:
            payload: Raw TLS payload

        Returns:
            ClientHelloInfo object or None if parsing fails
        """
        try:
            # Validate TLS record header
            if not TLSParser._is_valid_tls_record(payload):
                return None

            # Skip TLS record header (5 bytes) and handshake type/length (4 bytes)
            pos = 9

            # Client version (2 bytes)
            version = payload[pos : pos + 2]
            pos += 2

            # Random (32 bytes)
            random = payload[pos : pos + 32]
            pos += 32

            # Session ID
            session_id_len = payload[pos]
            pos += 1
            session_id = payload[pos : pos + session_id_len]
            pos += session_id_len

            # Cipher suites
            cipher_suites_len = struct.unpack("!H", payload[pos : pos + 2])[0]
            pos += 2
            cipher_suites = []
            for i in range(0, cipher_suites_len, 2):
                cipher_suites.append(payload[pos + i : pos + i + 2])
            pos += cipher_suites_len

            # Compression methods
            comp_methods_len = payload[pos]
            pos += 1
            compression_methods = list(payload[pos : pos + comp_methods_len])
            pos += comp_methods_len

            # Extensions
            extensions = {}
            extensions_start_pos = pos  # Сохраняем позицию начала расширений

            if pos + 2 <= len(payload):
                extensions_len = struct.unpack("!H", payload[pos : pos + 2])[0]
                pos += 2
                extensions_end = pos + extensions_len

                while pos < extensions_end and pos + 4 <= len(payload):
                    ext_type = struct.unpack("!H", payload[pos : pos + 2])[0]
                    ext_len = struct.unpack("!H", payload[pos + 2 : pos + 4])[0]
                    ext_start = pos
                    ext_data = payload[pos + 4 : pos + 4 + ext_len]
                    ext_end = pos + 4 + ext_len

                    if ext_end <= len(payload):
                        extensions[ext_type] = TLSExtension(
                            type=ext_type,
                            data=ext_data,
                            start_pos=ext_start,
                            end_pos=ext_end,
                        )

                    pos = ext_end

            return ClientHelloInfo(
                version=version,
                random=random,
                session_id=session_id,
                cipher_suites=cipher_suites,
                compression_methods=compression_methods,
                extensions=extensions,
                extensions_start_pos=extensions_start_pos,
            )

        except Exception as e:
            LOG.debug(f"Failed to parse ClientHello: {e}")
            return None

    @staticmethod
    def find_extension(payload: bytes, ext_type: int) -> Optional[TLSExtension]:
        """
        Находит расширение в TLS ClientHello.

        Args:
            payload: Raw TLS payload
            ext_type: Extension type to find

        Returns:
            TLSExtension object or None if not found
        """
        info = TLSParser.parse_client_hello(payload)
        if not info:
            return None

        return info.extensions.get(ext_type)

    @staticmethod
    def get_sni(payload: bytes) -> Optional[str]:
        """
        Извлекает SNI (Server Name Indication) из ClientHello.

        Args:
            payload: Raw TLS payload

        Returns:
            Domain name or None if not found
        """
        sni_ext = TLSParser.find_extension(payload, TLSExtensionType.SERVER_NAME)
        if not sni_ext:
            return None

        try:
            # Parse SNI extension data
            data = sni_ext.data
            if len(data) < 5:
                return None

            # Server name list length (2 bytes)
            list_len = struct.unpack("!H", data[0:2])[0]

            # Validate list length
            if list_len > len(data) - 2:
                return None

            # Server name type (1 byte) - should be 0 for hostname
            if data[2] != 0:
                return None

            # Server name length (2 bytes)
            name_len = struct.unpack("!H", data[3:5])[0]

            # Validate name length
            if name_len > len(data) - 5:
                return None

            # Server name
            if len(data) >= 5 + name_len:
                domain = data[5 : 5 + name_len].decode("utf-8", errors="ignore")
                return domain

        except Exception as e:
            LOG.debug(f"Failed to extract SNI: {e}")

        return None

    @staticmethod
    def replace_sni(payload: bytes, new_domain: str) -> bytes:
        """Заменяет SNI и корректно пересчитывает все длины."""
        sni_ext = TLSParser.find_extension(payload, TLSExtensionType.SERVER_NAME)
        if not sni_ext:
            LOG.warning("SNI extension not found for replacement.")
            return payload

        try:
            new_domain_bytes = new_domain.encode("utf-8")
            new_domain_len = len(new_domain_bytes)

            # Validate domain length
            if new_domain_len > 255:  # Max hostname length
                LOG.error(f"Domain name too long: {new_domain_len} bytes")
                return payload

            # Новые данные для SNI расширения
            new_sni_data = (
                struct.pack("!H", new_domain_len + 3)  # List length
                + b"\x00"  # Name type (hostname)
                + struct.pack("!H", new_domain_len)  # Name length
                + new_domain_bytes
            )

            return TLSParser._replace_extension_data(payload, sni_ext, new_sni_data)

        except Exception as e:
            LOG.error(f"Failed to replace SNI: {e}")
            return payload

    @staticmethod
    def add_extension(payload: bytes, ext_type: int, ext_data: bytes) -> bytes:
        """
        Добавляет новое расширение в ClientHello.

        Args:
            payload: Raw TLS payload
            ext_type: Extension type
            ext_data: Extension data

        Returns:
            Modified payload with new extension
        """
        info = TLSParser.parse_client_hello(payload)
        if not info:
            return payload

        try:
            # Validate extension type
            if ext_type > 65535:
                LOG.error(f"Invalid extension type: {ext_type}")
                return payload

            # Build new extension
            new_ext = (
                struct.pack("!H", ext_type)
                + struct.pack("!H", len(ext_data))
                + ext_data
            )

            # Find where to insert (at the end of extensions)
            if info.extensions:
                # Get position after last extension
                last_ext = max(info.extensions.values(), key=lambda e: e.end_pos)
                insert_pos = last_ext.end_pos
            else:
                # If no extensions, insert after extensions length field
                insert_pos = info.extensions_start_pos + 2

            # Insert new extension
            result = bytearray(payload)
            result[insert_pos:insert_pos] = new_ext

            # Update lengths
            result = TLSParser._update_lengths(result, len(new_ext))

            return bytes(result)

        except Exception as e:
            LOG.error(f"Failed to add extension: {e}")
            return payload

    @staticmethod
    def remove_extension(payload: bytes, ext_type: int) -> bytes:
        """
        Удаляет расширение из ClientHello.

        Args:
            payload: Raw TLS payload
            ext_type: Extension type to remove

        Returns:
            Modified payload without the extension
        """
        ext = TLSParser.find_extension(payload, ext_type)
        if not ext:
            return payload

        try:
            # Remove extension
            result = bytearray(payload)
            removed_len = ext.end_pos - ext.start_pos
            del result[ext.start_pos : ext.end_pos]

            # Update lengths
            result = TLSParser._update_lengths(result, -removed_len)

            return bytes(result)

        except Exception as e:
            LOG.error(f"Failed to remove extension: {e}")
            return payload

    @staticmethod
    def modify_alpn(payload: bytes, protocols: List[str]) -> bytes:
        """
        Модифицирует ALPN расширение.

        Args:
            payload: Raw TLS payload
            protocols: List of protocol names

        Returns:
            Modified payload with updated ALPN
        """
        # Build ALPN data
        alpn_data = b""
        for protocol in protocols:
            proto_bytes = protocol.encode("utf-8")
            if len(proto_bytes) > 255:
                LOG.warning(f"Protocol name too long: {protocol}")
                continue
            alpn_data += bytes([len(proto_bytes)]) + proto_bytes

        # ALPN structure: protocol_list_length (2 bytes) + protocols
        alpn_ext_data = struct.pack("!H", len(alpn_data)) + alpn_data

        # Check if ALPN already exists
        alpn_ext = TLSParser.find_extension(payload, TLSExtensionType.ALPN)
        if alpn_ext:
            # Replace existing ALPN
            return TLSParser._replace_extension_data(payload, alpn_ext, alpn_ext_data)
        else:
            # Add new ALPN
            return TLSParser.add_extension(
                payload, TLSExtensionType.ALPN, alpn_ext_data
            )

    @staticmethod
    def add_grease_extensions(payload: bytes, count: int = 2) -> bytes:
        """
        Добавляет GREASE расширения для тестирования устойчивости DPI.

        Args:
            payload: Raw TLS payload
            count: Number of GREASE extensions to add

        Returns:
            Modified payload with GREASE extensions
        """
        grease_values = [
            0x0A0A,
            0x1A1A,
            0x2A2A,
            0x3A3A,
            0x4A4A,
            0x5A5A,
            0x6A6A,
            0x7A7A,
            0x8A8A,
            0x9A9A,
            0xAAAA,
            0xBABA,
            0xCACA,
            0xDADA,
            0xEAEA,
            0xFAFA,
        ]

        result = payload
        import random

        for _ in range(count):
            grease_type = random.choice(grease_values)
            grease_data = bytes(
                [random.randint(0, 255) for _ in range(random.randint(0, 16))]
            )
            result = TLSParser.add_extension(result, grease_type, grease_data)

        return result

    @staticmethod
    def _is_valid_tls_record(payload: bytes) -> bool:
        """Проверяет, является ли payload валидным TLS записью."""
        if len(payload) < 9:
            return False

        # Check for TLS handshake record
        if not payload.startswith(b"\x16\x03"):
            return False

        # Check for ClientHello
        if payload[5] != 0x01:
            return False

        return True

    @staticmethod
    def _update_lengths(payload: bytearray, len_diff: int) -> bytes:
        """Обновляет все длины в TLS сообщении после изменения."""
        if len_diff == 0:
            return bytes(payload)

        try:
            # 1. TLS Record Length (байт 3-4)
            record_len = struct.unpack("!H", payload[3:5])[0]
            new_record_len = record_len + len_diff
            if new_record_len > 65535:
                LOG.error(f"TLS record length overflow: {new_record_len}")
                return bytes(payload)
            payload[3:5] = struct.pack("!H", new_record_len)

            # 2. Handshake Message Length (байт 6-8)
            handshake_len = int.from_bytes(payload[6:9], "big")
            new_handshake_len = handshake_len + len_diff
            if new_handshake_len > 0xFFFFFF:  # 3-byte max
                LOG.error(f"Handshake length overflow: {new_handshake_len}")
                return bytes(payload)
            payload[6:9] = new_handshake_len.to_bytes(3, "big")

            # 3. Extensions Block Length
            # Для этого нам нужно найти позицию блока расширений
            info = TLSParser.parse_client_hello(bytes(payload))
            if info and info.extensions_start_pos > 0:
                ext_len_pos = info.extensions_start_pos
                if ext_len_pos + 2 <= len(payload):
                    ext_len = struct.unpack(
                        "!H", payload[ext_len_pos : ext_len_pos + 2]
                    )[0]
                    new_ext_len = ext_len + len_diff
                    if new_ext_len > 65535:
                        LOG.error(f"Extensions length overflow: {new_ext_len}")
                        return bytes(payload)
                    payload[ext_len_pos : ext_len_pos + 2] = struct.pack(
                        "!H", new_ext_len
                    )

        except Exception as e:
            LOG.error(f"Error updating lengths: {e}")

        return bytes(payload)

    @staticmethod
    def _replace_extension_data(
        payload: bytes, ext: TLSExtension, new_data: bytes
    ) -> bytes:
        """Вспомогательный метод для замены данных расширения и обновления длин."""
        try:
            old_ext_total_len = ext.end_pos - ext.start_pos
            new_ext_total_len = 4 + len(new_data)  # 4 байта на тип и длину
            len_diff = new_ext_total_len - old_ext_total_len

            # Validate new data length
            if len(new_data) > 65535:
                LOG.error(f"Extension data too large: {len(new_data)} bytes")
                return payload

            # Собираем новое расширение
            new_ext_bytes = (
                struct.pack("!H", ext.type)
                + struct.pack("!H", len(new_data))
                + new_data
            )

            # Заменяем старое расширение на новое
            result = bytearray(payload)
            result[ext.start_pos : ext.end_pos] = new_ext_bytes

            # Обновляем все вышестоящие длины
            return TLSParser._update_lengths(result, len_diff)

        except Exception as e:
            LOG.error(f"Error replacing extension data: {e}")
            return payload


class TLSHandler:
    """
    Обработчик для создания TLS пакетов с использованием TLSParser.
    Сохранен для обратной совместимости.
    """

    def __init__(self, tls_template: bytes):
        self.tls_template = tls_template

    def build_client_hello(
        self,
        domain: str,
        version: bytes = b"\x03\x03",
        extensions: Optional[Dict] = None,
    ) -> bytes:
        """
        Строит кастомизированный TLS ClientHello на основе шаблона.
        Гарантирует наличие и корректность SNI.
        """
        try:
            # Начинаем с шаблона
            result_bytes = self.tls_template

            # Проверяем и обновляем SNI
            current_sni = TLSParser.get_sni(result_bytes)
            if current_sni:
                # Если SNI есть, заменяем его
                result_bytes = TLSParser.replace_sni(result_bytes, domain)
            else:
                # Если SNI нет, добавляем его
                LOG.warning("Template is missing SNI extension. Adding it manually.")
                # Собираем данные для нового SNI расширения
                domain_bytes = domain.encode("utf-8")
                if len(domain_bytes) > 255:
                    LOG.error(f"Domain name too long: {len(domain_bytes)} bytes")
                    return self.tls_template

                sni_data = (
                    struct.pack("!H", len(domain_bytes) + 3)  # List length
                    + b"\x00"  # Name type
                    + struct.pack("!H", len(domain_bytes))  # Name length
                    + domain_bytes
                )
                result_bytes = TLSParser.add_extension(
                    result_bytes, TLSExtensionType.SERVER_NAME, sni_data
                )

            # Устанавливаем версию TLS (в двух местах: record и handshake)
            result_array = bytearray(result_bytes)
            if len(result_array) > 11:
                result_array[1:3] = (
                    b"\x03\x01"  # Record version (legacy for compatibility)
                )
                result_array[9:11] = version  # Handshake version
            result_bytes = bytes(result_array)

            # Добавляем другие расширения, если нужно
            if extensions:
                for ext_name, ext_value in extensions.items():
                    if ext_name == "alpn" and isinstance(ext_value, list):
                        result_bytes = TLSParser.modify_alpn(result_bytes, ext_value)

            return result_bytes

        except Exception as e:
            LOG.error(f"Ошибка при построении ClientHello: {e}")
            return self.tls_template
