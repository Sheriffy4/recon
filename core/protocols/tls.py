# recon/core/protocols/tls.py (исправленная версия)

import struct
import logging
from typing import Dict, Optional, List
from dataclasses import dataclass, field
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
    EC_POINT_FORMATS = 0x000B


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
    cipher_suites: List[int]
    compression_methods: List[int]
    extensions: Dict[int, TLSExtension]
    extensions_order: List[int] = field(default_factory=list)
    supported_groups: Optional[List[int]] = None
    signature_algorithms: Optional[List[int]] = None
    ec_point_formats: Optional[List[int]] = None
    alpn_protocols: Optional[List[str]] = None
    extensions_start_pos: int = 0


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
            if not TLSParser._is_valid_tls_record(payload):
                return None

            pos = 9
            version = payload[pos : pos + 2]
            pos += 2
            random_bytes = payload[pos : pos + 32]
            pos += 32
            session_id_len = payload[pos]
            pos += 1
            session_id = payload[pos : pos + session_id_len]
            pos += session_id_len
            cipher_suites_len = struct.unpack("!H", payload[pos : pos + 2])[0]
            pos += 2
            cipher_suites = [
                struct.unpack("!H", payload[pos + i : pos + i + 2])[0]
                for i in range(0, cipher_suites_len, 2)
            ]
            pos += cipher_suites_len
            comp_methods_len = payload[pos]
            pos += 1
            compression_methods = list(payload[pos : pos + comp_methods_len])
            pos += comp_methods_len

            extensions = {}
            extensions_order = []
            extensions_start_pos = pos

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
                        extensions_order.append(ext_type)

                    pos = ext_end

            info = ClientHelloInfo(
                version=version,
                random=random_bytes,
                session_id=session_id,
                cipher_suites=cipher_suites,
                compression_methods=compression_methods,
                extensions=extensions,
                extensions_order=extensions_order,
                extensions_start_pos=extensions_start_pos,
            )

            # Post-parse extensions for detailed info
            TLSParser._parse_extension_details(info)

            return info

        except Exception as e:
            LOG.debug(f"Failed to parse ClientHello: {e}")
            return None

    @staticmethod
    def _parse_extension_details(info: ClientHelloInfo):
        """Parse specific extensions to populate detailed fields in ClientHelloInfo."""
        if TLSExtensionType.SUPPORTED_GROUPS in info.extensions:
            data = info.extensions[TLSExtensionType.SUPPORTED_GROUPS].data
            list_len = struct.unpack("!H", data[:2])[0]
            info.supported_groups = [
                struct.unpack("!H", data[2 + i : 2 + i + 2])[0] for i in range(0, list_len, 2)
            ]

        if TLSExtensionType.SIGNATURE_ALGORITHMS in info.extensions:
            data = info.extensions[TLSExtensionType.SIGNATURE_ALGORITHMS].data
            list_len = struct.unpack("!H", data[:2])[0]
            info.signature_algorithms = [
                struct.unpack("!H", data[2 + i : 2 + i + 2])[0] for i in range(0, list_len, 2)
            ]

        if TLSExtensionType.EC_POINT_FORMATS in info.extensions:
            data = info.extensions[TLSExtensionType.EC_POINT_FORMATS].data
            list_len = data[0]
            info.ec_point_formats = [data[1 + i] for i in range(list_len)]

        if TLSExtensionType.ALPN in info.extensions:
            data = info.extensions[TLSExtensionType.ALPN].data
            list_len = struct.unpack("!H", data[:2])[0]
            protocols = []
            pos = 2
            while pos < list_len + 2:
                proto_len = data[pos]
                pos += 1
                protocols.append(data[pos : pos + proto_len].decode("utf-8"))
                pos += proto_len
            info.alpn_protocols = protocols

    @staticmethod
    def find_extension(payload: bytes, ext_type: int) -> Optional[TLSExtension]:
        """
        Находит расширение в TLS ClientHello.
        """
        info = TLSParser.parse_client_hello(payload)
        if not info:
            return None
        return info.extensions.get(ext_type)

    @staticmethod
    def get_sni(payload: bytes) -> Optional[str]:
        """
        Извлекает SNI (Server Name Indication) из ClientHello.
        """
        sni_ext = TLSParser.find_extension(payload, TLSExtensionType.SERVER_NAME)
        if not sni_ext:
            return None

        try:
            data = sni_ext.data
            if len(data) < 5:
                return None
            list_len = struct.unpack("!H", data[0:2])[0]
            if list_len > len(data) - 2:
                return None
            if data[2] != 0:
                return None
            name_len = struct.unpack("!H", data[3:5])[0]
            if name_len > len(data) - 5:
                return None
            if len(data) >= 5 + name_len:
                return data[5 : 5 + name_len].decode("utf-8", errors="ignore")
        except Exception as e:
            LOG.debug(f"Failed to extract SNI: {e}")
        return None

    @staticmethod
    def _is_valid_tls_record(payload: bytes) -> bool:
        """Проверяет, является ли payload валидным TLS записью."""
        if len(payload) < 9:
            return False
        if not payload.startswith(b"\x16\x03"):
            return False
        if payload[5] != 0x01:
            return False
        return True


class TLSHandler:
    """
    Обработчик TLS пакетов для интеграции с системой обхода.
    Предоставляет высокоуровневый интерфейс для работы с TLS.
    """

    def __init__(self):
        self.parser = TLSParser()

    def parse_client_hello(self, payload: bytes) -> Optional[ClientHelloInfo]:
        """Парсит ClientHello пакет."""
        return self.parser.parse_client_hello(payload)

    def extract_sni(self, payload: bytes) -> Optional[str]:
        """Извлекает SNI из TLS пакета."""
        return self.parser.get_sni(payload)

    def find_extension(self, payload: bytes, ext_type: int) -> Optional[TLSExtension]:
        """Находит расширение в TLS пакете."""
        return self.parser.find_extension(payload, ext_type)

    def is_tls_handshake(self, payload: bytes) -> bool:
        """Проверяет, является ли пакет TLS handshake."""
        return self.parser._is_valid_tls_record(payload)

    def get_cipher_suites(self, payload: bytes) -> Optional[List[int]]:
        """Получает список cipher suites из ClientHello."""
        info = self.parse_client_hello(payload)
        return info.cipher_suites if info else None

    def get_supported_groups(self, payload: bytes) -> Optional[List[int]]:
        """Получает поддерживаемые группы из ClientHello."""
        info = self.parse_client_hello(payload)
        return info.supported_groups if info else None

    def get_alpn_protocols(self, payload: bytes) -> Optional[List[str]]:
        """Получает ALPN протоколы из ClientHello."""
        info = self.parse_client_hello(payload)
        return info.alpn_protocols if info else None
