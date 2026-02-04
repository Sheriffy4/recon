"""
TLS Analyzer - анализ TLS handshake для детекции блокировок.

Этот модуль предоставляет функциональность для анализа TLS handshake процесса
и определения различных типов блокировок на уровне TLS.
"""

import logging
from typing import Dict, List, Any

from core.packet.raw_packet_engine import RawPacket, TCPHeader
from core.packet.packet_parser_utils import parse_tcp_packet_headers

LOG = logging.getLogger("TLSAnalyzer")


class TLSAnalyzer:
    """
    Анализатор TLS handshake для детекции блокировок.

    Основные функции:
    - Детекция ClientHello и ServerHello
    - Анализ TLS Alert сообщений
    - Определение неудач TLS handshake
    - Проверка установления TCP соединения
    """

    def analyze_tls_handshake(self, tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Детальный анализ TLS handshake для обнаружения блокировок.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)

        Returns:
            Dict с результатами анализа TLS handshake
        """
        analysis = {
            "has_client_hello": False,
            "has_server_hello": False,
            "connection_established": False,
            "handshake_failed": False,
            "client_hello_count": 0,
            "server_hello_count": 0,
            "tls_alerts": [],
        }

        # Проверяем установление TCP соединения
        syn_packets = []
        syn_ack_packets = []

        for p in tcp_packets:
            headers = parse_tcp_packet_headers(p)
            if headers is None:
                continue

            _, tcp_header, _ = headers

            # SYN без ACK
            if (tcp_header.flags & TCPHeader.FLAG_SYN) and not (
                tcp_header.flags & TCPHeader.FLAG_ACK
            ):
                syn_packets.append(p)
            # SYN-ACK
            elif (tcp_header.flags & TCPHeader.FLAG_SYN) and (
                tcp_header.flags & TCPHeader.FLAG_ACK
            ):
                syn_ack_packets.append(p)

        if syn_packets and syn_ack_packets:
            analysis["connection_established"] = True

        # Анализируем TLS пакеты
        for packet in tcp_packets:
            if packet.payload:
                payload = packet.payload

                # ClientHello detection
                if self.is_client_hello_payload(payload):
                    analysis["has_client_hello"] = True
                    analysis["client_hello_count"] += 1

                # ServerHello detection
                elif self.is_server_hello_payload(payload):
                    analysis["has_server_hello"] = True
                    analysis["server_hello_count"] += 1

                # TLS Alert detection
                elif self.is_tls_alert(payload):
                    alert_info = self.parse_tls_alert(payload)
                    analysis["tls_alerts"].append(alert_info)

        # Определяем неудачу handshake
        if analysis["has_client_hello"] and not analysis["has_server_hello"]:
            if analysis["connection_established"]:
                # TCP соединение есть, но TLS handshake не завершен - блокировка контента
                analysis["handshake_failed"] = True

        return analysis

    def is_client_hello_payload(self, payload: bytes) -> bool:
        """
        Проверка, является ли payload TLS ClientHello.

        Args:
            payload: Байты payload для проверки

        Returns:
            bool - True если это ClientHello
        """
        try:
            # TLS Record: Type(1) + Version(2) + Length(2) + Handshake Header
            # Handshake: Type(1) + Length(3) + ...
            if len(payload) < 6:
                return False

            # TLS Record Type: Handshake (0x16)
            if payload[0] != 0x16:
                return False

            # TLS Version (обычно 0x0301, 0x0302, 0x0303)
            if len(payload) < 3 or payload[1] not in [0x03]:
                return False

            # Handshake Type: ClientHello (0x01)
            if len(payload) < 6 or payload[5] != 0x01:
                return False

            return True
        except Exception as e:
            LOG.debug(f"Ошибка проверки ClientHello: {e}")
            return False

    def is_server_hello_payload(self, payload: bytes) -> bool:
        """
        Проверка, является ли payload TLS ServerHello.

        Args:
            payload: Байты payload для проверки

        Returns:
            bool - True если это ServerHello
        """
        try:
            if len(payload) < 6:
                return False

            # TLS Record Type: Handshake (0x16)
            if payload[0] != 0x16:
                return False

            # Handshake Type: ServerHello (0x02)
            if payload[5] != 0x02:
                return False

            return True
        except Exception as e:
            LOG.debug(f"Ошибка проверки ServerHello: {e}")
            return False

    def is_tls_alert(self, payload: bytes) -> bool:
        """
        Проверка, является ли payload TLS Alert.

        Args:
            payload: Байты payload для проверки

        Returns:
            bool - True если это TLS Alert
        """
        try:
            # TLS Record Type: Alert (0x15)
            return len(payload) >= 1 and payload[0] == 0x15
        except Exception as e:
            LOG.debug(f"Ошибка проверки TLS Alert: {e}")
            return False

    def parse_tls_alert(self, payload: bytes) -> Dict[str, Any]:
        """
        Парсинг TLS Alert сообщения.

        Args:
            payload: Байты TLS Alert

        Returns:
            Dict с информацией об Alert
        """
        try:
            if len(payload) >= 7:
                alert_level = payload[5]  # Warning (1) or Fatal (2)
                alert_description = payload[6]

                return {
                    "level": "warning" if alert_level == 1 else "fatal",
                    "description_code": alert_description,
                    "description": self.get_tls_alert_description(alert_description),
                }
        except Exception as e:
            LOG.debug(f"Ошибка парсинга TLS Alert: {e}")

        return {"level": "unknown", "description": "parse_error"}

    def get_tls_alert_description(self, code: int) -> str:
        """
        Получение описания TLS Alert по коду.

        Args:
            code: Код TLS Alert

        Returns:
            str - Описание Alert
        """
        alert_descriptions = {
            0: "close_notify",
            10: "unexpected_message",
            20: "bad_record_mac",
            21: "decryption_failed",
            22: "record_overflow",
            30: "decompression_failure",
            40: "handshake_failure",
            41: "no_certificate",
            42: "bad_certificate",
            43: "unsupported_certificate",
            44: "certificate_revoked",
            45: "certificate_expired",
            46: "certificate_unknown",
            47: "illegal_parameter",
            48: "unknown_ca",
            49: "access_denied",
            50: "decode_error",
            51: "decrypt_error",
            70: "protocol_version",
            71: "insufficient_security",
            80: "internal_error",
            90: "user_canceled",
            100: "no_renegotiation",
            110: "unsupported_extension",
        }

        return alert_descriptions.get(code, f"unknown_alert_{code}")

    def analyze_tls_from_json(self, json_data: Dict) -> bool:
        """
        Анализ TLS проблем из JSON данных.

        Args:
            json_data: JSON данные с информацией о пакетах

        Returns:
            bool - True если обнаружены TLS проблемы
        """
        flows = json_data.get("flows", {})

        for flow_name, packets in flows.items():
            for packet in packets:
                # Поиск TLS Alert или handshake failures
                if "TLS" in packet.get("info", ""):
                    if "Alert" in packet.get("info", ""):
                        return True
                    if "Handshake Failure" in packet.get("info", ""):
                        return True

        return False
