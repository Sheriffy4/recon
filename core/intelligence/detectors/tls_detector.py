"""
Детектор прерываний TLS handshake

Реализует детекцию:
- Прерывания TLS handshake
- Анализ TLS alerts
- Timing анализ TLS соединений
"""

from __future__ import annotations

import logging
from typing import Dict, List

from .base import BaseDetector

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TLS
    from scapy.layers.tls.record import TLSClientHello, TLSServerHello, TLSAlert

    SCAPY_AVAILABLE = True
except ImportError:
    IP = None
    TLS = None
    TLSClientHello = None
    TLSServerHello = None
    TLSAlert = None

LOG = logging.getLogger("TLSDetector")


class TLSDetector(BaseDetector):
    """Детектор прерываний TLS handshake"""

    def __init__(self):
        self.min_confidence = 0.4

    async def detect(
        self, packets: List, domain: str, target_ip: str
    ) -> List:  # List[BlockingEvidence]
        """Детекция прерываний TLS handshake."""
        # Import here to avoid circular dependency
        from ..blocking_pattern_detector import BlockingEvidence, BlockingPattern

        evidence_list = []

        if not SCAPY_AVAILABLE or TLS is None:
            return evidence_list

        try:
            tls_packets = [p for p in packets if TLS in p]
            if not tls_packets:
                return evidence_list

            LOG.debug(f"Анализ TLS handshake: {len(tls_packets)} TLS пакетов")

            # Анализируем handshake последовательность
            client_hello_count = 0
            server_hello_count = 0
            tls_alerts = []

            for packet in tls_packets:
                # Легкая фильтрация по target_ip если есть IP-слой
                try:
                    if IP is not None and IP in packet and target_ip:
                        if str(packet[IP].src) != target_ip and str(packet[IP].dst) != target_ip:
                            continue
                except Exception:
                    pass

                if TLSClientHello and TLSClientHello in packet:
                    client_hello_count += 1

                if TLSServerHello and TLSServerHello in packet:
                    server_hello_count += 1

                if TLSAlert and TLSAlert in packet:
                    alert_info = {
                        "timestamp": float(packet.time),
                        "src_ip": str(packet[IP].src) if IP is not None and IP in packet else "",
                        "level": packet[TLSAlert].level,
                        "description": packet[TLSAlert].description,
                    }
                    tls_alerts.append(alert_info)

            # Анализируем паттерны прерывания
            confidence = 0.0
            interruption_indicators = []

            # Client Hello без Server Hello
            if client_hello_count > 0 and server_hello_count == 0:
                interruption_indicators.append("no_server_hello")
                confidence += 0.6

            # Множественные Client Hello (повторные попытки)
            if client_hello_count > 1:
                interruption_indicators.append("multiple_client_hello")
                confidence += 0.3

            # TLS Alert'ы
            if tls_alerts:
                for alert in tls_alerts:
                    if alert["level"] == 2:  # Fatal alert
                        interruption_indicators.append(f"fatal_alert_{alert['description']}")
                        confidence += 0.4

            # Создаем evidence если найдены индикаторы
            if interruption_indicators and confidence > self.min_confidence:
                evidence = BlockingEvidence(
                    pattern=BlockingPattern.TLS_HANDSHAKE_INTERRUPT,
                    confidence=min(confidence, 1.0),
                    evidence_data={
                        "domain": domain,
                        "target_ip": target_ip,
                        "client_hello_count": client_hello_count,
                        "server_hello_count": server_hello_count,
                        "tls_alerts": tls_alerts,
                        "interruption_indicators": interruption_indicators,
                    },
                    timing_analysis=self._analyze_tls_timing(tls_packets),
                )
                evidence_list.append(evidence)

            LOG.debug(f"Найдено {len(evidence_list)} прерываний TLS handshake")

        except Exception:
            LOG.exception("Ошибка детекции TLS прерываний")

        return evidence_list

    def _analyze_tls_timing(self, tls_packets: List) -> Dict[str, float]:
        """Анализ timing TLS handshake"""
        timing_analysis = {
            "handshake_duration": 0.0,
            "first_packet_time": 0.0,
            "last_packet_time": 0.0,
        }

        try:
            if tls_packets:
                timestamps = [float(p.time) for p in tls_packets]
                timing_analysis["first_packet_time"] = min(timestamps)
                timing_analysis["last_packet_time"] = max(timestamps)
                timing_analysis["handshake_duration"] = max(timestamps) - min(timestamps)

        except Exception as e:
            LOG.debug(f"Ошибка анализа TLS timing: {e}")

        return timing_analysis
