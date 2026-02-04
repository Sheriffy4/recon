"""
Детектор HTTP редиректов и content filtering

Реализует детекцию:
- HTTP редиректов (301, 302, 307, 308)
- Блокирующих страниц
- Content filtering
"""

import logging
import re
import statistics
from typing import Dict, List

from .base import BaseDetector

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    IP = None
    TCP = None
    Raw = None

LOG = logging.getLogger("HTTPDetector")

_RE_LOCATION = re.compile(r"Location:\s*([^\r\n]+)", re.IGNORECASE)


class HTTPDetector(BaseDetector):
    """Детектор HTTP редиректов и content filtering"""

    def __init__(self):
        self.min_confidence = 0.3
        self.blocking_keywords = [
            "blocked",
            "forbidden",
            "access denied",
            "restricted",
            "firewall",
            "filter",
            "censored",
            "unavailable",
        ]
        self.content_blocking_keywords = [
            "content blocked",
            "content filtered",
            "inappropriate content",
            "parental control",
            "web filter",
            "content restriction",
        ]

    async def detect(
        self, packets: List, domain: str, target_ip: str
    ) -> List:  # List[BlockingEvidence]
        """Детекция HTTP редиректов и блокировок"""
        # Import here to avoid circular dependency
        from ..blocking_pattern_detector import BlockingEvidence, BlockingPattern

        evidence_list = []

        if not SCAPY_AVAILABLE or TCP is None or Raw is None or IP is None:
            return evidence_list

        try:
            # Детекция HTTP редиректов
            redirect_evidence = await self._detect_http_redirects(packets)
            evidence_list.extend(redirect_evidence)

            # Детекция content filtering
            content_evidence = await self._detect_content_filtering(packets)
            evidence_list.extend(content_evidence)

        except Exception as e:
            LOG.exception("Ошибка детекции HTTP")

        return evidence_list

    async def _detect_http_redirects(self, packets: List) -> List:
        """Детекция HTTP редиректов и блокировок"""
        from ..blocking_pattern_detector import BlockingEvidence, BlockingPattern

        evidence_list = []

        def _decode_payload(packet) -> str:
            try:
                return packet[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                return ""

        try:
            http_packets = []

            # Ищем HTTP пакеты
            for packet in packets:
                if TCP in packet and Raw in packet:
                    payload = _decode_payload(packet)
                    if "HTTP/" in payload:
                        http_packets.append((packet, payload))

            if not http_packets:
                return evidence_list

            LOG.debug(f"Анализ HTTP: {len(http_packets)} HTTP пакетов")

            for packet, payload in http_packets:
                confidence = 0.0
                redirect_indicators = []

                # Проверяем статус коды редиректов
                redirect_codes = ["301", "302", "303", "307", "308"]
                for code in redirect_codes:
                    if f"HTTP/1.1 {code}" in payload or f"HTTP/1.0 {code}" in payload:
                        redirect_indicators.append(f"redirect_{code}")
                        confidence += 0.4

                # Проверяем блокирующие страницы
                payload_lower = payload.lower()
                for keyword in self.blocking_keywords:
                    if keyword in payload_lower:
                        redirect_indicators.append(f"blocking_keyword_{keyword}")
                        confidence += 0.3

                # Анализируем Location header
                location_match = _RE_LOCATION.search(payload)
                if location_match:
                    location = location_match.group(1).strip()

                    # Подозрительные редиректы
                    suspicious_domains = ["localhost", "127.0.0.1", "blocked.com", "warning."]
                    if any(sus_domain in location.lower() for sus_domain in suspicious_domains):
                        redirect_indicators.append(f"suspicious_redirect_{location}")
                        confidence += 0.5

                # Создаем evidence если найдены индикаторы
                if redirect_indicators and confidence > self.min_confidence:
                    src_ip = ""
                    dst_ip = ""
                    try:
                        if IP in packet:
                            src_ip = str(packet[IP].src)
                            dst_ip = str(packet[IP].dst)
                    except Exception:
                        pass
                    evidence = BlockingEvidence(
                        pattern=BlockingPattern.HTTP_REDIRECT,
                        confidence=min(confidence, 1.0),
                        evidence_data={
                            "http_payload_snippet": payload[:500],  # Первые 500 символов
                            "redirect_indicators": redirect_indicators,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                        },
                        timing_analysis={"packet_time": float(packet.time)},
                    )
                    evidence_list.append(evidence)

            LOG.debug(f"Найдено {len(evidence_list)} HTTP редиректов/блокировок")

        except Exception as e:
            LOG.exception("Ошибка детекции HTTP редиректов")

        return evidence_list

    async def _detect_content_filtering(self, packets: List) -> List:
        """Детекция content filtering"""
        from ..blocking_pattern_detector import BlockingEvidence, BlockingPattern

        evidence_list = []

        try:
            # Анализируем паттерны content filtering
            content_indicators = []
            confidence = 0.0

            # Поиск блокирующего контента в пакетах
            for packet in packets:
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode("utf-8", errors="ignore")
                        payload_lower = payload.lower()

                        for keyword in self.content_blocking_keywords:
                            if keyword in payload_lower:
                                content_indicators.append(
                                    f"content_blocking_{keyword.replace(' ', '_')}"
                                )
                                confidence += 0.4

                    except Exception:
                        pass

            # Анализ размеров пакетов (маленькие пакеты могут указывать на блокировку)
            packet_sizes = [len(packet) for packet in packets if Raw in packet]
            if packet_sizes:
                avg_size = statistics.mean(packet_sizes)
                if avg_size < 100:  # Очень маленькие пакеты
                    content_indicators.append("small_packet_sizes")
                    confidence += 0.2

            # Создаем evidence если найдены индикаторы
            if content_indicators and confidence > self.min_confidence:
                avg_size = statistics.mean(packet_sizes) if packet_sizes else 0
                evidence = BlockingEvidence(
                    pattern=BlockingPattern.CONTENT_FILTERING,
                    confidence=min(confidence, 1.0),
                    evidence_data={
                        "content_indicators": content_indicators,
                        "average_packet_size": avg_size,
                        "total_packets_analyzed": len(packets),
                    },
                )
                evidence_list.append(evidence)

        except Exception as e:
            LOG.exception("Ошибка детекции content filtering")

        return evidence_list
