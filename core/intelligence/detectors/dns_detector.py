"""
Детектор DNS poisoning и подмены ответов

Реализует детекцию:
- DNS poisoning
- Подмены DNS ответов
- Анализ timing DNS запросов/ответов
"""

import logging
import ipaddress
from typing import Any, Dict, List

from .base import BaseDetector
from ..utils.dns_utils import extract_dns_answers

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import DNS, IP

    SCAPY_AVAILABLE = True
except ImportError:
    DNS = None
    IP = None

LOG = logging.getLogger("DNSDetector")


class DNSDetector(BaseDetector):
    """Детектор DNS poisoning и манипуляций"""

    def __init__(self):
        self.suspicious_ips = [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.1",
            "192.168.1.1",
            "1.1.1.1",
            "8.8.8.8",  # Иногда используются для блокировки
        ]

    def _get_ip_src(self, packet) -> str:
        if IP is None:
            return ""
        try:
            if IP in packet:
                return str(packet[IP].src)
        except Exception:
            return ""
        return ""

    async def detect(
        self, packets: List, domain: str, target_ip: str
    ) -> List:  # List[BlockingEvidence]
        """Детекция DNS poisoning и подмены ответов"""
        # Import here to avoid circular dependency
        from ..blocking_pattern_detector import BlockingEvidence, BlockingPattern

        evidence_list = []

        if not SCAPY_AVAILABLE or DNS is None:
            return evidence_list

        try:
            dns_queries = []
            dns_responses = []

            # Собираем DNS пакеты
            for packet in packets:
                if DNS in packet:
                    if packet[DNS].qr == 0:  # Query
                        dns_queries.append(packet)
                    elif packet[DNS].qr == 1:  # Response
                        dns_responses.append(packet)

            if not dns_queries or not dns_responses:
                return evidence_list

            LOG.debug(f"Анализ DNS: {len(dns_queries)} запросов, {len(dns_responses)} ответов")

            # Анализируем каждый ответ
            for response in dns_responses:
                suspicion_indicators = []
                confidence = 0.0

                # Проверяем код ответа
                if response[DNS].rcode == 3:  # NXDOMAIN
                    suspicion_indicators.append("NXDOMAIN_for_existing_domain")
                    confidence += 0.4

                # Анализируем ответы
                if response[DNS].ancount > 0:
                    for i in range(response[DNS].ancount):
                        try:
                            answer = response[DNS].an[i]
                            answer_data = str(answer.rdata)

                            # Подозрительные IP адреса
                            if answer_data in self.suspicious_ips:
                                suspicion_indicators.append(f"suspicious_ip_{answer_data}")
                                confidence += 0.3

                            # Проверяем на локальные адреса
                            try:
                                ip = ipaddress.ip_address(answer_data)
                                if ip.is_private or ip.is_loopback:
                                    suspicion_indicators.append(f"private_ip_{answer_data}")
                                    confidence += 0.2
                            except ValueError:
                                # Не IP адрес (например, CNAME)
                                pass

                        except Exception as e:
                            LOG.debug(f"Ошибка анализа DNS ответа: {e}")

                # Анализ timing
                timing_analysis = self._analyze_dns_timing(response, dns_queries)
                if timing_analysis.get("too_fast", False):
                    suspicion_indicators.append("response_too_fast")
                    confidence += 0.2

                # Если найдены подозрительные индикаторы
                if suspicion_indicators and confidence > 0.3:
                    evidence = BlockingEvidence(
                        pattern=BlockingPattern.DNS_POISONING,
                        confidence=min(confidence, 1.0),
                        evidence_data={
                            "domain": domain,
                            "target_ip": target_ip,
                            "dns_response_code": response[DNS].rcode,
                            "dns_answers": extract_dns_answers(response),
                            "suspicion_indicators": suspicion_indicators,
                            "response_src_ip": self._get_ip_src(response),
                        },
                        timing_analysis=timing_analysis,
                    )
                    evidence_list.append(evidence)

            LOG.debug(f"Найдено {len(evidence_list)} случаев DNS poisoning")

        except Exception as e:
            LOG.exception("Ошибка детекции DNS poisoning")

        return evidence_list

    def _analyze_dns_timing(self, response, queries: List) -> Dict[str, Any]:
        """Анализ timing DNS ответов"""
        timing_analysis = {"response_time": 0.0, "too_fast": False, "too_slow": False}

        try:
            response_time = float(response.time)

            # Находим соответствующий запрос
            matching_queries = [q for q in queries if q[DNS].id == response[DNS].id]
            if matching_queries:
                # Берем ближайший запрос ДО ответа (если есть)
                candidates = [q for q in matching_queries if float(q.time) <= response_time]
                if candidates:
                    query = max(candidates, key=lambda q: float(q.time))
                else:
                    query = matching_queries[0]

                query_time = float(query.time)
                response_delay = response_time - query_time
                timing_analysis["response_time"] = response_delay

                # Слишком быстрый ответ подозрителен (меньше 1ms)
                if response_delay < 0.001:
                    timing_analysis["too_fast"] = True

                # Слишком медленный ответ тоже может быть подозрителен
                if response_delay > 10.0:
                    timing_analysis["too_slow"] = True

        except Exception as e:
            LOG.debug(f"Ошибка анализа DNS timing: {e}")

        return timing_analysis
