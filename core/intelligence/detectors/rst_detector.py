"""
Детектор RST инъекций

Реализует детекцию:
- RST инъекций с анализом timing
- Анализ источника RST пакетов
- Анализ TCP параметров
- Вычисление подозрительности RST
"""

import logging
import ipaddress
from typing import Any, Dict, List

from .base import BaseDetector

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP

    SCAPY_AVAILABLE = True
except ImportError:
    IP = None
    TCP = None

LOG = logging.getLogger("RSTDetector")


class RSTDetector(BaseDetector):
    """Детектор RST инъекций"""

    def __init__(self):
        self.min_suspicion_score = 0.6
        self.timing_threshold_ms = 100
        self.ttl_threshold = 32

    def _flow_id(self, packet) -> Any:
        """Нестрогий flow-id (без привязки к направлению)."""
        if IP is None or TCP is None:
            return None
        try:
            if IP not in packet or TCP not in packet:
                return None
            a = (str(packet[IP].src), int(packet[TCP].sport))
            b = (str(packet[IP].dst), int(packet[TCP].dport))
            return tuple(sorted((a, b)))
        except Exception:
            return None

    async def detect(
        self, packets: List, domain: str, target_ip: str
    ) -> List:  # List[BlockingEvidence]
        """Детекция RST инъекций с анализом timing и источника"""
        # Import here to avoid circular dependency
        from ..blocking_pattern_detector import BlockingEvidence, BlockingPattern

        evidence_list = []

        if not SCAPY_AVAILABLE or TCP is None or IP is None:
            return evidence_list

        try:
            rst_packets = []
            connection_packets = []

            # Собираем RST пакеты и пакеты соединения
            for packet in packets:
                if TCP in packet and IP in packet:
                    if packet[TCP].flags.R:  # RST flag
                        rst_packets.append(packet)
                    else:
                        connection_packets.append(packet)

            if not rst_packets:
                return evidence_list

            LOG.debug(f"Анализ {len(rst_packets)} RST пакетов")

            for rst_packet in rst_packets:
                flow_id = self._flow_id(rst_packet)
                flow_packets = (
                    [p for p in connection_packets if self._flow_id(p) == flow_id]
                    if flow_id is not None
                    else connection_packets
                )
                # Анализ timing
                timing_analysis = self._analyze_rst_timing(rst_packet, flow_packets)

                # Анализ источника
                source_analysis = self._analyze_rst_source(rst_packet, target_ip)

                # Анализ TCP параметров
                tcp_analysis = self._analyze_rst_tcp_parameters(rst_packet)

                # Определяем подозрительность
                suspicion_score = self._calculate_rst_suspicion_score(
                    timing_analysis, source_analysis, tcp_analysis
                )

                if suspicion_score > self.min_suspicion_score:
                    evidence = BlockingEvidence(
                        pattern=BlockingPattern.RST_INJECTION,
                        confidence=suspicion_score,
                        evidence_data={
                            "domain": domain,
                            "target_ip": target_ip,
                            "rst_src_ip": rst_packet[IP].src,
                            "rst_dst_ip": rst_packet[IP].dst,
                            "rst_ttl": rst_packet[IP].ttl,
                            "rst_seq": rst_packet[TCP].seq,
                            "rst_ack": rst_packet[TCP].ack,
                            "rst_window": rst_packet[TCP].window,
                        },
                        timing_analysis=timing_analysis,
                        packet_analysis={
                            "source_analysis": source_analysis,
                            "tcp_analysis": tcp_analysis,
                            "suspicion_score": suspicion_score,
                        },
                    )
                    evidence_list.append(evidence)

            LOG.debug(f"Найдено {len(evidence_list)} подозрительных RST инъекций")

        except Exception as e:
            LOG.exception("Ошибка детекции RST инъекций")

        return evidence_list

    def _analyze_rst_timing(self, rst_packet, connection_packets: List) -> Dict[str, float]:
        """Анализ timing RST пакета"""
        timing_analysis = {
            "rst_timestamp": float(rst_packet.time),
            "time_since_syn": 0.0,
            "time_since_last_packet": 0.0,
            "timing_suspicion": 0.0,
        }

        try:
            rst_time = float(rst_packet.time)

            # Находим SYN пакет
            syn_packets = [p for p in connection_packets if TCP in p and p[TCP].flags.S]
            if syn_packets:
                syn_time = float(syn_packets[0].time)
                timing_analysis["time_since_syn"] = rst_time - syn_time

            # Находим последний пакет перед RST
            pre_rst_packets = [p for p in connection_packets if float(p.time) < rst_time]
            if pre_rst_packets:
                last_packet_time = max(float(p.time) for p in pre_rst_packets)
                timing_analysis["time_since_last_packet"] = rst_time - last_packet_time

            # Оценка подозрительности timing
            # Очень быстрый RST после SYN подозрителен
            if timing_analysis["time_since_syn"] < 0.1:  # Меньше 100ms
                timing_analysis["timing_suspicion"] += 0.4

            # RST сразу после пакета подозрителен
            if timing_analysis["time_since_last_packet"] < 0.01:  # Меньше 10ms
                timing_analysis["timing_suspicion"] += 0.3

        except Exception as e:
            LOG.debug(f"Ошибка анализа timing RST: {e}")

        return timing_analysis

    def _analyze_rst_source(self, rst_packet, target_ip: str) -> Dict[str, Any]:
        """Анализ источника RST пакета"""
        source_analysis = {
            "rst_src_ip": rst_packet[IP].src,
            "target_ip": target_ip,
            "is_from_target": False,
            "ip_distance": 0,
            "source_suspicion": 0.0,
        }

        try:
            rst_src = rst_packet[IP].src

            # Проверяем, от целевого ли IP
            source_analysis["is_from_target"] = rst_src == target_ip

            # Анализ IP адресов
            try:
                rst_ip = ipaddress.ip_address(rst_src)
                target_ip_obj = ipaddress.ip_address(target_ip)

                # Простая метрика "расстояния" между IP
                if isinstance(rst_ip, ipaddress.IPv4Address) and isinstance(
                    target_ip_obj, ipaddress.IPv4Address
                ):
                    source_analysis["ip_distance"] = abs(int(rst_ip) - int(target_ip_obj))
            except ValueError:
                # Невалидный IP адрес
                pass

            # Оценка подозрительности источника
            if not source_analysis["is_from_target"]:
                # RST не от целевого сервера подозрителен
                source_analysis["source_suspicion"] += 0.5

            # Проверяем TTL
            rst_ttl = rst_packet[IP].ttl
            if rst_ttl < self.ttl_threshold:  # Низкий TTL подозрителен
                source_analysis["source_suspicion"] += 0.3

        except Exception as e:
            LOG.debug(f"Ошибка анализа источника RST: {e}")

        return source_analysis

    def _analyze_rst_tcp_parameters(self, rst_packet) -> Dict[str, Any]:
        """Анализ TCP параметров RST пакета"""
        tcp_analysis = {
            "seq": rst_packet[TCP].seq,
            "ack": rst_packet[TCP].ack,
            "window": rst_packet[TCP].window,
            "tcp_suspicion": 0.0,
        }

        try:
            # Подозрительные TCP параметры
            if rst_packet[TCP].seq == 0:
                tcp_analysis["tcp_suspicion"] += 0.2

            if rst_packet[TCP].ack == 0:
                tcp_analysis["tcp_suspicion"] += 0.2

            if rst_packet[TCP].window == 0:
                tcp_analysis["tcp_suspicion"] += 0.3

        except Exception as e:
            LOG.debug(f"Ошибка анализа TCP параметров: {e}")

        return tcp_analysis

    def _calculate_rst_suspicion_score(
        self, timing_analysis: Dict, source_analysis: Dict, tcp_analysis: Dict
    ) -> float:
        """Вычисление общего score подозрительности RST"""
        total_suspicion = 0.0

        # Суммируем подозрительность из разных анализов
        total_suspicion += timing_analysis.get("timing_suspicion", 0.0)
        total_suspicion += source_analysis.get("source_suspicion", 0.0)
        total_suspicion += tcp_analysis.get("tcp_suspicion", 0.0)

        # Нормализуем к диапазону 0-1
        return min(total_suspicion, 1.0)
