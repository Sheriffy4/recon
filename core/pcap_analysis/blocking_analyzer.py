"""
Blocking Analyzer - анализ блокировок и генерация рекомендаций.

Этот модуль реализует:
- Определение типа блокировки
- Определение поведения DPI
- Сбор доказательств блокировки
- Генерацию рекомендаций по обходу

Requirements: FR-13.2, FR-13.4
Extracted from: intelligent_pcap_analyzer.py (Steps 4-6 refactoring)
"""

import logging
from typing import Dict, List, Any, Tuple, Iterable
from enum import Enum
from dataclasses import dataclass, field

LOG = logging.getLogger("BlockingAnalyzer")


class BlockingType(Enum):
    """Типы блокировок DPI."""

    RST_INJECTION = "rst_injection"
    CONNECTION_TIMEOUT = "connection_timeout"
    TLS_HANDSHAKE_BLOCKING = "tls_handshake_blocking"
    SNI_FILTERING = "sni_filtering"
    DNS_POISONING = "dns_poisoning"
    PACKET_DROP = "packet_drop"
    CONTENT_FILTERING = "content_filtering"
    FRAGMENTATION_REASSEMBLY = "fragmentation_reassembly"
    STATEFUL_TRACKING = "stateful_tracking"
    NO_BLOCKING = "no_blocking"
    UNKNOWN = "unknown"


class DPIBehavior(Enum):
    """Поведение DPI системы."""

    PASSIVE_MONITORING = "passive_monitoring"
    ACTIVE_RST_INJECTION = "active_rst_injection"
    ACTIVE_PACKET_DROP = "active_packet_drop"
    STATEFUL_INSPECTION = "stateful_inspection"
    STATELESS_FILTERING = "stateless_filtering"
    DEEP_PACKET_INSPECTION = "deep_packet_inspection"
    UNKNOWN = "unknown"


@dataclass
class FlowAnalysis:
    """Минимальное определение FlowAnalysis для типизации."""

    blocking_detected: bool = False
    blocking_type: BlockingType = BlockingType.NO_BLOCKING
    packets: List[Any] = field(default_factory=list)


class BlockingAnalyzer:
    """
    Анализатор блокировок и генератор рекомендаций.

    Определяет тип блокировки, поведение DPI и генерирует
    рекомендации по обходу на основе анализа потоков.
    """

    @staticmethod
    def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for x in items:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    def __init__(self):
        """Инициализация анализатора блокировок."""
        LOG.info("BlockingAnalyzer инициализирован")

    def determine_primary_blocking_type(
        self, flow_analyses: List[FlowAnalysis]
    ) -> Tuple[BlockingType, float]:
        """
        Определение основного типа блокировки.

        Args:
            flow_analyses: Список анализов потоков

        Returns:
            Tuple (primary_blocking_type, confidence)
        """
        if not flow_analyses:
            return BlockingType.UNKNOWN, 0.0

        def _bt_value(bt: Any) -> str:
            # Accept local Enum, foreign Enum, or plain string
            return getattr(bt, "value", bt) if bt is not None else BlockingType.UNKNOWN.value

        # Подсчет типов блокировок (by normalized value, to avoid Enum-class mismatch)
        blocking_counts: Dict[str, int] = {}
        total_flows = len(flow_analyses)
        blocked_flows = 0

        for flow in flow_analyses:
            if flow.blocking_detected:
                blocked_flows += 1
                bt_val = _bt_value(flow.blocking_type)
                blocking_counts[bt_val] = blocking_counts.get(bt_val, 0) + 1

        if blocked_flows == 0:
            return BlockingType.NO_BLOCKING, 1.0

        # Находим наиболее частый тип блокировки
        primary_val = max(blocking_counts.items(), key=lambda x: x[1])[0]
        try:
            primary_type = BlockingType(primary_val)
        except Exception:
            primary_type = BlockingType.UNKNOWN

        # Вычисляем уверенность
        confidence = blocking_counts.get(primary_val, 0) / total_flows

        return primary_type, confidence

    def determine_dpi_behavior(self, flow_analyses: List[FlowAnalysis]) -> DPIBehavior:
        """
        Определение поведения DPI системы.

        Args:
            flow_analyses: Список анализов потоков

        Returns:
            DPIBehavior
        """
        if not flow_analyses:
            return DPIBehavior.UNKNOWN

        def _bt_value(bt: Any) -> str:
            # Accept local Enum, foreign Enum, or plain string
            return getattr(bt, "value", bt) if bt is not None else BlockingType.UNKNOWN.value

        # Анализ паттернов блокировки (compare by normalized values to avoid Enum mismatch)
        has_rst_injection = any(
            _bt_value(f.blocking_type) == BlockingType.RST_INJECTION.value for f in flow_analyses
        )
        has_packet_drop = any(
            _bt_value(f.blocking_type) == BlockingType.PACKET_DROP.value for f in flow_analyses
        )
        has_content_filtering = any(
            _bt_value(f.blocking_type) == BlockingType.CONTENT_FILTERING.value
            for f in flow_analyses
        )
        has_stateful_issues = any(
            _bt_value(f.blocking_type) == BlockingType.STATEFUL_TRACKING.value
            for f in flow_analyses
        )

        if has_rst_injection:
            return DPIBehavior.ACTIVE_RST_INJECTION
        elif has_packet_drop:
            return DPIBehavior.ACTIVE_PACKET_DROP
        elif has_content_filtering:
            return DPIBehavior.DEEP_PACKET_INSPECTION
        elif has_stateful_issues:
            return DPIBehavior.STATEFUL_INSPECTION
        else:
            return DPIBehavior.PASSIVE_MONITORING

    def collect_blocking_evidence(self, flow_analyses: List[FlowAnalysis]) -> Dict[str, Any]:
        """
        Сбор доказательств блокировки.

        Args:
            flow_analyses: Список анализов потоков

        Returns:
            Словарь с доказательствами блокировки
        """
        evidence = {
            "total_flows": len(flow_analyses),
            "blocked_flows": sum(1 for f in flow_analyses if f.blocking_detected),
            "blocking_types": {},
            "suspicious_patterns": [],
            "timing_anomalies": [],
            "technical_indicators": {},
        }

        # Подсчет типов блокировок
        for flow in flow_analyses:
            if flow.blocking_detected:
                blocking_type = getattr(flow.blocking_type, "value", str(flow.blocking_type))
                evidence["blocking_types"][blocking_type] = (
                    evidence["blocking_types"].get(blocking_type, 0) + 1
                )

        # Сбор подозрительных паттернов
        for flow in flow_analyses:
            for packet in flow.packets:
                if hasattr(packet, "is_suspicious") and packet.is_suspicious:
                    if hasattr(packet, "suspicious_reasons"):
                        evidence["suspicious_patterns"].extend(packet.suspicious_reasons)

        # Удаление дубликатов (stable)
        evidence["suspicious_patterns"] = self._dedupe_preserve_order(
            evidence["suspicious_patterns"]
        )

        return evidence

    def generate_bypass_recommendations(
        self,
        primary_blocking_type: BlockingType,
        dpi_behavior: DPIBehavior,
        flow_analyses: List[FlowAnalysis] = None,
    ) -> List[str]:
        """
        Генерация рекомендаций по обходу блокировки.

        Args:
            primary_blocking_type: Основной тип блокировки
            dpi_behavior: Поведение DPI
            flow_analyses: Список анализов потоков (опционально)

        Returns:
            Список рекомендаций
        """
        recommendations = []

        # Normalize inputs to string values to tolerate foreign Enum instances
        primary_val = getattr(primary_blocking_type, "value", primary_blocking_type)
        dpi_val = getattr(dpi_behavior, "value", dpi_behavior)

        # Рекомендации на основе типа блокировки
        if primary_val == BlockingType.RST_INJECTION.value:
            recommendations.extend(
                [
                    "Используйте пакеты с низким TTL для обхода RST инъекций",
                    "Попробуйте атаки с нарушением порядка пакетов (disorder)",
                    "Рассмотрите использование fake пакетов с badseq/badsum",
                ]
            )

        elif primary_val == BlockingType.SNI_FILTERING.value:
            recommendations.extend(
                [
                    "Фрагментируйте TLS ClientHello на уровне SNI",
                    "Используйте fake SNI пакеты перед настоящим",
                    "Попробуйте multisplit для разбиения SNI",
                ]
            )

        elif primary_val == BlockingType.TLS_HANDSHAKE_BLOCKING.value:
            recommendations.extend(
                [
                    "Фрагментируйте TLS записи на мелкие части",
                    "Используйте обфускацию TLS handshake",
                    "Попробуйте изменение порядка TLS расширений",
                ]
            )

        elif primary_val == BlockingType.FRAGMENTATION_REASSEMBLY.value:
            recommendations.extend(
                [
                    "DPI собирает фрагменты - переключитесь на timing атаки",
                    "Используйте packet reordering вместо фрагментации",
                    "Попробуйте sequence overlap атаки",
                ]
            )

        elif primary_val == BlockingType.CONNECTION_TIMEOUT.value:
            recommendations.extend(
                [
                    "Проверьте доступность целевого сервера",
                    "Попробуйте альтернативные порты или протоколы",
                    "Рассмотрите использование proxy или VPN",
                ]
            )

        elif primary_val == BlockingType.PACKET_DROP.value:
            recommendations.extend(
                [
                    "Обнаружена потеря пакетов - проверьте сетевое соединение",
                    "Попробуйте использовать TCP retransmission обходы",
                    "Рассмотрите использование альтернативных маршрутов",
                ]
            )

        elif primary_val == BlockingType.CONTENT_FILTERING.value:
            recommendations.extend(
                [
                    "DPI анализирует содержимое - используйте шифрование",
                    "Попробуйте обфускацию payload",
                    "Рассмотрите использование протокольных туннелей",
                ]
            )

        # Рекомендации на основе поведения DPI
        if dpi_val == DPIBehavior.ACTIVE_RST_INJECTION.value:
            recommendations.append("DPI активно инжектирует RST - используйте TTL манипуляции")

        elif dpi_val == DPIBehavior.STATEFUL_INSPECTION.value:
            recommendations.append("DPI отслеживает состояние - используйте stateless обходы")

        elif dpi_val == DPIBehavior.DEEP_PACKET_INSPECTION.value:
            recommendations.append("DPI анализирует содержимое - используйте обфускацию payload")

        elif dpi_val == DPIBehavior.ACTIVE_PACKET_DROP.value:
            recommendations.append("DPI активно отбрасывает пакеты - используйте packet disorder")

        # Удаление дубликатов (stable)
        return self._dedupe_preserve_order(recommendations)
