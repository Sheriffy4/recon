"""
Система анализа паттернов блокировки

Задача 8.2: Создать систему анализа паттернов блокировки
- BlockingPatternDetector для выявления типов DPI блокировок
- Детекция RST-инъекций с анализом timing и источника пакетов
- Анализатор TLS handshake с выявлением точки обрыва соединения
- Детектор DNS манипуляций и подмены ответов
- Анализ HTTP/HTTPS редиректов и блокировок по содержимому
- Система классификации блокировок по уровням агрессивности DPI
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List
import statistics

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    import scapy  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG = logging.getLogger("BlockingPatternDetector")


class DPIAggressivenessLevel(Enum):
    """Уровни агрессивности DPI"""

    LOW = "low"  # Простая фильтрация
    MEDIUM = "medium"  # Активная блокировка
    HIGH = "high"  # Глубокая инспекция
    EXTREME = "extreme"  # Продвинутые методы


class BlockingPattern(Enum):
    """Паттерны блокировки"""

    RST_INJECTION = "rst_injection"
    DNS_POISONING = "dns_poisoning"
    TLS_HANDSHAKE_INTERRUPT = "tls_handshake_interrupt"
    HTTP_REDIRECT = "http_redirect"
    CONTENT_FILTERING = "content_filtering"
    CONNECTION_TIMEOUT = "connection_timeout"
    PACKET_DROP = "packet_drop"
    BANDWIDTH_THROTTLING = "bandwidth_throttling"


@dataclass
class BlockingEvidence:
    """Доказательства блокировки"""

    pattern: BlockingPattern
    confidence: float
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    timing_analysis: Dict[str, float] = field(default_factory=dict)
    packet_analysis: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.now)


@dataclass
class DPICharacteristics:
    """Характеристики DPI системы"""

    aggressiveness_level: DPIAggressivenessLevel
    detected_patterns: List[BlockingPattern] = field(default_factory=list)
    timing_signatures: Dict[str, float] = field(default_factory=dict)
    behavioral_indicators: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


class BlockingPatternDetector:
    """
    Детектор паттернов блокировки DPI

    Реализует требования FR-15.3, FR-15.4:
    - Классификация типов блокировок
    - Корректировка стратегий на основе анализа паттернов
    """

    def __init__(self):
        # Инициализируем реестр детекторов
        from .detectors.registry import DetectorRegistry

        self.detector_registry = DetectorRegistry()

        # Правила и пороги (для обратной совместимости)
        self.detection_rules = self._initialize_detection_rules()
        self.timing_thresholds = self._initialize_timing_thresholds()

        # Кэш анализа
        self.analysis_cache = {}

        # Статистика детекции
        self.stats = {
            "patterns_detected": 0,
            "rst_injections_found": 0,
            "dns_poisoning_found": 0,
            "tls_interrupts_found": 0,
            "http_redirects_found": 0,
            "connection_timeouts_found": 0,
            "analysis_time_total": 0.0,
        }

        LOG.info("✅ BlockingPatternDetector инициализирован")

    async def detect_blocking_patterns(
        self, packets: List, domain: str, target_ip: str
    ) -> List[BlockingEvidence]:
        """
        Основной метод детекции паттернов блокировки

        Args:
            packets: Список пакетов для анализа
            domain: Доменное имя
            target_ip: IP адрес цели

        Returns:
            Список найденных паттернов блокировки
        """
        start_time = time.time()

        LOG.info(f"🔍 Детекция паттернов блокировки для {domain} ({target_ip})")

        if not SCAPY_AVAILABLE:
            LOG.error("❌ Scapy недоступен для анализа пакетов")
            return []

        try:
            # Используем реестр детекторов для выполнения всех проверок
            evidence_list = await self.detector_registry.detect_all(packets, domain, target_ip)

            # Обновляем статистику из реестра
            detector_stats = self.detector_registry.get_detector_stats()
            for detector_name, stats in detector_stats.items():
                stat_key = stats.get("stat_key")
                if stat_key and stat_key in self.stats:
                    self.stats[stat_key] = stats["detections"]

            # Обновляем общую статистику
            analysis_time = time.time() - start_time
            self.stats["patterns_detected"] += len(evidence_list)
            self.stats["analysis_time_total"] += analysis_time

            LOG.info(
                f"✅ Детекция завершена за {analysis_time:.2f}s: найдено {len(evidence_list)} паттернов"
            )

            return evidence_list

        except Exception as e:
            LOG.error(f"❌ Ошибка детекции паттернов: {e}", exc_info=True)
            return []

    def classify_dpi_aggressiveness(
        self, evidence_list: List[BlockingEvidence]
    ) -> DPICharacteristics:
        """Классификация уровня агрессивности DPI"""
        try:
            if not evidence_list:
                return DPICharacteristics(
                    aggressiveness_level=DPIAggressivenessLevel.LOW, confidence=0.0
                )

            # Анализируем типы найденных паттернов
            pattern_counts = {}
            total_confidence = 0.0

            for evidence in evidence_list:
                pattern = evidence.pattern
                if pattern not in pattern_counts:
                    pattern_counts[pattern] = 0
                pattern_counts[pattern] += 1
                total_confidence += evidence.confidence

            avg_confidence = total_confidence / len(evidence_list)
            detected_patterns = list(pattern_counts.keys())

            # Определяем уровень агрессивности
            aggressiveness_score = 0

            # RST инъекции - средний уровень
            if BlockingPattern.RST_INJECTION in pattern_counts:
                aggressiveness_score += 2

            # DNS poisoning - высокий уровень
            if BlockingPattern.DNS_POISONING in pattern_counts:
                aggressiveness_score += 3

            # TLS прерывания - высокий уровень
            if BlockingPattern.TLS_HANDSHAKE_INTERRUPT in pattern_counts:
                aggressiveness_score += 3

            # Content filtering - экстремальный уровень
            if BlockingPattern.CONTENT_FILTERING in pattern_counts:
                aggressiveness_score += 4

            # HTTP редиректы - низкий уровень
            if BlockingPattern.HTTP_REDIRECT in pattern_counts:
                aggressiveness_score += 1

            # Connection timeout - низкий уровень
            if BlockingPattern.CONNECTION_TIMEOUT in pattern_counts:
                aggressiveness_score += 1

            # Определяем уровень на основе score
            if aggressiveness_score >= 8:
                level = DPIAggressivenessLevel.EXTREME
            elif aggressiveness_score >= 5:
                level = DPIAggressivenessLevel.HIGH
            elif aggressiveness_score >= 3:
                level = DPIAggressivenessLevel.MEDIUM
            else:
                level = DPIAggressivenessLevel.LOW

            # Создаем характеристики DPI
            characteristics = DPICharacteristics(
                aggressiveness_level=level,
                detected_patterns=detected_patterns,
                confidence=avg_confidence,
            )

            # Добавляем timing signatures
            timing_signatures = {}
            for evidence in evidence_list:
                if evidence.timing_analysis:
                    for key, value in evidence.timing_analysis.items():
                        if isinstance(value, (int, float)):
                            if key not in timing_signatures:
                                timing_signatures[key] = []
                            timing_signatures[key].append(value)

            # Усредняем timing signatures
            for key, values in timing_signatures.items():
                if values:
                    characteristics.timing_signatures[key] = statistics.mean(values)

            # Добавляем behavioral indicators
            characteristics.behavioral_indicators = {
                "pattern_diversity": len(detected_patterns),
                "total_evidence_count": len(evidence_list),
                "aggressiveness_score": aggressiveness_score,
                "most_common_pattern": (
                    max(pattern_counts.keys(), key=pattern_counts.get).value
                    if pattern_counts
                    else None
                ),
            }

            LOG.info(
                f"🎯 Классификация DPI: {level.value} (score: {aggressiveness_score}, confidence: {avg_confidence:.2f})"
            )

            return characteristics

        except Exception as e:
            LOG.error(f"❌ Ошибка классификации DPI: {e}")
            return DPICharacteristics(
                aggressiveness_level=DPIAggressivenessLevel.LOW, confidence=0.0
            )

    def _initialize_detection_rules(self) -> Dict[str, Any]:
        """Инициализация правил детекции"""
        return {
            "rst_injection": {
                "min_suspicion_score": 0.6,
                "timing_threshold_ms": 100,
                "ttl_threshold": 32,
            },
            "dns_poisoning": {
                "min_confidence": 0.3,
                "response_time_threshold_ms": 1,
                "suspicious_ips": ["127.0.0.1", "0.0.0.0", "10.0.0.1"],
            },
            "tls_interrupt": {"min_confidence": 0.4, "handshake_timeout_s": 10.0},
            "http_redirect": {
                "min_confidence": 0.3,
                "blocking_keywords": ["blocked", "forbidden", "restricted"],
            },
            "content_filtering": {"min_confidence": 0.3, "small_packet_threshold": 100},
            "connection_timeout": {
                "min_confidence": 0.3,
                "large_gap_threshold_s": 5.0,
                "long_duration_threshold_s": 30.0,
            },
        }

    def _initialize_timing_thresholds(self) -> Dict[str, float]:
        """Инициализация пороговых значений timing"""
        return {
            "rst_fast_response_ms": 100,
            "dns_fast_response_ms": 1,
            "tls_handshake_timeout_s": 10,
            "connection_large_gap_s": 5,
            "connection_long_duration_s": 30,
        }

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Получение статистики детекции"""
        stats = self.stats.copy()

        # Добавляем производительность
        if stats["patterns_detected"] > 0:
            stats["average_analysis_time"] = (
                stats["analysis_time_total"] / stats["patterns_detected"]
            )
        else:
            stats["average_analysis_time"] = 0.0

        # Добавляем информацию о правилах
        stats["detection_rules_count"] = len(self.detection_rules)
        stats["timing_thresholds_count"] = len(self.timing_thresholds)
        stats["cache_size"] = len(self.analysis_cache)

        return stats

    def update_detection_rules(self, new_rules: Dict[str, Any]):
        """Обновление правил детекции"""
        try:
            self.detection_rules.update(new_rules)
            LOG.info(f"🔧 Обновлены правила детекции: {len(new_rules)} правил")
        except Exception as e:
            LOG.error(f"❌ Ошибка обновления правил: {e}")

    def clear_cache(self):
        """Очистка кэша анализа"""
        self.analysis_cache.clear()
        self.detector_registry.clear_stats()
        LOG.info("🧹 Кэш детекции паттернов очищен")

    async def analyze_pattern_evolution(
        self, historical_evidence: List[List[BlockingEvidence]], time_windows: List[datetime]
    ) -> Dict[str, Any]:
        """Анализ эволюции паттернов блокировки во времени"""
        evolution_analysis = {
            "pattern_trends": {},
            "aggressiveness_trend": [],
            "new_patterns_detected": [],
            "disappeared_patterns": [],
        }

        try:
            if len(historical_evidence) != len(time_windows):
                LOG.warning("Несоответствие количества данных и временных окон")
                return evolution_analysis

            # Анализируем каждое временное окно
            previous_patterns = set()

            for i, (evidence_list, timestamp) in enumerate(zip(historical_evidence, time_windows)):
                if not evidence_list:
                    continue

                # Классифицируем DPI для этого окна
                characteristics = self.classify_dpi_aggressiveness(evidence_list)

                current_patterns = set(characteristics.detected_patterns)

                # Отслеживаем тренды паттернов
                for pattern in current_patterns:
                    if pattern not in evolution_analysis["pattern_trends"]:
                        evolution_analysis["pattern_trends"][pattern] = []

                    evolution_analysis["pattern_trends"][pattern].append(
                        {
                            "timestamp": timestamp.isoformat(),
                            "window_index": i,
                            "confidence": characteristics.confidence,
                        }
                    )

                # Отслеживаем тренд агрессивности
                evolution_analysis["aggressiveness_trend"].append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "level": characteristics.aggressiveness_level.value,
                        "confidence": characteristics.confidence,
                    }
                )

                # Новые паттерны
                if i > 0:  # Не для первого окна
                    new_patterns = current_patterns - previous_patterns
                    if new_patterns:
                        evolution_analysis["new_patterns_detected"].extend(
                            [
                                {
                                    "pattern": pattern.value,
                                    "detected_at": timestamp.isoformat(),
                                    "window_index": i,
                                }
                                for pattern in new_patterns
                            ]
                        )

                    # Исчезнувшие паттерны
                    disappeared = previous_patterns - current_patterns
                    if disappeared:
                        evolution_analysis["disappeared_patterns"].extend(
                            [
                                {
                                    "pattern": pattern.value,
                                    "disappeared_at": timestamp.isoformat(),
                                    "window_index": i,
                                }
                                for pattern in disappeared
                            ]
                        )

                previous_patterns = current_patterns

            LOG.info(
                f"📈 Анализ эволюции завершен: {len(evolution_analysis['pattern_trends'])} паттернов отслежено"
            )

        except Exception as e:
            LOG.error(f"❌ Ошибка анализа эволюции паттернов: {e}")

        return evolution_analysis
