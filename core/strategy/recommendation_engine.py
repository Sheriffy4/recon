"""
Recommendation Engine - генерация рекомендаций для улучшения стратегий.

Этот модуль предоставляет функциональность для генерации рекомендаций
на основе анализа неудач стратегий обхода DPI.
"""

import logging
from typing import List, Dict, Any
from dataclasses import dataclass

LOG = logging.getLogger("RecommendationEngine")


@dataclass
class Recommendation:
    """Рекомендация для улучшения стратегии."""

    action: str
    rationale: str
    priority: float
    parameters: Dict[str, Any]


class RecommendationEngine:
    """
    Генератор рекомендаций для улучшения стратегий обхода.

    Основные функции:
    - Генерация intent-based рекомендаций
    - Предложение альтернативных подходов
    - Адаптация параметров на основе технических деталей
    """

    def __init__(self):
        """Инициализация recommendation engine."""
        # Маппинг root_cause → intent'ы для замкнутого цикла обучения
        self.cause_to_intents = {
            "DPI_SNI_FILTERING": ["conceal_sni", "record_fragmentation", "fake_sni"],
            "DPI_ACTIVE_RST_INJECTION": [
                "short_ttl_decoy",
                "sequence_overlap",
                "timing_manipulation",
            ],
            "DPI_CONTENT_INSPECTION": [
                "payload_obfuscation",
                "tls_extension_manipulation",
                "record_fragmentation",
            ],
            "DPI_REASSEMBLES_FRAGMENTS": [
                "packet_reordering",
                "sequence_overlap",
                "timing_manipulation",
            ],
            "DPI_STATEFUL_TRACKING": [
                "sequence_overlap",
                "out_of_order_decoy",
                "timing_manipulation",
            ],
            "NETWORK_TIMEOUT": ["timeout_adjustment", "ipv6_fallback"],
            "CONNECTION_REFUSED": ["port_randomization", "ipv6_fallback"],
            "TLS_HANDSHAKE_FAILURE": [
                "tls_extension_manipulation",
                "record_fragmentation",
            ],
            "UNKNOWN": [
                "basic_fragmentation",
                "simple_reordering",
                "basic_sni_concealment",
            ],
        }

    def _generate_base_recommendations(self, failure_report) -> List[Recommendation]:
        """
        Базовые (не только intent-based) рекомендации.

        Ранее эта логика жила в StrategyFailureAnalyzer._generate_recommendations(),
        теперь перенесена сюда, чтобы не было двух источников правды.
        """
        root_cause_str = failure_report.root_cause.name
        confidence = float(getattr(failure_report, "confidence", 0.5) or 0.5)

        recs: List[Recommendation] = []

        if root_cause_str == "DPI_ACTIVE_RST_INJECTION":
            recs.extend(
                [
                    Recommendation(
                        action="use_ttl_manipulation",
                        rationale="DPI инжектирует RST - попробуйте манипуляции с TTL",
                        priority=min(1.0, 0.7 + confidence * 0.3),
                        parameters={"ttl": 1, "fooling": "badseq"},
                    ),
                    Recommendation(
                        action="try_disorder_attacks",
                        rationale="Атаки с нарушением порядка могут обойти RST инъекции",
                        priority=min(1.0, 0.6 + confidence * 0.3),
                        parameters={"attack_type": "disorder"},
                    ),
                ]
            )

        elif root_cause_str == "DPI_CONTENT_INSPECTION":
            recs.append(
                Recommendation(
                    action="use_content_obfuscation",
                    rationale="DPI анализирует содержимое - нужна обфускация",
                    priority=min(1.0, 0.65 + confidence * 0.3),
                    parameters={"method": "fragmentation"},
                )
            )

        elif root_cause_str == "DPI_REASSEMBLES_FRAGMENTS":
            recs.extend(
                [
                    Recommendation(
                        action="try_advanced_fragmentation",
                        rationale="Простая фрагментация не работает - нужны продвинутые методы",
                        priority=min(1.0, 0.6 + confidence * 0.3),
                        parameters={"method": "multisplit", "split_count": 10},
                    ),
                    Recommendation(
                        action="switch_to_timing_attacks",
                        rationale="Переключиться на атаки, основанные на времени",
                        priority=min(1.0, 0.55 + confidence * 0.25),
                        parameters={},
                    ),
                ]
            )

        elif root_cause_str == "DPI_SNI_FILTERING":
            recs.append(
                Recommendation(
                    action="conceal_sni",
                    rationale="DPI фильтрует по SNI - нужно скрыть или обфусцировать SNI",
                    priority=min(1.0, 0.7 + confidence * 0.3),
                    parameters={"method": "sni_split"},
                )
            )

        elif root_cause_str == "UNKNOWN":
            recs.append(
                Recommendation(
                    action="try_alternative_approaches",
                    rationale="Причина неудачи неясна - попробуйте альтернативные подходы",
                    priority=0.5,
                    parameters={"diversify": True},
                )
            )

        return recs

    def generate_recommendations(self, failure_report) -> List[Recommendation]:
        """
        Генерация рекомендаций на основе отчета о неудаче.

        Args:
            failure_report: FailureReport объект

        Returns:
            List[Recommendation] - список рекомендаций
        """
        recommendations = []

        # 0. Базовые рекомендации (централизованы тут)
        base_recommendations = self._generate_base_recommendations(failure_report)
        recommendations.extend(base_recommendations)

        # 1. Intent-based рекомендации
        intent_recommendations = self._generate_intent_based_recommendations(failure_report)
        recommendations.extend(intent_recommendations)

        # 2. Альтернативные подходы
        alternative_recommendations = self._suggest_alternative_intents(failure_report)
        recommendations.extend(alternative_recommendations)

        # 3. Дедупликация
        recommendations = self._deduplicate_recommendations(recommendations)

        # 4. Сортировка по приоритету
        recommendations.sort(key=lambda r: r.priority, reverse=True)

        return recommendations[:5]  # Топ-5 рекомендаций

    def _generate_intent_based_recommendations(self, failure_report) -> List[Recommendation]:
        """
        Генерация рекомендаций на основе Intent'ов.

        Args:
            failure_report: FailureReport объект

        Returns:
            List[Recommendation] - список intent-based рекомендаций
        """
        recommendations = []
        root_cause_str = failure_report.root_cause.name

        # Получаем рекомендуемые intent'ы для данной причины неудачи
        recommended_intents = self.cause_to_intents.get(root_cause_str, [])

        for intent_key in recommended_intents:
            # Генерируем параметры для intent'а
            parameters = self._get_intent_parameters(intent_key, failure_report)

            # Вычисляем приоритет
            priority = self._calculate_confidence(failure_report, intent_key)

            recommendations.append(
                Recommendation(
                    action=f"apply_intent_{intent_key}",
                    rationale=f"Рекомендуется intent '{intent_key}' для обхода {root_cause_str}",
                    priority=priority,
                    parameters={"intent_key": intent_key, **parameters},
                )
            )

        return recommendations

    def _get_intent_parameters(self, intent_key: str, failure_report) -> Dict[str, Any]:
        """
        Получение параметров для конкретного intent'а.

        Args:
            intent_key: Ключ intent'а
            failure_report: FailureReport объект

        Returns:
            Dict с параметрами
        """
        base_parameters = {}

        # Intent-specific параметры
        intent_specific_params = {
            "short_ttl_decoy": {
                "ttl": 1,
                "fooling_method": "badseq",
                "reason": "rst_injection_detected",
            },
            "conceal_sni": {
                "split_position": "sni",
                "fooling_method": "badsum",
                "reason": "sni_filtering_detected",
            },
            "record_fragmentation": {
                "split_count": 8,
                "split_position": "random",
                "reason": "content_inspection_detected",
            },
            "packet_reordering": {
                "reorder_method": "simple",
                "split_positions": [2, 3],
                "reason": "fragmentation_reassembly_detected",
            },
            "sequence_overlap": {"overlap_size": 2, "reason": "stateful_tracking_detected"},
            "timing_manipulation": {
                "delay_ms": 50,
                "jitter_enabled": True,
                "reason": "timing_sensitive_dpi",
            },
            "payload_obfuscation": {
                "obfuscation_method": "xor",
                "reason": "deep_content_inspection",
            },
        }

        specific_params = intent_specific_params.get(intent_key, {})
        base_parameters.update(specific_params)

        # Адаптируем параметры на основе технических деталей неудачи
        technical_details = failure_report.failure_details.get("technical_details", {})

        if intent_key == "short_ttl_decoy" and "injection_indicators" in technical_details:
            indicators = technical_details["injection_indicators"]
            if "suspicious_ttl" in indicators:
                base_parameters["ttl"] = 2  # Используем TTL=2 если DPI использует TTL=1

        if intent_key == "record_fragmentation" and "fragmented_packets" in technical_details:
            frag_count = technical_details.get("fragmented_packets", 0)
            if frag_count > 0:
                # Увеличиваем количество фрагментов если простая фрагментация не сработала
                base_parameters["split_count"] = min(16, frag_count * 2)

        return base_parameters

    def _suggest_alternative_intents(self, failure_report) -> List[Recommendation]:
        """
        Предложение альтернативных Intent'ов на основе технических деталей.

        Args:
            failure_report: FailureReport объект

        Returns:
            List[Recommendation] - альтернативные рекомендации
        """
        alternative_recommendations = []
        technical_details = failure_report.failure_details.get("technical_details", {})
        root_cause_str = failure_report.root_cause.name

        # Анализ RST инъекций для предложения альтернатив
        if root_cause_str == "DPI_ACTIVE_RST_INJECTION":
            injection_indicators = technical_details.get("injection_indicators", [])

            if "multiple_rst_sources" in injection_indicators:
                alternative_recommendations.append(
                    Recommendation(
                        action="apply_intent_timing_manipulation",
                        rationale="Обнаружены множественные источники RST - попробуйте манипуляции с таймингом",
                        priority=0.75,
                        parameters={"intent_key": "timing_manipulation", "delay_ms": 100},
                    )
                )

            if "unrealistic_timing" in injection_indicators:
                alternative_recommendations.append(
                    Recommendation(
                        action="apply_intent_sequence_overlap",
                        rationale="DPI реагирует слишком быстро - используйте перекрытие последовательностей",
                        priority=0.8,
                        parameters={"intent_key": "sequence_overlap", "overlap_size": 4},
                    )
                )

        # Анализ фрагментации для предложения альтернатив
        elif root_cause_str == "DPI_REASSEMBLES_FRAGMENTS":
            reassembly_indicators = technical_details.get("reassembly_indicators", [])

            if "tcp_reassembly_blocked" in reassembly_indicators:
                alternative_recommendations.append(
                    Recommendation(
                        action="apply_intent_payload_obfuscation",
                        rationale="TCP сборка работает - попробуйте обфускацию на уровне приложения",
                        priority=0.85,
                        parameters={
                            "intent_key": "payload_obfuscation",
                            "obfuscation_method": "xor",
                        },
                    )
                )

        return alternative_recommendations

    def _calculate_confidence(self, failure_report, intent_key: str) -> float:
        """
        Вычисление уверенности в рекомендации.

        Args:
            failure_report: FailureReport объект
            intent_key: Ключ intent'а

        Returns:
            float - уровень уверенности (0.0-1.0)
        """
        base_confidence = failure_report.confidence

        # Бонус за специфичность
        technical_details = failure_report.failure_details.get("technical_details", {})
        if technical_details:
            base_confidence += 0.1

        # Бонус за количество индикаторов
        indicators = technical_details.get("injection_indicators", [])
        if len(indicators) > 2:
            base_confidence += 0.1

        return min(1.0, base_confidence)

    def _deduplicate_recommendations(
        self, recommendations: List[Recommendation]
    ) -> List[Recommendation]:
        """
        Дедупликация рекомендаций.

        Args:
            recommendations: Список рекомендаций

        Returns:
            List[Recommendation] - дедуплицированный список
        """
        seen = set()
        unique = []

        for rec in recommendations:
            key = (rec.action, rec.parameters.get("intent_key"))
            if key not in seen:
                seen.add(key)
                unique.append(rec)

        return unique
