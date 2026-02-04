"""
Intelligent Combination Generator - расширение для автоматического поиска стратегий.

Интегрирует SmartAttackCombinator в систему автоматического поиска,
добавляя логику принятия решений о том, когда использовать комбинированные атаки.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

LOG = logging.getLogger("intelligent_combination_generator")


class CombinationTrigger(Enum):
    """Триггеры для использования комбинированных атак"""

    SIMPLE_ATTACKS_FAILED = "simple_attacks_failed"  # Простые атаки не сработали
    HIGH_DPI_COMPLEXITY = "high_dpi_complexity"  # Сложная DPI система
    GOOGLE_YOUTUBE_DOMAIN = "google_youtube_domain"  # Google/YouTube домены
    MULTIPLE_FAILURES = "multiple_failures"  # Множественные провалы
    STATEFUL_DPI_DETECTED = "stateful_dpi_detected"  # Обнаружен stateful DPI
    ACTIVE_RST_BLOCKING = "active_rst_blocking"  # Активная блокировка RST
    DEEP_PACKET_INSPECTION = "deep_packet_inspection"  # Глубокая инспекция пакетов


@dataclass
class CombinationDecision:
    """Решение о применении комбинированных атак"""

    should_use_combinations: bool
    triggers: List[CombinationTrigger]
    recommended_combinations: List[str]
    reasoning: str
    confidence: float
    priority: int  # 1-10, где 10 - наивысший приоритет


class IntelligentCombinationGenerator:
    """
    Интеллектуальный генератор комбинированных атак.

    Принимает решения о том, когда и какие комбинации использовать,
    основываясь на контексте и истории попыток.
    """

    def __init__(self):
        # Загружаем SmartAttackCombinator
        try:
            from core.strategy.smart_attack_combinator import SmartAttackCombinator

            self.combinator = SmartAttackCombinator()
            LOG.info("✅ SmartAttackCombinator загружен")
        except ImportError as e:
            LOG.error(f"❌ Не удалось загрузить SmartAttackCombinator: {e}")
            self.combinator = None

        # Правила принятия решений
        self.decision_rules = self._build_decision_rules()

        # Статистика решений
        self.decision_stats = {
            "total_decisions": 0,
            "combinations_recommended": 0,
            "simple_attacks_recommended": 0,
            "triggers_activated": {},
        }

        # Известные сложные домены
        self.complex_domains = self._load_complex_domains()

    def _build_decision_rules(self) -> Dict[CombinationTrigger, Dict[str, Any]]:
        """Построение правил принятия решений"""

        rules = {
            CombinationTrigger.SIMPLE_ATTACKS_FAILED: {
                "priority": 8,
                "confidence_boost": 0.3,
                "recommended_combinations": [
                    ["fake", "split"],
                    ["fake", "multisplit"],
                    ["disorder", "multisplit"],
                ],
                "reasoning": "Простые атаки не сработали, пробуем комбинации",
            },
            CombinationTrigger.HIGH_DPI_COMPLEXITY: {
                "priority": 9,
                "confidence_boost": 0.4,
                "recommended_combinations": [
                    ["fake", "multisplit", "seqovl"],
                    ["disorder", "split", "seqovl"],
                    ["fake", "disorder", "multisplit"],
                ],
                "reasoning": "Обнаружена сложная DPI система, требуются комплексные атаки",
            },
            CombinationTrigger.GOOGLE_YOUTUBE_DOMAIN: {
                "priority": 10,
                "confidence_boost": 0.5,
                "recommended_combinations": [
                    ["fake", "multisplit"],
                    ["disorder", "multisplit"],
                    ["split", "disorder"],
                    ["fake", "split", "seqovl"],
                ],
                "reasoning": "Google/YouTube требуют агрессивных комбинированных атак",
            },
            CombinationTrigger.MULTIPLE_FAILURES: {
                "priority": 7,
                "confidence_boost": 0.25,
                "recommended_combinations": [["fake", "split"], ["multisplit", "disorder"]],
                "reasoning": "Множественные провалы указывают на необходимость комбинаций",
            },
            CombinationTrigger.STATEFUL_DPI_DETECTED: {
                "priority": 9,
                "confidence_boost": 0.4,
                "recommended_combinations": [
                    ["fake", "seqovl"],
                    ["fake", "multisplit"],
                    ["disorder", "seqovl"],
                ],
                "reasoning": "Stateful DPI требует атак на уровне TCP последовательностей",
            },
            CombinationTrigger.ACTIVE_RST_BLOCKING: {
                "priority": 10,
                "confidence_boost": 0.5,
                "recommended_combinations": [
                    ["fake", "split"],
                    ["fake", "multisplit"],
                    ["fake", "disorder", "split"],
                ],
                "reasoning": "Активная RST блокировка требует fake packets с фрагментацией",
            },
            CombinationTrigger.DEEP_PACKET_INSPECTION: {
                "priority": 9,
                "confidence_boost": 0.45,
                "recommended_combinations": [
                    ["fake", "multisplit", "disorder"],
                    ["split", "seqovl", "disorder"],
                    ["fake", "split", "seqovl"],
                ],
                "reasoning": "Глубокая инспекция требует многоуровневых атак",
            },
        }

        return rules

    def _load_complex_domains(self) -> Dict[str, List[str]]:
        """Загрузка списка известных сложных доменов"""

        return {
            "google": [
                "google.com",
                "*.google.com",
                "googlevideo.com",
                "*.googlevideo.com",
                "youtube.com",
                "*.youtube.com",
                "ytimg.com",
                "*.ytimg.com",
                "ggpht.com",
                "*.ggpht.com",
                "gstatic.com",
                "*.gstatic.com",
            ],
            "cloudflare": [
                "cloudflare.com",
                "*.cloudflare.com",
                "cloudflare-dns.com",
                "*.cloudflare-dns.com",
            ],
            "social_media": [
                "facebook.com",
                "*.facebook.com",
                "instagram.com",
                "*.instagram.com",
                "twitter.com",
                "*.twitter.com",
                "tiktok.com",
                "*.tiktok.com",
            ],
            "streaming": [
                "netflix.com",
                "*.netflix.com",
                "twitch.tv",
                "*.twitch.tv",
                "vimeo.com",
                "*.vimeo.com",
            ],
        }

    def should_use_combinations(
        self,
        domain: str,
        failed_attempts: int = 0,
        failed_strategies: List[str] = None,
        fingerprint: Optional[Any] = None,
        pcap_analysis: Optional[Dict[str, Any]] = None,
    ) -> CombinationDecision:
        """
        Принятие решения о необходимости использования комбинированных атак.

        Args:
            domain: Целевой домен
            failed_attempts: Количество неудачных попыток
            failed_strategies: Список провалившихся стратегий
            fingerprint: DPI fingerprint (если доступен)
            pcap_analysis: Анализ PCAP (если доступен)

        Returns:
            CombinationDecision с рекомендациями
        """

        self.decision_stats["total_decisions"] += 1

        if failed_strategies is None:
            failed_strategies = []

        # Анализируем триггеры
        activated_triggers = []
        total_priority = 0
        total_confidence = 0.0
        all_recommended_combinations = []
        reasoning_parts = []

        # 1. Проверка домена
        if self._is_complex_domain(domain):
            activated_triggers.append(CombinationTrigger.GOOGLE_YOUTUBE_DOMAIN)
            rule = self.decision_rules[CombinationTrigger.GOOGLE_YOUTUBE_DOMAIN]
            total_priority += rule["priority"]
            total_confidence += rule["confidence_boost"]
            all_recommended_combinations.extend(rule["recommended_combinations"])
            reasoning_parts.append(rule["reasoning"])
            LOG.info(f"🎯 Обнаружен сложный домен: {domain}")

        # 2. Проверка провалившихся попыток
        if failed_attempts >= 5:
            if self._all_simple_attacks_failed(failed_strategies):
                activated_triggers.append(CombinationTrigger.SIMPLE_ATTACKS_FAILED)
                rule = self.decision_rules[CombinationTrigger.SIMPLE_ATTACKS_FAILED]
                total_priority += rule["priority"]
                total_confidence += rule["confidence_boost"]
                all_recommended_combinations.extend(rule["recommended_combinations"])
                reasoning_parts.append(rule["reasoning"])
                LOG.info(f"⚠️ Все простые атаки провалились ({failed_attempts} попыток)")

            if failed_attempts >= 10:
                activated_triggers.append(CombinationTrigger.MULTIPLE_FAILURES)
                rule = self.decision_rules[CombinationTrigger.MULTIPLE_FAILURES]
                total_priority += rule["priority"]
                total_confidence += rule["confidence_boost"]
                all_recommended_combinations.extend(rule["recommended_combinations"])
                reasoning_parts.append(rule["reasoning"])
                LOG.info(f"🔴 Множественные провалы: {failed_attempts}")

        # 3. Анализ DPI fingerprint
        if fingerprint:
            dpi_triggers = self._analyze_fingerprint_for_triggers(fingerprint)
            for trigger in dpi_triggers:
                if trigger not in activated_triggers:
                    activated_triggers.append(trigger)
                    rule = self.decision_rules[trigger]
                    total_priority += rule["priority"]
                    total_confidence += rule["confidence_boost"]
                    all_recommended_combinations.extend(rule["recommended_combinations"])
                    reasoning_parts.append(rule["reasoning"])

        # 4. Анализ PCAP
        if pcap_analysis:
            pcap_triggers = self._analyze_pcap_for_triggers(pcap_analysis)
            for trigger in pcap_triggers:
                if trigger not in activated_triggers:
                    activated_triggers.append(trigger)
                    rule = self.decision_rules[trigger]
                    total_priority += rule["priority"]
                    total_confidence += rule["confidence_boost"]
                    all_recommended_combinations.extend(rule["recommended_combinations"])
                    reasoning_parts.append(rule["reasoning"])

        # Принимаем решение
        should_use = len(activated_triggers) > 0

        if should_use:
            self.decision_stats["combinations_recommended"] += 1

            # Обновляем статистику триггеров
            for trigger in activated_triggers:
                trigger_name = trigger.value
                self.decision_stats["triggers_activated"][trigger_name] = (
                    self.decision_stats["triggers_activated"].get(trigger_name, 0) + 1
                )
        else:
            self.decision_stats["simple_attacks_recommended"] += 1

        # Вычисляем финальные метрики
        avg_priority = total_priority / max(1, len(activated_triggers))
        avg_confidence = min(1.0, total_confidence / max(1, len(activated_triggers)))

        # Дедупликация рекомендаций
        unique_combinations = []
        seen = set()
        for combo in all_recommended_combinations:
            combo_key = tuple(sorted(combo))
            if combo_key not in seen:
                seen.add(combo_key)
                unique_combinations.append(combo)

        # Формируем финальное объяснение
        final_reasoning = (
            " | ".join(reasoning_parts)
            if reasoning_parts
            else "Нет триггеров для комбинированных атак, используем простые стратегии"
        )

        decision = CombinationDecision(
            should_use_combinations=should_use,
            triggers=activated_triggers,
            recommended_combinations=unique_combinations,
            reasoning=final_reasoning,
            confidence=avg_confidence,
            priority=int(avg_priority),
        )

        LOG.info(
            f"📊 Решение: {'КОМБИНАЦИИ' if should_use else 'ПРОСТЫЕ АТАКИ'} "
            f"(confidence={avg_confidence:.2f}, priority={int(avg_priority)})"
        )

        return decision

    def _is_complex_domain(self, domain: str) -> bool:
        """Проверка, является ли домен известным сложным"""

        domain_lower = domain.lower()

        for category, domains in self.complex_domains.items():
            for pattern in domains:
                if pattern.startswith("*."):
                    # Wildcard match
                    suffix = pattern[2:]
                    if domain_lower.endswith(suffix):
                        return True
                else:
                    # Exact match
                    if domain_lower == pattern:
                        return True

        return False

    def _all_simple_attacks_failed(self, failed_strategies: List[str]) -> bool:
        """Проверка, провалились ли все простые атаки"""

        simple_attacks = {"fake", "split", "multisplit", "disorder", "seqovl"}

        # Проверяем, есть ли хотя бы 3 простые атаки в провалах
        failed_simple = sum(
            1
            for strategy in failed_strategies
            if any(attack in strategy for attack in simple_attacks)
        )

        return failed_simple >= 3

    def _analyze_fingerprint_for_triggers(self, fingerprint: Any) -> List[CombinationTrigger]:
        """Анализ DPI fingerprint для определения триггеров"""

        triggers = []

        try:
            # Проверка типа DPI
            if hasattr(fingerprint, "dpi_type"):
                dpi_type = (
                    fingerprint.dpi_type.value
                    if hasattr(fingerprint.dpi_type, "value")
                    else str(fingerprint.dpi_type)
                )

                if dpi_type == "stateful":
                    triggers.append(CombinationTrigger.STATEFUL_DPI_DETECTED)
                    LOG.info("🔍 Обнаружен stateful DPI")

            # Проверка режима DPI
            if hasattr(fingerprint, "dpi_mode"):
                dpi_mode = (
                    fingerprint.dpi_mode.value
                    if hasattr(fingerprint.dpi_mode, "value")
                    else str(fingerprint.dpi_mode)
                )

                if dpi_mode == "active_rst":
                    triggers.append(CombinationTrigger.ACTIVE_RST_BLOCKING)
                    LOG.info("🔍 Обнаружена активная RST блокировка")

            # Проверка сложности
            if hasattr(fingerprint, "confidence") and fingerprint.confidence > 0.8:
                triggers.append(CombinationTrigger.HIGH_DPI_COMPLEXITY)
                LOG.info("🔍 Высокая сложность DPI")

            # Проверка глубокой инспекции
            if hasattr(fingerprint, "inspection_depth"):
                if fingerprint.inspection_depth == "deep":
                    triggers.append(CombinationTrigger.DEEP_PACKET_INSPECTION)
                    LOG.info("🔍 Обнаружена глубокая инспекция пакетов")

        except Exception as e:
            LOG.warning(f"Ошибка анализа fingerprint: {e}")

        return triggers

    def _analyze_pcap_for_triggers(self, pcap_analysis: Dict[str, Any]) -> List[CombinationTrigger]:
        """Анализ PCAP для определения триггеров"""

        triggers = []

        try:
            # Проверка на RST пакеты
            rst_count = pcap_analysis.get("rst_packets", 0)
            if rst_count > 0:
                triggers.append(CombinationTrigger.ACTIVE_RST_BLOCKING)
                LOG.info(f"🔍 Обнаружено {rst_count} RST пакетов в PCAP")

            # Проверка на блокировку после TLS handshake
            if pcap_analysis.get("blocked_after_tls_handshake", False):
                triggers.append(CombinationTrigger.DEEP_PACKET_INSPECTION)
                LOG.info("🔍 Блокировка после TLS handshake - глубокая инспекция")

            # Проверка на множественные попытки соединения
            connection_attempts = pcap_analysis.get("connection_attempts", 0)
            if connection_attempts > 5:
                triggers.append(CombinationTrigger.MULTIPLE_FAILURES)
                LOG.info(f"🔍 Множественные попытки соединения: {connection_attempts}")

        except Exception as e:
            LOG.warning(f"Ошибка анализа PCAP: {e}")

        return triggers

    def generate_combination_strategies(
        self,
        decision: CombinationDecision,
        available_attacks: List[str] = None,
        max_strategies: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Генерация конкретных стратегий комбинированных атак.

        Args:
            decision: Решение о комбинациях
            available_attacks: Доступные атаки (если None, используем все)
            max_strategies: Максимальное количество стратегий

        Returns:
            Список стратегий в формате для тестирования
        """

        if not decision.should_use_combinations:
            return []

        if not self.combinator:
            LOG.error("SmartAttackCombinator недоступен")
            return []

        # Используем рекомендованные комбинации
        strategies = []

        for combo_attacks in decision.recommended_combinations[:max_strategies]:
            # Генерируем параметры для комбинации
            try:
                # Создаем временную CombinationStrategy для генерации параметров
                from core.strategy.smart_attack_combinator import CombinationStrategy

                temp_combo = CombinationStrategy(
                    attacks=combo_attacks,
                    execution_order=combo_attacks,  # Будет оптимизирован
                    parameters={},
                    compatibility_score=0.8,
                    expected_effectiveness=0.7,
                )

                # Генерируем параметры
                params = self.combinator._generate_combination_parameters(combo_attacks)

                # Определяем оптимальный порядок
                execution_order = self.combinator._determine_execution_order(combo_attacks)

                # Формируем стратегию
                strategy = {
                    "name": "_".join(execution_order),
                    "attacks": execution_order,
                    "parameters": params,
                    "reasoning": decision.reasoning,
                    "priority": decision.priority,
                    "confidence": decision.confidence,
                }

                strategies.append(strategy)

            except Exception as e:
                LOG.warning(f"Ошибка генерации стратегии для {combo_attacks}: {e}")
                continue

        LOG.info(f"✅ Сгенерировано {len(strategies)} комбинированных стратегий")
        return strategies

    def get_decision_statistics(self) -> Dict[str, Any]:
        """Получение статистики принятия решений"""

        total = self.decision_stats["total_decisions"]

        return {
            "total_decisions": total,
            "combinations_recommended": self.decision_stats["combinations_recommended"],
            "simple_attacks_recommended": self.decision_stats["simple_attacks_recommended"],
            "combination_rate": (self.decision_stats["combinations_recommended"] / max(1, total)),
            "triggers_activated": self.decision_stats["triggers_activated"],
            "most_common_trigger": (
                max(
                    self.decision_stats["triggers_activated"].items(),
                    key=lambda x: x[1],
                    default=("none", 0),
                )[0]
                if self.decision_stats["triggers_activated"]
                else "none"
            ),
        }


# Пример использования
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    generator = IntelligentCombinationGenerator()

    # Тест 1: Google домен
    print("\n=== Тест 1: Google домен ===")
    decision = generator.should_use_combinations(domain="www.googlevideo.com", failed_attempts=0)
    print(f"Решение: {decision.should_use_combinations}")
    print(f"Триггеры: {[t.value for t in decision.triggers]}")
    print(f"Reasoning: {decision.reasoning}")

    if decision.should_use_combinations:
        strategies = generator.generate_combination_strategies(decision, max_strategies=5)
        print(f"\nСгенерировано {len(strategies)} стратегий:")
        for i, strategy in enumerate(strategies, 1):
            print(f"  {i}. {strategy['name']}: {strategy['attacks']}")

    # Тест 2: Множественные провалы
    print("\n=== Тест 2: Множественные провалы ===")
    decision = generator.should_use_combinations(
        domain="example.com",
        failed_attempts=15,
        failed_strategies=["fake", "split", "multisplit", "disorder"],
    )
    print(f"Решение: {decision.should_use_combinations}")
    print(f"Триггеры: {[t.value for t in decision.triggers]}")
    print(f"Reasoning: {decision.reasoning}")

    # Статистика
    print("\n=== Статистика ===")
    stats = generator.get_decision_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
