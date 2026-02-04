# core/strategy/strategy_generator.py
"""
Strategy Generator (SG) - Task 5 Implementation
Автоматическая генерация конкретных стратегий на основе Intent'ов.

Реализует требования FR-2 и FR-3 для адаптивной системы мониторинга.
Интегрируется с существующими модулями:
- AttackRegistry для получения всех доступных атак
- AttackCombinator для создания комбинированных стратегий
- ParametricOptimizer для настройки параметров
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

LOG = logging.getLogger("strategy_generator")


@dataclass
class GeneratedStrategy:
    """Сгенерированная стратегия с метаданными генерации"""

    name: str
    attack_combination: List[str]
    parameters: Dict[str, Any]

    # Метаданные генерации
    generation_method: str
    source_intents: List[str]
    expected_success_rate: float
    rationale: str

    # Результаты тестирования
    tested: bool = False
    actual_success_rate: Optional[float] = None
    test_results: List[Any] = field(default_factory=list)

    # Дополнительные метаданные
    created_at: datetime = field(default_factory=datetime.now)
    complexity_score: float = 0.0
    compatibility_warnings: List[str] = field(default_factory=list)


class GenerationMethod(Enum):
    """Методы генерации стратегий"""

    INTENT_MAPPING = "intent_mapping"
    COMBINATION = "combination"
    OPTIMIZATION = "optimization"
    FALLBACK = "fallback"


class StrategyGenerator:
    """
    Генератор стратегий на основе Intent'ов с интеграцией существующих модулей.

    Основные функции:
    - Преобразование Intent'ов в конкретные стратегии
    - Умное комбинирование атак из AttackRegistry
    - Оптимизация параметров на основе DPI характеристик
    - Генерация объяснений для каждой стратегии
    """

    def __init__(self):
        self.attack_registry = None
        self.attack_combinator = None
        self.smart_combinator = None
        self.parametric_optimizer = None
        self.intent_mapper = None

        # Статистика генерации
        self.generation_stats = {
            "total_generated": 0,
            "by_method": {method.value: 0 for method in GenerationMethod},
            "successful_tests": 0,
            "failed_tests": 0,
        }

        # Инициализация компонентов
        self._initialize_components()

    def _initialize_components(self):
        """Инициализация интеграционных компонентов"""

        # Загружаем AttackRegistry
        try:
            from core.bypass.attacks import get_attack_registry

            self.attack_registry = get_attack_registry()
            LOG.info(
                f"Загружен AttackRegistry с {len(self.attack_registry.list_attacks())} атаками"
            )
        except ImportError as e:
            LOG.error(f"Не удалось загрузить AttackRegistry: {e}")

        # Загружаем AttackCombinator
        try:
            from core.attack_combinator import AttackCombinator

            self.attack_combinator = AttackCombinator()
            LOG.info("Загружен AttackCombinator")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить AttackCombinator: {e}")

        # Загружаем SmartAttackCombinator
        try:
            from core.strategy.smart_attack_combinator import SmartAttackCombinator

            self.smart_combinator = SmartAttackCombinator()
            LOG.info("Загружен SmartAttackCombinator")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить SmartAttackCombinator: {e}")

        # Загружаем ParametricOptimizer
        try:
            from core.parametric_optimizer import ParametricOptimizer

            # Создаем заглушку для optimizer (требует дополнительные параметры)
            self.parametric_optimizer = None
            LOG.info("ParametricOptimizer будет инициализирован при необходимости")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить ParametricOptimizer: {e}")

        # Загружаем StrategyParameterOptimizer
        try:
            from core.strategy.strategy_parameter_optimizer import StrategyParameterOptimizer

            self.parameter_optimizer = StrategyParameterOptimizer()
            LOG.info("Загружен StrategyParameterOptimizer")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить StrategyParameterOptimizer: {e}")
            self.parameter_optimizer = None

        # Загружаем IntentAttackMapper
        try:
            from core.strategy.intent_attack_mapper import IntentAttackMapper

            self.intent_mapper = IntentAttackMapper()
            LOG.info("Загружен IntentAttackMapper")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить IntentAttackMapper: {e}")

    async def generate_strategies(
        self,
        intents: List[Any],
        fingerprint: Optional[Any] = None,
        max_strategies: int = 15,
        enable_combinations: bool = True,
    ) -> List[GeneratedStrategy]:
        """
        Генерирует конкретные стратегии из Intent'ов.

        Args:
            intents: Список StrategyIntent объектов
            fingerprint: DPI fingerprint для адаптации
            max_strategies: Максимальное количество стратегий
            enable_combinations: Включить генерацию комбинированных стратегий

        Returns:
            Список GeneratedStrategy отсортированный по ожидаемой эффективности
        """

        LOG.info(f"Генерация стратегий из {len(intents)} Intent'ов")

        all_strategies = []

        # Этап 1: Генерация одиночных стратегий из Intent'ов
        single_strategies = await self._generate_single_strategies(intents, fingerprint)
        all_strategies.extend(single_strategies)

        # Этап 2: Генерация комбинированных стратегий (если включено)
        if enable_combinations and len(intents) > 1:
            combo_strategies = await self._generate_combination_strategies(intents, fingerprint)
            all_strategies.extend(combo_strategies)

        # Этап 3: Оптимизация параметров лучших стратегий
        optimized_strategies = await self._optimize_strategy_parameters(
            all_strategies[:5], fingerprint
        )
        all_strategies.extend(optimized_strategies)

        # Этап 4: Ранжирование и фильтрация
        ranked_strategies = self._rank_strategies(all_strategies, fingerprint)

        # Ограничиваем количество
        final_strategies = ranked_strategies[:max_strategies]

        # Обновляем статистику
        self.generation_stats["total_generated"] += len(final_strategies)

        LOG.info(f"Сгенерировано {len(final_strategies)} финальных стратегий")
        return final_strategies

    async def _generate_single_strategies(
        self, intents: List[Any], fingerprint: Optional[Any]
    ) -> List[GeneratedStrategy]:
        """Генерация одиночных стратегий из Intent'ов"""

        strategies = []

        if not self.intent_mapper:
            LOG.warning("IntentAttackMapper недоступен, пропускаем генерацию одиночных стратегий")
            return strategies

        for intent in intents:
            try:
                # Получаем маппинги атак для Intent'а
                attack_mappings = self.intent_mapper.map_intent_to_attacks(intent.key)

                for mapping in attack_mappings:
                    # Проверяем доступность атаки
                    if not self._is_attack_available(mapping.attack_name):
                        continue

                    # Адаптируем параметры под fingerprint
                    adapted_params = self._adapt_parameters_for_dpi(
                        mapping.parameters, fingerprint, intent
                    )

                    # Вычисляем ожидаемую эффективность
                    expected_success = self._calculate_expected_success(
                        intent, mapping, fingerprint
                    )

                    # Создаем стратегию
                    strategy = GeneratedStrategy(
                        name=f"{mapping.attack_name}_{intent.key}",
                        attack_combination=[mapping.attack_name],
                        parameters=adapted_params,
                        generation_method=GenerationMethod.INTENT_MAPPING.value,
                        source_intents=[intent.key],
                        expected_success_rate=expected_success,
                        rationale=f"{intent.rationale} -> {mapping.rationale}",
                        complexity_score=self._calculate_complexity_score([mapping.attack_name]),
                    )

                    strategies.append(strategy)

            except Exception as e:
                LOG.error(f"Ошибка генерации стратегии для Intent {intent.key}: {e}")

        self.generation_stats["by_method"][GenerationMethod.INTENT_MAPPING.value] += len(strategies)
        LOG.debug(f"Сгенерировано {len(strategies)} одиночных стратегий")

        return strategies

    async def _generate_combination_strategies(
        self, intents: List[Any], fingerprint: Optional[Any]
    ) -> List[GeneratedStrategy]:
        """Генерация комбинированных стратегий с использованием SmartAttackCombinator"""

        strategies = []

        if not self.smart_combinator or not self.intent_mapper:
            LOG.warning("SmartAttackCombinator или IntentAttackMapper недоступен")
            return strategies

        # Получаем все доступные атаки из Intent'ов
        available_attacks = set()
        intent_to_attacks = {}

        for intent in intents:
            attack_mappings = self.intent_mapper.map_intent_to_attacks(intent.key)
            # Фильтруем None значения и проверяем доступность
            intent_attacks = [
                m.attack_name
                for m in attack_mappings
                if m.attack_name is not None and self._is_attack_available(m.attack_name)
            ]

            # Дополнительная фильтрация None значений на всякий случай
            intent_attacks = [a for a in intent_attacks if a is not None and isinstance(a, str)]

            available_attacks.update(intent_attacks)
            intent_to_attacks[intent.key] = intent_attacks

        # Используем SmartAttackCombinator для генерации умных комбинаций
        combination_strategies = self.smart_combinator.generate_attack_combinations(
            list(available_attacks), max_combination_size=3, min_compatibility_score=0.5
        )

        # Ранжируем комбинации с учетом DPI fingerprint
        if fingerprint:
            combination_strategies = self.smart_combinator.rank_combinations_by_effectiveness(
                combination_strategies, fingerprint
            )

        # Преобразуем CombinationStrategy в GeneratedStrategy
        for combo_strategy in combination_strategies:
            # Определяем источники Intent'ов для комбинации
            source_intents = []
            for intent in intents:
                if any(
                    attack in intent_to_attacks.get(intent.key, [])
                    for attack in combo_strategy.attacks
                ):
                    source_intents.append(intent.key)

            if not source_intents:
                continue

            # Оптимизируем параметры под DPI
            optimized_params = combo_strategy.parameters
            if fingerprint:
                optimized_params = self.smart_combinator.optimize_combination_parameters(
                    combo_strategy, fingerprint
                )

            # Фильтруем None значения из attacks перед использованием
            filtered_attacks = [a for a in combo_strategy.attacks if a is not None]

            # Создаем GeneratedStrategy
            strategy = GeneratedStrategy(
                name=f"smart_combo_{'_'.join(filtered_attacks)}",
                attack_combination=filtered_attacks,
                parameters=optimized_params,
                generation_method=GenerationMethod.COMBINATION.value,
                source_intents=source_intents,
                expected_success_rate=combo_strategy.expected_effectiveness,
                rationale=f"Умная комбинация: {', '.join(filtered_attacks)}",
                complexity_score=self._calculate_complexity_score(filtered_attacks),
                compatibility_warnings=combo_strategy.warnings,
            )

            # Добавляем информацию о синергии в rationale
            if combo_strategy.synergy_effects:
                # Фильтруем None значения из synergy_effects
                filtered_synergy = [s for s in combo_strategy.synergy_effects if s is not None]
                if filtered_synergy:
                    strategy.rationale += f" (синергия: {'; '.join(filtered_synergy)})"

            strategies.append(strategy)

        self.generation_stats["by_method"][GenerationMethod.COMBINATION.value] += len(strategies)
        LOG.debug(f"Сгенерировано {len(strategies)} умных комбинированных стратегий")

        return strategies

    async def _optimize_strategy_parameters(
        self, strategies: List[GeneratedStrategy], fingerprint: Optional[Any]
    ) -> List[GeneratedStrategy]:
        """Оптимизация параметров лучших стратегий с использованием StrategyParameterOptimizer"""

        optimized_strategies = []

        if not strategies or not self.parameter_optimizer:
            if not self.parameter_optimizer:
                LOG.warning("StrategyParameterOptimizer недоступен")
            return optimized_strategies

        # Выбираем топ стратегии для оптимизации
        top_strategies = sorted(strategies, key=lambda s: s.expected_success_rate, reverse=True)[:3]

        for strategy in top_strategies:
            try:
                # Используем StrategyParameterOptimizer для оптимизации
                from core.strategy.strategy_parameter_optimizer import OptimizationMethod

                # Выбираем метод оптимизации
                optimization_method = (
                    OptimizationMethod.DPI_ADAPTIVE
                    if fingerprint
                    else OptimizationMethod.PRESET_GOOD_VALUES
                )

                # Выполняем оптимизацию
                optimization_result = self.parameter_optimizer.optimize_parameters(
                    base_parameters=strategy.parameters,
                    attack_names=strategy.attack_combination,
                    fingerprint=fingerprint,
                    method=optimization_method,
                )

                # Проверяем, есть ли улучшение
                if optimization_result.improvement_score > 0.05:  # Минимальное улучшение 5%
                    optimized_strategy = GeneratedStrategy(
                        name=f"{strategy.name}_optimized",
                        attack_combination=strategy.attack_combination,
                        parameters=optimization_result.optimized_parameters,
                        generation_method=GenerationMethod.OPTIMIZATION.value,
                        source_intents=strategy.source_intents,
                        expected_success_rate=strategy.expected_success_rate
                        * (1 + optimization_result.improvement_score),
                        rationale=f"{strategy.rationale} (оптимизировано: {optimization_result.explanation})",
                        complexity_score=strategy.complexity_score,
                    )

                    optimized_strategies.append(optimized_strategy)
                    LOG.debug(
                        f"Оптимизирована стратегия {strategy.name}, улучшение: {optimization_result.improvement_score:.2f}"
                    )
                else:
                    LOG.debug(f"Стратегия {strategy.name} не требует оптимизации")

            except Exception as e:
                LOG.error(f"Ошибка оптимизации стратегии {strategy.name}: {e}")

        self.generation_stats["by_method"][GenerationMethod.OPTIMIZATION.value] += len(
            optimized_strategies
        )
        LOG.debug(f"Оптимизировано {len(optimized_strategies)} стратегий")

        return optimized_strategies

    def _rank_strategies(
        self, strategies: List[GeneratedStrategy], fingerprint: Optional[Any]
    ) -> List[GeneratedStrategy]:
        """Ранжирование стратегий по ожидаемой эффективности"""

        # Вычисляем финальный score для каждой стратегии
        for strategy in strategies:
            score = strategy.expected_success_rate

            # Бонус за низкую сложность
            complexity_bonus = max(0, (1.0 - strategy.complexity_score) * 0.1)
            score += complexity_bonus

            # Бонус за соответствие DPI характеристикам
            if fingerprint:
                dpi_bonus = self._calculate_dpi_compatibility_bonus(strategy, fingerprint)
                score += dpi_bonus

            # Штраф за предупреждения совместимости
            compatibility_penalty = len(strategy.compatibility_warnings) * 0.05
            score -= compatibility_penalty

            # Обновляем expected_success_rate с учетом всех факторов
            strategy.expected_success_rate = max(0.0, min(1.0, score))

        # Сортируем по финальному score
        ranked = sorted(strategies, key=lambda s: s.expected_success_rate, reverse=True)

        LOG.debug(f"Ранжировано {len(ranked)} стратегий")
        return ranked

    def _is_attack_available(self, attack_name: str) -> bool:
        """Проверка доступности атаки в AttackRegistry"""

        if not self.attack_registry:
            return True  # Предполагаем доступность если registry недоступен

        try:
            available_attacks = self.attack_registry.list_attacks()
            return attack_name in available_attacks
        except Exception as e:
            LOG.warning(f"Ошибка проверки доступности атаки {attack_name}: {e}")
            return False

    def _adapt_parameters_for_dpi(
        self, base_params: Dict[str, Any], fingerprint: Optional[Any], intent: Any
    ) -> Dict[str, Any]:
        """Адаптация параметров под характеристики DPI"""

        adapted_params = base_params.copy()

        if not fingerprint:
            return adapted_params

        try:
            # Адаптация под тип DPI
            if hasattr(fingerprint, "dpi_type"):
                dpi_type = fingerprint.dpi_type.value

                if dpi_type == "stateless":
                    # Для stateless DPI увеличиваем сложность
                    if "split_count" in adapted_params:
                        adapted_params["split_count"] = min(
                            16, adapted_params.get("split_count", 4) * 2
                        )
                    if "split_pos" in adapted_params and adapted_params["split_pos"] == "random":
                        adapted_params["split_pos"] = 3  # Фиксированная позиция работает лучше

                elif dpi_type == "stateful":
                    # Для stateful DPI используем более агрессивные параметры
                    if "ttl" in adapted_params:
                        adapted_params["ttl"] = 1  # Минимальный TTL
                    if "fooling" in adapted_params:
                        adapted_params["fooling"] = "badseq"  # Более эффективный fooling

            # Адаптация под режим DPI
            if hasattr(fingerprint, "dpi_mode"):
                dpi_mode = fingerprint.dpi_mode.value

                if dpi_mode == "active_rst":
                    # Для активного RST используем специальные параметры
                    adapted_params["ttl"] = 1
                    adapted_params["fooling"] = "badseq"
                elif dpi_mode == "passive":
                    # Для пассивного DPI можем использовать более простые методы
                    if "split_count" in adapted_params:
                        adapted_params["split_count"] = max(
                            2, adapted_params.get("split_count", 4) // 2
                        )

            # Адаптация под поведенческие сигнатуры
            if hasattr(fingerprint, "behavioral_signatures"):
                signatures = fingerprint.behavioral_signatures

                if signatures.get("reassembles_fragments", False):
                    # DPI собирает фрагменты - увеличиваем сложность
                    if "split_count" in adapted_params:
                        adapted_params["split_count"] = max(8, adapted_params.get("split_count", 4))

                if signatures.get("checksum_validation", False):
                    # DPI проверяет checksum - избегаем badsum
                    if "fooling" in adapted_params and adapted_params["fooling"] == "badsum":
                        adapted_params["fooling"] = "badseq"

                if signatures.get("sni_filtering", False):
                    # SNI фильтрация - используем специальные позиции
                    adapted_params["split_pos"] = "sni"

            # Используем parameter_ranges из Intent'а
            if hasattr(intent, "parameter_ranges") and intent.parameter_ranges:
                for param, value_range in intent.parameter_ranges.items():
                    if param in adapted_params and isinstance(value_range, list) and value_range:
                        # Выбираем оптимальное значение из диапазона
                        if isinstance(value_range[0], (int, float)):
                            # Для числовых значений выбираем среднее или максимальное
                            if fingerprint.confidence > 0.7:
                                adapted_params[param] = max(value_range)  # Агрессивные параметры
                            else:
                                adapted_params[param] = value_range[
                                    len(value_range) // 2
                                ]  # Средние параметры
                        else:
                            # Для строковых значений выбираем первое
                            adapted_params[param] = value_range[0]

        except Exception as e:
            LOG.warning(f"Ошибка адаптации параметров: {e}")

        return adapted_params

    def _calculate_expected_success(
        self, intent: Any, mapping: Any, fingerprint: Optional[Any]
    ) -> float:
        """Вычисление ожидаемой эффективности стратегии"""

        # Базовая эффективность из Intent'а
        base_success = getattr(intent, "priority", 0.5)

        # Модификатор от маппинга
        mapping_modifier = getattr(mapping, "confidence_modifier", 1.0)

        # Модификатор совместимости
        compatibility_modifier = getattr(mapping, "compatibility_score", 1.0)

        # Модификатор от fingerprint confidence
        fingerprint_modifier = 1.0
        if fingerprint and hasattr(fingerprint, "confidence"):
            fingerprint_modifier = 0.8 + (fingerprint.confidence * 0.4)  # 0.8 - 1.2

        # Итоговая эффективность
        expected_success = (
            base_success * mapping_modifier * compatibility_modifier * fingerprint_modifier
        )

        return max(0.0, min(1.0, expected_success))

    def _generate_attack_combinations(
        self, attacks: List[str], max_combo_size: int = 2
    ) -> List[List[str]]:
        """Генерация комбинаций атак"""

        combinations = []

        # Генерируем комбинации размером 2
        if max_combo_size >= 2:
            for i in range(len(attacks)):
                for j in range(i + 1, len(attacks)):
                    combo = [attacks[i], attacks[j]]
                    if self._is_valid_combination(combo):
                        combinations.append(combo)

        # Можно добавить комбинации размером 3, но они сложнее
        if max_combo_size >= 3 and len(attacks) >= 3:
            for i in range(len(attacks)):
                for j in range(i + 1, len(attacks)):
                    for k in range(j + 1, len(attacks)):
                        combo = [attacks[i], attacks[j], attacks[k]]
                        if self._is_valid_combination(combo):
                            combinations.append(combo)

        return combinations

    def _is_valid_combination(self, attacks: List[str]) -> bool:
        """Проверка валидности комбинации атак"""

        # Простые правила совместимости
        incompatible_pairs = [
            ("fake", "disorder"),  # Конфликтуют по механизму
            ("split", "multisplit"),  # Дублируют функциональность
        ]

        for attack1, attack2 in incompatible_pairs:
            if attack1 in attacks and attack2 in attacks:
                return False

        return True

    def _check_attack_compatibility(self, attacks: List[str]) -> bool:
        """Проверка совместимости атак перед комбинированием"""

        if len(attacks) <= 1:
            return True

        # Проверяем попарную совместимость
        for i in range(len(attacks)):
            for j in range(i + 1, len(attacks)):
                if not self._are_attacks_compatible(attacks[i], attacks[j]):
                    return False

        return True

    def _are_attacks_compatible(self, attack1: str, attack2: str) -> bool:
        """Проверка совместимости двух атак"""

        # Правила несовместимости
        incompatible_patterns = [
            ("fake", "disorder"),  # Конфликт механизмов
            ("split", "multisplit"),  # Дублирование
            ("seqovl", "disorder"),  # Конфликт последовательностей
        ]

        for pattern1, pattern2 in incompatible_patterns:
            if (pattern1 in attack1 and pattern2 in attack2) or (
                pattern2 in attack1 and pattern1 in attack2
            ):
                return False

        return True

    def _generate_combination_parameters(
        self, attacks: List[str], fingerprint: Optional[Any]
    ) -> Dict[str, Any]:
        """Генерация параметров для комбинации атак"""

        params = {}

        # Базовые параметры для комбинаций
        if len(attacks) == 2:
            # Для двойных комбинаций используем умеренные параметры
            params.update({"split_pos": 3, "ttl": 2, "fooling": "badsum"})
        elif len(attacks) >= 3:
            # Для тройных комбинаций используем более агрессивные параметры
            params.update({"split_pos": 2, "ttl": 1, "fooling": "badseq", "split_count": 4})

        # Адаптируем под fingerprint
        if fingerprint:
            params = self._adapt_parameters_for_dpi(params, fingerprint, None)

        return params

    def _calculate_combination_success(
        self,
        attacks: List[str],
        source_intents: List[str],
        all_intents: List[Any],
        fingerprint: Optional[Any],
    ) -> float:
        """Вычисление ожидаемой эффективности комбинации"""

        # Базовая эффективность как среднее от Intent'ов
        intent_priorities = []
        for intent in all_intents:
            if intent.key in source_intents:
                intent_priorities.append(getattr(intent, "priority", 0.5))

        base_success = sum(intent_priorities) / len(intent_priorities) if intent_priorities else 0.5

        # Бонус за комбинирование (синергия)
        combination_bonus = min(0.2, len(attacks) * 0.05)

        # Штраф за сложность
        complexity_penalty = max(0, (len(attacks) - 2) * 0.1)

        # Модификатор от fingerprint
        fingerprint_modifier = 1.0
        if fingerprint and hasattr(fingerprint, "confidence"):
            fingerprint_modifier = 0.9 + (fingerprint.confidence * 0.2)

        expected_success = (
            base_success + combination_bonus - complexity_penalty
        ) * fingerprint_modifier

        return max(0.0, min(1.0, expected_success))

    def _calculate_complexity_score(self, attacks: List[str]) -> float:
        """Вычисление оценки сложности стратегии"""

        # Базовая сложность от количества атак
        base_complexity = len(attacks) * 0.2

        # Дополнительная сложность от типов атак
        complexity_weights = {
            "fake": 0.3,
            "disorder": 0.4,
            "multisplit": 0.5,
            "seqovl": 0.6,
            "multidisorder": 0.7,
        }

        type_complexity = 0
        for attack in attacks:
            for attack_type, weight in complexity_weights.items():
                if attack_type in attack:
                    type_complexity += weight
                    break

        total_complexity = base_complexity + (type_complexity / len(attacks))

        return min(1.0, total_complexity)

    def _optimize_parameters_for_dpi(
        self, base_params: Dict[str, Any], attacks: List[str], fingerprint: Optional[Any]
    ) -> Dict[str, Any]:
        """Оптимизация параметров под характеристики DPI"""

        optimized_params = base_params.copy()

        if not fingerprint:
            return optimized_params

        try:
            # Специфическая оптимизация для разных типов DPI
            if hasattr(fingerprint, "dpi_type"):
                dpi_type = fingerprint.dpi_type.value

                if dpi_type == "stateless":
                    # Для stateless DPI оптимизируем порядок и фрагментацию
                    if "split_count" in optimized_params:
                        optimized_params["split_count"] = min(
                            16, optimized_params["split_count"] * 2
                        )
                    if "disorder" in str(attacks):
                        optimized_params["split_pos"] = 2  # Более эффективная позиция

                elif dpi_type == "stateful":
                    # Для stateful DPI оптимизируем TTL и fooling
                    optimized_params["ttl"] = 1
                    optimized_params["fooling"] = "badseq"

            # Оптимизация под известные уязвимости
            if hasattr(fingerprint, "known_weaknesses"):
                for weakness in fingerprint.known_weaknesses:
                    if "fragmentation" in weakness:
                        optimized_params["split_count"] = max(
                            8, optimized_params.get("split_count", 4)
                        )
                    elif "sni" in weakness:
                        optimized_params["split_pos"] = "sni"

            # Оптимизация под confidence level
            if hasattr(fingerprint, "confidence"):
                if fingerprint.confidence > 0.8:
                    # Высокая уверенность - используем агрессивные параметры
                    if "ttl" in optimized_params:
                        optimized_params["ttl"] = 1
                    if "split_count" in optimized_params:
                        optimized_params["split_count"] = max(8, optimized_params["split_count"])
                elif fingerprint.confidence < 0.4:
                    # Низкая уверенность - используем консервативные параметры
                    if "ttl" in optimized_params:
                        optimized_params["ttl"] = max(3, optimized_params.get("ttl", 2))
                    if "split_count" in optimized_params:
                        optimized_params["split_count"] = min(4, optimized_params["split_count"])

        except Exception as e:
            LOG.warning(f"Ошибка оптимизации параметров: {e}")

        return optimized_params

    def _calculate_dpi_compatibility_bonus(
        self, strategy: GeneratedStrategy, fingerprint: Any
    ) -> float:
        """Вычисление бонуса за совместимость с DPI характеристиками"""

        bonus = 0.0

        try:
            # Бонус за соответствие типу DPI
            if hasattr(fingerprint, "dpi_type"):
                dpi_type = fingerprint.dpi_type.value

                if dpi_type == "stateless" and any(
                    "disorder" in attack for attack in strategy.attack_combination
                ):
                    bonus += 0.1
                elif dpi_type == "stateful" and any(
                    "fake" in attack for attack in strategy.attack_combination
                ):
                    bonus += 0.1

            # Бонус за соответствие режиму DPI
            if hasattr(fingerprint, "dpi_mode"):
                dpi_mode = fingerprint.dpi_mode.value

                if dpi_mode == "active_rst" and strategy.parameters.get("ttl") == 1:
                    bonus += 0.05

            # Бонус за использование известных уязвимостей
            if hasattr(fingerprint, "known_weaknesses"):
                for weakness in fingerprint.known_weaknesses:
                    if "fragmentation" in weakness and "split" in str(strategy.attack_combination):
                        bonus += 0.05
                    elif "sni" in weakness and strategy.parameters.get("split_pos") == "sni":
                        bonus += 0.05

        except Exception as e:
            LOG.warning(f"Ошибка вычисления DPI бонуса: {e}")

        return bonus

    def generate_strategy_explanations(self, strategies: List[GeneratedStrategy]) -> Dict[str, str]:
        """Генерация объяснений для каждой стратегии"""

        explanations = {}

        for strategy in strategies:
            explanation_parts = []

            # Основная информация
            explanation_parts.append(f"🎯 Стратегия '{strategy.name}':")
            explanation_parts.append(f"   Метод генерации: {strategy.generation_method}")
            explanation_parts.append(
                f"   Ожидаемая эффективность: {strategy.expected_success_rate:.2f}"
            )
            explanation_parts.append(f"   Сложность: {strategy.complexity_score:.2f}")

            # Атаки в комбинации
            # Фильтруем None значения перед отображением
            filtered_attacks = [a for a in strategy.attack_combination if a is not None]
            if len(filtered_attacks) == 1:
                explanation_parts.append(f"   Атака: {filtered_attacks[0]}")
            elif len(filtered_attacks) > 1:
                explanation_parts.append(f"   Комбинация атак: {', '.join(filtered_attacks)}")

            # Источники Intent'ов
            if strategy.source_intents:
                # Фильтруем None значения
                filtered_intents = [i for i in strategy.source_intents if i is not None]
                if filtered_intents:
                    explanation_parts.append(f"   Источники: {', '.join(filtered_intents)}")

            # Ключевые параметры
            key_params = []
            for param, value in strategy.parameters.items():
                if param in ["split_pos", "ttl", "fooling", "split_count"]:
                    key_params.append(f"{param}={value}")

            if key_params:
                explanation_parts.append(f"   Параметры: {', '.join(key_params)}")

            # Обоснование
            explanation_parts.append(f"   💡 {strategy.rationale}")

            # Предупреждения
            if strategy.compatibility_warnings:
                # Фильтруем None значения
                filtered_warnings = [w for w in strategy.compatibility_warnings if w is not None]
                if filtered_warnings:
                    explanation_parts.append(f"   ⚠️ Предупреждения: {'; '.join(filtered_warnings)}")

            explanations[strategy.name] = "\n".join(explanation_parts)

        return explanations

    def get_generation_statistics(self) -> Dict[str, Any]:
        """Получение статистики генерации стратегий"""

        return {
            "total_generated": self.generation_stats["total_generated"],
            "by_method": self.generation_stats["by_method"].copy(),
            "successful_tests": self.generation_stats["successful_tests"],
            "failed_tests": self.generation_stats["failed_tests"],
            "success_rate": (
                self.generation_stats["successful_tests"]
                / max(
                    1,
                    self.generation_stats["successful_tests"]
                    + self.generation_stats["failed_tests"],
                )
            ),
            "components_loaded": {
                "attack_registry": self.attack_registry is not None,
                "attack_combinator": self.attack_combinator is not None,
                "smart_combinator": self.smart_combinator is not None,
                "parametric_optimizer": self.parametric_optimizer is not None,
                "parameter_optimizer": self.parameter_optimizer is not None,
                "intent_mapper": self.intent_mapper is not None,
            },
        }

    def update_strategy_test_result(
        self, strategy_name: str, success: bool, details: Dict[str, Any]
    ):
        """Обновление результатов тестирования стратегии"""

        if success:
            self.generation_stats["successful_tests"] += 1
        else:
            self.generation_stats["failed_tests"] += 1

        LOG.info(
            f"Обновлен результат тестирования {strategy_name}: {'успех' if success else 'неудача'}"
        )


# Пример использования
if __name__ == "__main__":
    import asyncio

    async def test_strategy_generator():
        # Создаем генератор
        generator = StrategyGenerator()

        # Создаем тестовые Intent'ы
        from core.strategy.strategy_intent_engine import StrategyIntent

        test_intents = [
            StrategyIntent(
                key="conceal_sni",
                priority=0.9,
                rationale="Скрыть SNI от DPI",
                parameter_ranges={"split_count": [4, 8, 16]},
            ),
            StrategyIntent(
                key="short_ttl_decoy",
                priority=0.85,
                rationale="Обход активного RST",
                parameter_ranges={"ttl": [1, 2, 3]},
            ),
        ]

        # Генерируем стратегии
        strategies = await generator.generate_strategies(test_intents, max_strategies=10)

        print(f"Сгенерировано {len(strategies)} стратегий:")
        for strategy in strategies:
            print(f"  - {strategy.name} (эффективность: {strategy.expected_success_rate:.2f})")

        # Получаем объяснения
        explanations = generator.generate_strategy_explanations(strategies[:3])

        print("\nОбъяснения стратегий:")
        for name, explanation in explanations.items():
            print(f"\n{explanation}")

        # Статистика
        stats = generator.get_generation_statistics()
        print(f"\nСтатистика генератора: {stats}")

    # Запускаем тест
    asyncio.run(test_strategy_generator())
