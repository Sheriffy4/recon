# core/strategy/smart_attack_combinator.py
"""
Smart Attack Combinator - Task 5.2 Implementation
Умное комбинирование атак с проверкой совместимости и генерацией параметров.

Интегрируется с существующим AttackCombinator для создания комбинированных стратегий.
Реализует требования FR-2 для адаптивной системы мониторинга.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from itertools import combinations, permutations

LOG = logging.getLogger("smart_attack_combinator")


@dataclass
class AttackCompatibility:
    """Информация о совместимости атак"""

    attack1: str
    attack2: str
    compatible: bool
    compatibility_score: float  # 0.0 - 1.0
    synergy_bonus: float = 0.0  # Дополнительный бонус за синергию
    conflict_reason: Optional[str] = None
    recommended_order: Optional[List[str]] = None


@dataclass
class CombinationStrategy:
    """Стратегия комбинирования атак"""

    attacks: List[str]
    execution_order: List[str]
    parameters: Dict[str, Any]
    compatibility_score: float
    expected_effectiveness: float
    synergy_effects: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class AttackCategory(Enum):
    """Категории атак для анализа совместимости"""

    FRAGMENTATION = "fragmentation"  # split, multisplit
    DECEPTION = "deception"  # fake, disorder
    SEQUENCE_MANIPULATION = "sequence_manipulation"  # seqovl, multidisorder
    TIMING = "timing"  # delay-based attacks
    PROTOCOL_LEVEL = "protocol_level"  # TLS, HTTP specific
    NETWORK_LEVEL = "network_level"  # IP fragmentation


class SmartAttackCombinator:
    """
    Умный комбинатор атак с анализом совместимости и синергии.

    Интегрируется с существующим AttackCombinator для расширенной функциональности.
    """

    def __init__(self):
        self.attack_combinator = None
        self.attack_registry = None

        # Матрица совместимости атак
        self.compatibility_matrix = self._build_compatibility_matrix()

        # Правила синергии
        self.synergy_rules = self._build_synergy_rules()

        # Категоризация атак
        self.attack_categories = self._categorize_attacks()

        # Статистика комбинирования
        self.combination_stats = {
            "total_combinations_generated": 0,
            "compatible_combinations": 0,
            "synergistic_combinations": 0,
            "rejected_combinations": 0,
        }

        self._initialize_components()

    def _initialize_components(self):
        """Инициализация интеграционных компонентов"""

        # Загружаем AttackCombinator
        try:
            from core.attack_combinator import AttackCombinator

            self.attack_combinator = AttackCombinator()
            LOG.info("Загружен AttackCombinator для интеграции")
        except ImportError as e:
            LOG.error(f"Не удалось загрузить AttackCombinator: {e}")

        # Загружаем AttackRegistry
        try:
            from core.bypass.attacks import get_attack_registry

            self.attack_registry = get_attack_registry()
            LOG.info(
                f"Загружен AttackRegistry с {len(self.attack_registry.list_attacks())} атаками"
            )
        except ImportError as e:
            LOG.error(f"Не удалось загрузить AttackRegistry: {e}")

    def _build_compatibility_matrix(self) -> Dict[Tuple[str, str], AttackCompatibility]:
        """Построение матрицы совместимости атак"""

        matrix = {}

        # Определяем правила совместимости
        compatibility_rules = [
            # Совместимые комбинации
            ("fake", "split", True, 0.9, 0.1, "Fake packet + fragmentation работают синергично"),
            (
                "fake",
                "multisplit",
                True,
                0.85,
                0.15,
                "Fake packet усиливает множественную фрагментацию",
            ),
            (
                "disorder",
                "multisplit",
                True,
                0.8,
                0.1,
                "Disorder + multisplit создают сложную структуру",
            ),
            ("split", "seqovl", True, 0.75, 0.05, "Fragmentation + sequence overlap"),
            ("fake", "seqovl", True, 0.8, 0.1, "Fake packet + sequence overlap"),
            # Частично совместимые
            (
                "multisplit",
                "multidisorder",
                True,
                0.6,
                0.0,
                "Сложная комбинация, требует осторожности",
            ),
            ("fake", "disorder", True, 0.5, 0.0, "Возможны конфликты в механизмах"),
            ("split", "multisplit", True, 0.3, 0.0, "Дублирование функциональности - избегать"),
            # Несовместимые комбинации
            ("disorder", "seqovl", False, 0.2, 0.0, "Конфликт в управлении последовательностями"),
            ("fake", "fakeddisorder", False, 0.1, 0.0, "Дублирование fake механизма"),
            ("multidisorder", "seqovl", False, 0.3, 0.0, "Сложные конфликты последовательностей"),
        ]

        # Заполняем матрицу
        for attack1, attack2, compatible, score, synergy, reason in compatibility_rules:
            # Прямое направление
            matrix[(attack1, attack2)] = AttackCompatibility(
                attack1=attack1,
                attack2=attack2,
                compatible=compatible,
                compatibility_score=score,
                synergy_bonus=synergy,
                conflict_reason=None if compatible else reason,
                recommended_order=[attack1, attack2] if compatible else None,
            )

            # Обратное направление (может отличаться порядком)
            matrix[(attack2, attack1)] = AttackCompatibility(
                attack1=attack2,
                attack2=attack1,
                compatible=compatible,
                compatibility_score=score,
                synergy_bonus=synergy,
                conflict_reason=None if compatible else reason,
                recommended_order=[attack2, attack1] if compatible else None,
            )

        LOG.info(f"Построена матрица совместимости для {len(matrix)} пар атак")
        return matrix

    def _build_synergy_rules(self) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """Построение правил синергии между атаками"""

        synergy_rules = {
            # Fake + Fragmentation синергия
            ("fake", "split"): {
                "effect": "enhanced_deception",
                "parameter_adjustments": {"ttl": 1, "split_pos": 3},
                "effectiveness_multiplier": 1.2,
                "description": "Fake packet маскирует фрагментацию",
            },
            ("fake", "multisplit"): {
                "effect": "complex_deception",
                "parameter_adjustments": {"ttl": 1, "split_count": 8},
                "effectiveness_multiplier": 1.3,
                "description": "Fake packet + множественная фрагментация создают сложную структуру",
            },
            # Disorder + Split синергия
            ("disorder", "multisplit"): {
                "effect": "chaos_amplification",
                "parameter_adjustments": {"split_count": 6, "split_pos": 2},
                "effectiveness_multiplier": 1.15,
                "description": "Disorder усиливает эффект множественной фрагментации",
            },
            # Sequence overlap синергии
            ("fake", "seqovl"): {
                "effect": "sequence_confusion",
                "parameter_adjustments": {"ttl": 1, "overlap_size": 4},
                "effectiveness_multiplier": 1.25,
                "description": "Fake packet + sequence overlap создают путаницу в TCP state",
            },
            ("split", "seqovl"): {
                "effect": "fragmented_overlap",
                "parameter_adjustments": {"split_pos": 2, "overlap_size": 2},
                "effectiveness_multiplier": 1.1,
                "description": "Фрагментация + перекрытие последовательностей",
            },
        }

        # Добавляем обратные направления
        reverse_rules = {}
        for (attack1, attack2), rule in synergy_rules.items():
            reverse_rules[(attack2, attack1)] = rule.copy()
            # Может потребоваться корректировка порядка параметров

        synergy_rules.update(reverse_rules)

        LOG.info(f"Построены правила синергии для {len(synergy_rules)} комбинаций")
        return synergy_rules

    def _categorize_attacks(self) -> Dict[str, AttackCategory]:
        """Категоризация атак по типам"""

        categories = {
            # Fragmentation attacks
            "split": AttackCategory.FRAGMENTATION,
            "multisplit": AttackCategory.FRAGMENTATION,
            "tls_chello_frag": AttackCategory.FRAGMENTATION,
            # Deception attacks
            "fake": AttackCategory.DECEPTION,
            "disorder": AttackCategory.DECEPTION,
            "fakeddisorder": AttackCategory.DECEPTION,
            # Sequence manipulation
            "seqovl": AttackCategory.SEQUENCE_MANIPULATION,
            "multidisorder": AttackCategory.SEQUENCE_MANIPULATION,
            # Protocol level
            "tls_sni_split": AttackCategory.PROTOCOL_LEVEL,
            "http_header_attacks": AttackCategory.PROTOCOL_LEVEL,
            # Network level
            "ip_fragmentation": AttackCategory.NETWORK_LEVEL,
        }

        return categories

    def generate_attack_combinations(
        self,
        available_attacks: List[str],
        max_combination_size: int = 3,
        min_compatibility_score: float = 0.5,
    ) -> List[CombinationStrategy]:
        """
        Генерация умных комбинаций атак с проверкой совместимости.

        Args:
            available_attacks: Список доступных атак
            max_combination_size: Максимальный размер комбинации
            min_compatibility_score: Минимальный score совместимости

        Returns:
            Список CombinationStrategy отсортированный по эффективности
        """

        # Фильтруем None значения из списка атак
        available_attacks = [a for a in available_attacks if a is not None and isinstance(a, str)]

        LOG.info(f"Генерация комбинаций из {len(available_attacks)} атак")

        all_combinations = []

        # Генерируем комбинации разных размеров
        for size in range(2, min(max_combination_size + 1, len(available_attacks) + 1)):
            size_combinations = self._generate_combinations_of_size(
                available_attacks, size, min_compatibility_score
            )
            all_combinations.extend(size_combinations)

        # Сортируем по ожидаемой эффективности
        sorted_combinations = sorted(
            all_combinations, key=lambda c: c.expected_effectiveness, reverse=True
        )

        # Обновляем статистику
        self.combination_stats["total_combinations_generated"] += len(all_combinations)
        self.combination_stats["compatible_combinations"] += len(sorted_combinations)

        LOG.info(f"Сгенерировано {len(sorted_combinations)} совместимых комбинаций")
        return sorted_combinations

    def _generate_combinations_of_size(
        self, attacks: List[str], size: int, min_compatibility_score: float
    ) -> List[CombinationStrategy]:
        """Генерация комбинаций определенного размера"""

        combinations_list = []

        # Генерируем все возможные комбинации
        for attack_combo in combinations(attacks, size):
            attack_list = list(attack_combo)

            # Проверяем совместимость
            compatibility_result = self.check_combination_compatibility(attack_list)

            if not compatibility_result["compatible"]:
                self.combination_stats["rejected_combinations"] += 1
                continue

            if compatibility_result["overall_score"] < min_compatibility_score:
                self.combination_stats["rejected_combinations"] += 1
                continue

            # Определяем оптимальный порядок выполнения
            execution_order = self._determine_execution_order(attack_list)

            # Генерируем параметры для комбинации
            combo_parameters = self._generate_combination_parameters(attack_list)

            # Вычисляем ожидаемую эффективность
            effectiveness = self._calculate_combination_effectiveness(
                attack_list, compatibility_result
            )

            # Проверяем синергию
            synergy_effects = self._analyze_synergy_effects(attack_list)
            if synergy_effects:
                self.combination_stats["synergistic_combinations"] += 1

            # Создаем стратегию комбинации
            combination_strategy = CombinationStrategy(
                attacks=attack_list,
                execution_order=execution_order,
                parameters=combo_parameters,
                compatibility_score=compatibility_result["overall_score"],
                expected_effectiveness=effectiveness,
                synergy_effects=synergy_effects,
                warnings=compatibility_result.get("warnings", []),
            )

            combinations_list.append(combination_strategy)

        return combinations_list

    def check_combination_compatibility(self, attacks: List[str]) -> Dict[str, Any]:
        """
        Проверка совместимости комбинации атак.

        Args:
            attacks: Список атак в комбинации

        Returns:
            Словарь с результатами анализа совместимости
        """

        if len(attacks) < 2:
            return {
                "compatible": True,
                "overall_score": 1.0,
                "pairwise_scores": {},
                "conflicts": [],
                "warnings": [],
            }

        pairwise_scores = {}
        conflicts = []
        warnings = []

        # Проверяем все пары атак
        for i in range(len(attacks)):
            for j in range(i + 1, len(attacks)):
                attack1, attack2 = attacks[i], attacks[j]

                # Получаем информацию о совместимости
                compatibility = self._get_attack_compatibility(attack1, attack2)

                pair_key = f"{attack1}+{attack2}"
                pairwise_scores[pair_key] = compatibility.compatibility_score

                if not compatibility.compatible:
                    conflicts.append(
                        {
                            "attacks": [attack1, attack2],
                            "reason": compatibility.conflict_reason,
                            "score": compatibility.compatibility_score,
                        }
                    )
                elif compatibility.compatibility_score < 0.7:
                    warnings.append(f"Низкая совместимость между {attack1} и {attack2}")

        # Вычисляем общий score
        if pairwise_scores:
            overall_score = sum(pairwise_scores.values()) / len(pairwise_scores)
        else:
            overall_score = 1.0

        # Определяем общую совместимость
        compatible = len(conflicts) == 0 and overall_score >= 0.3

        return {
            "compatible": compatible,
            "overall_score": overall_score,
            "pairwise_scores": pairwise_scores,
            "conflicts": conflicts,
            "warnings": warnings,
        }

    def _get_attack_compatibility(self, attack1: str, attack2: str) -> AttackCompatibility:
        """Получение информации о совместимости двух атак"""

        # Проверяем в матрице совместимости
        pair_key = (attack1, attack2)
        if pair_key in self.compatibility_matrix:
            return self.compatibility_matrix[pair_key]

        # Если нет в матрице, используем эвристики
        return self._calculate_heuristic_compatibility(attack1, attack2)

    def _calculate_heuristic_compatibility(self, attack1: str, attack2: str) -> AttackCompatibility:
        """Эвристический расчет совместимости для неизвестных пар"""

        # Получаем категории атак
        cat1 = self.attack_categories.get(attack1, AttackCategory.FRAGMENTATION)
        cat2 = self.attack_categories.get(attack2, AttackCategory.FRAGMENTATION)

        # Правила совместимости по категориям
        category_compatibility = {
            (AttackCategory.FRAGMENTATION, AttackCategory.DECEPTION): 0.8,
            (AttackCategory.FRAGMENTATION, AttackCategory.SEQUENCE_MANIPULATION): 0.7,
            (AttackCategory.DECEPTION, AttackCategory.SEQUENCE_MANIPULATION): 0.6,
            (AttackCategory.PROTOCOL_LEVEL, AttackCategory.NETWORK_LEVEL): 0.9,
            (AttackCategory.TIMING, AttackCategory.FRAGMENTATION): 0.7,
        }

        # Проверяем прямое и обратное направления
        score = category_compatibility.get(
            (cat1, cat2), category_compatibility.get((cat2, cat1), 0.5)
        )

        # Штраф за одинаковые категории (возможное дублирование)
        if cat1 == cat2:
            score *= 0.6

        compatible = score >= 0.4

        return AttackCompatibility(
            attack1=attack1,
            attack2=attack2,
            compatible=compatible,
            compatibility_score=score,
            synergy_bonus=0.0,
            conflict_reason=None if compatible else "Эвристическая несовместимость",
            recommended_order=[attack1, attack2] if compatible else None,
        )

    def _determine_execution_order(self, attacks: List[str]) -> List[str]:
        """Определение оптимального порядка выполнения атак"""

        if len(attacks) <= 1:
            return attacks

        # Приоритеты выполнения атак
        execution_priorities = {
            "fake": 1,  # Fake packets должны идти первыми
            "split": 2,  # Затем фрагментация
            "multisplit": 2,
            "disorder": 3,  # Disorder после фрагментации
            "seqovl": 4,  # Sequence overlap в конце
            "multidisorder": 4,
        }

        # Сортируем по приоритетам
        sorted_attacks = sorted(attacks, key=lambda attack: execution_priorities.get(attack, 5))

        # Проверяем рекомендованный порядок из матрицы совместимости
        for i in range(len(sorted_attacks) - 1):
            attack1, attack2 = sorted_attacks[i], sorted_attacks[i + 1]
            compatibility = self._get_attack_compatibility(attack1, attack2)

            if compatibility.recommended_order:
                # Если есть рекомендованный порядок, используем его
                if compatibility.recommended_order != [attack1, attack2]:
                    # Меняем местами
                    sorted_attacks[i], sorted_attacks[i + 1] = (
                        sorted_attacks[i + 1],
                        sorted_attacks[i],
                    )

        return sorted_attacks

    def _generate_combination_parameters(self, attacks: List[str]) -> Dict[str, Any]:
        """Генерация параметров для комбинации атак"""

        base_params = {}

        # Базовые параметры в зависимости от типов атак
        if any("fake" in attack for attack in attacks):
            base_params.update({"ttl": 1, "fooling": "badseq"})  # Короткий TTL для fake packets

        if any("split" in attack for attack in attacks):
            base_params.update(
                {"split_pos": 3, "split_count": 4 if "multisplit" in str(attacks) else 2}
            )

        if any("disorder" in attack for attack in attacks):
            base_params.update({"disorder_method": "reverse"})

        if any("seqovl" in attack for attack in attacks):
            base_params.update({"overlap_size": 4})

        # Применяем синергетические корректировки
        for i in range(len(attacks)):
            for j in range(i + 1, len(attacks)):
                attack1, attack2 = attacks[i], attacks[j]
                synergy_rule = self.synergy_rules.get((attack1, attack2))

                if synergy_rule and "parameter_adjustments" in synergy_rule:
                    base_params.update(synergy_rule["parameter_adjustments"])

        return base_params

    def _calculate_combination_effectiveness(
        self, attacks: List[str], compatibility_result: Dict[str, Any]
    ) -> float:
        """Вычисление ожидаемой эффективности комбинации"""

        # Базовая эффективность от совместимости
        base_effectiveness = compatibility_result["overall_score"]

        # Бонус за количество атак (до определенного предела)
        size_bonus = min(0.2, len(attacks) * 0.05)

        # Бонус за синергию
        synergy_bonus = 0.0
        for i in range(len(attacks)):
            for j in range(i + 1, len(attacks)):
                attack1, attack2 = attacks[i], attacks[j]
                compatibility = self._get_attack_compatibility(attack1, attack2)
                synergy_bonus += compatibility.synergy_bonus

        # Штраф за сложность
        complexity_penalty = max(0, (len(attacks) - 2) * 0.1)

        # Бонус за разнообразие категорий
        categories = set(
            self.attack_categories.get(attack, AttackCategory.FRAGMENTATION) for attack in attacks
        )
        diversity_bonus = min(0.15, (len(categories) - 1) * 0.05)

        total_effectiveness = (
            base_effectiveness + size_bonus + synergy_bonus + diversity_bonus - complexity_penalty
        )

        return max(0.0, min(1.0, total_effectiveness))

    def _analyze_synergy_effects(self, attacks: List[str]) -> List[str]:
        """Анализ синергетических эффектов в комбинации"""

        synergy_effects = []

        for i in range(len(attacks)):
            for j in range(i + 1, len(attacks)):
                attack1, attack2 = attacks[i], attacks[j]

                # Проверяем правила синергии
                synergy_rule = self.synergy_rules.get((attack1, attack2))
                if synergy_rule:
                    effect_description = synergy_rule.get("description", "")
                    if effect_description:
                        synergy_effects.append(effect_description)

                # Проверяем совместимость для синергии
                compatibility = self._get_attack_compatibility(attack1, attack2)
                if compatibility.synergy_bonus > 0:
                    synergy_effects.append(f"Синергия между {attack1} и {attack2}")

        return synergy_effects

    def optimize_combination_parameters(
        self, combination: CombinationStrategy, fingerprint: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Оптимизация параметров комбинации под DPI характеристики"""

        optimized_params = combination.parameters.copy()

        if not fingerprint:
            return optimized_params

        try:
            # Оптимизация под тип DPI
            if hasattr(fingerprint, "dpi_type"):
                dpi_type = fingerprint.dpi_type.value

                if dpi_type == "stateless":
                    # Для stateless DPI увеличиваем сложность
                    if "split_count" in optimized_params:
                        optimized_params["split_count"] = min(
                            16, optimized_params["split_count"] * 2
                        )

                elif dpi_type == "stateful":
                    # Для stateful DPI используем агрессивные параметры
                    optimized_params["ttl"] = 1
                    optimized_params["fooling"] = "badseq"

            # Оптимизация под режим DPI
            if hasattr(fingerprint, "dpi_mode"):
                dpi_mode = fingerprint.dpi_mode.value

                if dpi_mode == "active_rst":
                    # Для активного RST используем специальные параметры
                    optimized_params["ttl"] = 1
                    if "overlap_size" in optimized_params:
                        optimized_params["overlap_size"] = max(4, optimized_params["overlap_size"])

            # Применяем синергетические корректировки для DPI
            for attack1, attack2 in combinations(combination.attacks, 2):
                synergy_rule = self.synergy_rules.get((attack1, attack2))
                if synergy_rule and fingerprint.confidence > 0.7:
                    # Применяем синергетические параметры только при высокой уверенности
                    synergy_params = synergy_rule.get("parameter_adjustments", {})
                    optimized_params.update(synergy_params)

        except Exception as e:
            LOG.warning(f"Ошибка оптимизации параметров комбинации: {e}")

        return optimized_params

    def rank_combinations_by_effectiveness(
        self, combinations: List[CombinationStrategy], fingerprint: Optional[Any] = None
    ) -> List[CombinationStrategy]:
        """Ранжирование комбинаций по эффективности с учетом DPI"""

        # Вычисляем финальные scores
        for combination in combinations:
            score = combination.expected_effectiveness

            # Бонус за высокую совместимость
            if combination.compatibility_score > 0.8:
                score += 0.1

            # Бонус за синергию
            if combination.synergy_effects:
                score += len(combination.synergy_effects) * 0.05

            # Штраф за предупреждения
            if combination.warnings:
                score -= len(combination.warnings) * 0.03

            # Бонус за соответствие DPI (если доступен fingerprint)
            if fingerprint:
                dpi_bonus = self._calculate_dpi_match_bonus(combination, fingerprint)
                score += dpi_bonus

            # Обновляем эффективность
            combination.expected_effectiveness = max(0.0, min(1.0, score))

        # Сортируем по финальному score
        return sorted(combinations, key=lambda c: c.expected_effectiveness, reverse=True)

    def _calculate_dpi_match_bonus(
        self, combination: CombinationStrategy, fingerprint: Any
    ) -> float:
        """Вычисление бонуса за соответствие DPI характеристикам"""

        bonus = 0.0

        try:
            # Бонус за соответствие типу DPI
            if hasattr(fingerprint, "dpi_type"):
                dpi_type = fingerprint.dpi_type.value

                if dpi_type == "stateless":
                    # Для stateless DPI бонус за disorder и reordering
                    if any("disorder" in attack for attack in combination.attacks):
                        bonus += 0.1

                elif dpi_type == "stateful":
                    # Для stateful DPI бонус за fake и sequence manipulation
                    if any("fake" in attack for attack in combination.attacks):
                        bonus += 0.1
                    if any("seqovl" in attack for attack in combination.attacks):
                        bonus += 0.05

            # Бонус за использование известных уязвимостей
            if hasattr(fingerprint, "known_weaknesses"):
                for weakness in fingerprint.known_weaknesses:
                    if "fragmentation" in weakness and any(
                        "split" in attack for attack in combination.attacks
                    ):
                        bonus += 0.05
                    elif "sni" in weakness and combination.parameters.get("split_pos") == "sni":
                        bonus += 0.05

        except Exception as e:
            LOG.warning(f"Ошибка вычисления DPI бонуса: {e}")

        return bonus

    def get_combination_explanation(self, combination: CombinationStrategy) -> str:
        """Генерация объяснения для комбинации атак"""

        explanation_parts = []

        # Фильтруем None значения из attacks и execution_order
        filtered_attacks = [a for a in combination.attacks if a is not None]
        filtered_execution_order = [e for e in combination.execution_order if e is not None]

        # Основная информация
        explanation_parts.append(f"🔗 Комбинация: {' + '.join(filtered_attacks)}")
        explanation_parts.append(f"   Порядок выполнения: {' → '.join(filtered_execution_order)}")
        explanation_parts.append(f"   Совместимость: {combination.compatibility_score:.2f}")
        explanation_parts.append(
            f"   Ожидаемая эффективность: {combination.expected_effectiveness:.2f}"
        )

        # Синергетические эффекты
        if combination.synergy_effects:
            explanation_parts.append("   🔥 Синергия:")
            for effect in combination.synergy_effects:
                explanation_parts.append(f"      - {effect}")

        # Ключевые параметры
        key_params = []
        for param, value in combination.parameters.items():
            if param in ["split_pos", "ttl", "fooling", "split_count", "overlap_size"]:
                key_params.append(f"{param}={value}")

        if key_params:
            explanation_parts.append(f"   🔧 Параметры: {', '.join(key_params)}")

        # Предупреждения
        if combination.warnings:
            explanation_parts.append("   ⚠️ Предупреждения:")
            for warning in combination.warnings:
                explanation_parts.append(f"      - {warning}")

        return "\n".join(explanation_parts)

    def get_combination_statistics(self) -> Dict[str, Any]:
        """Получение статистики комбинирования"""

        total_generated = self.combination_stats["total_combinations_generated"]

        return {
            "total_combinations_generated": total_generated,
            "compatible_combinations": self.combination_stats["compatible_combinations"],
            "synergistic_combinations": self.combination_stats["synergistic_combinations"],
            "rejected_combinations": self.combination_stats["rejected_combinations"],
            "compatibility_rate": (
                self.combination_stats["compatible_combinations"] / max(1, total_generated)
            ),
            "synergy_rate": (
                self.combination_stats["synergistic_combinations"]
                / max(1, self.combination_stats["compatible_combinations"])
            ),
            "components_loaded": {
                "attack_combinator": self.attack_combinator is not None,
                "attack_registry": self.attack_registry is not None,
            },
            "compatibility_matrix_size": len(self.compatibility_matrix),
            "synergy_rules_count": len(self.synergy_rules),
        }


# Пример использования
if __name__ == "__main__":
    # Создаем умный комбинатор
    combinator = SmartAttackCombinator()

    # Тестовые атаки
    test_attacks = ["fake", "split", "disorder", "multisplit", "seqovl"]

    # Генерируем комбинации
    combinations = combinator.generate_attack_combinations(
        test_attacks, max_combination_size=3, min_compatibility_score=0.5
    )

    print(f"Сгенерировано {len(combinations)} комбинаций:")

    for i, combo in enumerate(combinations[:5]):  # Показываем топ 5
        print(f"\n{i+1}. {combinator.get_combination_explanation(combo)}")

    # Статистика
    stats = combinator.get_combination_statistics()
    print(f"\nСтатистика комбинатора: {stats}")
