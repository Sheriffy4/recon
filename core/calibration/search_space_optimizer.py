"""
Search Space Optimizer - система сокращения пространства поиска стратегий
Реализует требования FR-2 для адаптивной системы мониторинга
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import hashlib

# Интеграция с существующими модулями
try:
    from core.fingerprint.dpi_fingerprint_service import DPIFingerprint, DPIType, DPIMode

    DFS_AVAILABLE = True
except ImportError:
    DFS_AVAILABLE = False

try:
    from intelligent_bypass_monitor import BypassStrategy

    BYPASS_STRATEGY_AVAILABLE = True
except ImportError:
    BYPASS_STRATEGY_AVAILABLE = False

    # Fallback
    @dataclass
    class BypassStrategy:
        name: str
        attack_type: str
        parameters: Dict[str, Any]
        success_rate: float = 0.0
        test_count: int = 0


try:
    from core.bypass.attacks.attack_registry import get_attack_registry

    ATTACK_REGISTRY_AVAILABLE = True
except ImportError:
    ATTACK_REGISTRY_AVAILABLE = False

LOG = logging.getLogger("SearchSpaceOptimizer")


class StrategyPriority(Enum):
    """Приоритеты стратегий"""

    CRITICAL = 1.0  # Высокая вероятность успеха
    HIGH = 0.8  # Хорошие шансы
    MEDIUM = 0.6  # Средние шансы
    LOW = 0.4  # Низкие шансы
    EXPERIMENTAL = 0.2  # Экспериментальные


@dataclass
class StrategyIntent:
    """Намерение стратегии - высокоуровневое описание подхода"""

    key: str  # "conceal_sni", "short_ttl_decoy", etc.
    priority: float  # 0.0 - 1.0
    rationale: str  # Объяснение логики
    preconditions: List[str] = field(default_factory=list)  # Условия применимости
    side_effects: List[str] = field(default_factory=list)  # Побочные эффекты
    parameter_ranges: Dict[str, Any] = field(default_factory=dict)  # Диапазоны параметров


@dataclass
class GeneratedStrategy:
    """Сгенерированная стратегия с метаданными"""

    name: str
    attack_combination: List[str]  # Список атак
    parameters: Dict[str, Any]

    # Метаданные генерации
    generation_method: str  # "intent_based", "ml_predicted", etc.
    source_intents: List[str]  # Исходные намерения
    expected_success_rate: float  # Ожидаемая вероятность успеха
    rationale: str  # Объяснение выбора

    # Результаты тестирования
    tested: bool = False
    actual_success_rate: Optional[float] = None

    def to_bypass_strategy(self) -> BypassStrategy:
        """Конвертация в BypassStrategy"""
        return BypassStrategy(
            name=self.name,
            attack_type=self.attack_combination[0] if self.attack_combination else "unknown",
            parameters=self.parameters,
            success_rate=self.actual_success_rate or 0.0,
            test_count=1 if self.tested else 0,
        )


@dataclass
class NegativeKnowledgeEntry:
    """Запись о неработающей стратегии"""

    domain: str
    strategy_signature: str  # Хэш стратегии
    attack_type: str
    parameters: Dict[str, Any]
    failure_reason: str
    confidence: float
    failed_at: datetime
    retry_after: Optional[datetime] = None  # Когда можно попробовать снова

    def is_expired(self, ttl_days: int = 7) -> bool:
        """Проверка истечения записи"""
        if self.retry_after:
            return datetime.now() > self.retry_after

        age = datetime.now() - self.failed_at
        return age > timedelta(days=ttl_days)


class StrategyIntentEngine:
    """
    Движок намерений стратегий - преобразует DPI характеристики в высокоуровневые намерения.

    Основная идея: вместо перебора всех возможных комбинаций параметров,
    сначала определяем КАКОЙ подход нужен, а потом генерируем конкретные стратегии.
    """

    def __init__(self):
        self.intent_rules = self._initialize_intent_rules()
        LOG.info("🧠 StrategyIntentEngine инициализирован")

    def _initialize_intent_rules(self) -> Dict[str, Any]:
        """Инициализация правил для определения намерений"""

        return {
            # Правила для SNI блокировки
            "sni_filtering_detected": {
                "intents": [
                    StrategyIntent(
                        key="conceal_sni",
                        priority=0.9,
                        rationale="DPI фильтрует по SNI - нужно скрыть или обфусцировать SNI",
                        preconditions=["sni_in_client_hello"],
                        parameter_ranges={"split_pos": ["sni"], "split_count": [2, 4, 8]},
                    ),
                    StrategyIntent(
                        key="fragment_client_hello",
                        priority=0.8,
                        rationale="Фрагментация ClientHello может обойти SNI фильтрацию",
                        parameter_ranges={"split_count": [3, 5, 10]},
                    ),
                ]
            },
            # Правила для RST инъекций
            "active_rst_injection": {
                "intents": [
                    StrategyIntent(
                        key="short_ttl_decoy",
                        priority=0.85,
                        rationale="DPI инжектирует RST - используем короткий TTL для обмана",
                        parameter_ranges={"ttl": [1, 2], "fooling": ["badseq", "badsum"]},
                    ),
                    StrategyIntent(
                        key="out_of_order_decoy",
                        priority=0.7,
                        rationale="Нарушение порядка пакетов может обойти RST инъекции",
                        parameter_ranges={"split_pos": [2, 3, 5]},
                    ),
                ]
            },
            # Правила для stateless DPI
            "stateless_dpi": {
                "intents": [
                    StrategyIntent(
                        key="packet_reordering",
                        priority=0.8,
                        rationale="Stateless DPI не отслеживает порядок - используем переупорядочивание",
                        parameter_ranges={"disorder_type": ["simple", "complex"]},
                    ),
                    StrategyIntent(
                        key="timing_manipulation",
                        priority=0.6,
                        rationale="Временные задержки могут обойти stateless анализ",
                    ),
                ]
            },
            # Правила для глубокой инспекции контента
            "deep_content_inspection": {
                "intents": [
                    StrategyIntent(
                        key="content_obfuscation",
                        priority=0.75,
                        rationale="DPI анализирует содержимое - нужна обфускация",
                        parameter_ranges={"obfuscation_method": ["fragmentation", "padding"]},
                    ),
                    StrategyIntent(
                        key="protocol_mimicry",
                        priority=0.65,
                        rationale="Маскировка под другой протокол",
                    ),
                ]
            },
        }

    def propose_intents(
        self, fingerprint: Optional[DPIFingerprint], failure_history: List[str] = None
    ) -> List[StrategyIntent]:
        """
        Предложение намерений на основе DPI fingerprint и истории неудач.

        Args:
            fingerprint: DPI fingerprint домена
            failure_history: История неудачных подходов

        Returns:
            Список намерений, отсортированных по приоритету
        """
        intents = []

        if not fingerprint:
            # Fallback к базовым намерениям
            return self._get_default_intents()

        # Анализируем характеристики DPI
        if fingerprint.behavioral_signatures.get("sni_filtering"):
            intents.extend(self.intent_rules["sni_filtering_detected"]["intents"])

        if fingerprint.dpi_mode == DPIMode.ACTIVE_RST:
            intents.extend(self.intent_rules["active_rst_injection"]["intents"])

        if fingerprint.dpi_type == DPIType.STATELESS:
            intents.extend(self.intent_rules["stateless_dpi"]["intents"])

        if fingerprint.behavioral_signatures.get("deep_content_inspection"):
            intents.extend(self.intent_rules["deep_content_inspection"]["intents"])

        # Учитываем известные уязвимости
        for weakness in fingerprint.known_weaknesses:
            if "vulnerable_to_fragmentation" in weakness:
                intents.append(
                    StrategyIntent(
                        key="exploit_fragmentation_weakness",
                        priority=0.95,
                        rationale=f"Известная уязвимость: {weakness}",
                    )
                )

        # Фильтруем на основе истории неудач
        if failure_history:
            intents = self._filter_by_failure_history(intents, failure_history)

        # Сортируем по приоритету
        intents.sort(key=lambda x: x.priority, reverse=True)

        # Ограничиваем количество для эффективности
        return intents[:5]

    def _get_default_intents(self) -> List[StrategyIntent]:
        """Базовые намерения для случаев без fingerprint"""

        return [
            StrategyIntent(
                key="basic_sni_concealment",
                priority=0.7,
                rationale="Базовое сокрытие SNI - работает в большинстве случаев",
            ),
            StrategyIntent(
                key="basic_fragmentation",
                priority=0.6,
                rationale="Базовая фрагментация - универсальный подход",
            ),
            StrategyIntent(
                key="basic_ttl_manipulation", priority=0.5, rationale="Базовая манипуляция TTL"
            ),
        ]

    def _filter_by_failure_history(
        self, intents: List[StrategyIntent], failure_history: List[str]
    ) -> List[StrategyIntent]:
        """Фильтрация намерений на основе истории неудач"""

        # Снижаем приоритет намерений, которые уже не сработали
        filtered_intents = []

        for intent in intents:
            if intent.key in failure_history:
                # Снижаем приоритет, но не исключаем полностью
                intent.priority *= 0.5
                intent.rationale += " (сниженный приоритет из-за предыдущих неудач)"

            # Исключаем только если приоритет стал слишком низким
            if intent.priority > 0.2:
                filtered_intents.append(intent)

        return filtered_intents


class TargetedStrategyGenerator:
    """
    Генератор целевых стратегий на основе намерений.

    Вместо полного перебора генерирует только те стратегии,
    которые имеют высокую вероятность успеха для данного DPI.
    """

    def __init__(self):
        self.intent_engine = StrategyIntentEngine()
        self.attack_registry = None

        if ATTACK_REGISTRY_AVAILABLE:
            try:
                self.attack_registry = get_attack_registry()
                LOG.info("✅ AttackRegistry подключен")
            except Exception as e:
                LOG.warning(f"⚠️ Ошибка подключения AttackRegistry: {e}")

        # Маппинг намерений на атаки
        self.intent_to_attacks = self._initialize_intent_mappings()

        LOG.info("🎯 TargetedStrategyGenerator инициализирован")

    def _initialize_intent_mappings(self) -> Dict[str, List[str]]:
        """Инициализация маппинга намерений на конкретные атаки"""

        return {
            "conceal_sni": ["fake", "multisplit", "tls_sni_split"],
            "fragment_client_hello": ["multisplit", "tls_chello_frag"],
            "short_ttl_decoy": ["fake", "disorder"],
            "out_of_order_decoy": ["disorder", "multidisorder", "seqovl"],
            "packet_reordering": ["disorder", "multidisorder"],
            "timing_manipulation": ["fake", "disorder"],
            "content_obfuscation": ["multisplit", "fake"],
            "protocol_mimicry": ["fake"],
            # Базовые намерения
            "basic_sni_concealment": ["fake", "multisplit"],
            "basic_fragmentation": ["multisplit", "disorder"],
            "basic_ttl_manipulation": ["fake"],
            # Специальные случаи
            "exploit_fragmentation_weakness": ["multisplit", "tls_chello_frag"],
        }

    def generate_strategies(
        self, fingerprint: Optional[DPIFingerprint], max_strategies: int = 15
    ) -> List[GeneratedStrategy]:
        """
        Генерация целевых стратегий на основе DPI fingerprint.

        Args:
            fingerprint: DPI fingerprint домена
            max_strategies: Максимальное количество стратегий

        Returns:
            Список сгенерированных стратегий, отсортированных по ожидаемой эффективности
        """
        LOG.info(f"🎯 Генерация целевых стратегий (макс: {max_strategies})")

        # Получаем намерения
        intents = self.intent_engine.propose_intents(fingerprint)
        LOG.info(f"🧠 Определено {len(intents)} намерений")

        strategies = []

        # Генерируем стратегии для каждого намерения
        for intent in intents:
            intent_strategies = self._generate_strategies_for_intent(intent, fingerprint)
            strategies.extend(intent_strategies)

            # Ограничиваем количество
            if len(strategies) >= max_strategies:
                break

        # Сортируем по ожидаемой эффективности
        strategies.sort(key=lambda x: x.expected_success_rate, reverse=True)

        # Ограничиваем финальный список
        final_strategies = strategies[:max_strategies]

        LOG.info(f"✅ Сгенерировано {len(final_strategies)} целевых стратегий")

        return final_strategies

    def _generate_strategies_for_intent(
        self, intent: StrategyIntent, fingerprint: Optional[DPIFingerprint]
    ) -> List[GeneratedStrategy]:
        """Генерация стратегий для конкретного намерения"""

        strategies = []

        # Получаем атаки для данного намерения
        attack_names = self.intent_to_attacks.get(intent.key, [])

        if not attack_names:
            LOG.warning(f"⚠️ Нет атак для намерения: {intent.key}")
            return strategies

        # Фильтруем доступные атаки
        available_attacks = self._filter_available_attacks(attack_names)

        for attack_name in available_attacks:
            # Генерируем параметры для атаки
            param_sets = self._generate_parameters_for_attack(attack_name, intent, fingerprint)

            for params in param_sets:
                strategy = GeneratedStrategy(
                    name=f"{attack_name}_{intent.key}_{len(strategies)}",
                    attack_combination=[attack_name],
                    parameters=params,
                    generation_method="intent_based",
                    source_intents=[intent.key],
                    expected_success_rate=intent.priority,
                    rationale=f"{intent.rationale} -> {attack_name}",
                )

                strategies.append(strategy)

        return strategies

    def _filter_available_attacks(self, attack_names: List[str]) -> List[str]:
        """Фильтрация доступных атак из registry"""

        if not self.attack_registry:
            # Fallback к базовому списку
            return [name for name in attack_names if name in ["fake", "multisplit", "disorder"]]

        try:
            available_attacks = self.attack_registry.list_attacks()
            return [name for name in attack_names if name in available_attacks]
        except Exception as e:
            LOG.warning(f"Ошибка получения списка атак: {e}")
            return attack_names  # Возвращаем все, надеясь что они доступны

    def _generate_parameters_for_attack(
        self, attack_name: str, intent: StrategyIntent, fingerprint: Optional[DPIFingerprint]
    ) -> List[Dict[str, Any]]:
        """Генерация параметров для конкретной атаки"""

        # Базовые параметры по типу атаки
        base_params = {
            "fake": [
                {"split_pos": "sni", "ttl": 1, "fooling": "badseq"},
                {"split_pos": "sni", "ttl": 2, "fooling": "badsum"},
                {"split_pos": 3, "ttl": 1, "fooling": "badseq"},
            ],
            "multisplit": [
                {"split_count": 5, "split_pos": "sni"},
                {"split_count": 8, "split_pos": "sni"},
                {"split_count": 10, "split_pos": "chello"},
            ],
            "disorder": [
                {"split_pos": 2, "fooling": "badseq"},
                {"split_pos": 3, "fooling": "badsum"},
                {"split_pos": 5, "fooling": "none"},
            ],
            "multidisorder": [
                {"split_count": 3, "split_pos": 2},
                {"split_count": 5, "split_pos": 3},
            ],
        }

        params_list = base_params.get(attack_name, [{}])

        # Адаптируем параметры под намерение
        adapted_params = []

        for params in params_list:
            adapted = params.copy()

            # Адаптация под намерение
            if intent.key == "short_ttl_decoy":
                adapted["ttl"] = 1
            elif intent.key == "fragment_client_hello":
                if "split_count" in adapted:
                    adapted["split_count"] = min(10, adapted.get("split_count", 5) + 2)
            elif intent.key == "conceal_sni":
                adapted["split_pos"] = "sni"

            # Адаптация под DPI характеристики
            if fingerprint:
                if fingerprint.dpi_mode == DPIMode.ACTIVE_RST:
                    adapted["ttl"] = 1
                    adapted["fooling"] = "badseq"
                elif fingerprint.dpi_type == DPIType.STATELESS:
                    # Для stateless DPI можем использовать более простые параметры
                    adapted.pop("fooling", None)

            adapted_params.append(adapted)

        return adapted_params


class NegativeKnowledgeManager:
    """
    Менеджер negative knowledge - системы избежания повторных ошибок.

    Отслеживает какие стратегии точно не работают для каждого домена
    и исключает их из будущих попыток.
    """

    def __init__(self, storage_file: str = "negative_knowledge.json"):
        self.storage_file = Path(storage_file)
        self.knowledge: Dict[str, Dict[str, NegativeKnowledgeEntry]] = {}
        self._load_knowledge()

        LOG.info(f"📚 NegativeKnowledgeManager инициализирован: {len(self.knowledge)} доменов")

    def _load_knowledge(self):
        """Загрузка negative knowledge из файла"""

        if not self.storage_file.exists():
            self.knowledge = {}
            return

        try:
            with open(self.storage_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Конвертируем данные в объекты
            for domain, entries in data.items():
                self.knowledge[domain] = {}

                for sig, entry_data in entries.items():
                    # Конвертируем даты
                    entry_data["failed_at"] = datetime.fromisoformat(entry_data["failed_at"])
                    if entry_data.get("retry_after"):
                        entry_data["retry_after"] = datetime.fromisoformat(
                            entry_data["retry_after"]
                        )

                    self.knowledge[domain][sig] = NegativeKnowledgeEntry(**entry_data)

            LOG.info(f"📚 Загружено negative knowledge для {len(self.knowledge)} доменов")

        except Exception as e:
            LOG.error(f"Ошибка загрузки negative knowledge: {e}")
            self.knowledge = {}

    def _save_knowledge(self):
        """Сохранение negative knowledge в файл"""

        try:
            # Конвертируем в сериализуемый формат
            data = {}

            for domain, entries in self.knowledge.items():
                data[domain] = {}

                for sig, entry in entries.items():
                    entry_data = {
                        "domain": entry.domain,
                        "strategy_signature": entry.strategy_signature,
                        "attack_type": entry.attack_type,
                        "parameters": entry.parameters,
                        "failure_reason": entry.failure_reason,
                        "confidence": entry.confidence,
                        "failed_at": entry.failed_at.isoformat(),
                        "retry_after": entry.retry_after.isoformat() if entry.retry_after else None,
                    }

                    data[domain][sig] = entry_data

            # Атомарная запись
            temp_file = self.storage_file.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            temp_file.replace(self.storage_file)

        except Exception as e:
            LOG.error(f"Ошибка сохранения negative knowledge: {e}")

    def add_failed_strategy(
        self, domain: str, strategy: GeneratedStrategy, failure_reason: str, confidence: float = 0.8
    ):
        """Добавление неудачной стратегии в negative knowledge"""

        # Создаем сигнатуру стратегии
        signature = self._create_strategy_signature(strategy)

        if domain not in self.knowledge:
            self.knowledge[domain] = {}

        # Определяем время повторной попытки (если confidence низкий)
        retry_after = None
        if confidence < 0.7:
            # Для неуверенных неудач разрешаем повтор через неделю
            retry_after = datetime.now() + timedelta(days=7)

        entry = NegativeKnowledgeEntry(
            domain=domain,
            strategy_signature=signature,
            attack_type=(
                strategy.attack_combination[0] if strategy.attack_combination else "unknown"
            ),
            parameters=strategy.parameters,
            failure_reason=failure_reason,
            confidence=confidence,
            failed_at=datetime.now(),
            retry_after=retry_after,
        )

        self.knowledge[domain][signature] = entry
        self._save_knowledge()

        LOG.info(f"📚 Добавлена неудачная стратегия: {domain} -> {strategy.name}")

    def is_strategy_blocked(self, domain: str, strategy: GeneratedStrategy) -> bool:
        """Проверка, заблокирована ли стратегия в negative knowledge"""

        if domain not in self.knowledge:
            return False

        signature = self._create_strategy_signature(strategy)

        if signature not in self.knowledge[domain]:
            return False

        entry = self.knowledge[domain][signature]

        # Проверяем истечение записи
        if entry.is_expired():
            # Удаляем устаревшую запись
            del self.knowledge[domain][signature]
            self._save_knowledge()
            return False

        return True

    def filter_strategies(
        self, domain: str, strategies: List[GeneratedStrategy]
    ) -> List[GeneratedStrategy]:
        """Фильтрация стратегий на основе negative knowledge"""

        if domain not in self.knowledge:
            return strategies

        filtered = []
        blocked_count = 0

        for strategy in strategies:
            if not self.is_strategy_blocked(domain, strategy):
                filtered.append(strategy)
            else:
                blocked_count += 1

        if blocked_count > 0:
            LOG.info(f"🚫 Отфильтровано {blocked_count} стратегий из negative knowledge")

        return filtered

    def _create_strategy_signature(self, strategy: GeneratedStrategy) -> str:
        """Создание уникальной сигнатуры стратегии"""

        # Создаем детерминированную сигнатуру на основе атак и параметров
        key_data = {
            "attacks": sorted(strategy.attack_combination),
            "parameters": sorted(strategy.parameters.items()) if strategy.parameters else [],
        }

        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()[:16]

    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики negative knowledge"""

        total_entries = sum(len(entries) for entries in self.knowledge.values())

        # Статистика по причинам неудач
        failure_reasons = {}
        expired_count = 0

        for domain_entries in self.knowledge.values():
            for entry in domain_entries.values():
                if entry.is_expired():
                    expired_count += 1
                else:
                    reason = entry.failure_reason
                    failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

        return {
            "total_domains": len(self.knowledge),
            "total_entries": total_entries,
            "expired_entries": expired_count,
            "active_entries": total_entries - expired_count,
            "failure_reasons": failure_reasons,
        }

    def cleanup_expired(self):
        """Очистка устаревших записей"""

        cleaned_count = 0

        for domain in list(self.knowledge.keys()):
            domain_entries = self.knowledge[domain]

            for signature in list(domain_entries.keys()):
                if domain_entries[signature].is_expired():
                    del domain_entries[signature]
                    cleaned_count += 1

            # Удаляем пустые домены
            if not domain_entries:
                del self.knowledge[domain]

        if cleaned_count > 0:
            self._save_knowledge()
            LOG.info(f"🧹 Очищено {cleaned_count} устаревших записей negative knowledge")


class SearchSpaceOptimizer:
    """
    Главный класс оптимизации пространства поиска.

    Объединяет все компоненты для максимального сокращения количества
    попыток до нахождения рабочей стратегии.
    """

    def __init__(self):
        self.strategy_generator = TargetedStrategyGenerator()
        self.negative_knowledge = NegativeKnowledgeManager()

        LOG.info("🎯 SearchSpaceOptimizer инициализирован")

    def optimize_strategies(
        self, domain: str, fingerprint: Optional[DPIFingerprint], max_strategies: int = 15
    ) -> Tuple[List[GeneratedStrategy], Dict[str, Any]]:
        """
        Оптимизация пространства поиска стратегий.

        Args:
            domain: Домен для оптимизации
            fingerprint: DPI fingerprint домена
            max_strategies: Максимальное количество стратегий

        Returns:
            Tuple[оптимизированные стратегии, метрики оптимизации]
        """
        LOG.info(f"🎯 Оптимизация пространства поиска для {domain}")

        # Генерируем целевые стратегии
        all_strategies = self.strategy_generator.generate_strategies(
            fingerprint, max_strategies * 2
        )

        # Фильтруем через negative knowledge
        filtered_strategies = self.negative_knowledge.filter_strategies(domain, all_strategies)

        # Ограничиваем финальное количество
        final_strategies = filtered_strategies[:max_strategies]

        # Метрики оптимизации
        metrics = {
            "original_count": len(all_strategies),
            "filtered_count": len(filtered_strategies),
            "final_count": len(final_strategies),
            "negative_knowledge_reduction": len(all_strategies) - len(filtered_strategies),
            "total_reduction_ratio": 1.0 - (len(final_strategies) / max(1, len(all_strategies))),
            "has_fingerprint": fingerprint is not None,
            "fingerprint_confidence": fingerprint.confidence if fingerprint else 0.0,
        }

        LOG.info(f"📊 Оптимизация завершена:")
        LOG.info(f"   - Исходных стратегий: {metrics['original_count']}")
        LOG.info(f"   - После фильтрации: {metrics['filtered_count']}")
        LOG.info(f"   - Финальных: {metrics['final_count']}")
        LOG.info(f"   - Сокращение: {metrics['total_reduction_ratio']:.1%}")

        return final_strategies, metrics

    def record_strategy_result(
        self, domain: str, strategy: GeneratedStrategy, success: bool, failure_reason: str = None
    ):
        """Запись результата тестирования стратегии"""

        strategy.tested = True
        strategy.actual_success_rate = 1.0 if success else 0.0

        if not success and failure_reason:
            # Добавляем в negative knowledge
            self.negative_knowledge.add_failed_strategy(
                domain, strategy, failure_reason, confidence=0.8
            )

    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Получение статистики оптимизации"""

        nk_stats = self.negative_knowledge.get_statistics()

        return {
            "negative_knowledge": nk_stats,
            "strategy_generator": {
                "intent_rules_count": len(self.strategy_generator.intent_engine.intent_rules),
                "attack_mappings_count": len(self.strategy_generator.intent_to_attacks),
            },
        }


# Удобные функции
def create_search_space_optimizer() -> SearchSpaceOptimizer:
    """Фабричная функция для создания оптимизатора"""
    return SearchSpaceOptimizer()


def optimize_strategies_for_domain(
    domain: str, fingerprint: Optional[DPIFingerprint] = None, max_strategies: int = 15
) -> List[GeneratedStrategy]:
    """
    Удобная функция для оптимизации стратегий домена.

    Args:
        domain: Домен
        fingerprint: DPI fingerprint (опционально)
        max_strategies: Максимальное количество стратегий

    Returns:
        Список оптимизированных стратегий
    """
    optimizer = SearchSpaceOptimizer()
    strategies, _ = optimizer.optimize_strategies(domain, fingerprint, max_strategies)
    return strategies


# Пример использования
if __name__ == "__main__":
    # Создаем оптимизатор
    optimizer = SearchSpaceOptimizer()

    # Тестовый fingerprint
    if DFS_AVAILABLE:
        from core.fingerprint.dpi_fingerprint_service import DPIFingerprint, DPIType, DPIMode

        test_fingerprint = DPIFingerprint(
            fingerprint_id="test",
            domain="example.com",
            ip_address="1.2.3.4",
            dpi_type=DPIType.STATEFUL,
            dpi_mode=DPIMode.ACTIVE_RST,
            behavioral_signatures={"sni_filtering": True},
            confidence=0.8,
        )
    else:
        test_fingerprint = None

    # Оптимизируем стратегии
    strategies, metrics = optimizer.optimize_strategies("example.com", test_fingerprint)

    print(f"Результат оптимизации:")
    print(f"- Стратегий: {len(strategies)}")
    print(f"- Сокращение: {metrics['total_reduction_ratio']:.1%}")

    for i, strategy in enumerate(strategies[:3]):
        print(f"{i+1}. {strategy.name}: {strategy.rationale}")
