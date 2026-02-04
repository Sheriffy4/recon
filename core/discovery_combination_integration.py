"""
Discovery Combination Integration - интеграция комбинированных атак в систему discovery.

Этот модуль расширяет DiscoveryController для поддержки интеллектуальных
комбинированных атак на основе анализа провалов и контекста.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

LOG = logging.getLogger("discovery_combination_integration")


@dataclass
class CombinationContext:
    """Контекст для принятия решений о комбинациях"""

    session_id: str
    target_domain: str
    failed_strategies: List[str] = field(default_factory=list)
    failed_attempts: int = 0
    last_pcap_analysis: Optional[Dict[str, Any]] = None
    last_fingerprint: Optional[Any] = None
    session_duration: float = 0.0

    # Статистика провалов
    simple_attack_failures: int = 0
    combination_failures: int = 0

    # Флаги состояния
    combinations_enabled: bool = False
    combination_phase_started: bool = False


class DiscoveryCombinationIntegration:
    """
    Интеграция комбинированных атак в систему discovery.

    Расширяет функциональность DiscoveryController для:
    - Анализа провалов простых атак
    - Принятия решений о переходе к комбинациям
    - Генерации интеллектуальных комбинированных стратегий
    - Адаптации под специфику доменов
    """

    def __init__(self, discovery_controller=None):
        self.discovery_controller = discovery_controller

        # Загружаем генератор комбинаций
        try:
            from core.strategy.intelligent_combination_generator import (
                IntelligentCombinationGenerator,
            )

            self.combination_generator = IntelligentCombinationGenerator()
            LOG.info("✅ IntelligentCombinationGenerator загружен")
        except ImportError as e:
            LOG.error(f"❌ Не удалось загрузить IntelligentCombinationGenerator: {e}")
            self.combination_generator = None

        # Контексты активных сессий
        self.session_contexts: Dict[str, CombinationContext] = {}

        # Настройки
        self.config = {
            "simple_failure_threshold": 5,  # После скольких провалов переходить к комбинациям
            "combination_failure_threshold": 3,  # После скольких провалов комбинаций остановиться
            "max_combination_strategies": 15,  # Максимум комбинированных стратегий
            "enable_adaptive_thresholds": True,  # Адаптивные пороги для разных доменов
            "google_domain_immediate_combinations": True,  # Сразу комбинации для Google
        }

        # Статистика
        self.stats = {
            "sessions_with_combinations": 0,
            "combination_decisions_made": 0,
            "successful_combinations": 0,
            "failed_combinations": 0,
        }

    def initialize_session_context(self, session_id: str, target_domain: str) -> CombinationContext:
        """Инициализация контекста для новой сессии"""

        context = CombinationContext(session_id=session_id, target_domain=target_domain)

        # Проверяем, нужны ли комбинации сразу для этого домена
        if self.combination_generator:
            decision = self.combination_generator.should_use_combinations(
                domain=target_domain, failed_attempts=0
            )

            if decision.should_use_combinations:
                context.combinations_enabled = True
                LOG.info(f"🎯 Комбинации включены сразу для домена: {target_domain}")
                LOG.info(f"   Триггеры: {[t.value for t in decision.triggers]}")

        self.session_contexts[session_id] = context
        return context

    def analyze_strategy_failure(
        self,
        session_id: str,
        failed_strategy: str,
        test_results: Optional[Dict[str, Any]] = None,
        pcap_analysis: Optional[Dict[str, Any]] = None,
        fingerprint: Optional[Any] = None,
    ) -> bool:
        """
        Анализ провала стратегии и принятие решения о комбинациях.

        Args:
            session_id: ID сессии discovery
            failed_strategy: Название провалившейся стратегии
            test_results: Результаты тестирования
            pcap_analysis: Анализ PCAP файла
            fingerprint: DPI fingerprint

        Returns:
            True если нужно переходить к комбинациям, False иначе
        """

        if session_id not in self.session_contexts:
            LOG.warning(f"Контекст сессии {session_id} не найден")
            return False

        context = self.session_contexts[session_id]

        # Обновляем контекст
        context.failed_strategies.append(failed_strategy)
        context.failed_attempts += 1

        if pcap_analysis:
            context.last_pcap_analysis = pcap_analysis
        if fingerprint:
            context.last_fingerprint = fingerprint

        # Классифицируем тип провала
        if self._is_simple_attack(failed_strategy):
            context.simple_attack_failures += 1
        else:
            context.combination_failures += 1

        LOG.info(f"📊 Провал стратегии {failed_strategy} в сессии {session_id}")
        LOG.info(
            f"   Простые атаки: {context.simple_attack_failures}, "
            f"Комбинации: {context.combination_failures}"
        )

        # Принимаем решение о комбинациях
        should_use_combinations = self._should_enable_combinations(context)

        if should_use_combinations and not context.combinations_enabled:
            context.combinations_enabled = True
            context.combination_phase_started = True
            self.stats["sessions_with_combinations"] += 1

            LOG.info(f"🔄 Переход к комбинированным атакам для сессии {session_id}")
            return True

        return context.combinations_enabled

    def _is_simple_attack(self, strategy_name: str) -> bool:
        """Проверка, является ли стратегия простой атакой"""

        simple_attacks = {"fake", "split", "multisplit", "disorder", "seqovl", "multidisorder"}

        # Проверяем, содержит ли название только одну атаку
        strategy_lower = strategy_name.lower()

        # Подсчитываем количество простых атак в названии
        attack_count = sum(1 for attack in simple_attacks if attack in strategy_lower)

        return attack_count <= 1

    def _should_enable_combinations(self, context: CombinationContext) -> bool:
        """Принятие решения о включении комбинаций"""

        if context.combinations_enabled:
            return True

        # Проверяем пороги провалов
        simple_threshold = self.config["simple_failure_threshold"]

        # Адаптивные пороги для разных типов доменов
        if self.config["enable_adaptive_thresholds"]:
            if self._is_google_domain(context.target_domain):
                simple_threshold = 2  # Для Google быстрее переходим к комбинациям
            elif self._is_social_media_domain(context.target_domain):
                simple_threshold = 3

        # Основное условие - достаточно провалов простых атак
        if context.simple_attack_failures >= simple_threshold:
            return True

        # Дополнительные условия на основе анализа
        if context.last_pcap_analysis:
            # Если в PCAP видны RST пакеты - сразу комбинации
            if context.last_pcap_analysis.get("rst_packets", 0) > 0:
                LOG.info("🔍 RST пакеты в PCAP - включаем комбинации")
                return True

            # Если блокировка после TLS handshake - комбинации
            if context.last_pcap_analysis.get("blocked_after_tls_handshake", False):
                LOG.info("🔍 Блокировка после TLS handshake - включаем комбинации")
                return True

        return False

    def _is_google_domain(self, domain: str) -> bool:
        """Проверка, является ли домен Google/YouTube"""
        google_patterns = [
            "google.com",
            "googlevideo.com",
            "youtube.com",
            "ytimg.com",
            "ggpht.com",
            "gstatic.com",
            "googleapis.com",
        ]

        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in google_patterns)

    def _is_social_media_domain(self, domain: str) -> bool:
        """Проверка, является ли домен социальной сети"""
        social_patterns = [
            "facebook.com",
            "instagram.com",
            "twitter.com",
            "tiktok.com",
            "vk.com",
            "ok.ru",
            "telegram.org",
        ]

        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in social_patterns)

    def generate_combination_strategies(
        self, session_id: str, max_strategies: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Генерация комбинированных стратегий для сессии.

        Args:
            session_id: ID сессии discovery
            max_strategies: Максимальное количество стратегий

        Returns:
            Список сгенерированных комбинированных стратегий
        """

        if not self.combination_generator:
            LOG.error("IntelligentCombinationGenerator недоступен")
            return []

        if session_id not in self.session_contexts:
            LOG.warning(f"Контекст сессии {session_id} не найден")
            return []

        context = self.session_contexts[session_id]

        if not context.combinations_enabled:
            LOG.info(f"Комбинации не включены для сессии {session_id}")
            return []

        max_strategies = max_strategies or self.config["max_combination_strategies"]

        LOG.info(f"🔧 Генерация комбинированных стратегий для сессии {session_id}")

        try:
            # Принимаем решение о комбинациях
            decision = self.combination_generator.should_use_combinations(
                domain=context.target_domain,
                failed_attempts=context.failed_attempts,
                failed_strategies=context.failed_strategies,
                fingerprint=context.last_fingerprint,
                pcap_analysis=context.last_pcap_analysis,
            )

            self.stats["combination_decisions_made"] += 1

            if not decision.should_use_combinations:
                LOG.info("Генератор не рекомендует комбинации")
                return []

            # Генерируем стратегии
            strategies = self.combination_generator.generate_combination_strategies(
                decision=decision, max_strategies=max_strategies
            )

            LOG.info(f"✅ Сгенерировано {len(strategies)} комбинированных стратегий")
            LOG.info(f"   Триггеры: {[t.value for t in decision.triggers]}")
            LOG.info(f"   Reasoning: {decision.reasoning}")

            # Конвертируем в формат для discovery system
            discovery_strategies = []
            for strategy in strategies:
                discovery_strategy = self._convert_to_discovery_format(strategy, context)
                discovery_strategies.append(discovery_strategy)

            return discovery_strategies

        except Exception as e:
            LOG.error(f"Ошибка генерации комбинированных стратегий: {e}")
            return []

    def _convert_to_discovery_format(
        self, strategy: Dict[str, Any], context: CombinationContext
    ) -> Dict[str, Any]:
        """Конвертация стратегии в формат для discovery system"""

        return {
            "name": f"combo_{strategy['name']}_{context.target_domain}",
            "attack_combination": strategy["attacks"],
            "parameters": strategy["parameters"],
            "generation_method": "intelligent_combination",
            "source_context": {
                "session_id": context.session_id,
                "target_domain": context.target_domain,
                "failed_attempts": context.failed_attempts,
                "reasoning": strategy.get("reasoning", ""),
                "priority": strategy.get("priority", 5),
                "confidence": strategy.get("confidence", 0.5),
            },
            "expected_success_rate": strategy.get("confidence", 0.5),
            "rationale": f"Комбинированная атака: {strategy.get('reasoning', 'Нет описания')}",
        }

    def mark_combination_result(
        self,
        session_id: str,
        strategy_name: str,
        success: bool,
        test_results: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Отметка результата тестирования комбинированной стратегии"""

        if session_id not in self.session_contexts:
            return

        context = self.session_contexts[session_id]

        if success:
            self.stats["successful_combinations"] += 1
            LOG.info(f"✅ Успешная комбинированная стратегия: {strategy_name}")
        else:
            self.stats["failed_combinations"] += 1
            context.combination_failures += 1
            LOG.info(f"❌ Провал комбинированной стратегии: {strategy_name}")

        # Проверяем, не превышен ли лимит провалов комбинаций
        if context.combination_failures >= self.config["combination_failure_threshold"]:
            LOG.warning(f"⚠️ Превышен лимит провалов комбинаций для сессии {session_id}")
            # Можно отправить сигнал о завершении сессии

    def should_continue_combinations(self, session_id: str) -> bool:
        """Проверка, стоит ли продолжать генерировать комбинации"""

        if session_id not in self.session_contexts:
            return False

        context = self.session_contexts[session_id]

        # Не продолжаем, если превышен лимит провалов
        if context.combination_failures >= self.config["combination_failure_threshold"]:
            return False

        # Не продолжаем, если комбинации не включены
        if not context.combinations_enabled:
            return False

        return True

    def cleanup_session_context(self, session_id: str) -> None:
        """Очистка контекста сессии"""

        if session_id in self.session_contexts:
            context = self.session_contexts[session_id]

            LOG.info(f"🧹 Очистка контекста сессии {session_id}")
            LOG.info(
                f"   Провалы: простые={context.simple_attack_failures}, "
                f"комбинации={context.combination_failures}"
            )

            del self.session_contexts[session_id]

    def get_session_statistics(self, session_id: str) -> Dict[str, Any]:
        """Получение статистики сессии"""

        if session_id not in self.session_contexts:
            return {}

        context = self.session_contexts[session_id]

        return {
            "session_id": session_id,
            "target_domain": context.target_domain,
            "failed_attempts": context.failed_attempts,
            "simple_attack_failures": context.simple_attack_failures,
            "combination_failures": context.combination_failures,
            "combinations_enabled": context.combinations_enabled,
            "combination_phase_started": context.combination_phase_started,
            "failed_strategies": context.failed_strategies,
        }

    def get_global_statistics(self) -> Dict[str, Any]:
        """Получение глобальной статистики"""

        return {
            "sessions_with_combinations": self.stats["sessions_with_combinations"],
            "combination_decisions_made": self.stats["combination_decisions_made"],
            "successful_combinations": self.stats["successful_combinations"],
            "failed_combinations": self.stats["failed_combinations"],
            "success_rate": (
                self.stats["successful_combinations"]
                / max(1, self.stats["successful_combinations"] + self.stats["failed_combinations"])
            ),
            "active_sessions": len(self.session_contexts),
            "config": self.config,
        }


# Пример интеграции с DiscoveryController
def integrate_with_discovery_controller(discovery_controller):
    """Интеграция с существующим DiscoveryController"""

    # Создаем интеграцию
    combination_integration = DiscoveryCombinationIntegration(discovery_controller)

    # Добавляем методы в discovery_controller
    discovery_controller.combination_integration = combination_integration

    # Monkey patch методов для интеграции
    original_start_discovery = discovery_controller.start_discovery
    original_stop_discovery = discovery_controller.stop_discovery
    original_mark_strategy_tested = discovery_controller.mark_strategy_tested

    def enhanced_start_discovery(config):
        """Расширенный метод запуска с поддержкой комбинаций"""
        session_id = original_start_discovery(config)

        # Инициализируем контекст комбинаций
        combination_integration.initialize_session_context(session_id, config.target_domain)

        return session_id

    def enhanced_stop_discovery(session_id, reason="Manual stop"):
        """Расширенный метод остановки с очисткой контекста"""
        report = original_stop_discovery(session_id, reason)

        # Очищаем контекст комбинаций
        combination_integration.cleanup_session_context(session_id)

        return report

    def enhanced_mark_strategy_tested(session_id, strategy, success_rate=None, test_results=None):
        """Расширенный метод отметки с анализом провалов"""
        original_mark_strategy_tested(session_id, strategy, success_rate, test_results)

        # Анализируем провал для принятия решений о комбинациях
        if success_rate is None or success_rate < 0.1:  # Считаем провалом
            combination_integration.analyze_strategy_failure(
                session_id=session_id,
                failed_strategy=strategy.name if hasattr(strategy, "name") else str(strategy),
                test_results=test_results,
            )

    # Заменяем методы
    discovery_controller.start_discovery = enhanced_start_discovery
    discovery_controller.stop_discovery = enhanced_stop_discovery
    discovery_controller.mark_strategy_tested = enhanced_mark_strategy_tested

    LOG.info("✅ DiscoveryController интегрирован с поддержкой комбинированных атак")

    return combination_integration


if __name__ == "__main__":
    # Тестирование интеграции
    logging.basicConfig(level=logging.INFO)

    integration = DiscoveryCombinationIntegration()

    # Тест 1: Google домен
    print("\n=== Тест 1: Google домен ===")
    context = integration.initialize_session_context("test_001", "www.googlevideo.com")
    print(f"Комбинации включены: {context.combinations_enabled}")

    # Тест 2: Анализ провалов
    print("\n=== Тест 2: Анализ провалов ===")
    for i in range(6):
        should_use = integration.analyze_strategy_failure("test_001", f"fake_strategy_{i}")
        print(f"Провал {i+1}: комбинации = {should_use}")

    # Тест 3: Генерация стратегий
    print("\n=== Тест 3: Генерация стратегий ===")
    strategies = integration.generate_combination_strategies("test_001", max_strategies=3)
    print(f"Сгенерировано {len(strategies)} стратегий:")
    for strategy in strategies:
        print(f"  - {strategy['name']}: {strategy['attack_combination']}")

    # Статистика
    print("\n=== Статистика ===")
    stats = integration.get_global_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
