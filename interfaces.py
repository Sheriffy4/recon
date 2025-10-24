"""
Централизованный модуль интерфейсов для системы обхода DPI.

Основные цели:
- Решение проблем циклических зависимостей между модулями
- Упрощение архитектуры через четкое разделение интерфейсов
- Обеспечение совместимости между различными компонентами
- Стандартизация API для всех подсистем

Группы интерфейсов:
1. Обнаружение и анализ DPI:
   - IProber: Зондирование DPI систем
   - IClassifier: Классификация типов DPI
   - IFingerprintEngine: Создание отпечатков DPI

2. Выполнение атак:
   - IAttackAdapter: Адаптация и выполнение атак
   - IEffectivenessTester: Тестирование эффективности

3. Обучение и оптимизация:
   - ILearningMemory: Сохранение результатов обучения
   - IStrategyGenerator: Генерация стратегий
   - IEvolutionarySearcher: Эволюционный поиск

4. Управление и координация:
   - IClosedLoopManager: Управление замкнутым циклом
   - IPacketBuilder: Построение пакетов

Принципы проектирования:
- Все интерфейсы наследуются от ABC (Abstract Base Class)
- Методы помечены @abstractmethod для обязательной реализации
- Типизация через typing для лучшей документации
- Минимальные зависимости для избежания циклических импортов
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Union
from core.fingerprint.models import EnhancedFingerprint
from recon.bypass.attacks.base import AttackContext, AttackResult


class IProber(ABC):
    """
    Интерфейс для зондирования и обнаружения DPI систем.

    Основные функции:
    - Активное зондирование целевых доменов
    - Обнаружение типа и характеристик DPI
    - Сбор данных для создания отпечатков
    - Предварительная классификация DPI систем
    """

    @abstractmethod
    async def run_probes(
        self, domain: str, preliminary_type: Optional[str] = None
    ) -> Dict[str, Any]:
        pass


class IClassifier(ABC):
    """Interface for DPI classification functionality."""

    @abstractmethod
    def classify(self, fingerprint: EnhancedFingerprint) -> Any:
        pass


class IFingerprintEngine(ABC):
    """Interface for fingerprint engine functionality."""

    @abstractmethod
    async def create_comprehensive_fingerprint(
        self,
        domain: str,
        target_ips: List[str] = None,
        packets: List[Any] = None,
        force_refresh: bool = False,
    ) -> EnhancedFingerprint:
        pass

    @abstractmethod
    async def refine_fingerprint(
        self,
        current_fingerprint: EnhancedFingerprint,
        test_results: List[Any],
        learning_insights: Optional[Dict[str, Any]] = None,
    ) -> EnhancedFingerprint:
        pass


class IAttackAdapter(ABC):
    """
    Интерфейс для адаптации и выполнения атак обхода DPI.

    Основные функции:
    - Выполнение атак по имени с контекстом
    - Получение списка доступных атак
    - Адаптация параметров под конкретные условия
    - Интеграция с AttackRegistry и AttackDispatcher

    Поддерживаемые категории атак:
    - TCP-based: fakeddisorder, seqovl, multisplit
    - UDP-based: QUIC манипуляции
    - HTTP-based: заголовки и содержимое
    - TLS-based: ClientHello модификации
    """

    @abstractmethod
    async def execute_attack_by_name(
        self, attack_name: str, context: AttackContext
    ) -> AttackResult:
        pass

    @abstractmethod
    def get_available_attacks(
        self, category: Optional[str] = None, protocol: Optional[str] = None
    ) -> List[str]:
        pass


class IEffectivenessTester(ABC):
    """Interface for effectiveness testing functionality."""

    @abstractmethod
    async def test_baseline(self, domain: str, port: int) -> Any:
        pass

    @abstractmethod
    async def test_with_bypass(
        self, domain: str, port: int, attack_result: AttackResult
    ) -> Any:
        pass

    @abstractmethod
    async def compare_results(self, baseline: Any, bypass: Any) -> Any:
        pass


class ILearningMemory(ABC):
    """Interface for learning memory functionality."""

    @abstractmethod
    async def save_learning_result(
        self,
        fingerprint_hash: str,
        attack_name: str,
        effectiveness: float,
        parameters: Dict[str, Any],
    ) -> None:
        pass

    @abstractmethod
    async def load_learning_history(self, fingerprint_hash: str) -> Any:
        pass


class IStrategyGenerator(ABC):
    """Interface for strategy generation functionality."""

    @abstractmethod
    def generate_strategies(
        self, count: int = 20, use_parameter_ranges: bool = True
    ) -> List[Dict]:
        pass


class IStrategySaver(ABC):
    """Interface for strategy saving functionality."""

    @abstractmethod
    def save_effective_strategies(self, strategies: List[Dict[str, Any]]) -> bool:
        pass


class IClosedLoopManager(ABC):
    """Interface for closed loop management functionality."""

    @abstractmethod
    async def run_closed_loop(
        self, domain: str, port: int = 443, max_iterations: Optional[int] = None
    ) -> Any:
        pass


class IEvolutionarySearcher(ABC):
    """Interface for evolutionary strategy search functionality."""

    @abstractmethod
    async def run(
        self,
        domains: List[str],
        ips: Set[str],
        dns_cache: Dict[str, str],
        fingerprint_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        pass


class IPacketBuilder(ABC):
    """
    Интерфейс для унифицированного построения сетевых пакетов.

    Основные функции:
    - Создание TCP пакетов с заданными параметрами
    - Поддержка различных TCP флагов и опций
    - Настройка IP заголовков (TTL, DSCP, etc.)
    - Интеграция с системой инъекции пакетов

    Поддерживаемые протоколы:
    - TCP: Полная поддержка всех флагов и опций
    - UDP: Базовая поддержка для QUIC
    - IP: Настройка заголовков и фрагментации

    Используется AttackDispatcher и PacketSender для:
    - Генерации последовательностей пакетов
    - Инъекции через WinDivert
    - Контроля временных задержек
    """

    @abstractmethod
    def create_tcp_packet(self, **kwargs) -> Optional[Union[Any, bytes]]:
        pass
