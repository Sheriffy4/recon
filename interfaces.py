"""
Централизованный модуль для всех интерфейсов системы.
Это решает проблемы циклических зависимостей и упрощает архитектуру.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Set, Union
from core.fingerprint.models import EnhancedFingerprint
from recon.bypass.attacks.base import AttackContext, AttackResult


class IProber(ABC):
    """Interface for DPI probing functionality."""

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
    """Interface for attack adaptation functionality."""

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
    """Interface for unified packet building functionality."""

    @abstractmethod
    def create_tcp_packet(self, **kwargs) -> Optional[Union[Any, bytes]]:
        pass
