#!/usr/bin/env python3
"""
Advanced Attack Manager - Central coordinator for Phase 2 advanced attacks.
Integrates with Phase 1 ML systems and manages specialized attack execution.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from abc import ABC, abstractmethod

# Import Phase 1 integrations
try:
    from .strategy_prediction_integration import (
        get_strategy_integrator,
        StrategyRecommendation,
    )
    from .fingerprint_integration import get_fingerprint_integrator, FingerprintResult
    from .performance_integration import get_performance_integrator
    from .evolutionary_optimization_integration import get_evolutionary_integrator

    PHASE1_INTEGRATIONS_AVAILABLE = True
except ImportError as e:
    PHASE1_INTEGRATIONS_AVAILABLE = False
    logging.warning(f"Phase 1 integrations not fully available: {e}")

# Import fingerprint models
try:
    from core.fingerprint.models import DPIBehaviorProfile, EnhancedFingerprint

    FINGERPRINT_MODELS_AVAILABLE = True
except ImportError:
    FINGERPRINT_MODELS_AVAILABLE = False

LOG = logging.getLogger("advanced_attack_manager")


@dataclass
class TargetInfo:
    """Information about attack target."""

    domain: str
    ip: str
    port: int = 443
    protocol: str = "https"
    additional_info: Dict[str, Any] = None


@dataclass
class DPISignature:
    """DPI system signature information."""

    dpi_type: str
    capabilities: List[str]
    confidence: float
    fingerprint_data: Dict[str, Any]
    sophistication_level: str = (
        "basic"  # 'basic', 'intermediate', 'advanced', 'sophisticated'
    )


@dataclass
class AttackContext:
    """Context for advanced attack execution."""

    target_info: TargetInfo
    dpi_signature: DPISignature
    ml_prediction: Optional[StrategyRecommendation]
    fingerprint_data: Optional[FingerprintResult]
    historical_data: Optional[Dict[str, Any]]
    performance_constraints: Optional[Dict[str, Any]]


@dataclass
class MLFeedback:
    """ML feedback from attack execution."""

    attack_name: str
    success: bool
    latency_ms: float
    effectiveness_score: float
    failure_reason: Optional[str]
    adaptation_suggestions: List[str]


@dataclass
class LearningData:
    """Data for learning memory system."""

    target_signature: str
    attack_parameters: Dict[str, Any]
    effectiveness: float
    context: Dict[str, Any]
    timestamp: datetime


@dataclass
class PerformanceMetrics:
    """Performance metrics for advanced attacks."""

    execution_time_ms: float
    memory_usage_mb: float
    cpu_usage_percent: float
    network_overhead_bytes: int
    success_rate: float


@dataclass
class AdaptationSuggestion:
    """Suggestion for attack adaptation."""

    parameter: str
    current_value: Any
    suggested_value: Any
    reason: str
    confidence: float


@dataclass
class AdvancedAttackResult:
    """Result from advanced attack execution."""

    attack_name: str
    success: bool
    latency_ms: float
    effectiveness_score: float
    ml_feedback: MLFeedback
    learning_data: LearningData
    performance_metrics: PerformanceMetrics
    adaptation_suggestions: List[AdaptationSuggestion]
    error_message: Optional[str] = None


@dataclass
class AdvancedAttackConfig:
    """Configuration for advanced attacks."""

    name: str
    priority: int
    complexity: str  # 'Low', 'Medium', 'High'
    expected_improvement: str
    target_protocols: List[str]
    dpi_signatures: List[str]
    ml_integration: bool
    learning_enabled: bool


class AdvancedAttack(ABC):
    """Base class for all advanced attacks."""

    def __init__(self, config: AdvancedAttackConfig):
        self.config = config
        self.ml_predictor = None
        self.fingerprint_engine = None
        self.performance_monitor = None
        self.learning_memory = None
        self.enabled = True
        self.stats = {
            "executions": 0,
            "successes": 0,
            "total_latency_ms": 0.0,
            "last_execution": None,
        }

    @abstractmethod
    async def execute(
        self, target: str, context: AttackContext
    ) -> AdvancedAttackResult:
        """Execute the advanced attack."""
        pass

    @abstractmethod
    async def adapt_from_feedback(self, feedback: MLFeedback) -> None:
        """Adapt attack parameters based on ML feedback."""
        pass

    @abstractmethod
    async def get_effectiveness_metrics(self) -> Dict[str, float]:
        """Get attack effectiveness metrics."""
        pass

    def update_stats(self, result: AdvancedAttackResult):
        """Update attack statistics."""
        self.stats["executions"] += 1
        if result.success:
            self.stats["successes"] += 1
        self.stats["total_latency_ms"] += result.latency_ms
        self.stats["last_execution"] = datetime.now()

    def get_success_rate(self) -> float:
        """Get attack success rate."""
        if self.stats["executions"] == 0:
            return 0.0
        return self.stats["successes"] / self.stats["executions"]

    def get_average_latency(self) -> float:
        """Get average attack latency."""
        if self.stats["executions"] == 0:
            return 0.0
        return self.stats["total_latency_ms"] / self.stats["executions"]


class AdvancedAttackManager:
    """
    Central coordinator for all advanced attacks.
    Integrates with Phase 1 ML systems and manages attack execution.
    """

    def __init__(self, enable_ml_integration: bool = True):
        self.enable_ml_integration = (
            enable_ml_integration and PHASE1_INTEGRATIONS_AVAILABLE
        )
        self.registered_attacks: Dict[str, AdvancedAttack] = {}
        self.attack_registry = None

        # Phase 1 integrations
        self.strategy_integrator = None
        self.fingerprint_integrator = None
        self.performance_integrator = None
        self.evolutionary_integrator = None

        # Advanced attack state
        self.execution_history = []
        self.adaptation_cache = {}
        self.performance_cache = {}

        if self.enable_ml_integration:
            try:
                self._initialize_phase1_integrations()
                LOG.info("Phase 1 integrations initialized successfully")
            except Exception as e:
                LOG.error(f"Failed to initialize Phase 1 integrations: {e}")
                self.enable_ml_integration = False

        if not self.enable_ml_integration:
            LOG.info("Using standalone advanced attack mode")

    def _initialize_phase1_integrations(self):
        """Initialize Phase 1 system integrations."""

        # Strategy prediction integration
        self.strategy_integrator = get_strategy_integrator()

        # Fingerprint integration
        self.fingerprint_integrator = get_fingerprint_integrator()

        # Performance integration
        self.performance_integrator = get_performance_integrator()

        # Evolutionary optimization integration
        try:
            self.evolutionary_integrator = get_evolutionary_integrator()
        except Exception as e:
            LOG.debug(f"Evolutionary integration not available: {e}")
            self.evolutionary_integrator = None

    async def initialize_advanced_attacks(self) -> bool:
        """Initialize all registered advanced attacks."""

        LOG.info("Initializing advanced attacks system")

        try:
            # Initialize attack registry
            try:
                from .advanced_attack_registry import get_advanced_attack_registry

                self.attack_registry = get_advanced_attack_registry()
            except ImportError as e:
                LOG.warning(f"Advanced attack registry not available: {e}")
                self.attack_registry = None

            # Register all available advanced attacks
            await self._register_available_attacks()

            # Initialize ML integration for attacks
            if self.enable_ml_integration:
                await self._setup_ml_integration_for_attacks()

            LOG.info(
                f"Advanced attacks system initialized with {len(self.registered_attacks)} attacks"
            )
            return True

        except Exception as e:
            LOG.error(f"Failed to initialize advanced attacks: {e}")
            return False

    async def _register_available_attacks(self):
        """Register all available advanced attacks."""

        # Import and register adaptive combo attacks
        try:
            from .adaptive_combo_integration import create_adaptive_combo_integration

            attack = create_adaptive_combo_integration()
            self.registered_attacks["adaptive_combo"] = attack
            LOG.info("Registered Adaptive Combo Attack")
        except ImportError as e:
            LOG.debug(f"Adaptive Combo Attack not available: {e}")

        # Import and register learning memory system
        try:
            from .learning_memory_integration import create_learning_memory_integration

            attack = create_learning_memory_integration()
            self.registered_attacks["learning_memory"] = attack
            LOG.info("Registered Learning Memory System")
        except ImportError as e:
            LOG.debug(f"Learning Memory System not available: {e}")

        # Import and register ECH attacks
        try:
            from .ech_attack_integration import create_ech_attack_integration

            attack = create_ech_attack_integration()
            self.registered_attacks["ech_attack"] = attack
            LOG.info("Registered ECH Attack Integration")
        except ImportError as e:
            LOG.debug(f"ECH Attack Integration not available: {e}")

        # Import and register QUIC attacks
        try:
            from .quic_attack_integration import create_quic_attack_integration

            attack = create_quic_attack_integration()
            self.registered_attacks["quic_attack"] = attack
            LOG.info("Registered QUIC Attack Integration")
        except ImportError as e:
            LOG.debug(f"QUIC Attack Integration not available: {e}")

        # Import and register traffic mimicry attacks
        try:
            from .traffic_mimicry_integration import create_traffic_mimicry_integration

            attack = create_traffic_mimicry_integration()
            self.registered_attacks["traffic_mimicry"] = attack
            LOG.info("Registered Traffic Mimicry Integration")
        except ImportError as e:
            LOG.debug(f"Traffic Mimicry Integration not available: {e}")

        LOG.info(f"Registered {len(self.registered_attacks)} advanced attacks")

    async def _setup_ml_integration_for_attacks(self):
        """Setup ML integration for all registered attacks."""

        for attack_name, attack in self.registered_attacks.items():
            if attack.config.ml_integration:
                try:
                    # Set ML predictor
                    if self.strategy_integrator:
                        attack.ml_predictor = self.strategy_integrator

                    # Set fingerprint engine
                    if self.fingerprint_integrator:
                        attack.fingerprint_engine = self.fingerprint_integrator

                    # Set performance monitor
                    if self.performance_integrator:
                        attack.performance_monitor = self.performance_integrator

                    # Set learning memory (will be implemented per attack)
                    if attack.config.learning_enabled:
                        # This will be set up when learning memory integration is implemented
                        pass

                    LOG.debug(f"ML integration setup for {attack_name}")

                except Exception as e:
                    LOG.error(f"Failed to setup ML integration for {attack_name}: {e}")

    async def select_optimal_attack(
        self, target_info: TargetInfo, dpi_signature: DPISignature
    ) -> Optional[AdvancedAttack]:
        """
        Select the optimal advanced attack based on target and DPI signature.

        Args:
            target_info: Information about the target
            dpi_signature: DPI system signature

        Returns:
            Optimal AdvancedAttack instance or None
        """

        LOG.info(
            f"Selecting optimal attack for {target_info.domain} (DPI: {dpi_signature.dpi_type})"
        )

        # Get ML strategy recommendation if available
        ml_recommendation = None
        if self.enable_ml_integration and self.strategy_integrator:
            try:
                ml_recommendation = self.strategy_integrator.predict_best_strategy(
                    target_ip=target_info.ip,
                    domain=target_info.domain,
                    fingerprint=dpi_signature.fingerprint_data,
                )
                LOG.debug(f"ML recommendation: {ml_recommendation.primary_strategy}")
            except Exception as e:
                LOG.error(f"ML strategy prediction failed: {e}")

        # Filter attacks by protocol and DPI signature compatibility
        compatible_attacks = []
        for attack_name, attack in self.registered_attacks.items():
            if not attack.enabled:
                continue

            # Check protocol compatibility
            if target_info.protocol not in attack.config.target_protocols:
                continue

            # Check DPI signature compatibility
            if (
                attack.config.dpi_signatures != ["all"]
                and dpi_signature.dpi_type not in attack.config.dpi_signatures
            ):
                continue

            compatible_attacks.append((attack_name, attack))

        if not compatible_attacks:
            LOG.warning(
                f"No compatible advanced attacks found for {target_info.domain}"
            )
            return None

        # Sort by priority and success rate
        def attack_score(attack_tuple):
            attack_name, attack = attack_tuple
            priority_score = (
                1.0 / attack.config.priority
            )  # Lower priority number = higher score
            success_rate = attack.get_success_rate()
            ml_bonus = 0.0

            # Bonus if ML recommends this attack type
            if ml_recommendation and attack_name in ml_recommendation.primary_strategy:
                ml_bonus = 0.2

            return priority_score + success_rate + ml_bonus

        compatible_attacks.sort(key=attack_score, reverse=True)

        selected_attack_name, selected_attack = compatible_attacks[0]
        LOG.info(f"Selected advanced attack: {selected_attack_name}")

        return selected_attack

    async def execute_attack_with_ml_feedback(
        self, attack: AdvancedAttack, target: str
    ) -> AdvancedAttackResult:
        """
        Execute advanced attack with ML feedback integration.

        Args:
            attack: AdvancedAttack instance to execute
            target: Target URL or domain

        Returns:
            AdvancedAttackResult with ML feedback
        """

        LOG.info(f"Executing advanced attack: {attack.config.name} on {target}")

        start_time = time.time()

        try:
            # Parse target info
            target_info = self._parse_target_info(target)

            # Get DPI signature
            dpi_signature = await self._get_dpi_signature(target_info)

            # Create attack context
            context = await self._create_attack_context(target_info, dpi_signature)

            # Execute the attack
            result = await attack.execute(target, context)

            # Update attack statistics
            attack.update_stats(result)

            # Record performance metrics
            if self.performance_integrator:
                self.performance_integrator.record_attack_executed(
                    result.latency_ms, result.success
                )

            # Store execution history
            self.execution_history.append(
                {
                    "attack_name": attack.config.name,
                    "target": target,
                    "result": result,
                    "timestamp": datetime.now(),
                }
            )

            # Trigger adaptation if needed
            if result.adaptation_suggestions:
                await self._apply_adaptations(attack, result.adaptation_suggestions)

            execution_time = (time.time() - start_time) * 1000
            LOG.info(
                f"Advanced attack completed: {attack.config.name} -> {'SUCCESS' if result.success else 'FAILURE'} ({execution_time:.1f}ms)"
            )

            return result

        except Exception as e:
            LOG.error(f"Advanced attack execution failed: {e}")

            # Create error result
            error_result = AdvancedAttackResult(
                attack_name=attack.config.name,
                success=False,
                latency_ms=(time.time() - start_time) * 1000,
                effectiveness_score=0.0,
                ml_feedback=MLFeedback(
                    attack_name=attack.config.name,
                    success=False,
                    latency_ms=0.0,
                    effectiveness_score=0.0,
                    failure_reason=str(e),
                    adaptation_suggestions=[],
                ),
                learning_data=LearningData(
                    target_signature=target,
                    attack_parameters={},
                    effectiveness=0.0,
                    context={},
                    timestamp=datetime.now(),
                ),
                performance_metrics=PerformanceMetrics(
                    execution_time_ms=0.0,
                    memory_usage_mb=0.0,
                    cpu_usage_percent=0.0,
                    network_overhead_bytes=0,
                    success_rate=0.0,
                ),
                adaptation_suggestions=[],
                error_message=str(e),
            )

            attack.update_stats(error_result)
            return error_result

    def _parse_target_info(self, target: str) -> TargetInfo:
        """Parse target string into TargetInfo."""

        # Simple parsing - can be enhanced
        if "://" in target:
            parts = target.split("://")
            protocol = parts[0]
            domain_part = parts[1]
        else:
            protocol = "https"
            domain_part = target

        if ":" in domain_part:
            domain, port_str = domain_part.split(":", 1)
            port = int(port_str)
        else:
            domain = domain_part
            port = 443 if protocol == "https" else 80

        # Resolve IP (simplified)
        target_ip = "1.1.1.1"  # Placeholder - should use actual DNS resolution

        return TargetInfo(domain=domain, ip=target_ip, port=port, protocol=protocol)

    async def _get_dpi_signature(self, target_info: TargetInfo) -> DPISignature:
        """Get DPI signature for target."""

        if self.enable_ml_integration and self.fingerprint_integrator:
            try:
                fingerprint_result = (
                    await self.fingerprint_integrator.fingerprint_target(
                        target_info.domain, target_info.ip
                    )
                )

                return DPISignature(
                    dpi_type=fingerprint_result.dpi_type,
                    sophistication_level=self._determine_sophistication_level(
                        fingerprint_result
                    ),
                    capabilities=self._extract_capabilities(fingerprint_result),
                    confidence=fingerprint_result.confidence,
                    fingerprint_data=fingerprint_result.fingerprint_data,
                )

            except Exception as e:
                LOG.error(f"Fingerprinting failed: {e}")

        # Fallback to basic signature
        return DPISignature(
            dpi_type="unknown",
            sophistication_level="basic",
            capabilities=["basic_filtering"],
            confidence=0.3,
            fingerprint_data={},
        )

    def _determine_sophistication_level(
        self, fingerprint_result: FingerprintResult
    ) -> str:
        """Determine DPI sophistication level from fingerprint."""

        if fingerprint_result.confidence > 0.8:
            return "sophisticated"
        elif fingerprint_result.confidence > 0.6:
            return "advanced"
        elif fingerprint_result.confidence > 0.4:
            return "intermediate"
        else:
            return "basic"

    def _extract_capabilities(self, fingerprint_result: FingerprintResult) -> List[str]:
        """Extract DPI capabilities from fingerprint."""

        capabilities = ["basic_filtering"]

        if fingerprint_result.fingerprint_data.get("deep_inspection", False):
            capabilities.append("deep_packet_inspection")

        if fingerprint_result.fingerprint_data.get("timing_sensitive", False):
            capabilities.append("timing_analysis")

        if fingerprint_result.fingerprint_data.get("supports_ip_frag", False):
            capabilities.append("fragmentation_handling")

        return capabilities

    async def _create_attack_context(
        self, target_info: TargetInfo, dpi_signature: DPISignature
    ) -> AttackContext:
        """Create attack context with all available information."""

        # Get ML prediction
        ml_prediction = None
        if self.enable_ml_integration and self.strategy_integrator:
            try:
                ml_prediction = self.strategy_integrator.predict_best_strategy(
                    target_info.ip, target_info.domain, dpi_signature.fingerprint_data
                )
            except Exception as e:
                LOG.debug(f"ML prediction failed: {e}")

        # Get fingerprint data
        fingerprint_data = None
        if self.enable_ml_integration and self.fingerprint_integrator:
            try:
                fingerprint_data = await self.fingerprint_integrator.fingerprint_target(
                    target_info.domain, target_info.ip
                )
            except Exception as e:
                LOG.debug(f"Fingerprint data retrieval failed: {e}")

        # Get historical data (placeholder)
        historical_data = self._get_historical_data(target_info.domain)

        # Get performance constraints
        performance_constraints = self._get_performance_constraints()

        return AttackContext(
            target_info=target_info,
            dpi_signature=dpi_signature,
            ml_prediction=ml_prediction,
            fingerprint_data=fingerprint_data,
            historical_data=historical_data,
            performance_constraints=performance_constraints,
        )

    def _get_historical_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get historical attack data for domain."""

        # Filter execution history for this domain
        domain_history = [
            entry for entry in self.execution_history if domain in entry["target"]
        ]

        if not domain_history:
            return None

        # Aggregate historical data
        successful_attacks = [
            entry for entry in domain_history if entry["result"].success
        ]

        return {
            "total_attempts": len(domain_history),
            "successful_attempts": len(successful_attacks),
            "success_rate": (
                len(successful_attacks) / len(domain_history) if domain_history else 0.0
            ),
            "most_successful_attack": self._get_most_successful_attack(
                successful_attacks
            ),
            "last_attempt": domain_history[-1]["timestamp"] if domain_history else None,
        }

    def _get_most_successful_attack(
        self, successful_attacks: List[Dict]
    ) -> Optional[str]:
        """Get the most successful attack type from history."""

        if not successful_attacks:
            return None

        attack_counts = {}
        for entry in successful_attacks:
            attack_name = entry["result"].attack_name
            attack_counts[attack_name] = attack_counts.get(attack_name, 0) + 1

        return max(attack_counts, key=attack_counts.get)

    def _get_performance_constraints(self) -> Optional[Dict[str, Any]]:
        """Get current performance constraints."""

        if not self.performance_integrator:
            return None

        try:
            metrics = self.performance_integrator.get_current_metrics()

            return {
                "max_cpu_usage": 80.0,
                "max_memory_usage": 500.0,  # MB
                "max_latency_ms": 2000.0,
                "current_cpu": metrics.cpu_usage_percent,
                "current_memory": metrics.memory_usage_mb,
            }

        except Exception as e:
            LOG.debug(f"Failed to get performance constraints: {e}")
            return None

    async def _apply_adaptations(
        self, attack: AdvancedAttack, suggestions: List[AdaptationSuggestion]
    ):
        """Apply adaptation suggestions to attack."""

        LOG.info(f"Applying {len(suggestions)} adaptations to {attack.config.name}")

        for suggestion in suggestions:
            try:
                # Create ML feedback for adaptation
                feedback = MLFeedback(
                    attack_name=attack.config.name,
                    success=False,  # Adaptation triggered by failure
                    latency_ms=0.0,
                    effectiveness_score=0.0,
                    failure_reason=suggestion.reason,
                    adaptation_suggestions=[suggestion.parameter],
                )

                await attack.adapt_from_feedback(feedback)
                LOG.debug(
                    f"Applied adaptation: {suggestion.parameter} -> {suggestion.suggested_value}"
                )

            except Exception as e:
                LOG.error(f"Failed to apply adaptation {suggestion.parameter}: {e}")

    async def update_learning_systems(self, result: AdvancedAttackResult) -> None:
        """Update learning systems with attack result."""

        LOG.debug(f"Updating learning systems with result from {result.attack_name}")

        # Update ML strategy predictor
        if self.enable_ml_integration and self.strategy_integrator:
            try:
                # This would update the ML model with feedback
                # For now, just log the feedback
                LOG.debug(f"ML feedback: {result.ml_feedback}")
            except Exception as e:
                LOG.error(f"Failed to update ML strategy predictor: {e}")

        # Update learning memory system
        if result.learning_data:
            try:
                # Store learning data for future use
                self.adaptation_cache[result.learning_data.target_signature] = (
                    result.learning_data
                )
                LOG.debug(
                    f"Stored learning data for {result.learning_data.target_signature}"
                )
            except Exception as e:
                LOG.error(f"Failed to update learning memory: {e}")

    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics for advanced attacks."""

        metrics = {
            "registered_attacks": len(self.registered_attacks),
            "enabled_attacks": len(
                [a for a in self.registered_attacks.values() if a.enabled]
            ),
            "total_executions": sum(
                a.stats["executions"] for a in self.registered_attacks.values()
            ),
            "total_successes": sum(
                a.stats["successes"] for a in self.registered_attacks.values()
            ),
            "execution_history_size": len(self.execution_history),
            "ml_integration_enabled": self.enable_ml_integration,
        }

        # Per-attack metrics
        attack_metrics = {}
        for name, attack in self.registered_attacks.items():
            attack_metrics[name] = {
                "executions": attack.stats["executions"],
                "successes": attack.stats["successes"],
                "success_rate": attack.get_success_rate(),
                "average_latency_ms": attack.get_average_latency(),
                "enabled": attack.enabled,
                "priority": attack.config.priority,
                "complexity": attack.config.complexity,
            }

        metrics["attacks"] = attack_metrics

        # Phase 1 integration metrics
        if self.enable_ml_integration:
            if self.performance_integrator:
                try:
                    phase1_metrics = self.performance_integrator.get_current_metrics()
                    metrics["phase1_performance"] = {
                        "cpu_usage_percent": phase1_metrics.cpu_usage_percent,
                        "memory_usage_mb": phase1_metrics.memory_usage_mb,
                        "ml_predictions_per_second": phase1_metrics.ml_predictions_per_second,
                        "fingerprints_per_second": phase1_metrics.fingerprints_per_second,
                    }
                except Exception as e:
                    LOG.debug(f"Failed to get Phase 1 metrics: {e}")

        return metrics

    def get_registered_attacks(self) -> Dict[str, AdvancedAttack]:
        """Get all registered advanced attacks."""
        return self.registered_attacks.copy()

    def enable_attack(self, attack_name: str) -> bool:
        """Enable a specific advanced attack."""
        if attack_name in self.registered_attacks:
            self.registered_attacks[attack_name].enabled = True
            LOG.info(f"Enabled advanced attack: {attack_name}")
            return True
        return False

    def disable_attack(self, attack_name: str) -> bool:
        """Disable a specific advanced attack."""
        if attack_name in self.registered_attacks:
            self.registered_attacks[attack_name].enabled = False
            LOG.info(f"Disabled advanced attack: {attack_name}")
            return True
        return False


# Global instance for easy access
_global_advanced_attack_manager = None


def get_advanced_attack_manager() -> AdvancedAttackManager:
    """Get global advanced attack manager instance."""
    global _global_advanced_attack_manager
    if _global_advanced_attack_manager is None:
        _global_advanced_attack_manager = AdvancedAttackManager()
    return _global_advanced_attack_manager
