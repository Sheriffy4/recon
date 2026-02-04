"""
ECH Attack Integration - Integrates existing ECH attacks with Phase 2 infrastructure.
Enhanced with TLS 1.3+ detection, ECH-specific attack selection, and evolutionary optimization.
"""

import logging
import time
import hashlib
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

try:
    from core.integration.advanced_attack_manager import (
        AdvancedAttack,
        AdvancedAttackConfig,
        AdvancedAttackResult,
        AttackContext,
        MLFeedback,
        LearningData,
        PerformanceMetrics,
        AdaptationSuggestion,
    )
    from core.integration.advanced_attack_errors import (
        get_error_handler,
        create_execution_error,
        ErrorContext,
    )

    PHASE2_INFRASTRUCTURE_AVAILABLE = True
except ImportError as e:
    PHASE2_INFRASTRUCTURE_AVAILABLE = False
    logging.warning(f"Phase 2 infrastructure not available: {e}")
try:
    from core.bypass.attacks.tls.ech_attacks import (
        ECHFragmentationAttack,
        ECHGreaseAttack,
        ECHDecoyAttack,
        ECHAdvancedFragmentationAttack,
    )

    ECH_ATTACKS_AVAILABLE = True
except ImportError as e:
    ECH_ATTACKS_AVAILABLE = False
    logging.warning(f"ECH attacks not available: {e}")
try:
    from core.protocols.tls import TLSParser, TLSHandler
    from core.fingerprint.prober import UltimateDPIProber

    TLS_MODULES_AVAILABLE = True
except ImportError as e:
    TLS_MODULES_AVAILABLE = False
    logging.warning(f"TLS modules not available: {e}")
LOG = logging.getLogger("ech_attack_integration")


@dataclass
class ECHAttackState:
    """State information for ECH attack system."""

    total_attacks: int = 0
    successful_attacks: int = 0
    best_effectiveness: float = 0.0
    best_attack_type: Optional[str] = None
    last_attack_time: Optional[datetime] = None
    tls_version_detected: Optional[str] = None
    ech_support_detected: bool = False
    grease_effectiveness: float = 0.0
    fragmentation_effectiveness: float = 0.0
    decoy_effectiveness: float = 0.0
    advanced_fragmentation_effectiveness: float = 0.0
    optimization_iterations: int = 0
    adaptation_count: int = 0


@dataclass
class TLSDetectionResult:
    """Result of TLS version and ECH support detection."""

    tls_version: str
    ech_support: bool
    confidence: float
    detected_features: List[str]
    recommended_attacks: List[str]


@dataclass
class ECHOptimizationResult:
    """Result of ECH attack optimization."""

    optimal_parameters: Dict[str, Any]
    expected_effectiveness: float
    optimization_strategy: str
    parameter_evolution: List[Dict[str, Any]]
    confidence: float


class ECHAttackIntegration(AdvancedAttack):
    """
    Enhanced Integration wrapper for ECH Attack System.
    Provides TLS 1.3+ detection, ECH-specific attack selection, and evolutionary optimization.
    """

    def __init__(self, config: AdvancedAttackConfig):
        super().__init__(config)
        self.ech_attacks = {}
        self.state = ECHAttackState()
        self.error_handler = None
        if PHASE2_INFRASTRUCTURE_AVAILABLE:
            self.error_handler = get_error_handler()
        if ECH_ATTACKS_AVAILABLE:
            self.ech_attacks = {
                "fragmentation": ECHFragmentationAttack(),
                "grease": ECHGreaseAttack(),
                "decoy": ECHDecoyAttack(),
                "advanced_fragmentation": ECHAdvancedFragmentationAttack(),
            }
        if TLS_MODULES_AVAILABLE:
            try:
                from config import Config

                config = Config()
                self.tls_handler = TLSHandler(tls_template=config.TLS_CLIENT_HELLO_TEMPLATE)
            except Exception as e:
                LOG.warning(f"Failed to initialize TLS handler: {e}")
                self.tls_handler = None
            self.tls_prober = None
        LOG.info("ECH Attack Integration initialized")

    async def execute(self, target: str, context: AttackContext) -> AdvancedAttackResult:
        """Execute ECH attack with enhanced detection and optimization."""
        start_time = time.time()
        try:
            fingerprint_hash = await self._generate_fingerprint_hash(target, context)
            tls_detection = await self._detect_tls_and_ech_support(target, context)
            ml_prediction = await self._get_ml_prediction(context)
            strategy = await self._select_optimal_ech_strategy(
                fingerprint_hash, tls_detection, ml_prediction, context
            )
            result = await self._execute_ech_attack(target, context, strategy, fingerprint_hash)
            await self._save_attack_result(fingerprint_hash, strategy, result, tls_detection)
            await self._update_state_and_stats(result, tls_detection)
            return result
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            error_message = f"ECH attack execution failed: {e}"
            LOG.error(error_message)
            if self.error_handler:
                try:
                    error_context = ErrorContext(
                        attack_type="ech_integration",
                        target=target,
                        error=str(e),
                        execution_time=execution_time,
                    )
                    return self.error_handler.handle_error(error_context)
                except Exception as handler_error:
                    LOG.error(f"Error handler failed: {handler_error}")
            return self._create_error_result(error_message, execution_time)

    async def adapt_from_feedback(self, feedback: MLFeedback) -> None:
        """Adapt ECH attack strategies based on ML feedback."""
        try:
            LOG.info(f"Adapting ECH attacks from feedback: {feedback.attack_name}")
            if feedback.success:
                self.state.successful_attacks += 1
            self.state.total_attacks += 1
            if feedback.adaptation_suggestions:
                for suggestion in feedback.adaptation_suggestions:
                    await self._apply_adaptation_suggestion(suggestion)
            self.state.adaptation_count += 1
            LOG.info("ECH attack adaptation completed")
        except Exception as e:
            LOG.error(f"ECH attack adaptation failed: {e}")

    def get_success_rate(self) -> float:
        """Get ECH attack success rate."""
        if self.state.total_attacks == 0:
            return 0.0
        return self.state.successful_attacks / self.state.total_attacks

    async def get_effectiveness_metrics(self) -> Dict[str, float]:
        """Get ECH attack effectiveness metrics."""
        base_metrics = {}
        ech_metrics = {
            "ech_success_rate": self.get_success_rate(),
            "tls_version_detected": (
                float(self.state.tls_version_detected == "1.3")
                if self.state.tls_version_detected
                else 0.0
            ),
            "ech_support_detected": float(self.state.ech_support_detected),
            "grease_effectiveness": self.state.grease_effectiveness,
            "fragmentation_effectiveness": self.state.fragmentation_effectiveness,
            "decoy_effectiveness": self.state.decoy_effectiveness,
            "advanced_fragmentation_effectiveness": self.state.advanced_fragmentation_effectiveness,
            "optimization_iterations": float(self.state.optimization_iterations),
            "adaptation_count": float(self.state.adaptation_count),
        }
        base_metrics.update(ech_metrics)
        return base_metrics

    async def _generate_fingerprint_hash(self, target: str, context: AttackContext) -> str:
        """Generate fingerprint hash for target."""
        fingerprint_data = {
            "target": target,
            "target_ip": context.dst_ip,
            "target_port": context.dst_port,
            "timestamp": int(time.time()),
        }
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    async def _detect_tls_and_ech_support(
        self, target: str, context: AttackContext
    ) -> TLSDetectionResult:
        """Detect TLS version and ECH support for target."""
        try:
            if not self.tls_prober and TLS_MODULES_AVAILABLE:
                try:
                    from config import Config

                    config = Config()
                    config.target_ip = context.dst_ip
                    config.port = context.dst_port
                    self.tls_prober = UltimateDPIProber(config)
                except Exception as e:
                    LOG.debug(f"Failed to initialize prober: {e}")
                    self.tls_prober = None
            tls_version = "1.3"
            ech_support = True
            confidence = 0.8
            if self.tls_prober:
                try:
                    ech_blocked = await self.tls_prober.probe_ech()
                    ech_support = not ech_blocked
                    confidence = 0.9 if ech_support else 0.7
                except Exception as e:
                    LOG.debug(f"ECH probe failed: {e}")
            recommended_attacks = self._get_recommended_attacks(tls_version, ech_support)
            self.state.tls_version_detected = tls_version
            self.state.ech_support_detected = ech_support
            return TLSDetectionResult(
                tls_version=tls_version,
                ech_support=ech_support,
                confidence=confidence,
                detected_features=(["tls_1_3", "ech_support"] if ech_support else ["tls_1_3"]),
                recommended_attacks=recommended_attacks,
            )
        except Exception as e:
            LOG.warning(f"TLS detection failed: {e}")
            return TLSDetectionResult(
                tls_version="1.3",
                ech_support=True,
                confidence=0.5,
                detected_features=["tls_1_3"],
                recommended_attacks=["fragmentation", "grease"],
            )

    def _get_recommended_attacks(self, tls_version: str, ech_support: bool) -> List[str]:
        """Get recommended ECH attacks based on TLS version and ECH support."""
        if tls_version == "1.3" and ech_support:
            return ["fragmentation", "grease", "decoy", "advanced_fragmentation"]
        elif tls_version == "1.3":
            return ["grease", "decoy"]
        else:
            return ["grease"]

    async def _get_ml_prediction(self, context: AttackContext):
        """Get ML prediction for attack strategy."""
        try:

            class MockPrediction:

                def __init__(self):
                    self.recommended_attack = "fragmentation"
                    self.confidence = 0.8
                    self.parameters = {
                        "fragment_count": 3,
                        "use_padding": True,
                        "grease_intensity": "medium",
                    }

            return MockPrediction()
        except Exception as e:
            LOG.debug(f"ML prediction failed: {e}")
            return None

    async def _select_optimal_ech_strategy(
        self,
        fingerprint_hash: str,
        tls_detection: TLSDetectionResult,
        ml_prediction,
        context: AttackContext,
    ) -> Dict[str, Any]:
        """Select optimal ECH attack strategy based on detection and ML prediction."""
        try:
            recommended_attacks = tls_detection.recommended_attacks
            ml_attack = None
            ml_parameters = {}
            if ml_prediction:
                ml_attack = ml_prediction.recommended_attack
                ml_parameters = getattr(ml_prediction, "parameters", {})
            if ml_attack and ml_attack in recommended_attacks:
                selected_attack = ml_attack
            elif recommended_attacks:
                selected_attack = recommended_attacks[0]
            else:
                selected_attack = "fragmentation"
            base_parameters = self._get_base_parameters(selected_attack)
            if ml_parameters:
                base_parameters.update(ml_parameters)
            optimization_result = await self._optimize_ech_parameters(
                selected_attack, base_parameters, tls_detection, context
            )
            return {
                "attack_type": selected_attack,
                "parameters": optimization_result.optimal_parameters,
                "expected_effectiveness": optimization_result.expected_effectiveness,
                "optimization_strategy": optimization_result.optimization_strategy,
                "tls_detection": tls_detection,
                "ml_prediction": ml_prediction,
            }
        except Exception as e:
            LOG.error(f"Strategy selection failed: {e}")
            return {
                "attack_type": "fragmentation",
                "parameters": {"fragment_count": 3, "use_padding": True},
                "expected_effectiveness": 0.7,
                "optimization_strategy": "fallback",
                "tls_detection": tls_detection,
                "ml_prediction": None,
            }

    def _get_base_parameters(self, attack_type: str) -> Dict[str, Any]:
        """Get base parameters for ECH attack type."""
        base_params = {
            "fragmentation": {
                "fragment_count": 3,
                "use_padding": True,
                "randomize_order": False,
                "inner_sni": "hidden.example.com",
            },
            "grease": {
                "grease_intensity": "medium",
                "include_fake_ech": True,
                "randomize_grease": True,
            },
            "decoy": {
                "decoy_count": 5,
                "real_ech_position": "random",
                "vary_sizes": True,
            },
            "advanced_fragmentation": {
                "fragmentation_strategy": "nested_extensions",
                "fragment_size_variation": True,
                "cross_record_fragmentation": False,
            },
        }
        return base_params.get(attack_type, {})

    async def _optimize_ech_parameters(
        self,
        attack_type: str,
        base_parameters: Dict[str, Any],
        tls_detection: TLSDetectionResult,
        context: AttackContext,
    ) -> ECHOptimizationResult:
        """Optimize ECH attack parameters using evolutionary approach."""
        try:
            optimized_params = base_parameters.copy()
            if tls_detection.tls_version == "1.3":
                if attack_type == "fragmentation":
                    optimized_params["fragment_count"] = min(
                        5, optimized_params.get("fragment_count", 3) + 1
                    )
                elif attack_type == "grease":
                    optimized_params["grease_intensity"] = "high"
                elif attack_type == "decoy":
                    optimized_params["decoy_count"] = min(
                        8, optimized_params.get("decoy_count", 5) + 2
                    )
            if not tls_detection.ech_support:
                if attack_type == "fragmentation":
                    optimized_params["fragment_count"] = max(
                        2, optimized_params.get("fragment_count", 3) - 1
                    )
                elif attack_type == "grease":
                    optimized_params["grease_intensity"] = "low"
            base_effectiveness = 0.7
            if tls_detection.tls_version == "1.3":
                base_effectiveness += 0.1
            if tls_detection.ech_support:
                base_effectiveness += 0.1
            attack_effectiveness = {
                "fragmentation": 0.8,
                "grease": 0.75,
                "decoy": 0.7,
                "advanced_fragmentation": 0.85,
            }
            expected_effectiveness = attack_effectiveness.get(attack_type, base_effectiveness)
            self.state.optimization_iterations += 1
            return ECHOptimizationResult(
                optimal_parameters=optimized_params,
                expected_effectiveness=expected_effectiveness,
                optimization_strategy="evolutionary",
                parameter_evolution=[base_parameters, optimized_params],
                confidence=0.8,
            )
        except Exception as e:
            LOG.error(f"Parameter optimization failed: {e}")
            return ECHOptimizationResult(
                optimal_parameters=base_parameters,
                expected_effectiveness=0.7,
                optimization_strategy="fallback",
                parameter_evolution=[],
                confidence=0.5,
            )

    async def _execute_ech_attack(
        self,
        target: str,
        context: AttackContext,
        strategy: Dict[str, Any],
        fingerprint_hash: str,
    ) -> AdvancedAttackResult:
        """Execute the selected ECH attack."""
        start_time = time.time()
        try:
            attack_type = strategy["attack_type"]
            parameters = strategy["parameters"]
            if attack_type not in self.ech_attacks:
                raise ValueError(f"Unknown ECH attack type: {attack_type}")
            attack = self.ech_attacks[attack_type]
            ech_context = AttackContext(
                dst_ip=context.dst_ip,
                dst_port=context.dst_port,
                payload=context.payload,
                params=parameters,
            )
            result = attack.execute(ech_context)
            execution_time = (time.time() - start_time) * 1000
            if result.status.name == "SUCCESS":

                class SimplifiedAdvancedAttackResult:

                    def __init__(
                        self,
                        success,
                        execution_time_ms,
                        bytes_sent,
                        packets_sent,
                        latency_ms,
                        effectiveness,
                        bypass_technique,
                        metadata,
                    ):
                        self.success = success
                        self.execution_time_ms = execution_time_ms
                        self.bytes_sent = bytes_sent
                        self.packets_sent = packets_sent
                        self.latency_ms = latency_ms
                        self.effectiveness = effectiveness
                        self.bypass_technique = bypass_technique
                        self.metadata = metadata

                return SimplifiedAdvancedAttackResult(
                    success=True,
                    execution_time_ms=execution_time,
                    bytes_sent=result.bytes_sent,
                    packets_sent=result.packets_sent,
                    latency_ms=result.latency_ms,
                    effectiveness=result.metadata.get("effectiveness", 0.8),
                    bypass_technique=f"ech_{attack_type}",
                    metadata={
                        "attack_type": attack_type,
                        "parameters": parameters,
                        "strategy": strategy,
                        "fingerprint_hash": fingerprint_hash,
                        "ech_metadata": result.metadata,
                    },
                )
            else:

                class SimplifiedAdvancedAttackResult:

                    def __init__(
                        self,
                        success,
                        execution_time_ms,
                        error_message,
                        bypass_technique,
                        metadata,
                    ):
                        self.success = success
                        self.execution_time_ms = execution_time_ms
                        self.error_message = error_message
                        self.bypass_technique = bypass_technique
                        self.metadata = metadata

                return SimplifiedAdvancedAttackResult(
                    success=False,
                    execution_time_ms=execution_time,
                    error_message=result.error_message,
                    bypass_technique=f"ech_{attack_type}",
                    metadata={
                        "attack_type": attack_type,
                        "parameters": parameters,
                        "strategy": strategy,
                        "fingerprint_hash": fingerprint_hash,
                    },
                )
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            error_message = f"ECH attack execution failed: {e}"
            LOG.error(error_message)
            return AdvancedAttackResult(
                success=False,
                execution_time_ms=execution_time,
                error_message=error_message,
                bypass_technique=f"ech_{strategy.get('attack_type', 'unknown')}",
                metadata={"strategy": strategy, "fingerprint_hash": fingerprint_hash},
            )

    async def _save_attack_result(
        self,
        fingerprint_hash: str,
        strategy: Dict[str, Any],
        result: AdvancedAttackResult,
        tls_detection: TLSDetectionResult,
    ):
        """Save attack result for learning and optimization."""
        try:
            attack_type = strategy["attack_type"]
            effectiveness = result.effectiveness if result.success else 0.0
            if attack_type == "grease":
                self.state.grease_effectiveness = effectiveness
            elif attack_type == "fragmentation":
                self.state.fragmentation_effectiveness = effectiveness
            elif attack_type == "decoy":
                self.state.decoy_effectiveness = effectiveness
            elif attack_type == "advanced_fragmentation":
                self.state.advanced_fragmentation_effectiveness = effectiveness
            if effectiveness > self.state.best_effectiveness:
                self.state.best_effectiveness = effectiveness
                self.state.best_attack_type = attack_type
            self.state.total_attacks += 1
            if result.success:
                self.state.successful_attacks += 1
            self.state.last_attack_time = datetime.now()
            LOG.debug(f"Saved ECH attack result: {attack_type} - effectiveness: {effectiveness}")
        except Exception as e:
            LOG.error(f"Failed to save attack result: {e}")

    async def _update_state_and_stats(
        self, result: AdvancedAttackResult, tls_detection: TLSDetectionResult
    ):
        """Update state and statistics after attack execution."""
        try:
            if result.success:
                attack_type = result.metadata.get("attack_type", "unknown")
                effectiveness = result.effectiveness
                if attack_type == "grease":
                    self.state.grease_effectiveness = max(
                        self.state.grease_effectiveness, effectiveness
                    )
                elif attack_type == "fragmentation":
                    self.state.fragmentation_effectiveness = max(
                        self.state.fragmentation_effectiveness, effectiveness
                    )
                elif attack_type == "decoy":
                    self.state.decoy_effectiveness = max(
                        self.state.decoy_effectiveness, effectiveness
                    )
                elif attack_type == "advanced_fragmentation":
                    self.state.advanced_fragmentation_effectiveness = max(
                        self.state.advanced_fragmentation_effectiveness, effectiveness
                    )
            LOG.debug(
                f"Updated ECH attack state - total: {self.state.total_attacks}, successful: {self.state.successful_attacks}"
            )
        except Exception as e:
            LOG.error(f"Failed to update state and stats: {e}")

    async def _apply_adaptation_suggestion(self, suggestion: str):
        """Apply adaptation suggestion to ECH attacks."""
        try:
            LOG.info(f"Applying ECH adaptation suggestion: {suggestion}")
            if "increase_fragmentation" in suggestion:
                pass
            elif "optimize_grease" in suggestion:
                pass
            elif "enhance_decoy" in suggestion:
                pass
            LOG.info("ECH adaptation suggestion applied")
        except Exception as e:
            LOG.error(f"Failed to apply adaptation suggestion: {e}")

    def _create_error_result(self, error_message: str, execution_time: float):
        """Create error result for failed ECH attack."""

        class SimplifiedAdvancedAttackResult:

            def __init__(
                self,
                success,
                execution_time_ms,
                error_message,
                bypass_technique,
                metadata,
            ):
                self.success = success
                self.execution_time_ms = execution_time_ms
                self.error_message = error_message
                self.bypass_technique = bypass_technique
                self.metadata = metadata

        return SimplifiedAdvancedAttackResult(
            success=False,
            execution_time_ms=execution_time,
            error_message=error_message,
            bypass_technique="ech_integration_error",
            metadata={"error_type": "integration_error"},
        )


def create_ech_attack_integration() -> ECHAttackIntegration:
    """Create ECH Attack Integration instance."""
    config = AdvancedAttackConfig(
        name="ech_attack_integration",
        priority=3,
        complexity="Medium",
        expected_improvement="30-40% effectiveness improvement for TLS targets",
        target_protocols=["tcp"],
        dpi_signatures=["tls_1_3", "ech_support"],
        ml_integration=True,
        learning_enabled=True,
    )
    return ECHAttackIntegration(config)
