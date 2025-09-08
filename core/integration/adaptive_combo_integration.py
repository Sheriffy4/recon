"""
Adaptive Combo Attack Integration - Integrates existing adaptive combo attacks with Phase 2 infrastructure.
"""

import logging
import time
import hashlib
from typing import Dict, List, Any
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
    from core.bypass.attacks.combo.adaptive_combo import DPIResponseAdaptiveAttack
    from core.bypass.attacks.base import (
        AttackContext as BaseAttackContext,
        AttackResult as BaseAttackResult,
    )

    ADAPTIVE_COMBO_AVAILABLE = True
except ImportError as e:
    ADAPTIVE_COMBO_AVAILABLE = False
    logging.warning(f"Adaptive combo attacks not available: {e}")
LOG = logging.getLogger("adaptive_combo_integration")


@dataclass
class AdaptiveComboState:
    """State information for adaptive combo attacks."""

    iteration: int = 0
    techniques_tried: List[str] = None
    success_rate: float = 0.0
    current_strategy: str = "conservative"
    detection_scores: List[float] = None
    adaptation_history: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.techniques_tried is None:
            self.techniques_tried = []
        if self.detection_scores is None:
            self.detection_scores = []
        if self.adaptation_history is None:
            self.adaptation_history = []


class AdaptiveComboAttackIntegration(AdvancedAttack):
    """
    Integration wrapper for Adaptive Combo Attacks.
    Provides ML integration, learning capabilities, and Phase 2 compatibility.
    """

    def __init__(self, config: AdvancedAttackConfig):
        super().__init__(config)
        self.adaptive_attack = None
        self.state_cache: Dict[str, AdaptiveComboState] = {}
        self.learning_data_cache: Dict[str, List[Dict]] = {}
        self.error_handler = None
        self.max_iterations = 5
        self.detection_threshold = 0.6
        self.learning_rate = 0.1
        self.adaptation_aggressiveness = 0.8
        if ADAPTIVE_COMBO_AVAILABLE:
            try:
                self.adaptive_attack = DPIResponseAdaptiveAttack()
                LOG.info("Adaptive combo attack initialized successfully")
            except Exception as e:
                LOG.error(f"Failed to initialize adaptive combo attack: {e}")
                self.adaptive_attack = None
        if PHASE2_INFRASTRUCTURE_AVAILABLE:
            try:
                self.error_handler = get_error_handler()
            except Exception as e:
                LOG.warning(f"Error handler not available: {e}")
        LOG.info(f"Adaptive Combo Attack Integration initialized: {self.config.name}")

    async def execute(
        self, target: str, context: AttackContext
    ) -> AdvancedAttackResult:
        """Execute adaptive combo attack with ML integration."""
        LOG.info(f"Executing adaptive combo attack on {target}")
        start_time = time.time()
        try:
            target_key = self._get_target_key(target, context)
            state = self._get_or_create_state(target_key)
            if context.ml_prediction and self.ml_predictor:
                await self._apply_ml_predictions(context.ml_prediction, state)
            if context.historical_data:
                await self._apply_historical_learning(context.historical_data, state)
            base_context = await self._convert_to_base_context(context, state)
            if self.adaptive_attack:
                base_result = await self.adaptive_attack.execute(base_context)
                result = await self._convert_from_base_result(
                    base_result, state, target_key
                )
            else:
                result = await self._fallback_execution(target, context, state)
            await self._update_state_and_learning(state, result, target_key)
            self.update_stats(result)
            execution_time = (time.time() - start_time) * 1000
            LOG.info(
                f"Adaptive combo attack completed: {('SUCCESS' if result.success else 'FAILURE')} ({execution_time:.1f}ms)"
            )
            return result
        except Exception as e:
            LOG.error(f"Adaptive combo attack execution failed: {e}")
            if self.error_handler:
                try:
                    error_context = ErrorContext(
                        attack_name=self.config.name, target=target, operation="execute"
                    )
                    error = create_execution_error(
                        str(e), self.config.name, error_context, e
                    )
                    recovery_result = await self.error_handler.handle_error(error)
                    if (
                        recovery_result.success
                        and recovery_result.action.value == "retry"
                    ):
                        return await self._retry_with_fallback(target, context)
                except Exception as error_handling_error:
                    LOG.error(f"Error handling failed: {error_handling_error}")
            return self._create_error_result(str(e), time.time() - start_time)

    async def adapt_from_feedback(self, feedback: MLFeedback) -> None:
        """Adapt attack parameters based on ML feedback."""
        LOG.info(f"Adapting from ML feedback: {feedback.attack_name}")
        try:
            if feedback.success:
                self.adaptation_aggressiveness = max(
                    0.1, self.adaptation_aggressiveness * 0.95
                )
                self.detection_threshold = min(0.9, self.detection_threshold * 1.05)
            else:
                self.adaptation_aggressiveness = min(
                    1.0, self.adaptation_aggressiveness * 1.1
                )
                self.detection_threshold = max(0.3, self.detection_threshold * 0.95)
            for suggestion in feedback.adaptation_suggestions:
                await self._apply_adaptation_suggestion(suggestion)
            if feedback.effectiveness_score > 0.8:
                self.learning_rate = max(0.05, self.learning_rate * 0.9)
            elif feedback.effectiveness_score < 0.4:
                self.learning_rate = min(0.3, self.learning_rate * 1.2)
            LOG.debug(
                f"Adaptation completed: aggressiveness={self.adaptation_aggressiveness:.2f}, threshold={self.detection_threshold:.2f}"
            )
        except Exception as e:
            LOG.error(f"Adaptation from feedback failed: {e}")

    async def get_effectiveness_metrics(self) -> Dict[str, float]:
        """Get attack effectiveness metrics."""
        try:
            base_metrics = {
                "success_rate": self.get_success_rate(),
                "average_latency_ms": self.get_average_latency(),
                "adaptation_aggressiveness": self.adaptation_aggressiveness,
                "detection_threshold": self.detection_threshold,
                "learning_rate": self.learning_rate,
            }
            if self.state_cache:
                total_iterations = sum(
                    (state.iteration for state in self.state_cache.values())
                )
                total_techniques = sum(
                    (len(state.techniques_tried) for state in self.state_cache.values())
                )
                avg_success_rate = sum(
                    (state.success_rate for state in self.state_cache.values())
                ) / len(self.state_cache)
                base_metrics.update(
                    {
                        "total_adaptations": total_iterations,
                        "total_techniques_tried": total_techniques,
                        "average_state_success_rate": avg_success_rate,
                        "cached_states": len(self.state_cache),
                    }
                )
            if self.learning_data_cache:
                total_learning_entries = sum(
                    (len(entries) for entries in self.learning_data_cache.values())
                )
                base_metrics["total_learning_entries"] = total_learning_entries
            return base_metrics
        except Exception as e:
            LOG.error(f"Failed to get effectiveness metrics: {e}")
            return {"error": str(e)}

    def _get_target_key(self, target: str, context: AttackContext) -> str:
        """Generate unique key for target and context."""
        key_components = [
            target,
            context.target_info.domain,
            context.dpi_signature.dpi_type,
            str(context.dpi_signature.sophistication_level),
        ]
        key_string = "|".join(key_components)
        return hashlib.md5(key_string.encode()).hexdigest()[:16]

    def _get_or_create_state(self, target_key: str) -> AdaptiveComboState:
        """Get existing state or create new one for target."""
        if target_key not in self.state_cache:
            self.state_cache[target_key] = AdaptiveComboState()
        return self.state_cache[target_key]

    async def _apply_ml_predictions(self, ml_prediction, state: AdaptiveComboState):
        """Apply ML predictions to adaptive state."""
        try:
            if ml_prediction.confidence > 0.8:
                state.current_strategy = "aggressive"
                self.max_iterations = min(8, self.max_iterations + 1)
            elif ml_prediction.confidence < 0.4:
                state.current_strategy = "conservative"
                self.max_iterations = max(3, self.max_iterations - 1)
            primary_strategy = ml_prediction.primary_strategy
            if "combo" in primary_strategy or "adaptive" in primary_strategy:
                self.adaptation_aggressiveness = min(
                    1.0, self.adaptation_aggressiveness * 1.2
                )
            elif "steganography" in primary_strategy:
                self.detection_threshold = max(0.3, self.detection_threshold * 0.8)
            LOG.debug(
                f"Applied ML predictions: strategy={state.current_strategy}, iterations={self.max_iterations}"
            )
        except Exception as e:
            LOG.error(f"Failed to apply ML predictions: {e}")

    async def _apply_historical_learning(
        self, historical_data: Dict[str, Any], state: AdaptiveComboState
    ):
        """Apply historical learning data to adaptive state."""
        try:
            most_successful = historical_data.get("most_successful_attack")
            if most_successful and "adaptive" in most_successful:
                state.current_strategy = "proven"
                self.adaptation_aggressiveness = min(
                    1.0, self.adaptation_aggressiveness * 1.1
                )
            historical_success_rate = historical_data.get("success_rate", 0.5)
            if historical_success_rate > 0.8:
                self.detection_threshold = min(0.9, self.detection_threshold * 1.1)
            elif historical_success_rate < 0.3:
                self.detection_threshold = max(0.3, self.detection_threshold * 0.9)
            LOG.debug(
                f"Applied historical learning: success_rate={historical_success_rate}"
            )
        except Exception as e:
            LOG.error(f"Failed to apply historical learning: {e}")

    async def _convert_to_base_context(
        self, context: AttackContext, state: AdaptiveComboState
    ) -> BaseAttackContext:
        """Convert Phase 2 context to base attack context."""
        try:
            payload = (
                f"GET / HTTP/1.1\r\nHost: {context.target_info.domain}\r\n\r\n".encode()
            )
            base_context = BaseAttackContext(
                payload=payload,
                dst_ip=context.target_info.ip,
                dst_port=context.target_info.port,
                domain=context.target_info.domain,
                params={
                    "max_iterations": self.max_iterations,
                    "detection_threshold": self.detection_threshold,
                    "adaptation_aggressiveness": self.adaptation_aggressiveness,
                    "current_strategy": state.current_strategy,
                    "techniques_tried": state.techniques_tried.copy(),
                },
            )
            if hasattr(base_context, "domain"):
                base_context.domain = context.target_info.domain
            if hasattr(base_context, "engine_type"):
                base_context.engine_type = "advanced"
            return base_context
        except Exception as e:
            LOG.error(f"Failed to convert context: {e}")
            return BaseAttackContext(
                payload=b"GET / HTTP/1.1\r\n\r\n",
                dst_ip=context.target_info.ip,
                dst_port=context.target_info.port,
            )

    async def _convert_from_base_result(
        self, base_result: BaseAttackResult, state: AdaptiveComboState, target_key: str
    ) -> AdvancedAttackResult:
        """Convert base attack result to Phase 2 result."""
        try:
            metadata = base_result.metadata or {}
            adaptation_iterations = metadata.get("adaptation_iterations", 1)
            techniques_tried = metadata.get("techniques_tried", [])
            final_success_rate = metadata.get("final_success_rate", 0.5)
            detection_score = metadata.get("final_detection_score", 0.5)
            state.iteration = adaptation_iterations
            state.techniques_tried.extend(techniques_tried)
            state.success_rate = final_success_rate
            ml_feedback = MLFeedback(
                attack_name=self.config.name,
                success=base_result.status.name == "SUCCESS",
                latency_ms=base_result.latency_ms,
                effectiveness_score=final_success_rate,
                failure_reason=(
                    base_result.error_message if base_result.error_message else None
                ),
                adaptation_suggestions=self._generate_adaptation_suggestions(
                    state, detection_score
                ),
            )
            learning_data = LearningData(
                target_signature=target_key,
                attack_parameters={
                    "max_iterations": self.max_iterations,
                    "detection_threshold": self.detection_threshold,
                    "adaptation_aggressiveness": self.adaptation_aggressiveness,
                    "techniques_tried": techniques_tried,
                },
                effectiveness=final_success_rate,
                context={
                    "adaptation_iterations": adaptation_iterations,
                    "detection_score": detection_score,
                    "strategy": state.current_strategy,
                },
                timestamp=datetime.now(),
            )
            performance_metrics = PerformanceMetrics(
                execution_time_ms=base_result.latency_ms,
                memory_usage_mb=0.0,
                cpu_usage_percent=0.0,
                network_overhead_bytes=base_result.bytes_sent,
                success_rate=final_success_rate,
            )
            adaptation_suggestions = self._generate_adaptation_suggestions(
                state, detection_score
            )
            return AdvancedAttackResult(
                attack_name=self.config.name,
                success=base_result.status.name == "SUCCESS",
                latency_ms=base_result.latency_ms,
                effectiveness_score=final_success_rate,
                ml_feedback=ml_feedback,
                learning_data=learning_data,
                performance_metrics=performance_metrics,
                adaptation_suggestions=adaptation_suggestions,
            )
        except Exception as e:
            LOG.error(f"Failed to convert result: {e}")
            return self._create_error_result(str(e), 0)

    def _generate_adaptation_suggestions(
        self, state: AdaptiveComboState, detection_score: float
    ) -> List[AdaptationSuggestion]:
        """Generate adaptation suggestions based on current state."""
        suggestions = []
        try:
            if detection_score > 0.8 and self.max_iterations < 8:
                suggestions.append(
                    AdaptationSuggestion(
                        parameter="max_iterations",
                        current_value=self.max_iterations,
                        suggested_value=self.max_iterations + 1,
                        reason="High detection score requires more adaptation iterations",
                        confidence=0.8,
                    )
                )
            if state.success_rate < 0.4:
                suggestions.append(
                    AdaptationSuggestion(
                        parameter="detection_threshold",
                        current_value=self.detection_threshold,
                        suggested_value=max(0.3, self.detection_threshold * 0.9),
                        reason="Low success rate suggests threshold is too high",
                        confidence=0.7,
                    )
                )
            if len(state.techniques_tried) > 5 and state.success_rate < 0.6:
                suggestions.append(
                    AdaptationSuggestion(
                        parameter="adaptation_aggressiveness",
                        current_value=self.adaptation_aggressiveness,
                        suggested_value=min(1.0, self.adaptation_aggressiveness * 1.2),
                        reason="Many techniques tried with low success - increase aggressiveness",
                        confidence=0.6,
                    )
                )
        except Exception as e:
            LOG.error(f"Failed to generate adaptation suggestions: {e}")
        return suggestions

    async def _apply_adaptation_suggestion(self, suggestion: str):
        """Apply a specific adaptation suggestion."""
        try:
            if suggestion == "increase_iterations":
                self.max_iterations = min(10, self.max_iterations + 1)
            elif suggestion == "decrease_threshold":
                self.detection_threshold = max(0.2, self.detection_threshold * 0.9)
            elif suggestion == "increase_aggressiveness":
                self.adaptation_aggressiveness = min(
                    1.0, self.adaptation_aggressiveness * 1.1
                )
            elif suggestion == "reset_techniques":
                for state in self.state_cache.values():
                    state.techniques_tried.clear()
            LOG.debug(f"Applied adaptation suggestion: {suggestion}")
        except Exception as e:
            LOG.error(f"Failed to apply adaptation suggestion {suggestion}: {e}")

    async def _update_state_and_learning(
        self, state: AdaptiveComboState, result: AdvancedAttackResult, target_key: str
    ):
        """Update state and learning data after execution."""
        try:
            state.adaptation_history.append(
                {
                    "timestamp": datetime.now(),
                    "success": result.success,
                    "effectiveness": result.effectiveness_score,
                    "techniques": state.techniques_tried.copy(),
                    "iterations": state.iteration,
                }
            )
            if len(state.adaptation_history) > 50:
                state.adaptation_history = state.adaptation_history[-50:]
            if target_key not in self.learning_data_cache:
                self.learning_data_cache[target_key] = []
            self.learning_data_cache[target_key].append(
                {
                    "timestamp": datetime.now(),
                    "learning_data": result.learning_data,
                    "effectiveness": result.effectiveness_score,
                }
            )
            if len(self.learning_data_cache[target_key]) > 20:
                self.learning_data_cache[target_key] = self.learning_data_cache[
                    target_key
                ][-20:]
        except Exception as e:
            LOG.error(f"Failed to update state and learning: {e}")

    async def _fallback_execution(
        self, target: str, context: AttackContext, state: AdaptiveComboState
    ) -> AdvancedAttackResult:
        """Fallback execution when adaptive attack is not available."""
        LOG.warning("Using fallback execution for adaptive combo attack")
        try:
            start_time = time.time()
            techniques_tried = ["segmentation", "obfuscation"]
            if state.current_strategy == "aggressive":
                techniques_tried.extend(["tunneling", "fragmentation"])
            sophistication = context.dpi_signature.sophistication_level
            if sophistication == "basic":
                success = True
                effectiveness = 0.9
            elif sophistication == "intermediate":
                success = True
                effectiveness = 0.7
            else:
                success = False
                effectiveness = 0.4
            latency = (time.time() - start_time) * 1000
            ml_feedback = MLFeedback(
                attack_name=self.config.name,
                success=success,
                latency_ms=latency,
                effectiveness_score=effectiveness,
                failure_reason=(
                    None if success else "DPI too sophisticated for fallback"
                ),
                adaptation_suggestions=(
                    ["increase_aggressiveness"] if not success else []
                ),
            )
            learning_data = LearningData(
                target_signature=target,
                attack_parameters={"fallback": True},
                effectiveness=effectiveness,
                context={"sophistication": sophistication},
                timestamp=datetime.now(),
            )
            performance_metrics = PerformanceMetrics(
                execution_time_ms=latency,
                memory_usage_mb=1.0,
                cpu_usage_percent=5.0,
                network_overhead_bytes=1024,
                success_rate=effectiveness,
            )
            return AdvancedAttackResult(
                attack_name=self.config.name,
                success=success,
                latency_ms=latency,
                effectiveness_score=effectiveness,
                ml_feedback=ml_feedback,
                learning_data=learning_data,
                performance_metrics=performance_metrics,
                adaptation_suggestions=[],
            )
        except Exception as e:
            return self._create_error_result(str(e), time.time() - start_time)

    async def _retry_with_fallback(
        self, target: str, context: AttackContext
    ) -> AdvancedAttackResult:
        """Retry execution with simplified fallback parameters."""
        LOG.info("Retrying adaptive combo attack with fallback parameters")
        original_iterations = self.max_iterations
        original_threshold = self.detection_threshold
        self.max_iterations = 3
        self.detection_threshold = 0.8
        try:
            target_key = self._get_target_key(target, context)
            state = self._get_or_create_state(target_key)
            state.current_strategy = "conservative"
            result = await self._fallback_execution(target, context, state)
            return result
        finally:
            self.max_iterations = original_iterations
            self.detection_threshold = original_threshold

    def _create_error_result(
        self, error_message: str, execution_time: float
    ) -> AdvancedAttackResult:
        """Create error result for failed execution."""
        ml_feedback = MLFeedback(
            attack_name=self.config.name,
            success=False,
            latency_ms=execution_time * 1000 if execution_time > 0 else 0,
            effectiveness_score=0.0,
            failure_reason=error_message,
            adaptation_suggestions=["retry", "fallback"],
        )
        learning_data = LearningData(
            target_signature="error",
            attack_parameters={},
            effectiveness=0.0,
            context={"error": error_message},
            timestamp=datetime.now(),
        )
        performance_metrics = PerformanceMetrics(
            execution_time_ms=execution_time * 1000 if execution_time > 0 else 0,
            memory_usage_mb=0.0,
            cpu_usage_percent=0.0,
            network_overhead_bytes=0,
            success_rate=0.0,
        )
        return AdvancedAttackResult(
            attack_name=self.config.name,
            success=False,
            latency_ms=execution_time * 1000 if execution_time > 0 else 0,
            effectiveness_score=0.0,
            ml_feedback=ml_feedback,
            learning_data=learning_data,
            performance_metrics=performance_metrics,
            adaptation_suggestions=[],
            error_message=error_message,
        )


def create_adaptive_combo_integration() -> AdaptiveComboAttackIntegration:
    """Create configured Adaptive Combo Attack Integration instance."""
    config = AdvancedAttackConfig(
        name="adaptive_combo",
        priority=1,
        complexity="High",
        expected_improvement="25-35%",
        target_protocols=["tcp", "http", "https"],
        dpi_signatures=["complex_dpi", "sophisticated_dpi", "ai_dpi", "all"],
        ml_integration=True,
        learning_enabled=True,
    )
    return AdaptiveComboAttackIntegration(config)
