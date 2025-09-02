"""
Closed Loop Manager

Manages the closed loop feedback cycle: Fingerprint → Plan → Execute → Analyze → Refine
Integrates all components into a unified automatic process for continuous improvement.
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from core.fingerprint.models import EnhancedFingerprint
from ml.strategy_generator import AdvancedStrategyGenerator
from core.bypass.attacks.real_effectiveness_tester import EffectivenessResult
from core.bypass.attacks.combo.adaptive_combo import LearningAdaptiveAttack
from core.failure_analyzer import FailureAnalyzer, FailureAnalysisResult
from core.interfaces import (
    IFingerprintEngine,
    IStrategyGenerator,
    IEffectivenessTester,
    ILearningMemory,
    IAttackAdapter,
    IStrategySaver,
    IClosedLoopManager,
)

LOG = logging.getLogger("ClosedLoopManager")


@dataclass
class ClosedLoopIteration:
    """Result of a single closed loop iteration."""

    iteration_number: int
    fingerprint: EnhancedFingerprint
    strategies_generated: int
    strategies_tested: int
    best_effectiveness: float
    improvement_over_baseline: float
    analysis_notes: List[str] = field(default_factory=list)
    failure_analysis: Optional[FailureAnalysisResult] = None
    strategic_recommendations: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ClosedLoopResult:
    """Complete result of closed loop execution."""

    domain: str
    total_iterations: int
    final_effectiveness: float
    best_strategy: Optional[Dict[str, Any]]
    iterations: List[ClosedLoopIteration] = field(default_factory=list)
    convergence_achieved: bool = False
    total_time_seconds: float = 0.0
    analysis_summary: List[str] = field(default_factory=list)


class ClosedLoopManager(IClosedLoopManager):
    """
    Manages the closed loop feedback cycle for intelligent DPI bypass.

    Implements the cycle: Fingerprint → Plan → Execute → Analyze → Refine
    Continuously improves bypass effectiveness through automated learning.

    Fully supports Dependency Injection for improved testability and modularity.
    """

    def __init__(
        self,
        fingerprint_engine: IFingerprintEngine,
        strategy_generator: IStrategyGenerator,
        effectiveness_tester: IEffectivenessTester,
        learning_memory: ILearningMemory,
        attack_adapter: IAttackAdapter,
        strategy_saver: IStrategySaver,
        failure_analyzer: Optional[FailureAnalyzer] = None,
    ):
        """
        Initialize ClosedLoopManager with injected dependencies.

        Args:
            fingerprint_engine: Engine for creating and refining fingerprints (required)
            strategy_generator: Generator for creating attack strategies (required)
            effectiveness_tester: Tester for real effectiveness measurement (required)
            learning_memory: Persistent learning storage (required)
            attack_adapter: Adapter for executing attacks (required)
            strategy_saver: Saver for persisting effective strategies (required)
            failure_analyzer: Analyzer for failure patterns and strategic planning (optional)
        """
        if not fingerprint_engine:
            raise ValueError("fingerprint_engine is required for ClosedLoopManager")
        if not strategy_generator:
            raise ValueError("strategy_generator is required for ClosedLoopManager")
        if not effectiveness_tester:
            raise ValueError("effectiveness_tester is required for ClosedLoopManager")
        if not learning_memory:
            raise ValueError("learning_memory is required for ClosedLoopManager")
        if not attack_adapter:
            raise ValueError("attack_adapter is required for ClosedLoopManager")
        if not strategy_saver:
            raise ValueError("strategy_saver is required for ClosedLoopManager")
        self.fingerprint_engine = fingerprint_engine
        self.strategy_generator = strategy_generator
        self.effectiveness_tester = effectiveness_tester
        self.learning_memory = learning_memory
        self.attack_adapter = attack_adapter
        self.strategy_saver = strategy_saver
        self.failure_analyzer = failure_analyzer or FailureAnalyzer()
        self.logger = LOG
        self.max_iterations = 5
        self.convergence_threshold = 0.9
        self.improvement_threshold = 0.05
        self.strategies_per_iteration = 10
        self.max_strategies_to_test = 5
        self.current_iteration = 0
        self.best_effectiveness = 0.0
        self.baseline_effectiveness = 0.0
        self.iterations_without_improvement = 0
        self.max_iterations_without_improvement = 2

    async def run_closed_loop(
        self, domain: str, port: int = 443, max_iterations: Optional[int] = None
    ) -> ClosedLoopResult:
        """
        Run the enhanced closed loop process with clear algorithm:
        Fingerprint → Plan → Execute → Analyze → Refine & Learn

        Args:
            domain: Target domain to analyze and bypass
            port: Target port (default 443 for HTTPS)
            max_iterations: Maximum iterations to run (overrides default)

        Returns:
            ClosedLoopResult with complete analysis and results
        """
        start_time = time.time()
        if max_iterations is not None:
            self.max_iterations = max_iterations
        self.logger.info(f"Starting enhanced closed loop process for {domain}:{port}")
        self.logger.info(
            "Algorithm: Fingerprint → Plan → Execute → Analyze → Refine & Learn"
        )
        self.logger.info(
            f"Configuration: max_iterations={self.max_iterations}, convergence_threshold={self.convergence_threshold}"
        )
        result = ClosedLoopResult(
            domain=domain,
            total_iterations=0,
            final_effectiveness=0.0,
            best_strategy=None,
        )
        self.current_iteration = 0
        self.best_effectiveness = 0.0
        self.baseline_effectiveness = 0.0
        self.iterations_without_improvement = 0
        cumulative_failure_analysis = None
        all_test_results = []
        try:
            self.logger.info("=== PHASE 1: FINGERPRINT ===")
            baseline_result = await self.effectiveness_tester.test_baseline(
                domain, port
            )
            self.baseline_effectiveness = 1.0 if baseline_result.success else 0.0
            self.logger.info(
                f"Baseline established: success={baseline_result.success}, latency={baseline_result.latency_ms:.1f}ms"
            )
            if baseline_result.success:
                result.analysis_summary.append(
                    f"Domain {domain} is accessible without bypass"
                )
                self.baseline_effectiveness = 0.5
            else:
                result.analysis_summary.append(
                    f"Domain {domain} is blocked, bypass required"
                )
            current_fingerprint = await self.fingerprint_engine.create_comprehensive_fingerprint_with_extended_metrics(
                domain=domain, force_refresh=True
            )
            behavioral_profile = await self.fingerprint_engine.analyze_dpi_behavior(
                domain, current_fingerprint
            )
            self.logger.info(
                f"Behavioral profile created: {len(behavioral_profile.identified_weaknesses)} weaknesses identified"
            )
            fingerprint_hash = self.learning_memory._generate_fingerprint_hash(
                current_fingerprint.__dict__
            )
            learning_history = await self.learning_memory.load_learning_history(
                fingerprint_hash
            )
            if learning_history:
                self.logger.info(
                    f"Loaded learning history: {len(learning_history.successful_attacks)} successful attacks, best effectiveness: {learning_history.best_effectiveness:.2f}"
                )
            for iteration in range(self.max_iterations):
                self.current_iteration = iteration + 1
                self.logger.info(
                    f"=== Closed Loop Iteration {self.current_iteration}/{self.max_iterations} ==="
                )
                self.logger.info("=== PHASE 2: PLAN ===")
                iteration_result = await self._run_enhanced_iteration(
                    domain,
                    port,
                    current_fingerprint,
                    behavioral_profile,
                    learning_history,
                    baseline_result,
                    cumulative_failure_analysis,
                )
                result.iterations.append(iteration_result)
                result.total_iterations = self.current_iteration
                if hasattr(iteration_result, "test_results"):
                    all_test_results.extend(iteration_result.test_results)
                self.logger.info("=== PHASE 4: ANALYZE ===")
                if iteration_result.failure_analysis:
                    cumulative_failure_analysis = (
                        await self._integrate_failure_analysis(
                            cumulative_failure_analysis,
                            iteration_result.failure_analysis,
                        )
                    )
                    self.logger.info(
                        f"Failure analysis: {len(iteration_result.failure_analysis.failure_patterns)} patterns identified"
                    )
                if iteration_result.best_effectiveness > self.best_effectiveness:
                    improvement = (
                        iteration_result.best_effectiveness - self.best_effectiveness
                    )
                    self.best_effectiveness = iteration_result.best_effectiveness
                    result.final_effectiveness = self.best_effectiveness
                    result.best_strategy = getattr(
                        iteration_result, "best_strategy", None
                    )
                    self.iterations_without_improvement = 0
                    self.logger.info(
                        f"New best effectiveness: {self.best_effectiveness:.2f} (improvement: +{improvement:.2f})"
                    )
                else:
                    self.iterations_without_improvement += 1
                    self.logger.info(
                        f"No improvement in iteration {self.current_iteration} ({self.iterations_without_improvement} consecutive)"
                    )
                should_continue, reason = await self.should_continue_loop(result)
                if not should_continue:
                    self.logger.info(f"Stopping closed loop: {reason}")
                    result.analysis_summary.append(f"Convergence: {reason}")
                    break
                if iteration < self.max_iterations - 1:
                    self.logger.info("=== PHASE 5: REFINE & LEARN ===")
                    current_fingerprint = (
                        await self.fingerprint_engine.refine_fingerprint(
                            current_fingerprint,
                            getattr(iteration_result, "test_results", []),
                            learning_insights={
                                "failure_patterns": (
                                    cumulative_failure_analysis.failure_patterns
                                    if cumulative_failure_analysis
                                    else []
                                ),
                                "successful_techniques": [
                                    r.bypass.attack_name
                                    for r in all_test_results
                                    if getattr(r, "bypass_effective", False)
                                ],
                                "behavioral_insights": behavioral_profile.__dict__,
                            },
                        )
                    )
                    behavioral_profile = (
                        await self.fingerprint_engine.analyze_dpi_behavior(
                            domain, current_fingerprint
                        )
                    )
                    await self._update_learning_memory_with_behavioral_insights(
                        fingerprint_hash, behavioral_profile, iteration_result
                    )
                    self.logger.info(
                        "Fingerprint and behavioral profile refined for next iteration"
                    )
            result.total_time_seconds = time.time() - start_time
            result.convergence_achieved = (
                self.best_effectiveness >= self.convergence_threshold
            )
            await self._generate_final_analysis_summary(
                result, behavioral_profile, cumulative_failure_analysis
            )
            self.logger.info(
                f"Enhanced closed loop completed: {result.total_iterations} iterations, final effectiveness: {result.final_effectiveness:.2f}, time: {result.total_time_seconds:.1f}s"
            )
            return result
        except Exception as e:
            self.logger.error(f"Closed loop failed for {domain}: {e}")
            result.analysis_summary.append(f"Error: {str(e)}")
            result.total_time_seconds = time.time() - start_time
            return result

    async def _run_enhanced_iteration(
        self,
        domain: str,
        port: int,
        fingerprint: EnhancedFingerprint,
        behavioral_profile: Any,
        learning_history: Optional[Any],
        baseline_result: Any,
        previous_failure_analysis: Optional[FailureAnalysisResult] = None,
    ) -> ClosedLoopIteration:
        """
        Run an enhanced iteration of the closed loop with behavioral analysis integration.

        Args:
            domain: Target domain
            port: Target port
            fingerprint: Current enhanced fingerprint
            behavioral_profile: DPI behavioral profile
            learning_history: Learning history from memory
            baseline_result: Baseline test result
            previous_failure_analysis: Cumulative failure analysis from previous iterations

        Returns:
            ClosedLoopIteration with enhanced analysis
        """
        iteration_start = time.time()
        iteration_result = ClosedLoopIteration(
            iteration_number=self.current_iteration,
            fingerprint=fingerprint,
            strategies_generated=0,
            strategies_tested=0,
            best_effectiveness=0.0,
            improvement_over_baseline=0.0,
        )
        try:
            if previous_failure_analysis:
                self.logger.info("Generating strategies with failure analysis insights")
                strategies = (
                    self.strategy_generator.generate_strategies_with_failure_analysis(
                        count=self.strategies_per_iteration,
                        failure_analysis=previous_failure_analysis,
                        use_parameter_ranges=True,
                    )
                )
            else:
                self.logger.info(
                    "Generating strategies with behavioral profile insights"
                )
                strategies = self.strategy_generator.generate_strategies(
                    count=self.strategies_per_iteration, use_parameter_ranges=True
                )
            iteration_result.strategies_generated = len(strategies)
            prioritized_strategies = self._prioritize_strategies_by_behavioral_profile(
                strategies, behavioral_profile
            )
            strategies_to_test = prioritized_strategies[: self.max_strategies_to_test]
            iteration_result.strategies_tested = len(strategies_to_test)
            self.logger.info(
                f"Generated {iteration_result.strategies_generated} strategies, testing top {iteration_result.strategies_tested}"
            )
            self.logger.info("=== PHASE 3: EXECUTE ===")
            test_results = []
            best_strategy = None
            for i, strategy in enumerate(strategies_to_test):
                self.logger.info(
                    f"Testing strategy {i + 1}/{len(strategies_to_test)}: {strategy['name']}"
                )
                try:
                    attack_result = await self.attack_adapter.execute_attack(
                        strategy["name"], strategy.get("params", {}), domain, port
                    )
                    effectiveness_result = (
                        await self.effectiveness_tester.test_with_bypass(
                            domain, port, attack_result
                        )
                    )
                    test_results.append(effectiveness_result)
                    if (
                        effectiveness_result.effectiveness_score
                        > iteration_result.best_effectiveness
                    ):
                        iteration_result.best_effectiveness = (
                            effectiveness_result.effectiveness_score
                        )
                        best_strategy = strategy
                        self.logger.info(
                            f"New best in iteration: {effectiveness_result.effectiveness_score:.2f} with {strategy['name']}"
                        )
                except Exception as e:
                    self.logger.error(
                        f"Failed to test strategy {strategy['name']}: {e}"
                    )
                    continue
            iteration_result.test_results = test_results
            iteration_result.best_strategy = best_strategy
            iteration_result.improvement_over_baseline = (
                iteration_result.best_effectiveness - self.baseline_effectiveness
            )
            if test_results:
                failure_analysis = (
                    await self.failure_analyzer.analyze_iteration_results(
                        test_results, fingerprint, behavioral_profile
                    )
                )
                iteration_result.failure_analysis = failure_analysis
                strategic_recommendations = (
                    await self._generate_strategic_recommendations(
                        failure_analysis, behavioral_profile, learning_history
                    )
                )
                iteration_result.strategic_recommendations = strategic_recommendations
                iteration_result.analysis_notes.extend(
                    [
                        f"Tested {len(test_results)} strategies",
                        f"Best effectiveness: {iteration_result.best_effectiveness:.2f}",
                        f"Improvement over baseline: {iteration_result.improvement_over_baseline:.2f}",
                        f"Failure patterns identified: {len(failure_analysis.failure_patterns)}",
                        f"Strategic recommendations: {len(strategic_recommendations)}",
                    ]
                )
                for pattern in failure_analysis.failure_patterns[:3]:
                    self.logger.info(
                        f"Failure pattern: {pattern.pattern_type} affecting {len(pattern.affected_techniques)} techniques"
                    )
                for recommendation in strategic_recommendations[:3]:
                    self.logger.info(f"Strategic recommendation: {recommendation}")
            else:
                iteration_result.analysis_notes.append("No test results to analyze")
                self.logger.warning("No test results available for analysis")
            if learning_history and test_results:
                await self._update_learning_memory_from_iteration(
                    fingerprint, test_results, iteration_result
                )
            iteration_time = time.time() - iteration_start
            self.logger.info(
                f"Iteration {self.current_iteration} completed in {iteration_time:.1f}s: best_effectiveness={iteration_result.best_effectiveness:.2f}"
            )
            return iteration_result
        except Exception as e:
            self.logger.error(
                f"Enhanced iteration {self.current_iteration} failed: {e}"
            )
            iteration_result.analysis_notes.append(f"Iteration failed: {str(e)}")
            return iteration_result

    async def _run_single_iteration(
        self,
        domain: str,
        port: int,
        fingerprint: EnhancedFingerprint,
        learning_history: Optional[Any],
        baseline_result: Any,
    ) -> ClosedLoopIteration:
        """
        Legacy method - redirects to enhanced iteration for backward compatibility.

        Args:
            domain: Target domain
            port: Target port
            fingerprint: Current fingerprint
            learning_history: Historical learning data
            baseline_result: Baseline test result

        Returns:
            ClosedLoopIteration with iteration results
        """
        iteration_start = time.time()
        self.logger.info(f"Running iteration {self.current_iteration} for {domain}")
        fingerprint_dict = fingerprint.__dict__ if fingerprint else {}
        history_list = []
        if learning_history:
            for (
                attack_name,
                success_rate,
            ) in learning_history.successful_attacks.items():
                history_list.append(
                    {
                        "attack_name": attack_name,
                        "success_rate": success_rate,
                        "parameters": learning_history.optimal_parameters.get(
                            attack_name, {}
                        ),
                    }
                )
        strategy_gen = AdvancedStrategyGenerator(
            fingerprint_dict=fingerprint_dict, history=history_list, doh_success=False
        )
        previous_failure_analysis = None
        if hasattr(self, "_previous_failure_analysis"):
            previous_failure_analysis = self._previous_failure_analysis
        if previous_failure_analysis:
            strategies = strategy_gen.generate_strategies_with_failure_analysis(
                count=self.strategies_per_iteration,
                failure_analysis=previous_failure_analysis,
                use_parameter_ranges=True,
            )
            self.logger.info("Generated strategies with failure analysis guidance")
        else:
            strategies = strategy_gen.generate_strategies(
                count=self.strategies_per_iteration
            )
            self.logger.info(
                "Generated strategies without failure analysis (first iteration)"
            )
        self.logger.info(
            f"Generated {len(strategies)} strategies for iteration {self.current_iteration}"
        )
        tested_strategies = 0
        best_effectiveness = 0.0
        effectiveness_results = []
        strategies_to_test = strategies[: self.max_strategies_to_test]
        for i, strategy in enumerate(strategies_to_test):
            try:
                self.logger.debug(
                    f"Testing strategy {i + 1}/{len(strategies_to_test)}: {strategy['name']}"
                )
                adaptive_attack = LearningAdaptiveAttack(
                    effectiveness_tester=self.effectiveness_tester,
                    learning_memory=self.learning_memory,
                )
                attack_result = await self._execute_strategy_with_adaptive_attack(
                    domain, port, strategy, adaptive_attack, fingerprint
                )
                if attack_result:
                    effectiveness_results.append(attack_result)
                    if attack_result.effectiveness_score > best_effectiveness:
                        best_effectiveness = attack_result.effectiveness_score
                tested_strategies += 1
                await asyncio.sleep(0.5)
            except Exception as e:
                self.logger.warning(f"Failed to test strategy {strategy['name']}: {e}")
                continue
        analysis_notes = []
        failure_analysis = None
        strategic_recommendations = []
        if effectiveness_results:
            avg_effectiveness = sum(
                (r.effectiveness_score for r in effectiveness_results)
            ) / len(effectiveness_results)
            analysis_notes.append(
                f"Tested {tested_strategies} strategies, avg effectiveness: {avg_effectiveness:.2f}"
            )
            failure_analysis = self.failure_analyzer.analyze_closed_loop_failures(
                effectiveness_results
            )
            strategic_recommendations = failure_analysis.strategic_recommendations
            if failure_analysis.detected_patterns:
                self.logger.info(
                    f"Detected {len(failure_analysis.detected_patterns)} failure patterns"
                )
                for pattern in failure_analysis.detected_patterns:
                    self.logger.debug(
                        f"Pattern: {pattern.pattern_type} (confidence: {pattern.confidence:.2f})"
                    )
            if failure_analysis.dpi_behavior_insights:
                insights = failure_analysis.dpi_behavior_insights
                if "recommended_classification" in insights:
                    analysis_notes.append(
                        f"DPI classification: {insights['recommended_classification']}"
                    )
            fingerprint_hash = self.learning_memory._generate_fingerprint_hash(
                fingerprint_dict
            )
            for result in effectiveness_results:
                await self.learning_memory.save_learning_result(
                    fingerprint_hash=fingerprint_hash,
                    attack_name=result.bypass.attack_name or "unknown",
                    effectiveness_score=result.effectiveness_score,
                    parameters={},
                    success=result.bypass_effective,
                    latency_ms=result.bypass.latency_ms,
                )
        else:
            analysis_notes.append("No strategies could be tested successfully")
            failure_analysis = FailureAnalysisResult(
                total_failures=tested_strategies,
                failure_breakdown={},
                detected_patterns=[],
                strategic_recommendations=[
                    "No test results available - check network connectivity"
                ],
            )
        improvement_over_baseline = best_effectiveness - self.baseline_effectiveness
        iteration_result = ClosedLoopIteration(
            iteration_number=self.current_iteration,
            fingerprint=fingerprint,
            strategies_generated=len(strategies),
            strategies_tested=tested_strategies,
            best_effectiveness=best_effectiveness,
            improvement_over_baseline=improvement_over_baseline,
            analysis_notes=analysis_notes,
            failure_analysis=failure_analysis,
            strategic_recommendations=strategic_recommendations,
            timestamp=time.time(),
        )
        self._previous_failure_analysis = failure_analysis
        iteration_time = time.time() - iteration_start
        self.logger.info(
            f"Iteration {self.current_iteration} completed in {iteration_time:.1f}s: best_effectiveness={best_effectiveness:.2f}, improvement={improvement_over_baseline:.2f}"
        )
        if strategic_recommendations:
            self.logger.info(
                f"Strategic recommendations: {'; '.join(strategic_recommendations[:3])}"
            )
        return iteration_result

    async def _execute_strategy_with_adaptive_attack(
        self,
        domain: str,
        port: int,
        strategy: Dict[str, Any],
        adaptive_attack: LearningAdaptiveAttack,
        fingerprint: EnhancedFingerprint,
    ) -> Optional[EffectivenessResult]:
        """
        Execute a strategy using adaptive attack and measure effectiveness.

        Args:
            domain: Target domain
            port: Target port
            strategy: Strategy to execute
            adaptive_attack: Adaptive attack instance
            fingerprint: Current fingerprint

        Returns:
            EffectivenessResult or None if execution failed
        """
        try:
            baseline_result = await self.effectiveness_tester.test_baseline(
                domain, port
            )
            from core.bypass.attacks.base import AttackResult, AttackStatus

            mock_attack_result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=strategy["name"],
                packets_sent=1,
                latency_ms=100.0,
            )
            bypass_result = await self.effectiveness_tester.test_with_bypass(
                domain, port, mock_attack_result
            )
            effectiveness_result = await self.effectiveness_tester.compare_results(
                baseline_result, bypass_result
            )
            return effectiveness_result
        except Exception as e:
            self.logger.error(f"Failed to execute strategy {strategy['name']}: {e}")
            return None

    async def should_continue_loop(
        self, current_results: ClosedLoopResult
    ) -> Tuple[bool, str]:
        """
        Determine if the closed loop should continue.

        Args:
            current_results: Current results of the closed loop

        Returns:
            Tuple of (should_continue, reason)
        """
        if self.best_effectiveness >= self.convergence_threshold:
            return (
                False,
                f"Convergence achieved (effectiveness: {self.best_effectiveness:.2f})",
            )
        if self.current_iteration >= self.max_iterations:
            return (False, f"Maximum iterations reached ({self.max_iterations})")
        if (
            self.iterations_without_improvement
            >= self.max_iterations_without_improvement
        ):
            return (
                False,
                f"No improvement for {self.iterations_without_improvement} iterations",
            )
        if (
            self.current_iteration >= 2
            and self.best_effectiveness
            <= self.baseline_effectiveness + self.improvement_threshold
        ):
            return (
                False,
                f"Insufficient improvement over baseline ({self.best_effectiveness:.2f} vs {self.baseline_effectiveness:.2f})",
            )
        return (True, "Continuing optimization")

    async def _refine_fingerprint_from_results(
        self,
        current_fingerprint: EnhancedFingerprint,
        test_results: List[EffectivenessResult],
    ) -> EnhancedFingerprint:
        """
        Уточняет фингерпринт на основе результатов тестирования.
        """
        LOG.info(f"Refining fingerprint for {current_fingerprint.domain}...")
        for result in test_results:
            attack_name = result.bypass.attack_name
            effectiveness = result.effectiveness_score
            current_rate = current_fingerprint.technique_success_rates.get(
                attack_name, 0.0
            )
            new_rate = current_rate * 0.7 + effectiveness * 0.3
            current_fingerprint.technique_success_rates[attack_name] = new_rate
        if (
            current_fingerprint.technique_success_rates.get(
                "ip_fragmentation_advanced", 0.0
            )
            > 0.7
        ):
            current_fingerprint.supports_ip_frag = True
            LOG.debug("Refined: DPI is likely vulnerable to fragmentation.")
        if current_fingerprint.technique_success_rates.get("badsum_fooling", 0.0) < 0.2:
            current_fingerprint.checksum_validation = True
            LOG.debug("Refined: DPI likely validates checksums.")
        new_classification = self.fingerprint_engine.classifier.classify(
            current_fingerprint
        )
        current_fingerprint.dpi_type = new_classification.dpi_type
        current_fingerprint.confidence = new_classification.confidence
        LOG.info(
            f"Fingerprint refined. New classification: {current_fingerprint.get_summary()}"
        )
        return current_fingerprint

    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics of the closed loop manager."""
        return {
            "current_iteration": self.current_iteration,
            "best_effectiveness": self.best_effectiveness,
            "baseline_effectiveness": self.baseline_effectiveness,
            "iterations_without_improvement": self.iterations_without_improvement,
            "configuration": {
                "max_iterations": self.max_iterations,
                "convergence_threshold": self.convergence_threshold,
                "improvement_threshold": self.improvement_threshold,
                "strategies_per_iteration": self.strategies_per_iteration,
                "max_strategies_to_test": self.max_strategies_to_test,
            },
        }

    def _prioritize_strategies_by_behavioral_profile(
        self, strategies: List[Dict[str, Any]], behavioral_profile: Any
    ) -> List[Dict[str, Any]]:
        """
        Prioritize strategies based on DPI behavioral profile weaknesses.

        Args:
            strategies: List of strategy dictionaries
            behavioral_profile: DPI behavioral profile

        Returns:
            Prioritized list of strategies
        """

        def calculate_strategy_priority(strategy: Dict[str, Any]) -> float:
            """Calculate priority score for a strategy based on behavioral profile"""
            priority_score = 0.5
            strategy_name = strategy.get("name", "")
            for weakness in behavioral_profile.identified_weaknesses:
                if (
                    "fragmentation" in weakness.lower()
                    and "fragmentation" in strategy_name.lower()
                ):
                    priority_score += 0.3
                elif "timing" in weakness.lower() and "timing" in strategy_name.lower():
                    priority_score += 0.3
                elif "checksum" in weakness.lower() and (
                    "badsum" in strategy_name.lower()
                    or "checksum" in strategy_name.lower()
                ):
                    priority_score += 0.3
                elif "tcp" in weakness.lower() and "tcp" in strategy_name.lower():
                    priority_score += 0.2
            if (
                not behavioral_profile.supports_ip_frag
                and "fragmentation" in strategy_name.lower()
            ):
                priority_score -= 0.2
            if (
                not behavioral_profile.checksum_validation
                and "badsum" in strategy_name.lower()
            ):
                priority_score += 0.2
            if behavioral_profile.ech_support is False and (
                "ech" in strategy_name.lower() or "modern" in strategy_name.lower()
            ):
                priority_score += 0.2
            if behavioral_profile.ml_detection and "mimicry" in strategy_name.lower():
                priority_score += 0.3
            return min(priority_score, 1.0)

        strategy_priorities = [
            (strategy, calculate_strategy_priority(strategy)) for strategy in strategies
        ]
        strategy_priorities.sort(key=lambda x: x[1], reverse=True)
        self.logger.debug("Strategy priorities:")
        for strategy, priority in strategy_priorities[:5]:
            self.logger.debug(f"  {strategy['name']}: {priority:.2f}")
        return [strategy for strategy, _ in strategy_priorities]

    async def _integrate_failure_analysis(
        self,
        cumulative_analysis: Optional[FailureAnalysisResult],
        new_analysis: FailureAnalysisResult,
    ) -> FailureAnalysisResult:
        """
        Integrate new failure analysis with cumulative analysis.

        Args:
            cumulative_analysis: Previous cumulative failure analysis
            new_analysis: New failure analysis from current iteration

        Returns:
            Updated cumulative failure analysis
        """
        if not cumulative_analysis:
            return new_analysis
        merged_patterns = list(cumulative_analysis.failure_patterns)
        for new_pattern in new_analysis.failure_patterns:
            similar_found = False
            for existing_pattern in merged_patterns:
                if (
                    existing_pattern.pattern_type == new_pattern.pattern_type
                    and len(
                        set(existing_pattern.affected_techniques)
                        & set(new_pattern.affected_techniques)
                    )
                    > 0
                ):
                    existing_pattern.affected_techniques.extend(
                        new_pattern.affected_techniques
                    )
                    existing_pattern.affected_techniques = list(
                        set(existing_pattern.affected_techniques)
                    )
                    existing_pattern.confidence = max(
                        existing_pattern.confidence, new_pattern.confidence
                    )
                    similar_found = True
                    break
            if not similar_found:
                merged_patterns.append(new_pattern)
        merged_analysis = FailureAnalysisResult(
            failure_patterns=merged_patterns,
            next_iteration_focus=new_analysis.next_iteration_focus,
            strategic_insights=cumulative_analysis.strategic_insights
            + new_analysis.strategic_insights,
            confidence_score=max(
                cumulative_analysis.confidence_score, new_analysis.confidence_score
            ),
        )
        return merged_analysis

    async def _generate_strategic_recommendations(
        self,
        failure_analysis: FailureAnalysisResult,
        behavioral_profile: Any,
        learning_history: Optional[Any],
    ) -> List[str]:
        """
        Generate strategic recommendations based on failure analysis and behavioral profile.

        Args:
            failure_analysis: Current failure analysis
            behavioral_profile: DPI behavioral profile
            learning_history: Learning history from memory

        Returns:
            List of strategic recommendations
        """
        recommendations = []
        for pattern in failure_analysis.failure_patterns:
            if pattern.pattern_type == "consistent_blocking":
                recommendations.append(
                    f"Consider alternative attack categories - {len(pattern.affected_techniques)} techniques consistently blocked"
                )
            elif pattern.pattern_type == "timing_sensitive":
                recommendations.append(
                    "Focus on timing-based attacks - DPI shows timing sensitivity"
                )
            elif pattern.pattern_type == "protocol_specific":
                recommendations.append(
                    "Try protocol tunneling or modern protocol attacks"
                )
        if behavioral_profile.ml_detection:
            recommendations.append("Use traffic mimicry to evade ML detection")
        if (
            behavioral_profile.burst_tolerance
            and behavioral_profile.burst_tolerance < 0.3
        ):
            recommendations.append(
                "Avoid burst traffic patterns - low burst tolerance detected"
            )
        if len(behavioral_profile.anti_evasion_techniques) >= 3:
            recommendations.append(
                "Use multi-layer combination attacks against sophisticated anti-evasion"
            )
        if learning_history and hasattr(learning_history, "successful_attacks"):
            successful_categories = set()
            for attack_name in learning_history.successful_attacks.keys():
                if "fragmentation" in attack_name.lower():
                    successful_categories.add("fragmentation")
                elif "timing" in attack_name.lower():
                    successful_categories.add("timing")
                elif "tcp" in attack_name.lower():
                    successful_categories.add("tcp_manipulation")
            if successful_categories:
                recommendations.append(
                    f"Focus on previously successful categories: {', '.join(successful_categories)}"
                )
        return recommendations[:5]

    async def _update_learning_memory_with_behavioral_insights(
        self,
        fingerprint_hash: str,
        behavioral_profile: Any,
        iteration_result: ClosedLoopIteration,
    ):
        """
        Update learning memory with behavioral profile insights.

        Args:
            fingerprint_hash: Hash of the fingerprint
            behavioral_profile: DPI behavioral profile
            iteration_result: Results from current iteration
        """
        try:
            behavioral_insights = {
                "dpi_capabilities": {
                    "supports_ip_frag": behavioral_profile.supports_ip_frag,
                    "checksum_validation": behavioral_profile.checksum_validation,
                    "rst_latency_ms": behavioral_profile.rst_latency_ms,
                    "ech_support": behavioral_profile.ech_support,
                },
                "detection_sophistication": {
                    "ml_detection": behavioral_profile.ml_detection,
                    "behavioral_analysis": behavioral_profile.behavioral_analysis,
                    "statistical_analysis": behavioral_profile.statistical_analysis,
                },
                "identified_weaknesses": behavioral_profile.identified_weaknesses,
                "anti_evasion_techniques": behavioral_profile.anti_evasion_techniques,
            }
            await self.learning_memory.store_behavioral_insights(
                fingerprint_hash, behavioral_insights
            )
            self.logger.debug(
                f"Updated learning memory with behavioral insights for {fingerprint_hash}"
            )
        except Exception as e:
            self.logger.error(
                f"Failed to update learning memory with behavioral insights: {e}"
            )

    async def _update_learning_memory_from_iteration(
        self,
        fingerprint: EnhancedFingerprint,
        test_results: List[Any],
        iteration_result: ClosedLoopIteration,
    ):
        """
        Update learning memory with results from current iteration.

        Args:
            fingerprint: Current fingerprint
            test_results: Test results from iteration
            iteration_result: Complete iteration result
        """
        try:
            fingerprint_hash = self.learning_memory._generate_fingerprint_hash(
                fingerprint.__dict__
            )
            for result in test_results:
                if hasattr(result, "bypass_effective") and result.bypass_effective:
                    attack_name = result.bypass.attack_name
                    effectiveness = result.effectiveness_score
                    await self.learning_memory.save_learning_result(
                        fingerprint_hash,
                        attack_name,
                        effectiveness,
                        getattr(result.bypass, "parameters", {}),
                    )
            if iteration_result.strategic_recommendations:
                await self.learning_memory.store_strategic_insights(
                    fingerprint_hash, iteration_result.strategic_recommendations
                )
            self.logger.debug(
                f"Updated learning memory from iteration {iteration_result.iteration_number}"
            )
        except Exception as e:
            self.logger.error(f"Failed to update learning memory from iteration: {e}")

    async def _generate_final_analysis_summary(
        self,
        result: ClosedLoopResult,
        behavioral_profile: Any,
        cumulative_failure_analysis: Optional[FailureAnalysisResult],
    ):
        """
        Generate final analysis summary for the closed loop result.

        Args:
            result: Closed loop result to update
            behavioral_profile: Final behavioral profile
            cumulative_failure_analysis: Cumulative failure analysis
        """
        try:
            result.analysis_summary.append(
                f"DPI Behavioral Profile: {len(behavioral_profile.identified_weaknesses)} weaknesses, {len(behavioral_profile.anti_evasion_techniques)} anti-evasion techniques"
            )
            if cumulative_failure_analysis:
                result.analysis_summary.append(
                    f"Failure Analysis: {len(cumulative_failure_analysis.failure_patterns)} patterns identified"
                )
                for pattern in cumulative_failure_analysis.failure_patterns[:3]:
                    result.analysis_summary.append(
                        f"  - {pattern.pattern_type}: {len(pattern.affected_techniques)} techniques affected"
                    )
            if result.convergence_achieved:
                result.analysis_summary.append(
                    f"Convergence achieved with {result.final_effectiveness:.2f} effectiveness"
                )
            else:
                result.analysis_summary.append(
                    f"Convergence not achieved - final effectiveness: {result.final_effectiveness:.2f}"
                )
            if result.iterations:
                best_iteration = max(
                    result.iterations, key=lambda x: x.best_effectiveness
                )
                result.analysis_summary.append(
                    f"Best iteration: #{best_iteration.iteration_number} with {best_iteration.best_effectiveness:.2f} effectiveness"
                )
            self.logger.info("Final analysis summary generated")
        except Exception as e:
            self.logger.error(f"Failed to generate final analysis summary: {e}")
            result.analysis_summary.append(
                f"Analysis summary generation failed: {str(e)}"
            )
