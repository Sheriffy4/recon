#!/usr/bin/env python3
"""
Segment-based Attack Workflow Integration.

This module integrates segment-based attacks with existing workflow systems,
providing enhanced monitoring, optimization, and closed-loop feedback.
"""

import asyncio
import time
import json
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

# Core imports
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.integration.attack_adapter import AttackAdapter
from core.bypass.monitoring.segment_execution_stats import (
    SegmentExecutionStatsCollector,
)
from core.bypass.performance.segment_performance_optimizer import (
    SegmentPerformanceOptimizer,
    OptimizationConfig,
)
from core.cli_workflow_optimizer import WorkflowOptimizer
from core.integration.closed_loop_manager import ClosedLoopManager


class WorkflowExecutionMode(Enum):
    """Workflow execution modes."""

    SINGLE_SHOT = "single_shot"
    CONTINUOUS = "continuous"
    ADAPTIVE = "adaptive"
    BENCHMARK = "benchmark"


@dataclass
class SegmentWorkflowConfig:
    """Configuration for segment-based workflow execution."""

    # Execution settings
    execution_mode: WorkflowExecutionMode = WorkflowExecutionMode.SINGLE_SHOT
    max_concurrent_attacks: int = 5
    execution_timeout_seconds: int = 300
    retry_attempts: int = 3

    # Performance optimization
    enable_performance_optimization: bool = True
    optimization_config: OptimizationConfig = field(
        default_factory=lambda: OptimizationConfig()
    )

    # Monitoring and statistics
    enable_detailed_monitoring: bool = True
    statistics_collection_interval: int = 10
    enable_real_time_feedback: bool = True

    # Workflow integration
    enable_closed_loop_optimization: bool = True
    effectiveness_threshold: float = 0.7
    performance_threshold_ms: float = 100.0

    # Reporting
    enable_workflow_reporting: bool = True
    report_output_directory: str = "workflow_reports"
    save_execution_logs: bool = True


@dataclass
class WorkflowExecutionResult:
    """Result of workflow execution."""

    workflow_id: str
    execution_mode: WorkflowExecutionMode
    start_time: float
    end_time: float
    total_duration: float

    # Execution statistics
    attacks_executed: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    success_rate: float = 0.0

    # Performance metrics
    average_execution_time_ms: float = 0.0
    total_segments_executed: int = 0
    total_bytes_transmitted: int = 0

    # Effectiveness metrics
    average_effectiveness_score: float = 0.0
    effectiveness_scores: List[float] = field(default_factory=list)

    # Optimization results
    optimization_applied: bool = False
    performance_improvements: Dict[str, float] = field(default_factory=dict)

    # Issues and recommendations
    issues_encountered: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Raw data
    execution_details: List[Dict[str, Any]] = field(default_factory=list)


class SegmentWorkflowIntegration:
    """Integration layer for segment-based attacks with workflow systems."""

    def __init__(self, config: SegmentWorkflowConfig):
        self.config = config
        self.workflow_id = f"segment_workflow_{int(time.time())}"

        # Core components
        self.attack_adapter = AttackAdapter()
        self.stats_collector = SegmentExecutionStatsCollector()
        self.performance_optimizer = None
        self.workflow_optimizer = WorkflowOptimizer()
        self.closed_loop_manager = None

        # Execution state
        self.active_executions: Dict[str, Dict[str, Any]] = {}
        self.execution_history: List[Dict[str, Any]] = []
        self.workflow_metrics: Dict[str, Any] = {}

        # Initialize components based on configuration
        self._initialize_components()

    def _initialize_components(self):
        """Initialize workflow components based on configuration."""

        # Initialize performance optimizer
        if self.config.enable_performance_optimization:
            self.performance_optimizer = SegmentPerformanceOptimizer(
                self.config.optimization_config
            )

        # Initialize closed-loop manager
        if self.config.enable_closed_loop_optimization:
            self.closed_loop_manager = ClosedLoopManager()

    async def execute_workflow(
        self,
        attack_scenarios: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> WorkflowExecutionResult:
        """Execute segment-based attack workflow."""

        print(f"🚀 Starting segment workflow execution (ID: {self.workflow_id})")
        print(f"   Mode: {self.config.execution_mode.value}")
        print(f"   Scenarios: {len(attack_scenarios)}")

        # Initialize workflow result
        result = WorkflowExecutionResult(
            workflow_id=self.workflow_id,
            execution_mode=self.config.execution_mode,
            start_time=time.time(),
            end_time=0,
            total_duration=0,
        )

        try:
            # Execute based on mode
            if self.config.execution_mode == WorkflowExecutionMode.SINGLE_SHOT:
                await self._execute_single_shot(
                    attack_scenarios, result, progress_callback
                )
            elif self.config.execution_mode == WorkflowExecutionMode.CONTINUOUS:
                await self._execute_continuous(
                    attack_scenarios, result, progress_callback
                )
            elif self.config.execution_mode == WorkflowExecutionMode.ADAPTIVE:
                await self._execute_adaptive(
                    attack_scenarios, result, progress_callback
                )
            elif self.config.execution_mode == WorkflowExecutionMode.BENCHMARK:
                await self._execute_benchmark(
                    attack_scenarios, result, progress_callback
                )

            # Finalize results
            result.end_time = time.time()
            result.total_duration = result.end_time - result.start_time

            # Calculate final metrics
            self._calculate_final_metrics(result)

            # Generate recommendations
            self._generate_recommendations(result)

            # Save workflow report
            if self.config.enable_workflow_reporting:
                await self._save_workflow_report(result)

            print("✅ Workflow execution completed successfully")
            print(f"   Duration: {result.total_duration:.2f}s")
            print(f"   Success Rate: {result.success_rate:.1%}")
            print(f"   Average Effectiveness: {result.average_effectiveness_score:.1%}")

            return result

        except Exception as e:
            result.end_time = time.time()
            result.total_duration = result.end_time - result.start_time
            result.issues_encountered.append(f"Workflow execution error: {str(e)}")

            print(f"❌ Workflow execution failed: {e}")
            return result

        finally:
            # Cleanup resources
            await self._cleanup_workflow_resources()

    async def _execute_single_shot(
        self,
        attack_scenarios: List[Dict[str, Any]],
        result: WorkflowExecutionResult,
        progress_callback: Optional[Callable],
    ):
        """Execute attacks in single-shot mode."""

        print("📋 Executing single-shot workflow")

        # Execute scenarios sequentially or concurrently based on config
        if self.config.max_concurrent_attacks > 1:
            await self._execute_concurrent_scenarios(
                attack_scenarios, result, progress_callback
            )
        else:
            await self._execute_sequential_scenarios(
                attack_scenarios, result, progress_callback
            )

    async def _execute_continuous(
        self,
        attack_scenarios: List[Dict[str, Any]],
        result: WorkflowExecutionResult,
        progress_callback: Optional[Callable],
    ):
        """Execute attacks in continuous mode."""

        print("🔄 Executing continuous workflow")

        # Continuous execution with monitoring
        start_time = time.time()
        iteration = 0

        while time.time() - start_time < self.config.execution_timeout_seconds:
            iteration += 1
            print(f"   Iteration {iteration}")

            # Execute scenarios
            await self._execute_sequential_scenarios(
                attack_scenarios, result, progress_callback
            )

            # Check for optimization opportunities
            if self.config.enable_closed_loop_optimization and iteration % 5 == 0:
                await self._apply_closed_loop_optimization(result)

            # Brief pause between iterations
            await asyncio.sleep(1)

    async def _execute_adaptive(
        self,
        attack_scenarios: List[Dict[str, Any]],
        result: WorkflowExecutionResult,
        progress_callback: Optional[Callable],
    ):
        """Execute attacks in adaptive mode with real-time optimization."""

        print("🧠 Executing adaptive workflow")

        # Adaptive execution with real-time feedback
        for i, scenario in enumerate(attack_scenarios):
            print(f"   Executing scenario {i+1}/{len(attack_scenarios)}")

            # Execute scenario
            execution_result = await self._execute_single_scenario(scenario, result)

            # Analyze results and adapt
            if self.config.enable_real_time_feedback:
                adaptations = await self._analyze_and_adapt(execution_result, scenario)

                if adaptations:
                    print(f"   Applied {len(adaptations)} adaptations")
                    # Apply adaptations to remaining scenarios
                    self._apply_adaptations_to_scenarios(
                        adaptations, attack_scenarios[i + 1 :]
                    )

            # Progress callback
            if progress_callback:
                progress_callback(
                    {
                        "scenario_index": i,
                        "total_scenarios": len(attack_scenarios),
                        "current_result": execution_result,
                    }
                )

    async def _execute_benchmark(
        self,
        attack_scenarios: List[Dict[str, Any]],
        result: WorkflowExecutionResult,
        progress_callback: Optional[Callable],
    ):
        """Execute attacks in benchmark mode."""

        print("📊 Executing benchmark workflow")

        # Benchmark execution with detailed metrics
        benchmark_iterations = 10

        for iteration in range(benchmark_iterations):
            print(f"   Benchmark iteration {iteration+1}/{benchmark_iterations}")

            iteration_start = time.time()

            # Execute all scenarios
            await self._execute_sequential_scenarios(
                attack_scenarios, result, progress_callback
            )

            iteration_duration = time.time() - iteration_start

            # Record benchmark metrics
            self.workflow_metrics[f"iteration_{iteration}"] = {
                "duration": iteration_duration,
                "scenarios_executed": len(attack_scenarios),
                "timestamp": time.time(),
            }

    async def _execute_sequential_scenarios(
        self,
        attack_scenarios: List[Dict[str, Any]],
        result: WorkflowExecutionResult,
        progress_callback: Optional[Callable],
    ):
        """Execute scenarios sequentially."""

        for i, scenario in enumerate(attack_scenarios):
            execution_result = await self._execute_single_scenario(scenario, result)

            if progress_callback:
                progress_callback(
                    {
                        "scenario_index": i,
                        "total_scenarios": len(attack_scenarios),
                        "current_result": execution_result,
                    }
                )

    async def _execute_concurrent_scenarios(
        self,
        attack_scenarios: List[Dict[str, Any]],
        result: WorkflowExecutionResult,
        progress_callback: Optional[Callable],
    ):
        """Execute scenarios concurrently."""

        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.config.max_concurrent_attacks)

        async def execute_with_semaphore(scenario, index):
            async with semaphore:
                return await self._execute_single_scenario(scenario, result), index

        # Execute scenarios concurrently
        tasks = [
            execute_with_semaphore(scenario, i)
            for i, scenario in enumerate(attack_scenarios)
        ]

        completed_tasks = 0
        for task in asyncio.as_completed(tasks):
            execution_result, index = await task
            completed_tasks += 1

            if progress_callback:
                progress_callback(
                    {
                        "scenario_index": index,
                        "total_scenarios": len(attack_scenarios),
                        "completed_scenarios": completed_tasks,
                        "current_result": execution_result,
                    }
                )

    async def _execute_single_scenario(
        self, scenario: Dict[str, Any], result: WorkflowExecutionResult
    ) -> Dict[str, Any]:
        """Execute a single attack scenario."""

        scenario_id = f"scenario_{int(time.time() * 1000)}"
        execution_start = time.time()

        try:
            # Extract scenario parameters
            attack_type = scenario.get("attack_type")
            target = scenario.get("target", "127.0.0.1")
            port = scenario.get("port", 80)
            payload = scenario.get("payload", b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            params = scenario.get("params", {})

            # Create attack context
            context = AttackContext(
                dst_ip=target,
                dst_port=port,
                payload=payload if isinstance(payload, bytes) else payload.encode(),
                connection_id=scenario_id,
                params=params,
            )

            # Start statistics collection
            self.stats_collector.start_execution(attack_type, scenario_id)

            # Execute attack through adapter
            attack_result = await self.attack_adapter.execute_attack_by_name(
                attack_name=attack_type, context=context
            )

            execution_time = time.time() - execution_start

            # Record execution result
            self.stats_collector.record_execution_result(
                attack_type,
                scenario_id,
                attack_result.status == AttackStatus.SUCCESS,
                execution_time,
            )

            # Update workflow result
            result.attacks_executed += 1
            if attack_result.status == AttackStatus.SUCCESS:
                result.successful_attacks += 1

                # Estimate effectiveness
                effectiveness = self._estimate_attack_effectiveness(
                    attack_result, context
                )
                result.effectiveness_scores.append(effectiveness)
            else:
                result.failed_attacks += 1
                result.issues_encountered.append(
                    f"Attack {attack_type} failed: {attack_result.error}"
                )

            # Collect segment statistics
            if attack_result.segments:
                result.total_segments_executed += len(attack_result.segments)
                result.total_bytes_transmitted += sum(
                    len(seg[0]) for seg in attack_result.segments
                )

            # Create execution detail record
            execution_detail = {
                "scenario_id": scenario_id,
                "attack_type": attack_type,
                "target": f"{target}:{port}",
                "execution_time_ms": execution_time * 1000,
                "status": attack_result.status.value,
                "technique_used": attack_result.technique_used,
                "packets_sent": attack_result.packets_sent,
                "bytes_sent": attack_result.bytes_sent,
                "segments_count": (
                    len(attack_result.segments) if attack_result.segments else 0
                ),
                "effectiveness_score": (
                    effectiveness if attack_result.status == AttackStatus.SUCCESS else 0
                ),
                "timestamp": time.time(),
            }

            result.execution_details.append(execution_detail)

            return execution_detail

        except Exception as e:
            execution_time = time.time() - execution_start

            # Record failure
            result.attacks_executed += 1
            result.failed_attacks += 1
            result.issues_encountered.append(f"Scenario execution error: {str(e)}")

            execution_detail = {
                "scenario_id": scenario_id,
                "attack_type": scenario.get("attack_type", "unknown"),
                "execution_time_ms": execution_time * 1000,
                "status": "ERROR",
                "error": str(e),
                "timestamp": time.time(),
            }

            result.execution_details.append(execution_detail)

            return execution_detail

    def _estimate_attack_effectiveness(
        self, attack_result, context: AttackContext
    ) -> float:
        """Estimate attack effectiveness based on result and context."""

        # Basic effectiveness estimation
        base_effectiveness = 0.5

        # Bonus for successful execution
        if attack_result.status == AttackStatus.SUCCESS:
            base_effectiveness += 0.3

        # Bonus for segment-based attacks
        if attack_result.segments:
            base_effectiveness += 0.2

            # Additional bonus for complex scenarios
            if len(attack_result.segments) > 2:
                base_effectiveness += 0.1

            # Bonus for timing manipulation
            has_timing = any("delay_ms" in seg[2] for seg in attack_result.segments)
            if has_timing:
                base_effectiveness += 0.1

            # Bonus for TTL manipulation
            has_ttl = any("ttl" in seg[2] for seg in attack_result.segments)
            if has_ttl:
                base_effectiveness += 0.1

        return min(1.0, base_effectiveness)

    async def _apply_closed_loop_optimization(self, result: WorkflowExecutionResult):
        """Apply closed-loop optimization based on execution results."""

        if not self.closed_loop_manager:
            return

        print("🔄 Applying closed-loop optimization")

        # Analyze current performance
        current_metrics = {
            "success_rate": result.success_rate,
            "average_effectiveness": result.average_effectiveness_score,
            "average_execution_time": result.average_execution_time_ms,
        }

        # Get optimization recommendations
        optimizations = await self.closed_loop_manager.analyze_and_optimize(
            current_metrics, result.execution_details
        )

        if optimizations:
            print(f"   Applied {len(optimizations)} optimizations")
            result.optimization_applied = True

            # Record optimization details
            for opt in optimizations:
                result.performance_improvements[opt["type"]] = opt.get("improvement", 0)

    async def _analyze_and_adapt(
        self, execution_result: Dict[str, Any], scenario: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze execution result and generate adaptations."""

        adaptations = []

        # Analyze execution time
        execution_time = execution_result.get("execution_time_ms", 0)
        if execution_time > self.config.performance_threshold_ms:
            adaptations.append(
                {
                    "type": "performance_optimization",
                    "action": "enable_caching",
                    "reason": f"Execution time {execution_time:.1f}ms exceeds threshold",
                }
            )

        # Analyze effectiveness
        effectiveness = execution_result.get("effectiveness_score", 0)
        if effectiveness < self.config.effectiveness_threshold:
            adaptations.append(
                {
                    "type": "effectiveness_improvement",
                    "action": "increase_complexity",
                    "reason": f"Effectiveness {effectiveness:.1%} below threshold",
                }
            )

        # Analyze failure patterns
        if execution_result.get("status") != "SUCCESS":
            adaptations.append(
                {
                    "type": "reliability_improvement",
                    "action": "add_retry_logic",
                    "reason": "Execution failure detected",
                }
            )

        return adaptations

    def _apply_adaptations_to_scenarios(
        self,
        adaptations: List[Dict[str, Any]],
        remaining_scenarios: List[Dict[str, Any]],
    ):
        """Apply adaptations to remaining scenarios."""

        for adaptation in adaptations:
            action = adaptation["action"]

            if action == "enable_caching":
                # Enable performance optimization for remaining scenarios
                for scenario in remaining_scenarios:
                    scenario.setdefault("optimization", {})["enable_caching"] = True

            elif action == "increase_complexity":
                # Increase attack complexity
                for scenario in remaining_scenarios:
                    params = scenario.setdefault("params", {})
                    if "split_count" in params:
                        params["split_count"] = min(params["split_count"] + 1, 10)

            elif action == "add_retry_logic":
                # Add retry attempts
                for scenario in remaining_scenarios:
                    scenario["retry_attempts"] = 3

    def _calculate_final_metrics(self, result: WorkflowExecutionResult):
        """Calculate final workflow metrics."""

        # Calculate success rate
        if result.attacks_executed > 0:
            result.success_rate = result.successful_attacks / result.attacks_executed

        # Calculate average effectiveness
        if result.effectiveness_scores:
            result.average_effectiveness_score = sum(result.effectiveness_scores) / len(
                result.effectiveness_scores
            )

        # Calculate average execution time
        execution_times = [
            detail["execution_time_ms"] for detail in result.execution_details
        ]
        if execution_times:
            result.average_execution_time_ms = sum(execution_times) / len(
                execution_times
            )

    def _generate_recommendations(self, result: WorkflowExecutionResult):
        """Generate recommendations based on workflow results."""

        # Performance recommendations
        if result.average_execution_time_ms > self.config.performance_threshold_ms:
            result.recommendations.append(
                f"Consider enabling performance optimization - average execution time {result.average_execution_time_ms:.1f}ms exceeds threshold"
            )

        # Effectiveness recommendations
        if result.average_effectiveness_score < self.config.effectiveness_threshold:
            result.recommendations.append(
                f"Consider using more complex attack techniques - average effectiveness {result.average_effectiveness_score:.1%} below threshold"
            )

        # Reliability recommendations
        if result.success_rate < 0.9:
            result.recommendations.append(
                f"Consider adding retry logic or error handling - success rate {result.success_rate:.1%} is low"
            )

        # Concurrency recommendations
        if result.total_duration > 60 and self.config.max_concurrent_attacks == 1:
            result.recommendations.append(
                "Consider enabling concurrent execution to reduce total workflow time"
            )

    async def _save_workflow_report(self, result: WorkflowExecutionResult):
        """Save detailed workflow report."""

        from pathlib import Path

        # Create report directory
        report_dir = Path(self.config.report_output_directory)
        report_dir.mkdir(exist_ok=True)

        # Generate report filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = report_dir / f"workflow_report_{timestamp}.json"

        try:
            # Convert result to dictionary
            report_data = {
                "workflow_id": result.workflow_id,
                "execution_mode": result.execution_mode.value,
                "start_time": result.start_time,
                "end_time": result.end_time,
                "total_duration": result.total_duration,
                "attacks_executed": result.attacks_executed,
                "successful_attacks": result.successful_attacks,
                "failed_attacks": result.failed_attacks,
                "success_rate": result.success_rate,
                "average_execution_time_ms": result.average_execution_time_ms,
                "total_segments_executed": result.total_segments_executed,
                "total_bytes_transmitted": result.total_bytes_transmitted,
                "average_effectiveness_score": result.average_effectiveness_score,
                "effectiveness_scores": result.effectiveness_scores,
                "optimization_applied": result.optimization_applied,
                "performance_improvements": result.performance_improvements,
                "issues_encountered": result.issues_encountered,
                "recommendations": result.recommendations,
                "execution_details": result.execution_details,
                "workflow_metrics": self.workflow_metrics,
                "configuration": {
                    "execution_mode": self.config.execution_mode.value,
                    "max_concurrent_attacks": self.config.max_concurrent_attacks,
                    "enable_performance_optimization": self.config.enable_performance_optimization,
                    "enable_closed_loop_optimization": self.config.enable_closed_loop_optimization,
                },
            }

            # Save report
            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"📄 Workflow report saved: {report_file}")

        except Exception as e:
            print(f"⚠️ Failed to save workflow report: {e}")

    async def _cleanup_workflow_resources(self):
        """Cleanup workflow resources."""

        try:
            # Cleanup performance optimizer
            if self.performance_optimizer:
                self.performance_optimizer.cleanup()

            # Clear active executions
            self.active_executions.clear()

            print("🧹 Workflow resources cleaned up")

        except Exception as e:
            print(f"⚠️ Error during cleanup: {e}")


# Convenience functions for common workflow patterns


async def execute_single_attack_workflow(
    attack_type: str,
    target: str,
    port: int = 80,
    payload: Optional[bytes] = None,
    params: Optional[Dict[str, Any]] = None,
) -> WorkflowExecutionResult:
    """Execute a single attack workflow."""

    config = SegmentWorkflowConfig(
        execution_mode=WorkflowExecutionMode.SINGLE_SHOT,
        enable_performance_optimization=True,
    )

    workflow = SegmentWorkflowIntegration(config)

    scenario = {
        "attack_type": attack_type,
        "target": target,
        "port": port,
        "payload": payload or f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode(),
        "params": params or {},
    }

    return await workflow.execute_workflow([scenario])


async def execute_benchmark_workflow(
    attack_types: List[str], target: str = "127.0.0.1", iterations: int = 10
) -> WorkflowExecutionResult:
    """Execute benchmark workflow for multiple attack types."""

    config = SegmentWorkflowConfig(
        execution_mode=WorkflowExecutionMode.BENCHMARK,
        enable_performance_optimization=True,
        enable_detailed_monitoring=True,
    )

    workflow = SegmentWorkflowIntegration(config)

    scenarios = []
    for attack_type in attack_types:
        for i in range(iterations):
            scenarios.append(
                {
                    "attack_type": attack_type,
                    "target": target,
                    "port": 80,
                    "payload": f"GET /benchmark_{i} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode(),
                    "params": {},
                }
            )

    return await workflow.execute_workflow(scenarios)


async def execute_adaptive_workflow(
    attack_scenarios: List[Dict[str, Any]], effectiveness_threshold: float = 0.8
) -> WorkflowExecutionResult:
    """Execute adaptive workflow with real-time optimization."""

    config = SegmentWorkflowConfig(
        execution_mode=WorkflowExecutionMode.ADAPTIVE,
        enable_performance_optimization=True,
        enable_real_time_feedback=True,
        enable_closed_loop_optimization=True,
        effectiveness_threshold=effectiveness_threshold,
    )

    workflow = SegmentWorkflowIntegration(config)

    return await workflow.execute_workflow(attack_scenarios)
