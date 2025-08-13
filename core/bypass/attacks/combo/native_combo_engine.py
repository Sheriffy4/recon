#!/usr/bin/env python3
"""
Native Combo Engine

Provides native combination capabilities for DPI bypass attacks,
allowing complex multi-technique strategies similar to zapret.
"""

import asyncio
import time
import logging
from typing import Dict, Any, Optional, List, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import importlib
import inspect

try:
    from ..base import AttackContext, AttackResult, AttackStatus
    from .zapret_strategy import ZapretStrategy, ZapretConfig
except ImportError:
    # Fallback for standalone testing
    from enum import Enum
    from dataclasses import dataclass
    from typing import Optional, Dict, Any

    class AttackStatus(Enum):
        SUCCESS = "success"
        FAILED = "failed"
        PARTIAL = "partial"

    @dataclass
    class AttackContext:
        target_host: str
        target_port: int
        source_ip: Optional[str] = None
        source_port: Optional[int] = None
        payload: Optional[bytes] = None

    @dataclass
    class AttackResult:
        success: bool
        status: AttackStatus = AttackStatus.SUCCESS
        technique_used: str = ""
        packets_sent: int = 0
        execution_time_ms: float = 0.0
        details: Optional[Dict[str, Any]] = None
        error_message: Optional[str] = None

    # Mock classes for fallback
    class ZapretStrategy:
        def __init__(self, config=None):
            pass

        async def execute(self, context):
            return AttackResult(success=True, technique_used="zapret_mock")

    class ZapretConfig:
        def __init__(self, **kwargs):
            pass


LOG = logging.getLogger("NativeComboEngine")


class ComboMode(Enum):
    """Combination execution modes."""

    SEQUENTIAL = "sequential"  # Execute attacks one after another
    PARALLEL = "parallel"  # Execute attacks simultaneously
    CONDITIONAL = "conditional"  # Execute based on conditions
    LAYERED = "layered"  # Layer attacks on top of each other
    ADAPTIVE = "adaptive"  # Adapt based on feedback


class ComboTiming(Enum):
    """Timing strategies for combinations."""

    IMMEDIATE = "immediate"  # No delay between attacks
    STAGGERED = "staggered"  # Small delays between attacks
    BURST = "burst"  # Burst patterns
    RANDOM = "random"  # Random timing
    SYNCHRONIZED = "synchronized"  # Synchronized execution


@dataclass
class ComboRule:
    """Rule for combining attacks."""

    name: str
    attacks: List[str]  # Attack names to combine
    mode: ComboMode = ComboMode.SEQUENTIAL
    timing: ComboTiming = ComboTiming.IMMEDIATE
    conditions: List[Callable] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)

    # Timing parameters
    delay_ms: float = 0.0
    stagger_ms: float = 10.0
    burst_size: int = 3
    burst_delay_ms: float = 100.0

    # Success criteria
    min_success_rate: float = 0.5
    required_attacks: List[str] = field(default_factory=list)

    # Adaptive parameters
    adapt_on_failure: bool = True
    max_adaptations: int = 3


@dataclass
class ComboResult:
    """Result of combo execution."""

    success: bool
    total_attacks: int
    successful_attacks: int
    failed_attacks: int
    execution_time_ms: float
    attack_results: List[AttackResult] = field(default_factory=list)
    combo_rule: Optional[str] = None
    adaptations_made: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        return (
            self.successful_attacks / self.total_attacks
            if self.total_attacks > 0
            else 0.0
        )


class NativeComboEngine:
    """
    Native combination engine for DPI bypass attacks.

    Provides sophisticated combination capabilities including:
    - Sequential and parallel execution
    - Conditional combinations
    - Layered attack strategies
    - Adaptive combinations with feedback
    - Timing control and synchronization
    """

    def __init__(self):
        self.attack_registry = {}
        self.combo_rules = {}
        self.execution_stats = {}

        # Load built-in attacks
        self._load_builtin_attacks()

        # Load built-in combo rules
        self._load_builtin_combo_rules()

        LOG.info(
            f"Native combo engine initialized with {len(self.attack_registry)} attacks "
            f"and {len(self.combo_rules)} combo rules"
        )

    def register_attack(self, name: str, attack_class: type, **default_params):
        """Register an attack for use in combinations."""
        self.attack_registry[name] = {
            "class": attack_class,
            "default_params": default_params,
            "usage_count": 0,
            "success_count": 0,
        }
        LOG.debug(f"Registered attack: {name}")

    def register_combo_rule(self, rule: ComboRule):
        """Register a combination rule."""
        self.combo_rules[rule.name] = rule
        LOG.debug(f"Registered combo rule: {rule.name}")

    async def execute_combo(
        self,
        combo_name: str,
        context: AttackContext,
        custom_params: Optional[Dict[str, Any]] = None,
    ) -> ComboResult:
        """
        Execute a combination of attacks.

        Args:
            combo_name: Name of the combo rule to execute
            context: Attack execution context
            custom_params: Custom parameters to override defaults

        Returns:
            ComboResult with execution details
        """
        if combo_name not in self.combo_rules:
            raise ValueError(f"Unknown combo rule: {combo_name}")

        rule = self.combo_rules[combo_name]
        start_time = time.time()

        LOG.info(f"Executing combo '{combo_name}' with {len(rule.attacks)} attacks")

        # Merge custom parameters
        params = rule.parameters.copy()
        if custom_params:
            params.update(custom_params)

        # Execute based on mode
        if rule.mode == ComboMode.SEQUENTIAL:
            result = await self._execute_sequential(rule, context, params)
        elif rule.mode == ComboMode.PARALLEL:
            result = await self._execute_parallel(rule, context, params)
        elif rule.mode == ComboMode.CONDITIONAL:
            result = await self._execute_conditional(rule, context, params)
        elif rule.mode == ComboMode.LAYERED:
            result = await self._execute_layered(rule, context, params)
        elif rule.mode == ComboMode.ADAPTIVE:
            result = await self._execute_adaptive(rule, context, params)
        else:
            raise ValueError(f"Unsupported combo mode: {rule.mode}")

        # Update statistics
        execution_time = time.time() - start_time
        result.execution_time_ms = execution_time * 1000
        result.combo_rule = combo_name

        self._update_stats(combo_name, result)

        LOG.info(
            f"Combo '{combo_name}' completed: {result.successful_attacks}/{result.total_attacks} "
            f"successful in {execution_time:.3f}s"
        )

        return result

    async def _execute_sequential(
        self, rule: ComboRule, context: AttackContext, params: Dict[str, Any]
    ) -> ComboResult:
        """Execute attacks sequentially."""
        results = []
        successful = 0

        for i, attack_name in enumerate(rule.attacks):
            # Check conditions
            if not self._check_conditions(rule, context, results):
                LOG.debug(f"Conditions not met for {attack_name}, skipping")
                continue

            # Apply timing
            if i > 0:
                await self._apply_timing(rule, i)

            # Execute attack
            attack_result = await self._execute_single_attack(
                attack_name, context, params
            )
            results.append(attack_result)

            if attack_result.success:
                successful += 1

            # Early termination if required attacks fail
            if attack_name in rule.required_attacks and not attack_result.success:
                LOG.warning(f"Required attack {attack_name} failed, terminating combo")
                break

        return ComboResult(
            success=successful >= len(rule.attacks) * rule.min_success_rate,
            total_attacks=len(results),
            successful_attacks=successful,
            failed_attacks=len(results) - successful,
            execution_time_ms=0,  # Will be set by caller
            attack_results=results,
        )

    async def _execute_parallel(
        self, rule: ComboRule, context: AttackContext, params: Dict[str, Any]
    ) -> ComboResult:
        """Execute attacks in parallel."""
        # Create tasks for all attacks
        tasks = []
        for attack_name in rule.attacks:
            if self._check_conditions(rule, context, []):
                task = self._execute_single_attack(attack_name, context, params)
                tasks.append((attack_name, task))

        # Execute all tasks concurrently
        results = []
        successful = 0

        if rule.timing == ComboTiming.SYNCHRONIZED:
            # Wait for all to complete
            task_results = await asyncio.gather(
                *[task for _, task in tasks], return_exceptions=True
            )

            for i, (attack_name, result) in enumerate(
                zip([name for name, _ in tasks], task_results)
            ):
                if isinstance(result, Exception):
                    LOG.error(f"Attack {attack_name} failed with exception: {result}")
                    attack_result = AttackResult(
                        success=False,
                        status=AttackStatus.ERROR,
                        technique_used=attack_name,
                        error_message=str(result),
                    )
                else:
                    attack_result = result

                results.append(attack_result)
                if attack_result.success:
                    successful += 1
        else:
            # Staggered parallel execution
            for i, (attack_name, task) in enumerate(tasks):
                if i > 0 and rule.timing == ComboTiming.STAGGERED:
                    await asyncio.sleep(rule.stagger_ms / 1000)

                try:
                    attack_result = await task
                    results.append(attack_result)
                    if attack_result.success:
                        successful += 1
                except Exception as e:
                    LOG.error(f"Attack {attack_name} failed: {e}")
                    results.append(
                        AttackResult(
                            success=False,
                            status=AttackStatus.ERROR,
                            technique_used=attack_name,
                            error_message=str(e),
                        )
                    )

        return ComboResult(
            success=successful >= len(rule.attacks) * rule.min_success_rate,
            total_attacks=len(results),
            successful_attacks=successful,
            failed_attacks=len(results) - successful,
            execution_time_ms=0,
            attack_results=results,
        )

    async def _execute_conditional(
        self, rule: ComboRule, context: AttackContext, params: Dict[str, Any]
    ) -> ComboResult:
        """Execute attacks based on conditions."""
        results = []
        successful = 0

        for attack_name in rule.attacks:
            # Check specific conditions for this attack
            if not self._check_conditions(rule, context, results):
                LOG.debug(f"Conditions not met for {attack_name}, skipping")
                continue

            # Execute attack
            attack_result = await self._execute_single_attack(
                attack_name, context, params
            )
            results.append(attack_result)

            if attack_result.success:
                successful += 1

                # If this attack succeeded, we might skip others
                if params.get("stop_on_first_success", False):
                    LOG.info(
                        f"Attack {attack_name} succeeded, stopping conditional execution"
                    )
                    break

        return ComboResult(
            success=successful > 0,  # Conditional combos succeed if any attack succeeds
            total_attacks=len(results),
            successful_attacks=successful,
            failed_attacks=len(results) - successful,
            execution_time_ms=0,
            attack_results=results,
        )

    async def _execute_layered(
        self, rule: ComboRule, context: AttackContext, params: Dict[str, Any]
    ) -> ComboResult:
        """Execute attacks in layers, each building on the previous."""
        results = []
        successful = 0
        modified_context = context

        for attack_name in rule.attacks:
            # Execute attack with context modified by previous layers
            attack_result = await self._execute_single_attack(
                attack_name, modified_context, params
            )
            results.append(attack_result)

            if attack_result.success:
                successful += 1

                # Modify context for next layer based on this result
                modified_context = self._modify_context_for_layer(
                    modified_context, attack_result
                )
            else:
                LOG.warning(
                    f"Layer {attack_name} failed, continuing with original context"
                )

        return ComboResult(
            success=successful >= len(rule.attacks) * rule.min_success_rate,
            total_attacks=len(results),
            successful_attacks=successful,
            failed_attacks=len(results) - successful,
            execution_time_ms=0,
            attack_results=results,
        )

    async def _execute_adaptive(
        self, rule: ComboRule, context: AttackContext, params: Dict[str, Any]
    ) -> ComboResult:
        """Execute attacks with adaptive behavior based on feedback."""
        results = []
        successful = 0
        adaptations = 0

        for attempt in range(rule.max_adaptations + 1):
            attempt_results = []
            attempt_successful = 0

            for attack_name in rule.attacks:
                # Adapt parameters based on previous results
                adapted_params = self._adapt_parameters(params, results, attack_name)

                attack_result = await self._execute_single_attack(
                    attack_name, context, adapted_params
                )
                attempt_results.append(attack_result)

                if attack_result.success:
                    attempt_successful += 1

            results.extend(attempt_results)
            successful += attempt_successful

            # Check if we should adapt
            success_rate = attempt_successful / len(rule.attacks) if rule.attacks else 0
            if success_rate >= rule.min_success_rate or not rule.adapt_on_failure:
                break

            if attempt < rule.max_adaptations:
                adaptations += 1
                LOG.info(
                    f"Adapting combo strategy (attempt {attempt + 1}/{rule.max_adaptations + 1})"
                )
                await asyncio.sleep(0.1)  # Brief pause before adaptation

        return ComboResult(
            success=successful >= len(rule.attacks) * rule.min_success_rate,
            total_attacks=len(results),
            successful_attacks=successful,
            failed_attacks=len(results) - successful,
            execution_time_ms=0,
            attack_results=results,
            adaptations_made=adaptations,
        )

    async def _execute_single_attack(
        self, attack_name: str, context: AttackContext, params: Dict[str, Any]
    ) -> AttackResult:
        """Execute a single attack."""
        if attack_name not in self.attack_registry:
            LOG.error(f"Unknown attack: {attack_name}")
            return AttackResult(
                success=False,
                status=AttackStatus.ERROR,
                technique_used=attack_name,
                error_message=f"Unknown attack: {attack_name}",
            )

        attack_info = self.attack_registry[attack_name]
        attack_info["usage_count"] += 1

        try:
            # Merge default parameters with custom ones
            attack_params = attack_info["default_params"].copy()
            attack_params.update(params.get(attack_name, {}))

            # Create attack instance
            attack_class = attack_info["class"]
            if attack_params:
                attack_instance = attack_class(**attack_params)
            else:
                attack_instance = attack_class()

            # Execute attack
            result = await attack_instance.execute(context)

            if result.success:
                attack_info["success_count"] += 1

            return result

        except Exception as e:
            LOG.error(f"Attack {attack_name} execution failed: {e}")
            return AttackResult(
                success=False,
                status=AttackStatus.ERROR,
                technique_used=attack_name,
                error_message=str(e),
            )

    async def _apply_timing(self, rule: ComboRule, attack_index: int):
        """Apply timing strategy between attacks."""
        if rule.timing == ComboTiming.IMMEDIATE:
            return
        elif rule.timing == ComboTiming.STAGGERED:
            await asyncio.sleep(rule.stagger_ms / 1000)
        elif rule.timing == ComboTiming.BURST:
            if attack_index % rule.burst_size == 0 and attack_index > 0:
                await asyncio.sleep(rule.burst_delay_ms / 1000)
        elif rule.timing == ComboTiming.RANDOM:
            import random

            delay = random.uniform(0, rule.delay_ms / 1000)
            await asyncio.sleep(delay)

    def _check_conditions(
        self,
        rule: ComboRule,
        context: AttackContext,
        previous_results: List[AttackResult],
    ) -> bool:
        """Check if conditions are met for attack execution."""
        for condition in rule.conditions:
            try:
                if not condition(context, previous_results):
                    return False
            except Exception as e:
                LOG.warning(f"Condition check failed: {e}")
                return False
        return True

    def _modify_context_for_layer(
        self, context: AttackContext, result: AttackResult
    ) -> AttackContext:
        """Modify context based on layer result."""
        # Create new context with modifications from the result
        new_context = AttackContext(
            target_host=context.target_host,
            target_port=context.target_port,
            source_ip=context.source_ip,
            source_port=context.source_port,
            payload=context.payload,
        )

        # Apply modifications based on result
        if hasattr(result, "modified_packets") and result.modified_packets:
            new_context.payload = result.modified_packets[
                -1
            ]  # Use last modified packet

        return new_context

    def _adapt_parameters(
        self,
        base_params: Dict[str, Any],
        previous_results: List[AttackResult],
        attack_name: str,
    ) -> Dict[str, Any]:
        """Adapt parameters based on previous results."""
        adapted_params = base_params.copy()

        # Simple adaptation logic - can be made more sophisticated
        failed_count = sum(1 for r in previous_results if not r.success)

        if failed_count > 0:
            # Increase intensity for failed attempts
            if attack_name in adapted_params:
                attack_params = adapted_params[attack_name].copy()

                # Increase repeats if available
                if "repeats" in attack_params:
                    attack_params["repeats"] = min(
                        20, attack_params["repeats"] + failed_count
                    )

                # Decrease delays for more aggressive approach
                if "delay_ms" in attack_params:
                    attack_params["delay_ms"] = max(
                        1, attack_params["delay_ms"] - failed_count * 10
                    )

                adapted_params[attack_name] = attack_params

        return adapted_params

    def _update_stats(self, combo_name: str, result: ComboResult):
        """Update execution statistics."""
        if combo_name not in self.execution_stats:
            self.execution_stats[combo_name] = {
                "executions": 0,
                "successes": 0,
                "total_attacks": 0,
                "successful_attacks": 0,
                "avg_execution_time_ms": 0.0,
            }

        stats = self.execution_stats[combo_name]
        stats["executions"] += 1
        if result.success:
            stats["successes"] += 1
        stats["total_attacks"] += result.total_attacks
        stats["successful_attacks"] += result.successful_attacks

        # Update average execution time
        old_avg = stats["avg_execution_time_ms"]
        new_avg = (
            old_avg * (stats["executions"] - 1) + result.execution_time_ms
        ) / stats["executions"]
        stats["avg_execution_time_ms"] = new_avg

    def _load_builtin_attacks(self):
        """Load built-in attacks into registry."""
        # Register zapret strategy
        self.register_attack("zapret", ZapretStrategy)

        # Try to load other attacks dynamically
        attack_modules = [
            "tcp.fooling",
            "tcp.segmentation",
            "tcp.manipulation",
            "tcp.timing",
            "tls.record_manipulation",
            "tls.extension_attacks",
            "tls.confusion",
            "http.header_attacks",
            "http.method_attacks",
            "ip.fragmentation",
            "ip.header_manipulation",
            "payload.obfuscation",
            "payload.encryption",
            "payload.noise",
        ]

        for module_name in attack_modules:
            try:
                module = importlib.import_module(f"..{module_name}", __name__)

                # Find attack classes in the module
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if hasattr(obj, "execute") and name != "AttackContext":
                        attack_name = module_name.split(".")[-1] + "_" + name.lower()
                        self.register_attack(attack_name, obj)

            except ImportError as e:
                LOG.debug(f"Could not load attack module {module_name}: {e}")

    def _load_builtin_combo_rules(self):
        """Load built-in combination rules."""
        # Zapret-style combo
        zapret_rule = ComboRule(
            name="zapret_combo",
            attacks=["zapret"],
            mode=ComboMode.SEQUENTIAL,
            timing=ComboTiming.IMMEDIATE,
            parameters={
                "zapret": {
                    "split_seqovl": 297,
                    "base_ttl": 51,
                    "repeats": 10,
                    "auto_ttl": True,
                }
            },
        )
        self.register_combo_rule(zapret_rule)

        # Multi-layer TCP combo
        tcp_combo = ComboRule(
            name="tcp_multi_layer",
            attacks=["tcp_segmentation", "tcp_fooling", "tcp_manipulation"],
            mode=ComboMode.LAYERED,
            timing=ComboTiming.STAGGERED,
            stagger_ms=50,
            min_success_rate=0.6,
        )
        self.register_combo_rule(tcp_combo)

        # Adaptive TLS combo
        tls_adaptive = ComboRule(
            name="tls_adaptive",
            attacks=["tls_record_manipulation", "tls_extension_attacks"],
            mode=ComboMode.ADAPTIVE,
            timing=ComboTiming.BURST,
            adapt_on_failure=True,
            max_adaptations=3,
        )
        self.register_combo_rule(tls_adaptive)

        # Parallel payload combo
        payload_parallel = ComboRule(
            name="payload_parallel",
            attacks=["payload_obfuscation", "payload_encryption", "payload_noise"],
            mode=ComboMode.PARALLEL,
            timing=ComboTiming.SYNCHRONIZED,
            min_success_rate=0.3,  # Only need one to succeed
        )
        self.register_combo_rule(payload_parallel)

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "registered_attacks": len(self.attack_registry),
            "registered_combos": len(self.combo_rules),
            "execution_stats": self.execution_stats,
            "attack_usage": {
                name: {
                    "usage_count": info["usage_count"],
                    "success_count": info["success_count"],
                    "success_rate": (
                        info["success_count"] / info["usage_count"]
                        if info["usage_count"] > 0
                        else 0.0
                    ),
                }
                for name, info in self.attack_registry.items()
            },
        }


# Global combo engine instance
_global_combo_engine: Optional[NativeComboEngine] = None


def get_global_combo_engine() -> NativeComboEngine:
    """Get or create global combo engine."""
    global _global_combo_engine
    if _global_combo_engine is None:
        _global_combo_engine = NativeComboEngine()
    return _global_combo_engine
