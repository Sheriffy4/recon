"""
Intelligent Attack Combination System - Task 17
Implements intelligent attack combination, adaptive selection, and comprehensive testing framework.

This module addresses requirements:
- 1.1, 1.2, 1.3, 1.4: Strategy selection with priority logic
- 6.1, 6.2, 6.3, 6.4: Enhanced logging and monitoring

Features:
- Multi-strategy testing with parallel execution
- Real-time success rate tracking and adaptation
- Attack chaining and fallback mechanisms
- Comprehensive effectiveness testing framework
"""

import asyncio
import logging
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import random

# Import recon modules
from .strategy_selector import StrategySelector
from .strategy_interpreter import StrategyTranslator
from .strategy_integration_fix import StrategyIntegrationFix


@dataclass
class AttackResult:
    """Result of a single attack attempt."""

    attack_id: str
    strategy_type: str
    strategy_string: str
    domain: str
    target_ip: str
    success: bool
    latency_ms: float
    rst_packets: int
    connection_established: bool
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Represents a chain of attacks to try in sequence."""

    chain_id: str
    attacks: List[str]  # List of attack strategy strings
    success_threshold: float = 0.7  # Success rate threshold to continue chain
    max_attempts: int = 3
    fallback_strategy: Optional[str] = None


@dataclass
class AdaptiveMetrics:
    """Metrics for adaptive attack selection."""

    strategy_type: str
    domain_pattern: str
    success_count: int = 0
    total_attempts: int = 0
    avg_latency_ms: float = 0.0
    recent_results: deque = field(default_factory=lambda: deque(maxlen=10))
    last_updated: datetime = field(default_factory=datetime.now)

    @property
    def success_rate(self) -> float:
        """Calculate current success rate."""
        return (self.success_count / self.total_attempts) if self.total_attempts > 0 else 0.0

    @property
    def recent_success_rate(self) -> float:
        """Calculate success rate from recent results."""
        if not self.recent_results:
            return 0.0
        return sum(1 for r in self.recent_results if r) / len(self.recent_results)


class AttackCombinator:
    """
    Intelligent attack combination system that tests multiple strategies
    simultaneously and adapts based on real-time success rates.
    """

    def __init__(self, strategy_selector: Optional[StrategySelector] = None, debug: bool = True):
        """
        Initialize AttackCombinator.

        Args:
            strategy_selector: Optional StrategySelector instance
            debug: Enable debug logging
        """
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        if debug and self.logger.level == logging.NOTSET:
            self.logger.setLevel(logging.DEBUG)

        # Core components
        self.strategy_selector = strategy_selector or StrategySelector()
        self.strategy_translator = StrategyTranslator()
        self.integration_fix = StrategyIntegrationFix(debug=debug)

        # Attack definitions and chains
        self.attack_strategies = self._initialize_attack_strategies()
        self.attack_chains = self._initialize_attack_chains()

        # Adaptive metrics tracking
        self.metrics: Dict[str, AdaptiveMetrics] = {}
        self.global_metrics = AdaptiveMetrics("global", "*")

        # Configuration
        self.config = {
            "parallel_attacks": 3,  # Number of parallel attacks to test
            "adaptation_window": 50,  # Number of results to consider for adaptation
            "min_attempts_for_adaptation": 10,  # Minimum attempts before adapting
            "success_threshold": 0.75,  # Success rate threshold for strategy promotion
            "failure_threshold": 0.25,  # Success rate threshold for strategy demotion
            "latency_weight": 0.3,  # Weight of latency in strategy scoring
            "recency_weight": 0.4,  # Weight of recent results vs historical
        }

        # State tracking
        self.active_tests: Dict[str, asyncio.Task] = {}
        self.results_history: List[AttackResult] = []
        self.lock = threading.Lock()

        self.logger.info(
            f"AttackCombinator initialized with {len(self.attack_strategies)} strategies"
        )

    def _initialize_attack_strategies(self) -> Dict[str, str]:
        """Initialize the comprehensive set of attack strategies."""
        return {
            # Core DPI bypass attacks
            "fakeddisorder_basic": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "fakeddisorder_seqovl": "--dpi-desync=fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1",
            "multisplit_aggressive": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
            "multisplit_conservative": "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "multidisorder": "--dpi-desync=multidisorder --dpi-desync-split-count=5 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "seqovl_standard": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "seqovl_large": "--dpi-desync=fake,disorder --dpi-desync-split-pos=5 --dpi-desync-split-seqovl=100 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "badsum_race": "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=4 --dpi-desync-split-pos=3 --dpi-desync-window-div=6 --dpi-desync-delay=10",
            "md5sig_race": "--dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-ttl=6 --dpi-desync-split-pos=3",
            "badseq_race": "--dpi-desync=fake --dpi-desync-fooling=badseq --dpi-desync-ttl=3 --dpi-desync-split-pos=3",
            "combined_fooling": "--dpi-desync=fake --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-ttl=4 --dpi-desync-split-pos=3",
            # Specialized attacks for different scenarios
            "twitter_optimized": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
            "instagram_optimized": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
            "rutracker_optimized": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=5 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            # High-latency tolerant attacks
            "slow_connection": "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=8 --dpi-desync-delay=50",
            # Low-latency optimized attacks
            "fast_connection": "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-ttl=1",
            # Fallback strategies
            "minimal_bypass": "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "conservative_bypass": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=10 --dpi-desync-ttl=3",
        }

    def _initialize_attack_chains(self) -> Dict[str, AttackChain]:
        """Initialize predefined attack chains for different scenarios."""
        return {
            "twitter_chain": AttackChain(
                chain_id="twitter_chain",
                attacks=[
                    "twitter_optimized",
                    "multisplit_aggressive",
                    "fakeddisorder_seqovl",
                    "badsum_race",
                ],
                success_threshold=0.8,
                fallback_strategy="minimal_bypass",
            ),
            "social_media_chain": AttackChain(
                chain_id="social_media_chain",
                attacks=[
                    "instagram_optimized",
                    "multisplit_conservative",
                    "seqovl_standard",
                    "combined_fooling",
                ],
                success_threshold=0.7,
                fallback_strategy="conservative_bypass",
            ),
            "torrent_chain": AttackChain(
                chain_id="torrent_chain",
                attacks=[
                    "rutracker_optimized",
                    "fakeddisorder_basic",
                    "multidisorder",
                    "badseq_race",
                ],
                success_threshold=0.6,
                fallback_strategy="minimal_bypass",
            ),
            "adaptive_chain": AttackChain(
                chain_id="adaptive_chain",
                attacks=[
                    "fakeddisorder_seqovl",  # Start with most sophisticated
                    "multisplit_aggressive",
                    "seqovl_large",
                    "badsum_race",
                    "minimal_bypass",  # Always end with simple fallback
                ],
                success_threshold=0.5,
                fallback_strategy="conservative_bypass",
            ),
            "fast_chain": AttackChain(
                chain_id="fast_chain",
                attacks=[
                    "fast_connection",
                    "multisplit_conservative",
                    "minimal_bypass",
                ],
                success_threshold=0.8,
                max_attempts=2,
            ),
            "slow_chain": AttackChain(
                chain_id="slow_chain",
                attacks=["slow_connection", "seqovl_standard", "conservative_bypass"],
                success_threshold=0.6,
                max_attempts=5,
            ),
        }

    async def test_multiple_attacks_parallel(
        self,
        domain: str,
        target_ip: str,
        attack_list: Optional[List[str]] = None,
        max_parallel: Optional[int] = None,
    ) -> List[AttackResult]:
        """
        Test multiple attacks in parallel against a target.

        Args:
            domain: Target domain
            target_ip: Target IP address
            attack_list: List of attack strategy names to test (None for adaptive selection)
            max_parallel: Maximum number of parallel tests

        Returns:
            List of AttackResult objects
        """
        max_parallel = max_parallel or self.config["parallel_attacks"]

        # Select attacks to test
        if attack_list is None:
            attack_list = self._select_adaptive_attacks(domain, target_ip)

        self.logger.info(
            f"Testing {len(attack_list)} attacks in parallel on {domain} ({target_ip})"
        )
        self.logger.debug(f"Selected attacks: {attack_list}")

        # Create semaphore to limit parallel execution
        semaphore = asyncio.Semaphore(max_parallel)

        # Create tasks for parallel execution
        tasks = []
        for attack_name in attack_list:
            if attack_name in self.attack_strategies:
                task = asyncio.create_task(
                    self._test_single_attack_with_semaphore(
                        semaphore, attack_name, domain, target_ip
                    )
                )
                tasks.append(task)

        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and collect valid results
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Attack {attack_list[i]} failed with exception: {result}")
            elif isinstance(result, AttackResult):
                valid_results.append(result)
                self._update_metrics(result)

        self.logger.info(f"Completed parallel testing: {len(valid_results)} results")
        return valid_results

    async def _test_single_attack_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        attack_name: str,
        domain: str,
        target_ip: str,
    ) -> AttackResult:
        """Test a single attack with semaphore control."""
        async with semaphore:
            return await self._test_single_attack(attack_name, domain, target_ip)

    async def _test_single_attack(
        self, attack_name: str, domain: str, target_ip: str
    ) -> AttackResult:
        """
        Test a single attack strategy against a target.

        Args:
            attack_name: Name of attack strategy
            domain: Target domain
            target_ip: Target IP address

        Returns:
            AttackResult with test results
        """
        attack_id = f"{attack_name}_{domain}_{int(time.time())}"
        strategy_string = self.attack_strategies[attack_name]

        self.logger.debug(f"Testing attack {attack_name} on {domain}")

        start_time = time.time()

        try:
            # Parse strategy to engine task
            engine_task = self.strategy_translator.translate_zapret_to_recon(strategy_string)

            # Simulate attack execution (in real implementation, this would use BypassEngine)
            success, latency_ms, rst_packets, connection_established, error = (
                await self._execute_attack(engine_task, domain, target_ip)
            )

            result = AttackResult(
                attack_id=attack_id,
                strategy_type=attack_name,
                strategy_string=strategy_string,
                domain=domain,
                target_ip=target_ip,
                success=success,
                latency_ms=latency_ms,
                rst_packets=rst_packets,
                connection_established=connection_established,
                error_message=error,
            )

            self.logger.debug(
                f"Attack {attack_name} result: success={success}, latency={latency_ms:.1f}ms"
            )
            return result

        except Exception as e:
            self.logger.error(f"Error testing attack {attack_name}: {e}")
            return AttackResult(
                attack_id=attack_id,
                strategy_type=attack_name,
                strategy_string=strategy_string,
                domain=domain,
                target_ip=target_ip,
                success=False,
                latency_ms=time.time() - start_time,
                rst_packets=0,
                connection_established=False,
                error_message=str(e),
            )

    async def _execute_attack(
        self, engine_task: Dict[str, Any], domain: str, target_ip: str
    ) -> Tuple[bool, float, int, bool, Optional[str]]:
        """
        Execute the actual attack (simulated for now).

        In a real implementation, this would:
        1. Use BypassEngine to apply the strategy
        2. Attempt connection to target
        3. Monitor for RST packets
        4. Measure latency and success

        Returns:
            Tuple of (success, latency_ms, rst_packets, connection_established, error_message)
        """
        # Simulate network delay
        await asyncio.sleep(random.uniform(0.1, 0.5))

        # Simulate attack execution with realistic success rates
        attack_type = engine_task.get("type", "unknown")

        # Different attack types have different success rates
        base_success_rates = {
            "fakeddisorder_seqovl": 0.85,
            "multisplit": 0.75,
            "fakeddisorder": 0.70,
            "badsum_race": 0.65,
            "seqovl": 0.60,
            "multidisorder": 0.55,
        }

        base_rate = base_success_rates.get(attack_type, 0.50)

        # Add some randomness and domain-specific adjustments
        if "twimg.com" in domain or "x.com" in domain:
            base_rate += 0.1  # Twitter domains work better with optimized strategies
        elif "instagram.com" in domain:
            base_rate += 0.05
        elif "rutracker" in domain:
            base_rate -= 0.1  # Torrent sites are harder

        # Simulate success/failure
        success = random.random() < base_rate
        latency_ms = random.uniform(50, 300)
        rst_packets = 0 if success else random.randint(1, 5)
        connection_established = success
        error_message = None if success else "Connection failed"

        return success, latency_ms, rst_packets, connection_established, error_message

    def _select_adaptive_attacks(self, domain: str, target_ip: str) -> List[str]:
        """
        Adaptively select attacks based on historical performance.

        Args:
            domain: Target domain
            target_ip: Target IP address

        Returns:
            List of attack strategy names to test
        """
        # Get domain pattern for metrics lookup
        domain_pattern = self._get_domain_pattern(domain)

        # Get metrics for this domain pattern
        pattern_metrics = self._get_metrics_for_pattern(domain_pattern)

        # Score all available attacks
        attack_scores = {}
        for attack_name in self.attack_strategies.keys():
            score = self._calculate_attack_score(attack_name, pattern_metrics)
            attack_scores[attack_name] = score

        # Sort by score (descending)
        sorted_attacks = sorted(attack_scores.items(), key=lambda x: x[1], reverse=True)

        # Select top attacks
        num_attacks = min(self.config["parallel_attacks"], len(sorted_attacks))
        selected = [attack for attack, score in sorted_attacks[:num_attacks]]

        self.logger.info(f"Adaptive selection for {domain_pattern}: {selected}")
        self.logger.debug(f"Attack scores: {dict(sorted_attacks[:5])}")  # Log top 5 scores

        return selected

    def _get_domain_pattern(self, domain: str) -> str:
        """Get domain pattern for metrics grouping."""
        # Check for known patterns
        if "twimg.com" in domain:
            return "*.twimg.com"
        elif domain.endswith(".com"):
            return "*.com"
        elif domain.endswith(".org"):
            return "*.org"
        elif domain.endswith(".to"):
            return "*.to"
        else:
            return domain

    def _get_metrics_for_pattern(self, pattern: str) -> Dict[str, AdaptiveMetrics]:
        """Get metrics for a specific domain pattern."""
        pattern_metrics = {}

        for key, metrics in self.metrics.items():
            if metrics.domain_pattern == pattern or pattern == "*":
                pattern_metrics[metrics.strategy_type] = metrics

        return pattern_metrics

    def _calculate_attack_score(
        self, attack_name: str, pattern_metrics: Dict[str, AdaptiveMetrics]
    ) -> float:
        """
        Calculate score for an attack based on historical performance.

        Args:
            attack_name: Name of attack strategy
            pattern_metrics: Metrics for the domain pattern

        Returns:
            Score (higher is better)
        """
        # Get metrics for this attack
        if attack_name in pattern_metrics:
            metrics = pattern_metrics[attack_name]
        else:
            # No historical data, use global metrics or defaults
            metrics = self.global_metrics

        # Base score from success rate
        success_rate = (
            metrics.recent_success_rate
            if len(metrics.recent_results) >= 3
            else metrics.success_rate
        )
        score = success_rate * 100

        # Adjust for latency (lower latency is better)
        if metrics.avg_latency_ms > 0:
            latency_penalty = (metrics.avg_latency_ms / 1000) * self.config["latency_weight"] * 10
            score -= latency_penalty

        # Boost for recent good performance
        if len(metrics.recent_results) >= 3:
            recent_boost = (
                (metrics.recent_success_rate - metrics.success_rate)
                * self.config["recency_weight"]
                * 50
            )
            score += recent_boost

        # Penalty for insufficient data (exploration vs exploitation)
        if metrics.total_attempts < self.config["min_attempts_for_adaptation"]:
            exploration_boost = 20  # Encourage trying less-tested strategies
            score += exploration_boost

        # Domain-specific bonuses
        if "twitter" in attack_name and (
            "twimg.com" in pattern_metrics or "x.com" in pattern_metrics
        ):
            score += 15
        elif "instagram" in attack_name and "instagram.com" in pattern_metrics:
            score += 10
        elif "rutracker" in attack_name and "rutracker" in pattern_metrics:
            score += 10

        return max(0, score)  # Ensure non-negative score

    def _update_metrics(self, result: AttackResult) -> None:
        """Update metrics with new attack result."""
        with self.lock:
            # Get or create metrics for this strategy + domain pattern
            domain_pattern = self._get_domain_pattern(result.domain)
            metrics_key = f"{result.strategy_type}_{domain_pattern}"

            if metrics_key not in self.metrics:
                self.metrics[metrics_key] = AdaptiveMetrics(
                    strategy_type=result.strategy_type, domain_pattern=domain_pattern
                )

            metrics = self.metrics[metrics_key]

            # Update counters
            metrics.total_attempts += 1
            if result.success:
                metrics.success_count += 1

            # Update average latency
            if metrics.total_attempts == 1:
                metrics.avg_latency_ms = result.latency_ms
            else:
                # Exponential moving average
                alpha = 0.3
                metrics.avg_latency_ms = (
                    alpha * result.latency_ms + (1 - alpha) * metrics.avg_latency_ms
                )

            # Update recent results
            metrics.recent_results.append(result.success)
            metrics.last_updated = datetime.now()

            # Update global metrics
            self.global_metrics.total_attempts += 1
            if result.success:
                self.global_metrics.success_count += 1
            self.global_metrics.recent_results.append(result.success)

            # Store result in history
            self.results_history.append(result)

            # Limit history size
            if len(self.results_history) > 1000:
                self.results_history = self.results_history[-500:]

    async def execute_attack_chain(
        self, chain_name: str, domain: str, target_ip: str
    ) -> List[AttackResult]:
        """
        Execute an attack chain with fallback mechanisms.

        Args:
            chain_name: Name of attack chain to execute
            domain: Target domain
            target_ip: Target IP address

        Returns:
            List of AttackResult objects from chain execution
        """
        if chain_name not in self.attack_chains:
            raise ValueError(f"Unknown attack chain: {chain_name}")

        chain = self.attack_chains[chain_name]
        self.logger.info(f"Executing attack chain '{chain_name}' on {domain}")

        results = []
        current_success_rate = 0.0

        for i, attack_name in enumerate(chain.attacks):
            if attack_name not in self.attack_strategies:
                self.logger.warning(f"Unknown attack in chain: {attack_name}")
                continue

            # Test current attack
            self.logger.info(f"Chain step {i+1}/{len(chain.attacks)}: {attack_name}")
            result = await self._test_single_attack(attack_name, domain, target_ip)
            results.append(result)
            self._update_metrics(result)

            # Calculate current success rate
            successful = sum(1 for r in results if r.success)
            current_success_rate = successful / len(results)

            self.logger.info(
                f"Chain progress: {successful}/{len(results)} success rate: {current_success_rate:.2f}"
            )

            # Check if we've met the success threshold
            if current_success_rate >= chain.success_threshold:
                self.logger.info(
                    f"Chain success threshold met ({current_success_rate:.2f} >= {chain.success_threshold})"
                )
                break

            # Check if we've exceeded max attempts
            if len(results) >= chain.max_attempts:
                self.logger.info(f"Chain max attempts reached ({chain.max_attempts})")
                break

        # If chain failed and fallback is available, try fallback
        if current_success_rate < chain.success_threshold and chain.fallback_strategy:
            self.logger.info(f"Chain failed, trying fallback: {chain.fallback_strategy}")
            fallback_result = await self._test_single_attack(
                chain.fallback_strategy, domain, target_ip
            )
            results.append(fallback_result)
            self._update_metrics(fallback_result)

        self.logger.info(f"Attack chain '{chain_name}' completed with {len(results)} attempts")
        return results

    def get_best_strategy_for_domain(self, domain: str) -> Tuple[str, float]:
        """
        Get the best performing strategy for a domain based on historical data.

        Args:
            domain: Target domain

        Returns:
            Tuple of (strategy_name, success_rate)
        """
        domain_pattern = self._get_domain_pattern(domain)
        pattern_metrics = self._get_metrics_for_pattern(domain_pattern)

        if not pattern_metrics:
            # No historical data, return adaptive selection
            adaptive_attacks = self._select_adaptive_attacks(domain, "0.0.0.0")
            return adaptive_attacks[0] if adaptive_attacks else "badsum_race", 0.0

        # Find strategy with highest success rate
        best_strategy = None
        best_rate = 0.0

        for strategy_name, metrics in pattern_metrics.items():
            rate = (
                metrics.recent_success_rate
                if len(metrics.recent_results) >= 3
                else metrics.success_rate
            )
            if rate > best_rate:
                best_rate = rate
                best_strategy = strategy_name

        return best_strategy or "badsum_race", best_rate

    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about attack performance."""
        stats = {
            "global_metrics": {
                "total_attempts": self.global_metrics.total_attempts,
                "success_count": self.global_metrics.success_count,
                "success_rate": self.global_metrics.success_rate,
                "recent_success_rate": self.global_metrics.recent_success_rate,
            },
            "strategy_performance": {},
            "domain_performance": {},
            "recent_activity": len(
                [
                    r
                    for r in self.results_history
                    if r.timestamp > datetime.now() - timedelta(hours=1)
                ]
            ),
            "total_strategies_tested": len(set(r.strategy_type for r in self.results_history)),
            "total_domains_tested": len(set(r.domain for r in self.results_history)),
        }

        # Strategy performance breakdown
        strategy_stats = defaultdict(lambda: {"attempts": 0, "successes": 0, "avg_latency": 0.0})

        for result in self.results_history:
            strategy_stats[result.strategy_type]["attempts"] += 1
            if result.success:
                strategy_stats[result.strategy_type]["successes"] += 1

            # Update average latency
            current_avg = strategy_stats[result.strategy_type]["avg_latency"]
            attempts = strategy_stats[result.strategy_type]["attempts"]
            strategy_stats[result.strategy_type]["avg_latency"] = (
                current_avg * (attempts - 1) + result.latency_ms
            ) / attempts

        for strategy, data in strategy_stats.items():
            stats["strategy_performance"][strategy] = {
                "success_rate": (
                    data["successes"] / data["attempts"] if data["attempts"] > 0 else 0
                ),
                "total_attempts": data["attempts"],
                "avg_latency_ms": data["avg_latency"],
            }

        # Domain performance breakdown
        domain_stats = defaultdict(lambda: {"attempts": 0, "successes": 0})

        for result in self.results_history:
            domain_stats[result.domain]["attempts"] += 1
            if result.success:
                domain_stats[result.domain]["successes"] += 1

        for domain, data in domain_stats.items():
            stats["domain_performance"][domain] = {
                "success_rate": (
                    data["successes"] / data["attempts"] if data["attempts"] > 0 else 0
                ),
                "total_attempts": data["attempts"],
            }

        return stats

    def save_metrics(self, filepath: str) -> None:
        """Save metrics to file for persistence."""
        data = {
            "metrics": {
                k: {
                    "strategy_type": v.strategy_type,
                    "domain_pattern": v.domain_pattern,
                    "success_count": v.success_count,
                    "total_attempts": v.total_attempts,
                    "avg_latency_ms": v.avg_latency_ms,
                    "recent_results": list(v.recent_results),
                    "last_updated": v.last_updated.isoformat(),
                }
                for k, v in self.metrics.items()
            },
            "global_metrics": {
                "success_count": self.global_metrics.success_count,
                "total_attempts": self.global_metrics.total_attempts,
                "avg_latency_ms": self.global_metrics.avg_latency_ms,
                "recent_results": list(self.global_metrics.recent_results),
            },
            "config": self.config,
            "timestamp": datetime.now().isoformat(),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        self.logger.info(f"Metrics saved to {filepath}")

    def load_metrics(self, filepath: str) -> bool:
        """Load metrics from file."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            # Load individual metrics
            for key, metric_data in data.get("metrics", {}).items():
                metrics = AdaptiveMetrics(
                    strategy_type=metric_data["strategy_type"],
                    domain_pattern=metric_data["domain_pattern"],
                    success_count=metric_data["success_count"],
                    total_attempts=metric_data["total_attempts"],
                    avg_latency_ms=metric_data["avg_latency_ms"],
                    last_updated=datetime.fromisoformat(metric_data["last_updated"]),
                )
                metrics.recent_results = deque(metric_data["recent_results"], maxlen=10)
                self.metrics[key] = metrics

            # Load global metrics
            global_data = data.get("global_metrics", {})
            self.global_metrics.success_count = global_data.get("success_count", 0)
            self.global_metrics.total_attempts = global_data.get("total_attempts", 0)
            self.global_metrics.avg_latency_ms = global_data.get("avg_latency_ms", 0.0)
            self.global_metrics.recent_results = deque(
                global_data.get("recent_results", []), maxlen=10
            )

            # Load config
            if "config" in data:
                self.config.update(data["config"])

            self.logger.info(f"Metrics loaded from {filepath}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to load metrics from {filepath}: {e}")
            return False

    def reset_metrics(self) -> None:
        """Reset all metrics and statistics."""
        with self.lock:
            self.metrics.clear()
            self.global_metrics = AdaptiveMetrics("global", "*")
            self.results_history.clear()

        self.logger.info("All metrics reset")

    def __str__(self) -> str:
        """String representation of AttackCombinator."""
        return (
            f"AttackCombinator(strategies={len(self.attack_strategies)}, "
            f"chains={len(self.attack_chains)}, "
            f"metrics={len(self.metrics)}, "
            f"success_rate={self.global_metrics.success_rate:.2f})"
        )
