"""
Strategy Optimizer for finding optimal DPI bypass strategies.

This module orchestrates the optimization process by generating strategy
variations, testing them, scoring, and ranking to find the best performing
strategies for a given domain.

Requirements: 1.1, 1.2, 1.5, 1.6
"""

import logging
import time
from typing import List, Optional, Dict, Any
from pathlib import Path

from core.optimization.models import Strategy, OptimizationResult, RankedStrategy
from core.optimization.variation_generator import VariationGenerator
from core.optimization.metrics_collector import PerformanceMetricsCollector
from core.optimization.scorer import OptimizationScorer
from core.optimization.ranker import StrategyRanker

LOG = logging.getLogger(__name__)


class StrategyOptimizer:
    """
    Orchestrates strategy optimization for a domain.

    Responsibilities:
    - Generate strategy variations
    - Test each variation with metrics collection
    - Score and rank strategies
    - Present results to user

    Requirements: 1.1, 1.2, 1.5, 1.6
    """

    def __init__(
        self,
        adaptive_engine: Any,
        metrics_collector: Optional[PerformanceMetricsCollector] = None,
        variation_generator: Optional[VariationGenerator] = None,
    ):
        """
        Initialize the strategy optimizer.

        Args:
            adaptive_engine: AdaptiveEngine instance for testing strategies
            metrics_collector: Optional PerformanceMetricsCollector instance
            variation_generator: Optional VariationGenerator instance
        """
        self.adaptive_engine = adaptive_engine
        self.metrics_collector = metrics_collector or PerformanceMetricsCollector()
        self.variation_generator = variation_generator or VariationGenerator()
        self.scorer = OptimizationScorer()
        self.ranker = StrategyRanker()
        self.logger = LOG

    async def optimize(
        self,
        domain: str,
        min_strategies: int = 3,
        max_trials: int = 20,
    ) -> OptimizationResult:
        """
        Find optimal strategy for domain.

        Orchestrates the full optimization process:
        1. Get base strategies (known or generate defaults)
        2. Generate variations
        3. Test each variation
        4. Collect metrics
        5. Score and rank
        6. Return results

        Args:
            domain: Target domain to optimize
            min_strategies: Minimum working strategies to find
            max_trials: Maximum test iterations

        Returns:
            OptimizationResult with ranked strategies

        Requirements: 1.1, 1.2, 1.5, 1.6
        """
        self.logger.info(f"🚀 Starting optimization for {domain}")
        self.logger.info(f"   Min strategies: {min_strategies}, Max trials: {max_trials}")

        start_time = time.time()

        # Step 1: Get base strategies
        base_strategies = self.get_base_strategies(domain)
        self.logger.info(f"📋 Found {len(base_strategies)} base strategies")

        # Step 2: Generate all candidate strategies
        all_strategies = []
        seen_strategies = set()  # Track unique strategies by (type, attacks, params) tuple

        def strategy_key(strategy):
            """Create a hashable key for a strategy including params."""
            # Convert params dict to a sorted tuple of items for hashing
            params_tuple = tuple(sorted(strategy.params.items())) if strategy.params else ()
            return (strategy.type, tuple(strategy.attacks), params_tuple)

        # Add base strategies
        for base_strategy in base_strategies:
            key = strategy_key(base_strategy)
            if key not in seen_strategies:
                all_strategies.append(base_strategy)
                seen_strategies.add(key)

        # Generate variations from each base strategy
        for base_strategy in base_strategies:
            variations = self.variation_generator.generate_variations(
                base_strategy,
                max_variations=(
                    max_trials // len(base_strategies) if base_strategies else max_trials
                ),
            )

            # Add only unique variations
            for variation in variations:
                key = strategy_key(variation)
                if key not in seen_strategies and len(all_strategies) < max_trials:
                    all_strategies.append(variation)
                    seen_strategies.add(key)

            self.logger.info(f"   Generated {len(variations)} variations from {base_strategy.type}")

        self.logger.info(f"🧪 Testing {len(all_strategies)} unique strategies total")

        # Step 3: Test each strategy and collect metrics
        tested_strategies = []
        working_count = 0

        for idx, strategy in enumerate(all_strategies, 1):
            self.logger.info(
                f"   [{idx}/{len(all_strategies)}] Testing {strategy.type} "
                f"with attacks={strategy.attacks}"
            )

            try:
                # Test the strategy
                test_result = await self._test_strategy(domain, strategy)

                if test_result:
                    metrics, pcap_file = test_result

                    # Calculate score
                    score = self.scorer.calculate_score(metrics)

                    # Store result
                    tested_strategies.append((strategy, score, metrics))

                    if metrics.success:
                        working_count += 1
                        self.logger.info(
                            f"      ✅ Success! Score: {score:.2f}, "
                            f"Retrans: {metrics.retransmission_count}, "
                            f"TTFB: {metrics.ttfb_ms:.2f}ms"
                        )

                        # Check if we have enough working strategies
                        if working_count >= min_strategies:
                            self.logger.info(
                                f"🎯 Found {working_count} working strategies "
                                f"(min: {min_strategies}), stopping early"
                            )
                            break
                    else:
                        self.logger.info(f"      ❌ Failed: {metrics.error_message}")
                else:
                    self.logger.warning(f"      ⚠️ Test returned no result")

            except Exception as e:
                self.logger.error(f"      ❌ Error testing strategy: {e}", exc_info=True)
                continue

        # Step 4: Rank strategies
        ranked_strategies = self.ranker.rank_strategies(tested_strategies)

        # Step 5: Determine best strategy
        best_strategy = None
        if ranked_strategies and working_count > 0:
            # Best is rank 1 (highest score) - but only if we have working strategies
            # Find the first working strategy in the ranked list
            for ranked in ranked_strategies:
                if ranked.metrics.success:
                    best_strategy = ranked
                    break

        # Calculate optimization time
        optimization_time = time.time() - start_time

        # Create result
        result = OptimizationResult(
            domain=domain,
            strategies=ranked_strategies,
            best_strategy=best_strategy,
            total_tested=len(tested_strategies),
            total_working=working_count,
            optimization_time=optimization_time,
        )

        self.logger.info(
            f"✨ Optimization complete in {optimization_time:.2f}s: "
            f"{working_count}/{len(tested_strategies)} strategies worked"
        )

        if best_strategy:
            self.logger.info(
                f"🏆 Best strategy: {best_strategy.strategy.type} "
                f"(score: {best_strategy.score:.2f})"
            )
        else:
            self.logger.warning("⚠️ No working strategies found")

        return result

    def get_base_strategies(self, domain: str) -> List[Strategy]:
        """
        Get known strategies for domain or generate defaults.

        Checks if there are any known working strategies for the domain
        in the configuration. If not, generates a set of default strategies
        to test.

        Strategy sources (in priority order):
        1. domain_registry (domain_rules.json) - manual rules
        2. adaptive_knowledge.json - auto-discovered strategies
        3. Default generated strategies

        Args:
            domain: Target domain

        Returns:
            List of base strategies to start optimization from

        Requirements: 1.1
        """
        self.logger.debug(f"🔍 Looking for base strategies for {domain}")

        # Try to get strategies from adaptive engine's domain registry
        known_strategies = []

        # Source 1: domain_registry (domain_rules.json)
        try:
            if hasattr(self.adaptive_engine, "domain_registry"):
                # Check if domain has a rule
                rule = self.adaptive_engine.domain_registry.get_rule(domain)

                if rule and hasattr(rule, "attacks"):
                    # Convert rule to Strategy
                    strategy = Strategy(
                        type=rule.attacks[0] if rule.attacks else "split",
                        attacks=rule.attacks,
                        params=getattr(rule, "params", {}),
                    )
                    known_strategies.append(strategy)
                    self.logger.debug(
                        f"   ✅ Found strategy from domain_rules.json: {strategy.type}"
                    )
        except Exception as e:
            self.logger.debug(f"   ⚠️ Could not load strategies from domain_registry: {e}")

        # Source 2: adaptive_knowledge.json (auto-discovered strategies)
        try:
            if (
                hasattr(self.adaptive_engine, "adaptive_knowledge")
                and self.adaptive_engine.adaptive_knowledge
            ):
                adaptive_strategies = (
                    self.adaptive_engine.adaptive_knowledge.get_strategies_for_domain(domain)
                )

                if adaptive_strategies:
                    self.logger.debug(
                        f"   📚 Found {len(adaptive_strategies)} strategies in adaptive_knowledge.json"
                    )

                    # Add top-3 strategies from adaptive_knowledge (sorted by success rate)
                    for i, strategy_record in enumerate(adaptive_strategies[:3]):
                        strategy = Strategy(
                            type=strategy_record.strategy_name,
                            attacks=[strategy_record.strategy_name],
                            params=strategy_record.strategy_params,
                        )
                        known_strategies.append(strategy)
                        self.logger.debug(
                            f"   ✅ Added strategy #{i+1} from adaptive_knowledge.json: "
                            f"{strategy.type} (success_rate: {strategy_record.success_rate():.2%})"
                        )
                else:
                    self.logger.debug(
                        f"   📚 No strategies in adaptive_knowledge.json for {domain}"
                    )
        except Exception as e:
            self.logger.debug(f"   ⚠️ Could not load strategies from adaptive_knowledge: {e}")

        # If we have known strategies, return them (possibly with defaults)
        if known_strategies:
            self.logger.debug(f"   🎯 Returning {len(known_strategies)} known strategies")

            # Add some defaults if we have less than 5 strategies
            if len(known_strategies) < 5:
                self.logger.debug("   📝 Adding default strategies to reach minimum of 5")
                default_strategies = self.variation_generator.generate_default_strategies(domain)

                # Add defaults that aren't already in known_strategies
                for default in default_strategies:
                    if not any(
                        k.type == default.type and k.attacks == default.attacks
                        for k in known_strategies
                    ):
                        known_strategies.append(default)
                        if len(known_strategies) >= 5:
                            break

            return known_strategies

        # Source 3: Generate default strategies as last resort
        self.logger.debug("   📝 No known strategies, generating defaults")
        default_strategies = self.variation_generator.generate_default_strategies(domain)

        return default_strategies

    async def _test_strategy(
        self,
        domain: str,
        strategy: Strategy,
    ) -> Optional[tuple]:
        """
        Test a single strategy and collect metrics.

        Args:
            domain: Target domain
            strategy: Strategy to test

        Returns:
            Tuple of (PerformanceMetrics, pcap_file_path) or None if test failed
        """
        try:
            # Record start time
            start_time = time.time()

            # Test the strategy using adaptive engine
            # This will capture PCAP and test the connection
            test_result = await self._run_strategy_test(domain, strategy)

            # Record end time
            end_time = time.time()

            # Extract success and pcap_file from result
            if isinstance(test_result, dict):
                test_success = test_result.get("success", False)
                pcap_file = test_result.get("pcap_file") or test_result.get("capture_path")
            elif hasattr(test_result, "success"):
                test_success = test_result.success
                pcap_file = getattr(test_result, "pcap_file", None)
                if not pcap_file and hasattr(test_result, "artifacts"):
                    pcap_file = getattr(test_result.artifacts, "pcap_file", None)
            else:
                test_success = bool(test_result)
                pcap_file = None

            # If no PCAP file, try to find the most recent one for this domain
            if not pcap_file:
                pcap_file = self._find_recent_pcap_file(domain)

            # Collect metrics from PCAP (or create fallback metrics)
            if pcap_file and Path(pcap_file).exists():
                metrics = await self.metrics_collector.collect_metrics(
                    domain=domain,
                    strategy=(
                        strategy.__dict__
                        if hasattr(strategy, "__dict__")
                        else {
                            "type": strategy.type,
                            "attacks": strategy.attacks,
                            "params": strategy.params,
                        }
                    ),
                    pcap_file=pcap_file,
                    start_time=start_time,
                    end_time=end_time,
                )
            else:
                # Create fallback metrics without PCAP
                from core.optimization.models import PerformanceMetrics

                metrics = PerformanceMetrics(
                    retransmission_count=0,
                    ttfb_ms=(end_time - start_time) * 1000,
                    total_time_ms=(end_time - start_time) * 1000,
                    packets_sent=0,
                    packets_received=1 if test_success else 0,
                    success=test_success,
                    error_message=None if test_success else "No PCAP file available",
                )

            return (metrics, pcap_file)

        except Exception as e:
            self.logger.error(f"Error testing strategy: {e}", exc_info=True)
            return None

    async def _run_strategy_test(
        self,
        domain: str,
        strategy: Strategy,
    ):
        """
        Run the actual strategy test using adaptive engine.

        Args:
            domain: Target domain
            strategy: Strategy to test

        Returns:
            Test result (dict or object with success, pcap_file attributes)
        """
        try:
            # Use adaptive engine to test the strategy
            if hasattr(self.adaptive_engine, "test_strategy"):
                result = await self.adaptive_engine.test_strategy(domain, strategy)
                return result
            elif hasattr(self.adaptive_engine, "_test_strategy_with_capture"):
                # Fallback to internal method
                result = await self.adaptive_engine._test_strategy_with_capture(domain, strategy)
                return result
            else:
                # Fallback: assume test completed
                self.logger.warning("AdaptiveEngine doesn't have test_strategy method")
                return {"success": True, "pcap_file": None}

        except Exception as e:
            self.logger.error(f"Error running strategy test: {e}")
            return {"success": False, "error": str(e), "pcap_file": None}

    def _find_recent_pcap_file(self, domain: str) -> Optional[str]:
        """
        Find the most recent PCAP file for a domain.

        Args:
            domain: Target domain

        Returns:
            Path to most recent PCAP file or None
        """
        pcap_dir = Path("temp_pcap")
        if not pcap_dir.exists():
            return None

        safe_domain = domain.replace(".", "_")

        # Find all PCAP files for this domain
        pcap_files = list(pcap_dir.glob(f"*{safe_domain}*.pcap"))

        if not pcap_files:
            return None

        # Return the most recently modified file
        most_recent = max(pcap_files, key=lambda p: p.stat().st_mtime)
        return str(most_recent)
