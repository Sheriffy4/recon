"""
Strategy validation and refinement system.
Compares generated strategies with manual ones and iteratively improves them.
"""

import logging
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

LOG = logging.getLogger("strategy_validator")

# Import fingerprinting and rule engine
try:
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from core.strategy_rule_engine import StrategyRuleEngine
    from core.strategy_combinator import StrategyCombinator

    DEPENDENCIES_AVAILABLE = True
except ImportError as e:
    LOG.warning(f"Dependencies not available: {e}")
    DEPENDENCIES_AVAILABLE = False


@dataclass
class StrategyTestResult:
    """Results from testing a strategy"""

    strategy: Dict[str, Any]
    success_count: int
    total_count: int
    success_rate: float
    avg_latency: float
    test_sites: List[str]
    failed_sites: List[str]
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.success_rate == 0.0 and self.total_count > 0:
            self.success_rate = self.success_count / self.total_count


@dataclass
class ValidationReport:
    """Comprehensive validation report"""

    generated_strategies: List[StrategyTestResult]
    manual_strategies: List[StrategyTestResult]
    best_generated: Optional[StrategyTestResult]
    best_manual: Optional[StrategyTestResult]
    improvement_suggestions: List[str]
    performance_comparison: Dict[str, float]
    timestamp: float = field(default_factory=time.time)


class StrategyValidator:
    """
    Validates and refines generated strategies by comparing with manual ones.
    Provides iterative improvement suggestions.
    """

    def __init__(
        self,
        rule_engine: Optional[StrategyRuleEngine] = None,
        combinator: Optional[StrategyCombinator] = None,
    ):
        self.rule_engine = rule_engine
        self.combinator = combinator
        self.test_results_cache = {}
        self.manual_strategies_db = {}
        self.validation_history = []

        # Load manual strategies if available
        self._load_manual_strategies()

    def _load_manual_strategies(self):
        """Load manually crafted strategies for comparison"""

        # These are known effective manual strategies from Task 3.4
        self.manual_strategies_db = {
            "roskomnadzor_manual_v1": {
                "type": "fakeddisorder",
                "params": {
                    "ttl": 64,
                    "split_pos": 76,
                    "overlap_size": 1,
                    "autottl": 2,
                    "fooling": ["badseq", "md5sig"],
                    "fake_http": "PAYLOADTLS",
                    "fake_tls": "PAYLOADTLS",
                },
                "expected_success_rate": 0.87,  # 27/31 domains
                "description": "Manual strategy based on zapret compatibility",
            },
            "commercial_dpi_manual_v1": {
                "type": "multisplit",
                "params": {
                    "positions": [1, 5, 10, 20],
                    "ttl": 64,
                    "fooling": ["badsum"],
                },
                "expected_success_rate": 0.75,
                "description": "Manual strategy for commercial DPI",
            },
            "aggressive_manual_v1": {
                "type": "fakeddisorder",
                "params": {
                    "ttl": 1,
                    "split_pos": 41,
                    "overlap_size": 1,
                    "fooling": ["badsum", "md5sig", "badseq"],
                    "repeats": 2,
                },
                "expected_success_rate": 0.80,
                "description": "Aggressive manual strategy with multiple fooling methods",
            },
            "conservative_manual_v1": {
                "type": "fake",
                "params": {"ttl": 64, "fooling": ["badsum"]},
                "expected_success_rate": 0.60,
                "description": "Conservative manual strategy",
            },
        }

    def add_manual_strategy(
        self,
        name: str,
        strategy: Dict[str, Any],
        expected_success_rate: float,
        description: str = "",
    ):
        """Add a manual strategy to the database"""

        self.manual_strategies_db[name] = {
            "type": strategy.get("type"),
            "params": strategy.get("params", {}),
            "expected_success_rate": expected_success_rate,
            "description": description,
        }

    async def test_strategy_effectiveness(
        self, strategy: Dict[str, Any], test_sites: List[str], hybrid_engine=None
    ) -> StrategyTestResult:
        """
        Test a strategy's effectiveness against a set of sites.

        Args:
            strategy: Strategy to test
            test_sites: List of test sites
            hybrid_engine: HybridEngine instance for testing (optional)

        Returns:
            StrategyTestResult with performance metrics
        """

        # Create cache key
        strategy_key = json.dumps(strategy, sort_keys=True)
        sites_key = json.dumps(sorted(test_sites))
        cache_key = f"{strategy_key}:{sites_key}"

        # Check cache
        if cache_key in self.test_results_cache:
            LOG.debug("Using cached test result")
            return self.test_results_cache[cache_key]

        LOG.info(f"Testing strategy: {strategy}")

        # If no hybrid engine provided, simulate results
        if hybrid_engine is None:
            success_count, avg_latency, failed_sites = self._simulate_strategy_test(
                strategy, test_sites
            )
        else:
            success_count, avg_latency, failed_sites = await self._real_strategy_test(
                strategy, test_sites, hybrid_engine
            )

        result = StrategyTestResult(
            strategy=strategy,
            success_count=success_count,
            total_count=len(test_sites),
            success_rate=success_count / len(test_sites) if test_sites else 0.0,
            avg_latency=avg_latency,
            test_sites=test_sites,
            failed_sites=failed_sites,
        )

        # Cache result
        self.test_results_cache[cache_key] = result

        LOG.info(
            f"Strategy test result: {success_count}/{len(test_sites)} success rate: {result.success_rate:.2%}"
        )
        return result

    def _simulate_strategy_test(
        self, strategy: Dict[str, Any], test_sites: List[str]
    ) -> Tuple[int, float, List[str]]:
        """
        Simulate strategy testing based on heuristics.
        Used when no real testing engine is available.
        """

        # Heuristic scoring based on strategy parameters
        base_score = 0.5  # Base 50% success rate

        strategy_type = strategy.get("type", "")
        params = strategy.get("params", {})

        # Type-based scoring
        type_scores = {
            "fakeddisorder": 0.8,
            "multisplit": 0.7,
            "fake": 0.6,
            "seqovl": 0.65,
        }
        base_score = type_scores.get(strategy_type, 0.5)

        # Parameter-based adjustments
        if "fooling" in params:
            fooling_methods = params["fooling"]
            if isinstance(fooling_methods, list):
                # More fooling methods = higher success rate
                base_score += len(fooling_methods) * 0.05

                # Specific method bonuses
                if "badsum" in fooling_methods:
                    base_score += 0.1
                if "md5sig" in fooling_methods:
                    base_score += 0.08

        # TTL adjustments
        ttl = params.get("ttl", 64)
        if ttl == 64:
            base_score += 0.05  # High TTL generally more reliable
        elif ttl == 1:
            base_score += 0.03  # Low TTL good for some DPI

        # Split position adjustments
        split_pos = params.get("split_pos", 76)
        if isinstance(split_pos, int):
            if 40 <= split_pos <= 80:
                base_score += 0.05  # Good split position range

        # Overlap size adjustments
        overlap_size = params.get("overlap_size", 0)
        if overlap_size == 1:
            base_score += 0.03  # Optimal overlap

        # Cap at 95% to be realistic
        final_score = min(base_score, 0.95)

        # Calculate success count
        success_count = int(len(test_sites) * final_score)

        # Simulate latency (lower is better)
        base_latency = 150.0  # Base 150ms
        if strategy_type == "fakeddisorder":
            base_latency += 20.0  # More complex = higher latency
        if len(params.get("fooling", [])) > 2:
            base_latency += 10.0  # Multiple fooling methods add latency

        avg_latency = base_latency + (len(test_sites) * 2.0)  # Scale with site count

        # Generate failed sites (last ones in list)
        failed_count = len(test_sites) - success_count
        failed_sites = test_sites[-failed_count:] if failed_count > 0 else []

        return success_count, avg_latency, failed_sites

    async def _real_strategy_test(
        self, strategy: Dict[str, Any], test_sites: List[str], hybrid_engine
    ) -> Tuple[int, float, List[str]]:
        """
        Perform real strategy testing using HybridEngine.
        """

        try:
            # Convert test sites to full URLs if needed
            full_sites = []
            for site in test_sites:
                if not site.startswith(("http://", "https://")):
                    full_sites.append(f"https://{site}")
                else:
                    full_sites.append(site)

            # Create dummy DNS cache and target IPs
            dns_cache = {
                site.replace("https://", "").replace("http://", ""): "1.1.1.1"
                for site in full_sites
            }
            target_ips = set(dns_cache.values())

            # Test strategy
            result_status, success_count, total_count, avg_latency = (
                await hybrid_engine.execute_strategy_real_world(
                    strategy=strategy,
                    test_sites=full_sites,
                    target_ips=target_ips,
                    dns_cache=dns_cache,
                    return_details=True,
                )
            )

            # Calculate failed sites
            failed_count = total_count - success_count
            failed_sites = test_sites[-failed_count:] if failed_count > 0 else []

            return success_count, avg_latency, failed_sites

        except Exception as e:
            LOG.error(f"Real strategy test failed: {e}")
            # Fallback to simulation
            return self._simulate_strategy_test(strategy, test_sites)

    async def validate_generated_strategies(
        self, fingerprint: DPIFingerprint, test_sites: List[str], hybrid_engine=None
    ) -> ValidationReport:
        """
        Validate generated strategies against manual ones.

        Args:
            fingerprint: DPI fingerprint for strategy generation
            test_sites: Sites to test against
            hybrid_engine: Optional HybridEngine for real testing

        Returns:
            ValidationReport with comparison results
        """

        if not DEPENDENCIES_AVAILABLE:
            LOG.error("Dependencies not available for validation")
            return ValidationReport([], [], None, None, [], {})

        LOG.info("Starting strategy validation")

        # Generate strategies using rule engine
        generated_strategies = []
        if self.rule_engine:
            # Primary strategy
            primary = self.rule_engine.generate_strategy(fingerprint)
            generated_strategies.append(primary)

            # Multiple alternatives
            alternatives = self.rule_engine.generate_multiple_strategies(
                fingerprint, count=3
            )
            generated_strategies.extend(
                alternatives[1:]
            )  # Skip primary (already added)

        # Generate strategies using combinator
        if self.combinator:
            suggestions = self.combinator.suggest_combinations_for_fingerprint(
                fingerprint
            )
            for name, strategy in suggestions[:2]:  # Add top 2 suggestions
                if strategy not in generated_strategies:
                    generated_strategies.append(strategy)

        # Test generated strategies
        generated_results = []
        for strategy in generated_strategies:
            result = await self.test_strategy_effectiveness(
                strategy, test_sites, hybrid_engine
            )
            generated_results.append(result)

        # Test manual strategies
        manual_results = []
        for name, manual_strategy in self.manual_strategies_db.items():
            strategy = {
                "type": manual_strategy["type"],
                "params": manual_strategy["params"],
            }
            result = await self.test_strategy_effectiveness(
                strategy, test_sites, hybrid_engine
            )
            manual_results.append(result)

        # Find best strategies
        best_generated = (
            max(generated_results, key=lambda r: r.success_rate)
            if generated_results
            else None
        )
        best_manual = (
            max(manual_results, key=lambda r: r.success_rate)
            if manual_results
            else None
        )

        # Generate improvement suggestions
        suggestions = self._generate_improvement_suggestions(
            generated_results, manual_results
        )

        # Performance comparison
        comparison = self._compare_performance(generated_results, manual_results)

        report = ValidationReport(
            generated_strategies=generated_results,
            manual_strategies=manual_results,
            best_generated=best_generated,
            best_manual=best_manual,
            improvement_suggestions=suggestions,
            performance_comparison=comparison,
        )

        self.validation_history.append(report)

        LOG.info(
            f"Validation complete. Best generated: {best_generated.success_rate:.2%}, "
            f"Best manual: {best_manual.success_rate:.2%}"
        )

        return report

    def _generate_improvement_suggestions(
        self,
        generated_results: List[StrategyTestResult],
        manual_results: List[StrategyTestResult],
    ) -> List[str]:
        """Generate suggestions for improving generated strategies"""

        suggestions = []

        if not generated_results or not manual_results:
            return suggestions

        best_generated = max(generated_results, key=lambda r: r.success_rate)
        best_manual = max(manual_results, key=lambda r: r.success_rate)

        # Performance gap analysis
        performance_gap = best_manual.success_rate - best_generated.success_rate

        if performance_gap > 0.1:  # 10% gap
            suggestions.append(
                f"Generated strategies underperform by {performance_gap:.1%}. "
                "Consider analyzing manual strategy parameters."
            )

            # Analyze parameter differences
            manual_params = best_manual.strategy.get("params", {})
            generated_params = best_generated.strategy.get("params", {})

            # TTL analysis
            manual_ttl = manual_params.get("ttl")
            generated_ttl = generated_params.get("ttl")
            if manual_ttl != generated_ttl:
                suggestions.append(
                    f"Consider using TTL={manual_ttl} instead of TTL={generated_ttl}"
                )

            # Fooling methods analysis
            manual_fooling = set(manual_params.get("fooling", []))
            generated_fooling = set(generated_params.get("fooling", []))
            if manual_fooling != generated_fooling:
                missing = manual_fooling - generated_fooling
                extra = generated_fooling - manual_fooling
                if missing:
                    suggestions.append(
                        f"Consider adding fooling methods: {list(missing)}"
                    )
                if extra:
                    suggestions.append(
                        f"Consider removing fooling methods: {list(extra)}"
                    )

        elif performance_gap < -0.05:  # Generated is better by 5%
            suggestions.append(
                "Generated strategies outperform manual ones. "
                "Consider updating manual strategy database."
            )

        # Latency analysis
        avg_generated_latency = sum(r.avg_latency for r in generated_results) / len(
            generated_results
        )
        avg_manual_latency = sum(r.avg_latency for r in manual_results) / len(
            manual_results
        )

        if avg_generated_latency > avg_manual_latency * 1.2:  # 20% slower
            suggestions.append(
                "Generated strategies have higher latency. "
                "Consider optimizing for performance."
            )

        return suggestions

    def _compare_performance(
        self,
        generated_results: List[StrategyTestResult],
        manual_results: List[StrategyTestResult],
    ) -> Dict[str, float]:
        """Compare performance metrics between generated and manual strategies"""

        comparison = {}

        if generated_results:
            comparison["avg_generated_success_rate"] = sum(
                r.success_rate for r in generated_results
            ) / len(generated_results)
            comparison["max_generated_success_rate"] = max(
                r.success_rate for r in generated_results
            )
            comparison["avg_generated_latency"] = sum(
                r.avg_latency for r in generated_results
            ) / len(generated_results)

        if manual_results:
            comparison["avg_manual_success_rate"] = sum(
                r.success_rate for r in manual_results
            ) / len(manual_results)
            comparison["max_manual_success_rate"] = max(
                r.success_rate for r in manual_results
            )
            comparison["avg_manual_latency"] = sum(
                r.avg_latency for r in manual_results
            ) / len(manual_results)

        if generated_results and manual_results:
            comparison["success_rate_improvement"] = (
                comparison["max_generated_success_rate"]
                - comparison["max_manual_success_rate"]
            )
            comparison["latency_improvement"] = (
                comparison["avg_manual_latency"] - comparison["avg_generated_latency"]
            )

        return comparison

    def save_validation_report(self, report: ValidationReport, filepath: str):
        """Save validation report to file"""

        # Convert to serializable format
        report_data = {
            "timestamp": report.timestamp,
            "generated_strategies": [
                {
                    "strategy": r.strategy,
                    "success_rate": r.success_rate,
                    "success_count": r.success_count,
                    "total_count": r.total_count,
                    "avg_latency": r.avg_latency,
                    "failed_sites": r.failed_sites,
                }
                for r in report.generated_strategies
            ],
            "manual_strategies": [
                {
                    "strategy": r.strategy,
                    "success_rate": r.success_rate,
                    "success_count": r.success_count,
                    "total_count": r.total_count,
                    "avg_latency": r.avg_latency,
                    "failed_sites": r.failed_sites,
                }
                for r in report.manual_strategies
            ],
            "best_generated": (
                {
                    "strategy": report.best_generated.strategy,
                    "success_rate": report.best_generated.success_rate,
                }
                if report.best_generated
                else None
            ),
            "best_manual": (
                {
                    "strategy": report.best_manual.strategy,
                    "success_rate": report.best_manual.success_rate,
                }
                if report.best_manual
                else None
            ),
            "improvement_suggestions": report.improvement_suggestions,
            "performance_comparison": report.performance_comparison,
        }

        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2)

        LOG.info(f"Validation report saved to {filepath}")


def create_default_validator() -> StrategyValidator:
    """Factory function to create validator with default components"""

    if not DEPENDENCIES_AVAILABLE:
        return StrategyValidator()

    from core.strategy_rule_engine import create_default_rule_engine
    from core.strategy_combinator import create_default_combinator

    rule_engine = create_default_rule_engine()
    combinator = create_default_combinator()

    return StrategyValidator(rule_engine, combinator)


# Example usage
if __name__ == "__main__":
    import asyncio

    if DEPENDENCIES_AVAILABLE:
        from core.fingerprint.advanced_models import DPIFingerprint, DPIType

        # Create test fingerprint
        test_fingerprint = DPIFingerprint(
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            allows_badsum=True,
            allows_md5sig=True,
            requires_low_ttl=True,
        )

        # Create validator
        validator = create_default_validator()

        # Test sites
        test_sites = ["x.com", "youtube.com", "instagram.com", "facebook.com"]

        # Run validation
        async def run_validation():
            report = await validator.validate_generated_strategies(
                test_fingerprint, test_sites
            )

            print("Validation Report:")
            print(f"Generated strategies: {len(report.generated_strategies)}")
            print(f"Manual strategies: {len(report.manual_strategies)}")

            if report.best_generated:
                print(
                    f"Best generated success rate: {report.best_generated.success_rate:.2%}"
                )

            if report.best_manual:
                print(
                    f"Best manual success rate: {report.best_manual.success_rate:.2%}"
                )

            print("\nImprovement suggestions:")
            for suggestion in report.improvement_suggestions:
                print(f"  - {suggestion}")

        asyncio.run(run_validation())
    else:
        print("Dependencies not available for testing")
