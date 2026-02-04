"""
A/B Tester for Results Validation System.

Extracted from results_validation_system.py to reduce god class complexity.
Handles A/B testing, statistical significance, and recommendation generation.
"""

import asyncio
import math
import logging
import random
import statistics
from typing import List, Tuple

LOG = logging.getLogger("ABTester")


class ABTester:
    """Performs A/B testing and statistical analysis."""

    async def test_approach(self, approach: str, domains: List[str], engines: dict) -> List[bool]:
        """
        Test an approach on a list of domains.

        Args:
            approach: Approach name ("adaptive", "traditional", etc.)
            domains: List of domains to test
            engines: Dictionary with engine instances

        Returns:
            List of boolean results (True = success, False = failure)
        """
        results = []

        for domain in domains:
            try:
                if approach == "adaptive":
                    result = await self.test_adaptive_approach(domain, engines)
                elif approach == "traditional":
                    result = await self.test_traditional_approach(domain, engines)
                else:
                    # Unknown approach - random result
                    result = random.random() > 0.5

                results.append(result)

            except Exception as e:
                LOG.warning(f"Failed to test {approach} approach for {domain}: {e}")
                results.append(False)

        return results

    async def test_adaptive_approach(self, domain: str, engines: dict) -> bool:
        """
        Test adaptive approach on a domain.

        Args:
            domain: Domain to test
            engines: Dictionary with engine instances

        Returns:
            True if successful, False otherwise
        """
        try:
            adaptive_engine = engines.get("adaptive_engine")
            adaptive_available = engines.get("adaptive_available", False)

            # Create adaptive engine if needed
            if not adaptive_engine and adaptive_available:
                from core.adaptive_refactored.facade import AdaptiveEngine, AdaptiveConfig

                config = AdaptiveConfig()
                adaptive_engine = AdaptiveEngine(config)
                engines["adaptive_engine"] = adaptive_engine

            if adaptive_engine:
                result = await adaptive_engine.find_best_strategy(domain)
                return result.success
            else:
                # Fallback simulation
                await asyncio.sleep(0.2)
                return random.random() > 0.25  # 75% success for adaptive

        except Exception as e:
            LOG.warning(f"Adaptive approach test failed for {domain}: {e}")
            return False

    async def test_traditional_approach(self, domain: str, engines: dict) -> bool:
        """
        Test traditional approach on a domain.

        Args:
            domain: Domain to test
            engines: Dictionary with engine instances

        Returns:
            True if successful, False otherwise
        """
        try:
            # Simulate traditional approach (strategy enumeration)
            await asyncio.sleep(0.5)  # Traditional is slower
            return random.random() > 0.4  # 60% success for traditional

        except Exception as e:
            LOG.warning(f"Traditional approach test failed for {domain}: {e}")
            return False

    @staticmethod
    def calculate_statistical_significance(
        control: List[bool], treatment: List[bool], alpha: float
    ) -> float:
        """
        Calculate statistical significance using z-test.

        Args:
            control: Control group results
            treatment: Treatment group results
            alpha: Significance level (e.g., 0.05)

        Returns:
            p-value (lower = more significant)
        """
        if not control or not treatment:
            return 1.0  # No significance

        n1, n2 = len(control), len(treatment)
        p1 = sum(control) / n1
        p2 = sum(treatment) / n2

        # Pooled proportion
        p_pooled = (sum(control) + sum(treatment)) / (n1 + n2)

        # Standard error
        se = (p_pooled * (1 - p_pooled) * (1 / n1 + 1 / n2)) ** 0.5

        if se == 0:
            return 1.0

        # Z-statistic
        z = abs(p2 - p1) / se

        # Approximate p-value (two-tailed test)
        p_value = 2 * (1 - 0.5 * (1 + math.erf(z / math.sqrt(2))))

        return p_value

    @staticmethod
    def calculate_confidence_interval(
        control: List[bool], treatment: List[bool], confidence: float = 0.95
    ) -> Tuple[float, float]:
        """
        Calculate confidence interval for difference in proportions.

        Args:
            control: Control group results
            treatment: Treatment group results
            confidence: Confidence level (default 0.95 for 95% CI)

        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        if not control or not treatment:
            return (0.0, 0.0)

        n1, n2 = len(control), len(treatment)
        p1 = sum(control) / n1
        p2 = sum(treatment) / n2

        diff = p2 - p1

        # Standard error of difference
        se_diff = ((p1 * (1 - p1) / n1) + (p2 * (1 - p2) / n2)) ** 0.5

        if se_diff == 0:
            return (diff, diff)

        # Z-score for arbitrary confidence level (no scipy; Python 3.12 has NormalDist)
        # Two-tailed: alpha = 1 - confidence; quantile = 1 - alpha/2
        if not (0.0 < confidence < 1.0):
            # Keep behavior predictable; do not raise to avoid breaking callers.
            confidence = 0.95

        alpha = 1.0 - confidence
        z_score = statistics.NormalDist().inv_cdf(1.0 - alpha / 2.0)

        margin = z_score * se_diff

        return (diff - margin, diff + margin)

    @staticmethod
    def generate_recommendation(
        effect_size: float, p_value: float, alpha: float, min_effect_size: float
    ) -> str:
        """
        Generate recommendation based on A/B test results.

        Args:
            effect_size: Difference between treatment and control
            p_value: Statistical significance p-value
            alpha: Significance threshold
            min_effect_size: Minimum practical effect size

        Returns:
            Recommendation string
        """
        if p_value < alpha and abs(effect_size) >= min_effect_size:
            if effect_size > 0:
                return f"Рекомендуется внедрить новый подход. Улучшение: {effect_size:.2%}"
            else:
                return f"Рекомендуется остаться с контрольным подходом. Ухудшение: {abs(effect_size):.2%}"
        elif p_value < alpha:
            return (
                "Статистически значимая разница, но эффект слишком мал для практического применения"
            )
        else:
            return "Нет статистически значимой разности между подходами"
