"""
Strategy Tester for Results Validation System.

Extracted from results_validation_system.py to reduce god class complexity.
Handles strategy testing, consistency scoring, and reliability calculation.
"""

import asyncio
import statistics
import logging
import random
from typing import List

LOG = logging.getLogger("StrategyTester")


class StrategyTester:
    """Tests strategies and calculates reliability metrics."""

    async def test_strategy_once(
        self, strategy_name: str, domain: str, timeout: float, bypass_engine=None
    ) -> bool:
        """
        Test strategy once with timeout enforcement.

        Args:
            strategy_name: Name of strategy to test
            domain: Domain to test against
            timeout: Timeout in seconds (now properly enforced)
            bypass_engine: Optional bypass engine instance

        Returns:
            True if strategy succeeded, False otherwise
        """
        try:
            # Enforce timeout using asyncio.wait_for (fixes SR7)
            if bypass_engine:
                # Use real bypass engine
                async def run_test():
                    # TODO: Integrate with real engine
                    await asyncio.sleep(0.1)  # Simulate work
                    return random.random() > 0.3  # 70% success for demo

                result = await asyncio.wait_for(run_test(), timeout=timeout)
                return result
            else:
                # Fallback mode - simulation
                async def run_fallback():
                    await asyncio.sleep(0.1)
                    return random.random() > 0.4  # 60% success in fallback

                result = await asyncio.wait_for(run_fallback(), timeout=timeout)
                return result

        except asyncio.TimeoutError:
            LOG.warning(f"Strategy test timed out after {timeout}s: {strategy_name}/{domain}")
            return False

        except Exception as e:
            LOG.warning(f"Bypass engine test failed: {e}")
            return False

    @staticmethod
    def calculate_consistency_score(results: List[bool], response_times: List[float]) -> float:
        """
        Calculate consistency score from test results.

        Args:
            results: List of boolean test results
            response_times: List of response times in seconds

        Returns:
            Consistency score between 0.0 and 1.0
        """
        if len(results) < 2:
            return 1.0

        # Result consistency (less variation = higher score)
        result_variance = statistics.variance([1 if r else 0 for r in results])
        result_consistency = 1.0 - result_variance

        # Response time consistency
        if len(response_times) > 1:
            time_cv = statistics.stdev(response_times) / statistics.mean(response_times)
            time_consistency = max(0.0, 1.0 - time_cv)
        else:
            time_consistency = 1.0

        # Overall consistency score
        return (result_consistency + time_consistency) / 2

    @staticmethod
    def calculate_reliability_score(
        success_rate: float, consistency_score: float, avg_response_time: float
    ) -> float:
        """
        Calculate overall reliability score.

        Args:
            success_rate: Success rate (0.0 to 1.0)
            consistency_score: Consistency score (0.0 to 1.0)
            avg_response_time: Average response time in seconds

        Returns:
            Reliability score between 0.0 and 1.0
        """
        # Normalize response time (10 seconds = 0 score, 0 seconds = 1 score)
        time_score = max(0.0, 1.0 - (avg_response_time / 10.0))

        # Weighted reliability score
        reliability = (
            success_rate * 0.5  # 50% - success rate
            + consistency_score * 0.3  # 30% - consistency
            + time_score * 0.2  # 20% - performance
        )

        return min(1.0, reliability)
