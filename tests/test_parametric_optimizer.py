import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

# This is a bit of a hack to get the test to run from the root directory
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.parametric_optimizer import ParametricOptimizer

class TestParametricOptimizer(unittest.TestCase):

    def setUp(self):
        """Set up a mock engine and basic optimizer configuration."""
        self.mock_engine = MagicMock()
        self.mock_engine.test_strategies_hybrid = AsyncMock()

        self.optimizer = ParametricOptimizer(
            engine=self.mock_engine,
            sites=["test.com"],
            ips={"1.1.1.1"},
            dns_cache={"test.com": "1.1.1.1"},
            port=443,
            base_strategies=[{"type": "split", "params": {"split_pos": 3}}],
            optimization_strategy="random_search",
            max_iterations=5  # Keep iterations low for testing
        )

    def test_initialization(self):
        """Test that the optimizer initializes correctly."""
        self.assertIsNotNone(self.optimizer)
        self.assertEqual(self.optimizer.optimization_strategy, "random_search")
        self.assertEqual(self.optimizer.max_iterations, 5)
        self.assertIn("split", self.optimizer.parameter_space)

    def test_get_random_params(self):
        """Test the random parameter generation logic."""
        params = self._get_random_params("split")
        self.assertIn("split_pos", params)
        self.assertIn(params["split_pos"], self.optimizer.parameter_space["split"]["split_pos"])
        self.assertIn("ttl", params)
        self.assertIn(params["ttl"], self.optimizer.parameter_space["split"]["ttl"])

    def test_run_optimization_random_search(self):
        """Test the main optimization loop with random search."""
        # Configure the mock to return decreasing scores (higher is better)
        # to ensure the optimizer correctly selects the best one.
        mock_results = [
            # Each call represents a test_strategies_hybrid run
            # Format: [{'success_rate': score}]
            [{"success_rate": 0.5}],
            [{"success_rate": 0.8}], # This should be the best
            [{"success_rate": 0.2}],
            [{"success_rate": 0.7}],
            [{"success_rate": 0.4}]
        ]
        self.mock_engine.test_strategies_hybrid.side_effect = mock_results

        # Run the optimization
        best_strategy = asyncio.run(self.optimizer.run_optimization())

        # Verification
        self.assertEqual(self.mock_engine.test_strategies_hybrid.call_count, 5)
        self.assertIsNotNone(best_strategy)
        self.assertEqual(best_strategy["type"], "split")

        # The params of the best strategy should correspond to the second call
        # Since we can't know the exact random values, we check that they are valid
        self.assertIn("split_pos", best_strategy["params"])
        self.assertIn("ttl", best_strategy["params"])

    def test_bayesian_optimization_mock(self):
        """Test that Bayesian optimization mode can be called (mocked)."""
        # This test only ensures the logic branch is taken, not the actual optimization
        self.optimizer.optimization_strategy = "bayesian"

        # Mock the optimizer library if it were used
        # For now, just ensure it runs without error and returns a strategy
        self.mock_engine.test_strategies_hybrid.side_effect = [[{"success_rate": 0.9}]] * 5

        best_strategy = asyncio.run(self.optimizer.run_optimization())

        self.assertIsNotNone(best_strategy)
        self.assertEqual(best_strategy["type"], "split")
        # In a real scenario, we'd check if the bayesian optimizer was called
        # For now, we just confirm it completed a run.
        self.assertGreaterEqual(self.mock_engine.test_strategies_hybrid.call_count, 1)

    def _get_random_params(self, strategy_type: str) -> dict:
        """Helper to call the private method for testing purposes."""
        return self.optimizer._get_random_params(strategy_type)

if __name__ == '__main__':
    unittest.main()
