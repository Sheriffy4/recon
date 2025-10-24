import random
from typing import List, Dict, Any, Optional


class ParametricOptimizer:
    """
    A class to perform parametric optimization of bypass strategies.
    Supports random search and can be extended for more advanced methods.
    """

    def __init__(
        self,
        engine: Any,
        sites: List[str],
        ips: set,
        dns_cache: Dict[str, str],
        port: int,
        base_strategies: List[Dict[str, Any]],
        optimization_strategy: str = "random_search",
        max_iterations: int = 20,
    ):
        self.engine = engine
        self.sites = sites
        self.ips = ips
        self.dns_cache = dns_cache
        self.port = port
        self.base_strategies = base_strategies
        self.optimization_strategy = optimization_strategy
        self.max_iterations = max_iterations
        self.parameter_space = self._define_parameter_space()
        self.best_strategy = None
        self.best_score = -1.0

    def _define_parameter_space(self) -> Dict[str, Dict[str, list]]:
        """Defines the search space for strategy parameters."""
        return {
            "split": {
                "split_pos": list(range(1, 11)),
                "ttl": [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 128],
            },
            "disorder": {
                "split_pos": list(range(1, 11)),
                "ttl": [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 128],
            },
            "multisplit": {
                "split_count": list(range(2, 9)),
                "split_seqovl": [0, 5, 10, 15, 20, 25, 30],
                "ttl": [1, 2, 3, 4, 5, 6, 7, 8],
            },
            "ipfrag": {
                "fragment_size": [8, 16, 24, 32, 48, 64],
                "ttl": [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 128],
            },
        }

    def _get_random_params(self, strategy_type: str) -> Optional[Dict[str, Any]]:
        """Generates a set of random parameters for a given strategy type."""
        if strategy_type not in self.parameter_space:
            return None

        params = {}
        for param, values in self.parameter_space[strategy_type].items():
            params[param] = random.choice(values)
        return params

    async def _evaluate_strategy(self, strategy_task: Dict[str, Any]) -> float:
        """Evaluates a single strategy and returns its success rate."""
        results = await self.engine.test_strategies_hybrid(
            strategies=[strategy_task],
            test_sites=self.sites,
            ips=self.ips,
            dns_cache=self.dns_cache,
            port=self.port,
            domain=next(iter(self.dns_cache.keys())),
            strategy_evaluation_mode=True,  # Signal to engine to return raw score
        )
        if not results:
            return 0.0
        return results[0].get("success_rate", 0.0)

    async def run_optimization(self) -> Optional[Dict[str, Any]]:
        """
        Runs the optimization loop using the selected strategy.
        """
        if self.optimization_strategy == "random_search":
            return await self._random_search()
        elif self.optimization_strategy == "bayesian":
            # Placeholder for a more advanced optimization method
            print(
                "Bayesian optimization is not yet implemented. Falling back to random search."
            )
            return await self._random_search()
        else:
            print(f"Unknown optimization strategy: {self.optimization_strategy}")
            return None

    async def _random_search(self) -> Optional[Dict[str, Any]]:
        """Performs a random search over the parameter space."""
        for i in range(self.max_iterations):
            # Pick a base strategy to optimize
            base_strategy = random.choice(self.base_strategies)
            strategy_type = base_strategy.get("type")

            if not strategy_type or strategy_type not in self.parameter_space:
                continue

            # Generate new parameters
            new_params = self._get_random_params(strategy_type)
            if not new_params:
                continue

            # Create the full strategy task
            strategy_task = {"type": strategy_type, "params": new_params}

            print(f"[{i+1}/{self.max_iterations}] Testing: {strategy_task}")

            # Evaluate
            score = await self._evaluate_strategy(strategy_task)
            print(f"  -> Score: {score:.2f}")

            # Update best score
            if score > self.best_score:
                self.best_score = score
                self.best_strategy = strategy_task
                print(f"  -> New best score! Strategy: {self.best_strategy}")

        return self.best_strategy
