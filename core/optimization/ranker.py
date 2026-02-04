"""
Strategy ranker for optimization results.

This module provides functionality to rank strategies based on their
optimization scores, creating a sorted list of RankedStrategy objects.
"""

from typing import List, Tuple, TYPE_CHECKING
import importlib.util
from pathlib import Path

if TYPE_CHECKING:
    from core.optimization.models import Strategy, PerformanceMetrics, RankedStrategy


# Import models module directly to avoid core.__init__ triggering scapy imports
_models_path = Path(__file__).parent / "models.py"
_spec = importlib.util.spec_from_file_location("optimization_models_ranker", _models_path)
_models = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_models)


class StrategyRanker:
    """
    Ranks strategies based on their optimization scores.

    Takes a list of strategies with their scores and metrics, and produces
    a ranked list where rank 1 is the best (highest score).
    """

    def rank_strategies(
        self,
        strategies_with_scores: List[Tuple["Strategy", float, "PerformanceMetrics"]],
    ) -> List["RankedStrategy"]:
        """
        Rank strategies by score in descending order.

        Sorts strategies from highest to lowest score and assigns rank numbers
        starting from 1 (best) to N (worst).

        Args:
            strategies_with_scores: List of tuples containing:
                - Strategy: The strategy configuration
                - float: The optimization score
                - PerformanceMetrics: The performance metrics

        Returns:
            List of RankedStrategy objects sorted by score (highest first)
        """
        RankedStrategy = _models.RankedStrategy

        # Sort by score in descending order (highest score first)
        sorted_strategies = sorted(
            strategies_with_scores,
            key=lambda x: x[1],  # Sort by score (second element)
            reverse=True,  # Descending order
        )

        # Create RankedStrategy objects with rank numbers
        ranked_strategies = []
        for rank, (strategy, score, metrics) in enumerate(sorted_strategies, start=1):
            ranked_strategy = RankedStrategy(
                strategy=strategy,
                rank=rank,
                score=score,
                metrics=metrics,
            )
            ranked_strategies.append(ranked_strategy)

        return ranked_strategies
