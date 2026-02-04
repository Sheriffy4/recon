import unittest
from unittest.mock import patch
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.strategy.next_gen_strategy_generator import (
    StrategyGene,
    StrategyChromosome,
    CrossoverType,
)


class TestGenetics(unittest.TestCase):
    def test_strategy_gene_mutate_bool_not_treated_as_int(self):
        gene = StrategyGene(attack_name="x", parameters={"flag": True}, weight=1.0, enabled=True)
        # Ensure mutation triggers and bool inversion triggers.
        with patch("core.strategy.next_gen_strategy_generator.random.random", side_effect=[0.0, 0.0]):
            with patch("core.strategy.next_gen_strategy_generator.random.gauss", return_value=0.0):
                mutated = gene.mutate(mutation_rate=1.0)
        self.assertIsInstance(mutated.parameters["flag"], bool)
        self.assertEqual(mutated.parameters["flag"], False)

    def test_single_point_crossover_with_single_gene_does_not_crash(self):
        a = StrategyChromosome(chromosome_id="a", genes=[StrategyGene("attack_a")])
        b = StrategyChromosome(chromosome_id="b", genes=[StrategyGene("attack_b")])
        # If SINGLE_POINT fallback triggers, UNIFORM crossover uses random.random in loop.
        with patch("core.strategy.next_gen_strategy_generator.random.random", return_value=0.0):
            c1, c2 = a.crossover(b, CrossoverType.SINGLE_POINT)
        self.assertTrue(len(c1.genes) > 0)
        self.assertTrue(len(c2.genes) > 0)


if __name__ == "__main__":
    unittest.main()
