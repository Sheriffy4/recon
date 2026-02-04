import tempfile
import unittest
from datetime import datetime


class TestNextGenStrategyGenerator(unittest.IsolatedAsyncioTestCase):
    async def test_evolve_strategies_keeps_population_evaluated_and_sorted(self):
        # Import inside test to work with optional dependencies/fallbacks
        from core.strategy.next_gen_strategy_generator import (
            NextGenStrategyGenerator,
            EvolutionParameters,
            StrategyEffectivenessMetrics,
        )
        from core.pcap_analysis.blocking_pattern_detector import (
            BlockingPatternAnalysis,
            BlockingType,
            DPIAggressivenessLevel,
        )

        params = EvolutionParameters(
            population_size=12,
            generations=1,  # critical: should not leave an unevaluated "next generation"
            mutation_rate=0.2,
            crossover_rate=0.5,
            elite_size=2,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            gen = NextGenStrategyGenerator(data_dir=tmpdir, evolution_params=params)
            domain = "example.com"
            blocking = BlockingPatternAnalysis(
                domain=domain,
                analysis_id="test_001",
                analyzed_at=datetime.now(),
                primary_blocking_type=BlockingType.RST_INJECTION,
                dpi_aggressiveness=DPIAggressivenessLevel.MODERATE,
                blocking_confidence=0.9,
            )

            # Provide metrics for a broad set of attacks used by initializer
            attacks = [
                "fake",
                "multisplit",
                "disorder",
                "tls_sni_split",
                "tls_chello_frag",
                "http_split",
                "tcp_split",
            ]

            effectiveness = {
                f"{domain}_{a}": StrategyEffectivenessMetrics(
                    strategy_id=f"{domain}_{a}",
                    domain=domain,
                    success_rate=1.0,
                    reliability_score=1.0,
                    average_response_time=0.1,
                )
                for a in attacks
            }

            strategies = await gen.evolve_strategies(
                domain=domain,
                blocking_analysis=blocking,
                effectiveness_metrics=effectiveness,
                target_count=5,
            )

            self.assertTrue(strategies)
            self.assertIn(domain, gen.population)

            pop = gen.population[domain]
            self.assertEqual(len(pop), params.population_size)

            # Fitness must be evaluated (not default 0.0 across population)
            fitnesses = [c.fitness for c in pop]
            self.assertTrue(any(f > 0.0 for f in fitnesses))

            # Must be sorted by fitness descending
            self.assertEqual(fitnesses, sorted(fitnesses, reverse=True))

    async def test_population_serialization_roundtrip(self):
        from core.strategy.next_gen_strategy_generator import (
            NextGenStrategyGenerator,
            EvolutionParameters,
            StrategyEffectivenessMetrics,
        )
        from core.pcap_analysis.blocking_pattern_detector import (
            BlockingPatternAnalysis,
            BlockingType,
            DPIAggressivenessLevel,
        )

        params = EvolutionParameters(population_size=8, generations=1, elite_size=2)
        domain = "example.org"

        with tempfile.TemporaryDirectory() as tmpdir:
            gen1 = NextGenStrategyGenerator(data_dir=tmpdir, evolution_params=params)
            blocking = BlockingPatternAnalysis(
                domain=domain,
                analysis_id="test_002",
                analyzed_at=datetime.now(),
                primary_blocking_type=BlockingType.SNI_FILTERING,
                dpi_aggressiveness=DPIAggressivenessLevel.MODERATE,
                blocking_confidence=0.85,
            )
            effectiveness = {
                f"{domain}_fake": StrategyEffectivenessMetrics(
                    strategy_id=f"{domain}_fake",
                    domain=domain,
                    success_rate=1.0,
                    reliability_score=1.0,
                    average_response_time=0.1,
                )
            }
            await gen1.evolve_strategies(
                domain=domain,
                blocking_analysis=blocking,
                effectiveness_metrics=effectiveness,
                target_count=3,
            )

            # New instance must load saved populations
            gen2 = NextGenStrategyGenerator(data_dir=tmpdir, evolution_params=params)
            self.assertIn(domain, gen2.population)
            self.assertEqual(len(gen2.population[domain]), params.population_size)

            # Ensure chromosome structure is reconstructed
            c0 = gen2.population[domain][0]
            self.assertTrue(hasattr(c0, "chromosome_id"))
            self.assertTrue(hasattr(c0, "genes"))


if __name__ == "__main__":
    unittest.main()
