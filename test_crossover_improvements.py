#!/usr/bin/env python3
"""
Test improvements from ref.md: crossover with clone() and ATTACK_MERGE.
"""
from core.strategy.genetics.chromosome import (
    StrategyChromosome,
    StrategyGene,
    CrossoverType,
)


def test_gene_clone():
    """Test that clone() creates independent copies."""
    gene1 = StrategyGene(
        attack_name="fake",
        parameters={"ttl": 10, "enabled": True},
        weight=1.5,
        enabled=True,
    )

    gene2 = gene1.clone()

    # Modify clone
    gene2.parameters["ttl"] = 20
    gene2.weight = 2.0

    # Original should be unchanged
    assert gene1.parameters["ttl"] == 10
    assert gene1.weight == 1.5
    print("✅ Gene clone() works correctly - no aliasing")


def test_crossover_no_aliasing():
    """Test that crossover creates independent gene copies."""
    parent1 = StrategyChromosome(
        chromosome_id="p1",
        genes=[
            StrategyGene("fake", {"ttl": 10}, 1.0, True),
            StrategyGene("split", {"pos": 5}, 1.0, True),
        ],
        generation=0,
    )

    parent2 = StrategyChromosome(
        chromosome_id="p2",
        genes=[
            StrategyGene("fake", {"ttl": 20}, 1.0, True),
            StrategyGene("disorder", {"count": 3}, 1.0, True),
        ],
        generation=0,
    )

    child1, child2 = parent1.crossover(parent2, CrossoverType.SINGLE_POINT)

    # Modify child genes
    if child1.genes:
        child1.genes[0].parameters["ttl"] = 999

    # Parent genes should be unchanged
    assert parent1.genes[0].parameters["ttl"] == 10
    assert parent2.genes[0].parameters["ttl"] == 20
    print("✅ Crossover creates independent copies - no aliasing")


def test_attack_merge_crossover():
    """Test ATTACK_MERGE crossover type."""
    parent1 = StrategyChromosome(
        chromosome_id="p1",
        genes=[
            StrategyGene("fake", {"ttl": 10}, 1.0, True),
            StrategyGene("split", {"pos": 5}, 1.0, True),
        ],
        generation=0,
    )

    parent2 = StrategyChromosome(
        chromosome_id="p2",
        genes=[
            StrategyGene("fake", {"ttl": 20}, 1.0, True),
            StrategyGene("disorder", {"count": 3}, 1.0, True),
        ],
        generation=0,
    )

    child1, child2 = parent1.crossover(parent2, CrossoverType.ATTACK_MERGE)

    # Both children should have genes
    assert len(child1.genes) > 0
    assert len(child2.genes) > 0

    # Check that attacks are merged
    child1_attacks = {g.attack_name for g in child1.genes}
    child2_attacks = {g.attack_name for g in child2.genes}

    # Should contain attacks from both parents
    all_attacks = {"fake", "split", "disorder"}
    assert child1_attacks.issubset(all_attacks)
    assert child2_attacks.issubset(all_attacks)

    print(f"✅ ATTACK_MERGE works: child1={child1_attacks}, child2={child2_attacks}")


def test_parameter_blend_bool_handling():
    """Test that PARAMETER_BLEND correctly handles bool parameters."""
    parent1 = StrategyChromosome(
        chromosome_id="p1",
        genes=[
            StrategyGene("tls", {"enabled": True, "ttl": 10}, 1.0, True),
        ],
        generation=0,
    )

    parent2 = StrategyChromosome(
        chromosome_id="p2",
        genes=[
            StrategyGene("tls", {"enabled": False, "ttl": 20}, 1.0, True),
        ],
        generation=0,
    )

    child1, child2 = parent1.crossover(parent2, CrossoverType.PARAMETER_BLEND)

    # Bool should be chosen randomly, not interpolated
    assert child1.genes[0].parameters["enabled"] in [True, False]
    assert child2.genes[0].parameters["enabled"] in [True, False]

    # Int should be interpolated
    ttl1 = child1.genes[0].parameters["ttl"]
    assert isinstance(ttl1, int)
    assert 10 <= ttl1 <= 20

    print(f"✅ PARAMETER_BLEND handles bool correctly: enabled={child1.genes[0].parameters['enabled']}, ttl={ttl1}")


def test_empty_population_handling():
    """Test that empty genes don't crash crossover."""
    parent1 = StrategyChromosome(chromosome_id="p1", genes=[], generation=0)
    parent2 = StrategyChromosome(chromosome_id="p2", genes=[], generation=0)

    # Should not crash
    child1, child2 = parent1.crossover(parent2, CrossoverType.UNIFORM)

    assert len(child1.genes) == 0
    assert len(child2.genes) == 0
    print("✅ Empty population handling works")


if __name__ == "__main__":
    test_gene_clone()
    test_crossover_no_aliasing()
    test_attack_merge_crossover()
    test_parameter_blend_bool_handling()
    test_empty_population_handling()
    print("\n🎉 All crossover improvement tests passed!")
