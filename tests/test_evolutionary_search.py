"""
Comprehensive tests for evolutionary DPI bypass strategy search
"""

import pytest
import asyncio
import time
import json
import random
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any, Optional, Tuple, Set
from datetime import datetime

# Fix import for local cli.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + '/..'))
from cli import (
    SimpleEvolutionarySearcher, EvolutionaryChromosome, HybridEngine, 
    AdaptiveLearningCache
)

# Configure pytest for async tests
pytest_plugins = ('pytest_asyncio',)

@pytest.fixture
def evolutionary_searcher():
    """Create evolutionary searcher instance for testing"""
    return SimpleEvolutionarySearcher(
        population_size=5,
        generations=2,
        mutation_rate=0.2
    )

@pytest.fixture
def hybrid_engine():
    """Create mock hybrid engine for testing"""
    engine = MagicMock()
    async def mock_execute_strategy(*args, **kwargs):
        # Return random success metrics
        success = random.random() > 0.5
        return (
            "SUCCESS" if success else "FAILURE",
            1 if success else 0,
            1,
            random.uniform(50, 200)  # Latency between 50-200ms
        )
    engine.execute_strategy_real_world = AsyncMock(side_effect=mock_execute_strategy)
    return engine

@pytest.fixture
def adaptive_learning_cache():
    """Create mock adaptive learning cache for testing"""
    cache = MagicMock()
    return cache

def test_evolutionary_chromosome_initialization():
    """Test evolutionary chromosome initialization"""
    genes = {
        'type': 'fakedisorder',
        'ttl': 3,
        'split_pos': 3
    }
    chromosome = EvolutionaryChromosome(genes=genes)
    
    assert chromosome.genes == genes
    assert chromosome.fitness == 0.0
    assert chromosome.generation == 0

def test_evolutionary_chromosome_mutation():
    """Test chromosome mutation"""
    genes = {
        'type': 'fakedisorder',
        'ttl': 3,
        'split_pos': 3
    }
    chromosome = EvolutionaryChromosome(genes=genes.copy())
    
    # Force mutation by setting random to always trigger
    with patch('random.random', return_value=0.0):
        chromosome.mutate(mutation_rate=1.0)
        
        # Verify at least one gene was mutated
        assert chromosome.genes != genes

def test_evolutionary_chromosome_crossover():
    """Test chromosome crossover"""
    parent1 = EvolutionaryChromosome(genes={
        'type': 'fakedisorder',
        'ttl': 3,
        'split_pos': 3
    })
    parent2 = EvolutionaryChromosome(genes={
        'type': 'multisplit',
        'ttl': 5,
        'split_pos': 5,
        'overlap_size': 10
    })
    
    child = parent1.crossover(parent2)
    
    assert isinstance(child, EvolutionaryChromosome)
    assert child.generation == max(parent1.generation, parent2.generation) + 1
    # Child should inherit genes from either parent
    assert child.genes['type'] in ['fakedisorder', 'multisplit']

def test_evolutionary_searcher_initialization():
    """Test evolutionary searcher initialization"""
    searcher = SimpleEvolutionarySearcher(
        population_size=10,
        generations=3,
        mutation_rate=0.2
    )
    
    assert searcher.population_size == 10
    assert searcher.generations == 3
    assert searcher.mutation_rate == 0.2
    assert len(searcher.population) == 0
    assert len(searcher.best_fitness_history) == 0

def test_evolutionary_searcher_create_initial_population():
    """Test initial population creation"""
    searcher = SimpleEvolutionarySearcher(population_size=5)
    
    population = searcher.create_initial_population()
    
    assert len(population) == 5
    allowed_types = ['fakedisorder', 'multisplit', 'seqovl', 'badsum_race', 'md5sig_race']
    for chromosome in population:
        assert isinstance(chromosome, EvolutionaryChromosome)
        assert 'type' in chromosome.genes
        assert chromosome.genes['type'] in allowed_types

def test_evolutionary_searcher_create_population_with_learning():
    """Test initial population creation with learning cache"""
    searcher = SimpleEvolutionarySearcher(population_size=5)
    learning_cache = Mock()
    
    # Mock cache recommendations
    learning_cache.get_domain_recommendations = Mock(return_value=[
        ('fakedisorder', 0.8),
        ('multisplit', 0.6)
    ])
    learning_cache.get_dpi_recommendations = Mock(return_value=[
        ('seqovl', 0.7),
        ('badsum_race', 0.5)
    ])
    
    population = searcher.create_initial_population(
        learning_cache=learning_cache,
        domain="test.com",
        dpi_hash="abc123"
    )
    
    assert len(population) == 5
    # Should include learned strategies with high success rates
    strategies = [c.genes['type'] for c in population]
    assert 'fakedisorder' in strategies  # Highest success rate strategy
    assert all(isinstance(c, EvolutionaryChromosome) for c in population)

@pytest.mark.asyncio
async def test_evolutionary_searcher_evaluate_fitness(evolutionary_searcher, hybrid_engine):
    """Test chromosome fitness evaluation"""
    chromosome = EvolutionaryChromosome(genes={
        'type': 'fakedisorder',
        'ttl': 3,
        'split_pos': 3
    })
    
    blocked_sites = ["test1.com", "test2.com"]
    target_ips = {"192.168.1.1", "192.168.1.2"}
    dns_cache = {"test1.com": "192.168.1.1", "test2.com": "192.168.1.2"}
    
    fitness = await evolutionary_searcher.evaluate_fitness(
        chromosome, hybrid_engine, blocked_sites, target_ips, dns_cache, 443
    )
    
    assert 0.0 <= fitness <= 1.0
    assert hybrid_engine.execute_strategy_real_world.called

def test_evolutionary_searcher_selection(evolutionary_searcher):
    """Test population selection"""
    # Create population with known fitness values
    population = [
        EvolutionaryChromosome(genes={'type': 'a'}, fitness=0.9),
        EvolutionaryChromosome(genes={'type': 'b'}, fitness=0.7),
        EvolutionaryChromosome(genes={'type': 'c'}, fitness=0.5),
        EvolutionaryChromosome(genes={'type': 'd'}, fitness=0.3),
        EvolutionaryChromosome(genes={'type': 'e'}, fitness=0.1),
    ]
    
    selected = evolutionary_searcher.selection(population, elite_size=2)
    
    assert len(selected) == len(population)
    # Elite chromosomes should be preserved
    assert any(c.genes['type'] == 'a' for c in selected[:2])
    assert any(c.genes['type'] == 'b' for c in selected[:2])

@pytest.mark.asyncio
async def test_evolutionary_searcher_evolve(evolutionary_searcher, hybrid_engine):
    """Test full evolution process"""
    blocked_sites = ["test1.com", "test2.com"]
    target_ips = {"192.168.1.1", "192.168.1.2"}
    dns_cache = {"test1.com": "192.168.1.1", "test2.com": "192.168.1.2"}
    
    best_chromosome = await evolutionary_searcher.evolve(
        hybrid_engine, blocked_sites, target_ips, dns_cache, 443
    )
    
    assert isinstance(best_chromosome, EvolutionaryChromosome)
    assert len(evolutionary_searcher.best_fitness_history) > 0
    assert all('best_fitness' in gen for gen in evolutionary_searcher.best_fitness_history)

def test_genes_to_zapret_strategy():
    """Test conversion of genes to zapret strategy string"""
    searcher = SimpleEvolutionarySearcher()
    
    # Test fakedisorder strategy
    genes = {
        'type': 'fakedisorder',
        'ttl': 3,
        'split_pos': 3
    }
    strategy = searcher.genes_to_zapret_strategy(genes)
    assert 'fake,fakeddisorder' in strategy
    assert '--dpi-desync-split-pos=3' in strategy
    
    # Test multisplit strategy
    genes = {
        'type': 'multisplit',
        'ttl': 5,
        'split_pos': 5,
        'overlap_size': 10
    }
    strategy = searcher.genes_to_zapret_strategy(genes)
    assert '--dpi-desync=multisplit' in strategy
    assert '--dpi-desync-split-seqovl=10' in strategy

@pytest.mark.asyncio
async def test_evolutionary_search_integration():
    """Test integration of evolutionary search with hybrid engine"""
    searcher = SimpleEvolutionarySearcher(
        population_size=3,
        generations=2,
        mutation_rate=0.2
    )
    hybrid_engine = Mock()
    
    # Mock strategy execution results
    async def mock_execute_strategy(*args, **kwargs):
        return "SUCCESS", 1, 1, 100.0
    
    hybrid_engine.execute_strategy_real_world = AsyncMock(side_effect=mock_execute_strategy)
    
    # Test with minimal parameters
    blocked_sites = ["test.com"]
    target_ips = {"192.168.1.1"}
    dns_cache = {"test.com": "192.168.1.1"}
    
    best_chromosome = await searcher.evolve(
        hybrid_engine, blocked_sites, target_ips, dns_cache, 443
    )
    
    assert isinstance(best_chromosome, EvolutionaryChromosome)
    assert best_chromosome.fitness > 0
    assert len(searcher.best_fitness_history) == 2  # One entry per generation
    
    # Verify strategy generation
    strategy = searcher.genes_to_zapret_strategy(best_chromosome.genes)
    assert isinstance(strategy, str)
    assert '--dpi-desync=' in strategy

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
