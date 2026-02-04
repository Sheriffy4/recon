"""
Population management for genetic algorithm evolution.
"""

from __future__ import annotations

import logging
import random
import statistics
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from .chromosome import StrategyChromosome, StrategyGene

LOG = logging.getLogger("PopulationManager")


class PopulationManager:
    """Менеджер популяции для генетического алгоритма."""

    def __init__(self, population_size: int = 50):
        self.population_size = population_size

    async def initialize_population(
        self,
        domain: str,
        available_attacks: List[str],
        parameter_generator_func,
        blocking_analysis=None,
    ) -> List["StrategyChromosome"]:
        """
        Инициализация популяции стратегий.

        Args:
            domain: Целевой домен
            available_attacks: Список доступных атак
            parameter_generator_func: Функция генерации параметров
            blocking_analysis: Анализ блокировки (опционально)

        Returns:
            Список хромосом популяции
        """
        from .chromosome import StrategyChromosome, StrategyGene

        LOG.debug(f"Initializing population for {domain}")

        population = []

        if not available_attacks:
            LOG.warning(
                "No available attacks for domain=%s; initializing empty-gene population (%d chromosomes)",
                domain,
                self.population_size,
            )
            for i in range(self.population_size):
                population.append(
                    StrategyChromosome(
                        chromosome_id=f"{domain}_init_{i}",
                        genes=[],
                        generation=0,
                    )
                )
            return population

        for i in range(self.population_size):
            # Случайный выбор атак для хромосомы
            num_attacks = random.randint(1, min(4, len(available_attacks)))
            selected_attacks = random.sample(available_attacks, num_attacks)

            genes = []
            for attack_name in selected_attacks:
                # Генерация случайных параметров
                parameters = parameter_generator_func(attack_name, blocking_analysis)

                gene = StrategyGene(
                    attack_name=attack_name,
                    parameters=parameters,
                    weight=random.uniform(0.5, 2.0),
                    enabled=True,
                )
                genes.append(gene)

            chromosome = StrategyChromosome(
                chromosome_id=f"{domain}_init_{i}", genes=genes, generation=0
            )
            population.append(chromosome)

        LOG.debug(f"Initialized population of {len(population)} chromosomes for {domain}")
        return population

    def tournament_selection(
        self, population: List["StrategyChromosome"], tournament_size: int = 3
    ) -> "StrategyChromosome":
        """
        Турнирная селекция.

        Args:
            population: Популяция хромосом
            tournament_size: Размер турнира

        Returns:
            Выбранная хромосома
        """
        tournament = random.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda c: c.fitness)

    def calculate_population_diversity(self, population: List["StrategyChromosome"]) -> float:
        """
        Расчет разнообразия популяции.

        Args:
            population: Популяция хромосом

        Returns:
            Метрика разнообразия (0.0 - 1.0)
        """
        if len(population) < 2:
            return 0.0

        # Упрощенная метрика разнообразия на основе различий в генах
        diversity_scores = []

        for i in range(len(population)):
            for j in range(i + 1, len(population)):
                chromosome1 = population[i]
                chromosome2 = population[j]

                # Сравнение атак
                attacks1 = set(gene.attack_name for gene in chromosome1.genes)
                attacks2 = set(gene.attack_name for gene in chromosome2.genes)

                attack_similarity = len(attacks1 & attacks2) / max(len(attacks1 | attacks2), 1)
                diversity_scores.append(1.0 - attack_similarity)

        return statistics.mean(diversity_scores) if diversity_scores else 0.0
