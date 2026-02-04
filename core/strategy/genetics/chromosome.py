"""
Genetic algorithm chromosome and gene implementations for strategy evolution.
"""

from __future__ import annotations

import random
import time
import statistics
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


def _make_entity_id(prefix: str) -> str:
    """
    Generate reasonably collision-resistant ids.
    Keeps old prefix semantics (child_..., mutant_...).
    """
    return f"{prefix}_{time.time_ns()}_{random.randint(1000, 9999)}"


class EvolutionStrategy(Enum):
    """Стратегии эволюции."""

    GENETIC_ALGORITHM = "genetic_algorithm"
    PARTICLE_SWARM = "particle_swarm"
    SIMULATED_ANNEALING = "simulated_annealing"
    DIFFERENTIAL_EVOLUTION = "differential_evolution"
    HYBRID = "hybrid"


class MutationType(Enum):
    """Типы мутаций стратегий."""

    PARAMETER_TWEAK = "parameter_tweak"  # Небольшое изменение параметра
    PARAMETER_RANDOM = "parameter_random"  # Случайное значение параметра
    ATTACK_SUBSTITUTION = "attack_substitution"  # Замена атаки на похожую
    ATTACK_ADDITION = "attack_addition"  # Добавление новой атаки
    ATTACK_REMOVAL = "attack_removal"  # Удаление атаки
    SEQUENCE_REORDER = "sequence_reorder"  # Изменение порядка атак


class CrossoverType(Enum):
    """Типы кроссовера стратегий."""

    SINGLE_POINT = "single_point"  # Одноточечный кроссовер
    MULTI_POINT = "multi_point"  # Многоточечный кроссовер
    UNIFORM = "uniform"  # Равномерный кроссовер
    PARAMETER_BLEND = "parameter_blend"  # Смешивание параметров
    ATTACK_MERGE = "attack_merge"  # Слияние атак


@dataclass
class StrategyGene:
    """Ген стратегии для генетического алгоритма."""

    attack_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    enabled: bool = True

    def clone(self) -> "StrategyGene":
        """Создает независимую копию гена (без aliasing по parameters)."""
        return StrategyGene(
            attack_name=self.attack_name,
            parameters=self.parameters.copy(),
            weight=self.weight,
            enabled=self.enabled,
        )

    def mutate(self, mutation_rate: float = 0.1) -> "StrategyGene":
        """Мутация гена."""
        mutated = StrategyGene(
            attack_name=self.attack_name,
            parameters=self.parameters.copy(),
            weight=self.weight,
            enabled=self.enabled,
        )

        if random.random() < mutation_rate:
            # Мутация параметров
            for param_name, param_value in mutated.parameters.items():
                # IMPORTANT: bool is a subclass of int; handle it first.
                if isinstance(param_value, bool):
                    # Булевы параметры - инвертируем с малой вероятностью
                    if random.random() < 0.1:
                        mutated.parameters[param_name] = not param_value
                elif isinstance(param_value, (int, float)):
                    # Числовые параметры - добавляем шум
                    noise = random.gauss(0, abs(param_value) * 0.1)
                    new_val = max(0, param_value + noise)
                    # Preserve int-ness where possible
                    if isinstance(param_value, int) and not isinstance(param_value, bool):
                        new_val = int(round(new_val))
                    mutated.parameters[param_name] = new_val

            # Мутация веса
            weight_noise = random.gauss(0, 0.1)
            mutated.weight = max(0.1, min(2.0, mutated.weight + weight_noise))

        return mutated


@dataclass
class StrategyChromosome:
    """Хромосома стратегии для генетического алгоритма."""

    chromosome_id: str
    genes: List[StrategyGene] = field(default_factory=list)
    fitness: float = 0.0
    generation: int = 0

    # Метаданные
    created_at: datetime = field(default_factory=datetime.now)
    parent_ids: List[str] = field(default_factory=list)
    mutation_history: List[str] = field(default_factory=list)

    def calculate_fitness(self, effectiveness_metrics: Dict[str, Any], domain: str) -> float:
        """
        Расчет приспособленности хромосомы.

        Args:
            effectiveness_metrics: Метрики эффективности стратегий
            domain: Целевой домен

        Returns:
            Значение fitness
        """
        if not self.genes:
            return 0.0

        fitness_components = []

        for gene in self.genes:
            if not gene.enabled:
                continue

            # Поиск метрик эффективности для атаки
            strategy_key = f"{domain}_{gene.attack_name}"
            if strategy_key in effectiveness_metrics:
                metrics = effectiveness_metrics[strategy_key]

                # Компоненты приспособленности
                success_rate = getattr(metrics, "success_rate", 0.0)
                reliability_score = getattr(metrics, "reliability_score", 0.0)
                avg_response_time = getattr(metrics, "average_response_time", 1.0)

                success_component = success_rate * gene.weight
                reliability_component = reliability_score * 0.5
                speed_component = (1.0 / max(avg_response_time, 0.1)) * 0.3

                gene_fitness = success_component + reliability_component + speed_component
                fitness_components.append(gene_fitness)
            else:
                # Нет данных - базовая оценка
                fitness_components.append(0.5 * gene.weight)

        self.fitness = statistics.mean(fitness_components) if fitness_components else 0.0
        return self.fitness

    def crossover(
        self, other: "StrategyChromosome", crossover_type: CrossoverType
    ) -> Tuple["StrategyChromosome", "StrategyChromosome"]:
        """Кроссовер с другой хромосомой."""
        ct = crossover_type
        child1_genes: List[StrategyGene] = []
        child2_genes: List[StrategyGene] = []

        # Some crossovers require >= 2 genes. Fallback to UNIFORM for safety.
        if ct in (CrossoverType.SINGLE_POINT, CrossoverType.MULTI_POINT):
            if min(len(self.genes), len(other.genes)) < 2:
                ct = CrossoverType.UNIFORM

        if ct == CrossoverType.SINGLE_POINT:
            min_len = min(len(self.genes), len(other.genes))
            crossover_point = random.randint(1, min_len - 1)
            child1_genes = [
                g.clone() for g in (self.genes[:crossover_point] + other.genes[crossover_point:])
            ]
            child2_genes = [
                g.clone() for g in (other.genes[:crossover_point] + self.genes[crossover_point:])
            ]

        elif ct == CrossoverType.MULTI_POINT:
            min_len = min(len(self.genes), len(other.genes))
            p1 = random.randint(1, min_len - 1)
            p2 = random.randint(1, min_len - 1)
            a, b = sorted((p1, p2))
            child1_genes = [g.clone() for g in (self.genes[:a] + other.genes[a:b] + self.genes[b:])]
            child2_genes = [
                g.clone() for g in (other.genes[:a] + self.genes[a:b] + other.genes[b:])
            ]

        elif ct == CrossoverType.UNIFORM:
            max_length = max(len(self.genes), len(other.genes))
            for i in range(max_length):
                if random.random() < 0.5:
                    if i < len(self.genes):
                        child1_genes.append(self.genes[i].clone())
                    if i < len(other.genes):
                        child2_genes.append(other.genes[i].clone())
                else:
                    if i < len(other.genes):
                        child1_genes.append(other.genes[i].clone())
                    if i < len(self.genes):
                        child2_genes.append(self.genes[i].clone())

        elif ct == CrossoverType.PARAMETER_BLEND:
            all_attacks = {gene.attack_name for gene in (self.genes + other.genes)}

            for attack_name in all_attacks:
                self_gene = next((g for g in self.genes if g.attack_name == attack_name), None)
                other_gene = next((g for g in other.genes if g.attack_name == attack_name), None)

                if self_gene and other_gene:
                    blended_params: Dict[str, Any] = {}
                    all_params = set(self_gene.parameters.keys()) | set(
                        other_gene.parameters.keys()
                    )

                    for param_name in all_params:
                        self_value = self_gene.parameters.get(param_name, 0)
                        other_value = other_gene.parameters.get(param_name, 0)

                        # bool is subclass of int -> treat as categorical
                        if isinstance(self_value, bool) or isinstance(other_value, bool):
                            blended_params[param_name] = random.choice([self_value, other_value])
                        elif isinstance(self_value, (int, float)) and isinstance(
                            other_value, (int, float)
                        ):
                            alpha = random.random()
                            val = self_value * alpha + other_value * (1 - alpha)
                            if isinstance(self_value, int) and isinstance(other_value, int):
                                val = int(round(val))
                            blended_params[param_name] = val
                        else:
                            blended_params[param_name] = random.choice([self_value, other_value])

                    child1_genes.append(
                        StrategyGene(
                            attack_name=attack_name,
                            parameters=blended_params,
                            weight=(self_gene.weight + other_gene.weight) / 2,
                            enabled=self_gene.enabled and other_gene.enabled,
                        )
                    )
                    child2_genes.append(
                        StrategyGene(
                            attack_name=attack_name,
                            parameters=blended_params.copy(),
                            weight=(self_gene.weight + other_gene.weight) / 2,
                            enabled=self_gene.enabled or other_gene.enabled,
                        )
                    )

                elif self_gene:
                    child1_genes.append(self_gene.clone())
                elif other_gene:
                    child2_genes.append(other_gene.clone())

        elif ct == CrossoverType.ATTACK_MERGE:
            # Merge attacks from both parents, maximizing diversity.
            all_attacks = {gene.attack_name for gene in (self.genes + other.genes)}
            for attack_name in all_attacks:
                self_gene = next((g for g in self.genes if g.attack_name == attack_name), None)
                other_gene = next((g for g in other.genes if g.attack_name == attack_name), None)

                if self_gene and other_gene:
                    if random.random() < 0.5:
                        child1_genes.append(self_gene.clone())
                        child2_genes.append(other_gene.clone())
                    else:
                        child1_genes.append(other_gene.clone())
                        child2_genes.append(self_gene.clone())
                elif self_gene:
                    # Keep both children structurally compatible
                    child1_genes.append(self_gene.clone())
                    child2_genes.append(self_gene.clone())
                elif other_gene:
                    child1_genes.append(other_gene.clone())
                    child2_genes.append(other_gene.clone())

        else:
            # Future-proof fallback
            max_length = max(len(self.genes), len(other.genes))
            for i in range(max_length):
                if i < len(self.genes):
                    child1_genes.append(self.genes[i].clone())
                if i < len(other.genes):
                    child2_genes.append(other.genes[i].clone())

        # Создание потомков
        child1 = StrategyChromosome(
            chromosome_id=_make_entity_id("child"),
            genes=child1_genes,
            generation=max(self.generation, other.generation) + 1,
            parent_ids=[self.chromosome_id, other.chromosome_id],
        )

        child2 = StrategyChromosome(
            chromosome_id=_make_entity_id("child"),
            genes=child2_genes,
            generation=max(self.generation, other.generation) + 1,
            parent_ids=[self.chromosome_id, other.chromosome_id],
        )

        return child1, child2

    def mutate(
        self, mutation_rate: float = 0.1, mutation_types: List[MutationType] = None
    ) -> "StrategyChromosome":
        """Мутация хромосомы."""
        if mutation_types is None:
            mutation_types = [MutationType.PARAMETER_TWEAK, MutationType.PARAMETER_RANDOM]

        mutated = StrategyChromosome(
            chromosome_id=_make_entity_id("mutant"),
            genes=[gene.mutate(mutation_rate) for gene in self.genes],
            generation=self.generation + 1,
            parent_ids=[self.chromosome_id],
        )

        # Дополнительные мутации
        for mutation_type in mutation_types:
            if random.random() < mutation_rate:
                if mutation_type == MutationType.ATTACK_ADDITION and len(mutated.genes) < 5:
                    # Добавление новой атаки (требует доступа к реестру атак)
                    pass  # Реализуется в контексте генератора

                elif mutation_type == MutationType.ATTACK_REMOVAL and len(mutated.genes) > 1:
                    # Удаление случайной атаки
                    gene_to_remove = random.choice(mutated.genes)
                    mutated.genes.remove(gene_to_remove)
                    mutated.mutation_history.append(f"removed_{gene_to_remove.attack_name}")

                elif mutation_type == MutationType.SEQUENCE_REORDER:
                    # Изменение порядка атак
                    random.shuffle(mutated.genes)
                    mutated.mutation_history.append("reordered_sequence")

        return mutated


@dataclass
class EvolutionParameters:
    """Параметры эволюционного алгоритма."""

    population_size: int = 50
    generations: int = 20
    mutation_rate: float = 0.1
    crossover_rate: float = 0.8
    elite_size: int = 5

    # Стратегии
    evolution_strategy: EvolutionStrategy = EvolutionStrategy.GENETIC_ALGORITHM
    crossover_type: CrossoverType = CrossoverType.PARAMETER_BLEND
    mutation_types: List[MutationType] = field(
        default_factory=lambda: [MutationType.PARAMETER_TWEAK, MutationType.PARAMETER_RANDOM]
    )

    # Критерии остановки
    max_generations_without_improvement: int = 10
    target_fitness: float = 0.95
    max_evolution_time_minutes: int = 30
