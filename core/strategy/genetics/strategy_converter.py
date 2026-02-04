"""
Strategy conversion from chromosome representation to strategy dictionary.
"""

from __future__ import annotations

from typing import Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .chromosome import StrategyChromosome


class StrategyConverter:
    """Конвертер хромосом в стратегии."""

    async def chromosome_to_strategy(
        self,
        domain: str,
        chromosome: "StrategyChromosome",
        blocking_analysis: Any = None,
    ) -> Dict[str, Any]:
        """
        Конвертация хромосомы в стратегию.

        Args:
            domain: Целевой домен
            chromosome: Хромосома для конвертации
            blocking_analysis: Анализ блокировки (опционально, не используется пока)

        Returns:
            Словарь стратегии
        """
        strategy = {
            "strategy_id": chromosome.chromosome_id,
            "name": f"Evolved strategy for {domain}",
            "generation_method": "genetic_evolution",
            "fitness": chromosome.fitness,
            "generation": chromosome.generation,
            "attacks": [],
            "parameters": {},
            "metadata": {
                "parent_ids": chromosome.parent_ids,
                "mutation_history": chromosome.mutation_history,
                "created_at": chromosome.created_at.isoformat(),
            },
        }

        # Конвертация генов в атаки
        for gene in chromosome.genes:
            if gene.enabled:
                attack_config = {
                    "name": gene.attack_name,
                    "parameters": gene.parameters,
                    "weight": gene.weight,
                }
                strategy["attacks"].append(attack_config)

                # Объединение параметров
                for param_name, param_value in gene.parameters.items():
                    strategy["parameters"][f"{gene.attack_name}_{param_name}"] = param_value

        return strategy
