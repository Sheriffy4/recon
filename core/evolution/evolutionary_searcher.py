#!/usr/bin/env python3
"""
Evolutionary Strategy Search Module

Implements genetic algorithm for finding optimal DPI bypass strategies.
Extracted from cli.py to improve modularity and reduce complexity.
"""

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Import Rich components for UI
try:
    from rich.console import Console
    from rich.progress import Progress

    console = Console()
except ImportError:
    # Fallback console
    class Console:
        def print(self, *args, **kwargs):
            print(*args)

    console = Console()
    Progress = None

# Get logger
LOG = logging.getLogger("recon.evolutionary_searcher")


@dataclass
class EvolutionaryChromosome:
    """Хромосома для эволюционного алгоритма."""

    genes: Dict[str, Any]  # Параметры стратегии
    fitness: float = 0.0
    generation: int = 0

    def mutate(self, mutation_rate: float = 0.1):
        if random.random() < mutation_rate:
            # Comprehensive parameter mutation for all attack types
            mutation_ranges = {
                "ttl": [1, 2, 3, 4, 5, 6, 7, 8, 10, 64, 127, 128],
                "split_pos": [
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    10,
                    15,
                    20,
                    50,
                    100,
                    200,
                    300,
                    400,
                ],  # ✅ Добавлены большие значения для фрагментации ClientHello
                "split_count": [2, 3, 4, 5, 6, 7, 8, 9, 10],
                "split_seqovl": [5, 10, 15, 20, 25, 30, 35, 40],
                "overlap_size": [5, 10, 15, 20, 25, 30],  # Legacy parameter
                "fragment_size": [8, 16, 24, 32, 48, 64],
                "reorder_distance": [2, 3, 4, 5, 6, 8, 10],
                "repeats": [1, 2, 3, 4, 5],
                "delay": [5, 10, 15, 20, 25, 30],
                "window_size": [512, 1024, 2048, 4096, 8192],
                "fooling": ["badsum", "badseq", "md5sig", "hopbyhop"],
            }

            # Mutate existing parameters
            for param_name, current_value in self.genes.items():
                if param_name in mutation_ranges:
                    if isinstance(current_value, bool):
                        # Boolean parameters
                        if random.random() < 0.1:
                            self.genes[param_name] = not current_value
                    else:
                        # Numeric/string parameters
                        self.genes[param_name] = random.choice(mutation_ranges[param_name])

            # Occasionally change attack type to explore different strategies
            if random.random() < 0.05:  # 5% chance to change attack type
                from core.attack_mapping import get_attack_mapping

                attack_mapping = get_attack_mapping()

                # Get attacks from same category or similar attacks
                current_type = self.genes.get("type", "fake_disorder")
                current_attack_info = attack_mapping.get_attack_info(current_type)

                if current_attack_info:
                    # Try to find similar attacks in the same category
                    similar_attacks = attack_mapping.get_attacks_by_category(
                        current_attack_info.category
                    )
                    if similar_attacks and len(similar_attacks) > 1:
                        new_type = random.choice(
                            [name for name in similar_attacks.keys() if name != current_type]
                        )
                        new_attack_info = similar_attacks[new_type]

                        # Update genes with new attack type and its default parameters
                        self.genes["type"] = new_type
                        for (
                            param_name,
                            default_value,
                        ) in new_attack_info.default_params.items():
                            if param_name not in self.genes:
                                self.genes[param_name] = default_value

    def crossover(self, other: "EvolutionaryChromosome") -> "EvolutionaryChromosome":
        child_genes = {}
        for key in self.genes:
            if key in other.genes:
                child_genes[key] = random.choice([self.genes[key], other.genes[key]])
            else:
                child_genes[key] = self.genes[key]
        return EvolutionaryChromosome(
            genes=child_genes, generation=max(self.generation, other.generation) + 1
        )


class SimpleEvolutionarySearcher:
    """Упрощенный эволюционный поисковик стратегий."""

    def __init__(
        self,
        population_size: int = 10,
        generations: int = 3,
        mutation_rate: float = 0.2,
    ):
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.population: List[EvolutionaryChromosome] = []
        self.best_fitness_history = []

    def create_initial_population(
        self, learning_cache=None, domain=None, dpi_hash=None
    ) -> List[EvolutionaryChromosome]:
        population = []
        # Приоритеты из StrategyManager
        sm_split = sm_overlap = None
        sm_fooling = None
        if domain:
            try:
                from core.strategy_manager import StrategyManager

                sm = StrategyManager()
                ds = sm.get_strategy(domain)
                if ds:
                    sm_split = int(ds.split_pos) if ds.split_pos else None
                    sm_overlap = int(ds.overlap_size) if ds.overlap_size else None
                    sm_fooling = ds.fooling_modes if ds.fooling_modes else None
            except Exception:
                pass
        # Import comprehensive attack mapping
        from core.attack_mapping import get_attack_mapping

        attack_mapping = get_attack_mapping()

        # Get all supported attacks and create base strategies
        all_attacks = attack_mapping.get_all_attacks()
        base_strategies = []

        # Priority attacks (most effective)
        priority_attacks = [
            "fake_disorder",
            "multisplit",
            "sequence_overlap",
            "badsum_race",
            "md5sig_race",
            "ip_fragmentation_advanced",
            "force_tcp",
            "tcp_multidisorder",
            "tcp_multisplit",
            "simple_fragment",
            "window_manipulation",
        ]

        # Add priority attacks first
        for attack_name in priority_attacks:
            if attack_name in all_attacks:
                attack_info = all_attacks[attack_name]
                base_strategies.append(
                    {
                        "type": attack_name,
                        **attack_info.default_params,
                        "no_fallbacks": True,
                        "forced": True,
                    }
                )

        # Add other TCP and IP attacks
        tcp_ip_categories = ["tcp", "ip", "fragmentation", "race"]
        for category in tcp_ip_categories:
            category_attacks = attack_mapping.get_attacks_by_category(category)
            for attack_name, attack_info in category_attacks.items():
                if attack_name not in [s["type"] for s in base_strategies]:
                    base_strategies.append(
                        {
                            "type": attack_name,
                            **attack_info.default_params,
                            "no_fallbacks": True,
                            "forced": True,
                        }
                    )

        # Fallback to original if no attacks found
        if not base_strategies:
            base_strategies = [
                {
                    "type": "fake_disorder",
                    "ttl": 3,
                    "split_pos": 3,
                    "no_fallbacks": True,
                    "forced": True,
                },
                {
                    "type": "multisplit",
                    "ttl": 5,
                    "split_pos": 5,
                    "split_seqovl": 10,
                    "no_fallbacks": True,
                    "forced": True,
                },
                {
                    "type": "sequence_overlap",
                    "ttl": 2,
                    "split_pos": 3,
                    "split_seqovl": 20,
                    "no_fallbacks": True,
                    "forced": True,
                },
                {"type": "badsum_race", "ttl": 4, "no_fallbacks": True, "forced": True},
                {"type": "md5sig_race", "ttl": 6, "no_fallbacks": True, "forced": True},
            ]
        learned_strategies = []
        if learning_cache and domain:
            from core.attack_mapping import get_attack_mapping

            attack_mapping = get_attack_mapping()

            domain_recs = learning_cache.get_domain_recommendations(domain, 10)
            if dpi_hash:
                dpi_recs = learning_cache.get_dpi_recommendations(dpi_hash, 10)
                all_recs = domain_recs + dpi_recs
            else:
                all_recs = domain_recs

            for strategy_type, success_rate in all_recs:
                if success_rate > 0.3:
                    # Get attack info from comprehensive mapping
                    attack_info = attack_mapping.get_attack_info(strategy_type)
                    if attack_info:
                        # Create learned strategy with randomized parameters
                        learned_strategy = {
                            "type": strategy_type,
                            "no_fallbacks": True,
                            "forced": True,
                        }

                        # Add randomized parameters based on attack info
                        for (
                            param_name,
                            default_value,
                        ) in attack_info.default_params.items():
                            if param_name == "ttl":
                                learned_strategy[param_name] = random.choice([2, 3, 4, 5, 6])
                            elif param_name == "split_pos":
                                learned_strategy[param_name] = random.choice([2, 3, 4, 5, 6])
                            elif param_name == "split_count":
                                learned_strategy[param_name] = random.choice([3, 4, 5, 6, 7])
                            elif param_name == "split_seqovl":
                                learned_strategy[param_name] = random.choice([10, 15, 20, 25, 30])
                            elif param_name == "fragment_size":
                                learned_strategy[param_name] = random.choice([8, 16, 24, 32])
                            elif param_name == "fooling":
                                learned_strategy[param_name] = random.choice(
                                    ["badsum", "badseq", "md5sig"]
                                )
                            elif param_name == "repeats":
                                learned_strategy[param_name] = random.choice([1, 2, 3])
                            else:
                                learned_strategy[param_name] = default_value

                        learned_strategies.append(learned_strategy)
                    else:
                        # Fallback for unknown strategy types
                        if strategy_type in [
                            "fake_disorder",
                            "fakedisorder",
                            "tcp_fakeddisorder",
                        ]:
                            learned_strategies.append(
                                {
                                    "type": "fake_disorder",
                                    "ttl": random.choice([2, 3, 4]),
                                    "split_pos": random.choice([2, 3, 4]),
                                    "no_fallbacks": True,
                                    "forced": True,
                                }
                            )
                        elif strategy_type in ["multisplit", "tcp_multisplit"]:
                            learned_strategies.append(
                                {
                                    "type": "multisplit",
                                    "ttl": random.choice([4, 5, 6]),
                                    "split_count": random.choice([4, 5, 6]),
                                    "split_seqovl": random.choice([8, 10, 12]),
                                    "no_fallbacks": True,
                                    "forced": True,
                                }
                            )
                        elif strategy_type in [
                            "sequence_overlap",
                            "seqovl",
                            "tcp_seqovl",
                        ]:
                            learned_strategies.append(
                                {
                                    "type": "sequence_overlap",
                                    "ttl": random.choice([2, 3, 4]),
                                    "split_pos": random.choice([2, 3, 4]),
                                    "split_seqovl": random.choice([15, 20, 25]),
                                    "no_fallbacks": True,
                                    "forced": True,
                                }
                            )
        all_base_strategies = base_strategies + learned_strategies
        for i in range(self.population_size):
            if i < len(all_base_strategies):
                genes = all_base_strategies[i].copy()
            else:
                from core.attack_mapping import get_attack_mapping

                attack_mapping = get_attack_mapping()

                # Get all available attacks and select randomly
                all_attacks = attack_mapping.get_all_attacks()

                # Prefer TCP and IP attacks for better compatibility
                preferred_categories = ["tcp", "ip", "fragmentation", "race", "unknown"]
                preferred_attacks = []

                for category in preferred_categories:
                    category_attacks = attack_mapping.get_attacks_by_category(category)
                    preferred_attacks.extend(category_attacks.keys())

                # Add some specific high-success attacks
                high_success_attacks = [
                    "fake_disorder",
                    "multisplit",
                    "tcp_multisplit",
                    "sequence_overlap",
                    "badsum_race",
                    "md5sig_race",
                    "simple_fragment",
                    "tcp_fragmentation",
                    "multidisorder",
                    "tcp_multidisorder",
                    "ip_fragmentation_advanced",
                ]

                # Combine and deduplicate
                available_attacks = list(set(preferred_attacks + high_success_attacks))

                # Filter to only include attacks that exist
                available_attacks = [
                    attack for attack in available_attacks if attack in all_attacks
                ]

                if not available_attacks:
                    # Fallback to any available attack
                    available_attacks = list(all_attacks.keys())

                # Select random attack type
                attack_type = random.choice(available_attacks)
                attack_info = all_attacks[attack_type]

                # Start with attack type and default parameters
                genes = {
                    "type": attack_type,
                    **attack_info.default_params,
                    "no_fallbacks": True,
                    "forced": True,
                }
                # Инъекция микропараметров, если применимо
                if sm_split is not None:
                    genes["split_pos"] = sm_split
                if sm_overlap is not None:
                    genes["overlap_size"] = sm_overlap
                if sm_fooling and "fooling" not in genes:
                    genes["fooling"] = sm_fooling

                # Add some randomization to parameters
                if "ttl" in genes:
                    genes["ttl"] = random.choice([1, 2, 3, 4, 5, 6, 7, 8])
                if "split_pos" in genes:
                    genes["split_pos"] = random.choice([1, 2, 3, 4, 5, 6, 7, 8, 10])
                if "split_count" in genes:
                    genes["split_count"] = random.choice([2, 3, 4, 5, 6, 7])
                if "split_seqovl" in genes:
                    genes["split_seqovl"] = random.choice([5, 10, 15, 20, 25, 30])
                if "fragment_size" in genes:
                    genes["fragment_size"] = random.choice([8, 16, 24, 32])
                if "fooling" in genes:
                    genes["fooling"] = random.choice(["badsum", "badseq", "md5sig"])
            population.append(EvolutionaryChromosome(genes=genes, generation=0))
        return population

    def genes_to_zapret_strategy(self, genes: Dict[str, Any]) -> str:
        """
        Convert genes to zapret strategy command.

        This function has been updated to properly support all attack types
        registered in the AttackRegistry and generate appropriate zapret commands.
        """
        from core.bypass.attacks.attack_registry import get_attack_registry
        from core.attack_mapping import get_attack_mapping

        strategy_type = genes.get("type", "fakeddisorder")
        registry = get_attack_registry()
        attack_mapping = get_attack_mapping()

        # Validate that this is a known attack type
        try:
            # Try to get the attack handler to verify it exists
            handler = registry.get_attack_handler(strategy_type)
            if handler is None:
                LOG.warning(f"Unknown attack type '{strategy_type}', using fallback")
        except Exception as e:
            LOG.warning(f"Error validating attack type '{strategy_type}': {e}")

        # Try to generate command using comprehensive mapping first
        zapret_cmd = attack_mapping.get_zapret_command(strategy_type, genes)
        if zapret_cmd:
            return zapret_cmd

        # Fallback to legacy mapping for backward compatibility
        strategy_parts = []
        ttl = genes.get("ttl", 3)
        split_pos = genes.get("split_pos", 3)
        split_seqovl = genes.get("split_seqovl", genes.get("overlap_size", 10))
        fragment_size = genes.get("fragment_size", 8)
        disable_quic = genes.get("disable_quic", False)
        reorder_distance = genes.get("reorder_distance", 3)

        # Updated legacy mappings with correct zapret commands for all attack types
        legacy_mappings = {
            "fakedisorder": "--dpi-desync=fake,disorder",
            "fake_disorder": "--dpi-desync=fake,disorder",
            "fakeddisorder": "--dpi-desync=fake,disorder",
            "tcp_fakeddisorder": "--dpi-desync=fake,disorder",
            "multisplit": "--dpi-desync=multisplit",
            "tcp_multisplit": "--dpi-desync=multisplit",
            "multidisorder": "--dpi-desync=multidisorder",
            "tcp_multidisorder": "--dpi-desync=multidisorder",
            "seqovl": "--dpi-desync=fake,disorder",
            "sequence_overlap": "--dpi-desync=fake,disorder",
            "tcp_seqovl": "--dpi-desync=fake,disorder",
            "badsum_race": "--dpi-desync=fake",
            "md5sig_race": "--dpi-desync=fake",
            "ip_fragmentation": "--dpi-desync=split",
            "ip_fragmentation_advanced": "--dpi-desync=split",
            "force_tcp": "--filter-udp=443 --dpi-desync=fake,disorder",
            "tcp_reorder": "--dpi-desync=disorder",
            "simple_fragment": "--dpi-desync=split",
            "tcp_fragmentation": "--dpi-desync=split",
            # Add correct mappings for disorder and split
            "disorder": "--dpi-desync=disorder",
            "disorder2": "--dpi-desync=disorder",
            "split": "--dpi-desync=split",
            "fake": "--dpi-desync=fake",
            "wssize_limit": "--dpi-desync=wssize",
            "tlsrec_split": "--dpi-desync=tlsrec",
        }

        if strategy_type in legacy_mappings:
            strategy_parts.append(legacy_mappings[strategy_type])

            # Handle parameters based on attack type
            if "multisplit" in strategy_type:
                # Handle positions parameter for multisplit
                positions = genes.get("positions", [1, 5, 10])
                split_count = genes.get("split_count", len(positions) if positions else 3)
                strategy_parts.append(f"--dpi-desync-split-count={split_count}")

                # Add split_seqovl for multisplit
                multisplit_seqovl = genes.get("split_seqovl", genes.get("overlap_size", 0))
                strategy_parts.append(f"--dpi-desync-split-seqovl={multisplit_seqovl}")

            elif strategy_type in ["seqovl", "sequence_overlap", "tcp_seqovl"]:
                # seqovl attacks need both split_pos and split_seqovl
                strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
                seqovl_value = genes.get("split_seqovl", genes.get("overlap_size", split_seqovl))
                strategy_parts.append(f"--dpi-desync-split-seqovl={seqovl_value}")

            elif (
                strategy_type
                in [
                    "disorder",
                    "disorder2",
                    "split",
                    "simple_fragment",
                    "tcp_fragmentation",
                ]
                or ("split" in strategy_type and "multisplit" not in strategy_type)
                or ("disorder" in strategy_type and "multidisorder" not in strategy_type)
            ):
                # For disorder and split attacks, add split_pos
                strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")

            elif "fragmentation" in strategy_type:
                strategy_parts.append(f"--dpi-desync-split-pos={fragment_size}")

            # Handle TTL for appropriate attacks
            if strategy_type not in ["disorder", "split"] or "fake" in strategy_type:
                # For attacks that need TTL or are fake-based attacks
                if "ttl" in genes or "fake" in strategy_type:
                    strategy_parts.append(f"--dpi-desync-ttl={ttl}")

            # Handle fooling methods
            fooling_already_added = any("--dpi-desync-fooling=" in part for part in strategy_parts)
            if not fooling_already_added:
                # Add fooling for attacks that typically need it
                fooling_attacks = [
                    "fake",
                    "fakeddisorder",
                    "fake_disorder",
                    "fakeddisorder",
                    "tcp_fakeddisorder",
                    "badsum_race",
                    "md5sig_race",
                    "badseq_fooling",
                ]
                if strategy_type in fooling_attacks or "race" in strategy_type:
                    fooling = genes.get("fooling", "badsum")
                    # Ensure fooling is a string or list
                    if isinstance(fooling, list):
                        fooling_str = ",".join(fooling) if len(fooling) > 1 else fooling[0]
                    else:
                        fooling_str = str(fooling)
                    strategy_parts.append(f"--dpi-desync-fooling={fooling_str}")
        else:
            # Generic fallback for unknown attack types
            strategy_parts.append("--dpi-desync=fake")
            strategy_parts.append(f"--dpi-desync-split-pos={split_pos}")
            strategy_parts.append(f"--dpi-desync-ttl={ttl}")
            strategy_parts.append("--dpi-desync-fooling=badsum")

        return " ".join(strategy_parts)

    async def evaluate_fitness(
        self,
        chromosome: EvolutionaryChromosome,
        hybrid_engine,
        blocked_sites: List[str],
        port: int,
        engine_override: Optional[str] = None,
    ) -> float:
        try:
            strategy = self.genes_to_zapret_strategy(chromosome.genes)
            result_status, successful_count, total_count, avg_latency = (
                await hybrid_engine.execute_strategy_real_world(
                    strategy,
                    blocked_sites,
                    set(),  # Empty IP set - engine will resolve domains as needed
                    {},  # Empty DNS cache - engine will resolve domains as needed
                    port,
                    engine_override=engine_override,
                )
            )
            if successful_count == 0:
                return 0.0
            success_rate = successful_count / total_count
            latency_bonus = max(0, (500 - avg_latency) / 500) * 0.1
            fitness = success_rate + latency_bonus
            return min(fitness, 1.0)
        except Exception as e:
            console.print(f"[red]Error evaluating fitness: {e}[/red]")
            return 0.0

    def selection(
        self, population: List[EvolutionaryChromosome], elite_size: int = 2
    ) -> List[EvolutionaryChromosome]:
        sorted_population = sorted(population, key=lambda x: x.fitness, reverse=True)
        selected = sorted_population[:elite_size]
        while len(selected) < len(population):
            tournament = random.sample(sorted_population, min(3, len(sorted_population)))
            winner = max(tournament, key=lambda x: x.fitness)
            selected.append(winner)
        return selected

    async def evolve(
        self,
        hybrid_engine,
        blocked_sites: List[str],
        port: int,
        learning_cache=None,
        domain: str = None,
        dpi_hash: str = None,
        engine_override: Optional[str] = None,
    ) -> "EvolutionaryChromosome":
        console.print("[bold magenta][DNA] Starting evolutionary search...[/bold magenta]")
        console.print(f"Population: {self.population_size}, Generations: {self.generations}")

        # Create initial population with fingerprint-informed strategies
        self.population = self.create_initial_population(
            learning_cache=learning_cache, domain=domain, dpi_hash=dpi_hash
        )
        for generation in range(self.generations):
            console.print(f"\n[yellow]Generation {generation + 1}/{self.generations}[/yellow]")
            with Progress(console=console, transient=True) as progress:
                task = progress.add_task(
                    f"[cyan]Evaluating generation {generation + 1}...",
                    total=len(self.population),
                )
                for chromosome in self.population:
                    chromosome.fitness = await self.evaluate_fitness(
                        chromosome,
                        hybrid_engine,
                        blocked_sites,
                        port,
                        engine_override=engine_override,
                    )
                    chromosome.generation = generation
                    progress.update(task, advance=1)
            best = max(self.population, key=lambda x: x.fitness)
            avg_fitness = sum(c.fitness for c in self.population) / len(self.population)
            self.best_fitness_history.append(
                {
                    "generation": generation,
                    "best_fitness": best.fitness,
                    "avg_fitness": avg_fitness,
                    "best_strategy": self.genes_to_zapret_strategy(best.genes),
                }
            )
            console.print(
                f"  Best fitness: [green]{best.fitness:.3f}[/green], Avg: {avg_fitness:.3f}"
            )
            console.print(
                f"  Best strategy: [cyan]{self.genes_to_zapret_strategy(best.genes)}[/cyan]"
            )
            if generation < self.generations - 1:
                selected = self.selection(self.population, elite_size=2)
                new_population = []
                new_population.extend(selected[:2])
                while len(new_population) < self.population_size:
                    parent1 = random.choice(selected)
                    parent2 = random.choice(selected)
                    if parent1 != parent2:
                        child = parent1.crossover(parent2)
                    else:
                        child = EvolutionaryChromosome(
                            genes=parent1.genes.copy(), generation=generation + 1
                        )
                    child.mutate(self.mutation_rate)
                    new_population.append(child)
                self.population = new_population
        best_chromosome = max(self.population, key=lambda x: x.fitness)
        console.print(
            f"\n[bold green][TROPHY] Evolution complete! Best fitness: {best_chromosome.fitness:.3f}[/bold green]"
        )
        return best_chromosome

    def _validate_attack_parameters(
        self, attack_type: str, genes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate and normalize parameters for a specific attack type using AttackRegistry."""
        try:
            # Use AttackRegistry for comprehensive validation
            from core.bypass.attacks.attack_registry import get_attack_registry

            registry = get_attack_registry()

            # Normalize attack type - remove tcp_ prefix and other prefixes for registry lookup
            normalized_type = self._normalize_attack_type_for_registry(attack_type)

            # First, apply parameter correction using legacy validation
            # This ensures parameters are in valid ranges
            corrected_genes = self._legacy_validate_attack_parameters(attack_type, genes)

            # Then validate the corrected parameters using the registry
            validation_result = registry.validate_parameters(normalized_type, corrected_genes)

            if not validation_result.is_valid:
                # Log validation error but return the corrected parameters anyway
                LOG.warning(
                    f"AttackRegistry validation failed for {attack_type} even after correction: {validation_result.error_message}"
                )

            # Return the corrected parameters
            validated = corrected_genes

            # Get attack metadata to add any missing default parameters
            metadata = registry.get_attack_metadata(attack_type)
            if metadata:
                for param_name, default_value in metadata.optional_params.items():
                    if param_name not in validated:
                        validated[param_name] = default_value

            # Special handling for positions parameter in multisplit
            if attack_type in ["multisplit", "tcp_multisplit"] and "positions" in validated:
                positions = validated["positions"]
                if isinstance(positions, list) and len(positions) > 0:
                    # Ensure split_count matches positions length
                    validated["split_count"] = len(positions)

            return validated

        except Exception as e:
            LOG.warning(f"Failed to use AttackRegistry validation for {attack_type}: {e}")
            # Fall back to legacy validation
            return self._legacy_validate_attack_parameters(attack_type, genes)

    def _normalize_attack_type_for_registry(self, attack_type: str) -> str:
        """Normalize attack type for AttackRegistry lookup by removing prefixes."""
        # Remove common prefixes
        prefixes_to_remove = ["tcp_", "udp_", "http_", "tls_"]

        normalized = attack_type
        for prefix in prefixes_to_remove:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                break

        # Handle special cases
        type_mappings = {
            "badsum_race": "fake",
            "md5sig_race": "fake",
            "ip_fragmentation": "split",
            "ip_fragmentation_advanced": "split",
            "force_tcp": "fakeddisorder",  # Map to closest equivalent
            "tcp_reorder": "disorder",
            "simple_fragment": "split",
            "tcp_fragmentation": "split",
        }

        return type_mappings.get(normalized, normalized)

    def _legacy_validate_attack_parameters(
        self, attack_type: str, genes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Legacy parameter validation for backward compatibility."""
        validated = genes.copy()

        # Parameter validation rules for each attack type
        validation_rules = {
            "multisplit": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_count": {"type": int, "min": 2, "max": 10, "default": 3},
                "split_seqovl": {"type": int, "min": 0, "max": 100, "default": 0},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
            },
            "tcp_multisplit": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_count": {"type": int, "min": 2, "max": 10, "default": 3},
                "split_seqovl": {"type": int, "min": 0, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
            },
            "seqovl": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "split_seqovl": {"type": int, "min": 5, "max": 100, "default": 20},
                "overlap_size": {"type": int, "min": 5, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 3},
            },
            "sequence_overlap": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "split_seqovl": {"type": int, "min": 5, "max": 100, "default": 20},
                "overlap_size": {"type": int, "min": 5, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 3},
            },
            "tcp_seqovl": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "split_seqovl": {"type": int, "min": 5, "max": 100, "default": 20},
                "overlap_size": {"type": int, "min": 5, "max": 100, "default": 20},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 3},
            },
            "fake_disorder": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
            },
            "fakeddisorder": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
            },
            "multidisorder": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
            },
            "tcp_multidisorder": {
                "positions": {"type": list, "default": [1, 5, 10]},
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 3},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
            },
            "disorder": {"split_pos": {"type": int, "min": 1, "max": 50, "default": 3}},
            "split": {"split_pos": {"type": int, "min": 1, "max": 50, "default": 5}},
            "simple_fragment": {"split_pos": {"type": int, "min": 1, "max": 50, "default": 5}},
            "tcp_fragmentation": {"split_pos": {"type": int, "min": 1, "max": 50, "default": 5}},
            "ip_fragmentation": {
                "split_pos": {"type": int, "min": 1, "max": 50, "default": 8},
                "fragment_size": {"type": int, "min": 8, "max": 64, "default": 8},
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
            },
            "badsum_race": {
                "ttl": {"type": int, "min": 1, "max": 255, "default": 4},
                "fooling": {
                    "type": list,
                    "values": ["badsum", "badseq", "badack"],
                    "default": ["badsum"],
                },
            },
            "md5sig_race": {
                "ttl": {"type": int, "min": 1, "max": 255, "default": 6},
                "fooling": {
                    "type": list,
                    "values": ["badsum", "badseq", "badack"],
                    "default": ["badseq"],
                },
            },
        }

        # Apply validation rules if they exist for this attack type
        if attack_type in validation_rules:
            rules = validation_rules[attack_type]

            for param_name, rule in rules.items():
                if param_name in validated:
                    value = validated[param_name]

                    # Type validation
                    if rule["type"] == int:
                        try:
                            value = int(value)
                            # Range validation
                            if "min" in rule and value < rule["min"]:
                                value = rule["min"]
                            if "max" in rule and value > rule["max"]:
                                value = rule["max"]
                            validated[param_name] = value
                        except (ValueError, TypeError):
                            validated[param_name] = rule.get("default", 3)

                    elif rule["type"] == str:
                        # String validation
                        if "values" in rule and value not in rule["values"]:
                            validated[param_name] = rule.get("default", rule["values"][0])

                    elif rule["type"] == list:
                        # List validation
                        if not isinstance(value, list):
                            # Convert string to list if needed
                            if isinstance(value, str):
                                if "values" in rule and value in rule["values"]:
                                    validated[param_name] = [value]
                                else:
                                    validated[param_name] = rule.get("default", [])
                            else:
                                validated[param_name] = rule.get("default", [])
                        else:
                            # Validate list elements if values are specified
                            if "values" in rule:
                                validated_list = [item for item in value if item in rule["values"]]
                                if not validated_list:
                                    validated_list = rule.get("default", [])
                                validated[param_name] = validated_list
                            else:
                                validated[param_name] = value

                else:
                    # Add default value if parameter is missing
                    if "default" in rule:
                        validated[param_name] = rule["default"]
        else:
            # Fallback validation for unknown attack types
            # Apply common parameter corrections
            if "ttl" in validated:
                try:
                    ttl_value = int(validated["ttl"])
                    if ttl_value < 1:
                        validated["ttl"] = 1
                    elif ttl_value > 255:
                        validated["ttl"] = 255
                    else:
                        validated["ttl"] = ttl_value
                except (ValueError, TypeError):
                    validated["ttl"] = 3

            if "split_pos" in validated:
                try:
                    split_pos = validated["split_pos"]
                    if isinstance(split_pos, str) and split_pos not in [
                        "cipher",
                        "sni",
                        "midsld",
                    ]:
                        validated["split_pos"] = int(split_pos)
                    elif isinstance(split_pos, int) and split_pos < 1:
                        validated["split_pos"] = 1
                except (ValueError, TypeError):
                    validated["split_pos"] = 3

            if "overlap_size" in validated:
                try:
                    overlap_size = int(validated["overlap_size"])
                    if overlap_size < 0:
                        validated["overlap_size"] = 0
                    else:
                        validated["overlap_size"] = overlap_size
                except (ValueError, TypeError):
                    validated["overlap_size"] = 10

        # Special handling for positions parameter in multisplit
        if attack_type in ["multisplit", "tcp_multisplit"] and "positions" in validated:
            positions = validated["positions"]
            if isinstance(positions, list) and len(positions) > 0:
                # Ensure split_count matches positions length
                validated["split_count"] = len(positions)

        return validated


# Adaptive learning and caching system
import pickle
import hashlib
from pathlib import Path
