"""
Next generation strategy generator.

Note: This module can run with optional dependencies missing. In that case it provides
minimal fallback types to prevent runtime NameError in non-critical paths.
"""

from __future__ import annotations

import logging
import random
import time
import statistics
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

# Genetic algorithm components
from .genetics import (
    EvolutionStrategy,
    MutationType,
    CrossoverType,
    StrategyGene,
    StrategyChromosome,
    EvolutionParameters,
)
from .genetics.topology_analyzer import NetworkTopologyInfo, TopologyAnalyzer
from .genetics.payload_analyzer import PayloadAnalysisResult, PayloadAnalyzer
from .genetics.population_manager import PopulationManager
from .genetics.attack_parameter_generator import AttackParameterGenerator
from .genetics.strategy_converter import StrategyConverter
from .genetics.parameter_weight_analyzer import ParameterWeightAnalyzer

# Utilities
from utils.config_loader import load_json_config, save_json_config

# Интеграция с существующими модулями
try:
    from ..pcap_analysis.blocking_pattern_detector import (
        BlockingPatternAnalysis,
        BlockingType,
    )
    from ..learning.iterative_analysis_engine import StrategyEffectivenessMetrics

    STRATEGY_COMPONENTS_AVAILABLE = True
except ImportError:
    STRATEGY_COMPONENTS_AVAILABLE = False
    logging.getLogger(__name__).warning("Strategy components not available; using fallbacks")

    class BlockingType(Enum):
        SNI_FILTERING = "sni_filtering"
        RST_INJECTION = "rst_injection"
        UNKNOWN = "unknown"

    @dataclass
    class BlockingPatternAnalysis:
        primary_blocking_type: BlockingType = BlockingType.UNKNOWN

    @dataclass
    class StrategyEffectivenessMetrics:
        success_rate: float = 0.0
        reliability_score: float = 0.0
        average_response_time: float = 1.0


LOG = logging.getLogger("NextGenStrategyGenerator")


class NextGenStrategyGenerator:
    """
    Адаптивный генератор стратегий следующего поколения.

    Использует машинное обучение и генетические алгоритмы для
    эволюции стратегий обхода DPI.
    """

    def __init__(
        self,
        data_dir: str = "data/next_gen_strategies",
        evolution_params: Optional[EvolutionParameters] = None,
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.evolution_params = evolution_params or EvolutionParameters()

        # Популяция стратегий
        self.population: Dict[str, List[StrategyChromosome]] = {}
        self.generation_history: Dict[str, List[Dict[str, Any]]] = {}

        # Веса параметров
        self.parameter_weights: Dict[str, Dict[str, float]] = {}

        # Кэш анализов
        self.topology_cache: Dict[str, NetworkTopologyInfo] = {}
        self.payload_analysis_cache: Dict[str, PayloadAnalysisResult] = {}

        # Analyzers
        self.topology_analyzer = TopologyAnalyzer()
        self.payload_analyzer = PayloadAnalyzer()
        self.population_manager = PopulationManager(
            population_size=self.evolution_params.population_size
        )
        self.attack_param_generator = AttackParameterGenerator()
        self.strategy_converter = StrategyConverter()
        self.weight_analyzer = ParameterWeightAnalyzer()

        # Статистика
        self.stats = {
            "populations_evolved": 0,
            "generations_computed": 0,
            "strategies_generated": 0,
            "successful_mutations": 0,
            "successful_crossovers": 0,
            "topology_analyses": 0,
            "payload_analyses": 0,
        }

        # Загрузка сохраненных данных
        self._load_evolution_data()

        LOG.info("NextGenStrategyGenerator initialized")

    def _strategy_gene_to_dict(self, gene: StrategyGene) -> Dict[str, Any]:
        return {
            "attack_name": gene.attack_name,
            "parameters": gene.parameters,
            "weight": gene.weight,
            "enabled": gene.enabled,
        }

    def _strategy_gene_from_dict(self, data: Dict[str, Any]) -> StrategyGene:
        return StrategyGene(
            attack_name=str(data.get("attack_name", "")),
            parameters=dict(data.get("parameters", {}) or {}),
            weight=float(data.get("weight", 1.0)),
            enabled=bool(data.get("enabled", True)),
        )

    def _chromosome_to_dict(self, chromosome: StrategyChromosome) -> Dict[str, Any]:
        return {
            "chromosome_id": chromosome.chromosome_id,
            "genes": [self._strategy_gene_to_dict(g) for g in chromosome.genes],
            "fitness": chromosome.fitness,
            "generation": chromosome.generation,
            "created_at": chromosome.created_at.isoformat(),
            "parent_ids": list(chromosome.parent_ids),
            "mutation_history": list(chromosome.mutation_history),
        }

    def _chromosome_from_dict(self, data: Dict[str, Any]) -> StrategyChromosome:
        created_at_raw = data.get("created_at")
        created_at = datetime.now()
        if isinstance(created_at_raw, str):
            try:
                created_at = datetime.fromisoformat(created_at_raw)
            except ValueError:
                created_at = datetime.now()

        genes_raw = data.get("genes", []) or []
        genes: List[StrategyGene] = []
        if isinstance(genes_raw, list):
            for g in genes_raw:
                if isinstance(g, dict):
                    genes.append(self._strategy_gene_from_dict(g))

        return StrategyChromosome(
            chromosome_id=str(data.get("chromosome_id", "")),
            genes=genes,
            fitness=float(data.get("fitness", 0.0)),
            generation=int(data.get("generation", 0)),
            created_at=created_at,
            parent_ids=list(data.get("parent_ids", []) or []),
            mutation_history=list(data.get("mutation_history", []) or []),
        )

    def _save_populations(self) -> None:
        """Best-effort сохранение популяций (без изменения внешнего интерфейса)."""
        populations_file = self.data_dir / "populations.json"
        payload: Dict[str, Any] = {}
        for domain, chromosomes in self.population.items():
            payload[domain] = [self._chromosome_to_dict(c) for c in chromosomes]
        try:
            save_json_config(populations_file, payload)
        except Exception as e:
            LOG.error("Failed to save populations: %s", e, exc_info=True)

    async def evolve_strategies(
        self,
        domain: str,
        blocking_analysis: BlockingPatternAnalysis,
        effectiveness_metrics: Dict[str, StrategyEffectivenessMetrics],
        target_count: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Эволюция стратегий с использованием генетического алгоритма.

        Args:
            domain: Целевой домен
            blocking_analysis: Анализ паттернов блокировки
            effectiveness_metrics: Метрики эффективности стратегий
            target_count: Целевое количество стратегий

        Returns:
            Список эволюционировавших стратегий
        """
        LOG.info(f"Starting strategy evolution for {domain}")
        start_time = time.time()

        # Инициализация популяции
        if domain not in self.population:
            await self._initialize_population(domain, blocking_analysis)

        population = self.population[domain]
        best_fitness_history = []
        generations_without_improvement = 0

        # Основной цикл эволюции
        for generation in range(self.evolution_params.generations):
            generation_start = time.time()

            # Оценка и сортировка популяции
            self._evaluate_population(population, effectiveness_metrics, domain)
            current_best_fitness = population[0].fitness if population else 0.0
            best_fitness_history.append(current_best_fitness)

            LOG.debug(f"Generation {generation}: best fitness = {current_best_fitness:.3f}")

            # Проверка критериев остановки
            should_stop, stop_reason = self._check_stopping_criteria(
                generation,
                current_best_fitness,
                best_fitness_history,
                generations_without_improvement,
                start_time,
            )

            if should_stop:
                LOG.info(f"Evolution stopped: {stop_reason}")
                break

            # Обновление счетчика поколений без улучшения
            if generation > 0 and current_best_fitness <= best_fitness_history[-2]:
                generations_without_improvement += 1
            else:
                generations_without_improvement = 0

            # Создание нового поколения (кроме последнего шага, чтобы не оставить "неоцененную" популяцию на выходе)
            if generation < self.evolution_params.generations - 1:
                population = self._create_next_generation(population)

            # Сохранение истории поколения
            self._save_generation_stats(
                domain, generation, current_best_fitness, population, generation_start
            )

        # Обновление популяции
        self.population[domain] = population

        # Best-effort persist populations
        self._save_populations()

        # Конвертация лучших хромосом в стратегии
        strategies = await self._convert_best_chromosomes(
            domain, population, blocking_analysis, target_count
        )

        # Обновление статистики
        self._update_evolution_stats(best_fitness_history, strategies, start_time, domain)

        return strategies

    def _evaluate_population(
        self,
        population: List[StrategyChromosome],
        effectiveness_metrics: Dict[str, StrategyEffectivenessMetrics],
        domain: str,
    ):
        """Оценка приспособленности и сортировка популяции."""
        for chromosome in population:
            chromosome.calculate_fitness(effectiveness_metrics, domain)
        population.sort(key=lambda c: c.fitness, reverse=True)

    def _check_stopping_criteria(
        self,
        generation: int,
        current_best_fitness: float,
        best_fitness_history: List[float],
        generations_without_improvement: int,
        start_time: float,
    ) -> tuple[bool, str]:
        """Проверка критериев остановки эволюции."""
        # Достигнута целевая приспособленность
        if current_best_fitness >= self.evolution_params.target_fitness:
            return True, f"Target fitness reached in generation {generation}"

        # Нет улучшений длительное время
        if (
            generations_without_improvement
            >= self.evolution_params.max_generations_without_improvement
        ):
            return (
                True,
                f"No improvement for {generations_without_improvement} generations",
            )

        # Превышено время эволюции
        elapsed_minutes = (time.time() - start_time) / 60
        if elapsed_minutes >= self.evolution_params.max_evolution_time_minutes:
            return True, f"Evolution time limit reached ({elapsed_minutes:.1f} minutes)"

        return False, ""

    def _create_next_generation(
        self, population: List[StrategyChromosome]
    ) -> List[StrategyChromosome]:
        """Создание нового поколения через селекцию, кроссовер и мутацию."""
        # Селекция элиты
        elite = population[: self.evolution_params.elite_size]
        new_population = elite.copy()

        while len(new_population) < self.evolution_params.population_size:
            # Селекция родителей
            parent1 = self.population_manager.tournament_selection(population)
            parent2 = self.population_manager.tournament_selection(population)

            # Кроссовер
            if random.random() < self.evolution_params.crossover_rate:
                child1, child2 = parent1.crossover(parent2, self.evolution_params.crossover_type)

                # Мутация потомков
                if random.random() < self.evolution_params.mutation_rate:
                    child1 = child1.mutate(
                        self.evolution_params.mutation_rate,
                        self.evolution_params.mutation_types,
                    )
                    self.stats["successful_mutations"] += 1

                if random.random() < self.evolution_params.mutation_rate:
                    child2 = child2.mutate(
                        self.evolution_params.mutation_rate,
                        self.evolution_params.mutation_types,
                    )
                    self.stats["successful_mutations"] += 1

                new_population.extend([child1, child2])
                self.stats["successful_crossovers"] += 1
            else:
                # Клонирование с мутацией
                clone = parent1.mutate(
                    self.evolution_params.mutation_rate, self.evolution_params.mutation_types
                )
                new_population.append(clone)

        # Обрезка до нужного размера
        return new_population[: self.evolution_params.population_size]

    def _save_generation_stats(
        self,
        domain: str,
        generation: int,
        best_fitness: float,
        population: List[StrategyChromosome],
        generation_start: float,
    ):
        """Сохранение статистики поколения."""
        generation_stats = {
            "generation": generation,
            "best_fitness": best_fitness,
            "average_fitness": (
                statistics.mean(c.fitness for c in population) if population else 0.0
            ),
            "diversity": self.population_manager.calculate_population_diversity(population),
            "generation_time_ms": (time.time() - generation_start) * 1000,
        }

        if domain not in self.generation_history:
            self.generation_history[domain] = []
        self.generation_history[domain].append(generation_stats)

    async def _convert_best_chromosomes(
        self,
        domain: str,
        population: List[StrategyChromosome],
        blocking_analysis: BlockingPatternAnalysis,
        target_count: int,
    ) -> List[Dict[str, Any]]:
        """Конвертация лучших хромосом в стратегии."""
        best_chromosomes = population[:target_count]
        strategies = []

        for chromosome in best_chromosomes:
            strategy = await self.strategy_converter.chromosome_to_strategy(
                domain, chromosome, blocking_analysis
            )
            strategies.append(strategy)

        return strategies

    def _update_evolution_stats(
        self,
        best_fitness_history: List[float],
        strategies: List[Dict[str, Any]],
        start_time: float,
        domain: str,
    ):
        """Обновление статистики эволюции."""
        self.stats["populations_evolved"] += 1
        self.stats["generations_computed"] += len(best_fitness_history)
        self.stats["strategies_generated"] += len(strategies)

        evolution_time = time.time() - start_time
        LOG.info(
            f"Strategy evolution completed for {domain} in {evolution_time:.2f}s, "
            f"generated {len(strategies)} strategies"
        )

    async def adaptive_ttl_optimization(self, domain: str, target_ip: str) -> NetworkTopologyInfo:
        """
        Адаптивная настройка TTL на основе сетевой топологии.

        Args:
            domain: Целевой домен
            target_ip: IP адрес цели

        Returns:
            Информация о сетевой топологии с рекомендациями по TTL
        """
        cache_key = f"{domain}_{target_ip}"

        # Проверяем кэш
        if cache_key in self.topology_cache:
            cached_info = self.topology_cache[cache_key]
            # Проверяем актуальность (обновляем каждые 24 часа)
            if datetime.now() - cached_info.created_at < timedelta(hours=24):
                return cached_info

        LOG.info(f"Analyzing network topology for {domain} ({target_ip})")

        topology_info = NetworkTopologyInfo(domain=domain, target_ip=target_ip)

        try:
            # Анализ маршрута (упрощенная версия без внешних зависимостей)
            await self.topology_analyzer.analyze_network_route(topology_info)

            # Анализ TTL паттернов
            await self.topology_analyzer.analyze_ttl_patterns(topology_info)

            # Оценка позиции DPI
            await self.topology_analyzer.estimate_dpi_position(topology_info)

            # Генерация рекомендаций по TTL
            self.topology_analyzer.generate_ttl_recommendations(topology_info)

            # Кэширование результата
            self.topology_cache[cache_key] = topology_info
            self.stats["topology_analyses"] += 1

            LOG.info(
                f"Network topology analysis completed for {domain}, optimal TTL: {topology_info.optimal_ttl}"
            )

        except Exception as e:
            LOG.error("Network topology analysis failed for %s: %s", domain, e, exc_info=True)

        return topology_info

    async def intelligent_split_position_selection(
        self, payload: bytes, payload_type: str = "auto"
    ) -> PayloadAnalysisResult:
        """
        Интеллектуальный выбор позиций split на основе анализа payload.

        Args:
            payload: Данные для анализа
            payload_type: Тип payload ("tls_client_hello", "http_request", "auto")

        Returns:
            Результат анализа с рекомендациями по позициям split
        """
        # Avoid MD5-related restrictions in some environments (e.g., FIPS).
        # Key is internal/in-memory only.
        payload_hash = hashlib.blake2s(payload, digest_size=16).hexdigest()

        # Проверяем кэш
        if payload_hash in self.payload_analysis_cache:
            return self.payload_analysis_cache[payload_hash]

        LOG.debug(f"Analyzing payload for split positions (length: {len(payload)})")

        # Автоопределение типа payload
        if payload_type == "auto":
            payload_type = self.payload_analyzer.detect_payload_type(payload)

        analysis = PayloadAnalysisResult(payload_type=payload_type, total_length=len(payload))

        try:
            if payload_type == "tls_client_hello":
                await self.payload_analyzer.analyze_tls_client_hello(payload, analysis)
            elif payload_type == "http_request":
                await self.payload_analyzer.analyze_http_request(payload, analysis)
            else:
                await self.payload_analyzer.analyze_generic_payload(payload, analysis)

            # Генерация рекомендаций по split позициям
            self.payload_analyzer.generate_split_recommendations(analysis)

            # Кэширование результата
            self.payload_analysis_cache[payload_hash] = analysis
            self.stats["payload_analyses"] += 1

        except Exception as e:
            LOG.error("Payload analysis failed: %s", e, exc_info=True)

        return analysis

    async def update_parameter_weights(
        self, domain: str, strategy_results: List[Tuple[Dict[str, Any], bool, float]]
    ):
        """
        Обновление весов параметров стратегий на основе успешности.

        Args:
            domain: Целевой домен
            strategy_results: Результаты тестирования (стратегия, успех, время_ответа)
        """
        LOG.info(
            f"Updating parameter weights for {domain} based on {len(strategy_results)} results"
        )

        if domain not in self.parameter_weights:
            self.parameter_weights[domain] = {}

        domain_weights = self.parameter_weights[domain]

        # Разделение на успешные и неуспешные стратегии
        successful_strategies, failed_strategies = self.weight_analyzer.split_by_success(
            strategy_results
        )

        # Извлечение всех параметров
        all_parameters = self.weight_analyzer.extract_all_parameters(strategy_results)

        # Обновление весов для каждого параметра
        for param_name in all_parameters:
            successful_values = self.weight_analyzer.collect_parameter_values(
                successful_strategies, param_name
            )
            failed_values = self.weight_analyzer.collect_parameter_values(
                failed_strategies, param_name
            )

            self.weight_analyzer.update_weights_for_parameter(
                domain_weights, param_name, successful_values, failed_values
            )

        # Сохранение обновленных весов
        await self._save_parameter_weights()

        LOG.info(f"Parameter weights updated for {domain}")

    # Приватные методы для внутренней логики

    async def _initialize_population(self, domain: str, blocking_analysis: BlockingPatternAnalysis):
        """Инициализация популяции стратегий."""
        available_attacks = self.attack_param_generator.get_available_attacks(blocking_analysis)
        population = await self.population_manager.initialize_population(
            domain=domain,
            available_attacks=available_attacks,
            parameter_generator_func=self.attack_param_generator.generate_random_parameters,
            blocking_analysis=blocking_analysis,
        )
        self.population[domain] = population

    def _load_evolution_data(self):
        """Загрузка сохраненных данных эволюции."""
        # Загрузка весов параметров
        weights_file = self.data_dir / "parameter_weights.json"
        self.parameter_weights = load_json_config(weights_file, default={})
        if self.parameter_weights:
            LOG.info(f"Loaded parameter weights for {len(self.parameter_weights)} domains")

        # Загрузка популяций (упрощенная версия)
        populations_file = self.data_dir / "populations.json"
        populations_data = load_json_config(populations_file, default={})
        if populations_data:
            loaded = 0
            if isinstance(populations_data, dict):
                for domain, chromo_list in populations_data.items():
                    if not isinstance(chromo_list, list):
                        continue
                    chromosomes: List[StrategyChromosome] = []
                    for item in chromo_list:
                        if isinstance(item, dict):
                            try:
                                chromosomes.append(self._chromosome_from_dict(item))
                            except Exception:
                                LOG.debug(
                                    "Skipping invalid chromosome data for domain=%s",
                                    domain,
                                    exc_info=True,
                                )
                    if chromosomes:
                        self.population[str(domain)] = chromosomes
                        loaded += 1

            if loaded:
                LOG.info("Loaded saved populations for %d domains", loaded)
            else:
                LOG.debug("Found populations.json but nothing could be loaded safely")

    async def _save_parameter_weights(self):
        """Сохранение весов параметров."""
        weights_file = self.data_dir / "parameter_weights.json"
        try:
            save_json_config(weights_file, self.parameter_weights)
        except Exception as e:
            LOG.error("Failed to save parameter weights: %s", e, exc_info=True)

    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики работы генератора."""
        return {
            **self.stats,
            "active_populations": len(self.population),
            "cached_topologies": len(self.topology_cache),
            "cached_payload_analyses": len(self.payload_analysis_cache),
            "parameter_weight_domains": len(self.parameter_weights),
        }
