"""
NextGenStrategyGenerator - адаптивный генератор стратегий следующего поколения.

Этот модуль реализует:
- Машинное обучение для генерации стратегий обхода
- Алгоритм генетической эволюции стратегий
- Систему весов для параметров стратегий на основе успешности
- Механизм мутации и кроссовера стратегий для поиска новых решений
- Адаптивную настройку TTL на основе сетевой топологии
- Интеллектуальный выбор позиций split на основе анализа payload

Requirements: FR-15.5, FR-15.6
"""

import asyncio
import logging
import random
import time
import statistics
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import json
import math
from collections import defaultdict, deque

# Интеграция с существующими модулями
try:
    from ..pcap_analysis.blocking_pattern_detector import (
        BlockingPatternAnalysis, DPIAggressivenessLevel, BlockingType
    )
    from ..learning.iterative_analysis_engine import (
        KnowledgePattern, StrategyEffectivenessMetrics
    )
    from ..bypass.attacks.attack_registry import get_attack_registry
    from ..strategy_failure_analyzer import FailureReport, FailureCause
    STRATEGY_COMPONENTS_AVAILABLE = True
except ImportError:
    STRATEGY_COMPONENTS_AVAILABLE = False
    logging.warning("Strategy components not available")

LOG = logging.getLogger("NextGenStrategyGenerator")


class EvolutionStrategy(Enum):
    """Стратегии эволюции."""
    GENETIC_ALGORITHM = "genetic_algorithm"
    PARTICLE_SWARM = "particle_swarm"
    SIMULATED_ANNEALING = "simulated_annealing"
    DIFFERENTIAL_EVOLUTION = "differential_evolution"
    HYBRID = "hybrid"


class MutationType(Enum):
    """Типы мутаций стратегий."""
    PARAMETER_TWEAK = "parameter_tweak"        # Небольшое изменение параметра
    PARAMETER_RANDOM = "parameter_random"      # Случайное значение параметра
    ATTACK_SUBSTITUTION = "attack_substitution" # Замена атаки на похожую
    ATTACK_ADDITION = "attack_addition"        # Добавление новой атаки
    ATTACK_REMOVAL = "attack_removal"          # Удаление атаки
    SEQUENCE_REORDER = "sequence_reorder"      # Изменение порядка атак


class CrossoverType(Enum):
    """Типы кроссовера стратегий."""
    SINGLE_POINT = "single_point"              # Одноточечный кроссовер
    MULTI_POINT = "multi_point"                # Многоточечный кроссовер
    UNIFORM = "uniform"                        # Равномерный кроссовер
    PARAMETER_BLEND = "parameter_blend"        # Смешивание параметров
    ATTACK_MERGE = "attack_merge"              # Слияние атак


@dataclass
class StrategyGene:
    """Ген стратегии для генетического алгоритма."""
    attack_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    enabled: bool = True
    
    def mutate(self, mutation_rate: float = 0.1) -> 'StrategyGene':
        """Мутация гена."""
        mutated = StrategyGene(
            attack_name=self.attack_name,
            parameters=self.parameters.copy(),
            weight=self.weight,
            enabled=self.enabled
        )
        
        if random.random() < mutation_rate:
            # Мутация параметров
            for param_name, param_value in mutated.parameters.items():
                if isinstance(param_value, (int, float)):
                    # Числовые параметры - добавляем шум
                    noise = random.gauss(0, abs(param_value) * 0.1)
                    mutated.parameters[param_name] = max(0, param_value + noise)
                elif isinstance(param_value, bool):
                    # Булевы параметры - инвертируем с малой вероятностью
                    if random.random() < 0.1:
                        mutated.parameters[param_name] = not param_value
            
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
    
    def calculate_fitness(self, 
                         effectiveness_metrics: Dict[str, StrategyEffectivenessMetrics],
                         domain: str) -> float:
        """Расчет приспособленности хромосомы."""
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
                success_component = metrics.success_rate * gene.weight
                reliability_component = metrics.reliability_score * 0.5
                speed_component = (1.0 / max(metrics.average_response_time, 0.1)) * 0.3
                
                gene_fitness = success_component + reliability_component + speed_component
                fitness_components.append(gene_fitness)
            else:
                # Нет данных - базовая оценка
                fitness_components.append(0.5 * gene.weight)
        
        self.fitness = statistics.mean(fitness_components) if fitness_components else 0.0
        return self.fitness
    
    def crossover(self, other: 'StrategyChromosome', crossover_type: CrossoverType) -> Tuple['StrategyChromosome', 'StrategyChromosome']:
        """Кроссовер с другой хромосомой."""
        child1_genes = []
        child2_genes = []
        
        if crossover_type == CrossoverType.SINGLE_POINT:
            # Одноточечный кроссовер
            crossover_point = random.randint(1, min(len(self.genes), len(other.genes)) - 1)
            
            child1_genes = self.genes[:crossover_point] + other.genes[crossover_point:]
            child2_genes = other.genes[:crossover_point] + self.genes[crossover_point:]
        
        elif crossover_type == CrossoverType.UNIFORM:
            # Равномерный кроссовер
            max_length = max(len(self.genes), len(other.genes))
            
            for i in range(max_length):
                if random.random() < 0.5:
                    if i < len(self.genes):
                        child1_genes.append(self.genes[i])
                    if i < len(other.genes):
                        child2_genes.append(other.genes[i])
                else:
                    if i < len(other.genes):
                        child1_genes.append(other.genes[i])
                    if i < len(self.genes):
                        child2_genes.append(self.genes[i])
        
        elif crossover_type == CrossoverType.PARAMETER_BLEND:
            # Смешивание параметров
            all_attacks = set(gene.attack_name for gene in self.genes + other.genes)
            
            for attack_name in all_attacks:
                self_gene = next((g for g in self.genes if g.attack_name == attack_name), None)
                other_gene = next((g for g in other.genes if g.attack_name == attack_name), None)
                
                if self_gene and other_gene:
                    # Смешиваем параметры
                    blended_params = {}
                    all_params = set(self_gene.parameters.keys()) | set(other_gene.parameters.keys())
                    
                    for param_name in all_params:
                        self_value = self_gene.parameters.get(param_name, 0)
                        other_value = other_gene.parameters.get(param_name, 0)
                        
                        if isinstance(self_value, (int, float)) and isinstance(other_value, (int, float)):
                            # Числовые параметры - линейная интерполяция
                            alpha = random.random()
                            blended_params[param_name] = self_value * alpha + other_value * (1 - alpha)
                        else:
                            # Остальные параметры - случайный выбор
                            blended_params[param_name] = random.choice([self_value, other_value])
                    
                    # Создаем гены для потомков
                    child1_gene = StrategyGene(
                        attack_name=attack_name,
                        parameters=blended_params,
                        weight=(self_gene.weight + other_gene.weight) / 2,
                        enabled=self_gene.enabled and other_gene.enabled
                    )
                    child1_genes.append(child1_gene)
                    
                    child2_gene = StrategyGene(
                        attack_name=attack_name,
                        parameters=blended_params.copy(),
                        weight=(self_gene.weight + other_gene.weight) / 2,
                        enabled=self_gene.enabled or other_gene.enabled
                    )
                    child2_genes.append(child2_gene)
                
                elif self_gene:
                    child1_genes.append(self_gene)
                elif other_gene:
                    child2_genes.append(other_gene)
        
        # Создание потомков
        child1 = StrategyChromosome(
            chromosome_id=f"child_{int(time.time())}_{random.randint(1000, 9999)}",
            genes=child1_genes,
            generation=max(self.generation, other.generation) + 1,
            parent_ids=[self.chromosome_id, other.chromosome_id]
        )
        
        child2 = StrategyChromosome(
            chromosome_id=f"child_{int(time.time())}_{random.randint(1000, 9999)}",
            genes=child2_genes,
            generation=max(self.generation, other.generation) + 1,
            parent_ids=[self.chromosome_id, other.chromosome_id]
        )
        
        return child1, child2
    
    def mutate(self, mutation_rate: float = 0.1, mutation_types: List[MutationType] = None) -> 'StrategyChromosome':
        """Мутация хромосомы."""
        if mutation_types is None:
            mutation_types = [MutationType.PARAMETER_TWEAK, MutationType.PARAMETER_RANDOM]
        
        mutated = StrategyChromosome(
            chromosome_id=f"mutant_{int(time.time())}_{random.randint(1000, 9999)}",
            genes=[gene.mutate(mutation_rate) for gene in self.genes],
            generation=self.generation + 1,
            parent_ids=[self.chromosome_id]
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
    mutation_types: List[MutationType] = field(default_factory=lambda: [
        MutationType.PARAMETER_TWEAK, MutationType.PARAMETER_RANDOM
    ])
    
    # Критерии остановки
    max_generations_without_improvement: int = 10
    target_fitness: float = 0.95
    max_evolution_time_minutes: int = 30


@dataclass
class NetworkTopologyInfo:
    """Информация о сетевой топологии для адаптивной настройки TTL."""
    domain: str
    target_ip: str
    
    # Характеристики маршрута
    hop_count: Optional[int] = None
    intermediate_hops: List[str] = field(default_factory=list)
    rtt_ms: Optional[float] = None
    
    # Анализ TTL
    observed_ttl_values: List[int] = field(default_factory=list)
    estimated_initial_ttl: Optional[int] = None
    ttl_decrement_pattern: List[int] = field(default_factory=list)
    
    # DPI характеристики
    dpi_hop_estimate: Optional[int] = None
    dpi_detection_timing_ms: Optional[float] = None
    
    # Рекомендации
    recommended_ttl_range: Tuple[int, int] = (1, 64)
    optimal_ttl: Optional[int] = None


@dataclass
class PayloadAnalysisResult:
    """Результат анализа payload для интеллектуального выбора позиций split."""
    payload_type: str  # "tls_client_hello", "http_request", "generic"
    total_length: int
    
    # Критические позиции
    critical_positions: List[int] = field(default_factory=list)
    safe_split_positions: List[int] = field(default_factory=list)
    avoid_positions: List[int] = field(default_factory=list)
    
    # Анализ содержимого
    contains_sni: bool = False
    sni_position: Optional[int] = None
    contains_host_header: bool = False
    host_header_position: Optional[int] = None
    
    # Рекомендации
    recommended_split_positions: List[int] = field(default_factory=list)
    split_strategy: str = "random"  # "random", "targeted", "multi_point"


class NextGenStrategyGenerator:
    """
    Адаптивный генератор стратегий следующего поколения.
    
    Использует машинное обучение и генетические алгоритмы для
    эволюции стратегий обхода DPI.
    """
    
    def __init__(self, 
                 data_dir: str = "data/next_gen_strategies",
                 evolution_params: Optional[EvolutionParameters] = None):
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
        
        # Статистика
        self.stats = {
            "populations_evolved": 0,
            "generations_computed": 0,
            "strategies_generated": 0,
            "successful_mutations": 0,
            "successful_crossovers": 0,
            "topology_analyses": 0,
            "payload_analyses": 0
        }
        
        # Загрузка сохраненных данных
        self._load_evolution_data()
        
        LOG.info("NextGenStrategyGenerator initialized")
    
    async def evolve_strategies(self, 
                              domain: str,
                              blocking_analysis: BlockingPatternAnalysis,
                              effectiveness_metrics: Dict[str, StrategyEffectivenessMetrics],
                              target_count: int = 10) -> List[Dict[str, Any]]:
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
        
        for generation in range(self.evolution_params.generations):
            generation_start = time.time()
            
            # Оценка приспособленности
            for chromosome in population:
                chromosome.calculate_fitness(effectiveness_metrics, domain)
            
            # Сортировка по приспособленности
            population.sort(key=lambda c: c.fitness, reverse=True)
            
            current_best_fitness = population[0].fitness
            best_fitness_history.append(current_best_fitness)
            
            LOG.debug(f"Generation {generation}: best fitness = {current_best_fitness:.3f}")
            
            # Проверка критериев остановки
            if current_best_fitness >= self.evolution_params.target_fitness:
                LOG.info(f"Target fitness reached in generation {generation}")
                break
            
            if generation > 0 and current_best_fitness <= best_fitness_history[-2]:
                generations_without_improvement += 1
            else:
                generations_without_improvement = 0
            
            if generations_without_improvement >= self.evolution_params.max_generations_without_improvement:
                LOG.info(f"No improvement for {generations_without_improvement} generations, stopping")
                break
            
            # Проверка времени
            elapsed_minutes = (time.time() - start_time) / 60
            if elapsed_minutes >= self.evolution_params.max_evolution_time_minutes:
                LOG.info(f"Evolution time limit reached ({elapsed_minutes:.1f} minutes)")
                break
            
            # Селекция элиты
            elite = population[:self.evolution_params.elite_size]
            
            # Создание нового поколения
            new_population = elite.copy()
            
            while len(new_population) < self.evolution_params.population_size:
                # Селекция родителей (турнирная селекция)
                parent1 = self._tournament_selection(population)
                parent2 = self._tournament_selection(population)
                
                # Кроссовер
                if random.random() < self.evolution_params.crossover_rate:
                    child1, child2 = parent1.crossover(parent2, self.evolution_params.crossover_type)
                    
                    # Мутация
                    if random.random() < self.evolution_params.mutation_rate:
                        child1 = child1.mutate(
                            self.evolution_params.mutation_rate,
                            self.evolution_params.mutation_types
                        )
                        self.stats["successful_mutations"] += 1
                    
                    if random.random() < self.evolution_params.mutation_rate:
                        child2 = child2.mutate(
                            self.evolution_params.mutation_rate,
                            self.evolution_params.mutation_types
                        )
                        self.stats["successful_mutations"] += 1
                    
                    new_population.extend([child1, child2])
                    self.stats["successful_crossovers"] += 1
                else:
                    # Клонирование с мутацией
                    clone = parent1.mutate(
                        self.evolution_params.mutation_rate,
                        self.evolution_params.mutation_types
                    )
                    new_population.append(clone)
            
            # Обрезка до нужного размера
            population = new_population[:self.evolution_params.population_size]
            
            # Сохранение истории поколения
            generation_stats = {
                "generation": generation,
                "best_fitness": current_best_fitness,
                "average_fitness": statistics.mean(c.fitness for c in population),
                "diversity": self._calculate_population_diversity(population),
                "generation_time_ms": (time.time() - generation_start) * 1000
            }
            
            if domain not in self.generation_history:
                self.generation_history[domain] = []
            self.generation_history[domain].append(generation_stats)
        
        # Обновление популяции
        self.population[domain] = population
        
        # Конвертация лучших хромосом в стратегии
        best_chromosomes = population[:target_count]
        strategies = []
        
        for chromosome in best_chromosomes:
            strategy = await self._chromosome_to_strategy(domain, chromosome, blocking_analysis)
            strategies.append(strategy)
        
        # Обновление статистики
        self.stats["populations_evolved"] += 1
        self.stats["generations_computed"] += len(best_fitness_history)
        self.stats["strategies_generated"] += len(strategies)
        
        evolution_time = time.time() - start_time
        LOG.info(f"Strategy evolution completed for {domain} in {evolution_time:.2f}s, generated {len(strategies)} strategies")
        
        return strategies
    
    async def adaptive_ttl_optimization(self, 
                                      domain: str,
                                      target_ip: str) -> NetworkTopologyInfo:
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
        
        topology_info = NetworkTopologyInfo(
            domain=domain,
            target_ip=target_ip
        )
        
        try:
            # Анализ маршрута (упрощенная версия без внешних зависимостей)
            await self._analyze_network_route(topology_info)
            
            # Анализ TTL паттернов
            await self._analyze_ttl_patterns(topology_info)
            
            # Оценка позиции DPI
            await self._estimate_dpi_position(topology_info)
            
            # Генерация рекомендаций по TTL
            self._generate_ttl_recommendations(topology_info)
            
            # Кэширование результата
            self.topology_cache[cache_key] = topology_info
            self.stats["topology_analyses"] += 1
            
            LOG.info(f"Network topology analysis completed for {domain}, optimal TTL: {topology_info.optimal_ttl}")
            
        except Exception as e:
            LOG.error(f"Network topology analysis failed for {domain}: {e}")
        
        return topology_info
    
    async def intelligent_split_position_selection(self, 
                                                 payload: bytes,
                                                 payload_type: str = "auto") -> PayloadAnalysisResult:
        """
        Интеллектуальный выбор позиций split на основе анализа payload.
        
        Args:
            payload: Данные для анализа
            payload_type: Тип payload ("tls_client_hello", "http_request", "auto")
            
        Returns:
            Результат анализа с рекомендациями по позициям split
        """
        payload_hash = hashlib.md5(payload).hexdigest()
        
        # Проверяем кэш
        if payload_hash in self.payload_analysis_cache:
            return self.payload_analysis_cache[payload_hash]
        
        LOG.debug(f"Analyzing payload for split positions (length: {len(payload)})")
        
        # Автоопределение типа payload
        if payload_type == "auto":
            payload_type = self._detect_payload_type(payload)
        
        analysis = PayloadAnalysisResult(
            payload_type=payload_type,
            total_length=len(payload)
        )
        
        try:
            if payload_type == "tls_client_hello":
                await self._analyze_tls_client_hello(payload, analysis)
            elif payload_type == "http_request":
                await self._analyze_http_request(payload, analysis)
            else:
                await self._analyze_generic_payload(payload, analysis)
            
            # Генерация рекомендаций по split позициям
            self._generate_split_recommendations(analysis)
            
            # Кэширование результата
            self.payload_analysis_cache[payload_hash] = analysis
            self.stats["payload_analyses"] += 1
            
        except Exception as e:
            LOG.error(f"Payload analysis failed: {e}")
        
        return analysis
    
    async def update_parameter_weights(self, 
                                     domain: str,
                                     strategy_results: List[Tuple[Dict[str, Any], bool, float]]):
        """
        Обновление весов параметров стратегий на основе успешности.
        
        Args:
            domain: Целевой домен
            strategy_results: Результаты тестирования (стратегия, успех, время_ответа)
        """
        LOG.info(f"Updating parameter weights for {domain} based on {len(strategy_results)} results")
        
        if domain not in self.parameter_weights:
            self.parameter_weights[domain] = {}
        
        domain_weights = self.parameter_weights[domain]
        
        # Анализ успешных и неуспешных стратегий
        successful_strategies = [s for s, success, _ in strategy_results if success]
        failed_strategies = [s for s, success, _ in strategy_results if not success]
        
        # Обновление весов для каждого параметра
        all_parameters = set()
        for strategy, _, _ in strategy_results:
            if 'parameters' in strategy:
                all_parameters.update(strategy['parameters'].keys())
        
        for param_name in all_parameters:
            if param_name not in domain_weights:
                domain_weights[param_name] = {}
            
            # Анализ значений параметра в успешных стратегиях
            successful_values = []
            failed_values = []
            
            for strategy in successful_strategies:
                if param_name in strategy.get('parameters', {}):
                    successful_values.append(strategy['parameters'][param_name])
            
            for strategy in failed_strategies:
                if param_name in strategy.get('parameters', {}):
                    failed_values.append(strategy['parameters'][param_name])
            
            # Обновление весов на основе успешности
            if successful_values:
                # Для числовых параметров - анализ распределения
                if all(isinstance(v, (int, float)) for v in successful_values):
                    mean_successful = statistics.mean(successful_values)
                    
                    # Увеличиваем вес для успешных значений
                    for value in successful_values:
                        value_key = str(value)
                        if value_key not in domain_weights[param_name]:
                            domain_weights[param_name][value_key] = 1.0
                        domain_weights[param_name][value_key] *= 1.1  # Увеличиваем вес
                
                # Для категориальных параметров - подсчет частоты
                else:
                    for value in successful_values:
                        value_key = str(value)
                        if value_key not in domain_weights[param_name]:
                            domain_weights[param_name][value_key] = 1.0
                        domain_weights[param_name][value_key] *= 1.2
            
            # Уменьшение весов для неуспешных значений
            for value in failed_values:
                value_key = str(value)
                if value_key not in domain_weights[param_name]:
                    domain_weights[param_name][value_key] = 1.0
                domain_weights[param_name][value_key] *= 0.9  # Уменьшаем вес
        
        # Сохранение обновленных весов
        await self._save_parameter_weights()
        
        LOG.info(f"Parameter weights updated for {domain}")
    
    # Приватные методы для внутренней логики
    
    async def _initialize_population(self, 
                                   domain: str,
                                   blocking_analysis: BlockingPatternAnalysis):
        """Инициализация популяции стратегий."""
        LOG.debug(f"Initializing population for {domain}")
        
        population = []
        
        # Получение доступных атак (заглушка, требует интеграции с реестром)
        available_attacks = self._get_available_attacks(blocking_analysis)
        
        for i in range(self.evolution_params.population_size):
            # Случайный выбор атак для хромосомы
            num_attacks = random.randint(1, min(4, len(available_attacks)))
            selected_attacks = random.sample(available_attacks, num_attacks)
            
            genes = []
            for attack_name in selected_attacks:
                # Генерация случайных параметров
                parameters = self._generate_random_parameters(attack_name, blocking_analysis)
                
                gene = StrategyGene(
                    attack_name=attack_name,
                    parameters=parameters,
                    weight=random.uniform(0.5, 2.0),
                    enabled=True
                )
                genes.append(gene)
            
            chromosome = StrategyChromosome(
                chromosome_id=f"{domain}_init_{i}",
                genes=genes,
                generation=0
            )
            population.append(chromosome)
        
        self.population[domain] = population
        LOG.debug(f"Initialized population of {len(population)} chromosomes for {domain}")
    
    def _tournament_selection(self, population: List[StrategyChromosome], tournament_size: int = 3) -> StrategyChromosome:
        """Турнирная селекция."""
        tournament = random.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda c: c.fitness)
    
    def _calculate_population_diversity(self, population: List[StrategyChromosome]) -> float:
        """Расчет разнообразия популяции."""
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
    
    async def _chromosome_to_strategy(self, 
                                    domain: str,
                                    chromosome: StrategyChromosome,
                                    blocking_analysis: BlockingPatternAnalysis) -> Dict[str, Any]:
        """Конвертация хромосомы в стратегию."""
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
                "created_at": chromosome.created_at.isoformat()
            }
        }
        
        # Конвертация генов в атаки
        for gene in chromosome.genes:
            if gene.enabled:
                attack_config = {
                    "name": gene.attack_name,
                    "parameters": gene.parameters,
                    "weight": gene.weight
                }
                strategy["attacks"].append(attack_config)
                
                # Объединение параметров
                for param_name, param_value in gene.parameters.items():
                    strategy["parameters"][f"{gene.attack_name}_{param_name}"] = param_value
        
        return strategy
    
    def _get_available_attacks(self, blocking_analysis: BlockingPatternAnalysis) -> List[str]:
        """Получение доступных атак на основе анализа блокировки."""
        # Базовый набор атак (заглушка)
        base_attacks = [
            "fake", "multisplit", "disorder", "tls_sni_split",
            "tls_chello_frag", "http_split", "tcp_split"
        ]
        
        # Фильтрация атак на основе типа блокировки
        if blocking_analysis.primary_blocking_type == BlockingType.SNI_FILTERING:
            return ["fake", "tls_sni_split", "tls_chello_frag", "disorder"]
        elif blocking_analysis.primary_blocking_type == BlockingType.RST_INJECTION:
            return ["fake", "disorder", "multisplit", "tcp_split"]
        else:
            return base_attacks
    
    def _generate_random_parameters(self, 
                                  attack_name: str,
                                  blocking_analysis: BlockingPatternAnalysis) -> Dict[str, Any]:
        """Генерация случайных параметров для атаки."""
        parameters = {}
        
        # Базовые параметры для разных типов атак
        if "split" in attack_name:
            parameters["split_position"] = random.randint(1, 100)
            parameters["split_count"] = random.randint(1, 5)
        
        if "fake" in attack_name:
            parameters["fake_ttl"] = random.randint(1, 32)
            parameters["fake_count"] = random.randint(1, 3)
        
        if "disorder" in attack_name:
            parameters["disorder_count"] = random.randint(2, 10)
            parameters["disorder_delay_ms"] = random.randint(1, 100)
        
        if "tls" in attack_name:
            parameters["tls_record_split"] = random.choice([True, False])
            parameters["sni_obfuscation"] = random.choice([True, False])
        
        # Общие параметры
        parameters["enabled"] = True
        parameters["priority"] = random.uniform(0.1, 1.0)
        
        return parameters
    
    async def _analyze_network_route(self, topology_info: NetworkTopologyInfo):
        """Анализ сетевого маршрута (упрощенная версия)."""
        # Заглушка для анализа маршрута
        # В реальной реализации здесь был бы traceroute или аналогичный анализ
        topology_info.hop_count = random.randint(8, 20)
        topology_info.rtt_ms = random.uniform(10.0, 200.0)
        topology_info.intermediate_hops = [f"hop_{i}" for i in range(topology_info.hop_count)]
    
    async def _analyze_ttl_patterns(self, topology_info: NetworkTopologyInfo):
        """Анализ паттернов TTL."""
        # Симуляция наблюдаемых TTL значений
        topology_info.observed_ttl_values = [
            random.randint(50, 64) for _ in range(10)
        ]
        
        if topology_info.observed_ttl_values:
            # Оценка начального TTL
            max_observed = max(topology_info.observed_ttl_values)
            if max_observed <= 64:
                topology_info.estimated_initial_ttl = 64
            elif max_observed <= 128:
                topology_info.estimated_initial_ttl = 128
            else:
                topology_info.estimated_initial_ttl = 255
    
    async def _estimate_dpi_position(self, topology_info: NetworkTopologyInfo):
        """Оценка позиции DPI в маршруте."""
        if topology_info.hop_count:
            # Предполагаем, что DPI находится в первой трети маршрута
            topology_info.dpi_hop_estimate = random.randint(1, topology_info.hop_count // 3)
            topology_info.dpi_detection_timing_ms = random.uniform(1.0, 50.0)
    
    def _generate_ttl_recommendations(self, topology_info: NetworkTopologyInfo):
        """Генерация рекомендаций по TTL."""
        if topology_info.dpi_hop_estimate:
            # Рекомендуем TTL меньше позиции DPI
            min_ttl = 1
            max_ttl = max(topology_info.dpi_hop_estimate - 1, 1)
            topology_info.recommended_ttl_range = (min_ttl, max_ttl)
            topology_info.optimal_ttl = max_ttl
        else:
            # Базовые рекомендации
            topology_info.recommended_ttl_range = (1, 32)
            topology_info.optimal_ttl = 16
    
    def _detect_payload_type(self, payload: bytes) -> str:
        """Автоопределение типа payload."""
        if len(payload) > 5:
            # TLS Client Hello
            if payload[0] == 0x16 and payload[1] == 0x03:
                return "tls_client_hello"
            
            # HTTP запрос
            if payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'PUT '):
                return "http_request"
        
        return "generic"
    
    async def _analyze_tls_client_hello(self, payload: bytes, analysis: PayloadAnalysisResult):
        """Анализ TLS Client Hello для выбора позиций split."""
        try:
            # Поиск SNI extension
            sni_position = payload.find(b'\x00\x00')  # Упрощенный поиск SNI
            if sni_position != -1:
                analysis.contains_sni = True
                analysis.sni_position = sni_position
                analysis.critical_positions.append(sni_position)
                
                # Позиции до и после SNI - критические
                analysis.avoid_positions.extend([
                    sni_position - 1, sni_position, sni_position + 1
                ])
            
            # Безопасные позиции для split
            safe_positions = []
            for i in range(5, len(payload) - 5, 10):  # Каждые 10 байт, избегая краев
                if i not in analysis.avoid_positions:
                    safe_positions.append(i)
            
            analysis.safe_split_positions = safe_positions[:10]  # Максимум 10 позиций
            
        except Exception as e:
            LOG.error(f"TLS Client Hello analysis failed: {e}")
    
    async def _analyze_http_request(self, payload: bytes, analysis: PayloadAnalysisResult):
        """Анализ HTTP запроса для выбора позиций split."""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Поиск Host заголовка
            host_match = payload_str.find('Host:')
            if host_match != -1:
                analysis.contains_host_header = True
                analysis.host_header_position = host_match
                analysis.critical_positions.append(host_match)
                
                # Избегаем split в области Host заголовка
                analysis.avoid_positions.extend(range(host_match - 5, host_match + 50))
            
            # Безопасные позиции - между заголовками
            lines = payload_str.split('\r\n')
            current_pos = 0
            
            for line in lines:
                if line and not line.startswith('Host:'):
                    # Позиция в конце строки - безопасна для split
                    line_end = current_pos + len(line)
                    if line_end not in analysis.avoid_positions:
                        analysis.safe_split_positions.append(line_end)
                
                current_pos += len(line) + 2  # +2 для \r\n
            
        except Exception as e:
            LOG.error(f"HTTP request analysis failed: {e}")
    
    async def _analyze_generic_payload(self, payload: bytes, analysis: PayloadAnalysisResult):
        """Анализ общего payload для выбора позиций split."""
        # Простая стратегия - равномерное распределение позиций
        step = max(len(payload) // 10, 1)
        
        for i in range(step, len(payload) - step, step):
            analysis.safe_split_positions.append(i)
    
    def _generate_split_recommendations(self, analysis: PayloadAnalysisResult):
        """Генерация рекомендаций по позициям split."""
        if analysis.contains_sni or analysis.contains_host_header:
            # Целевая стратегия - избегаем критических позиций
            analysis.split_strategy = "targeted"
            analysis.recommended_split_positions = analysis.safe_split_positions[:5]
        else:
            # Случайная стратегия
            analysis.split_strategy = "random"
            if analysis.safe_split_positions:
                analysis.recommended_split_positions = random.sample(
                    analysis.safe_split_positions,
                    min(5, len(analysis.safe_split_positions))
                )
            else:
                # Fallback - равномерное распределение
                step = max(analysis.total_length // 5, 1)
                analysis.recommended_split_positions = list(range(step, analysis.total_length, step))[:5]
    
    def _load_evolution_data(self):
        """Загрузка сохраненных данных эволюции."""
        try:
            # Загрузка весов параметров
            weights_file = self.data_dir / "parameter_weights.json"
            if weights_file.exists():
                with open(weights_file, 'r', encoding='utf-8') as f:
                    self.parameter_weights = json.load(f)
                LOG.info(f"Loaded parameter weights for {len(self.parameter_weights)} domains")
            
            # Загрузка популяций (упрощенная версия)
            populations_file = self.data_dir / "populations.json"
            if populations_file.exists():
                with open(populations_file, 'r', encoding='utf-8') as f:
                    populations_data = json.load(f)
                    # Конвертация обратно в объекты (упрощенная)
                    LOG.info(f"Found saved populations for {len(populations_data)} domains")
        
        except Exception as e:
            LOG.error(f"Failed to load evolution data: {e}")
    
    async def _save_parameter_weights(self):
        """Сохранение весов параметров."""
        try:
            weights_file = self.data_dir / "parameter_weights.json"
            with open(weights_file, 'w', encoding='utf-8') as f:
                json.dump(self.parameter_weights, f, indent=2, ensure_ascii=False)
        except Exception as e:
            LOG.error(f"Failed to save parameter weights: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики работы генератора."""
        return {
            **self.stats,
            "active_populations": len(self.population),
            "cached_topologies": len(self.topology_cache),
            "cached_payload_analyses": len(self.payload_analysis_cache),
            "parameter_weight_domains": len(self.parameter_weights)
        }