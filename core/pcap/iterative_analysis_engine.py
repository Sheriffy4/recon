"""
Интеллектуальная система итеративного анализа и адаптации

Задача 7.4: Создать интеллектуальную систему итеративного анализа и адаптации
- IterativeAnalysisEngine для многоуровневого анализа неудач
- Система накопления знаний о DPI поведении по итерациям
- Алгоритм корреляции PCAP паттернов с DPI fingerprint данными
- Адаптивная генерация стратегий на основе истории неудач
- Система обучения на основе успешных и неуспешных попыток
- Механизм эволюции стратегий через генетические алгоритмы
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set
import json
import hashlib
from pathlib import Path

# Импорт PCAP компонентов
try:
    from .intelligent_pcap_analyzer import PCAPAnalysisResult, BlockingType, DPISignature
    from .pcap_strategy_generator import PCAPGeneratedStrategy
    PCAP_COMPONENTS_AVAILABLE = True
except ImportError:
    PCAP_COMPONENTS_AVAILABLE = False

LOG = logging.getLogger("IterativeAnalysisEngine")


class LearningPhase(Enum):
    """Фазы обучения системы"""
    EXPLORATION = "exploration"      # Исследование новых стратегий
    EXPLOITATION = "exploitation"    # Использование лучших стратегий
    ADAPTATION = "adaptation"        # Адаптация к изменениям DPI
    EVOLUTION = "evolution"          # Эволюция стратегий


@dataclass
class IterationContext:
    """Контекст итерации анализа"""
    iteration_number: int
    domain: str
    phase: LearningPhase
    strategies_tested: List[str] = field(default_factory=list)
    successful_strategies: List[str] = field(default_factory=list)
    failed_strategies: List[str] = field(default_factory=list)
    pcap_analyses: List[PCAPAnalysisResult] = field(default_factory=list)
    knowledge_updates: List[Dict[str, Any]] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None


@dataclass
class DPIKnowledge:
    """Накопленные знания о DPI"""
    domain: str
    blocking_patterns: Dict[BlockingType, float] = field(default_factory=dict)
    effective_strategies: Dict[str, float] = field(default_factory=dict)
    ineffective_strategies: Set[str] = field(default_factory=set)
    dpi_evolution_timeline: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: datetime = field(default_factory=datetime.now)
    confidence: float = 0.5


@dataclass
class StrategyGene:
    """Ген стратегии для генетического алгоритма"""
    attack_type: str
    parameters: Dict[str, Any]
    fitness: float = 0.0
    generation: int = 0
    parent_genes: List[str] = field(default_factory=list)


class IterativeAnalysisEngine:
    """
    Ядро интеллектуального анализа для адаптивной системы обхода DPI
    
    Реализует требования FR-15.1, FR-15.2, FR-15.3, FR-15.4:
    - Многоуровневый анализ PCAP файлов по итерациям
    - Накопление знаний о DPI поведении
    - Корреляция паттернов и адаптивная генерация стратегий
    """
    
    def __init__(self):
        self.knowledge_base = {}  # domain -> DPIKnowledge
        self.iteration_history = {}  # domain -> List[IterationContext]
        self.strategy_gene_pool = {}  # strategy_id -> StrategyGene
        
        # Конфигурация обучения
        self.learning_config = {
            "max_iterations": 10,
            "exploration_rate": 0.3,
            "mutation_rate": 0.1,
            "crossover_rate": 0.7,
            "fitness_threshold": 0.8,
            "knowledge_decay_rate": 0.05
        }
        
        # Статистика работы
        self.stats = {
            "iterations_completed": 0,
            "knowledge_updates": 0,
            "strategy_evolutions": 0,
            "successful_adaptations": 0,
            "pcap_correlations": 0
        }
        
        # Файлы для сохранения состояния
        self.knowledge_file = "iterative_dpi_knowledge.json"
        self.gene_pool_file = "strategy_gene_pool.json"
        
        # Загружаем сохраненное состояние
        self._load_persistent_state()
        
        LOG.info("✅ IterativeAnalysisEngine инициализирован")
    
    async def analyze_pcap_iteration(self, domain: str, pcap_analysis: PCAPAnalysisResult,
                                   failed_strategy: Any, iteration_number: int) -> Dict[str, Any]:
        """
        Анализ PCAP файла в контексте итерации
        
        Args:
            domain: Доменное имя
            pcap_analysis: Результат PCAP анализа
            failed_strategy: Стратегия которая не сработала
            iteration_number: Номер итерации
            
        Returns:
            Результаты итеративного анализа
        """
        start_time = time.time()
        
        LOG.info(f"🔄 Итерация {iteration_number}: анализ PCAP для {domain}")
        
        try:
            # Получаем или создаем контекст итерации
            iteration_context = self._get_or_create_iteration_context(
                domain, iteration_number, failed_strategy
            )
            
            # Добавляем PCAP анализ в контекст
            iteration_context.pcap_analyses.append(pcap_analysis)
            
            # Обновляем знания о DPI
            knowledge_updates = await self._update_dpi_knowledge(
                domain, pcap_analysis, failed_strategy, iteration_context
            )
            iteration_context.knowledge_updates.extend(knowledge_updates)
            
            # Корреляция с предыдущими итерациями
            correlation_results = await self._correlate_with_previous_iterations(
                domain, pcap_analysis, iteration_context
            )
            
            # Определяем фазу обучения
            learning_phase = self._determine_learning_phase(domain, iteration_context)
            iteration_context.phase = learning_phase
            
            # Генерируем адаптивные стратегии
            adaptive_strategies = await self._generate_adaptive_strategies(
                domain, pcap_analysis, iteration_context, learning_phase
            )
            
            # Обновляем статистику
            analysis_time = time.time() - start_time
            self.stats["iterations_completed"] += 1
            self.stats["knowledge_updates"] += len(knowledge_updates)
            if correlation_results.get("correlations_found", 0) > 0:
                self.stats["pcap_correlations"] += 1
            
            # Завершаем итерацию
            iteration_context.end_time = datetime.now()
            
            result = {
                "iteration_number": iteration_number,
                "domain": domain,
                "learning_phase": learning_phase.value,
                "knowledge_updates": knowledge_updates,
                "correlation_results": correlation_results,
                "adaptive_strategies": adaptive_strategies,
                "analysis_time": analysis_time,
                "iteration_context": iteration_context
            }
            
            LOG.info(f"✅ Итерация {iteration_number} завершена за {analysis_time:.2f}s: "
                    f"фаза {learning_phase.value}, {len(adaptive_strategies)} стратегий")
            
            return result
            
        except Exception as e:
            LOG.error(f"❌ Ошибка итеративного анализа: {e}")
            return {"error": str(e)}
    
    async def _update_dpi_knowledge(self, domain: str, pcap_analysis: PCAPAnalysisResult,
                                  failed_strategy: Any, iteration_context: IterationContext) -> List[Dict[str, Any]]:
        """Обновление знаний о DPI на основе анализа"""
        updates = []
        
        try:
            # Получаем или создаем знания о домене
            if domain not in self.knowledge_base:
                self.knowledge_base[domain] = DPIKnowledge(domain=domain)
            
            knowledge = self.knowledge_base[domain]
            
            # Обновляем паттерны блокировок
            blocking_type = pcap_analysis.blocking_type
            if blocking_type in knowledge.blocking_patterns:
                # Скользящее среднее для confidence
                old_confidence = knowledge.blocking_patterns[blocking_type]
                new_confidence = (old_confidence * 0.7 + pcap_analysis.confidence * 0.3)
                knowledge.blocking_patterns[blocking_type] = new_confidence
            else:
                knowledge.blocking_patterns[blocking_type] = pcap_analysis.confidence
            
            updates.append({
                "type": "blocking_pattern_update",
                "blocking_type": blocking_type.value,
                "confidence": knowledge.blocking_patterns[blocking_type],
                "iteration": iteration_context.iteration_number
            })
            
            # Обновляем неэффективные стратегии
            strategy_name = getattr(failed_strategy, 'name', 'unknown')
            knowledge.ineffective_strategies.add(strategy_name)
            
            updates.append({
                "type": "ineffective_strategy_added",
                "strategy": strategy_name,
                "blocking_type": blocking_type.value,
                "iteration": iteration_context.iteration_number
            })
            
            # Добавляем в timeline эволюции DPI
            evolution_entry = {
                "timestamp": datetime.now().isoformat(),
                "iteration": iteration_context.iteration_number,
                "blocking_type": blocking_type.value,
                "confidence": pcap_analysis.confidence,
                "signatures_count": len(pcap_analysis.dpi_signatures),
                "failed_strategy": strategy_name
            }
            knowledge.dpi_evolution_timeline.append(evolution_entry)
            
            # Ограничиваем размер timeline
            if len(knowledge.dpi_evolution_timeline) > 100:
                knowledge.dpi_evolution_timeline = knowledge.dpi_evolution_timeline[-50:]
            
            updates.append({
                "type": "evolution_timeline_updated",
                "entry": evolution_entry
            })
            
            # Обновляем общую confidence и timestamp
            knowledge.last_updated = datetime.now()
            knowledge.confidence = self._calculate_knowledge_confidence(knowledge)
            
            LOG.debug(f"🧠 Обновлены знания о {domain}: {len(updates)} изменений")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка обновления знаний: {e}")
        
        return updates
    
    def _calculate_knowledge_confidence(self, knowledge: DPIKnowledge) -> float:
        """Вычисление общей confidence знаний"""
        if not knowledge.blocking_patterns:
            return 0.0
        
        # Средняя confidence по всем паттернам блокировок
        pattern_confidence = sum(knowledge.blocking_patterns.values()) / len(knowledge.blocking_patterns)
        
        # Бонус за количество данных
        data_bonus = min(len(knowledge.dpi_evolution_timeline) * 0.01, 0.2)
        
        # Штраф за устаревшие данные
        age_penalty = 0.0
        if knowledge.last_updated:
            age_days = (datetime.now() - knowledge.last_updated).days
            age_penalty = min(age_days * 0.01, 0.3)
        
        final_confidence = min(max(pattern_confidence + data_bonus - age_penalty, 0.1), 0.9)
        return final_confidence  
  
    async def _correlate_with_previous_iterations(self, domain: str, pcap_analysis: PCAPAnalysisResult,
                                                iteration_context: IterationContext) -> Dict[str, Any]:
        """Корреляция с предыдущими итерациями"""
        correlation_results = {
            "correlations_found": 0,
            "pattern_changes": [],
            "dpi_evolution_detected": False,
            "recommendations": []
        }
        
        try:
            if domain not in self.iteration_history:
                self.iteration_history[domain] = []
            
            previous_iterations = self.iteration_history[domain]
            
            if not previous_iterations:
                LOG.debug("Нет предыдущих итераций для корреляции")
                return correlation_results
            
            # Анализируем изменения в паттернах блокировок
            for prev_iteration in previous_iterations[-5:]:  # Последние 5 итераций
                for prev_pcap in prev_iteration.pcap_analyses:
                    if prev_pcap.blocking_type == pcap_analysis.blocking_type:
                        # Сравниваем confidence
                        confidence_change = pcap_analysis.confidence - prev_pcap.confidence
                        
                        if abs(confidence_change) > 0.2:
                            pattern_change = {
                                "blocking_type": pcap_analysis.blocking_type.value,
                                "confidence_change": confidence_change,
                                "previous_iteration": prev_iteration.iteration_number,
                                "current_iteration": iteration_context.iteration_number
                            }
                            correlation_results["pattern_changes"].append(pattern_change)
                            correlation_results["correlations_found"] += 1
            
            # Детекция эволюции DPI
            if len(previous_iterations) >= 3:
                recent_blocking_types = []
                for iteration in previous_iterations[-3:]:
                    for pcap in iteration.pcap_analyses:
                        recent_blocking_types.append(pcap.blocking_type)
                
                # Если появился новый тип блокировки
                if pcap_analysis.blocking_type not in recent_blocking_types:
                    correlation_results["dpi_evolution_detected"] = True
                    correlation_results["recommendations"].append(
                        f"Обнаружена эволюция DPI: новый тип блокировки {pcap_analysis.blocking_type.value}"
                    )
            
            # Анализ эффективности стратегий по итерациям
            strategy_effectiveness = self._analyze_strategy_effectiveness_trends(previous_iterations)
            if strategy_effectiveness:
                correlation_results["strategy_trends"] = strategy_effectiveness
            
            LOG.debug(f"🔗 Корреляция: {correlation_results['correlations_found']} связей найдено")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка корреляции: {e}")
        
        return correlation_results
    
    def _analyze_strategy_effectiveness_trends(self, previous_iterations: List[IterationContext]) -> Dict[str, Any]:
        """Анализ трендов эффективности стратегий"""
        trends = {}
        
        try:
            strategy_success_rates = {}
            
            for iteration in previous_iterations:
                total_strategies = len(iteration.strategies_tested)
                successful_strategies = len(iteration.successful_strategies)
                
                if total_strategies > 0:
                    success_rate = successful_strategies / total_strategies
                    
                    for strategy in iteration.strategies_tested:
                        if strategy not in strategy_success_rates:
                            strategy_success_rates[strategy] = []
                        
                        is_successful = strategy in iteration.successful_strategies
                        strategy_success_rates[strategy].append({
                            "iteration": iteration.iteration_number,
                            "successful": is_successful,
                            "success_rate": success_rate
                        })
            
            # Анализируем тренды
            for strategy, history in strategy_success_rates.items():
                if len(history) >= 2:
                    recent_success = sum(1 for h in history[-3:] if h["successful"])
                    total_recent = len(history[-3:])
                    
                    if total_recent > 0:
                        recent_rate = recent_success / total_recent
                        trends[strategy] = {
                            "recent_success_rate": recent_rate,
                            "total_attempts": len(history),
                            "trend": "improving" if recent_rate > 0.5 else "declining"
                        }
            
        except Exception as e:
            LOG.error(f"❌ Ошибка анализа трендов: {e}")
        
        return trends
    
    def _determine_learning_phase(self, domain: str, iteration_context: IterationContext) -> LearningPhase:
        """Определение фазы обучения"""
        try:
            iteration_number = iteration_context.iteration_number
            
            # Начальные итерации - исследование
            if iteration_number <= 2:
                return LearningPhase.EXPLORATION
            
            # Анализируем успешность предыдущих итераций
            if domain in self.iteration_history:
                recent_iterations = self.iteration_history[domain][-3:]
                total_success_rate = 0
                
                for iteration in recent_iterations:
                    if iteration.strategies_tested:
                        success_rate = len(iteration.successful_strategies) / len(iteration.strategies_tested)
                        total_success_rate += success_rate
                
                avg_success_rate = total_success_rate / len(recent_iterations) if recent_iterations else 0
                
                # Высокая успешность - эксплуатация
                if avg_success_rate > 0.6:
                    return LearningPhase.EXPLOITATION
                
                # Средняя успешность - адаптация
                elif avg_success_rate > 0.3:
                    return LearningPhase.ADAPTATION
                
                # Низкая успешность - эволюция
                else:
                    return LearningPhase.EVOLUTION
            
            return LearningPhase.EXPLORATION
            
        except Exception as e:
            LOG.error(f"❌ Ошибка определения фазы обучения: {e}")
            return LearningPhase.EXPLORATION
    
    async def _generate_adaptive_strategies(self, domain: str, pcap_analysis: PCAPAnalysisResult,
                                          iteration_context: IterationContext, 
                                          learning_phase: LearningPhase) -> List[Dict[str, Any]]:
        """Генерация адаптивных стратегий на основе фазы обучения"""
        adaptive_strategies = []
        
        try:
            knowledge = self.knowledge_base.get(domain)
            
            if learning_phase == LearningPhase.EXPLORATION:
                # Исследование новых стратегий
                strategies = await self._generate_exploration_strategies(pcap_analysis, knowledge)
                
            elif learning_phase == LearningPhase.EXPLOITATION:
                # Использование лучших известных стратегий
                strategies = await self._generate_exploitation_strategies(pcap_analysis, knowledge)
                
            elif learning_phase == LearningPhase.ADAPTATION:
                # Адаптация существующих стратегий
                strategies = await self._generate_adaptation_strategies(pcap_analysis, knowledge, iteration_context)
                
            elif learning_phase == LearningPhase.EVOLUTION:
                # Эволюция стратегий через генетические алгоритмы
                strategies = await self._generate_evolution_strategies(pcap_analysis, knowledge, iteration_context)
            
            else:
                strategies = []
            
            # Добавляем метаданные
            for strategy in strategies:
                strategy.update({
                    "learning_phase": learning_phase.value,
                    "iteration": iteration_context.iteration_number,
                    "domain": domain,
                    "generated_at": datetime.now().isoformat()
                })
            
            adaptive_strategies = strategies
            
            LOG.info(f"🎯 Сгенерировано {len(adaptive_strategies)} адаптивных стратегий "
                    f"для фазы {learning_phase.value}")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка генерации адаптивных стратегий: {e}")
        
        return adaptive_strategies
    
    async def _generate_exploration_strategies(self, pcap_analysis: PCAPAnalysisResult, 
                                             knowledge: Optional[DPIKnowledge]) -> List[Dict[str, Any]]:
        """Генерация стратегий для фазы исследования"""
        strategies = []
        
        # Базовые стратегии для исследования
        base_strategies = [
            {"attack": "fake", "params": {"ttl": random.randint(1, 5), "fooling": "badseq"}},
            {"attack": "disorder", "params": {"split_pos": random.randint(2, 10), "fooling": "badsum"}},
            {"attack": "split", "params": {"split_pos": "sni", "fooling": "badsum"}},
            {"attack": "multisplit", "params": {"split_count": random.randint(4, 12), "split_pos": "sni"}},
        ]
        
        for base in base_strategies:
            strategy = {
                "name": f"explore_{base['attack']}_{random.randint(1000, 9999)}",
                "attack_combination": [base["attack"]],
                "parameters": base["params"],
                "rationale": f"Исследование {base['attack']} для {pcap_analysis.blocking_type.value}",
                "expected_success_rate": 0.3,
                "priority": random.uniform(0.4, 0.7)
            }
            strategies.append(strategy)
        
        return strategies
    
    async def _generate_exploitation_strategies(self, pcap_analysis: PCAPAnalysisResult,
                                              knowledge: Optional[DPIKnowledge]) -> List[Dict[str, Any]]:
        """Генерация стратегий для фазы эксплуатации"""
        strategies = []
        
        if knowledge and knowledge.effective_strategies:
            # Используем лучшие известные стратегии
            sorted_strategies = sorted(
                knowledge.effective_strategies.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            for strategy_name, effectiveness in sorted_strategies[:3]:
                strategy = {
                    "name": f"exploit_{strategy_name}",
                    "attack_combination": [strategy_name.split('_')[0]],  # Упрощенное извлечение
                    "parameters": {"ttl": 3, "fooling": "badseq"},  # Базовые параметры
                    "rationale": f"Эксплуатация эффективной стратегии (rate: {effectiveness:.2f})",
                    "expected_success_rate": effectiveness,
                    "priority": 0.8 + effectiveness * 0.2
                }
                strategies.append(strategy)
        
        # Если нет эффективных стратегий, используем консервативные
        if not strategies:
            strategies = await self._generate_exploration_strategies(pcap_analysis, knowledge)
        
        return strategies
    
    async def _generate_adaptation_strategies(self, pcap_analysis: PCAPAnalysisResult,
                                            knowledge: Optional[DPIKnowledge],
                                            iteration_context: IterationContext) -> List[Dict[str, Any]]:
        """Генерация стратегий для фазы адаптации"""
        strategies = []
        
        # Адаптируем параметры на основе PCAP анализа
        if pcap_analysis.blocking_type == BlockingType.RST_INJECTION:
            # Для RST инъекций адаптируем TTL
            rst_analysis = pcap_analysis.analysis_details.get("rst_analysis", {})
            suspicious_rsts = rst_analysis.get("suspicious_details", [])
            
            if suspicious_rsts:
                min_ttl = min(rst["ttl"] for rst in suspicious_rsts)
                adapted_ttl = max(1, min_ttl - 1)
                
                strategy = {
                    "name": f"adapt_rst_ttl_{adapted_ttl}",
                    "attack_combination": ["fake"],
                    "parameters": {"ttl": adapted_ttl, "fooling": "badseq"},
                    "rationale": f"Адаптация TTL для обхода RST (min_rst_ttl: {min_ttl})",
                    "expected_success_rate": 0.7,
                    "priority": 0.8
                }
                strategies.append(strategy)
        
        elif pcap_analysis.blocking_type == BlockingType.SNI_FILTERING:
            # Для SNI фильтрации адаптируем позицию split
            tls_analysis = pcap_analysis.analysis_details.get("tls_analysis", {})
            sni_values = tls_analysis.get("sni_values", [])
            
            if sni_values:
                for sni in sni_values[:2]:  # Первые 2 SNI
                    strategy = {
                        "name": f"adapt_sni_split_{hashlib.md5(sni.encode()).hexdigest()[:8]}",
                        "attack_combination": ["split"],
                        "parameters": {"split_pos": "sni", "fooling": "badsum"},
                        "rationale": f"Адаптация для SNI: {sni}",
                        "expected_success_rate": 0.6,
                        "priority": 0.7
                    }
                    strategies.append(strategy)
        
        return strategies
    
    async def _generate_evolution_strategies(self, pcap_analysis: PCAPAnalysisResult,
                                           knowledge: Optional[DPIKnowledge],
                                           iteration_context: IterationContext) -> List[Dict[str, Any]]:
        """Генерация стратегий через генетические алгоритмы"""
        strategies = []
        
        try:
            # Создаем начальную популяцию генов
            if not self.strategy_gene_pool:
                self._initialize_gene_pool()
            
            # Селекция лучших генов
            selected_genes = self._select_genes_for_reproduction()
            
            # Скрещивание и мутация
            offspring_genes = []
            for i in range(0, len(selected_genes) - 1, 2):
                parent1 = selected_genes[i]
                parent2 = selected_genes[i + 1]
                
                if random.random() < self.learning_config["crossover_rate"]:
                    child1, child2 = self._crossover_genes(parent1, parent2)
                    offspring_genes.extend([child1, child2])
            
            # Мутация
            for gene in offspring_genes:
                if random.random() < self.learning_config["mutation_rate"]:
                    self._mutate_gene(gene)
            
            # Конвертируем гены в стратегии
            for gene in offspring_genes[:5]:  # Топ 5 потомков
                strategy = self._gene_to_strategy(gene, pcap_analysis)
                strategies.append(strategy)
            
            self.stats["strategy_evolutions"] += len(strategies)
            
            LOG.info(f"🧬 Эволюция: создано {len(strategies)} стратегий из {len(offspring_genes)} генов")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка эволюции стратегий: {e}")
        
        return strategies
    
    def _initialize_gene_pool(self):
        """Инициализация пула генов"""
        attacks = ["fake", "disorder", "split", "multisplit", "multidisorder"]
        
        for attack in attacks:
            for i in range(5):  # 5 генов на атаку
                gene_id = f"{attack}_{i}"
                gene = StrategyGene(
                    attack_type=attack,
                    parameters=self._generate_random_parameters(attack),
                    fitness=random.uniform(0.1, 0.5),
                    generation=0
                )
                self.strategy_gene_pool[gene_id] = gene
    
    def _generate_random_parameters(self, attack: str) -> Dict[str, Any]:
        """Генерация случайных параметров для атаки"""
        base_params = {"fooling": random.choice(["badseq", "badsum", "badack"])}
        
        if attack == "fake":
            base_params["ttl"] = random.randint(1, 10)
        elif attack in ["disorder", "split"]:
            base_params["split_pos"] = random.choice([2, 3, 5, 10, "sni", "host"])
        elif attack in ["multisplit", "multidisorder"]:
            base_params["split_count"] = random.randint(2, 16)
            base_params["split_pos"] = random.choice(["sni", "host", 5])
        
        return base_params 
   
    def _select_genes_for_reproduction(self) -> List[StrategyGene]:
        """Селекция генов для размножения"""
        # Турнирная селекция
        selected = []
        tournament_size = 3
        
        for _ in range(min(10, len(self.strategy_gene_pool))):
            tournament = random.sample(list(self.strategy_gene_pool.values()), 
                                     min(tournament_size, len(self.strategy_gene_pool)))
            winner = max(tournament, key=lambda g: g.fitness)
            selected.append(winner)
        
        return selected
    
    def _crossover_genes(self, parent1: StrategyGene, parent2: StrategyGene) -> Tuple[StrategyGene, StrategyGene]:
        """Скрещивание двух генов"""
        # Создаем потомков
        child1 = StrategyGene(
            attack_type=parent1.attack_type,
            parameters=parent1.parameters.copy(),
            generation=max(parent1.generation, parent2.generation) + 1,
            parent_genes=[f"{parent1.attack_type}_{parent1.generation}", 
                         f"{parent2.attack_type}_{parent2.generation}"]
        )
        
        child2 = StrategyGene(
            attack_type=parent2.attack_type,
            parameters=parent2.parameters.copy(),
            generation=max(parent1.generation, parent2.generation) + 1,
            parent_genes=[f"{parent1.attack_type}_{parent1.generation}", 
                         f"{parent2.attack_type}_{parent2.generation}"]
        )
        
        # Обмен параметрами
        if "ttl" in parent1.parameters and "ttl" in parent2.parameters:
            child1.parameters["ttl"] = parent2.parameters["ttl"]
            child2.parameters["ttl"] = parent1.parameters["ttl"]
        
        if "fooling" in parent1.parameters and "fooling" in parent2.parameters:
            child1.parameters["fooling"] = parent2.parameters["fooling"]
            child2.parameters["fooling"] = parent1.parameters["fooling"]
        
        return child1, child2
    
    def _mutate_gene(self, gene: StrategyGene):
        """Мутация гена"""
        mutation_type = random.choice(["parameter", "value"])
        
        if mutation_type == "parameter" and len(gene.parameters) > 1:
            # Удаляем случайный параметр
            param_to_remove = random.choice(list(gene.parameters.keys()))
            if param_to_remove != "fooling":  # Сохраняем fooling
                del gene.parameters[param_to_remove]
        
        elif mutation_type == "value":
            # Изменяем значение случайного параметра
            param_to_mutate = random.choice(list(gene.parameters.keys()))
            
            if param_to_mutate == "ttl":
                gene.parameters["ttl"] = random.randint(1, 10)
            elif param_to_mutate == "split_pos":
                gene.parameters["split_pos"] = random.choice([2, 3, 5, 10, "sni"])
            elif param_to_mutate == "split_count":
                gene.parameters["split_count"] = random.randint(2, 16)
            elif param_to_mutate == "fooling":
                gene.parameters["fooling"] = random.choice(["badseq", "badsum", "badack"])
    
    def _gene_to_strategy(self, gene: StrategyGene, pcap_analysis: PCAPAnalysisResult) -> Dict[str, Any]:
        """Конвертация гена в стратегию"""
        strategy = {
            "name": f"evolved_{gene.attack_type}_{gene.generation}_{random.randint(100, 999)}",
            "attack_combination": [gene.attack_type],
            "parameters": gene.parameters.copy(),
            "rationale": f"Эволюционная стратегия поколения {gene.generation} (fitness: {gene.fitness:.2f})",
            "expected_success_rate": gene.fitness,
            "priority": 0.5 + gene.fitness * 0.3,
            "genetic_info": {
                "generation": gene.generation,
                "parent_genes": gene.parent_genes,
                "fitness": gene.fitness
            }
        }
        
        return strategy
    
    def update_gene_fitness(self, strategy_name: str, success: bool, performance_metrics: Dict[str, Any]):
        """Обновление fitness гена на основе результатов тестирования"""
        try:
            # Ищем соответствующий ген
            for gene_id, gene in self.strategy_gene_pool.items():
                if strategy_name.startswith(f"evolved_{gene.attack_type}_{gene.generation}"):
                    # Обновляем fitness
                    if success:
                        gene.fitness = min(gene.fitness + 0.1, 1.0)
                    else:
                        gene.fitness = max(gene.fitness - 0.05, 0.1)
                    
                    LOG.debug(f"🧬 Обновлен fitness гена {gene_id}: {gene.fitness:.2f}")
                    break
        
        except Exception as e:
            LOG.error(f"❌ Ошибка обновления fitness: {e}")
    
    def _get_or_create_iteration_context(self, domain: str, iteration_number: int, 
                                       failed_strategy: Any) -> IterationContext:
        """Получение или создание контекста итерации"""
        if domain not in self.iteration_history:
            self.iteration_history[domain] = []
        
        # Ищем существующий контекст
        for context in self.iteration_history[domain]:
            if context.iteration_number == iteration_number:
                return context
        
        # Создаем новый контекст
        context = IterationContext(
            iteration_number=iteration_number,
            domain=domain,
            phase=LearningPhase.EXPLORATION
        )
        
        # Добавляем информацию о неудачной стратегии
        strategy_name = getattr(failed_strategy, 'name', 'unknown')
        context.strategies_tested.append(strategy_name)
        context.failed_strategies.append(strategy_name)
        
        self.iteration_history[domain].append(context)
        
        return context
    
    def _load_persistent_state(self):
        """Загрузка сохраненного состояния"""
        try:
            # Загрузка базы знаний
            if Path(self.knowledge_file).exists():
                with open(self.knowledge_file, 'r', encoding='utf-8') as f:
                    knowledge_data = json.load(f)
                
                for domain, data in knowledge_data.items():
                    knowledge = DPIKnowledge(domain=domain)
                    knowledge.blocking_patterns = {
                        BlockingType(k): v for k, v in data.get("blocking_patterns", {}).items()
                    }
                    knowledge.effective_strategies = data.get("effective_strategies", {})
                    knowledge.ineffective_strategies = set(data.get("ineffective_strategies", []))
                    knowledge.dpi_evolution_timeline = data.get("dpi_evolution_timeline", [])
                    knowledge.last_updated = datetime.fromisoformat(data.get("last_updated", datetime.now().isoformat()))
                    knowledge.confidence = data.get("confidence", 0.5)
                    
                    self.knowledge_base[domain] = knowledge
                
                LOG.info(f"📁 Загружена база знаний: {len(self.knowledge_base)} доменов")
            
            # Загрузка пула генов
            if Path(self.gene_pool_file).exists():
                with open(self.gene_pool_file, 'r', encoding='utf-8') as f:
                    gene_data = json.load(f)
                
                for gene_id, data in gene_data.items():
                    gene = StrategyGene(
                        attack_type=data["attack_type"],
                        parameters=data["parameters"],
                        fitness=data["fitness"],
                        generation=data["generation"],
                        parent_genes=data.get("parent_genes", [])
                    )
                    self.strategy_gene_pool[gene_id] = gene
                
                LOG.info(f"🧬 Загружен пул генов: {len(self.strategy_gene_pool)} генов")
        
        except Exception as e:
            LOG.warning(f"⚠️ Ошибка загрузки состояния: {e}")
    
    def _save_persistent_state(self):
        """Сохранение состояния"""
        try:
            # Сохранение базы знаний
            knowledge_data = {}
            for domain, knowledge in self.knowledge_base.items():
                knowledge_data[domain] = {
                    "blocking_patterns": {k.value: v for k, v in knowledge.blocking_patterns.items()},
                    "effective_strategies": knowledge.effective_strategies,
                    "ineffective_strategies": list(knowledge.ineffective_strategies),
                    "dpi_evolution_timeline": knowledge.dpi_evolution_timeline,
                    "last_updated": knowledge.last_updated.isoformat(),
                    "confidence": knowledge.confidence
                }
            
            with open(self.knowledge_file, 'w', encoding='utf-8') as f:
                json.dump(knowledge_data, f, indent=2, ensure_ascii=False)
            
            # Сохранение пула генов
            gene_data = {}
            for gene_id, gene in self.strategy_gene_pool.items():
                gene_data[gene_id] = {
                    "attack_type": gene.attack_type,
                    "parameters": gene.parameters,
                    "fitness": gene.fitness,
                    "generation": gene.generation,
                    "parent_genes": gene.parent_genes
                }
            
            with open(self.gene_pool_file, 'w', encoding='utf-8') as f:
                json.dump(gene_data, f, indent=2, ensure_ascii=False)
            
            LOG.debug("💾 Состояние сохранено")
        
        except Exception as e:
            LOG.error(f"❌ Ошибка сохранения состояния: {e}")
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """Получение статистики обучения"""
        stats = self.stats.copy()
        
        # Статистика базы знаний
        stats["knowledge_base"] = {
            "domains_count": len(self.knowledge_base),
            "total_blocking_patterns": sum(len(k.blocking_patterns) for k in self.knowledge_base.values()),
            "total_effective_strategies": sum(len(k.effective_strategies) for k in self.knowledge_base.values()),
            "average_confidence": sum(k.confidence for k in self.knowledge_base.values()) / len(self.knowledge_base) if self.knowledge_base else 0
        }
        
        # Статистика генетического алгоритма
        if self.strategy_gene_pool:
            fitnesses = [gene.fitness for gene in self.strategy_gene_pool.values()]
            stats["genetic_algorithm"] = {
                "gene_pool_size": len(self.strategy_gene_pool),
                "average_fitness": sum(fitnesses) / len(fitnesses),
                "max_fitness": max(fitnesses),
                "min_fitness": min(fitnesses),
                "max_generation": max(gene.generation for gene in self.strategy_gene_pool.values())
            }
        
        # Статистика итераций
        stats["iterations"] = {
            "domains_with_history": len(self.iteration_history),
            "total_iterations": sum(len(history) for history in self.iteration_history.values()),
            "average_iterations_per_domain": sum(len(history) for history in self.iteration_history.values()) / len(self.iteration_history) if self.iteration_history else 0
        }
        
        return stats
    
    async def cleanup_old_data(self, max_age_days: int = 30):
        """Очистка старых данных"""
        try:
            cleanup_count = 0
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            
            # Очистка старых записей в timeline
            for knowledge in self.knowledge_base.values():
                original_count = len(knowledge.dpi_evolution_timeline)
                knowledge.dpi_evolution_timeline = [
                    entry for entry in knowledge.dpi_evolution_timeline
                    if datetime.fromisoformat(entry["timestamp"]) > cutoff_date
                ]
                cleanup_count += original_count - len(knowledge.dpi_evolution_timeline)
            
            # Очистка старых итераций
            for domain, iterations in self.iteration_history.items():
                original_count = len(iterations)
                self.iteration_history[domain] = [
                    iteration for iteration in iterations
                    if iteration.start_time > cutoff_date
                ]
                cleanup_count += original_count - len(self.iteration_history[domain])
            
            if cleanup_count > 0:
                self._save_persistent_state()
                LOG.info(f"🧹 Очищено {cleanup_count} старых записей")
        
        except Exception as e:
            LOG.error(f"❌ Ошибка очистки данных: {e}")
    
    def __del__(self):
        """Деструктор - сохраняем состояние при завершении"""
        try:
            self._save_persistent_state()
        except:
            pass