"""
IterativeAnalysisEngine - ядро интеллектуального анализа для адаптивной системы обхода DPI.

Этот модуль реализует многоуровневый итеративный анализ для:
- Анализа PCAP файлов по итерациям с накоплением знаний
- Корреляции DPI fingerprint с PCAP данными
- Генерации адаптивных стратегий на основе анализа
- Накопления знаний между итерациями
- Оценки эффективности стратегий

Requirements: FR-15.1, FR-15.2
"""

import asyncio
import json
import logging
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import concurrent.futures
from collections import defaultdict, deque
import statistics

# Интеграция с существующими модулями
try:
    from ..pcap_analysis.intelligent_pcap_analyzer import (
        IntelligentPCAPAnalyzer, PCAPAnalysisResult, BlockingType, DPIBehavior, FlowAnalysis
    )
    from ..pcap_analysis.pcap_strategy_generator import (
        PCAPStrategyGenerator, GeneratedStrategy, StrategyPriority
    )
    from ..strategy_failure_analyzer import (
        StrategyFailureAnalyzer, FailureReport, FailureCause
    )
    from ..fingerprint.dpi_fingerprint_service import (
        DPIFingerprintService, DPIFingerprint
    )
    ANALYSIS_COMPONENTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Analysis components not available: {e}")
    ANALYSIS_COMPONENTS_AVAILABLE = False

LOG = logging.getLogger("IterativeAnalysisEngine")


class AnalysisPhase(Enum):
    """Фазы итеративного анализа."""
    INITIAL_DISCOVERY = "initial_discovery"
    PATTERN_CORRELATION = "pattern_correlation"
    STRATEGY_REFINEMENT = "strategy_refinement"
    KNOWLEDGE_CONSOLIDATION = "knowledge_consolidation"
    EFFECTIVENESS_EVALUATION = "effectiveness_evaluation"


class IterationStatus(Enum):
    """Статус итерации анализа."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class IterationContext:
    """Контекст итерации анализа."""
    iteration_id: str
    domain: str
    phase: AnalysisPhase
    status: IterationStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Входные данные
    pcap_files: List[str] = field(default_factory=list)
    previous_strategies: List[Dict[str, Any]] = field(default_factory=list)
    failure_reports: List[FailureReport] = field(default_factory=list)
    
    # Результаты итерации
    analysis_results: List[PCAPAnalysisResult] = field(default_factory=list)
    generated_strategies: List[GeneratedStrategy] = field(default_factory=list)
    correlations: Dict[str, Any] = field(default_factory=dict)
    insights: List[str] = field(default_factory=list)
    
    # Метрики
    processing_time: float = 0.0
    confidence_score: float = 0.0
    knowledge_gain: float = 0.0


@dataclass
class KnowledgePattern:
    """Паттерн знаний, выявленный в процессе анализа."""
    pattern_id: str
    pattern_type: str  # "blocking_signature", "dpi_behavior", "strategy_effectiveness"
    domain_pattern: str  # Регулярное выражение для доменов
    
    # Характеристики паттерна
    features: Dict[str, Any] = field(default_factory=dict)
    conditions: List[str] = field(default_factory=list)
    outcomes: Dict[str, float] = field(default_factory=dict)  # исход -> вероятность
    
    # Статистика
    observed_count: int = 0
    success_rate: float = 0.0
    confidence: float = 0.0
    last_observed: Optional[datetime] = None
    
    # Применимость
    applicable_strategies: List[str] = field(default_factory=list)
    contraindicated_strategies: List[str] = field(default_factory=list)


@dataclass
class CorrelationResult:
    """Результат корреляции между DPI fingerprint и PCAP данными."""
    correlation_id: str
    fingerprint_id: str
    pcap_analysis_id: str
    correlation_strength: float  # 0.0 - 1.0
    
    # Корреляции
    behavioral_correlations: Dict[str, float] = field(default_factory=dict)
    timing_correlations: Dict[str, float] = field(default_factory=dict)
    pattern_correlations: Dict[str, float] = field(default_factory=dict)
    
    # Выводы
    confirmed_hypotheses: List[str] = field(default_factory=list)
    new_hypotheses: List[str] = field(default_factory=list)
    strategy_implications: List[str] = field(default_factory=list)


@dataclass
class StrategyEffectivenessMetrics:
    """Метрики эффективности стратегии."""
    strategy_id: str
    domain: str
    
    # Основные метрики
    success_rate: float = 0.0
    average_response_time: float = 0.0
    reliability_score: float = 0.0
    
    # Детальные метрики
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    timeout_attempts: int = 0
    
    # Временные характеристики
    response_times: List[float] = field(default_factory=list)
    failure_patterns: Dict[str, int] = field(default_factory=dict)
    
    # Контекстные факторы
    network_conditions: Dict[str, Any] = field(default_factory=dict)
    dpi_characteristics: Dict[str, Any] = field(default_factory=dict)
    
    # История
    measurement_history: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: Optional[datetime] = None


class IterativeAnalysisEngine:
    """
    Ядро интеллектуального анализа для адаптивной системы обхода DPI.
    
    Реализует многоуровневый итеративный анализ с накоплением знаний
    и корреляцией различных источников данных.
    """
    
    def __init__(self, 
                 data_dir: str = "data/iterative_analysis",
                 max_iterations: int = 10,
                 knowledge_retention_days: int = 30):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_iterations = max_iterations
        self.knowledge_retention_days = knowledge_retention_days
        
        # Инициализация компонентов
        self._init_components()
        
        # Состояние анализа
        self.active_iterations: Dict[str, IterationContext] = {}
        self.knowledge_patterns: Dict[str, KnowledgePattern] = {}
        self.correlation_cache: Dict[str, CorrelationResult] = {}
        self.effectiveness_metrics: Dict[str, StrategyEffectivenessMetrics] = {}
        
        # Загрузка сохраненных данных
        self._load_knowledge_base()
        
        LOG.info(f"IterativeAnalysisEngine initialized with data_dir={data_dir}")
    
    def _init_components(self):
        """Инициализация компонентов анализа."""
        if ANALYSIS_COMPONENTS_AVAILABLE:
            self.pcap_analyzer = IntelligentPCAPAnalyzer()
            self.strategy_generator = PCAPStrategyGenerator()
            self.failure_analyzer = StrategyFailureAnalyzer()
            self.fingerprint_service = DPIFingerprintService()
        else:
            LOG.warning("Analysis components not available - running in limited mode")
            self.pcap_analyzer = None
            self.strategy_generator = None
            self.failure_analyzer = None
            self.fingerprint_service = None
    
    async def analyze_pcap_iteration(self, 
                                   domain: str,
                                   pcap_files: List[str],
                                   iteration_number: int = 1,
                                   previous_context: Optional[IterationContext] = None) -> IterationContext:
        """
        Анализ PCAP файлов по итерациям с накоплением знаний.
        
        Args:
            domain: Целевой домен
            pcap_files: Список PCAP файлов для анализа
            iteration_number: Номер итерации
            previous_context: Контекст предыдущей итерации
            
        Returns:
            Контекст текущей итерации с результатами анализа
        """
        iteration_id = f"{domain}_{iteration_number}_{int(time.time())}"
        
        context = IterationContext(
            iteration_id=iteration_id,
            domain=domain,
            phase=AnalysisPhase.INITIAL_DISCOVERY,
            status=IterationStatus.RUNNING,
            started_at=datetime.now(),
            pcap_files=pcap_files
        )
        
        if previous_context:
            context.previous_strategies = [
                asdict(s) for s in previous_context.generated_strategies
            ]
            context.failure_reports = previous_context.failure_reports
        
        self.active_iterations[iteration_id] = context
        
        try:
            LOG.info(f"Starting PCAP iteration analysis for {domain} (iteration {iteration_number})")
            start_time = time.time()
            
            # Фаза 1: Анализ PCAP файлов
            context.phase = AnalysisPhase.INITIAL_DISCOVERY
            analysis_results = await self._analyze_pcap_files(pcap_files, context)
            context.analysis_results = analysis_results
            
            # Фаза 2: Корреляция с предыдущими данными
            context.phase = AnalysisPhase.PATTERN_CORRELATION
            correlations = await self._correlate_with_previous_data(domain, analysis_results, previous_context)
            context.correlations = correlations
            
            # Фаза 3: Генерация инсайтов
            insights = await self._generate_iteration_insights(context)
            context.insights = insights
            
            # Фаза 4: Обновление базы знаний
            context.phase = AnalysisPhase.KNOWLEDGE_CONSOLIDATION
            knowledge_gain = await self._update_knowledge_from_iteration(context)
            context.knowledge_gain = knowledge_gain
            
            # Завершение итерации
            context.processing_time = time.time() - start_time
            context.confidence_score = self._calculate_iteration_confidence(context)
            context.status = IterationStatus.COMPLETED
            context.completed_at = datetime.now()
            
            LOG.info(f"PCAP iteration analysis completed for {domain} in {context.processing_time:.2f}s")
            
        except Exception as e:
            LOG.error(f"PCAP iteration analysis failed for {domain}: {e}")
            context.status = IterationStatus.FAILED
            context.completed_at = datetime.now()
            raise
        
        return context
    
    async def correlate_dpi_patterns(self, 
                                   fingerprint: DPIFingerprint,
                                   pcap_analysis: PCAPAnalysisResult,
                                   domain: str) -> CorrelationResult:
        """
        Корреляция DPI fingerprint с PCAP данными для выявления паттернов.
        
        Args:
            fingerprint: DPI отпечаток
            pcap_analysis: Результат анализа PCAP
            domain: Целевой домен
            
        Returns:
            Результат корреляции с выявленными паттернами
        """
        correlation_id = f"{fingerprint.fingerprint_id}_{pcap_analysis.analysis_id}"
        
        # Проверяем кэш корреляций
        if correlation_id in self.correlation_cache:
            LOG.debug(f"Using cached correlation for {correlation_id}")
            return self.correlation_cache[correlation_id]
        
        LOG.info(f"Correlating DPI patterns for {domain}")
        
        correlation = CorrelationResult(
            correlation_id=correlation_id,
            fingerprint_id=fingerprint.fingerprint_id,
            pcap_analysis_id=pcap_analysis.analysis_id,
            correlation_strength=0.0
        )
        
        try:
            # Корреляция поведенческих характеристик
            behavioral_correlations = await self._correlate_behavioral_patterns(
                fingerprint, pcap_analysis
            )
            correlation.behavioral_correlations = behavioral_correlations
            
            # Корреляция временных характеристик
            timing_correlations = await self._correlate_timing_patterns(
                fingerprint, pcap_analysis
            )
            correlation.timing_correlations = timing_correlations
            
            # Корреляция паттернов блокировки
            pattern_correlations = await self._correlate_blocking_patterns(
                fingerprint, pcap_analysis
            )
            correlation.pattern_correlations = pattern_correlations
            
            # Расчет общей силы корреляции
            correlation.correlation_strength = self._calculate_correlation_strength(
                behavioral_correlations, timing_correlations, pattern_correlations
            )
            
            # Генерация гипотез и выводов
            correlation.confirmed_hypotheses = await self._generate_confirmed_hypotheses(
                fingerprint, pcap_analysis, correlation
            )
            correlation.new_hypotheses = await self._generate_new_hypotheses(
                fingerprint, pcap_analysis, correlation
            )
            correlation.strategy_implications = await self._generate_strategy_implications(
                correlation
            )
            
            # Кэширование результата
            self.correlation_cache[correlation_id] = correlation
            
            LOG.info(f"DPI pattern correlation completed with strength {correlation.correlation_strength:.3f}")
            
        except Exception as e:
            LOG.error(f"DPI pattern correlation failed for {domain}: {e}")
            raise
        
        return correlation
    
    async def generate_adaptive_strategies(self, 
                                         domain: str,
                                         iteration_contexts: List[IterationContext],
                                         target_count: int = 5) -> List[GeneratedStrategy]:
        """
        Генерация адаптивных стратегий на основе итеративного анализа.
        
        Args:
            domain: Целевой домен
            iteration_contexts: Контексты итераций анализа
            target_count: Целевое количество стратегий
            
        Returns:
            Список сгенерированных адаптивных стратегий
        """
        LOG.info(f"Generating adaptive strategies for {domain} based on {len(iteration_contexts)} iterations")
        
        strategies = []
        
        try:
            # Анализ накопленных знаний
            accumulated_knowledge = await self._analyze_accumulated_knowledge(
                domain, iteration_contexts
            )
            
            # Выявление наиболее эффективных паттернов
            effective_patterns = await self._identify_effective_patterns(
                domain, accumulated_knowledge
            )
            
            # Генерация стратегий на основе паттернов
            for pattern in effective_patterns[:target_count]:
                strategy = await self._generate_strategy_from_pattern(
                    domain, pattern, accumulated_knowledge
                )
                if strategy:
                    strategies.append(strategy)
            
            # Дополнение экспериментальными стратегиями
            if len(strategies) < target_count:
                experimental_strategies = await self._generate_experimental_strategies(
                    domain, accumulated_knowledge, target_count - len(strategies)
                )
                strategies.extend(experimental_strategies)
            
            # Ранжирование стратегий по ожидаемой эффективности
            strategies = await self._rank_strategies_by_effectiveness(
                domain, strategies, accumulated_knowledge
            )
            
            LOG.info(f"Generated {len(strategies)} adaptive strategies for {domain}")
            
        except Exception as e:
            LOG.error(f"Adaptive strategy generation failed for {domain}: {e}")
            raise
        
        return strategies[:target_count]
    
    async def update_knowledge_base(self, 
                                  domain: str,
                                  strategy_results: List[Tuple[GeneratedStrategy, bool, Dict[str, Any]]],
                                  iteration_context: IterationContext) -> Dict[str, Any]:
        """
        Обновление базы знаний на основе результатов тестирования стратегий.
        
        Args:
            domain: Целевой домен
            strategy_results: Результаты тестирования стратегий (стратегия, успех, метаданные)
            iteration_context: Контекст итерации
            
        Returns:
            Статистика обновления базы знаний
        """
        LOG.info(f"Updating knowledge base for {domain} with {len(strategy_results)} strategy results")
        
        update_stats = {
            "patterns_updated": 0,
            "new_patterns_created": 0,
            "effectiveness_metrics_updated": 0,
            "knowledge_gain": 0.0
        }
        
        try:
            # Обновление метрик эффективности стратегий
            for strategy, success, metadata in strategy_results:
                await self._update_strategy_effectiveness(
                    domain, strategy, success, metadata
                )
                update_stats["effectiveness_metrics_updated"] += 1
            
            # Выявление новых паттернов
            new_patterns = await self._extract_patterns_from_results(
                domain, strategy_results, iteration_context
            )
            
            for pattern in new_patterns:
                if pattern.pattern_id not in self.knowledge_patterns:
                    self.knowledge_patterns[pattern.pattern_id] = pattern
                    update_stats["new_patterns_created"] += 1
                else:
                    await self._merge_pattern_knowledge(
                        self.knowledge_patterns[pattern.pattern_id], pattern
                    )
                    update_stats["patterns_updated"] += 1
            
            # Расчет прироста знаний
            update_stats["knowledge_gain"] = await self._calculate_knowledge_gain(
                domain, strategy_results, iteration_context
            )
            
            # Сохранение обновленной базы знаний
            await self._save_knowledge_base()
            
            LOG.info(f"Knowledge base updated for {domain}: {update_stats}")
            
        except Exception as e:
            LOG.error(f"Knowledge base update failed for {domain}: {e}")
            raise
        
        return update_stats
    
    async def evaluate_strategy_effectiveness(self, 
                                            domain: str,
                                            strategy: GeneratedStrategy,
                                            historical_data: Optional[Dict[str, Any]] = None) -> StrategyEffectivenessMetrics:
        """
        Оценка эффективности стратегии на основе исторических данных и прогнозов.
        
        Args:
            domain: Целевой домен
            strategy: Стратегия для оценки
            historical_data: Исторические данные о стратегии
            
        Returns:
            Метрики эффективности стратегии
        """
        strategy_key = f"{domain}_{strategy.strategy_id}"
        
        # Получаем существующие метрики или создаем новые
        if strategy_key in self.effectiveness_metrics:
            metrics = self.effectiveness_metrics[strategy_key]
        else:
            metrics = StrategyEffectivenessMetrics(
                strategy_id=strategy.strategy_id,
                domain=domain
            )
            self.effectiveness_metrics[strategy_key] = metrics
        
        try:
            LOG.info(f"Evaluating strategy effectiveness for {strategy.name} on {domain}")
            
            # Анализ исторических данных
            if historical_data:
                await self._analyze_historical_effectiveness(metrics, historical_data)
            
            # Прогнозирование эффективности на основе паттернов
            predicted_effectiveness = await self._predict_strategy_effectiveness(
                domain, strategy, metrics
            )
            
            # Обновление метрик
            metrics.reliability_score = predicted_effectiveness.get("reliability", 0.0)
            metrics.network_conditions = predicted_effectiveness.get("network_conditions", {})
            metrics.dpi_characteristics = predicted_effectiveness.get("dpi_characteristics", {})
            metrics.last_updated = datetime.now()
            
            # Добавление записи в историю
            metrics.measurement_history.append({
                "timestamp": datetime.now().isoformat(),
                "predicted_success_rate": predicted_effectiveness.get("success_rate", 0.0),
                "confidence": predicted_effectiveness.get("confidence", 0.0),
                "factors": predicted_effectiveness.get("factors", [])
            })
            
            LOG.info(f"Strategy effectiveness evaluation completed: success_rate={metrics.success_rate:.3f}")
            
        except Exception as e:
            LOG.error(f"Strategy effectiveness evaluation failed: {e}")
            raise
        
        return metrics
    
    # Приватные методы для внутренней логики
    
    async def _analyze_pcap_files(self, 
                                pcap_files: List[str], 
                                context: IterationContext) -> List[PCAPAnalysisResult]:
        """Анализ PCAP файлов."""
        results = []
        
        if not self.pcap_analyzer:
            LOG.warning("PCAP analyzer not available")
            return results
        
        for pcap_file in pcap_files:
            try:
                result = await self.pcap_analyzer.analyze_pcap_file(pcap_file)
                results.append(result)
            except Exception as e:
                LOG.error(f"Failed to analyze PCAP file {pcap_file}: {e}")
        
        return results
    
    async def _correlate_with_previous_data(self, 
                                          domain: str,
                                          analysis_results: List[PCAPAnalysisResult],
                                          previous_context: Optional[IterationContext]) -> Dict[str, Any]:
        """Корреляция с данными предыдущих итераций."""
        correlations = {}
        
        if not previous_context:
            return correlations
        
        # Сравнение паттернов блокировки
        current_patterns = set()
        for result in analysis_results:
            for flow in result.flows:
                current_patterns.add(flow.blocking_type.value)
        
        previous_patterns = set()
        for result in previous_context.analysis_results:
            for flow in result.flows:
                previous_patterns.add(flow.blocking_type.value)
        
        correlations["pattern_consistency"] = len(current_patterns & previous_patterns) / max(len(current_patterns | previous_patterns), 1)
        correlations["new_patterns"] = list(current_patterns - previous_patterns)
        correlations["disappeared_patterns"] = list(previous_patterns - current_patterns)
        
        return correlations
    
    async def _generate_iteration_insights(self, context: IterationContext) -> List[str]:
        """Генерация инсайтов на основе итерации."""
        insights = []
        
        # Анализ паттернов блокировки
        blocking_types = defaultdict(int)
        for result in context.analysis_results:
            for flow in result.flows:
                blocking_types[flow.blocking_type.value] += 1
        
        if blocking_types:
            most_common = max(blocking_types.items(), key=lambda x: x[1])
            insights.append(f"Most common blocking type: {most_common[0]} ({most_common[1]} occurrences)")
        
        # Анализ корреляций
        if context.correlations.get("pattern_consistency", 0) > 0.8:
            insights.append("High pattern consistency with previous iterations - DPI behavior is stable")
        elif context.correlations.get("pattern_consistency", 0) < 0.3:
            insights.append("Low pattern consistency - DPI behavior may be evolving")
        
        return insights
    
    async def _update_knowledge_from_iteration(self, context: IterationContext) -> float:
        """Обновление базы знаний на основе итерации."""
        knowledge_gain = 0.0
        
        # Извлечение паттернов из результатов анализа
        for result in context.analysis_results:
            for flow in result.flows:
                pattern_id = f"{context.domain}_{flow.blocking_type.value}"
                
                if pattern_id not in self.knowledge_patterns:
                    # Создание нового паттерна
                    pattern = KnowledgePattern(
                        pattern_id=pattern_id,
                        pattern_type="blocking_signature",
                        domain_pattern=context.domain,
                        features={
                            "blocking_type": flow.blocking_type.value,
                            "packet_count": flow.packet_count,
                            "duration": flow.duration
                        },
                        observed_count=1,
                        last_observed=datetime.now()
                    )
                    self.knowledge_patterns[pattern_id] = pattern
                    knowledge_gain += 1.0
                else:
                    # Обновление существующего паттерна
                    pattern = self.knowledge_patterns[pattern_id]
                    pattern.observed_count += 1
                    pattern.last_observed = datetime.now()
                    knowledge_gain += 0.1
        
        return knowledge_gain
    
    def _calculate_iteration_confidence(self, context: IterationContext) -> float:
        """Расчет уверенности в результатах итерации."""
        confidence = 0.0
        
        # Базовая уверенность от количества анализируемых данных
        confidence += min(len(context.analysis_results) * 0.1, 0.5)
        
        # Уверенность от качества корреляций
        pattern_consistency = context.correlations.get("pattern_consistency", 0)
        confidence += pattern_consistency * 0.3
        
        # Уверенность от количества инсайтов
        confidence += min(len(context.insights) * 0.05, 0.2)
        
        return min(confidence, 1.0)
    
    async def _correlate_behavioral_patterns(self, 
                                           fingerprint: DPIFingerprint,
                                           pcap_analysis: PCAPAnalysisResult) -> Dict[str, float]:
        """Корреляция поведенческих паттернов."""
        correlations = {}
        
        # Корреляция типов блокировки
        fingerprint_blocking = fingerprint.behavioral_signatures.get("primary_blocking_type")
        pcap_blocking_types = set()
        
        for flow in pcap_analysis.flows:
            pcap_blocking_types.add(flow.blocking_type.value)
        
        if fingerprint_blocking in pcap_blocking_types:
            correlations["blocking_type_match"] = 1.0
        else:
            correlations["blocking_type_match"] = 0.0
        
        return correlations
    
    async def _correlate_timing_patterns(self, 
                                       fingerprint: DPIFingerprint,
                                       pcap_analysis: PCAPAnalysisResult) -> Dict[str, float]:
        """Корреляция временных паттернов."""
        correlations = {}
        
        # Анализ времени блокировки
        fingerprint_timing = fingerprint.behavioral_signatures.get("average_block_time", 0)
        pcap_timings = []
        
        for flow in pcap_analysis.flows:
            if flow.blocking_detected:
                pcap_timings.append(flow.duration)
        
        if pcap_timings and fingerprint_timing > 0:
            avg_pcap_timing = statistics.mean(pcap_timings)
            timing_diff = abs(fingerprint_timing - avg_pcap_timing)
            correlations["timing_consistency"] = max(0, 1.0 - timing_diff / max(fingerprint_timing, avg_pcap_timing))
        else:
            correlations["timing_consistency"] = 0.0
        
        return correlations
    
    async def _correlate_blocking_patterns(self, 
                                         fingerprint: DPIFingerprint,
                                         pcap_analysis: PCAPAnalysisResult) -> Dict[str, float]:
        """Корреляция паттернов блокировки."""
        correlations = {}
        
        # Анализ сигнатур блокировки
        fingerprint_signatures = set(fingerprint.known_weaknesses)
        pcap_signatures = set()
        
        for flow in pcap_analysis.flows:
            if hasattr(flow, 'blocking_details') and flow.blocking_details:
                signature = flow.blocking_details.get('signature')
                if signature:
                    pcap_signatures.add(signature)
        
        if fingerprint_signatures and pcap_signatures:
            intersection = len(fingerprint_signatures & pcap_signatures)
            union = len(fingerprint_signatures | pcap_signatures)
            correlations["signature_overlap"] = intersection / union if union > 0 else 0.0
        else:
            correlations["signature_overlap"] = 0.0
        
        return correlations
    
    def _calculate_correlation_strength(self, 
                                      behavioral: Dict[str, float],
                                      timing: Dict[str, float],
                                      patterns: Dict[str, float]) -> float:
        """Расчет общей силы корреляции."""
        all_correlations = []
        all_correlations.extend(behavioral.values())
        all_correlations.extend(timing.values())
        all_correlations.extend(patterns.values())
        
        if not all_correlations:
            return 0.0
        
        return statistics.mean(all_correlations)
    
    async def _generate_confirmed_hypotheses(self, 
                                           fingerprint: DPIFingerprint,
                                           pcap_analysis: PCAPAnalysisResult,
                                           correlation: CorrelationResult) -> List[str]:
        """Генерация подтвержденных гипотез."""
        hypotheses = []
        
        if correlation.behavioral_correlations.get("blocking_type_match", 0) > 0.8:
            hypotheses.append("DPI consistently uses the same blocking mechanism")
        
        if correlation.timing_correlations.get("timing_consistency", 0) > 0.7:
            hypotheses.append("DPI blocking timing is predictable and consistent")
        
        return hypotheses
    
    async def _generate_new_hypotheses(self, 
                                     fingerprint: DPIFingerprint,
                                     pcap_analysis: PCAPAnalysisResult,
                                     correlation: CorrelationResult) -> List[str]:
        """Генерация новых гипотез."""
        hypotheses = []
        
        if correlation.correlation_strength < 0.3:
            hypotheses.append("DPI behavior may be adaptive or context-dependent")
        
        # Анализ новых паттернов в PCAP
        new_blocking_types = set()
        for flow in pcap_analysis.flows:
            if flow.blocking_type.value not in fingerprint.behavioral_signatures.get("observed_blocking_types", []):
                new_blocking_types.add(flow.blocking_type.value)
        
        if new_blocking_types:
            hypotheses.append(f"DPI may have evolved to use new blocking methods: {', '.join(new_blocking_types)}")
        
        return hypotheses
    
    async def _generate_strategy_implications(self, correlation: CorrelationResult) -> List[str]:
        """Генерация выводов для стратегий."""
        implications = []
        
        if correlation.behavioral_correlations.get("blocking_type_match", 0) > 0.8:
            implications.append("Strategies targeting the confirmed blocking type should be prioritized")
        
        if correlation.timing_correlations.get("timing_consistency", 0) > 0.7:
            implications.append("Timing-based evasion strategies may be effective")
        
        return implications
    
    async def _analyze_accumulated_knowledge(self, 
                                           domain: str,
                                           iteration_contexts: List[IterationContext]) -> Dict[str, Any]:
        """Анализ накопленных знаний."""
        knowledge = {
            "total_iterations": len(iteration_contexts),
            "blocking_patterns": defaultdict(int),
            "strategy_patterns": defaultdict(list),
            "evolution_timeline": []
        }
        
        for context in iteration_contexts:
            # Анализ паттернов блокировки
            for result in context.analysis_results:
                for flow in result.flows:
                    knowledge["blocking_patterns"][flow.blocking_type.value] += 1
            
            # Анализ стратегий
            for strategy in context.generated_strategies:
                knowledge["strategy_patterns"][strategy.attack_name].append({
                    "iteration": context.iteration_id,
                    "priority": strategy.priority.value,
                    "confidence": strategy.confidence
                })
            
            # Временная линия эволюции
            knowledge["evolution_timeline"].append({
                "iteration": context.iteration_id,
                "timestamp": context.started_at.isoformat(),
                "insights": context.insights,
                "knowledge_gain": context.knowledge_gain
            })
        
        return knowledge
    
    async def _identify_effective_patterns(self, 
                                         domain: str,
                                         accumulated_knowledge: Dict[str, Any]) -> List[KnowledgePattern]:
        """Выявление наиболее эффективных паттернов."""
        effective_patterns = []
        
        # Анализ паттернов блокировки по частоте
        blocking_patterns = accumulated_knowledge["blocking_patterns"]
        for blocking_type, count in blocking_patterns.items():
            if count >= 2:  # Паттерн наблюдался минимум в 2 итерациях
                pattern = KnowledgePattern(
                    pattern_id=f"{domain}_{blocking_type}_frequent",
                    pattern_type="blocking_signature",
                    domain_pattern=domain,
                    features={"blocking_type": blocking_type},
                    observed_count=count,
                    confidence=min(count / len(accumulated_knowledge.get("evolution_timeline", [])), 1.0)
                )
                effective_patterns.append(pattern)
        
        # Сортировка по уверенности
        effective_patterns.sort(key=lambda p: p.confidence, reverse=True)
        
        return effective_patterns
    
    async def _generate_strategy_from_pattern(self, 
                                            domain: str,
                                            pattern: KnowledgePattern,
                                            accumulated_knowledge: Dict[str, Any]) -> Optional[GeneratedStrategy]:
        """Генерация стратегии на основе паттерна."""
        if not self.strategy_generator:
            return None
        
        try:
            # Создание псевдо-анализа PCAP для генератора стратегий
            mock_analysis = type('MockAnalysis', (), {
                'analysis_id': f"pattern_{pattern.pattern_id}",
                'domain': domain,
                'flows': [type('MockFlow', (), {
                    'blocking_type': type('BlockingType', (), {'value': pattern.features.get("blocking_type", "unknown")})(),
                    'blocking_detected': True
                })()]
            })()
            
            strategies = await self.strategy_generator.generate_strategies_from_analysis(mock_analysis)
            
            if strategies:
                strategy = strategies[0]
                strategy.generation_method = "pattern_based"
                strategy.confidence = pattern.confidence
                return strategy
        
        except Exception as e:
            LOG.error(f"Failed to generate strategy from pattern {pattern.pattern_id}: {e}")
        
        return None
    
    async def _generate_experimental_strategies(self, 
                                              domain: str,
                                              accumulated_knowledge: Dict[str, Any],
                                              count: int) -> List[GeneratedStrategy]:
        """Генерация экспериментальных стратегий."""
        strategies = []
        
        # Простые экспериментальные стратегии на основе накопленных знаний
        blocking_types = list(accumulated_knowledge["blocking_patterns"].keys())
        
        for i, blocking_type in enumerate(blocking_types[:count]):
            strategy = GeneratedStrategy(
                strategy_id=f"experimental_{domain}_{i}",
                name=f"Experimental strategy for {blocking_type}",
                attack_name="experimental",
                priority=StrategyPriority.EXPERIMENTAL,
                confidence=0.2,
                generation_method="experimental",
                rationale=f"Experimental approach for {blocking_type} blocking"
            )
            strategies.append(strategy)
        
        return strategies
    
    async def _rank_strategies_by_effectiveness(self, 
                                              domain: str,
                                              strategies: List[GeneratedStrategy],
                                              accumulated_knowledge: Dict[str, Any]) -> List[GeneratedStrategy]:
        """Ранжирование стратегий по ожидаемой эффективности."""
        # Простое ранжирование по уверенности и приоритету
        def strategy_score(strategy):
            priority_scores = {
                StrategyPriority.CRITICAL: 1.0,
                StrategyPriority.HIGH: 0.8,
                StrategyPriority.MEDIUM: 0.6,
                StrategyPriority.LOW: 0.4,
                StrategyPriority.EXPERIMENTAL: 0.2
            }
            return strategy.confidence * priority_scores.get(strategy.priority, 0.5)
        
        return sorted(strategies, key=strategy_score, reverse=True)
    
    async def _update_strategy_effectiveness(self, 
                                           domain: str,
                                           strategy: GeneratedStrategy,
                                           success: bool,
                                           metadata: Dict[str, Any]):
        """Обновление метрик эффективности стратегии."""
        strategy_key = f"{domain}_{strategy.strategy_id}"
        
        if strategy_key not in self.effectiveness_metrics:
            self.effectiveness_metrics[strategy_key] = StrategyEffectivenessMetrics(
                strategy_id=strategy.strategy_id,
                domain=domain
            )
        
        metrics = self.effectiveness_metrics[strategy_key]
        metrics.total_attempts += 1
        
        if success:
            metrics.successful_attempts += 1
        else:
            metrics.failed_attempts += 1
        
        # Обновление показателей успешности
        metrics.success_rate = metrics.successful_attempts / metrics.total_attempts
        
        # Обновление времени отклика
        response_time = metadata.get("response_time", 0.0)
        if response_time > 0:
            metrics.response_times.append(response_time)
            metrics.average_response_time = statistics.mean(metrics.response_times)
        
        metrics.last_updated = datetime.now()
    
    async def _extract_patterns_from_results(self, 
                                            domain: str,
                                            strategy_results: List[Tuple[GeneratedStrategy, bool, Dict[str, Any]]],
                                            iteration_context: IterationContext) -> List[KnowledgePattern]:
        """Извлечение паттернов из результатов тестирования."""
        patterns = []
        
        # Анализ успешных стратегий
        successful_strategies = [s for s, success, _ in strategy_results if success]
        
        if successful_strategies:
            # Создание паттерна успешных стратегий
            pattern = KnowledgePattern(
                pattern_id=f"{domain}_successful_strategies_{int(time.time())}",
                pattern_type="strategy_effectiveness",
                domain_pattern=domain,
                features={
                    "successful_attacks": [s.attack_name for s in successful_strategies],
                    "success_rate": len(successful_strategies) / len(strategy_results)
                },
                observed_count=1,
                success_rate=len(successful_strategies) / len(strategy_results),
                confidence=0.8,
                last_observed=datetime.now(),
                applicable_strategies=[s.strategy_id for s in successful_strategies]
            )
            patterns.append(pattern)
        
        return patterns
    
    async def _merge_pattern_knowledge(self, existing_pattern: KnowledgePattern, new_pattern: KnowledgePattern):
        """Слияние знаний паттернов."""
        existing_pattern.observed_count += new_pattern.observed_count
        existing_pattern.last_observed = max(existing_pattern.last_observed or datetime.min, 
                                           new_pattern.last_observed or datetime.min)
        
        # Обновление показателей успешности
        if new_pattern.success_rate > 0:
            total_observations = existing_pattern.observed_count + new_pattern.observed_count
            existing_pattern.success_rate = (
                (existing_pattern.success_rate * existing_pattern.observed_count + 
                 new_pattern.success_rate * new_pattern.observed_count) / total_observations
            )
        
        # Слияние применимых стратегий
        existing_strategies = set(existing_pattern.applicable_strategies)
        new_strategies = set(new_pattern.applicable_strategies)
        existing_pattern.applicable_strategies = list(existing_strategies | new_strategies)
    
    async def _calculate_knowledge_gain(self, 
                                      domain: str,
                                      strategy_results: List[Tuple[GeneratedStrategy, bool, Dict[str, Any]]],
                                      iteration_context: IterationContext) -> float:
        """Расчет прироста знаний."""
        knowledge_gain = 0.0
        
        # Прирост от успешных стратегий
        successful_count = sum(1 for _, success, _ in strategy_results if success)
        knowledge_gain += successful_count * 0.5
        
        # Прирост от новых инсайтов
        knowledge_gain += len(iteration_context.insights) * 0.1
        
        # Прирост от корреляций
        correlation_strength = sum(iteration_context.correlations.values()) / max(len(iteration_context.correlations), 1)
        knowledge_gain += correlation_strength * 0.3
        
        return knowledge_gain
    
    async def _analyze_historical_effectiveness(self, 
                                              metrics: StrategyEffectivenessMetrics,
                                              historical_data: Dict[str, Any]):
        """Анализ исторической эффективности."""
        if "success_attempts" in historical_data and "total_attempts" in historical_data:
            metrics.successful_attempts += historical_data["success_attempts"]
            metrics.total_attempts += historical_data["total_attempts"]
            metrics.success_rate = metrics.successful_attempts / metrics.total_attempts
        
        if "response_times" in historical_data:
            metrics.response_times.extend(historical_data["response_times"])
            metrics.average_response_time = statistics.mean(metrics.response_times)
    
    async def _predict_strategy_effectiveness(self, 
                                            domain: str,
                                            strategy: GeneratedStrategy,
                                            current_metrics: StrategyEffectivenessMetrics) -> Dict[str, Any]:
        """Прогнозирование эффективности стратегии."""
        prediction = {
            "success_rate": 0.5,  # Базовая оценка
            "confidence": 0.3,
            "reliability": 0.5,
            "factors": [],
            "network_conditions": {},
            "dpi_characteristics": {}
        }
        
        # Корректировка на основе исторических данных
        if current_metrics.total_attempts > 0:
            prediction["success_rate"] = current_metrics.success_rate
            prediction["confidence"] = min(current_metrics.total_attempts / 10.0, 1.0)
        
        # Корректировка на основе приоритета стратегии
        priority_adjustments = {
            StrategyPriority.CRITICAL: 0.2,
            StrategyPriority.HIGH: 0.1,
            StrategyPriority.MEDIUM: 0.0,
            StrategyPriority.LOW: -0.1,
            StrategyPriority.EXPERIMENTAL: -0.2
        }
        
        adjustment = priority_adjustments.get(strategy.priority, 0.0)
        prediction["success_rate"] = max(0.0, min(1.0, prediction["success_rate"] + adjustment))
        
        # Добавление факторов
        prediction["factors"].append(f"Strategy priority: {strategy.priority.value}")
        prediction["factors"].append(f"Historical attempts: {current_metrics.total_attempts}")
        
        return prediction
    
    def _load_knowledge_base(self):
        """Загрузка сохраненной базы знаний."""
        knowledge_file = self.data_dir / "knowledge_patterns.json"
        metrics_file = self.data_dir / "effectiveness_metrics.json"
        
        try:
            if knowledge_file.exists():
                with open(knowledge_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for pattern_id, pattern_data in data.items():
                        pattern = KnowledgePattern(**pattern_data)
                        if pattern.last_observed:
                            pattern.last_observed = datetime.fromisoformat(pattern.last_observed)
                        self.knowledge_patterns[pattern_id] = pattern
                
                LOG.info(f"Loaded {len(self.knowledge_patterns)} knowledge patterns")
            
            if metrics_file.exists():
                with open(metrics_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for metrics_id, metrics_data in data.items():
                        metrics = StrategyEffectivenessMetrics(**metrics_data)
                        if metrics.last_updated:
                            metrics.last_updated = datetime.fromisoformat(metrics.last_updated)
                        self.effectiveness_metrics[metrics_id] = metrics
                
                LOG.info(f"Loaded {len(self.effectiveness_metrics)} effectiveness metrics")
        
        except Exception as e:
            LOG.error(f"Failed to load knowledge base: {e}")
    
    async def _save_knowledge_base(self):
        """Сохранение базы знаний."""
        knowledge_file = self.data_dir / "knowledge_patterns.json"
        metrics_file = self.data_dir / "effectiveness_metrics.json"
        
        try:
            # Сохранение паттернов знаний
            patterns_data = {}
            for pattern_id, pattern in self.knowledge_patterns.items():
                pattern_dict = asdict(pattern)
                if pattern_dict.get("last_observed"):
                    pattern_dict["last_observed"] = pattern.last_observed.isoformat()
                patterns_data[pattern_id] = pattern_dict
            
            with open(knowledge_file, 'w', encoding='utf-8') as f:
                json.dump(patterns_data, f, indent=2, ensure_ascii=False)
            
            # Сохранение метрик эффективности
            metrics_data = {}
            for metrics_id, metrics in self.effectiveness_metrics.items():
                metrics_dict = asdict(metrics)
                if metrics_dict.get("last_updated"):
                    metrics_dict["last_updated"] = metrics.last_updated.isoformat()
                metrics_data[metrics_id] = metrics_dict
            
            with open(metrics_file, 'w', encoding='utf-8') as f:
                json.dump(metrics_data, f, indent=2, ensure_ascii=False)
            
            LOG.info("Knowledge base saved successfully")
        
        except Exception as e:
            LOG.error(f"Failed to save knowledge base: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики работы движка."""
        return {
            "active_iterations": len(self.active_iterations),
            "knowledge_patterns": len(self.knowledge_patterns),
            "cached_correlations": len(self.correlation_cache),
            "effectiveness_metrics": len(self.effectiveness_metrics),
            "data_directory": str(self.data_dir)
        }