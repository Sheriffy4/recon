"""
PCAP Strategy Generator - генератор стратегий на основе PCAP анализа.

Этот модуль реализует:
- Маппинг выявленных проблем в PCAP на конкретные стратегии обхода
- Систему приоритизации стратегий на основе анализа трафика
- Генерацию параметров стратегий (TTL, позиции split, методы fooling)
- Адаптивную настройку параметров на основе характеристик блокировки
- Систему валидации сгенерированных стратегий

Requirements: FR-13.4, FR-13.5, FR-13.6
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Импорт из intelligent_pcap_analyzer
try:
    from .intelligent_pcap_analyzer import (
        PCAPAnalysisResult, BlockingType, DPIBehavior, FlowAnalysis, DPISignature
    )
except ImportError:
    # Fallback для standalone тестирования
    try:
        import sys
        import os
        sys.path.append(os.path.dirname(__file__))
        from intelligent_pcap_analyzer import (
            PCAPAnalysisResult, BlockingType, DPIBehavior, FlowAnalysis, DPISignature
        )
    except ImportError:
        # Заглушки для случая, когда модули недоступны
        PCAPAnalysisResult = None
        BlockingType = None
        DPIBehavior = None
        FlowAnalysis = None
        DPISignature = None

# Интеграция с существующими модулями
try:
    from ...strategy_failure_analyzer import FailureCause, Recommendation
    from ...attack_registry import get_attack_registry
except ImportError:
    try:
        # Fallback для standalone тестирования
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), '../../..'))
        from core.strategy_failure_analyzer import FailureCause, Recommendation
        from core.attack_registry import get_attack_registry
    except ImportError:
        FailureCause = None
        Recommendation = None
        get_attack_registry = None

LOG = logging.getLogger("PCAPStrategyGenerator")


class StrategyPriority(Enum):
    """Приоритеты стратегий."""
    CRITICAL = "critical"      # 0.9-1.0
    HIGH = "high"             # 0.7-0.9
    MEDIUM = "medium"         # 0.5-0.7
    LOW = "low"              # 0.3-0.5
    EXPERIMENTAL = "experimental"  # 0.0-0.3


@dataclass
class StrategyParameter:
    """Параметр стратегии."""
    name: str
    value: Any
    confidence: float
    source: str  # "pcap_analysis", "heuristic", "default"
    rationale: str


@dataclass
class GeneratedStrategy:
    """Сгенерированная стратегия обхода."""
    strategy_id: str
    name: str
    attack_name: str
    priority: StrategyPriority
    confidence: float
    
    # Параметры стратегии
    parameters: Dict[str, StrategyParameter] = field(default_factory=dict)
    
    # Метаданные генерации
    generation_method: str = "pcap_analysis"
    source_evidence: List[str] = field(default_factory=list)
    target_blocking_type: BlockingType = BlockingType.UNKNOWN
    rationale: str = ""
    
    # Валидация
    is_validated: bool = False
    validation_score: float = 0.0
    validation_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StrategyGenerationResult:
    """Результат генерации стратегий."""
    pcap_file: str
    generation_timestamp: datetime
    total_strategies: int
    
    # Сгенерированные стратегии
    strategies: List[GeneratedStrategy] = field(default_factory=list)
    
    # Метаданные
    generation_details: Dict[str, Any] = field(default_factory=dict)
    validation_summary: Dict[str, Any] = field(default_factory=dict)


class PCAPStrategyGenerator:
    """
    Генератор стратегий на основе анализа PCAP файлов.
    
    Основные возможности:
    - Анализ результатов PCAP анализа для выявления оптимальных стратегий
    - Маппинг типов блокировок на конкретные атаки из registry
    - Адаптивная генерация параметров на основе характеристик DPI
    - Приоритизация стратегий по вероятности успеха
    - Валидация сгенерированных стратегий
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Инициализация генератора стратегий.
        
        Args:
            config: Конфигурация генератора
        """
        self.config = config or {}
        
        # Настройки генерации
        self.max_strategies_per_type = self.config.get("max_strategies_per_type", 5)
        self.enable_experimental = self.config.get("enable_experimental", False)
        self.confidence_threshold = self.config.get("confidence_threshold", 0.5)
        self.enable_parameter_optimization = self.config.get("enable_parameter_optimization", True)
        
        # Инициализация компонентов
        self.blocking_mapper = BlockingTypeMapper()
        self.parameter_optimizer = ParameterOptimizer()
        self.strategy_validator = StrategyValidator()
        self.priority_calculator = PriorityCalculator()
        
        # Загрузка attack registry если доступен
        self.attack_registry = None
        if get_attack_registry:
            try:
                self.attack_registry = get_attack_registry()
                LOG.info("Attack registry загружен успешно")
            except Exception as e:
                LOG.warning(f"Не удалось загрузить attack registry: {e}")
        
        LOG.info("PCAPStrategyGenerator инициализирован")
    
    async def generate_strategies(self, pcap_analysis: PCAPAnalysisResult) -> StrategyGenerationResult:
        """
        Основной метод генерации стратегий на основе PCAP анализа.
        
        Args:
            pcap_analysis: Результат анализа PCAP файла
            
        Returns:
            StrategyGenerationResult с сгенерированными стратегиями
        """
        start_time = datetime.now()
        LOG.info(f"Начало генерации стратегий для {pcap_analysis.pcap_file}")
        
        try:
            strategies = []
            
            # Генерация стратегий на основе основного типа блокировки
            primary_strategies = await self._generate_primary_strategies(pcap_analysis)
            strategies.extend(primary_strategies)
            
            # Генерация стратегий на основе DPI поведения
            behavior_strategies = await self._generate_behavior_strategies(pcap_analysis)
            strategies.extend(behavior_strategies)
            
            # Генерация стратегий на основе DPI сигнатур
            signature_strategies = await self._generate_signature_strategies(pcap_analysis)
            strategies.extend(signature_strategies)
            
            # Генерация комбинированных стратегий
            combo_strategies = await self._generate_combo_strategies(pcap_analysis, strategies)
            strategies.extend(combo_strategies)
            
            # Оптимизация параметров
            if self.enable_parameter_optimization:
                strategies = await self._optimize_strategy_parameters(strategies, pcap_analysis)
            
            # Приоритизация стратегий
            strategies = await self._prioritize_strategies(strategies, pcap_analysis)
            
            # Валидация стратегий
            strategies = await self._validate_strategies(strategies, pcap_analysis)
            
            # Фильтрация по уверенности
            strategies = [s for s in strategies if s.confidence >= self.confidence_threshold]
            
            # Ограничение количества стратегий
            strategies = strategies[:20]  # Максимум 20 стратегий
            
            # Создание результата
            result = StrategyGenerationResult(
                pcap_file=pcap_analysis.pcap_file,
                generation_timestamp=datetime.now(),
                total_strategies=len(strategies),
                strategies=strategies,
                generation_details={
                    "primary_blocking_type": pcap_analysis.primary_blocking_type.value,
                    "dpi_behavior": pcap_analysis.dpi_behavior.value,
                    "confidence": pcap_analysis.confidence,
                    "generation_time": (datetime.now() - start_time).total_seconds()
                }
            )
            
            LOG.info(f"Генерация завершена: {len(strategies)} стратегий за "
                    f"{result.generation_details['generation_time']:.2f}с")
            
            return result
            
        except Exception as e:
            LOG.error(f"Ошибка генерации стратегий: {e}")
            return StrategyGenerationResult(
                pcap_file=pcap_analysis.pcap_file,
                generation_timestamp=datetime.now(),
                total_strategies=0,
                generation_details={"error": str(e)}
            )
    
    async def _generate_primary_strategies(self, pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Генерация стратегий на основе основного типа блокировки."""
        strategies = []
        blocking_type = pcap_analysis.primary_blocking_type
        
        LOG.info(f"Генерация стратегий для типа блокировки: {blocking_type.value}")
        
        # Маппинг типов блокировок на стратегии
        strategy_mappings = await self.blocking_mapper.get_strategies_for_blocking_type(blocking_type)
        
        for mapping in strategy_mappings:
            strategy = GeneratedStrategy(
                strategy_id=f"primary_{mapping['attack_name']}_{blocking_type.value}",
                name=mapping['name'],
                attack_name=mapping['attack_name'],
                priority=StrategyPriority.HIGH,
                confidence=pcap_analysis.confidence * mapping['base_confidence'],
                target_blocking_type=blocking_type,
                rationale=mapping['rationale'],
                source_evidence=[f"blocking_type:{blocking_type.value}"]
            )
            
            # Добавление базовых параметров
            for param_name, param_config in mapping.get('parameters', {}).items():
                strategy.parameters[param_name] = StrategyParameter(
                    name=param_name,
                    value=param_config['default_value'],
                    confidence=param_config.get('confidence', 0.7),
                    source="blocking_type_mapping",
                    rationale=param_config.get('rationale', f"Default for {blocking_type.value}")
                )
            
            strategies.append(strategy)
        
        return strategies
    
    async def _generate_behavior_strategies(self, pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Генерация стратегий на основе поведения DPI."""
        strategies = []
        dpi_behavior = pcap_analysis.dpi_behavior
        
        if dpi_behavior == DPIBehavior.UNKNOWN:
            return strategies
        
        LOG.info(f"Генерация стратегий для поведения DPI: {dpi_behavior.value}")
        
        # Маппинг поведения DPI на стратегии
        behavior_mappings = await self.blocking_mapper.get_strategies_for_dpi_behavior(dpi_behavior)
        
        for mapping in behavior_mappings:
            strategy = GeneratedStrategy(
                strategy_id=f"behavior_{mapping['attack_name']}_{dpi_behavior.value}",
                name=mapping['name'],
                attack_name=mapping['attack_name'],
                priority=StrategyPriority.MEDIUM,
                confidence=pcap_analysis.confidence * mapping['base_confidence'] * 0.8,
                target_blocking_type=pcap_analysis.primary_blocking_type,
                rationale=mapping['rationale'],
                source_evidence=[f"dpi_behavior:{dpi_behavior.value}"]
            )
            
            # Добавление параметров для поведения DPI
            for param_name, param_config in mapping.get('parameters', {}).items():
                strategy.parameters[param_name] = StrategyParameter(
                    name=param_name,
                    value=param_config['default_value'],
                    confidence=param_config.get('confidence', 0.6),
                    source="dpi_behavior_mapping",
                    rationale=param_config.get('rationale', f"Optimized for {dpi_behavior.value}")
                )
            
            strategies.append(strategy)
        
        return strategies
    
    async def _generate_signature_strategies(self, pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Генерация стратегий на основе DPI сигнатур."""
        strategies = []
        
        if not pcap_analysis.dpi_signatures:
            return strategies
        
        LOG.info(f"Генерация стратегий для {len(pcap_analysis.dpi_signatures)} DPI сигнатур")
        
        for signature in pcap_analysis.dpi_signatures:
            signature_strategies = await self._generate_strategies_for_signature(signature, pcap_analysis)
            strategies.extend(signature_strategies)
        
        return strategies
    
    async def _generate_strategies_for_signature(self, signature: DPISignature, 
                                               pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Генерация стратегий для конкретной DPI сигнатуры."""
        strategies = []
        
        if signature.signature_type == "rst_pattern":
            # Стратегии для обхода RST паттернов
            rst_strategies = await self._generate_rst_bypass_strategies(signature, pcap_analysis)
            strategies.extend(rst_strategies)
        
        elif signature.signature_type == "timing_pattern":
            # Стратегии для обхода timing паттернов
            timing_strategies = await self._generate_timing_bypass_strategies(signature, pcap_analysis)
            strategies.extend(timing_strategies)
        
        elif signature.signature_type == "content_pattern":
            # Стратегии для обхода content паттернов
            content_strategies = await self._generate_content_bypass_strategies(signature, pcap_analysis)
            strategies.extend(content_strategies)
        
        return strategies
    
    async def _generate_rst_bypass_strategies(self, signature: DPISignature, 
                                            pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Генерация стратегий для обхода RST паттернов."""
        strategies = []
        pattern_data = signature.pattern_data
        
        # Анализ TTL значений в RST пакетах
        ttl_values = pattern_data.get("ttl_values", [])
        if ttl_values:
            min_ttl = min(ttl_values)
            
            # Стратегия с TTL манипуляцией
            ttl_strategy = GeneratedStrategy(
                strategy_id=f"ttl_bypass_{signature.signature_id}",
                name="TTL Manipulation Bypass",
                attack_name="fake",
                priority=StrategyPriority.HIGH,
                confidence=signature.confidence * 0.9,
                target_blocking_type=pcap_analysis.primary_blocking_type,
                rationale=f"Bypass RST injection with TTL={min_ttl-1}",
                source_evidence=[f"rst_signature:{signature.signature_id}"]
            )
            
            # Параметры TTL стратегии
            ttl_strategy.parameters["ttl"] = StrategyParameter(
                name="ttl",
                value=max(1, min_ttl - 1),
                confidence=0.8,
                source="rst_signature_analysis",
                rationale=f"Set TTL below DPI RST TTL ({min_ttl})"
            )
            
            ttl_strategy.parameters["fooling"] = StrategyParameter(
                name="fooling",
                value="badseq",
                confidence=0.7,
                source="rst_bypass_heuristic",
                rationale="Use bad sequence numbers to confuse DPI"
            )
            
            strategies.append(ttl_strategy)
        
        # Стратегия с disorder для обхода RST
        disorder_strategy = GeneratedStrategy(
            strategy_id=f"disorder_bypass_{signature.signature_id}",
            name="Packet Disorder Bypass",
            attack_name="disorder",
            priority=StrategyPriority.MEDIUM,
            confidence=signature.confidence * 0.7,
            target_blocking_type=pcap_analysis.primary_blocking_type,
            rationale="Use packet reordering to bypass RST injection",
            source_evidence=[f"rst_signature:{signature.signature_id}"]
        )
        
        disorder_strategy.parameters["split_pos"] = StrategyParameter(
            name="split_pos",
            value=3,
            confidence=0.6,
            source="rst_bypass_heuristic",
            rationale="Split early to trigger RST before real data"
        )
        
        strategies.append(disorder_strategy)
        
        return strategies
    
    async def _generate_timing_bypass_strategies(self, signature: DPISignature, 
                                               pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Генерация стратегий для обхода timing паттернов."""
        strategies = []
        pattern_data = signature.pattern_data
        
        avg_timing = pattern_data.get("average_blocking_time", 0)
        
        if avg_timing > 0:
            # Стратегия с задержкой
            delay_strategy = GeneratedStrategy(
                strategy_id=f"timing_bypass_{signature.signature_id}",
                name="Timing Manipulation Bypass",
                attack_name="fake",
                priority=StrategyPriority.MEDIUM,
                confidence=signature.confidence * 0.6,
                target_blocking_type=pcap_analysis.primary_blocking_type,
                rationale=f"Manipulate timing to avoid {avg_timing:.3f}s detection window",
                source_evidence=[f"timing_signature:{signature.signature_id}"]
            )
            
            # Параметры timing стратегии
            delay_ms = int(avg_timing * 1000 * 1.5)  # 150% от среднего времени
            delay_strategy.parameters["delay"] = StrategyParameter(
                name="delay",
                value=delay_ms,
                confidence=0.5,
                source="timing_signature_analysis",
                rationale=f"Delay packets by {delay_ms}ms to avoid detection window"
            )
            
            strategies.append(delay_strategy)
        
        return strategies
    
    async def _generate_content_bypass_strategies(self, signature: DPISignature, 
                                                pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Генерация стратегий для обхода content паттернов."""
        strategies = []
        
        # Стратегия фрагментации для обхода content inspection
        frag_strategy = GeneratedStrategy(
            strategy_id=f"content_bypass_{signature.signature_id}",
            name="Content Fragmentation Bypass",
            attack_name="multisplit",
            priority=StrategyPriority.MEDIUM,
            confidence=signature.confidence * 0.6,
            target_blocking_type=pcap_analysis.primary_blocking_type,
            rationale="Fragment content to bypass deep packet inspection",
            source_evidence=[f"content_signature:{signature.signature_id}"]
        )
        
        frag_strategy.parameters["split_count"] = StrategyParameter(
            name="split_count",
            value=8,
            confidence=0.6,
            source="content_bypass_heuristic",
            rationale="Split into small fragments to evade content analysis"
        )
        
        strategies.append(frag_strategy)
        
        return strategies
    
    async def _generate_combo_strategies(self, pcap_analysis: PCAPAnalysisResult, 
                                       base_strategies: List[GeneratedStrategy]) -> List[GeneratedStrategy]:
        """Генерация комбинированных стратегий."""
        combo_strategies = []
        
        if len(base_strategies) < 2:
            return combo_strategies
        
        LOG.info("Генерация комбинированных стратегий")
        
        # Комбинирование стратегий с высоким приоритетом
        high_priority_strategies = [s for s in base_strategies if s.priority == StrategyPriority.HIGH]
        
        for i, strategy1 in enumerate(high_priority_strategies):
            for strategy2 in high_priority_strategies[i+1:]:
                if self._can_combine_strategies(strategy1, strategy2):
                    combo_strategy = await self._create_combo_strategy(strategy1, strategy2, pcap_analysis)
                    if combo_strategy:
                        combo_strategies.append(combo_strategy)
        
        return combo_strategies[:3]  # Максимум 3 комбинированные стратегии
    
    def _can_combine_strategies(self, strategy1: GeneratedStrategy, strategy2: GeneratedStrategy) -> bool:
        """Проверка возможности комбинирования стратегий."""
        # Не комбинируем стратегии одного типа
        if strategy1.attack_name == strategy2.attack_name:
            return False
        
        # Не комбинируем конфликтующие стратегии
        conflicting_pairs = [
            ("fake", "disorder"),  # Могут конфликтовать
            ("multisplit", "disorder")  # Могут конфликтовать
        ]
        
        for pair in conflicting_pairs:
            if (strategy1.attack_name in pair and strategy2.attack_name in pair):
                return False
        
        return True
    
    async def _create_combo_strategy(self, strategy1: GeneratedStrategy, strategy2: GeneratedStrategy,
                                   pcap_analysis: PCAPAnalysisResult) -> Optional[GeneratedStrategy]:
        """Создание комбинированной стратегии."""
        try:
            combo_strategy = GeneratedStrategy(
                strategy_id=f"combo_{strategy1.attack_name}_{strategy2.attack_name}",
                name=f"Combined {strategy1.name} + {strategy2.name}",
                attack_name=f"{strategy1.attack_name}+{strategy2.attack_name}",
                priority=StrategyPriority.MEDIUM,
                confidence=min(strategy1.confidence, strategy2.confidence) * 0.8,
                target_blocking_type=pcap_analysis.primary_blocking_type,
                rationale=f"Combination of {strategy1.rationale} and {strategy2.rationale}",
                source_evidence=strategy1.source_evidence + strategy2.source_evidence
            )
            
            # Объединение параметров
            combo_strategy.parameters.update(strategy1.parameters)
            combo_strategy.parameters.update(strategy2.parameters)
            
            return combo_strategy
            
        except Exception as e:
            LOG.warning(f"Не удалось создать комбинированную стратегию: {e}")
            return None    

    async def _optimize_strategy_parameters(self, strategies: List[GeneratedStrategy], 
                                          pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Оптимизация параметров стратегий."""
        if not self.enable_parameter_optimization:
            return strategies
        
        LOG.info("Оптимизация параметров стратегий")
        
        optimized_strategies = []
        for strategy in strategies:
            optimized_strategy = await self.parameter_optimizer.optimize_parameters(strategy, pcap_analysis)
            optimized_strategies.append(optimized_strategy)
        
        return optimized_strategies
    
    async def _prioritize_strategies(self, strategies: List[GeneratedStrategy], 
                                   pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Приоритизация стратегий."""
        LOG.info("Приоритизация стратегий")
        
        for strategy in strategies:
            priority, confidence_adjustment = await self.priority_calculator.calculate_priority(
                strategy, pcap_analysis
            )
            strategy.priority = priority
            strategy.confidence *= confidence_adjustment
        
        # Сортировка по приоритету и уверенности
        strategies.sort(key=lambda s: (s.priority.value, s.confidence), reverse=True)
        
        return strategies
    
    async def _validate_strategies(self, strategies: List[GeneratedStrategy], 
                                 pcap_analysis: PCAPAnalysisResult) -> List[GeneratedStrategy]:
        """Валидация сгенерированных стратегий."""
        LOG.info("Валидация стратегий")
        
        validated_strategies = []
        for strategy in strategies:
            validation_result = await self.strategy_validator.validate_strategy(strategy, pcap_analysis)
            
            strategy.is_validated = validation_result["is_valid"]
            strategy.validation_score = validation_result["score"]
            strategy.validation_details = validation_result["details"]
            
            if strategy.is_validated:
                validated_strategies.append(strategy)
        
        return validated_strategies


class BlockingTypeMapper:
    """Маппер типов блокировок на стратегии."""
    
    async def get_strategies_for_blocking_type(self, blocking_type: BlockingType) -> List[Dict[str, Any]]:
        """Получение стратегий для типа блокировки."""
        
        strategy_mappings = {
            BlockingType.RST_INJECTION: [
                {
                    "name": "TTL Manipulation",
                    "attack_name": "fake",
                    "base_confidence": 0.9,
                    "rationale": "Use low TTL to bypass RST injection",
                    "parameters": {
                        "ttl": {"default_value": 1, "confidence": 0.8, "rationale": "Low TTL to expire before DPI"},
                        "fooling": {"default_value": "badseq", "confidence": 0.7, "rationale": "Bad sequence numbers"}
                    }
                },
                {
                    "name": "Packet Disorder",
                    "attack_name": "disorder",
                    "base_confidence": 0.8,
                    "rationale": "Reorder packets to confuse DPI state tracking",
                    "parameters": {
                        "split_pos": {"default_value": 3, "confidence": 0.7, "rationale": "Early split position"}
                    }
                },
                {
                    "name": "Fake Packets with Bad Checksum",
                    "attack_name": "fake",
                    "base_confidence": 0.7,
                    "rationale": "Send fake packets with invalid checksums",
                    "parameters": {
                        "fooling": {"default_value": "badsum", "confidence": 0.8, "rationale": "Invalid checksums"},
                        "ttl": {"default_value": 2, "confidence": 0.6, "rationale": "Short TTL for fake packets"}
                    }
                }
            ],
            
            BlockingType.SNI_FILTERING: [
                {
                    "name": "SNI Fragmentation",
                    "attack_name": "multisplit",
                    "base_confidence": 0.9,
                    "rationale": "Fragment TLS ClientHello at SNI position",
                    "parameters": {
                        "split_tls": {"default_value": "sni", "confidence": 0.9, "rationale": "Split at SNI extension"},
                        "split_count": {"default_value": 5, "confidence": 0.7, "rationale": "Multiple fragments"}
                    }
                },
                {
                    "name": "Fake SNI",
                    "attack_name": "fake",
                    "base_confidence": 0.8,
                    "rationale": "Send fake SNI before real one",
                    "parameters": {
                        "fake_tls": {"default_value": "0x160301", "confidence": 0.8, "rationale": "Fake TLS record"},
                        "fooling": {"default_value": "badsum", "confidence": 0.7, "rationale": "Invalid checksum"}
                    }
                },
                {
                    "name": "TLS Record Split",
                    "attack_name": "split",
                    "base_confidence": 0.7,
                    "rationale": "Split TLS record to hide SNI",
                    "parameters": {
                        "split_pos": {"default_value": 10, "confidence": 0.6, "rationale": "Split within TLS header"}
                    }
                }
            ],
            
            BlockingType.TLS_HANDSHAKE_BLOCKING: [
                {
                    "name": "TLS Fragmentation",
                    "attack_name": "multisplit",
                    "base_confidence": 0.8,
                    "rationale": "Fragment TLS handshake messages",
                    "parameters": {
                        "split_count": {"default_value": 10, "confidence": 0.7, "rationale": "Heavy fragmentation"},
                        "split_tls": {"default_value": "chello", "confidence": 0.8, "rationale": "Split ClientHello"}
                    }
                },
                {
                    "name": "TLS Fake Handshake",
                    "attack_name": "fake",
                    "base_confidence": 0.7,
                    "rationale": "Send fake TLS handshake messages",
                    "parameters": {
                        "fake_tls": {"default_value": "0x16030300", "confidence": 0.7, "rationale": "Fake handshake"},
                        "fooling": {"default_value": "badseq", "confidence": 0.6, "rationale": "Bad sequence"}
                    }
                }
            ],
            
            BlockingType.FRAGMENTATION_REASSEMBLY: [
                {
                    "name": "Packet Reordering",
                    "attack_name": "disorder",
                    "base_confidence": 0.8,
                    "rationale": "Change packet order instead of fragmentation",
                    "parameters": {
                        "split_pos": {"default_value": 2, "confidence": 0.7, "rationale": "Early reorder position"}
                    }
                },
                {
                    "name": "Sequence Overlap",
                    "attack_name": "fake",
                    "base_confidence": 0.7,
                    "rationale": "Create overlapping TCP sequences",
                    "parameters": {
                        "seqovl": {"default_value": 100, "confidence": 0.6, "rationale": "Sequence overlap"},
                        "fooling": {"default_value": "badsum", "confidence": 0.5, "rationale": "Invalid checksum"}
                    }
                }
            ],
            
            BlockingType.CONNECTION_TIMEOUT: [
                {
                    "name": "Fast Connection",
                    "attack_name": "syndata",
                    "base_confidence": 0.6,
                    "rationale": "Send data with SYN to speed up connection",
                    "parameters": {
                        "fooling": {"default_value": "badseq", "confidence": 0.5, "rationale": "Bad sequence for SYN"}
                    }
                }
            ],
            
            BlockingType.CONTENT_FILTERING: [
                {
                    "name": "Content Obfuscation",
                    "attack_name": "multisplit",
                    "base_confidence": 0.7,
                    "rationale": "Fragment content to evade inspection",
                    "parameters": {
                        "split_count": {"default_value": 15, "confidence": 0.6, "rationale": "Heavy fragmentation"},
                        "fooling": {"default_value": "badsum", "confidence": 0.5, "rationale": "Invalid checksums"}
                    }
                }
            ]
        }
        
        return strategy_mappings.get(blocking_type, [])
    
    async def get_strategies_for_dpi_behavior(self, dpi_behavior: DPIBehavior) -> List[Dict[str, Any]]:
        """Получение стратегий для поведения DPI."""
        
        behavior_mappings = {
            DPIBehavior.ACTIVE_RST_INJECTION: [
                {
                    "name": "Anti-RST TTL",
                    "attack_name": "fake",
                    "base_confidence": 0.9,
                    "rationale": "Counter active RST injection with TTL manipulation",
                    "parameters": {
                        "ttl": {"default_value": 1, "confidence": 0.9, "rationale": "Expire before RST source"}
                    }
                }
            ],
            
            DPIBehavior.STATEFUL_INSPECTION: [
                {
                    "name": "State Confusion",
                    "attack_name": "disorder",
                    "base_confidence": 0.8,
                    "rationale": "Confuse stateful DPI with packet reordering",
                    "parameters": {
                        "split_pos": {"default_value": 1, "confidence": 0.7, "rationale": "Very early split"}
                    }
                }
            ],
            
            DPIBehavior.DEEP_PACKET_INSPECTION: [
                {
                    "name": "Deep Fragmentation",
                    "attack_name": "multisplit",
                    "base_confidence": 0.7,
                    "rationale": "Heavy fragmentation to evade deep inspection",
                    "parameters": {
                        "split_count": {"default_value": 20, "confidence": 0.6, "rationale": "Very heavy fragmentation"}
                    }
                }
            ]
        }
        
        return behavior_mappings.get(dpi_behavior, [])


class ParameterOptimizer:
    """Оптимизатор параметров стратегий."""
    
    async def optimize_parameters(self, strategy: GeneratedStrategy, 
                                pcap_analysis: PCAPAnalysisResult) -> GeneratedStrategy:
        """Оптимизация параметров стратегии."""
        
        # Оптимизация TTL на основе анализа
        if "ttl" in strategy.parameters:
            optimized_ttl = await self._optimize_ttl_parameter(strategy, pcap_analysis)
            if optimized_ttl:
                strategy.parameters["ttl"].value = optimized_ttl
                strategy.parameters["ttl"].source = "pcap_optimization"
                strategy.parameters["ttl"].confidence *= 1.1
        
        # Оптимизация позиций split
        if "split_pos" in strategy.parameters:
            optimized_split = await self._optimize_split_parameter(strategy, pcap_analysis)
            if optimized_split:
                strategy.parameters["split_pos"].value = optimized_split
                strategy.parameters["split_pos"].source = "pcap_optimization"
        
        # Оптимизация методов fooling
        if "fooling" in strategy.parameters:
            optimized_fooling = await self._optimize_fooling_parameter(strategy, pcap_analysis)
            if optimized_fooling:
                strategy.parameters["fooling"].value = optimized_fooling
                strategy.parameters["fooling"].source = "pcap_optimization"
        
        return strategy
    
    async def _optimize_ttl_parameter(self, strategy: GeneratedStrategy, 
                                    pcap_analysis: PCAPAnalysisResult) -> Optional[int]:
        """Оптимизация TTL параметра."""
        # Анализ TTL в RST пакетах из evidence
        blocking_evidence = pcap_analysis.blocking_evidence
        
        if "suspicious_patterns" in blocking_evidence:
            if "low_ttl" in blocking_evidence["suspicious_patterns"]:
                return 1  # Очень низкий TTL
            elif "standard_dpi_ttl" in blocking_evidence["suspicious_patterns"]:
                return 2  # Чуть выше стандартного
        
        # Анализ flows для определения оптимального TTL
        for flow in pcap_analysis.flows:
            if flow.blocking_detected and flow.blocking_type == BlockingType.RST_INJECTION:
                rst_details = flow.blocking_details.get("rst_ttls", [])
                if rst_details:
                    min_rst_ttl = min(rst_details)
                    return max(1, min_rst_ttl - 1)
        
        return None
    
    async def _optimize_split_parameter(self, strategy: GeneratedStrategy, 
                                      pcap_analysis: PCAPAnalysisResult) -> Optional[int]:
        """Оптимизация split позиции."""
        # Анализ размеров пакетов для определения оптимальной позиции split
        if pcap_analysis.flows:
            avg_payload_size = sum(f.total_bytes / max(f.packet_count, 1) for f in pcap_analysis.flows) / len(pcap_analysis.flows)
            
            if avg_payload_size < 100:
                return 2  # Очень ранний split для малых пакетов
            elif avg_payload_size < 500:
                return 5  # Ранний split
            else:
                return 10  # Стандартный split
        
        return None
    
    async def _optimize_fooling_parameter(self, strategy: GeneratedStrategy, 
                                        pcap_analysis: PCAPAnalysisResult) -> Optional[str]:
        """Оптимизация fooling метода."""
        blocking_evidence = pcap_analysis.blocking_evidence
        
        # Выбор fooling метода на основе подозрительных паттернов
        if "suspicious_patterns" in blocking_evidence:
            patterns = blocking_evidence["suspicious_patterns"]
            
            if "zero_checksum" in patterns:
                return "badsum"  # Используем bad checksum
            elif "rst_packet" in patterns:
                return "badseq"  # Используем bad sequence
            elif "zero_window" in patterns:
                return "md5sig"  # Используем MD5 signature
        
        return None


class PriorityCalculator:
    """Калькулятор приоритетов стратегий."""
    
    async def calculate_priority(self, strategy: GeneratedStrategy, 
                               pcap_analysis: PCAPAnalysisResult) -> Tuple[StrategyPriority, float]:
        """Расчет приоритета стратегии."""
        
        base_priority = strategy.priority
        confidence_adjustment = 1.0
        
        # Повышение приоритета для точного соответствия типу блокировки
        if strategy.target_blocking_type == pcap_analysis.primary_blocking_type:
            if base_priority == StrategyPriority.MEDIUM:
                base_priority = StrategyPriority.HIGH
            confidence_adjustment *= 1.2
        
        # Повышение приоритета для высокой уверенности в анализе
        if pcap_analysis.confidence > 0.8:
            confidence_adjustment *= 1.1
        
        # Понижение приоритета для экспериментальных стратегий
        if "experimental" in strategy.source_evidence:
            base_priority = StrategyPriority.EXPERIMENTAL
            confidence_adjustment *= 0.7
        
        # Повышение приоритета для стратегий с оптимизированными параметрами
        optimized_params = sum(1 for p in strategy.parameters.values() if p.source == "pcap_optimization")
        if optimized_params > 0:
            confidence_adjustment *= (1.0 + optimized_params * 0.1)
        
        return base_priority, confidence_adjustment


class StrategyValidator:
    """Валидатор стратегий."""
    
    async def validate_strategy(self, strategy: GeneratedStrategy, 
                              pcap_analysis: PCAPAnalysisResult) -> Dict[str, Any]:
        """Валидация стратегии."""
        
        validation_result = {
            "is_valid": True,
            "score": 0.0,
            "details": {},
            "issues": []
        }
        
        # Валидация параметров
        param_validation = await self._validate_parameters(strategy)
        validation_result["details"]["parameters"] = param_validation
        validation_result["score"] += param_validation["score"] * 0.4
        
        # Валидация соответствия типу блокировки
        blocking_validation = await self._validate_blocking_match(strategy, pcap_analysis)
        validation_result["details"]["blocking_match"] = blocking_validation
        validation_result["score"] += blocking_validation["score"] * 0.3
        
        # Валидация логической согласованности
        logic_validation = await self._validate_logic(strategy)
        validation_result["details"]["logic"] = logic_validation
        validation_result["score"] += logic_validation["score"] * 0.3
        
        # Общая валидация
        if validation_result["score"] < 0.5:
            validation_result["is_valid"] = False
            validation_result["issues"].append("Low overall validation score")
        
        return validation_result
    
    async def _validate_parameters(self, strategy: GeneratedStrategy) -> Dict[str, Any]:
        """Валидация параметров стратегии."""
        
        param_validation = {
            "score": 1.0,
            "valid_params": [],
            "invalid_params": [],
            "issues": []
        }
        
        for param_name, param in strategy.parameters.items():
            if param_name == "ttl":
                if isinstance(param.value, int) and 1 <= param.value <= 255:
                    param_validation["valid_params"].append(param_name)
                else:
                    param_validation["invalid_params"].append(param_name)
                    param_validation["issues"].append(f"Invalid TTL value: {param.value}")
            
            elif param_name == "split_pos":
                if isinstance(param.value, int) and param.value > 0:
                    param_validation["valid_params"].append(param_name)
                else:
                    param_validation["invalid_params"].append(param_name)
                    param_validation["issues"].append(f"Invalid split position: {param.value}")
            
            elif param_name == "fooling":
                valid_fooling = ["badsum", "badseq", "md5sig", "none"]
                if param.value in valid_fooling:
                    param_validation["valid_params"].append(param_name)
                else:
                    param_validation["invalid_params"].append(param_name)
                    param_validation["issues"].append(f"Invalid fooling method: {param.value}")
        
        # Расчет score на основе валидных параметров
        total_params = len(strategy.parameters)
        valid_params = len(param_validation["valid_params"])
        
        if total_params > 0:
            param_validation["score"] = valid_params / total_params
        
        return param_validation
    
    async def _validate_blocking_match(self, strategy: GeneratedStrategy, 
                                     pcap_analysis: PCAPAnalysisResult) -> Dict[str, Any]:
        """Валидация соответствия стратегии типу блокировки."""
        
        blocking_validation = {
            "score": 0.5,
            "matches": [],
            "mismatches": []
        }
        
        # Проверка соответствия основному типу блокировки
        if strategy.target_blocking_type == pcap_analysis.primary_blocking_type:
            blocking_validation["matches"].append("primary_blocking_type")
            blocking_validation["score"] += 0.3
        
        # Проверка соответствия поведению DPI
        expected_attacks = {
            DPIBehavior.ACTIVE_RST_INJECTION: ["fake", "disorder"],
            DPIBehavior.STATEFUL_INSPECTION: ["disorder", "fake"],
            DPIBehavior.DEEP_PACKET_INSPECTION: ["multisplit", "split"]
        }
        
        expected = expected_attacks.get(pcap_analysis.dpi_behavior, [])
        if strategy.attack_name in expected:
            blocking_validation["matches"].append("dpi_behavior")
            blocking_validation["score"] += 0.2
        
        return blocking_validation
    
    async def _validate_logic(self, strategy: GeneratedStrategy) -> Dict[str, Any]:
        """Валидация логической согласованности стратегии."""
        
        logic_validation = {
            "score": 1.0,
            "logical_issues": []
        }
        
        # Проверка логических противоречий в параметрах
        if "ttl" in strategy.parameters and "fooling" in strategy.parameters:
            ttl_val = strategy.parameters["ttl"].value
            fooling_val = strategy.parameters["fooling"].value
            
            # TTL=1 с badsum может быть неэффективным
            if ttl_val == 1 and fooling_val == "badsum":
                logic_validation["logical_issues"].append("TTL=1 with badsum may be ineffective")
                logic_validation["score"] -= 0.2
        
        return logic_validation


# Удобные функции для использования
async def generate_strategies_from_pcap(pcap_analysis: PCAPAnalysisResult, 
                                      config: Optional[Dict[str, Any]] = None) -> StrategyGenerationResult:
    """
    Удобная функция для генерации стратегий из PCAP анализа.
    
    Args:
        pcap_analysis: Результат анализа PCAP файла
        config: Конфигурация генератора
        
    Returns:
        StrategyGenerationResult с сгенерированными стратегиями
    """
    generator = PCAPStrategyGenerator(config)
    return await generator.generate_strategies(pcap_analysis)


if __name__ == "__main__":
    # Пример использования
    async def main():
        # Настройка логирования
        logging.basicConfig(level=logging.INFO)
        
        # Пример PCAP анализа (заглушка)
        from .intelligent_pcap_analyzer import PCAPAnalysisResult, BlockingType, DPIBehavior
        
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            analysis_timestamp=datetime.now(),
            total_packets=100,
            total_flows=5,
            analysis_duration=2.5,
            blocking_detected=True,
            primary_blocking_type=BlockingType.RST_INJECTION,
            dpi_behavior=DPIBehavior.ACTIVE_RST_INJECTION,
            confidence=0.8
        )
        
        # Генерация стратегий
        config = {
            "max_strategies_per_type": 3,
            "enable_experimental": False,
            "confidence_threshold": 0.6
        }
        
        result = await generate_strategies_from_pcap(pcap_analysis, config)
        
        print(f"Сгенерировано {result.total_strategies} стратегий:")
        for strategy in result.strategies:
            print(f"- {strategy.name} ({strategy.attack_name}) - "
                  f"Приоритет: {strategy.priority.value}, "
                  f"Уверенность: {strategy.confidence:.2f}")
    
    # Запуск примера
    asyncio.run(main())