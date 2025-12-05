"""
Генератор стратегий на основе PCAP анализа

Задача 7.2: Создать генератор стратегий на основе PCAP анализа
- Маппинг выявленных проблем в PCAP на конкретные стратегии обхода
- Система приоритизации стратегий на основе анализа трафика
- Генерация параметров стратегий (TTL, позиции split, методы fooling)
- Адаптивная настройка параметров на основе характеристик блокировки
- Система валидации сгенерированных стратегий
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
import random

# Импорт компонентов PCAP анализа
try:
    from .intelligent_pcap_analyzer import (
        BlockingType, PCAPAnalysisResult, DPISignature, IntelligentPCAPAnalyzer
    )
    PCAP_ANALYZER_AVAILABLE = True
except ImportError:
    PCAP_ANALYZER_AVAILABLE = False
    # Fallback классы
    class BlockingType(Enum):
        RST_INJECTION = "rst_injection"
        SNI_FILTERING = "sni_filtering"
        UNKNOWN = "unknown"

LOG = logging.getLogger("PCAPStrategyGenerator")


@dataclass
class PCAPGeneratedStrategy:
    """Стратегия сгенерированная на основе PCAP анализа"""
    name: str
    attack_combination: List[str]
    parameters: Dict[str, Any]
    
    # Метаданные генерации
    source_blocking_type: BlockingType
    confidence: float
    rationale: str
    pcap_evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Приоритет и валидация
    priority: float = 0.5
    validated: bool = False
    expected_success_rate: float = 0.5
    
    # Временные метки
    generated_at: datetime = field(default_factory=datetime.now)


class PCAPStrategyGenerator:
    """
    Генератор стратегий на основе анализа PCAP файлов
    
    Реализует требования FR-13.4, FR-13.5, FR-13.6:
    - Маппинг проблем PCAP на стратегии обхода
    - Приоритизация стратегий
    - Адаптивная настройка параметров
    """
    
    def __init__(self):
        self.strategy_templates = self._initialize_strategy_templates()
        self.parameter_optimizers = self._initialize_parameter_optimizers()
        
        # Статистика генерации
        self.stats = {
            "strategies_generated": 0,
            "successful_mappings": 0,
            "parameter_optimizations": 0,
            "validation_attempts": 0
        }
        
        LOG.info("✅ PCAPStrategyGenerator инициализирован")
    
    async def generate_strategies_from_pcap(self, pcap_analysis: PCAPAnalysisResult, 
                                          max_strategies: int = 10) -> List[PCAPGeneratedStrategy]:
        """
        Основной метод генерации стратегий на основе PCAP анализа
        
        Args:
            pcap_analysis: Результат анализа PCAP файла
            max_strategies: Максимальное количество стратегий
            
        Returns:
            Список сгенерированных стратегий
        """
        start_time = time.time()
        
        LOG.info(f"🎯 Генерация стратегий для {pcap_analysis.blocking_type.value} "
                f"(confidence: {pcap_analysis.confidence:.2f})")
        
        strategies = []
        
        try:
            # 1. Получаем базовые стратегии для типа блокировки
            base_strategies = self._get_base_strategies_for_blocking_type(pcap_analysis.blocking_type)
            
            # 2. Генерируем стратегии с адаптивными параметрами
            for template in base_strategies[:max_strategies]:
                strategy = await self._generate_strategy_from_template(template, pcap_analysis)
                if strategy:
                    strategies.append(strategy)
            
            # 3. Оптимизируем параметры на основе PCAP данных
            for strategy in strategies:
                await self._optimize_strategy_parameters(strategy, pcap_analysis)
            
            # 4. Приоритизируем стратегии
            strategies = self._prioritize_strategies(strategies, pcap_analysis)
            
            # 5. Валидируем стратегии
            for strategy in strategies:
                await self._validate_strategy(strategy, pcap_analysis)
            
            # Обновляем статистику
            generation_time = time.time() - start_time
            self.stats["strategies_generated"] += len(strategies)
            self.stats["successful_mappings"] += 1
            
            LOG.info(f"✅ Сгенерировано {len(strategies)} стратегий за {generation_time:.2f}s")
            
            return strategies
            
        except Exception as e:
            LOG.error(f"❌ Ошибка генерации стратегий: {e}")
            return []
    
    def _initialize_strategy_templates(self) -> Dict[BlockingType, List[Dict]]:
        """Инициализация шаблонов стратегий для различных типов блокировок"""
        return {
            BlockingType.RST_INJECTION: [
                {
                    "name": "fake_rst_bypass",
                    "attacks": ["fake"],
                    "base_params": {"ttl": 1, "fooling": "badseq"},
                    "priority": 0.9,
                    "rationale": "Низкий TTL для обхода RST инъекций"
                },
                {
                    "name": "disorder_rst_bypass", 
                    "attacks": ["disorder"],
                    "base_params": {"split_pos": 3, "fooling": "badseq"},
                    "priority": 0.8,
                    "rationale": "Нарушение порядка пакетов для обхода stateful DPI"
                },
                {
                    "name": "multidisorder_rst_bypass",
                    "attacks": ["multidisorder"],
                    "base_params": {"split_count": 4, "fooling": "badsum"},
                    "priority": 0.7,
                    "rationale": "Множественное нарушение порядка"
                }
            ],
            
            BlockingType.SNI_FILTERING: [
                {
                    "name": "sni_split_bypass",
                    "attacks": ["split"],
                    "base_params": {"split_pos": "sni", "fooling": "badsum"},
                    "priority": 0.9,
                    "rationale": "Разделение SNI для обхода фильтрации"
                },
                {
                    "name": "tls_fragment_bypass",
                    "attacks": ["multisplit"],
                    "base_params": {"split_count": 8, "split_pos": "sni"},
                    "priority": 0.8,
                    "rationale": "Фрагментация TLS Client Hello"
                },
                {
                    "name": "fake_sni_bypass",
                    "attacks": ["fake"],
                    "base_params": {"ttl": 3, "split_pos": "sni", "fooling": "badseq"},
                    "priority": 0.7,
                    "rationale": "Fake пакеты для маскировки SNI"
                }
            ],
            
            BlockingType.TLS_HANDSHAKE_FAILURE: [
                {
                    "name": "tls_record_split",
                    "attacks": ["split"],
                    "base_params": {"split_pos": 5, "fooling": "badsum"},
                    "priority": 0.8,
                    "rationale": "Разделение TLS записей"
                },
                {
                    "name": "tls_multisplit",
                    "attacks": ["multisplit"],
                    "base_params": {"split_count": 6, "split_pos": 10},
                    "priority": 0.7,
                    "rationale": "Множественное разделение TLS"
                }
            ],
            
            BlockingType.DNS_POISONING: [
                {
                    "name": "dns_bypass_strategy",
                    "attacks": ["fake"],
                    "base_params": {"ttl": 2, "fooling": "badseq"},
                    "priority": 0.6,
                    "rationale": "Обход DNS poisoning через fake пакеты"
                }
            ],
            
            BlockingType.FRAGMENT_REASSEMBLY: [
                {
                    "name": "timing_based_bypass",
                    "attacks": ["disorder"],
                    "base_params": {"split_pos": 2, "fooling": "badseq"},
                    "priority": 0.7,
                    "rationale": "Timing-based обход для DPI с reassembly"
                }
            ],
            
            BlockingType.CONNECTION_TIMEOUT: [
                {
                    "name": "fast_connection_bypass",
                    "attacks": ["fake"],
                    "base_params": {"ttl": 5, "fooling": "badsum"},
                    "priority": 0.5,
                    "rationale": "Быстрое установление соединения"
                }
            ]
        }
    
    def _initialize_parameter_optimizers(self) -> Dict[str, callable]:
        """Инициализация оптимизаторов параметров"""
        return {
            "ttl": self._optimize_ttl_parameter,
            "split_pos": self._optimize_split_pos_parameter,
            "split_count": self._optimize_split_count_parameter,
            "fooling": self._optimize_fooling_parameter
        }
    
    def _get_base_strategies_for_blocking_type(self, blocking_type: BlockingType) -> List[Dict]:
        """Получение базовых стратегий для типа блокировки"""
        templates = self.strategy_templates.get(blocking_type, [])
        
        # Добавляем универсальные стратегии если специфичных нет
        if not templates:
            templates = [
                {
                    "name": "universal_bypass",
                    "attacks": ["fake"],
                    "base_params": {"ttl": 3, "fooling": "badseq"},
                    "priority": 0.4,
                    "rationale": f"Универсальная стратегия для {blocking_type.value}"
                }
            ]
        
        LOG.debug(f"📋 Найдено {len(templates)} шаблонов для {blocking_type.value}")
        return templates
    
    async def _generate_strategy_from_template(self, template: Dict, 
                                             pcap_analysis: PCAPAnalysisResult) -> Optional[PCAPGeneratedStrategy]:
        """Генерация стратегии из шаблона"""
        try:
            strategy = PCAPGeneratedStrategy(
                name=f"{template['name']}_{pcap_analysis.domain}",
                attack_combination=template["attacks"].copy(),
                parameters=template["base_params"].copy(),
                source_blocking_type=pcap_analysis.blocking_type,
                confidence=pcap_analysis.confidence,
                rationale=template["rationale"],
                priority=template["priority"],
                pcap_evidence=self._extract_relevant_evidence(pcap_analysis, template)
            )
            
            LOG.debug(f"🔧 Сгенерирована стратегия: {strategy.name}")
            return strategy
            
        except Exception as e:
            LOG.error(f"❌ Ошибка генерации стратегии из шаблона: {e}")
            return None
    
    def _extract_relevant_evidence(self, pcap_analysis: PCAPAnalysisResult, template: Dict) -> Dict[str, Any]:
        """Извлечение релевантных данных из PCAP анализа"""
        evidence = {
            "blocking_type": pcap_analysis.blocking_type.value,
            "confidence": pcap_analysis.confidence,
            "template_used": template["name"]
        }
        
        # Добавляем специфичные данные в зависимости от типа блокировки
        if pcap_analysis.blocking_type == BlockingType.RST_INJECTION:
            rst_data = pcap_analysis.analysis_details.get("rst_analysis", {})
            evidence.update({
                "rst_packets": rst_data.get("total_rst_packets", 0),
                "suspicious_rsts": rst_data.get("suspicious_rst_packets", 0)
            })
        
        elif pcap_analysis.blocking_type == BlockingType.SNI_FILTERING:
            tls_data = pcap_analysis.analysis_details.get("tls_analysis", {})
            evidence.update({
                "sni_values": tls_data.get("sni_values", []),
                "client_hello_count": tls_data.get("client_hello_count", 0)
            })
        
        return evidence    
  
  async def _optimize_strategy_parameters(self, strategy: PCAPGeneratedStrategy, 
                                          pcap_analysis: PCAPAnalysisResult):
        """Оптимизация параметров стратегии на основе PCAP данных"""
        try:
            # Оптимизируем каждый параметр
            for param_name, param_value in strategy.parameters.items():
                if param_name in self.parameter_optimizers:
                    optimizer = self.parameter_optimizers[param_name]
                    optimized_value = await optimizer(param_value, pcap_analysis, strategy)
                    
                    if optimized_value != param_value:
                        LOG.debug(f"🔧 Оптимизирован {param_name}: {param_value} -> {optimized_value}")
                        strategy.parameters[param_name] = optimized_value
                        self.stats["parameter_optimizations"] += 1
            
            # Обновляем rationale с информацией об оптимизации
            strategy.rationale += f" (оптимизировано на основе PCAP анализа)"
            
        except Exception as e:
            LOG.error(f"❌ Ошибка оптимизации параметров: {e}")
    
    async def _optimize_ttl_parameter(self, current_ttl: int, pcap_analysis: PCAPAnalysisResult, 
                                    strategy: PCAPGeneratedStrategy) -> int:
        """Оптимизация TTL параметра"""
        # Для RST инъекций используем очень низкий TTL
        if pcap_analysis.blocking_type == BlockingType.RST_INJECTION:
            rst_analysis = pcap_analysis.analysis_details.get("rst_analysis", {})
            suspicious_rsts = rst_analysis.get("suspicious_details", [])
            
            if suspicious_rsts:
                # Находим минимальный TTL среди подозрительных RST
                min_rst_ttl = min(rst["ttl"] for rst in suspicious_rsts)
                # Используем TTL меньше минимального RST TTL
                optimized_ttl = max(1, min_rst_ttl - 1)
                
                LOG.debug(f"🎯 TTL оптимизирован для RST bypass: {current_ttl} -> {optimized_ttl}")
                return optimized_ttl
        
        # Для других типов блокировок используем умеренные значения
        elif pcap_analysis.blocking_type == BlockingType.SNI_FILTERING:
            return min(current_ttl, 5)  # Умеренный TTL для SNI
        
        return current_ttl
    
    async def _optimize_split_pos_parameter(self, current_pos, pcap_analysis: PCAPAnalysisResult,
                                          strategy: PCAPGeneratedStrategy):
        """Оптимизация позиции split"""
        # Для SNI фильтрации оптимизируем позицию split
        if pcap_analysis.blocking_type == BlockingType.SNI_FILTERING:
            tls_analysis = pcap_analysis.analysis_details.get("tls_analysis", {})
            sni_values = tls_analysis.get("sni_values", [])
            
            if sni_values:
                # Используем позицию "sni" для точного разделения
                return "sni"
        
        # Для RST инъекций используем ранние позиции
        elif pcap_analysis.blocking_type == BlockingType.RST_INJECTION:
            return min(3, current_pos) if isinstance(current_pos, int) else current_pos
        
        return current_pos
    
    async def _optimize_split_count_parameter(self, current_count: int, pcap_analysis: PCAPAnalysisResult,
                                            strategy: PCAPGeneratedStrategy) -> int:
        """Оптимизация количества разделений"""
        # Для фрагментации увеличиваем количество split'ов
        if pcap_analysis.blocking_type == BlockingType.FRAGMENT_REASSEMBLY:
            fragment_analysis = pcap_analysis.analysis_details.get("fragment_analysis", {})
            if fragment_analysis.get("reassembly_problems", False):
                # DPI не может собрать фрагменты - используем меньше split'ов
                return max(2, current_count // 2)
            else:
                # DPI собирает фрагменты - используем больше split'ов
                return min(current_count * 2, 16)
        
        # Для SNI фильтрации используем умеренное количество
        elif pcap_analysis.blocking_type == BlockingType.SNI_FILTERING:
            return min(current_count, 8)
        
        return current_count
    
    async def _optimize_fooling_parameter(self, current_fooling: str, pcap_analysis: PCAPAnalysisResult,
                                        strategy: PCAPGeneratedStrategy) -> str:
        """Оптимизация метода fooling"""
        # Для RST инъекций используем badseq
        if pcap_analysis.blocking_type == BlockingType.RST_INJECTION:
            return "badseq"
        
        # Для SNI фильтрации используем badsum
        elif pcap_analysis.blocking_type == BlockingType.SNI_FILTERING:
            return "badsum"
        
        # Для TLS проблем используем badsum
        elif pcap_analysis.blocking_type == BlockingType.TLS_HANDSHAKE_FAILURE:
            return "badsum"
        
        return current_fooling
    
    def _prioritize_strategies(self, strategies: List[PCAPGeneratedStrategy], 
                             pcap_analysis: PCAPAnalysisResult) -> List[PCAPGeneratedStrategy]:
        """Приоритизация стратегий на основе анализа трафика"""
        try:
            for strategy in strategies:
                # Базовый приоритет из шаблона
                base_priority = strategy.priority
                
                # Корректировка на основе confidence анализа
                confidence_bonus = pcap_analysis.confidence * 0.2
                
                # Корректировка на основе количества DPI сигнатур
                signature_bonus = min(len(pcap_analysis.dpi_signatures) * 0.1, 0.3)
                
                # Корректировка на основе специфичности стратегии
                specificity_bonus = 0.0
                if strategy.source_blocking_type == pcap_analysis.blocking_type:
                    specificity_bonus = 0.2
                
                # Финальный приоритет
                final_priority = min(base_priority + confidence_bonus + signature_bonus + specificity_bonus, 1.0)
                strategy.priority = final_priority
                
                # Оценка ожидаемого успеха
                strategy.expected_success_rate = self._estimate_success_rate(strategy, pcap_analysis)
            
            # Сортируем по приоритету
            strategies.sort(key=lambda s: s.priority, reverse=True)
            
            LOG.info(f"📊 Приоритизировано {len(strategies)} стратегий")
            for i, strategy in enumerate(strategies[:5]):  # Топ 5
                LOG.debug(f"  {i+1}. {strategy.name}: priority={strategy.priority:.2f}, "
                         f"success_rate={strategy.expected_success_rate:.2f}")
            
            return strategies
            
        except Exception as e:
            LOG.error(f"❌ Ошибка приоритизации: {e}")
            return strategies
    
    def _estimate_success_rate(self, strategy: PCAPGeneratedStrategy, 
                             pcap_analysis: PCAPAnalysisResult) -> float:
        """Оценка ожидаемого успеха стратегии"""
        base_rate = 0.5
        
        # Бонус за соответствие типу блокировки
        if strategy.source_blocking_type == pcap_analysis.blocking_type:
            base_rate += 0.3
        
        # Бонус за высокую confidence анализа
        base_rate += pcap_analysis.confidence * 0.2
        
        # Бонус за наличие DPI сигнатур
        if pcap_analysis.dpi_signatures:
            base_rate += min(len(pcap_analysis.dpi_signatures) * 0.05, 0.2)
        
        # Штраф за неизвестный тип блокировки
        if pcap_analysis.blocking_type == BlockingType.UNKNOWN:
            base_rate -= 0.2
        
        return min(max(base_rate, 0.1), 0.9)  # Ограничиваем от 0.1 до 0.9
    
    async def _validate_strategy(self, strategy: PCAPGeneratedStrategy, 
                               pcap_analysis: PCAPAnalysisResult):
        """Валидация сгенерированной стратегии"""
        try:
            self.stats["validation_attempts"] += 1
            
            # Проверяем корректность параметров
            validation_errors = []
            
            # Валидация TTL
            if "ttl" in strategy.parameters:
                ttl = strategy.parameters["ttl"]
                if not isinstance(ttl, int) or ttl < 1 or ttl > 255:
                    validation_errors.append(f"Некорректный TTL: {ttl}")
            
            # Валидация split_count
            if "split_count" in strategy.parameters:
                split_count = strategy.parameters["split_count"]
                if not isinstance(split_count, int) or split_count < 1 or split_count > 32:
                    validation_errors.append(f"Некорректный split_count: {split_count}")
            
            # Валидация split_pos
            if "split_pos" in strategy.parameters:
                split_pos = strategy.parameters["split_pos"]
                if isinstance(split_pos, int):
                    if split_pos < 1 or split_pos > 1000:
                        validation_errors.append(f"Некорректный split_pos: {split_pos}")
                elif isinstance(split_pos, str):
                    valid_positions = ["sni", "host", "method"]
                    if split_pos not in valid_positions:
                        validation_errors.append(f"Некорректная позиция split_pos: {split_pos}")
            
            # Валидация fooling
            if "fooling" in strategy.parameters:
                fooling = strategy.parameters["fooling"]
                valid_fooling = ["badseq", "badsum", "badack", "none"]
                if fooling not in valid_fooling:
                    validation_errors.append(f"Некорректный fooling: {fooling}")
            
            # Проверяем совместимость атак и параметров
            for attack in strategy.attack_combination:
                if attack in ["split", "multisplit"] and "split_pos" not in strategy.parameters:
                    validation_errors.append(f"Атака {attack} требует параметр split_pos")
                
                if attack == "multisplit" and "split_count" not in strategy.parameters:
                    validation_errors.append(f"Атака multisplit требует параметр split_count")
            
            # Устанавливаем статус валидации
            strategy.validated = len(validation_errors) == 0
            
            if validation_errors:
                LOG.warning(f"⚠️ Ошибки валидации стратегии {strategy.name}: {validation_errors}")
                strategy.rationale += f" (ошибки валидации: {len(validation_errors)})"
            else:
                LOG.debug(f"✅ Стратегия {strategy.name} прошла валидацию")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка валидации стратегии: {e}")
            strategy.validated = False
    
    def get_generation_statistics(self) -> Dict[str, Any]:
        """Получение статистики генерации"""
        return {
            "strategies_generated": self.stats["strategies_generated"],
            "successful_mappings": self.stats["successful_mappings"],
            "parameter_optimizations": self.stats["parameter_optimizations"],
            "validation_attempts": self.stats["validation_attempts"],
            "template_count": sum(len(templates) for templates in self.strategy_templates.values()),
            "optimizer_count": len(self.parameter_optimizers)
        }
    
    async def generate_adaptive_parameters(self, base_strategy: Dict, 
                                         pcap_signatures: List[DPISignature]) -> Dict[str, Any]:
        """Генерация адаптивных параметров на основе DPI сигнатур"""
        adaptive_params = base_strategy["base_params"].copy()
        
        try:
            for signature in pcap_signatures:
                # Адаптация на основе RST сигнатур
                if signature.signature_type == BlockingType.RST_INJECTION:
                    if "ttl" in signature.evidence:
                        rst_ttl = signature.evidence["ttl"]
                        adaptive_params["ttl"] = max(1, rst_ttl - 2)
                
                # Адаптация на основе SNI сигнатур
                elif signature.signature_type == BlockingType.SNI_FILTERING:
                    adaptive_params["split_pos"] = "sni"
                    if "sni_value" in signature.evidence:
                        sni_length = len(signature.evidence["sni_value"])
                        # Адаптируем split_count на основе длины SNI
                        adaptive_params["split_count"] = min(max(4, sni_length // 4), 16)
            
            LOG.debug(f"🔧 Сгенерированы адаптивные параметры: {adaptive_params}")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка генерации адаптивных параметров: {e}")
        
        return adaptive_params
    
    def create_strategy_explanation(self, strategy: PCAPGeneratedStrategy, 
                                  pcap_analysis: PCAPAnalysisResult) -> str:
        """Создание объяснения для стратегии"""
        explanation_parts = [
            f"Стратегия '{strategy.name}' сгенерирована для обхода {strategy.source_blocking_type.value}",
            f"Confidence анализа: {pcap_analysis.confidence:.2f}",
            f"Приоритет стратегии: {strategy.priority:.2f}",
            f"Ожидаемый успех: {strategy.expected_success_rate:.2f}",
            f"Атаки: {', '.join([a for a in strategy.attack_combination if a is not None])}",
            f"Параметры: {strategy.parameters}",
            f"Обоснование: {strategy.rationale}"
        ]
        
        if pcap_analysis.dpi_signatures:
            explanation_parts.append(f"DPI сигнатуры: {len(pcap_analysis.dpi_signatures)}")
        
        if pcap_analysis.recommendations:
            explanation_parts.append(f"Рекомендации: {', '.join(pcap_analysis.recommendations[:3])}")
        
        return "\n".join(explanation_parts)