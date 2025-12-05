"""
Adaptive Engine Integration - интеграция PCAP анализа в AdaptiveEngine.

Этот модуль реализует:
- Автоматический запуск PCAP анализа после неудачных попыток
- Сохранение и загрузку результатов PCAP анализа
- Систему корреляции PCAP данных с историческими успехами
- Интеграцию с существующим Strategy Failure Analyzer
- Передачу результатов PCAP анализа в Strategy Generator

Requirements: FR-13.7, FR-13.8
"""

import os
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Импорт компонентов PCAP анализа
try:
    from .intelligent_pcap_analyzer import (
        IntelligentPCAPAnalyzer, PCAPAnalysisResult, BlockingType, DPIBehavior
    )
    from .pcap_strategy_generator import (
        PCAPStrategyGenerator, StrategyGenerationResult, GeneratedStrategy
    )
except ImportError:
    # Fallback для standalone тестирования
    try:
        import sys
        import os
        sys.path.append(os.path.dirname(__file__))
        from intelligent_pcap_analyzer import (
            IntelligentPCAPAnalyzer, PCAPAnalysisResult, BlockingType, DPIBehavior
        )
        from pcap_strategy_generator import (
            PCAPStrategyGenerator, StrategyGenerationResult, GeneratedStrategy
        )
    except ImportError:
        # Заглушки
        IntelligentPCAPAnalyzer = None
        PCAPAnalysisResult = None
        BlockingType = None
        DPIBehavior = None
        PCAPStrategyGenerator = None
        StrategyGenerationResult = None
        GeneratedStrategy = None

LOG = logging.getLogger("AdaptiveEngineIntegration")


@dataclass
class PCAPAnalysisCache:
    """Кэш результатов PCAP анализа."""
    domain: str
    pcap_file: str
    analysis_result: PCAPAnalysisResult
    generated_strategies: List[GeneratedStrategy]
    timestamp: datetime
    success_rate: float = 0.0
    usage_count: int = 0


@dataclass
class HistoricalCorrelation:
    """Корреляция PCAP данных с историческими успехами."""
    domain: str
    blocking_pattern: str
    successful_strategies: List[str]
    success_rate: float
    sample_count: int
    last_updated: datetime


class AdaptiveEnginePCAPIntegration:
    """
    Интеграция PCAP анализа в AdaptiveEngine.
    
    Основные функции:
    - Автоматический запуск PCAP анализа при неудачах
    - Кэширование и переиспользование результатов анализа
    - Корреляция с историческими данными
    - Интеграция с существующими компонентами
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Инициализация интеграции."""
        self.config = config or {}
        
        # Настройки интеграции
        self.enable_auto_pcap_analysis = self.config.get("enable_auto_pcap_analysis", True)
        self.pcap_cache_ttl_hours = self.config.get("pcap_cache_ttl_hours", 24)
        self.max_cache_entries = self.config.get("max_cache_entries", 100)
        self.correlation_threshold = self.config.get("correlation_threshold", 0.7)
        
        # Пути для хранения данных
        self.cache_dir = Path(self.config.get("cache_dir", "pcap_analysis_cache"))
        self.cache_dir.mkdir(exist_ok=True)
        
        self.correlation_file = self.cache_dir / "historical_correlations.json"
        self.cache_index_file = self.cache_dir / "cache_index.json"
        
        # Инициализация компонентов
        self.pcap_analyzer = IntelligentPCAPAnalyzer(self.config.get("analyzer_config", {}))
        self.strategy_generator = PCAPStrategyGenerator(self.config.get("generator_config", {}))
        
        # Кэш и корреляции
        self.analysis_cache: Dict[str, PCAPAnalysisCache] = {}
        self.historical_correlations: Dict[str, HistoricalCorrelation] = {}
        
        LOG.info("AdaptiveEnginePCAPIntegration инициализирован")
    
    async def analyze_failure_with_pcap(self, domain: str, pcap_file: str) -> Tuple[PCAPAnalysisResult, StrategyGenerationResult]:
        """Анализ неудачи с использованием PCAP файла."""
        LOG.info(f"Анализ неудачи для {domain} с PCAP файлом {pcap_file}")
        
        try:
            # Проверка кэша
            cached_result = await self._get_cached_analysis(domain, pcap_file)
            if cached_result:
                LOG.info(f"Использование кэшированного результата для {domain}")
                return cached_result.analysis_result, StrategyGenerationResult(
                    pcap_file=pcap_file,
                    generation_timestamp=datetime.now(),
                    total_strategies=len(cached_result.generated_strategies),
                    strategies=cached_result.generated_strategies
                )
            
            # PCAP анализ
            pcap_analysis = await self.pcap_analyzer.analyze_pcap(pcap_file)
            
            # Корреляция с историческими данными
            await self._correlate_with_historical_data(domain, pcap_analysis)
            
            # Генерация стратегий
            strategy_generation = await self.strategy_generator.generate_strategies(pcap_analysis)
            
            # Кэширование результата
            await self._cache_analysis_result(domain, pcap_file, pcap_analysis, strategy_generation.strategies)
            
            LOG.info(f"Анализ завершен: {len(strategy_generation.strategies)} стратегий сгенерировано")
            
            return pcap_analysis, strategy_generation
            
        except Exception as e:
            LOG.error(f"Ошибка анализа неудачи: {e}")
            # Возвращаем пустые результаты в случае ошибки
            empty_pcap = PCAPAnalysisResult(
                pcap_file=pcap_file,
                analysis_timestamp=datetime.now(),
                total_packets=0,
                total_flows=0,
                analysis_duration=0,
                blocking_detected=False,
                primary_blocking_type=BlockingType.UNKNOWN,
                dpi_behavior=DPIBehavior.UNKNOWN,
                confidence=0.0
            )
            
            empty_strategies = StrategyGenerationResult(
                pcap_file=pcap_file,
                generation_timestamp=datetime.now(),
                total_strategies=0
            )
            
            return empty_pcap, empty_strategies    

    async def integrate_with_adaptive_engine(self, adaptive_engine) -> bool:
        """Интеграция с AdaptiveEngine."""
        try:
            if not adaptive_engine:
                LOG.warning("AdaptiveEngine не предоставлен для интеграции")
                return False
            
            # Регистрация обработчика неудач
            if hasattr(adaptive_engine, 'register_failure_handler'):
                adaptive_engine.register_failure_handler(self._handle_strategy_failure)
                LOG.info("Обработчик неудач зарегистрирован в AdaptiveEngine")
            
            # Регистрация генератора стратегий
            if hasattr(adaptive_engine, 'register_strategy_generator'):
                adaptive_engine.register_strategy_generator(self._generate_pcap_strategies)
                LOG.info("Генератор стратегий зарегистрирован в AdaptiveEngine")
            
            return True
            
        except Exception as e:
            LOG.error(f"Ошибка интеграции с AdaptiveEngine: {e}")
            return False
    
    async def _handle_strategy_failure(self, domain: str, strategy: Any, 
                                     test_result: Any, pcap_file: Optional[str] = None) -> List[GeneratedStrategy]:
        """Обработчик неудач стратегий для AdaptiveEngine."""
        LOG.info(f"Обработка неудачи стратегии для {domain}")
        
        try:
            if not pcap_file or not os.path.exists(pcap_file):
                LOG.warning(f"PCAP файл недоступен для анализа: {pcap_file}")
                return []
            
            # Анализ неудачи с PCAP
            pcap_analysis, strategy_generation = await self.analyze_failure_with_pcap(
                domain, pcap_file
            )
            
            # Фильтрация стратегий по релевантности
            relevant_strategies = await self._filter_relevant_strategies(
                strategy_generation.strategies, strategy, test_result
            )
            
            # Обновление корреляций
            await self._update_failure_correlations(domain, strategy, pcap_analysis)
            
            return relevant_strategies
            
        except Exception as e:
            LOG.error(f"Ошибка обработки неудачи стратегии: {e}")
            return []
    
    async def _generate_pcap_strategies(self, domain: str, context: Dict[str, Any]) -> List[GeneratedStrategy]:
        """Генератор стратегий на основе PCAP для AdaptiveEngine."""
        LOG.info(f"Генерация PCAP стратегий для {domain}")
        
        try:
            # Поиск релевантных кэшированных анализов
            cached_analyses = await self._find_relevant_cached_analyses(domain)
            
            if not cached_analyses:
                LOG.info(f"Нет кэшированных PCAP анализов для {domain}")
                return []
            
            # Генерация стратегий на основе кэшированных анализов
            all_strategies = []
            for cached_analysis in cached_analyses:
                strategies = cached_analysis.generated_strategies
                # Адаптация стратегий под текущий контекст
                adapted_strategies = await self._adapt_strategies_to_context(strategies, context)
                all_strategies.extend(adapted_strategies)
            
            # Удаление дубликатов и ранжирование
            unique_strategies = await self._deduplicate_and_rank_strategies(all_strategies)
            
            return unique_strategies[:10]  # Максимум 10 стратегий
            
        except Exception as e:
            LOG.error(f"Ошибка генерации PCAP стратегий: {e}")
            return []
    
    async def _get_cached_analysis(self, domain: str, pcap_file: str) -> Optional[PCAPAnalysisCache]:
        """Получение кэшированного анализа."""
        cache_key = f"{domain}_{os.path.basename(pcap_file)}"
        
        if cache_key in self.analysis_cache:
            cached = self.analysis_cache[cache_key]
            
            # Проверка TTL
            age_hours = (datetime.now() - cached.timestamp).total_seconds() / 3600
            if age_hours < self.pcap_cache_ttl_hours:
                cached.usage_count += 1
                return cached
            else:
                # Удаление устаревшего кэша
                del self.analysis_cache[cache_key]
        
        return None
    
    async def _cache_analysis_result(self, domain: str, pcap_file: str, 
                                   pcap_analysis: PCAPAnalysisResult, 
                                   strategies: List[GeneratedStrategy]):
        """Кэширование результата анализа."""
        cache_key = f"{domain}_{os.path.basename(pcap_file)}"
        
        cache_entry = PCAPAnalysisCache(
            domain=domain,
            pcap_file=pcap_file,
            analysis_result=pcap_analysis,
            generated_strategies=strategies,
            timestamp=datetime.now()
        )
        
        self.analysis_cache[cache_key] = cache_entry
        
        # Ограничение размера кэша
        if len(self.analysis_cache) > self.max_cache_entries:
            # Удаление самых старых записей
            oldest_keys = sorted(
                self.analysis_cache.keys(),
                key=lambda k: self.analysis_cache[k].timestamp
            )[:len(self.analysis_cache) - self.max_cache_entries + 1]
            
            for key in oldest_keys:
                del self.analysis_cache[key]
        
        # Сохранение кэша на диск
        await self._save_cache_to_disk()
    
    async def _correlate_with_historical_data(self, domain: str, pcap_analysis: PCAPAnalysisResult):
        """Корреляция с историческими данными."""
        try:
            # Создание паттерна блокировки
            blocking_pattern = f"{pcap_analysis.primary_blocking_type.value}_{pcap_analysis.dpi_behavior.value}"
            
            # Поиск существующих корреляций
            correlation_key = f"{domain}_{blocking_pattern}"
            
            if correlation_key in self.historical_correlations:
                correlation = self.historical_correlations[correlation_key]
                correlation.sample_count += 1
                correlation.last_updated = datetime.now()
                LOG.info(f"Обновлена корреляция для {domain}: {blocking_pattern}")
            else:
                # Создание новой корреляции
                correlation = HistoricalCorrelation(
                    domain=domain,
                    blocking_pattern=blocking_pattern,
                    successful_strategies=[],
                    success_rate=0.0,
                    sample_count=1,
                    last_updated=datetime.now()
                )
                self.historical_correlations[correlation_key] = correlation
                LOG.info(f"Создана новая корреляция для {domain}: {blocking_pattern}")
            
            # Сохранение корреляций
            await self._save_correlations_to_disk()
            
        except Exception as e:
            LOG.error(f"Ошибка корреляции с историческими данными: {e}")
    
    async def _filter_relevant_strategies(self, strategies: List[GeneratedStrategy], 
                                        failed_strategy: Any, test_result: Any) -> List[GeneratedStrategy]:
        """Фильтрация релевантных стратегий."""
        relevant_strategies = []
        
        for strategy in strategies:
            # Исключаем стратегии, похожие на неудачную
            if hasattr(failed_strategy, 'attack_name'):
                if strategy.attack_name == failed_strategy.attack_name:
                    continue
            
            # Приоритет стратегиям с высокой уверенностью
            if strategy.confidence > 0.7:
                relevant_strategies.append(strategy)
            elif strategy.confidence > 0.5 and len(relevant_strategies) < 5:
                relevant_strategies.append(strategy)
        
        return relevant_strategies
    
    async def _update_failure_correlations(self, domain: str, failed_strategy: Any, 
                                         pcap_analysis: PCAPAnalysisResult):
        """Обновление корреляций неудач."""
        try:
            blocking_pattern = f"{pcap_analysis.primary_blocking_type.value}_{pcap_analysis.dpi_behavior.value}"
            correlation_key = f"{domain}_{blocking_pattern}"
            
            if correlation_key in self.historical_correlations:
                correlation = self.historical_correlations[correlation_key]
                
                # Удаление неудачной стратегии из успешных
                if hasattr(failed_strategy, 'attack_name'):
                    strategy_name = failed_strategy.attack_name
                    if strategy_name in correlation.successful_strategies:
                        correlation.successful_strategies.remove(strategy_name)
                        
                        # Пересчет success_rate
                        if correlation.sample_count > 0:
                            correlation.success_rate = len(correlation.successful_strategies) / correlation.sample_count
                
                correlation.last_updated = datetime.now()
                await self._save_correlations_to_disk()
            
        except Exception as e:
            LOG.error(f"Ошибка обновления корреляций неудач: {e}")
    
    async def _find_relevant_cached_analyses(self, domain: str) -> List[PCAPAnalysisCache]:
        """Поиск релевантных кэшированных анализов."""
        relevant_analyses = []
        
        for cache_entry in self.analysis_cache.values():
            # Точное совпадение домена
            if cache_entry.domain == domain:
                relevant_analyses.append(cache_entry)
            # Похожие домены (например, поддомены)
            elif domain in cache_entry.domain or cache_entry.domain in domain:
                relevant_analyses.append(cache_entry)
        
        # Сортировка по релевантности (usage_count и timestamp)
        relevant_analyses.sort(
            key=lambda x: (x.usage_count, x.timestamp),
            reverse=True
        )
        
        return relevant_analyses[:5]  # Максимум 5 релевантных анализов
    
    async def _adapt_strategies_to_context(self, strategies: List[GeneratedStrategy], 
                                         context: Dict[str, Any]) -> List[GeneratedStrategy]:
        """Адаптация стратегий под контекст."""
        adapted_strategies = []
        
        for strategy in strategies:
            # Создание копии стратегии
            adapted_strategy = GeneratedStrategy(
                strategy_id=f"adapted_{strategy.strategy_id}",
                name=f"Adapted {strategy.name}",
                attack_name=strategy.attack_name,
                priority=strategy.priority,
                confidence=strategy.confidence * 0.9,  # Небольшое снижение уверенности
                parameters=strategy.parameters.copy(),
                target_blocking_type=strategy.target_blocking_type,
                rationale=f"Adapted from cached analysis: {strategy.rationale}",
                source_evidence=strategy.source_evidence + ["cache_adaptation"]
            )
            
            # Адаптация параметров под контекст
            if "preferred_ttl" in context:
                if "ttl" in adapted_strategy.parameters:
                    adapted_strategy.parameters["ttl"].value = context["preferred_ttl"]
            
            if "max_split_count" in context:
                if "split_count" in adapted_strategy.parameters:
                    current_split = adapted_strategy.parameters["split_count"].value
                    max_split = context["max_split_count"]
                    adapted_strategy.parameters["split_count"].value = min(current_split, max_split)
            
            adapted_strategies.append(adapted_strategy)
        
        return adapted_strategies
    
    async def _deduplicate_and_rank_strategies(self, strategies: List[GeneratedStrategy]) -> List[GeneratedStrategy]:
        """Удаление дубликатов и ранжирование стратегий."""
        # Удаление дубликатов по attack_name
        seen_attacks = set()
        unique_strategies = []
        
        for strategy in strategies:
            if strategy.attack_name not in seen_attacks:
                seen_attacks.add(strategy.attack_name)
                unique_strategies.append(strategy)
        
        # Ранжирование по приоритету и уверенности
        unique_strategies.sort(
            key=lambda s: (s.priority.value, s.confidence),
            reverse=True
        )
        
        return unique_strategies
    
    async def _save_cache_to_disk(self):
        """Сохранение кэша на диск."""
        try:
            cache_data = {}
            for key, cache_entry in self.analysis_cache.items():
                cache_data[key] = {
                    "domain": cache_entry.domain,
                    "pcap_file": cache_entry.pcap_file,
                    "timestamp": cache_entry.timestamp.isoformat(),
                    "success_rate": cache_entry.success_rate,
                    "usage_count": cache_entry.usage_count,
                    # Сохраняем только основные данные анализа
                    "analysis_summary": {
                        "blocking_detected": cache_entry.analysis_result.blocking_detected,
                        "primary_blocking_type": cache_entry.analysis_result.primary_blocking_type.value,
                        "dpi_behavior": cache_entry.analysis_result.dpi_behavior.value,
                        "confidence": cache_entry.analysis_result.confidence
                    },
                    "strategies_count": len(cache_entry.generated_strategies)
                }
            
            with open(self.cache_index_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
        except Exception as e:
            LOG.error(f"Ошибка сохранения кэша: {e}")
    
    async def _save_correlations_to_disk(self):
        """Сохранение корреляций на диск."""
        try:
            correlations_data = {}
            for key, correlation in self.historical_correlations.items():
                correlations_data[key] = {
                    "domain": correlation.domain,
                    "blocking_pattern": correlation.blocking_pattern,
                    "successful_strategies": correlation.successful_strategies,
                    "success_rate": correlation.success_rate,
                    "sample_count": correlation.sample_count,
                    "last_updated": correlation.last_updated.isoformat()
                }
            
            with open(self.correlation_file, 'w', encoding='utf-8') as f:
                json.dump(correlations_data, f, indent=2, ensure_ascii=False)
            
        except Exception as e:
            LOG.error(f"Ошибка сохранения корреляций: {e}")
    
    async def _load_cached_data(self):
        """Загрузка кэшированных данных."""
        try:
            # Загрузка корреляций
            if self.correlation_file.exists():
                with open(self.correlation_file, 'r', encoding='utf-8') as f:
                    correlations_data = json.load(f)
                
                for key, data in correlations_data.items():
                    correlation = HistoricalCorrelation(
                        domain=data["domain"],
                        blocking_pattern=data["blocking_pattern"],
                        successful_strategies=data["successful_strategies"],
                        success_rate=data["success_rate"],
                        sample_count=data["sample_count"],
                        last_updated=datetime.fromisoformat(data["last_updated"])
                    )
                    self.historical_correlations[key] = correlation
                
                LOG.info(f"Загружено {len(self.historical_correlations)} корреляций")
            
        except Exception as e:
            LOG.error(f"Ошибка загрузки кэшированных данных: {e}")
    
    async def get_integration_stats(self) -> Dict[str, Any]:
        """Получение статистики интеграции."""
        return {
            "cache_entries": len(self.analysis_cache),
            "historical_correlations": len(self.historical_correlations),
            "cache_hit_rate": self._calculate_cache_hit_rate(),
            "most_common_blocking_types": self._get_most_common_blocking_types(),
            "top_successful_strategies": self._get_top_successful_strategies()
        }
    
    def _calculate_cache_hit_rate(self) -> float:
        """Расчет коэффициента попаданий в кэш."""
        if not self.analysis_cache:
            return 0.0
        
        total_usage = sum(entry.usage_count for entry in self.analysis_cache.values())
        cache_entries = len(self.analysis_cache)
        
        return total_usage / max(cache_entries, 1)
    
    def _get_most_common_blocking_types(self) -> List[Tuple[str, int]]:
        """Получение наиболее частых типов блокировок."""
        blocking_counts = {}
        
        for correlation in self.historical_correlations.values():
            pattern = correlation.blocking_pattern
            blocking_counts[pattern] = blocking_counts.get(pattern, 0) + correlation.sample_count
        
        return sorted(blocking_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    def _get_top_successful_strategies(self) -> List[Tuple[str, float]]:
        """Получение наиболее успешных стратегий."""
        strategy_success = {}
        
        for correlation in self.historical_correlations.values():
            for strategy in correlation.successful_strategies:
                if strategy not in strategy_success:
                    strategy_success[strategy] = []
                strategy_success[strategy].append(correlation.success_rate)
        
        # Расчет средней успешности
        strategy_avg_success = {}
        for strategy, success_rates in strategy_success.items():
            strategy_avg_success[strategy] = sum(success_rates) / len(success_rates)
        
        return sorted(strategy_avg_success.items(), key=lambda x: x[1], reverse=True)[:5]


# Удобные функции для использования
async def create_pcap_integration(config: Optional[Dict[str, Any]] = None) -> AdaptiveEnginePCAPIntegration:
    """Создание интеграции PCAP анализа."""
    integration = AdaptiveEnginePCAPIntegration(config)
    await integration._load_cached_data()
    return integration


async def integrate_pcap_with_adaptive_engine(adaptive_engine, config: Optional[Dict[str, Any]] = None) -> bool:
    """Интеграция PCAP анализа с AdaptiveEngine."""
    integration = await create_pcap_integration(config)
    return await integration.integrate_with_adaptive_engine(adaptive_engine)


if __name__ == "__main__":
    # Пример использования
    async def main():
        # Настройка логирования
        logging.basicConfig(level=logging.INFO)
        
        # Создание интеграции
        config = {
            "enable_auto_pcap_analysis": True,
            "pcap_cache_ttl_hours": 24,
            "max_cache_entries": 50,
            "correlation_threshold": 0.7
        }
        
        integration = await create_pcap_integration(config)
        
        # Пример анализа неудачи
        if os.path.exists("test.pcap"):
            pcap_analysis, strategy_generation = await integration.analyze_failure_with_pcap(
                "x.com", "test.pcap"
            )
            
            print(f"PCAP анализ: {pcap_analysis.primary_blocking_type.value}")
            print(f"Сгенерировано стратегий: {strategy_generation.total_strategies}")
            
            # Статистика интеграции
            stats = await integration.get_integration_stats()
            print(f"Статистика интеграции: {stats}")
        else:
            print("PCAP файл test.pcap не найден")
    
    # Запуск примера
    asyncio.run(main())