"""
Closed-Loop Learning Metrics - система метрик для замкнутого цикла обучения.

Этот модуль реализует сбор и экспорт метрик для оценки эффективности
системы замкнутого цикла обучения согласно требованиям FR-10.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from collections import defaultdict, deque
import threading

LOG = logging.getLogger("ClosedLoopMetrics")


@dataclass
class ClosedLoopMetrics:
    """
    Метрики замкнутого цикла обучения.
    
    Содержит все метрики, требуемые в FR-10.1-FR-10.6:
    - closed_loop.iterations_count
    - closed_loop.intents_generated_total  
    - closed_loop.strategies_generated_per_iteration
    - closed_loop.pattern_matches_total
    - closed_loop.knowledge_base_rules_count
    - closed_loop.success_rate_by_pattern
    """
    
    # FR-10.1: Количество итераций замкнутого цикла
    iterations_count: int = 0
    
    # FR-10.2: Общее количество сгенерированных intent'ов
    intents_generated_total: int = 0
    
    # FR-10.3: Стратегии, сгенерированные за итерацию (среднее)
    strategies_generated_per_iteration: float = 0.0
    
    # FR-10.4: Общее количество совпадений паттернов
    pattern_matches_total: int = 0
    
    # FR-10.5: Количество правил в базе знаний
    knowledge_base_rules_count: int = 0
    
    # FR-10.6: Успешность по паттернам (словарь pattern_id -> success_rate)
    success_rate_by_pattern: Dict[str, float] = field(default_factory=dict)
    
    # Дополнительные метрики для анализа
    knowledge_updates_total: int = 0
    strategies_augmented_total: int = 0
    average_iterations_to_success: float = 0.0
    pattern_match_rate: float = 0.0
    
    # Временные метки
    last_updated: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь для экспорта."""
        data = asdict(self)
        data["last_updated"] = self.last_updated.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClosedLoopMetrics':
        """Десериализация из словаря."""
        if "last_updated" in data and isinstance(data["last_updated"], str):
            data["last_updated"] = datetime.fromisoformat(data["last_updated"])
        return cls(**data)


class ClosedLoopMetricsCollector:
    """
    Коллектор метрик замкнутого цикла обучения.
    
    Собирает метрики из AdaptiveEngine и KnowledgeAccumulator,
    вычисляет агрегированные показатели и предоставляет
    интерфейс для интеграции с MonitoringSystem.
    """
    
    def __init__(self, export_file: str = "metrics/closed_loop_metrics.json"):
        """
        Инициализация коллектора метрик.
        
        Args:
            export_file: Путь к файлу для экспорта метрик
        """
        self.export_file = Path(export_file)
        self.export_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.metrics = ClosedLoopMetrics()
        self._lock = threading.RLock()
        
        # История для вычисления средних значений
        self._iteration_history = deque(maxlen=1000)  # Последние 1000 итераций
        self._strategies_per_iteration_history = deque(maxlen=100)  # Последние 100 итераций
        self._success_history = deque(maxlen=1000)  # История успехов для расчета среднего
        
        # Счетчики для паттернов
        self._pattern_usage_count = defaultdict(int)
        self._pattern_success_count = defaultdict(int)
        
        LOG.info(f"ClosedLoopMetricsCollector инициализирован, экспорт в {self.export_file}")
    
    def record_iteration_start(self, domain: str, iteration_number: int):
        """
        Запись начала новой итерации замкнутого цикла.
        
        Args:
            domain: Доменное имя
            iteration_number: Номер итерации для данного домена
        """
        with self._lock:
            self.metrics.iterations_count += 1
            self._iteration_history.append({
                "domain": domain,
                "iteration": iteration_number,
                "timestamp": datetime.now(),
                "strategies_generated": 0,
                "intents_generated": 0,
                "pattern_matched": False,
                "success": False
            })
            
            LOG.debug(f"📊 Итерация {self.metrics.iterations_count}: {domain} (#{iteration_number})")
    
    def record_intents_generated(self, intent_keys: List[str], source: str = "unknown"):
        """
        Запись сгенерированных intent'ов.
        
        Args:
            intent_keys: Список ключей intent'ов
            source: Источник генерации (SFA, KnowledgeBase, etc.)
        """
        with self._lock:
            count = len(intent_keys)
            self.metrics.intents_generated_total += count
            
            # Обновляем текущую итерацию
            if self._iteration_history:
                self._iteration_history[-1]["intents_generated"] += count
            
            LOG.debug(f"📊 Сгенерировано {count} intent'ов из {source}: {intent_keys}")
    
    def record_strategies_generated(self, strategies_count: int):
        """
        Запись количества сгенерированных стратегий.
        
        Args:
            strategies_count: Количество сгенерированных стратегий
        """
        with self._lock:
            self.metrics.strategies_augmented_total += strategies_count
            
            # Обновляем текущую итерацию
            if self._iteration_history:
                self._iteration_history[-1]["strategies_generated"] += strategies_count
            
            # Добавляем в историю для расчета среднего
            self._strategies_per_iteration_history.append(strategies_count)
            
            # Пересчитываем среднее количество стратегий за итерацию
            if self._strategies_per_iteration_history:
                self.metrics.strategies_generated_per_iteration = (
                    sum(self._strategies_per_iteration_history) / 
                    len(self._strategies_per_iteration_history)
                )
            
            LOG.debug(f"📊 Сгенерировано {strategies_count} стратегий, "
                     f"среднее за итерацию: {self.metrics.strategies_generated_per_iteration:.2f}")
    
    def record_pattern_match(self, pattern_id: str, matched: bool = True):
        """
        Запись совпадения паттерна.
        
        Args:
            pattern_id: ID паттерна из базы знаний
            matched: True если паттерн совпал
        """
        with self._lock:
            if matched:
                self.metrics.pattern_matches_total += 1
                self._pattern_usage_count[pattern_id] += 1
                
                # Обновляем текущую итерацию
                if self._iteration_history:
                    self._iteration_history[-1]["pattern_matched"] = True
                
                LOG.debug(f"📊 Паттерн совпал: {pattern_id} (всего совпадений: {self.metrics.pattern_matches_total})")
            
            # Пересчитываем pattern_match_rate
            if self.metrics.iterations_count > 0:
                self.metrics.pattern_match_rate = (
                    self.metrics.pattern_matches_total / self.metrics.iterations_count
                )
    
    def record_pattern_success(self, pattern_id: str, success: bool):
        """
        Запись успеха/неудачи паттерна.
        
        Args:
            pattern_id: ID паттерна
            success: True если паттерн привел к успеху
        """
        with self._lock:
            if success:
                self._pattern_success_count[pattern_id] += 1
            
            # Пересчитываем success_rate для паттерна
            usage_count = self._pattern_usage_count[pattern_id]
            success_count = self._pattern_success_count[pattern_id]
            
            if usage_count > 0:
                self.metrics.success_rate_by_pattern[pattern_id] = success_count / usage_count
            
            LOG.debug(f"📊 Паттерн {pattern_id}: успех={success}, "
                     f"rate={self.metrics.success_rate_by_pattern.get(pattern_id, 0.0):.2f}")
    
    def record_knowledge_base_update(self, rules_count: int):
        """
        Запись обновления базы знаний.
        
        Args:
            rules_count: Текущее количество правил в базе знаний
        """
        with self._lock:
            self.metrics.knowledge_base_rules_count = rules_count
            self.metrics.knowledge_updates_total += 1
            
            LOG.debug(f"📊 База знаний обновлена: {rules_count} правил")
    
    def record_iteration_success(self, domain: str, iterations_to_success: int):
        """
        Запись успешного завершения итераций для домена.
        
        Args:
            domain: Доменное имя
            iterations_to_success: Количество итераций до успеха
        """
        with self._lock:
            # Обновляем текущую итерацию
            if self._iteration_history:
                self._iteration_history[-1]["success"] = True
            
            # Добавляем в историю успехов
            self._success_history.append(iterations_to_success)
            
            # Пересчитываем среднее количество итераций до успеха
            if self._success_history:
                self.metrics.average_iterations_to_success = (
                    sum(self._success_history) / len(self._success_history)
                )
            
            LOG.info(f"📊 Успех для {domain} за {iterations_to_success} итераций, "
                    f"среднее: {self.metrics.average_iterations_to_success:.2f}")
    
    def update_from_adaptive_engine(self, adaptive_engine):
        """
        Обновление метрик из AdaptiveEngine.
        
        Args:
            adaptive_engine: Экземпляр AdaptiveEngine
        """
        try:
            with self._lock:
                # Получаем статистику замкнутого цикла
                if hasattr(adaptive_engine, 'closed_loop_stats'):
                    stats = adaptive_engine.closed_loop_stats
                    
                    self.metrics.iterations_count = stats.get("iterations_total", 0)
                    self.metrics.intents_generated_total = stats.get("intents_generated", 0)
                    self.metrics.pattern_matches_total = stats.get("pattern_matches", 0)
                    self.metrics.strategies_augmented_total = stats.get("strategies_augmented", 0)
                    self.metrics.knowledge_updates_total = stats.get("knowledge_updates", 0)
                
                # Получаем статистику базы знаний
                if hasattr(adaptive_engine, 'knowledge_accumulator') and adaptive_engine.knowledge_accumulator:
                    kb_stats = adaptive_engine.knowledge_accumulator.get_statistics()
                    self.metrics.knowledge_base_rules_count = kb_stats.get("total_patterns", 0)
                
                self.metrics.last_updated = datetime.now()
                
                LOG.debug("📊 Метрики обновлены из AdaptiveEngine")
                
        except Exception as e:
            LOG.error(f"Ошибка обновления метрик из AdaptiveEngine: {e}")
    
    def update_from_knowledge_accumulator(self, knowledge_accumulator):
        """
        Обновление метрик из KnowledgeAccumulator.
        
        Args:
            knowledge_accumulator: Экземпляр KnowledgeAccumulator
        """
        try:
            with self._lock:
                # Получаем общую статистику
                stats = knowledge_accumulator.get_statistics()
                self.metrics.knowledge_base_rules_count = stats.get("total_patterns", 0)
                
                # Обновляем success_rate_by_pattern из метаданных правил
                for pattern in knowledge_accumulator.get_all_patterns():
                    success_count = pattern.metadata.get("success_count", 0)
                    failure_count = pattern.metadata.get("failure_count", 0)
                    total_count = success_count + failure_count
                    
                    if total_count > 0:
                        self.metrics.success_rate_by_pattern[pattern.id] = success_count / total_count
                    else:
                        self.metrics.success_rate_by_pattern[pattern.id] = 0.0
                
                self.metrics.last_updated = datetime.now()
                
                LOG.debug("📊 Метрики обновлены из KnowledgeAccumulator")
                
        except Exception as e:
            LOG.error(f"Ошибка обновления метрик из KnowledgeAccumulator: {e}")
    
    def get_metrics(self) -> ClosedLoopMetrics:
        """
        Получение текущих метрик.
        
        Returns:
            Копия текущих метрик
        """
        with self._lock:
            # Создаем копию для безопасного доступа
            metrics_copy = ClosedLoopMetrics()
            metrics_copy.iterations_count = self.metrics.iterations_count
            metrics_copy.intents_generated_total = self.metrics.intents_generated_total
            metrics_copy.strategies_generated_per_iteration = self.metrics.strategies_generated_per_iteration
            metrics_copy.pattern_matches_total = self.metrics.pattern_matches_total
            metrics_copy.knowledge_base_rules_count = self.metrics.knowledge_base_rules_count
            metrics_copy.success_rate_by_pattern = self.metrics.success_rate_by_pattern.copy()
            metrics_copy.knowledge_updates_total = self.metrics.knowledge_updates_total
            metrics_copy.strategies_augmented_total = self.metrics.strategies_augmented_total
            metrics_copy.average_iterations_to_success = self.metrics.average_iterations_to_success
            metrics_copy.pattern_match_rate = self.metrics.pattern_match_rate
            metrics_copy.last_updated = self.metrics.last_updated
            
            return metrics_copy
    
    def get_metrics_dict(self) -> Dict[str, Any]:
        """
        Получение метрик в виде словаря для экспорта.
        
        Returns:
            Словарь с метриками
        """
        return self.get_metrics().to_dict()
    
    def export_metrics(self, file_path: Optional[str] = None) -> bool:
        """
        Экспорт метрик в JSON файл.
        
        Args:
            file_path: Путь к файлу (по умолчанию self.export_file)
            
        Returns:
            True если экспорт успешен
        """
        try:
            export_path = Path(file_path) if file_path else self.export_file
            export_path.parent.mkdir(parents=True, exist_ok=True)
            
            with self._lock:
                data = {
                    "timestamp": datetime.now().isoformat(),
                    "metrics": self.get_metrics_dict(),
                    "pattern_usage_stats": dict(self._pattern_usage_count),
                    "pattern_success_stats": dict(self._pattern_success_count),
                    "recent_iterations": list(self._iteration_history)[-10:] if self._iteration_history else []
                }
                
                # Конвертируем datetime объекты в строки для JSON
                for iteration in data["recent_iterations"]:
                    if "timestamp" in iteration:
                        iteration["timestamp"] = iteration["timestamp"].isoformat()
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"📊 Метрики экспортированы в {export_path}")
            return True
            
        except Exception as e:
            LOG.error(f"Ошибка экспорта метрик: {e}")
            return False
    
    def get_summary_report(self) -> Dict[str, Any]:
        """
        Получение сводного отчета по метрикам.
        
        Returns:
            Словарь с сводной информацией
        """
        with self._lock:
            metrics = self.get_metrics()
            
            # Топ паттернов по успешности
            top_patterns = sorted(
                metrics.success_rate_by_pattern.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            # Статистика за последние итерации
            recent_iterations = list(self._iteration_history)[-10:] if self._iteration_history else []
            recent_success_rate = 0.0
            if recent_iterations:
                recent_successes = sum(1 for it in recent_iterations if it.get("success", False))
                recent_success_rate = recent_successes / len(recent_iterations)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_iterations": metrics.iterations_count,
                    "total_intents_generated": metrics.intents_generated_total,
                    "avg_strategies_per_iteration": metrics.strategies_generated_per_iteration,
                    "pattern_matches": metrics.pattern_matches_total,
                    "knowledge_base_size": metrics.knowledge_base_rules_count,
                    "avg_iterations_to_success": metrics.average_iterations_to_success,
                    "pattern_match_rate": metrics.pattern_match_rate,
                    "recent_success_rate": recent_success_rate
                },
                "top_patterns": [
                    {"pattern_id": pid, "success_rate": rate}
                    for pid, rate in top_patterns
                ],
                "efficiency_indicators": {
                    "learning_effectiveness": (
                        metrics.knowledge_updates_total / max(1, metrics.iterations_count)
                    ),
                    "strategy_generation_efficiency": (
                        metrics.strategies_augmented_total / max(1, metrics.iterations_count)
                    ),
                    "intent_generation_rate": (
                        metrics.intents_generated_total / max(1, metrics.iterations_count)
                    )
                }
            }
    
    def reset_metrics(self):
        """Сброс всех метрик (для тестирования)."""
        with self._lock:
            self.metrics = ClosedLoopMetrics()
            self._iteration_history.clear()
            self._strategies_per_iteration_history.clear()
            self._success_history.clear()
            self._pattern_usage_count.clear()
            self._pattern_success_count.clear()
            
            LOG.info("📊 Метрики сброшены")


# Глобальный экземпляр коллектора метрик
_global_metrics_collector: Optional[ClosedLoopMetricsCollector] = None
_collector_lock = threading.Lock()


def get_closed_loop_metrics_collector() -> ClosedLoopMetricsCollector:
    """
    Получение глобального экземпляра коллектора метрик.
    
    Returns:
        Экземпляр ClosedLoopMetricsCollector
    """
    global _global_metrics_collector
    
    with _collector_lock:
        if _global_metrics_collector is None:
            _global_metrics_collector = ClosedLoopMetricsCollector()
        
        return _global_metrics_collector


def reset_global_metrics_collector():
    """Сброс глобального коллектора метрик (для тестирования)."""
    global _global_metrics_collector
    
    with _collector_lock:
        if _global_metrics_collector:
            _global_metrics_collector.reset_metrics()
        _global_metrics_collector = None