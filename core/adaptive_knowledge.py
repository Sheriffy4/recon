"""
AdaptiveKnowledgeBase - Автоматическая база найденных стратегий обхода DPI.

Этот модуль предоставляет:
- StrategyRecord: Запись о стратегии с метриками успеха/неудачи
- AdaptiveKnowledgeBase: Хранилище автоматически найденных стратегий

Основные функции:
- Сохранение успешных стратегий в adaptive_knowledge.json
- Приоритизация стратегий по метрикам
- Wildcard matching для CDN доменов
- Разделение ручной (domain_rules.json) и автоматической баз
"""

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading
import shutil

from core.connection_metrics import BlockType

LOG = logging.getLogger("AdaptiveKnowledgeBase")


@dataclass
class StrategyRecord:
    """
    Запись о стратегии обхода DPI с метриками успеха/неудачи.
    
    Attributes:
        strategy_name: Название стратегии (например, "fake_multisplit")
        strategy_params: Параметры стратегии (split_pos, split_count, fake_ttl и т.д.)
        success_count: Количество успешных применений
        failure_count: Количество неудачных применений
        last_success_ts: Timestamp последнего успеха
        last_failure_ts: Timestamp последней неудачи
        avg_connect_ms: Среднее время установки соединения в миллисекундах
        effective_against: Список типов блокировок, против которых эффективна стратегия
        verified: Флаг верификации через PCAP анализ
        verification_ts: Timestamp последней верификации
    """
    strategy_name: str
    strategy_params: Dict[str, Any]
    success_count: int = 0
    failure_count: int = 0
    last_success_ts: Optional[float] = None
    last_failure_ts: Optional[float] = None
    avg_connect_ms: Optional[float] = None
    effective_against: List[str] = field(default_factory=list)
    verified: bool = False
    verification_ts: Optional[float] = None
    
    def success_rate(self) -> float:
        """
        Рассчитать процент успехов стратегии.
        
        Returns:
            float: Процент успехов от 0.0 до 1.0
        """
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализовать запись в словарь для JSON.
        
        Returns:
            Dict: Словарь с данными записи
        """
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StrategyRecord":
        """
        Десериализовать запись из словаря.
        
        Args:
            data: Словарь с данными записи
        
        Returns:
            StrategyRecord: Восстановленная запись
        """
        # Ensure effective_against is a list
        if "effective_against" in data and not isinstance(data["effective_against"], list):
            data["effective_against"] = []
        return cls(**data)


class AdaptiveKnowledgeBase:
    """
    Хранилище автоматически найденных стратегий обхода DPI.
    
    Основные функции:
    - Сохранение успешных стратегий в adaptive_knowledge.json
    - НЕ изменяет domain_rules.json (ручная база)
    - Приоритизация стратегий по метрикам
    - Wildcard matching для CDN доменов (*.googlevideo.com)
    - Устойчивое хранение с блокировками и backup
    
    Usage:
        kb = AdaptiveKnowledgeBase()
        kb.record_success(domain, strategy_name, params, metrics)
        strategies = kb.get_strategies_for_domain(domain, block_type)
    """
    
    DEFAULT_PATH = Path("data/adaptive_knowledge.json")
    
    def __init__(self, knowledge_file: Optional[Path] = None):
        """
        Инициализация AdaptiveKnowledgeBase.
        
        Args:
            knowledge_file: Путь к файлу базы знаний (по умолчанию data/adaptive_knowledge.json)
        """
        self.knowledge_file = knowledge_file or self.DEFAULT_PATH
        self._lock = threading.RLock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()
    
    def _load(self) -> None:
        """
        Загрузить базу знаний из файла.
        
        При ошибке JSON (порча файла):
        - Логировать ошибку
        - Создать backup
        - Инициализировать пустую БД
        """
        if not self.knowledge_file.exists():
            LOG.info(f"Knowledge base file not found, creating new: {self.knowledge_file}")
            self._data = {}
            return
        
        try:
            with open(self.knowledge_file, 'r', encoding='utf-8') as f:
                self._data = json.load(f)
            LOG.info(f"Loaded adaptive knowledge base with {len(self._data)} domains")
        except json.JSONDecodeError as e:
            LOG.error(f"Corrupted knowledge base file: {e}")
            # Create backup
            backup_path = self.knowledge_file.with_suffix('.json.backup')
            try:
                shutil.copy2(self.knowledge_file, backup_path)
                LOG.info(f"Created backup at {backup_path}")
            except Exception as backup_error:
                LOG.error(f"Failed to create backup: {backup_error}")
            # Initialize empty database
            self._data = {}
            LOG.info("Initialized empty knowledge base")
        except Exception as e:
            LOG.error(f"Failed to load knowledge base: {e}")
            self._data = {}
    
    def _save(self) -> None:
        """
        Сохранить базу знаний в файл с блокировкой.
        
        Использует файловую блокировку для предотвращения гонок при записи.
        """
        # Ensure directory exists
        self.knowledge_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Use lock file for concurrent access protection
        lock_file = self.knowledge_file.with_suffix('.lock')
        
        try:
            # Simple file-based locking
            with self._lock:
                # Write to temporary file first
                temp_file = self.knowledge_file.with_suffix('.tmp')
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(self._data, f, indent=2, ensure_ascii=False)
                
                # Atomic rename
                temp_file.replace(self.knowledge_file)
                
            LOG.debug(f"Saved adaptive knowledge base with {len(self._data)} domains")
        except Exception as e:
            LOG.error(f"Failed to save knowledge base: {e}")
    
    def record_success(
        self,
        domain: str,
        strategy_name: str,
        strategy_params: Dict[str, Any],
        metrics: Any  # ConnectionMetrics
    ) -> None:
        """
        Записать успешную стратегию.
        
        Args:
            domain: Доменное имя
            strategy_name: Название стратегии
            strategy_params: Параметры стратегии
            metrics: ConnectionMetrics с результатами теста
        """
        with self._lock:
            # Initialize domain entry if not exists
            if domain not in self._data:
                self._data[domain] = {
                    "strategies": [],
                    "preferred_strategy": None,
                    "block_type": None
                }
            
            domain_data = self._data[domain]
            
            # Find existing strategy record or create new
            strategy_record = None
            for record_dict in domain_data["strategies"]:
                record = StrategyRecord.from_dict(record_dict)
                if (record.strategy_name == strategy_name and 
                    record.strategy_params == strategy_params):
                    strategy_record = record
                    break
            
            if strategy_record is None:
                # Create new record
                strategy_record = StrategyRecord(
                    strategy_name=strategy_name,
                    strategy_params=strategy_params
                )
                domain_data["strategies"].append(strategy_record.to_dict())
            
            # Update metrics
            strategy_record.success_count += 1
            strategy_record.last_success_ts = time.time()
            
            # Update average connect time
            if hasattr(metrics, 'connect_time_ms') and metrics.connect_time_ms > 0:
                if strategy_record.avg_connect_ms is None:
                    strategy_record.avg_connect_ms = metrics.connect_time_ms
                else:
                    # Running average
                    strategy_record.avg_connect_ms = (
                        (strategy_record.avg_connect_ms * (strategy_record.success_count - 1) +
                         metrics.connect_time_ms) / strategy_record.success_count
                    )
            
            # Update effective_against
            if hasattr(metrics, 'block_type') and metrics.block_type:
                block_type_str = metrics.block_type.value if hasattr(metrics.block_type, 'value') else str(metrics.block_type)
                if block_type_str not in strategy_record.effective_against:
                    strategy_record.effective_against.append(block_type_str)
            
            # Update the record in the list
            for i, record_dict in enumerate(domain_data["strategies"]):
                record = StrategyRecord.from_dict(record_dict)
                if (record.strategy_name == strategy_name and 
                    record.strategy_params == strategy_params):
                    domain_data["strategies"][i] = strategy_record.to_dict()
                    break
            
            # Update preferred strategy if this one has better success rate
            if domain_data["preferred_strategy"] is None:
                domain_data["preferred_strategy"] = strategy_name
            else:
                # Check if current strategy is better
                current_preferred = None
                for record_dict in domain_data["strategies"]:
                    record = StrategyRecord.from_dict(record_dict)
                    if record.strategy_name == domain_data["preferred_strategy"]:
                        current_preferred = record
                        break
                
                if current_preferred and strategy_record.success_rate() > current_preferred.success_rate():
                    domain_data["preferred_strategy"] = strategy_name
            
            # Update block type
            if hasattr(metrics, 'block_type') and metrics.block_type:
                block_type_str = metrics.block_type.value if hasattr(metrics.block_type, 'value') else str(metrics.block_type)
                domain_data["block_type"] = block_type_str
            
            self._save()
            
            LOG.info(f"Recorded success for {domain}: {strategy_name} "
                    f"(success_rate: {strategy_record.success_rate():.2%})")
    
    def record_failure(
        self,
        domain: str,
        strategy_name: str,
        strategy_params: Dict[str, Any],
        metrics: Any  # ConnectionMetrics
    ) -> None:
        """
        Записать неудачную попытку.
        
        Args:
            domain: Доменное имя
            strategy_name: Название стратегии
            strategy_params: Параметры стратегии
            metrics: ConnectionMetrics с результатами теста
        """
        with self._lock:
            # Initialize domain entry if not exists
            if domain not in self._data:
                self._data[domain] = {
                    "strategies": [],
                    "preferred_strategy": None,
                    "block_type": None
                }
            
            domain_data = self._data[domain]
            
            # Find existing strategy record or create new
            strategy_record = None
            for record_dict in domain_data["strategies"]:
                record = StrategyRecord.from_dict(record_dict)
                if (record.strategy_name == strategy_name and 
                    record.strategy_params == strategy_params):
                    strategy_record = record
                    break
            
            if strategy_record is None:
                # Create new record
                strategy_record = StrategyRecord(
                    strategy_name=strategy_name,
                    strategy_params=strategy_params
                )
                domain_data["strategies"].append(strategy_record.to_dict())
            
            # Update metrics
            strategy_record.failure_count += 1
            strategy_record.last_failure_ts = time.time()
            
            # Update the record in the list
            for i, record_dict in enumerate(domain_data["strategies"]):
                record = StrategyRecord.from_dict(record_dict)
                if (record.strategy_name == strategy_name and 
                    record.strategy_params == strategy_params):
                    domain_data["strategies"][i] = strategy_record.to_dict()
                    break
            
            # Recalculate preferred strategy if current one drops below 50%
            if domain_data["preferred_strategy"] == strategy_name:
                if strategy_record.success_rate() < 0.5:
                    # Find best alternative
                    best_record = None
                    best_rate = 0.0
                    for record_dict in domain_data["strategies"]:
                        record = StrategyRecord.from_dict(record_dict)
                        if record.success_rate() > best_rate:
                            best_rate = record.success_rate()
                            best_record = record
                    
                    if best_record:
                        domain_data["preferred_strategy"] = best_record.strategy_name
                        LOG.info(f"Updated preferred strategy for {domain}: {best_record.strategy_name} "
                                f"(success_rate: {best_rate:.2%})")
            
            self._save()
            
            LOG.debug(f"Recorded failure for {domain}: {strategy_name} "
                     f"(success_rate: {strategy_record.success_rate():.2%})")
    
    def get_strategies_for_domain(
        self,
        domain: str,
        block_type: Optional[BlockType] = None
    ) -> List[StrategyRecord]:
        """
        Получить стратегии для домена, отсортированные по приоритету.
        
        Приоритизация:
        1. preferred_strategy (если есть)
        2. effective_against текущий block_type
        3. success_rate (по убыванию)
        4. avg_connect_ms (по возрастанию)
        
        Args:
            domain: Доменное имя
            block_type: Тип блокировки для фильтрации (опционально)
        
        Returns:
            List[StrategyRecord]: Отсортированный список стратегий
        """
        with self._lock:
            # Try exact match first
            domain_data = self._data.get(domain)
            
            # If no exact match, try wildcard matching
            if domain_data is None:
                domain_data = self._match_wildcard_domain(domain)
            
            if domain_data is None:
                return []
            
            # Convert to StrategyRecord objects
            records = [StrategyRecord.from_dict(r) for r in domain_data["strategies"]]
            
            # Recalculate preferred_strategy to ensure it's the one with best success_rate
            if records:
                best_record = max(records, key=lambda r: (r.success_rate(), -r.avg_connect_ms if r.avg_connect_ms else 0))
                preferred = best_record.strategy_name
            else:
                preferred = domain_data.get("preferred_strategy")
            
            # Filter by block_type if specified
            if block_type is not None:
                block_type_str = block_type.value if hasattr(block_type, 'value') else str(block_type)
                records = [r for r in records if block_type_str in r.effective_against]
            
            # Use get_prioritized_strategies for sorting
            return self.get_prioritized_strategies(records, preferred, block_type)
    
    def get_prioritized_strategies(
        self,
        strategies: List[StrategyRecord],
        preferred_strategy: Optional[str] = None,
        block_type: Optional[BlockType] = None
    ) -> List[StrategyRecord]:
        """
        Сортировать стратегии по приоритету.
        
        Приоритизация согласно Requirements 5.3:
        1. preferred_strategy (если указан)
        2. effective_against текущий block_type (если указан)
        3. success_rate (по убыванию)
        4. avg_connect_ms (по возрастанию)
        
        Args:
            strategies: Список стратегий для сортировки
            preferred_strategy: Название предпочтительной стратегии (опционально)
            block_type: Тип блокировки для приоритизации (опционально)
        
        Returns:
            List[StrategyRecord]: Отсортированный список стратегий
        """
        if not strategies:
            return []
        
        block_type_str = None
        if block_type is not None:
            block_type_str = block_type.value if hasattr(block_type, 'value') else str(block_type)
        
        def sort_key(record: StrategyRecord) -> tuple:
            # Priority 1: preferred_strategy comes first
            is_preferred = 1 if preferred_strategy and record.strategy_name == preferred_strategy else 0
            
            # Priority 2: effective_against current block_type
            is_effective = 1 if block_type_str and block_type_str in record.effective_against else 0
            
            # Priority 3: success_rate (higher is better)
            success_rate = record.success_rate()
            
            # Priority 4: avg_connect_ms (lower is better)
            avg_time = record.avg_connect_ms if record.avg_connect_ms is not None else float('inf')
            
            # Return tuple for sorting (negative for descending order)
            return (-is_preferred, -is_effective, -success_rate, avg_time)
        
        sorted_strategies = sorted(strategies, key=sort_key)
        return sorted_strategies
    
    def get_fallback_strategies(
        self,
        domain: str,
        failed_strategy: str
    ) -> List[StrategyRecord]:
        """
        Получить альтернативные стратегии после неудачи.
        
        Args:
            domain: Доменное имя
            failed_strategy: Название неудачной стратегии
        
        Returns:
            List[StrategyRecord]: Список альтернативных стратегий
        """
        all_strategies = self.get_strategies_for_domain(domain)
        
        # Exclude failed strategy
        fallback = [s for s in all_strategies if s.strategy_name != failed_strategy]
        
        return fallback
    
    def _match_wildcard_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Сопоставить домен с wildcard паттернами.
        
        Поддерживает паттерны вида *.googlevideo.com для CDN доменов.
        Использует логику из StrategyLoader для совместимости.
        
        Args:
            domain: Доменное имя для сопоставления
        
        Returns:
            Optional[Dict]: Данные домена или None
        """
        # Check all wildcard patterns in knowledge base
        for pattern in self._data.keys():
            if pattern.startswith('*.'):
                # Extract the suffix (e.g., ".googlevideo.com" from "*.googlevideo.com")
                suffix = pattern[1:]  # Remove the '*'
                
                # Check if domain ends with this suffix
                if domain.endswith(suffix):
                    # Ensure it's a proper subdomain match (not partial match)
                    # e.g., "*.googlevideo.com" should match "rr3---sn-4pvgq-n8v6.googlevideo.com"
                    # but not "fakegooglevideo.com"
                    if len(domain) > len(suffix):  # Must have at least one character before suffix
                        LOG.debug(f"Matched {domain} with wildcard pattern {pattern}")
                        return self._data[pattern]
        
        # Fallback: Try parent domain matching
        # Example: rr1---sn-xxx.googlevideo.com -> googlevideo.com
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self._data:
                LOG.debug(f"Matched {domain} with parent domain {parent_domain}")
                return self._data[parent_domain]
        
        return None
    
    def set_verified(
        self,
        domain: str,
        strategy_name: str,
        strategy_params: Dict[str, Any],
        verified: bool = True
    ) -> None:
        """
        Установить флаг верификации для стратегии.
        
        Args:
            domain: Доменное имя
            strategy_name: Название стратегии
            strategy_params: Параметры стратегии
            verified: Флаг верификации (по умолчанию True)
        """
        with self._lock:
            if domain not in self._data:
                LOG.warning(f"Domain {domain} not found in knowledge base")
                return
            
            domain_data = self._data[domain]
            
            # Find and update strategy record
            for i, record_dict in enumerate(domain_data["strategies"]):
                record = StrategyRecord.from_dict(record_dict)
                if (record.strategy_name == strategy_name and 
                    record.strategy_params == strategy_params):
                    record.verified = verified
                    record.verification_ts = time.time() if verified else None
                    domain_data["strategies"][i] = record.to_dict()
                    self._save()
                    LOG.info(f"Set verified={verified} for {domain}: {strategy_name}")
                    return
            
            LOG.warning(f"Strategy {strategy_name} not found for domain {domain}")
    
    def get_all_domains(self) -> List[str]:
        """
        Получить список всех доменов в базе знаний.
        
        Returns:
            List[str]: Список доменных имен
        """
        with self._lock:
            return list(self._data.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Получить статистику по базе знаний.
        
        Returns:
            Dict: Статистика (количество доменов, стратегий, успехов и т.д.)
        """
        with self._lock:
            total_domains = len(self._data)
            total_strategies = sum(len(d["strategies"]) for d in self._data.values())
            total_successes = sum(
                sum(StrategyRecord.from_dict(s).success_count 
                    for s in d["strategies"])
                for d in self._data.values()
            )
            total_failures = sum(
                sum(StrategyRecord.from_dict(s).failure_count 
                    for s in d["strategies"])
                for d in self._data.values()
            )
            verified_strategies = sum(
                sum(1 for s in d["strategies"] 
                    if StrategyRecord.from_dict(s).verified)
                for d in self._data.values()
            )
            
            return {
                "total_domains": total_domains,
                "total_strategies": total_strategies,
                "total_successes": total_successes,
                "total_failures": total_failures,
                "verified_strategies": verified_strategies,
                "overall_success_rate": (
                    total_successes / (total_successes + total_failures)
                    if (total_successes + total_failures) > 0 else 0.0
                )
            }
