# core/adaptive_state_manager.py
"""
Adaptive State Manager - система сохранения и загрузки состояния AdaptiveEngine
Реализует требования FR-6, FR-7 для Task 1.2

Функции:
- Сохранение найденных стратегий в best_strategies.json
- Загрузка предыдущих результатов для ускорения повторных запусков
- Экспорт результатов в формате, совместимом с recon_service.py
- Система версионирования сохраненных данных
"""

import json
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import logging

LOG = logging.getLogger("AdaptiveStateManager")


class DataVersion(Enum):
    """Версии формата данных"""
    V1_0 = "1.0"
    V1_1 = "1.1"
    CURRENT = "1.1"


@dataclass
class StrategyRecord:
    """Запись о найденной стратегии"""
    domain: str
    strategy_name: str
    attack_type: str
    parameters: Dict[str, Any]
    success_rate: float
    test_count: int
    found_at: str
    last_tested: str
    engine_version: str
    confidence: float = 1.0
    execution_time_seconds: float = 0.0
    trials_count: int = 1
    fingerprint_hash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для сериализации"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StrategyRecord":
        """Создание из словаря"""
        return cls(**data)
    
    def is_expired(self, max_age_days: int = 30) -> bool:
        """Проверка устарела ли запись"""
        try:
            last_tested = datetime.fromisoformat(self.last_tested)
            return (datetime.now() - last_tested).days > max_age_days
        except:
            return True
    
    def get_age_days(self) -> int:
        """Возраст записи в днях"""
        try:
            last_tested = datetime.fromisoformat(self.last_tested)
            return (datetime.now() - last_tested).days
        except:
            return 999


@dataclass
class DomainState:
    """Состояние домена"""
    domain: str
    strategies: List[StrategyRecord] = field(default_factory=list)
    negative_knowledge: List[str] = field(default_factory=list)  # Неработающие стратегии
    dpi_fingerprint_hash: Optional[str] = None
    last_analysis: Optional[str] = None
    total_attempts: int = 0
    successful_attempts: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "domain": self.domain,
            "strategies": [s.to_dict() for s in self.strategies],
            "negative_knowledge": self.negative_knowledge,
            "dpi_fingerprint_hash": self.dpi_fingerprint_hash,
            "last_analysis": self.last_analysis,
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainState":
        """Создание из словаря"""
        strategies = [StrategyRecord.from_dict(s) for s in data.get("strategies", [])]
        return cls(
            domain=data["domain"],
            strategies=strategies,
            negative_knowledge=data.get("negative_knowledge", []),
            dpi_fingerprint_hash=data.get("dpi_fingerprint_hash"),
            last_analysis=data.get("last_analysis"),
            total_attempts=data.get("total_attempts", 0),
            successful_attempts=data.get("successful_attempts", 0)
        )
    
    def get_best_strategy(self) -> Optional[StrategyRecord]:
        """Получение лучшей стратегии"""
        if not self.strategies:
            return None
        
        # Сортируем по success_rate, затем по confidence, затем по свежести
        valid_strategies = [s for s in self.strategies if not s.is_expired()]
        if not valid_strategies:
            # Если нет свежих стратегий, возвращаем лучшую из всех
            if self.strategies:
                return max(self.strategies, key=lambda s: (s.success_rate, s.confidence))
            return None
        
        return max(valid_strategies, key=lambda s: (s.success_rate, s.confidence, -s.get_age_days()))
    
    def add_strategy(self, strategy: StrategyRecord):
        """Добавление стратегии"""
        # Удаляем дубликаты
        self.strategies = [s for s in self.strategies if s.strategy_name != strategy.strategy_name]
        self.strategies.append(strategy)
        
        # Ограничиваем количество стратегий
        self.strategies = sorted(self.strategies, key=lambda s: s.success_rate, reverse=True)[:10]
    
    def add_negative_knowledge(self, strategy_name: str):
        """Добавление негативного знания"""
        if strategy_name not in self.negative_knowledge:
            self.negative_knowledge.append(strategy_name)
        
        # Ограничиваем размер
        self.negative_knowledge = self.negative_knowledge[-50:]


@dataclass
class StateMetadata:
    """Метаданные состояния"""
    version: str
    created_at: str
    last_updated: str
    total_domains: int
    total_strategies: int
    engine_version: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StateMetadata":
        return cls(**data)


class AdaptiveStateManager:
    """
    Менеджер состояния адаптивной системы.
    
    Обеспечивает:
    - Сохранение и загрузку найденных стратегий
    - Версионирование данных
    - Экспорт в различные форматы
    - Управление жизненным циклом данных
    """
    
    def __init__(self, 
                 strategies_file: str = "best_strategies.json",
                 backup_dir: str = "state_backups",
                 max_backups: int = 10):
        """
        Инициализация менеджера состояния.
        
        Args:
            strategies_file: Файл для сохранения стратегий
            backup_dir: Директория для бэкапов
            max_backups: Максимальное количество бэкапов
        """
        self.strategies_file = Path(strategies_file)
        self.backup_dir = Path(backup_dir)
        self.max_backups = max_backups
        
        # Создаем директории
        self.backup_dir.mkdir(exist_ok=True)
        
        # Состояние
        self.domains: Dict[str, DomainState] = {}
        self.metadata: Optional[StateMetadata] = None
        
        # Загружаем существующее состояние
        self.load_state()
    
    def load_state(self) -> bool:
        """
        Загрузка состояния из файла.
        
        Returns:
            True если загрузка успешна
        """
        if not self.strategies_file.exists():
            LOG.info(f"Файл состояния {self.strategies_file} не найден, создаем новое состояние")
            self._initialize_empty_state()
            return True
        
        try:
            with open(self.strategies_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Проверяем версию
            version = data.get("metadata", {}).get("version", "1.0")
            if version != DataVersion.CURRENT.value:
                LOG.warning(f"Версия данных {version} отличается от текущей {DataVersion.CURRENT.value}")
                data = self._migrate_data(data, version)
            
            # Загружаем метаданные
            if "metadata" in data:
                self.metadata = StateMetadata.from_dict(data["metadata"])
            else:
                self._initialize_empty_state()
            
            # Загружаем домены
            self.domains = {}
            for domain_name, domain_data in data.get("domains", {}).items():
                try:
                    domain_state = DomainState.from_dict(domain_data)
                    self.domains[domain_name] = domain_state
                except Exception as e:
                    LOG.error(f"Ошибка загрузки домена {domain_name}: {e}")
            
            LOG.info(f"✅ Загружено состояние: {len(self.domains)} доменов, {self._count_total_strategies()} стратегий")
            return True
            
        except Exception as e:
            LOG.error(f"❌ Ошибка загрузки состояния: {e}")
            self._initialize_empty_state()
            return False
    
    def save_state(self, create_backup: bool = True) -> bool:
        """
        Сохранение состояния в файл.
        
        Args:
            create_backup: Создавать ли бэкап перед сохранением
            
        Returns:
            True если сохранение успешно
        """
        try:
            # Создаем бэкап если нужно
            if create_backup and self.strategies_file.exists():
                self._create_backup()
            
            # Обновляем метаданные
            self._update_metadata()
            
            # Подготавливаем данные для сохранения
            data = {
                "metadata": self.metadata.to_dict(),
                "domains": {name: domain.to_dict() for name, domain in self.domains.items()}
            }
            
            # Сохраняем во временный файл
            temp_file = self.strategies_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Атомарно заменяем основной файл
            temp_file.replace(self.strategies_file)
            
            LOG.info(f"💾 Состояние сохранено: {len(self.domains)} доменов, {self._count_total_strategies()} стратегий")
            return True
            
        except Exception as e:
            LOG.error(f"❌ Ошибка сохранения состояния: {e}")
            return False
    
    def save_strategy(self, 
                     domain: str, 
                     strategy: Any, 
                     execution_time: float = 0.0,
                     trials_count: int = 1,
                     fingerprint_hash: Optional[str] = None) -> bool:
        """
        Сохранение найденной стратегии.
        
        Args:
            domain: Домен
            strategy: Объект стратегии
            execution_time: Время выполнения
            trials_count: Количество попыток
            fingerprint_hash: Хэш DPI fingerprint
            
        Returns:
            True если сохранение успешно
        """
        try:
            # Получаем или создаем состояние домена
            if domain not in self.domains:
                self.domains[domain] = DomainState(domain=domain)
            
            domain_state = self.domains[domain]
            
            # Создаем запись стратегии
            strategy_record = StrategyRecord(
                domain=domain,
                strategy_name=getattr(strategy, 'name', str(strategy)),
                attack_type=getattr(strategy, 'attack_type', 'unknown'),
                parameters=getattr(strategy, 'parameters', {}),
                success_rate=getattr(strategy, 'success_rate', 1.0),
                test_count=getattr(strategy, 'test_count', 1),
                found_at=datetime.now().isoformat(),
                last_tested=datetime.now().isoformat(),
                engine_version="adaptive_v1.1",
                confidence=1.0,
                execution_time_seconds=execution_time,
                trials_count=trials_count,
                fingerprint_hash=fingerprint_hash
            )
            
            # Добавляем стратегию
            domain_state.add_strategy(strategy_record)
            domain_state.successful_attempts += 1
            domain_state.last_analysis = datetime.now().isoformat()
            
            if fingerprint_hash:
                domain_state.dpi_fingerprint_hash = fingerprint_hash
            
            # Сохраняем состояние
            return self.save_state()
            
        except Exception as e:
            LOG.error(f"❌ Ошибка сохранения стратегии для {domain}: {e}")
            return False
    
    def load_strategy(self, domain: str) -> Optional[StrategyRecord]:
        """
        Загрузка лучшей стратегии для домена.
        
        Args:
            domain: Домен
            
        Returns:
            Лучшая стратегия или None
        """
        if domain not in self.domains:
            return None
        
        return self.domains[domain].get_best_strategy()
    
    def has_recent_strategy(self, domain: str, max_age_days: int = 7) -> bool:
        """
        Проверка наличия свежей стратегии.
        
        Args:
            domain: Домен
            max_age_days: Максимальный возраст в днях
            
        Returns:
            True если есть свежая стратегия
        """
        strategy = self.load_strategy(domain)
        if not strategy:
            return False
        
        return not strategy.is_expired(max_age_days)
    
    def add_negative_knowledge(self, domain: str, strategy_name: str):
        """
        Добавление негативного знания (неработающая стратегия).
        
        Args:
            domain: Домен
            strategy_name: Название стратегии
        """
        if domain not in self.domains:
            self.domains[domain] = DomainState(domain=domain)
        
        self.domains[domain].add_negative_knowledge(strategy_name)
        self.domains[domain].total_attempts += 1
    
    def get_negative_knowledge(self, domain: str) -> List[str]:
        """
        Получение негативного знания для домена.
        
        Args:
            domain: Домен
            
        Returns:
            Список неработающих стратегий
        """
        if domain not in self.domains:
            return []
        
        return self.domains[domain].negative_knowledge.copy()
    
    def export_to_recon_service_format(self, output_file: str) -> bool:
        """
        Экспорт в формате, совместимом с recon_service.py.
        
        Args:
            output_file: Файл для экспорта
            
        Returns:
            True если экспорт успешен
        """
        try:
            # Формат для recon_service.py
            recon_data = {}
            
            for domain, domain_state in self.domains.items():
                best_strategy = domain_state.get_best_strategy()
                if best_strategy:
                    recon_data[domain] = {
                        "strategy": best_strategy.strategy_name,
                        "attack_type": best_strategy.attack_type,
                        "parameters": best_strategy.parameters,
                        "success_rate": best_strategy.success_rate,
                        "last_tested": best_strategy.last_tested,
                        "confidence": best_strategy.confidence
                    }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(recon_data, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"📤 Экспорт в формат recon_service: {len(recon_data)} доменов в {output_file}")
            return True
            
        except Exception as e:
            LOG.error(f"❌ Ошибка экспорта в формат recon_service: {e}")
            return False
    
    def export_statistics(self, output_file: str) -> bool:
        """
        Экспорт статистики.
        
        Args:
            output_file: Файл для экспорта
            
        Returns:
            True если экспорт успешен
        """
        try:
            stats = self.get_statistics()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False, default=str)
            
            LOG.info(f"📊 Статистика экспортирована в {output_file}")
            return True
            
        except Exception as e:
            LOG.error(f"❌ Ошибка экспорта статистики: {e}")
            return False
    
    def cleanup_expired_data(self, max_age_days: int = 30) -> int:
        """
        Очистка устаревших данных.
        
        Args:
            max_age_days: Максимальный возраст в днях
            
        Returns:
            Количество удаленных записей
        """
        removed_count = 0
        
        for domain_state in self.domains.values():
            original_count = len(domain_state.strategies)
            domain_state.strategies = [s for s in domain_state.strategies if not s.is_expired(max_age_days)]
            removed_count += original_count - len(domain_state.strategies)
        
        # Удаляем домены без стратегий
        empty_domains = [domain for domain, state in self.domains.items() if not state.strategies]
        for domain in empty_domains:
            del self.domains[domain]
            removed_count += 1
        
        if removed_count > 0:
            self.save_state()
            LOG.info(f"🧹 Очищено {removed_count} устаревших записей")
        
        return removed_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики состояния"""
        total_strategies = self._count_total_strategies()
        total_attempts = sum(d.total_attempts for d in self.domains.values())
        successful_attempts = sum(d.successful_attempts for d in self.domains.values())
        
        # Статистика по возрасту стратегий
        all_strategies = []
        for domain_state in self.domains.values():
            all_strategies.extend(domain_state.strategies)
        
        fresh_strategies = len([s for s in all_strategies if not s.is_expired(7)])
        old_strategies = len([s for s in all_strategies if s.is_expired(30)])
        
        return {
            "metadata": self.metadata.to_dict() if self.metadata else {},
            "domains_count": len(self.domains),
            "total_strategies": total_strategies,
            "total_attempts": total_attempts,
            "successful_attempts": successful_attempts,
            "success_rate": successful_attempts / max(total_attempts, 1),
            "fresh_strategies_7d": fresh_strategies,
            "old_strategies_30d": old_strategies,
            "average_strategies_per_domain": total_strategies / max(len(self.domains), 1),
            "domains_with_strategies": len([d for d in self.domains.values() if d.strategies]),
            "file_size_bytes": self.strategies_file.stat().st_size if self.strategies_file.exists() else 0,
            "last_backup": self._get_last_backup_time()
        }
    
    def _initialize_empty_state(self):
        """Инициализация пустого состояния"""
        self.metadata = StateMetadata(
            version=DataVersion.CURRENT.value,
            created_at=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat(),
            total_domains=0,
            total_strategies=0,
            engine_version="adaptive_v1.1"
        )
        self.domains = {}
    
    def _update_metadata(self):
        """Обновление метаданных"""
        if self.metadata:
            self.metadata.last_updated = datetime.now().isoformat()
            self.metadata.total_domains = len(self.domains)
            self.metadata.total_strategies = self._count_total_strategies()
    
    def _count_total_strategies(self) -> int:
        """Подсчет общего количества стратегий"""
        return sum(len(domain.strategies) for domain in self.domains.values())
    
    def _create_backup(self):
        """Создание бэкапа текущего состояния"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"strategies_backup_{timestamp}.json"
            
            shutil.copy2(self.strategies_file, backup_file)
            
            # Удаляем старые бэкапы
            self._cleanup_old_backups()
            
            LOG.debug(f"📦 Создан бэкап: {backup_file}")
            
        except Exception as e:
            LOG.error(f"❌ Ошибка создания бэкапа: {e}")
    
    def _cleanup_old_backups(self):
        """Очистка старых бэкапов"""
        try:
            backup_files = list(self.backup_dir.glob("strategies_backup_*.json"))
            backup_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
            
            # Удаляем лишние бэкапы
            for backup_file in backup_files[self.max_backups:]:
                backup_file.unlink()
                LOG.debug(f"🗑️ Удален старый бэкап: {backup_file}")
                
        except Exception as e:
            LOG.error(f"❌ Ошибка очистки бэкапов: {e}")
    
    def _get_last_backup_time(self) -> Optional[str]:
        """Получение времени последнего бэкапа"""
        try:
            backup_files = list(self.backup_dir.glob("strategies_backup_*.json"))
            if not backup_files:
                return None
            
            latest_backup = max(backup_files, key=lambda f: f.stat().st_mtime)
            return datetime.fromtimestamp(latest_backup.stat().st_mtime).isoformat()
            
        except Exception:
            return None
    
    def _migrate_data(self, data: Dict[str, Any], from_version: str) -> Dict[str, Any]:
        """
        Миграция данных между версиями.
        
        Args:
            data: Исходные данные
            from_version: Версия исходных данных
            
        Returns:
            Мигрированные данные
        """
        LOG.info(f"🔄 Миграция данных с версии {from_version} на {DataVersion.CURRENT.value}")
        
        if from_version == "1.0":
            # Миграция с версии 1.0 на 1.1
            migrated_data = {
                "metadata": {
                    "version": DataVersion.CURRENT.value,
                    "created_at": datetime.now().isoformat(),
                    "last_updated": datetime.now().isoformat(),
                    "total_domains": 0,
                    "total_strategies": 0,
                    "engine_version": "adaptive_v1.1"
                },
                "domains": {}
            }
            
            # Конвертируем старый формат
            for domain, strategy_data in data.items():
                if domain == "metadata":
                    continue
                
                # Обрабатываем как старый формат (прямое сохранение стратегии)
                if isinstance(strategy_data, dict) and "name" in strategy_data:
                    current_time = datetime.now().isoformat()
                    LOG.info(f"Мигрируем стратегию {strategy_data.get('name')} для {domain}, устанавливаем last_tested: {current_time}")
                    domain_state = {
                        "domain": domain,
                        "strategies": [{
                            "domain": domain,
                            "strategy_name": strategy_data.get("name", "unknown"),
                            "attack_type": strategy_data.get("attack_type", "unknown"),
                            "parameters": strategy_data.get("parameters", {}),
                            "success_rate": strategy_data.get("success_rate", 1.0),
                            "test_count": 1,
                            "found_at": strategy_data.get("found_at", datetime.now().isoformat()),
                            "last_tested": current_time,  # Обновляем на текущее время
                            "engine_version": strategy_data.get("engine_version", "adaptive_v1.0"),
                            "confidence": 1.0,
                            "execution_time_seconds": 0.0,
                            "trials_count": 1,
                            "fingerprint_hash": None
                        }],
                        "negative_knowledge": [],
                        "dpi_fingerprint_hash": None,
                        "last_analysis": strategy_data.get("found_at", datetime.now().isoformat()),
                        "total_attempts": 1,
                        "successful_attempts": 1
                    }
                    
                    migrated_data["domains"][domain] = domain_state
            
            return migrated_data
        
        # Для других версий возвращаем как есть
        return data


# Удобные функции для использования
def create_state_manager(strategies_file: str = "best_strategies.json") -> AdaptiveStateManager:
    """
    Фабричная функция для создания менеджера состояния.
    
    Args:
        strategies_file: Файл для сохранения стратегий
        
    Returns:
        Инициализированный AdaptiveStateManager
    """
    return AdaptiveStateManager(strategies_file)


def save_strategy_result(domain: str, 
                        strategy: Any,
                        execution_time: float = 0.0,
                        trials_count: int = 1,
                        state_manager: Optional[AdaptiveStateManager] = None) -> bool:
    """
    Удобная функция для сохранения результата стратегии.
    
    Args:
        domain: Домен
        strategy: Стратегия
        execution_time: Время выполнения
        trials_count: Количество попыток
        state_manager: Менеджер состояния (создается если None)
        
    Returns:
        True если сохранение успешно
    """
    if state_manager is None:
        state_manager = AdaptiveStateManager()
    
    return state_manager.save_strategy(domain, strategy, execution_time, trials_count)


def load_best_strategy(domain: str, 
                      state_manager: Optional[AdaptiveStateManager] = None) -> Optional[StrategyRecord]:
    """
    Удобная функция для загрузки лучшей стратегии.
    
    Args:
        domain: Домен
        state_manager: Менеджер состояния (создается если None)
        
    Returns:
        Лучшая стратегия или None
    """
    if state_manager is None:
        state_manager = AdaptiveStateManager()
    
    return state_manager.load_strategy(domain)


# Пример использования
if __name__ == "__main__":
    # Создаем менеджер состояния
    state_manager = AdaptiveStateManager()
    
    # Пример сохранения стратегии
    from dataclasses import dataclass
    
    @dataclass
    class ExampleStrategy:
        name: str
        attack_type: str
        parameters: dict
        success_rate: float = 1.0
    
    strategy = ExampleStrategy(
        name="fake_sni_test",
        attack_type="fake",
        parameters={"split_pos": "sni", "ttl": 1},
        success_rate=0.95
    )
    
    # Сохраняем стратегию
    success = state_manager.save_strategy("example.com", strategy, execution_time=2.5, trials_count=3)
    print(f"Сохранение стратегии: {'✅' if success else '❌'}")
    
    # Загружаем стратегию
    loaded_strategy = state_manager.load_strategy("example.com")
    if loaded_strategy:
        print(f"Загружена стратегия: {loaded_strategy.strategy_name}")
        print(f"Параметры: {loaded_strategy.parameters}")
        print(f"Success rate: {loaded_strategy.success_rate}")
    
    # Получаем статистику
    stats = state_manager.get_statistics()
    print(f"\nСтатистика:")
    print(f"- Доменов: {stats['domains_count']}")
    print(f"- Стратегий: {stats['total_strategies']}")
    print(f"- Success rate: {stats['success_rate']:.2%}")
    
    # Экспорт в формат recon_service
    state_manager.export_to_recon_service_format("recon_strategies.json")
    print("📤 Экспорт в формат recon_service завершен")