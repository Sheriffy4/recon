"""
Performance Optimizer - оптимизация производительности анализа PCAP.

Этот модуль предоставляет:
- Кэширование результатов анализа
- Оптимизацию обработки больших файлов
- Параллельную обработку потоков
- Мониторинг производительности

Requirements: Performance, Scalability
"""

import hashlib
import logging
import time
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
import json

LOG = logging.getLogger("PerformanceOptimizer")


@dataclass
class CacheEntry:
    """Запись в кэше."""

    key: str
    value: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int = 0
    size_bytes: int = 0
    ttl_seconds: Optional[int] = None

    def is_expired(self) -> bool:
        """Проверка истечения TTL."""
        if self.ttl_seconds is None:
            return False
        age = (datetime.now() - self.created_at).total_seconds()
        return age > self.ttl_seconds

    def touch(self) -> None:
        """Обновление времени доступа."""
        self.accessed_at = datetime.now()
        self.access_count += 1


class ResultCache:
    """
    Кэш результатов анализа PCAP.

    Особенности:
    - LRU eviction policy
    - TTL support
    - Size-based limits
    - Hit/miss statistics
    """

    def __init__(
        self,
        max_entries: int = 100,
        max_size_mb: int = 500,
        default_ttl_seconds: Optional[int] = 3600,
    ):
        """
        Инициализация кэша.

        Args:
            max_entries: Максимальное количество записей
            max_size_mb: Максимальный размер кэша в MB
            default_ttl_seconds: TTL по умолчанию (None = без ограничения)
        """
        self.max_entries = max_entries
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl_seconds = default_ttl_seconds

        self._cache: Dict[str, CacheEntry] = {}
        self._total_size_bytes = 0

        # Статистика
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: str) -> Optional[Any]:
        """
        Получение значения из кэша.

        Args:
            key: Ключ

        Returns:
            Значение или None если не найдено/истекло
        """
        entry = self._cache.get(key)

        if entry is None:
            self._misses += 1
            return None

        if entry.is_expired():
            self._remove(key)
            self._misses += 1
            return None

        entry.touch()
        self._hits += 1
        return entry.value

    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: Optional[int] = None,
        size_bytes: Optional[int] = None,
    ) -> None:
        """
        Сохранение значения в кэш.

        Args:
            key: Ключ
            value: Значение
            ttl_seconds: TTL (None = использовать default)
            size_bytes: Размер в байтах (None = оценить автоматически)
        """
        # Оценка размера если не указан
        if size_bytes is None:
            size_bytes = self._estimate_size(value)

        # Проверка лимита размера
        if size_bytes > self.max_size_bytes:
            LOG.warning(f"Value too large for cache: {size_bytes} bytes")
            return

        # Удаление старой записи если существует
        if key in self._cache:
            self._remove(key)

        # Освобождение места если нужно
        while (
            len(self._cache) >= self.max_entries
            or self._total_size_bytes + size_bytes > self.max_size_bytes
        ):
            self._evict_lru()

        # Создание новой записи
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        entry = CacheEntry(
            key=key,
            value=value,
            created_at=datetime.now(),
            accessed_at=datetime.now(),
            size_bytes=size_bytes,
            ttl_seconds=ttl,
        )

        self._cache[key] = entry
        self._total_size_bytes += size_bytes

    def _remove(self, key: str) -> None:
        """Удаление записи из кэша."""
        entry = self._cache.pop(key, None)
        if entry:
            self._total_size_bytes -= entry.size_bytes

    def _evict_lru(self) -> None:
        """Удаление наименее используемой записи (LRU)."""
        if not self._cache:
            return

        # Поиск LRU записи
        lru_key = min(
            self._cache.keys(),
            key=lambda k: (self._cache[k].accessed_at, self._cache[k].access_count),
        )

        self._remove(lru_key)
        self._evictions += 1

    def _estimate_size(self, value: Any) -> int:
        """Оценка размера значения в байтах."""
        try:
            # Попытка сериализации в JSON для оценки
            json_str = json.dumps(value, default=str)
            return len(json_str.encode("utf-8"))
        except Exception:
            # Грубая оценка
            return 1024  # 1KB по умолчанию

    def clear(self) -> None:
        """Очистка кэша."""
        self._cache.clear()
        self._total_size_bytes = 0

    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики кэша."""
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0.0

        return {
            "entries": len(self._cache),
            "size_mb": self._total_size_bytes / (1024 * 1024),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
            "evictions": self._evictions,
        }


def cache_result(
    cache: ResultCache,
    key_func: Optional[Callable] = None,
    ttl_seconds: Optional[int] = None,
) -> Callable:
    """
    Декоратор для кэширования результатов функции.

    Args:
        cache: Экземпляр ResultCache
        key_func: Функция для генерации ключа (по умолчанию - хэш аргументов)
        ttl_seconds: TTL для кэша

    Returns:
        Декоратор
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Генерация ключа
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = _generate_cache_key(func.__name__, args, kwargs)

            # Проверка кэша
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                LOG.debug(f"Cache hit for {func.__name__}: {cache_key}")
                return cached_value

            # Вызов функции
            LOG.debug(f"Cache miss for {func.__name__}: {cache_key}")
            result = await func(*args, **kwargs)

            # Сохранение в кэш
            cache.set(cache_key, result, ttl_seconds=ttl_seconds)

            return result

        return wrapper

    return decorator


def _generate_cache_key(func_name: str, args: tuple, kwargs: dict) -> str:
    """Генерация ключа кэша из аргументов функции."""
    # Создание строки из аргументов
    key_parts = [func_name]

    for arg in args:
        if isinstance(arg, (str, int, float, bool)):
            key_parts.append(str(arg))
        elif isinstance(arg, Path):
            key_parts.append(str(arg))
        else:
            key_parts.append(type(arg).__name__)

    for k, v in sorted(kwargs.items()):
        if isinstance(v, (str, int, float, bool)):
            key_parts.append(f"{k}={v}")

    key_string = ":".join(key_parts)

    # Хэширование для компактности
    return hashlib.sha256(key_string.encode()).hexdigest()[:16]


class ChunkedFileProcessor:
    """
    Обработчик больших PCAP файлов по частям.

    Позволяет обрабатывать файлы, которые не помещаются в память.
    """

    def __init__(self, chunk_size_mb: int = 100):
        """
        Инициализация процессора.

        Args:
            chunk_size_mb: Размер чанка в MB
        """
        self.chunk_size_bytes = chunk_size_mb * 1024 * 1024

    async def process_large_file(
        self, file_path: str, processor_func: Callable, **kwargs
    ) -> List[Any]:
        """
        Обработка большого файла по частям.

        Args:
            file_path: Путь к файлу
            processor_func: Функция обработки чанка
            **kwargs: Дополнительные параметры

        Returns:
            Список результатов обработки чанков
        """
        file_size = Path(file_path).stat().st_size

        if file_size <= self.chunk_size_bytes:
            # Файл маленький, обрабатываем целиком
            return [await processor_func(file_path, **kwargs)]

        LOG.info(f"Processing large file ({file_size / 1024 / 1024:.1f} MB) in chunks")

        # TODO: Реализация chunked processing для PCAP
        # Это требует специальной логики для разбиения PCAP на части
        # Пока возвращаем результат обработки целого файла
        return [await processor_func(file_path, **kwargs)]


class ParallelFlowProcessor:
    """
    Параллельная обработка потоков PCAP.

    Использует asyncio для параллельной обработки независимых потоков.
    """

    def __init__(self, max_concurrent: int = 10):
        """
        Инициализация процессора.

        Args:
            max_concurrent: Максимальное количество параллельных задач
        """
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def process_flows_parallel(
        self, flows: Dict[str, List], processor_func: Callable, **kwargs
    ) -> List[Any]:
        """
        Параллельная обработка потоков.

        Args:
            flows: Словарь {flow_id: packets}
            processor_func: Функция обработки потока
            **kwargs: Дополнительные параметры

        Returns:
            Список результатов обработки
        """

        async def process_with_semaphore(flow_id: str, packets: List):
            async with self._semaphore:
                return await processor_func(flow_id, packets, **kwargs)

        # Создание задач для всех потоков
        tasks = [process_with_semaphore(flow_id, packets) for flow_id, packets in flows.items()]

        # Параллельное выполнение
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start_time

        LOG.info(
            f"Processed {len(flows)} flows in {duration:.2f}s "
            f"({len(flows)/duration:.1f} flows/sec)"
        )

        # Фильтрация ошибок
        successful_results = [r for r in results if not isinstance(r, Exception)]

        errors = [r for r in results if isinstance(r, Exception)]
        if errors:
            LOG.warning(f"Failed to process {len(errors)} flows")

        return successful_results


@dataclass
class PerformanceMetrics:
    """Метрики производительности."""

    operation: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration_seconds: Optional[float] = None
    items_processed: int = 0
    throughput: Optional[float] = None
    memory_mb: Optional[float] = None

    def finish(self, items_processed: int = 0) -> None:
        """Завершение измерения."""
        self.end_time = time.time()
        self.duration_seconds = self.end_time - self.start_time
        self.items_processed = items_processed

        if self.duration_seconds > 0 and items_processed > 0:
            self.throughput = items_processed / self.duration_seconds


class PerformanceMonitor:
    """Мониторинг производительности."""

    def __init__(self):
        """Инициализация монитора."""
        self._metrics: List[PerformanceMetrics] = []

    def start_operation(self, operation: str) -> PerformanceMetrics:
        """Начало измерения операции."""
        metrics = PerformanceMetrics(operation=operation)
        self._metrics.append(metrics)
        return metrics

    def get_summary(self) -> Dict[str, Any]:
        """Получение сводки по производительности."""
        if not self._metrics:
            return {}

        completed = [m for m in self._metrics if m.duration_seconds is not None]

        if not completed:
            return {}

        total_duration = sum(m.duration_seconds for m in completed)
        total_items = sum(m.items_processed for m in completed)

        return {
            "operations": len(completed),
            "total_duration_seconds": total_duration,
            "total_items_processed": total_items,
            "average_throughput": total_items / total_duration if total_duration > 0 else 0,
            "operations_detail": [
                {
                    "operation": m.operation,
                    "duration": m.duration_seconds,
                    "items": m.items_processed,
                    "throughput": m.throughput,
                }
                for m in completed
            ],
        }


# Глобальные экземпляры
_global_cache: Optional[ResultCache] = None
_global_monitor: Optional[PerformanceMonitor] = None


def get_global_cache() -> ResultCache:
    """Получение глобального кэша."""
    global _global_cache
    if _global_cache is None:
        _global_cache = ResultCache()
    return _global_cache


def get_global_monitor() -> PerformanceMonitor:
    """Получение глобального монитора."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = PerformanceMonitor()
    return _global_monitor
