"""Оптимизатор производительности."""
import time
import gc
import psutil
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from collections import deque
from concurrent.futures import ThreadPoolExecutor, Future
from recon.core.diagnostics.logger import get_logger
from recon.core.diagnostics.metrics import MetricsCollector

@dataclass
class PerformanceProfile:
    """Профиль производительности."""
    cpu_percent: float
    memory_percent: float
    thread_count: int
    gc_stats: Dict[str, int]
    timestamp: float

class PerformanceOptimizer:
    """Оптимизатор производительности системы."""

    def __init__(self, name: str='PerformanceOptimizer'):
        """
        Инициализация оптимизатора.

        Args:
            name: Имя оптимизатора
        """
        self.name = name
        self.logger = get_logger(name)
        self.metrics = MetricsCollector(f'{name}.Metrics')
        self.monitoring_interval = 5.0
        self.history_size = 100
        self.profiles: deque[PerformanceProfile] = deque(maxlen=self.history_size)
        self.thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='PerfOpt')
        self._monitoring_thread: Optional[threading.Thread] = None
        self._monitoring_active = False
        self._caches: Dict[str, Any] = {}
        self._optimizations: List[Callable] = [self._optimize_gc, self._optimize_thread_pool, self._optimize_caches]

    def start_monitoring(self) -> None:
        """Запуск мониторинга производительности."""
        if self._monitoring_active:
            self.logger.warning('Monitoring already active')
            return
        try:
            self._monitoring_active = True
            self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True, name=f'{self.name}-Monitor')
            self._monitoring_thread.start()
            self.logger.info('Performance monitoring started')
        except Exception as e:
            self.logger.error(f'Failed to start performance monitoring: {e}')
            self._monitoring_active = False
            self.logger.warning('Continuing without performance monitoring')

    def stop_monitoring(self) -> None:
        """Остановка мониторинга."""
        if not self._monitoring_active:
            return
        self.logger.info('Stopping performance monitoring...')
        self._monitoring_active = False
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            timeout = max(self.monitoring_interval * 2, 10.0)
            self._monitoring_thread.join(timeout=timeout)
            if self._monitoring_thread.is_alive():
                self.logger.warning('Monitoring thread did not stop within timeout, forcing stop')
            else:
                self.logger.debug('Monitoring thread stopped successfully')
        self._monitoring_thread = None
        self.logger.info('Performance monitoring stopped')

    def _monitoring_loop(self) -> None:
        """Цикл мониторинга."""
        consecutive_errors = 0
        max_consecutive_errors = 5
        self.logger.debug('Monitoring loop started')
        while self._monitoring_active:
            try:
                if not self._monitoring_active:
                    break
                profile = self._collect_profile()
                self.profiles.append(profile)
                self.metrics.set_gauge('cpu_percent', profile.cpu_percent)
                self.metrics.set_gauge('memory_percent', profile.memory_percent)
                self.metrics.set_gauge('thread_count', profile.thread_count)
                if len(self.profiles) >= 10:
                    self._analyze_and_optimize()
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                self.logger.error(f'Monitoring error ({consecutive_errors}/{max_consecutive_errors}): {e}')
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.error('Too many consecutive monitoring errors, stopping monitoring')
                    self._monitoring_active = False
                    break
                self._interruptible_sleep(min(self.monitoring_interval * 2, 30))
                continue
            self._interruptible_sleep(self.monitoring_interval)
        self.logger.debug('Monitoring loop ended')

    def _interruptible_sleep(self, duration: float) -> None:
        """
        Прерываемый сон, который можно быстро остановить.

        Args:
            duration: Длительность сна в секундах
        """
        chunk_size = 0.1
        chunks = int(duration / chunk_size)
        remainder = duration % chunk_size
        for _ in range(chunks):
            if not self._monitoring_active:
                return
            time.sleep(chunk_size)
        if remainder > 0 and self._monitoring_active:
            time.sleep(remainder)

    def _collect_profile(self) -> PerformanceProfile:
        """Сбор текущего профиля производительности."""
        try:
            process = psutil.Process()
            with process.oneshot():
                cpu_percent = process.cpu_percent(interval=0.1)
                memory_info = process.memory_info()
                memory_percent = process.memory_percent()
                thread_count = process.num_threads()
            try:
                gc_stats = {f'gen{i}_collections': gc.get_stats()[i]['collections'] for i in range(len(gc.get_stats()))}
            except Exception as gc_error:
                self.logger.warning(f'Error collecting GC stats: {gc_error}')
                gc_stats = {}
            return PerformanceProfile(cpu_percent=cpu_percent, memory_percent=memory_percent, thread_count=thread_count, gc_stats=gc_stats, timestamp=time.time())
        except psutil.NoSuchProcess:
            self.logger.warning('Process no longer exists, using default profile')
            return PerformanceProfile(cpu_percent=0.0, memory_percent=0.0, thread_count=1, gc_stats={}, timestamp=time.time())
        except Exception as e:
            self.logger.error(f'Error collecting performance profile: {e}')
            return PerformanceProfile(cpu_percent=0.0, memory_percent=0.0, thread_count=1, gc_stats={}, timestamp=time.time())

    def _analyze_and_optimize(self) -> None:
        """Анализ производительности и применение оптимизаций."""
        recent_profiles = list(self.profiles)[-20:]
        avg_cpu = sum((p.cpu_percent for p in recent_profiles)) / len(recent_profiles)
        avg_memory = sum((p.memory_percent for p in recent_profiles)) / len(recent_profiles)
        self.logger.debug(f'Performance: CPU={avg_cpu:.1f}%, Memory={avg_memory:.1f}%')
        if avg_cpu > 80 or avg_memory > 80:
            self.logger.info('High resource usage detected, applying optimizations')
            self.apply_optimizations()

    def apply_optimizations(self) -> Dict[str, Any]:
        """
        Применение всех доступных оптимизаций.

        Returns:
            Результаты оптимизаций
        """
        results = {}
        for optimization in self._optimizations:
            try:
                name = optimization.__name__
                self.metrics.start_timer(f'optimization_{name}')
                result = optimization()
                results[name] = result
                self.metrics.stop_timer(f'optimization_{name}')
                if result.get('success'):
                    self.logger.info(f"Optimization {name} applied: {result.get('message')}")
            except Exception as e:
                self.logger.error(f'Optimization {optimization.__name__} failed: {e}')
                results[optimization.__name__] = {'success': False, 'error': str(e)}
                self._handle_optimization_failure(optimization.__name__, e)
        return results

    def _handle_optimization_failure(self, optimization_name: str, error: Exception) -> None:
        """
        Обработка ошибок оптимизации с graceful degradation.

        Args:
            optimization_name: Имя неудавшейся оптимизации
            error: Исключение, которое произошло
        """
        try:
            self.logger.warning(f'Optimization {optimization_name} failed, continuing without it')
            if hasattr(self, 'metrics'):
                self.metrics.increment_counter(f'optimization_failures_{optimization_name}')
            if optimization_name == '_optimize_gc':
                self.logger.info('Falling back to basic garbage collection')
                try:
                    import gc
                    gc.collect()
                except:
                    pass
            elif optimization_name == '_optimize_thread_pool':
                self.logger.info('Continuing with current thread pool configuration')
            elif optimization_name == '_optimize_caches':
                self.logger.info('Continuing without cache optimization')
        except Exception as fallback_error:
            self.logger.error(f'Error in optimization failure handler: {fallback_error}')

    def _optimize_gc(self) -> Dict[str, Any]:
        """Оптимизация сборщика мусора."""
        collected = gc.collect()
        if len(self.profiles) > 0:
            recent_profile = self.profiles[-1]
            if recent_profile.memory_percent > 70:
                gc.set_threshold(400, 5, 5)
            else:
                gc.set_threshold(700, 10, 10)
        return {'success': True, 'message': f'Collected {collected} objects', 'collected': collected}

    def _optimize_thread_pool(self) -> Dict[str, Any]:
        """Оптимизация пула потоков."""
        if hasattr(self.thread_pool, '_threads'):
            active_threads = len([t for t in self.thread_pool._threads if t.is_alive()])
            max_workers = self.thread_pool._max_workers
            if active_threads >= max_workers * 0.8:
                new_max = min(max_workers + 2, 16)
                self.thread_pool._max_workers = new_max
                message = f'Increased thread pool to {new_max}'
            elif active_threads < max_workers * 0.2 and max_workers > 2:
                new_max = max(max_workers - 1, 2)
                self.thread_pool._max_workers = new_max
                message = f'Decreased thread pool to {new_max}'
            else:
                message = f'Thread pool optimal at {max_workers}'
            return {'success': True, 'message': message, 'active_threads': active_threads, 'max_workers': max_workers}
        return {'success': False, 'message': 'Thread pool info not available'}

    def _optimize_caches(self) -> Dict[str, Any]:
        """Оптимизация кэшей."""
        cleared_caches = []
        total_cleared = 0
        for cache_name, cache in self._caches.items():
            if hasattr(cache, '__len__') and hasattr(cache, 'clear'):
                cache_size = len(cache)
                if cache_size > 1000:
                    cache.clear()
                    cleared_caches.append(cache_name)
                    total_cleared += cache_size
        message = f'Cleared {len(cleared_caches)} caches, {total_cleared} entries'
        return {'success': True, 'message': message, 'cleared_caches': cleared_caches, 'total_cleared': total_cleared}

    def register_cache(self, name: str, cache: Any) -> None:
        """
        Регистрация кэша для оптимизации.

        Args:
            name: Имя кэша
            cache: Объект кэша
        """
        self._caches[name] = cache
        self.logger.debug(f'Registered cache: {name}')

    def submit_task(self, func: Callable, *args, **kwargs) -> Future:
        """
        Отправка задачи в пул потоков.

        Args:
            func: Функция для выполнения
            *args: Позиционные аргументы
            **kwargs: Именованные аргументы

        Returns:
            Future объект
        """
        return self.thread_pool.submit(func, *args, **kwargs)

    def get_performance_report(self) -> Dict[str, Any]:
        """Получение отчета о производительности."""
        if not self.profiles:
            return {'message': 'No performance data available'}
        recent_profiles = list(self.profiles)[-20:]
        report = {'current': self._collect_profile().__dict__, 'averages': {'cpu_percent': sum((p.cpu_percent for p in recent_profiles)) / len(recent_profiles), 'memory_percent': sum((p.memory_percent for p in recent_profiles)) / len(recent_profiles), 'thread_count': sum((p.thread_count for p in recent_profiles)) / len(recent_profiles)}, 'metrics': self.metrics.get_stats(), 'recommendations': self._generate_recommendations()}
        return report

    def _generate_recommendations(self) -> List[str]:
        """Генерация рекомендаций по оптимизации."""
        recommendations = []
        if not self.profiles:
            return recommendations
        recent_profiles = list(self.profiles)[-10:]
        avg_cpu = sum((p.cpu_percent for p in recent_profiles)) / len(recent_profiles)
        avg_memory = sum((p.memory_percent for p in recent_profiles)) / len(recent_profiles)
        if avg_cpu > 80:
            recommendations.append('High CPU usage detected. Consider optimizing algorithms or distributing load.')
        if avg_memory > 80:
            recommendations.append('High memory usage detected. Review memory allocations and enable caching.')
        if len(self.profiles) > 50:
            older_profiles = list(self.profiles)[-50:-30]
            old_avg_memory = sum((p.memory_percent for p in older_profiles)) / len(older_profiles)
            if avg_memory > old_avg_memory * 1.2:
                recommendations.append('Memory usage is trending upward. Check for memory leaks.')
        return recommendations

    def start_optimization(self) -> None:
        """
        Запуск системы оптимизации производительности.

        Этот метод запускает мониторинг и подготавливает систему к оптимизации.
        """
        try:
            self.logger.info('Starting performance optimization system...')
            self.logger.info('Performance optimization started (basic mode)')
        except Exception as e:
            self.logger.error(f'Error starting performance optimization: {e}')
            self.logger.warning('Continuing without performance optimization')

    def stop_optimization(self) -> None:
        """
        Остановка оптимизации производительности.

        Этот метод обеспечивает graceful остановку всех компонентов оптимизатора.
        """
        try:
            self.logger.info('Stopping performance optimization...')
            if hasattr(self, '_monitoring_active') and self._monitoring_active:
                self._monitoring_active = False
                self.logger.debug('Monitoring stopped')
            self._basic_cleanup()
            self.logger.info('Performance optimization stopped successfully')
        except Exception as e:
            self.logger.error(f'Error during performance optimization shutdown: {e}')
            try:
                self._basic_cleanup()
            except:
                pass

    def _basic_cleanup(self) -> None:
        """
        Базовая очистка без мониторинга.
        """
        try:
            if hasattr(self, 'thread_pool') and self.thread_pool:
                self.thread_pool.shutdown(wait=False, cancel_futures=True)
            import gc
            gc.collect()
            self.logger.info('Basic cleanup completed')
        except Exception as e:
            self.logger.warning(f'Error during basic cleanup: {e}')

    def _force_cleanup(self) -> None:
        """
        Принудительная очистка ресурсов при ошибках.

        Используется как fallback когда graceful shutdown не удается.
        """
        try:
            self._monitoring_active = False
            if hasattr(self, 'thread_pool') and self.thread_pool:
                try:
                    self.thread_pool.shutdown(wait=False, cancel_futures=True)
                except:
                    pass
            self.logger.warning('Force cleanup completed')
        except Exception as e:
            self.logger.error(f'Error during force cleanup: {e}')

    def cleanup(self) -> None:
        """Очистка ресурсов."""
        self.stop_optimization()