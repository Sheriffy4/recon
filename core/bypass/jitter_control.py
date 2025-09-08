"""
Система добавления jitter и контроля скорости инъекций
"""

import random
import time
import threading
from typing import Optional, Dict, Any
from dataclasses import dataclass
from collections import deque

@dataclass
class InjectionTiming:
    """Параметры тайминга для инъекций"""
    base_delay_ms: float = 2.0
    jitter_percent: float = 0.2
    min_delay_ms: float = 0.5
    max_delay_ms: float = 10.0

    def get_jittered_delay(self) -> float:
        """Возвращает задержку с учётом jitter"""
        jitter_range = self.base_delay_ms * self.jitter_percent
        jittered = self.base_delay_ms + random.uniform(-jitter_range, jitter_range)
        return max(self.min_delay_ms, min(jittered, self.max_delay_ms))

class RateController:
    """Контроллер скорости инъекций для предотвращения перегрузки"""

    def __init__(self, max_concurrent: int = 10, max_per_second: int = 100):
        self.max_concurrent = max_concurrent
        self.max_per_second = max_per_second
        self.current_injections = 0
        self.injection_times = deque(maxlen=max_per_second)
        self.lock = threading.Lock()

    def can_inject(self) -> bool:
        """Проверяет, можно ли выполнить инъекцию"""
        with self.lock:
            if self.current_injections >= self.max_concurrent:
                return False
            now = time.time()
            while self.injection_times and self.injection_times[0] < now - 1.0:
                self.injection_times.popleft()
            if len(self.injection_times) >= self.max_per_second:
                return False
            return True

    def start_injection(self):
        """Регистрирует начало инъекции"""
        with self.lock:
            self.current_injections += 1
            self.injection_times.append(time.time())

    def end_injection(self):
        """Регистрирует конец инъекции"""
        with self.lock:
            self.current_injections = max(0, self.current_injections - 1)

class JitterController:
    """Управление jitter для различных типов пакетов"""

    def __init__(self):
        self.timing_profiles = {
            'aggressive': InjectionTiming(1.0, 0.3, 0.3, 5.0),
            'balanced': InjectionTiming(2.0, 0.2, 0.5, 10.0),
            'stealthy': InjectionTiming(5.0, 0.4, 1.0, 20.0),
        }
        self.cdn_timings = {
            'cloudflare': InjectionTiming(1.5, 0.15, 0.5, 5.0),
            'fastly': InjectionTiming(2.5, 0.25, 1.0, 8.0),
            'default': InjectionTiming(2.0, 0.2, 0.5, 10.0),
        }

    def get_timing_for_cdn(self, cdn: Optional[str]) -> InjectionTiming:
        """Возвращает тайминг для конкретного CDN"""
        return self.cdn_timings.get(cdn, self.cdn_timings['default'])
