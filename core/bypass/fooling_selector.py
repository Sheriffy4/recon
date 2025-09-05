"""
Автоматический селектор fooling методов с проверкой совместимости пути
"""

import asyncio
import logging
import time
import pickle
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

@dataclass
class FoolingCompatibility:
    """Результат проверки совместимости fooling метода"""
    method: str
    compatible: bool
    latency_ms: float
    error_type: Optional[str] = None
    tested_at: datetime = field(default_factory=datetime.now)

@dataclass
class PathProfile:
    """Профиль сетевого пути для домена/AS"""
    domain: str
    asn: Optional[int] = None
    cdn: Optional[str] = None
    compatible_fooling: Set[str] = field(default_factory=set)
    incompatible_fooling: Set[str] = field(default_factory=set)
    last_test: datetime = field(default_factory=datetime.now)
    test_count: int = 0

class FoolingSelector:
    """Интеллектуальный селектор fooling методов"""

    FOOLING_METHODS = ['badsum', 'badseq', 'md5sig', 'hopbyhop']
    CACHE_FILE = "fooling_compatibility_cache.pkl"

    def __init__(self, bypass_engine=None, debug=False):
        self.bypass_engine = bypass_engine
        self.debug = debug
        self.logger = logging.getLogger("FoolingSelector")
        self.compatibility_cache: Dict[str, PathProfile] = {}
        self.cdn_profiles = {
            'cloudflare': {'compatible': ['badsum'], 'incompatible': ['md5sig']},
            'fastly': {'compatible': ['badsum', 'badseq'], 'incompatible': []},
            'akamai': {'compatible': ['badseq'], 'incompatible': ['md5sig']},
            'amazon': {'compatible': ['badsum'], 'incompatible': ['hopbyhop']},
        }
        self.load_cache()

    def load_cache(self):
        """Загружает кэш совместимости из файла"""
        cache_path = Path(self.CACHE_FILE)
        if cache_path.exists():
            try:
                with open(cache_path, 'rb') as f:
                    self.compatibility_cache = pickle.load(f)
                self.logger.info(f"Loaded {len(self.compatibility_cache)} path profiles")
            except Exception as e:
                self.logger.error(f"Failed to load cache: {e}")

    def save_cache(self):
        """Сохраняет кэш совместимости"""
        try:
            with open(self.CACHE_FILE, 'wb') as f:
                pickle.dump(self.compatibility_cache, f)
        except Exception as e:
            self.logger.error(f"Failed to save cache: {e}")
