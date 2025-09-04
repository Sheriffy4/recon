"""
Менеджер fallback стратегий и быстрой деградации
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class DomainFailureTracker:
    """Отслеживание неудач для домена"""
    domain: str
    consecutive_failures: int = 0
    total_failures: int = 0
    last_failure: Optional[datetime] = None
    last_success: Optional[datetime] = None
    blacklisted_strategies: Set[str] = field(default_factory=set)

class FallbackManager:
    """Управление fallback стратегиями при неудачах"""

    FAILURE_THRESHOLD = 3
    BLACKLIST_THRESHOLD = 5

    def __init__(self, debug=False):
        self.debug = debug
        self.logger = logging.getLogger("FallbackManager")
        self.failure_trackers: Dict[str, DomainFailureTracker] = {}

        self.cdn_fallback_profiles = {
            'cloudflare': [
                {'type': 'multisplit', 'params': {'ttl': 5, 'split_count': 3}},
                {'type': 'fake_disorder', 'params': {'ttl': 2, 'split_pos': 3}},
            ],
            'default': [
                {'type': 'simple_fragment', 'params': {'split_pos': 5}},
                {'type': 'multisplit', 'params': {'ttl': 6, 'split_count': 4}},
            ]
        }

    def record_failure(self, domain: str, strategy: Dict, error_type: str = "unknown"):
        """Записывает неудачу стратегии"""
        if domain not in self.failure_trackers:
            self.failure_trackers[domain] = DomainFailureTracker(domain=domain)
        tracker = self.failure_trackers[domain]
        tracker.consecutive_failures += 1
        tracker.total_failures += 1
        tracker.last_failure = datetime.now()

    def record_success(self, domain: str, strategy: Dict):
        """Записывает успех стратегии"""
        if domain not in self.failure_trackers:
            self.failure_trackers[domain] = DomainFailureTracker(domain=domain)
        tracker = self.failure_trackers[domain]
        tracker.consecutive_failures = 0
        tracker.last_success = datetime.now()

    def should_fallback(self, domain: str) -> bool:
        """Определяет, нужно ли переключиться на fallback"""
        if domain not in self.failure_trackers:
            return False
        tracker = self.failure_trackers[domain]
        return tracker.consecutive_failures >= self.FAILURE_THRESHOLD

    def get_fallback_strategy(self, domain: str, cdn: Optional[str] = None) -> Optional[Dict]:
        """Возвращает fallback стратегию"""
        candidates = self.cdn_fallback_profiles.get(cdn, self.cdn_fallback_profiles['default'])
        if candidates:
            return candidates[0]
        return None
