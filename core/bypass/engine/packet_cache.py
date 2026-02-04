"""
Packet cache for retransmission deduplication.

This module provides caching functionality to prevent duplicate processing
of TCP retransmissions. Extracted from base_engine.py to reduce god class complexity.

Requirement 11: Deduplication TCP retransmissions
"""

import logging
import threading
import time
from typing import Dict, Tuple


class ProcessedPacketCache:
    """
    Кэш обработанных пакетов для предотвращения повторной обработки TCP ретрансмиссий.

    Requirement 11: Deduplication TCP ретрансмиссий
    - Хранит (flow_id, seq) → timestamp для обработанных пакетов
    - Автоматически удаляет устаревшие записи (> 60 секунд)
    - Thread-safe для concurrent access
    """

    def __init__(self, ttl_seconds: int = 60):
        self._cache: Dict[Tuple[Tuple[str, int, str, int], int], float] = {}
        self._lock = threading.Lock()
        self._ttl_seconds = ttl_seconds
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        self.logger = logging.getLogger("ProcessedPacketCache")

    def start_cleanup_thread(self):
        """Запускает background thread для периодической очистки кэша"""
        if self._cleanup_thread is None or not self._cleanup_thread.is_alive():
            self._stop_cleanup.clear()
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self._cleanup_thread.start()
            self.logger.debug("Cleanup thread started")

    def stop_cleanup_thread(self):
        """Останавливает background thread очистки"""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=2.0)
            self.logger.debug("Cleanup thread stopped")

    def _cleanup_loop(self):
        """Background loop для очистки устаревших записей каждые 10 секунд"""
        while not self._stop_cleanup.wait(timeout=10.0):
            removed = self.cleanup_expired()
            if removed > 0:
                self.logger.debug(f"Cache cleanup: removed {removed} expired entries")

    def is_processed(self, flow_id: Tuple[str, int, str, int], seq: int) -> bool:
        """
        Проверяет, был ли пакет уже обработан.

        Args:
            flow_id: (src_ip, src_port, dst_ip, dst_port)
            seq: TCP sequence number

        Returns:
            True если пакет уже обработан, False иначе
        """
        key = (flow_id, seq)
        with self._lock:
            if key in self._cache:
                timestamp = self._cache[key]
                # Проверяем не истек ли TTL
                if time.time() - timestamp < self._ttl_seconds:
                    return True
                else:
                    # Удаляем устаревшую запись
                    del self._cache[key]
            return False

    def mark_processed(self, flow_id: Tuple[str, int, str, int], seq: int):
        """
        Помечает пакет как обработанный.

        Args:
            flow_id: (src_ip, src_port, dst_ip, dst_port)
            seq: TCP sequence number
        """
        key = (flow_id, seq)
        with self._lock:
            self._cache[key] = time.time()

    def cleanup_expired(self) -> int:
        """
        Удаляет устаревшие записи (> TTL).

        Returns:
            Количество удаленных записей
        """
        now = time.time()
        with self._lock:
            expired_keys = [
                key
                for key, timestamp in self._cache.items()
                if now - timestamp >= self._ttl_seconds
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)

    def remove_flow(self, flow_id: Tuple[str, int, str, int]):
        """
        Удаляет все записи для указанного flow (при закрытии соединения).

        Args:
            flow_id: (src_ip, src_port, dst_ip, dst_port)
        """
        with self._lock:
            keys_to_remove = [key for key in self._cache.keys() if key[0] == flow_id]
            for key in keys_to_remove:
                del self._cache[key]
            if keys_to_remove:
                self.logger.debug(
                    f"Connection closed: flow={flow_id}, removed {len(keys_to_remove)} cache entries"
                )

    def get_stats(self) -> Dict[str, int]:
        """Возвращает статистику кэша"""
        with self._lock:
            return {"total_entries": len(self._cache), "ttl_seconds": self._ttl_seconds}
