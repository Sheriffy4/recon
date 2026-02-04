"""
ConnectionMetrics - Централизованные метрики соединения для оценки стратегий обхода DPI.

Этот модуль предоставляет:
- BlockType: Enum для классификации типов блокировки DPI
- ConnectionMetrics: Dataclass для хранения всех метрик соединения
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class BlockType(Enum):
    """Тип блокировки DPI"""

    NONE = "none"  # Нет блокировки
    ACTIVE_RST = "active_rst"  # RST < 100ms после ClientHello
    PASSIVE_DROP = "passive_drop"  # Таймаут > 10s, пакеты дропаются
    HTTP_BLOCK = "http_block"  # TLS ok, HTTP 403/451
    IP_BLOCK = "ip_block"  # Нет SYN-ACK вообще
    UNKNOWN = "unknown"


@dataclass
class ConnectionMetrics:
    """
    Централизованный класс для всех метрик соединения.

    Используется для единообразного сбора метрик при тестировании стратегий
    обхода DPI и последующей оценки успешности через StrategyEvaluator.
    """

    # Тайминги (в миллисекундах)
    connect_time_ms: float = 0.0  # TCP handshake
    tls_time_ms: float = 0.0  # TLS handshake
    ttfb_ms: float = 0.0  # Time to first byte
    total_time_ms: float = 0.0  # Общее время

    # Результат
    http_status: Optional[int] = None
    bytes_received: int = 0
    tls_completed: bool = False

    # Ошибки
    error: Optional[str] = None
    rst_received: bool = False
    rst_timing_ms: Optional[float] = None
    timeout: bool = False

    # Классификация
    block_type: BlockType = BlockType.UNKNOWN

    # Мета
    timestamp: float = field(default_factory=time.time)

    def is_success(self) -> bool:
        """
        Определить, было ли соединение успешным.

        Успешное соединение - это соединение, которое обошло DPI блокировку.
        Критерии успеха:
        - Нет таймаута
        - Нет RST в первые 100ms
        - Получен HTTP статус 200-499 ИЛИ
        - Получены данные (bytes_received > 0) ИЛИ
        - TLS handshake завершён

        Returns:
            bool: True если соединение успешно обошло DPI
        """
        # Явные признаки блокировки
        if self.timeout:
            return False
        if self.rst_received and self.rst_timing_ms is not None and self.rst_timing_ms < 100:
            return False

        # Признаки успеха
        if self.http_status is not None and 200 <= self.http_status < 500:
            return True
        if self.bytes_received > 0:
            return True
        if self.tls_completed:
            return True

        # Если ничего не получено и нет явной блокировки - неуспех
        return False

    def detect_block_type(self) -> BlockType:
        """
        Автоматически определить тип блокировки на основе метрик.

        Логика определения:
        - ACTIVE_RST: RST получен в первые 100ms после ClientHello
        - PASSIVE_DROP: Таймаут без получения данных
        - HTTP_BLOCK: TLS успешен, но HTTP статус 403/451
        - IP_BLOCK: Нет ответа на SYN (connect_time_ms = 0 и timeout)
        - NONE: Соединение успешно
        - UNKNOWN: Не удалось классифицировать

        Returns:
            BlockType: Определённый тип блокировки
        """
        # ACTIVE_RST: RST в первые 100ms
        if self.rst_received and self.rst_timing_ms is not None and self.rst_timing_ms < 100:
            return BlockType.ACTIVE_RST

        # IP_BLOCK: Нет ответа на SYN
        if self.timeout and self.connect_time_ms == 0.0:
            return BlockType.IP_BLOCK

        # PASSIVE_DROP: Таймаут после установки соединения
        if self.timeout:
            return BlockType.PASSIVE_DROP

        # HTTP_BLOCK: TLS успешен, но HTTP блокировка
        if self.http_status in (403, 451):
            return BlockType.HTTP_BLOCK

        # NONE: Успешное соединение
        if self.is_success():
            return BlockType.NONE

        # UNKNOWN: Не удалось классифицировать
        return BlockType.UNKNOWN
