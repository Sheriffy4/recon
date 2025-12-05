"""
StrategyEvaluator - Централизованная оценка успешности стратегий обхода DPI.

Этот модуль предоставляет единую точку для оценки результатов тестирования стратегий
на основе ConnectionMetrics. Заменяет разрозненную логику успеха/неудачи в коде.

Основные компоненты:
- EvaluationResult: Результат оценки стратегии
- StrategyEvaluator: Класс для оценки стратегий согласно Requirements 3.2-3.7
"""

from dataclasses import dataclass
from typing import Optional

from core.connection_metrics import ConnectionMetrics, BlockType


@dataclass
class EvaluationResult:
    """
    Результат оценки стратегии обхода DPI.
    
    Attributes:
        success: Успешно ли обошли DPI блокировку
        block_type: Тип обнаруженной блокировки (или NONE если успех)
        reason: Человекочитаемое объяснение результата
        confidence: Уверенность в оценке (0.0-1.0)
    """
    success: bool
    block_type: BlockType
    reason: str
    confidence: float = 1.0


class StrategyEvaluator:
    """
    Единая точка оценки успешности стратегии обхода DPI.
    
    Реализует централизованную логику оценки согласно Requirements 3.1-3.7:
    - 3.2: Таймаут -> success=False, block_type=PASSIVE_DROP
    - 3.3: RST < 100ms -> success=False, block_type=ACTIVE_RST
    - 3.4: HTTP 200-499 -> success=True (DPI обойден)
    - 3.5: HTTP 403/451 -> success=True, block_type=HTTP_BLOCK (DPI обойден, блок на уровне сервера)
    - 3.6: Получены байты без HTTP статуса -> success=True
    - 3.7: TLS handshake завершён -> success=True, confidence=0.8
    
    Usage:
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        if result.success:
            print(f"Strategy succeeded: {result.reason}")
    """
    
    def __init__(self, timeout_threshold_ms: int = 10000, rst_threshold_ms: int = 100):
        """
        Инициализация StrategyEvaluator.
        
        Args:
            timeout_threshold_ms: Порог таймаута в миллисекундах (по умолчанию 10000)
            rst_threshold_ms: Порог времени для RST в миллисекундах (по умолчанию 100)
        """
        self.timeout_threshold_ms = timeout_threshold_ms
        self.rst_threshold_ms = rst_threshold_ms
    
    def evaluate(self, metrics: ConnectionMetrics) -> EvaluationResult:
        """
        Оценить результат тестирования стратегии на основе метрик соединения.
        
        Логика оценки (в порядке приоритета):
        1. Таймаут -> PASSIVE_DROP (Requirement 3.2)
        2. RST < 100ms -> ACTIVE_RST (Requirement 3.3)
        3. HTTP 200-499 -> Успех (Requirement 3.4)
        4. HTTP 403/451 -> Успех с HTTP_BLOCK (Requirement 3.5)
        5. Байты получены -> Успех (Requirement 3.6)
        6. TLS завершён -> Успех с confidence=0.8 (Requirement 3.7)
        7. Иначе -> Неудача
        
        Args:
            metrics: ConnectionMetrics с результатами тестирования
        
        Returns:
            EvaluationResult: Результат оценки стратегии
        """
        # Requirement 3.2: Таймаут -> PASSIVE_DROP
        if metrics.timeout:
            return EvaluationResult(
                success=False,
                block_type=BlockType.PASSIVE_DROP,
                reason=f"Connection timed out after {metrics.total_time_ms:.0f}ms",
                confidence=1.0
            )
        
        # Requirement 3.3: RST < 100ms -> ACTIVE_RST
        if metrics.rst_received and metrics.rst_timing_ms is not None:
            if metrics.rst_timing_ms < self.rst_threshold_ms:
                return EvaluationResult(
                    success=False,
                    block_type=BlockType.ACTIVE_RST,
                    reason=f"RST received at {metrics.rst_timing_ms:.1f}ms (< {self.rst_threshold_ms}ms threshold)",
                    confidence=1.0
                )
        
        # Requirement 3.5: HTTP 403/451 -> Успех с HTTP_BLOCK (DPI обойден, блок на уровне сервера)
        if metrics.http_status in (403, 451):
            return EvaluationResult(
                success=True,
                block_type=BlockType.HTTP_BLOCK,
                reason=f"DPI bypassed, but server returned HTTP {metrics.http_status}",
                confidence=1.0
            )
        
        # Requirement 3.4: HTTP 200-499 -> Успех
        if metrics.http_status is not None and 200 <= metrics.http_status < 500:
            return EvaluationResult(
                success=True,
                block_type=BlockType.NONE,
                reason=f"HTTP {metrics.http_status} received, DPI bypassed",
                confidence=1.0
            )
        
        # Requirement 3.6: Байты получены без HTTP статуса -> Успех
        if metrics.bytes_received > 0:
            return EvaluationResult(
                success=True,
                block_type=BlockType.NONE,
                reason=f"Received {metrics.bytes_received} bytes, DPI bypassed",
                confidence=0.9  # Немного ниже уверенность, т.к. нет HTTP статуса
            )
        
        # Requirement 3.7: TLS handshake завершён -> Успех с confidence=0.8
        if metrics.tls_completed:
            return EvaluationResult(
                success=True,
                block_type=BlockType.NONE,
                reason="TLS handshake completed successfully",
                confidence=0.8
            )
        
        # Если ничего из вышеперечисленного не подошло -> Неудача
        # Определяем тип блокировки на основе метрик
        block_type = metrics.detect_block_type()
        if block_type == BlockType.NONE:
            # Если detect_block_type вернул NONE, но мы здесь - что-то не так
            block_type = BlockType.UNKNOWN
        
        reason = "Connection failed without clear success indicators"
        if metrics.error:
            reason = f"Connection error: {metrics.error}"
        
        return EvaluationResult(
            success=False,
            block_type=block_type,
            reason=reason,
            confidence=0.9
        )
