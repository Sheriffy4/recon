# core/bypass/attacks/multisplit_segment_fix.py

#!/usr/bin/env python3
"""
Multisplit Segment Fix - Исправление для правильной работы multisplit атаки.

Этот модуль обеспечивает правильную интеграцию multisplit стратегии
с новой segment-based архитектурой.
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from core.bypass.attacks.base import (
    AttackResult,
    AttackContext,
    AttackStatus,
    SegmentTuple,
)

LOG = logging.getLogger(__name__)


@dataclass
class MultisplitSegmentConfig:
    """Конфигурация для multisplit атаки с segments."""

    split_count: int = 5
    split_seqovl: int = 20
    fooling: str = "badsum"
    positions: Optional[List[int]] = None

    def __post_init__(self):
        """Генерируем позиции разбиения если не указаны."""
        if self.positions is None:
            # Генерируем N позиций для разбиения (например, 1, 3, 5, 7, 9 для N=5)
            self.positions = list(range(1, self.split_count * 2, 2))


class MultisplitSegmentProcessor:
    """Процессор для преобразования multisplit стратегии в segments."""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def create_multisplit_attack_result(
        self, context: AttackContext, strategy_params: Dict[str, Any]
    ) -> AttackResult:
        """
        Создает AttackResult с корректно нарезанными сегментами для multisplit атаки.

        Args:
            context: Контекст атаки.
            strategy_params: Параметры стратегии из zapret.

        Returns:
            AttackResult с готовыми сегментами для исполнения.
        """

        # 1. Проверяем, что это multisplit стратегия
        dpi_desync = strategy_params.get("dpi-desync", "")
        if "multisplit" not in dpi_desync:
            return AttackResult(
                status=AttackStatus.INVALID_PARAMS,
                error_message="Not a multisplit strategy",
            )

        # 2. Извлекаем параметры и создаем конфиг
        try:
            split_count = int(strategy_params.get("dpi-desync-split-count", 5))
            split_seqovl = int(strategy_params.get("dpi-desync-split-seqovl", 20))
            fooling = strategy_params.get("dpi-desync-fooling", "badsum")

            config = MultisplitSegmentConfig(
                split_count=split_count, split_seqovl=split_seqovl, fooling=fooling
            )
        except (ValueError, TypeError) as e:
            return AttackResult(
                status=AttackStatus.INVALID_PARAMS,
                error_message=f"Invalid multisplit params: {e}",
            )

        self.logger.info(
            f"Processing multisplit strategy: split_count={split_count}, seqovl={split_seqovl}, fooling={fooling}"
        )

        # 3. --- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ: Правильная нарезка payload ---
        payload = context.payload
        if not payload:
            return AttackResult(
                status=AttackStatus.INVALID_PARAMS, error_message="Payload is empty"
            )

        segments: List[SegmentTuple] = []
        last_pos = 0

        # Итерируемся по сгенерированным позициям [1, 3, 5, ...]
        for i, pos in enumerate(config.positions):
            # Убедимся, что не выходим за пределы payload
            if last_pos >= len(payload):
                break

            # Вычисляем конечную позицию для текущего сегмента
            current_end_pos = min(pos, len(payload))

            # Нарезаем кусок payload
            segment_payload = payload[last_pos:current_end_pos]

            if not segment_payload:
                continue

            # Собираем опции для сегмента
            options = {}
            if config.fooling == "badsum":
                options["bad_checksum"] = True
            elif config.fooling == "md5sig":
                options["md5sig"] = True

            # Добавляем overlap для всех сегментов, кроме первого
            if i > 0 and config.split_seqovl > 0:
                options["seq_overlap"] = config.split_seqovl

            # Добавляем небольшую задержку между сегментами
            if i > 0:
                options["delay_ms"] = i * 2

            # Создаем кортеж сегмента: (данные, смещение_seq, опции)
            # Смещение seq равно начальной позиции куска в оригинальном payload
            segments.append((segment_payload, last_pos, options))

            # Обновляем начальную позицию для следующего сегмента
            last_pos = current_end_pos

        # 4. Добавляем последний сегмент с остатком payload
        if last_pos < len(payload):
            remaining_payload = payload[last_pos:]
            options = {"bad_checksum": True} if config.fooling == "badsum" else {}
            if config.split_seqovl > 0:
                options["seq_overlap"] = config.split_seqovl
            options["delay_ms"] = len(config.positions) * 2

            segments.append((remaining_payload, last_pos, options))

        if not segments:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message="Failed to create any segments.",
            )

        # 5. Создаем и возвращаем успешный AttackResult
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="multisplit_segments",
            packets_sent=len(segments),
            bytes_sent=len(payload),
            metadata={"segments": segments},  # Сохраняем segments в metadata
        )

        # Также устанавливаем segments через свойство для совместимости
        result.segments = segments

        self.logger.info(
            f"Created multisplit attack result with {len(segments)} segments."
        )
        for i, (p, offset, opt) in enumerate(segments):
            self.logger.debug(
                f"  Segment {i}: len={len(p)}, offset={offset}, options={opt}"
            )

        return result


# Глобальный экземпляр для простоты использования
_multisplit_processor = MultisplitSegmentProcessor()


def create_multisplit_attack_result(
    context: AttackContext, strategy_params: Dict[str, Any]
) -> AttackResult:
    """
    Глобальная функция-фасад для создания multisplit attack result.
    """
    return _multisplit_processor.create_multisplit_attack_result(
        context, strategy_params
    )
