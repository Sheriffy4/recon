#!/usr/bin/env python3

"""
Attack parameter generation for genetic algorithm.
"""

from __future__ import annotations

import random
from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    try:
        from ...pcap_analysis.blocking_pattern_detector import (
            BlockingPatternAnalysis,
            BlockingType,
        )
    except ImportError:
        BlockingPatternAnalysis = Any
        BlockingType = Any


class AttackParameterGenerator:
    """Генератор параметров для атак обхода DPI."""

    def get_available_attacks(self, blocking_analysis: Any) -> List[str]:
        """
        Получение доступных атак на основе анализа блокировки.

        Args:
            blocking_analysis: Анализ паттернов блокировки

        Returns:
            Список названий доступных атак
        """
        # Базовый набор атак
        base_attacks = [
            "fake",
            "multisplit",
            "disorder",
            "tls_sni_split",
            "tls_chello_frag",
            "http_split",
            "tcp_split",
        ]

        # Фильтрация атак на основе типа блокировки
        if hasattr(blocking_analysis, "primary_blocking_type"):
            blocking_type = blocking_analysis.primary_blocking_type

            # Check if it's an enum or string
            if hasattr(blocking_type, "name"):
                blocking_type_str = blocking_type.name
            else:
                blocking_type_str = str(blocking_type)

            if "SNI_FILTERING" in blocking_type_str:
                return ["fake", "tls_sni_split", "tls_chello_frag", "disorder"]
            elif "RST_INJECTION" in blocking_type_str:
                return ["fake", "disorder", "multisplit", "tcp_split"]

        return base_attacks

    def generate_random_parameters(
        self, attack_name: str, blocking_analysis: Any = None
    ) -> Dict[str, Any]:
        """
        Генерация случайных параметров для атаки.

        Args:
            attack_name: Название атаки
            blocking_analysis: Анализ блокировки (опционально, не используется пока)

        Returns:
            Словарь параметров атаки
        """
        parameters = {}

        # Базовые параметры для разных типов атак
        if "split" in attack_name:
            # Canonical keys: split_pos, split_count.
            # Keep split_position as a mirror for backward compatibility (do not create divergent values).
            pos = random.randint(1, 100)
            parameters["split_pos"] = pos
            parameters.setdefault("split_position", pos)  # legacy mirror
            parameters["split_count"] = random.randint(2, 5)

        if "fake" in attack_name:
            ttl = random.randint(1, 32)
            # Dispatcher accepts ttl or fake_ttl
            parameters["ttl"] = ttl
            parameters["fake_ttl"] = ttl
            parameters["fake_count"] = random.randint(1, 3)
            # Canonical fooling key for engine parity
            parameters.setdefault("fooling", random.choice(["badsum", "badseq", "md5sig"]))

        if "disorder" in attack_name:
            parameters["disorder_count"] = random.randint(2, 10)
            parameters["disorder_delay_ms"] = random.randint(1, 100)

        if "tls" in attack_name:
            parameters["tls_record_split"] = random.choice([True, False])
            parameters["sni_obfuscation"] = random.choice([True, False])

        # Общие параметры
        parameters["enabled"] = True
        parameters["priority"] = random.uniform(0.1, 1.0)

        return parameters
