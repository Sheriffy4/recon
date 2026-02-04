"""
Legacy Adapter Module

Provides backward compatibility for legacy analyze_failures method.
Adapts old dict-based interface to new structured analysis.
"""

from typing import List, Dict, Any
from .models import FAILURE_PATTERNS


def analyze_failures(test_results: List[Dict], failure_patterns: Dict = None) -> Dict[str, Any]:
    """
    Legacy method for backward compatibility.
    Анализирует паттерны неудач и выдает рекомендации.

    Args:
        test_results: List of test result dictionaries
        failure_patterns: Optional failure patterns database (defaults to FAILURE_PATTERNS)

    Returns:
        Dictionary with analysis results
    """
    if failure_patterns is None:
        failure_patterns = FAILURE_PATTERNS

    failure_types = {}
    # В результатах hybrid_engine статус находится в 'result_status'
    for result in test_results:
        if result.get("success_rate", 0) == 0:
            failure_type = result.get("result_status", "UNKNOWN_FAILURE")
            failure_types[failure_type] = failure_types.get(failure_type, 0) + 1

    analysis = {
        "total_failures": len([r for r in test_results if r.get("success_rate", 0) == 0]),
        "failure_breakdown": failure_types,
        "recommendations": [],
        "likely_causes": [],
    }

    # Анализируем самый частый тип неудачи
    if failure_types:
        most_common = max(failure_types, key=failure_types.get)
        if most_common in failure_patterns:
            pattern = failure_patterns[most_common]
            analysis["likely_causes"] = pattern["причины"]
            analysis["recommendations"] = pattern["решения"]

    # Специфичные рекомендации
    if failure_types.get("TIMEOUT", 0) > len(test_results) * 0.8:
        analysis["recommendations"].append(
            "Подавляющее большинство тестов завершилось по таймауту. "
            "Возможно, требуется использовать прокси или VPN."
        )

    return analysis
