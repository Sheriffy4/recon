"""
Legacy Compatibility Layer - поддержка устаревших API.

Этот модуль обеспечивает обратную совместимость со старыми способами
использования, добавляя deprecation warnings для устаревших паттернов.

Requirements: Backward Compatibility, Smooth Migration
"""

from typing import Optional, Dict, Any, List

from .deprecation import deprecated, warn_deprecated_import
from .intelligent_pcap_analyzer import (
    IntelligentPCAPAnalyzer,
    PCAPAnalysisResult,
    analyze_pcap_file,
)

# Версия текущего API
CURRENT_VERSION = "2.0.0"
NEXT_MAJOR_VERSION = "3.0.0"


# Устаревший способ: прямой импорт из модуля вместо использования фабрики
@deprecated(
    reason="Direct instantiation is deprecated",
    version=CURRENT_VERSION,
    removal_version=NEXT_MAJOR_VERSION,
    alternative="use analyze_pcap_file() function or IntelligentPCAPAnalyzer()",
    level="info",
)
def create_analyzer(config: Optional[Dict[str, Any]] = None) -> IntelligentPCAPAnalyzer:
    """
    Создание анализатора (устаревший способ).

    Deprecated: Используйте IntelligentPCAPAnalyzer() напрямую.

    Args:
        config: Конфигурация анализатора

    Returns:
        IntelligentPCAPAnalyzer instance
    """
    return IntelligentPCAPAnalyzer(config)


# Устаревший способ: синхронная версия analyze_pcap
@deprecated(
    reason="Synchronous version is deprecated",
    version=CURRENT_VERSION,
    removal_version=NEXT_MAJOR_VERSION,
    alternative="use async analyze_pcap_file() or await analyzer.analyze_pcap()",
    level="warning",
)
def analyze_pcap_sync(
    pcap_file: str, config: Optional[Dict[str, Any]] = None
) -> PCAPAnalysisResult:
    """
    Синхронный анализ PCAP файла (устаревший).

    Deprecated: Используйте async версию analyze_pcap_file().

    Args:
        pcap_file: Путь к PCAP файлу
        config: Конфигурация анализатора

    Returns:
        PCAPAnalysisResult
    """
    import asyncio

    return asyncio.run(analyze_pcap_file(pcap_file, config))


# Устаревший способ: старое имя функции
@deprecated(
    reason="Function renamed for clarity",
    version=CURRENT_VERSION,
    removal_version=NEXT_MAJOR_VERSION,
    alternative="analyze_pcap_file()",
    level="info",
)
def pcap_analyze(pcap_file: str, config: Optional[Dict[str, Any]] = None) -> PCAPAnalysisResult:
    """
    Анализ PCAP файла (устаревшее имя).

    Deprecated: Используйте analyze_pcap_file().
    """
    import asyncio

    return asyncio.run(analyze_pcap_file(pcap_file, config))


# Предупреждение об устаревших импортах
def _warn_legacy_import(module_name: str) -> None:
    """Предупреждение об импорте из устаревшего модуля."""
    warn_deprecated_import(
        old_path=f"core.pcap_analysis.{module_name}",
        new_path="core.pcap_analysis",
        version=CURRENT_VERSION,
        removal_version=NEXT_MAJOR_VERSION,
    )


# Устаревшие алиасы для backward compatibility
def get_legacy_aliases() -> Dict[str, Any]:
    """
    Получение словаря устаревших алиасов.

    Returns:
        Словарь {старое_имя: новый_объект}
    """
    return {
        "create_analyzer": create_analyzer,
        "analyze_pcap_sync": analyze_pcap_sync,
        "pcap_analyze": pcap_analyze,
    }


# Проверка использования устаревших паттернов
def check_deprecated_usage(code: str) -> List[str]:
    """
    Проверка кода на использование устаревших паттернов.

    Args:
        code: Код для проверки

    Returns:
        Список найденных устаревших паттернов
    """
    deprecated_patterns = []

    # Проверка устаревших функций
    if "create_analyzer(" in code:
        deprecated_patterns.append(
            "create_analyzer() is deprecated, use IntelligentPCAPAnalyzer() directly"
        )

    if "analyze_pcap_sync(" in code:
        deprecated_patterns.append(
            "analyze_pcap_sync() is deprecated, use async analyze_pcap_file()"
        )

    if "pcap_analyze(" in code:
        deprecated_patterns.append("pcap_analyze() is deprecated, use analyze_pcap_file()")

    # Проверка устаревших импортов
    deprecated_imports = [
        "from core.pcap_analysis.legacy",
        "from core.pcap_analysis.old_api",
    ]

    for imp in deprecated_imports:
        if imp in code:
            deprecated_patterns.append(f"{imp} is deprecated")

    return deprecated_patterns


# Migration helper
class MigrationHelper:
    """Помощник для миграции на новый API."""

    @staticmethod
    def show_migration_guide() -> str:
        """
        Показать руководство по миграции.

        Returns:
            Текст руководства
        """
        return """
        Migration Guide: Old API → New API
        ===================================
        
        1. Analyzer Creation:
           OLD: analyzer = create_analyzer(config)
           NEW: analyzer = IntelligentPCAPAnalyzer(config)
        
        2. PCAP Analysis:
           OLD: result = analyze_pcap_sync("file.pcap")
           NEW: result = await analyze_pcap_file("file.pcap")
           
           Or with asyncio:
           import asyncio
           result = asyncio.run(analyze_pcap_file("file.pcap"))
        
        3. Function Names:
           OLD: result = pcap_analyze("file.pcap")
           NEW: result = await analyze_pcap_file("file.pcap")
        
        4. Imports:
           OLD: from core.pcap_analysis.legacy_compat import create_analyzer
           NEW: from core.pcap_analysis import IntelligentPCAPAnalyzer
        
        For more details, see documentation at:
        docs/migration_guide.md
        """

    @staticmethod
    def convert_old_code(old_code: str) -> str:
        """
        Автоматическая конвертация старого кода в новый.

        Args:
            old_code: Старый код

        Returns:
            Новый код
        """
        new_code = old_code

        # Замена функций
        replacements = {
            "create_analyzer(": "IntelligentPCAPAnalyzer(",
            "analyze_pcap_sync(": "asyncio.run(analyze_pcap_file(",
            "pcap_analyze(": "asyncio.run(analyze_pcap_file(",
        }

        for old, new in replacements.items():
            new_code = new_code.replace(old, new)

        # Добавление import asyncio если нужно
        if "asyncio.run(" in new_code and "import asyncio" not in new_code:
            new_code = "import asyncio\n" + new_code

        return new_code


# Экспорт для backward compatibility
__all__ = [
    "create_analyzer",
    "analyze_pcap_sync",
    "pcap_analyze",
    "get_legacy_aliases",
    "check_deprecated_usage",
    "MigrationHelper",
]
