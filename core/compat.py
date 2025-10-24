"""
Модуль совместимости для future annotations
"""

import sys

# Проверяем версию Python
if sys.version_info >= (3, 7):
    # В Python 3.7+ annotations доступны
    try:
        from __future__ import annotations

        ANNOTATIONS_AVAILABLE = True
    except ImportError:
        ANNOTATIONS_AVAILABLE = False
else:
    ANNOTATIONS_AVAILABLE = False


def get_type_hints(obj):
    """Безопасное получение type hints."""
    try:
        import typing

        return typing.get_type_hints(obj)
    except (ImportError, AttributeError, NameError):
        return {}


def safe_annotations(func):
    """Декоратор для безопасной работы с annotations."""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ImportError, AttributeError, NameError):
            # Если annotations не работают, возвращаем пустой результат
            return {}

    return wrapper
