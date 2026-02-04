"""
Deprecation utilities - управление устаревшими API.

Этот модуль предоставляет:
- Декораторы для пометки устаревших функций/классов
- Утилиты для логирования deprecation warnings
- Управление версиями API

Requirements: API Stability, Backward Compatibility
"""

import warnings
import functools
import logging
from typing import Optional, Callable, Any

LOG = logging.getLogger("Deprecation")


class DeprecationLevel:
    """Уровни deprecation."""

    INFO = "info"  # Информационное предупреждение
    WARNING = "warning"  # Будет удалено в следующей мажорной версии
    CRITICAL = "critical"  # Будет удалено в следующем минорном релизе


def deprecated(
    reason: str,
    version: str,
    removal_version: Optional[str] = None,
    alternative: Optional[str] = None,
    level: str = DeprecationLevel.WARNING,
) -> Callable:
    """
    Декоратор для пометки устаревших функций/методов.

    Args:
        reason: Причина deprecation
        version: Версия, в которой помечено как deprecated
        removal_version: Версия, в которой будет удалено
        alternative: Рекомендуемая альтернатива
        level: Уровень серьезности (info/warning/critical)

    Returns:
        Декоратор функции

    Example:
        @deprecated(
            reason="Use new_function instead",
            version="2.0.0",
            removal_version="3.0.0",
            alternative="new_function()"
        )
        def old_function():
            pass
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Формирование сообщения
            msg_parts = [
                f"{func.__module__}.{func.__name__} is deprecated since version {version}."
            ]

            if reason:
                msg_parts.append(f"Reason: {reason}")

            if alternative:
                msg_parts.append(f"Use {alternative} instead.")

            if removal_version:
                msg_parts.append(f"Will be removed in version {removal_version}.")

            message = " ".join(msg_parts)

            # Выбор типа warning
            if level == DeprecationLevel.CRITICAL:
                warning_class = FutureWarning
                LOG.error(message)
            elif level == DeprecationLevel.WARNING:
                warning_class = DeprecationWarning
                LOG.warning(message)
            else:  # INFO
                warning_class = PendingDeprecationWarning
                LOG.info(message)

            # Показ warning
            warnings.warn(message, warning_class, stacklevel=2)

            # Вызов оригинальной функции
            return func(*args, **kwargs)

        # Добавление метаданных
        wrapper.__deprecated__ = True
        wrapper.__deprecation_info__ = {
            "reason": reason,
            "version": version,
            "removal_version": removal_version,
            "alternative": alternative,
            "level": level,
        }

        return wrapper

    return decorator


def deprecated_class(
    reason: str,
    version: str,
    removal_version: Optional[str] = None,
    alternative: Optional[str] = None,
    level: str = DeprecationLevel.WARNING,
) -> Callable:
    """
    Декоратор для пометки устаревших классов.

    Args:
        reason: Причина deprecation
        version: Версия, в которой помечено как deprecated
        removal_version: Версия, в которой будет удалено
        alternative: Рекомендуемая альтернатива
        level: Уровень серьезности

    Returns:
        Декоратор класса
    """

    def decorator(cls: type) -> type:
        original_init = cls.__init__

        @functools.wraps(original_init)
        def new_init(self, *args: Any, **kwargs: Any) -> None:
            # Формирование сообщения
            msg_parts = [f"{cls.__module__}.{cls.__name__} is deprecated since version {version}."]

            if reason:
                msg_parts.append(f"Reason: {reason}")

            if alternative:
                msg_parts.append(f"Use {alternative} instead.")

            if removal_version:
                msg_parts.append(f"Will be removed in version {removal_version}.")

            message = " ".join(msg_parts)

            # Выбор типа warning
            if level == DeprecationLevel.CRITICAL:
                warning_class = FutureWarning
                LOG.error(message)
            elif level == DeprecationLevel.WARNING:
                warning_class = DeprecationWarning
                LOG.warning(message)
            else:  # INFO
                warning_class = PendingDeprecationWarning
                LOG.info(message)

            warnings.warn(message, warning_class, stacklevel=2)

            # Вызов оригинального __init__
            original_init(self, *args, **kwargs)

        cls.__init__ = new_init

        # Добавление метаданных
        cls.__deprecated__ = True
        cls.__deprecation_info__ = {
            "reason": reason,
            "version": version,
            "removal_version": removal_version,
            "alternative": alternative,
            "level": level,
        }

        return cls

    return decorator


def deprecated_parameter(
    param_name: str,
    reason: str,
    version: str,
    removal_version: Optional[str] = None,
    alternative: Optional[str] = None,
) -> Callable:
    """
    Декоратор для пометки устаревших параметров функции.

    Args:
        param_name: Имя устаревшего параметра
        reason: Причина deprecation
        version: Версия, в которой помечено как deprecated
        removal_version: Версия, в которой будет удалено
        alternative: Рекомендуемая альтернатива

    Returns:
        Декоратор функции
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Проверка использования устаревшего параметра
            if param_name in kwargs:
                msg_parts = [
                    f"Parameter '{param_name}' of {func.__module__}.{func.__name__} "
                    f"is deprecated since version {version}."
                ]

                if reason:
                    msg_parts.append(f"Reason: {reason}")

                if alternative:
                    msg_parts.append(f"Use {alternative} instead.")

                if removal_version:
                    msg_parts.append(f"Will be removed in version {removal_version}.")

                message = " ".join(msg_parts)
                warnings.warn(message, DeprecationWarning, stacklevel=2)
                LOG.warning(message)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def warn_deprecated_import(
    old_path: str,
    new_path: str,
    version: str,
    removal_version: Optional[str] = None,
) -> None:
    """
    Предупреждение об устаревшем пути импорта.

    Args:
        old_path: Старый путь импорта
        new_path: Новый путь импорта
        version: Версия, в которой помечено как deprecated
        removal_version: Версия, в которой будет удалено
    """
    msg_parts = [
        f"Importing from '{old_path}' is deprecated since version {version}.",
        f"Use 'from {new_path}' instead.",
    ]

    if removal_version:
        msg_parts.append(f"Old import path will be removed in version {removal_version}.")

    message = " ".join(msg_parts)
    warnings.warn(message, DeprecationWarning, stacklevel=3)
    LOG.warning(message)


def is_deprecated(obj: Any) -> bool:
    """
    Проверка, помечен ли объект как deprecated.

    Args:
        obj: Объект для проверки (функция, класс, метод)

    Returns:
        True если deprecated, False иначе
    """
    return getattr(obj, "__deprecated__", False)


def get_deprecation_info(obj: Any) -> Optional[dict]:
    """
    Получение информации о deprecation.

    Args:
        obj: Объект для проверки

    Returns:
        Словарь с информацией о deprecation или None
    """
    return getattr(obj, "__deprecation_info__", None)


# Настройка warnings для показа deprecation warnings
def enable_deprecation_warnings() -> None:
    """Включить показ deprecation warnings."""
    warnings.filterwarnings("default", category=DeprecationWarning)
    warnings.filterwarnings("default", category=PendingDeprecationWarning)
    warnings.filterwarnings("default", category=FutureWarning)


def disable_deprecation_warnings() -> None:
    """Отключить показ deprecation warnings."""
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
    warnings.filterwarnings("ignore", category=FutureWarning)


# По умолчанию включаем warnings
enable_deprecation_warnings()
