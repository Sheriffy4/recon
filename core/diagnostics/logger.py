# recon/core/diagnostics/logger.py
import logging
import sys

# Проверяем, доступна ли библиотека rich для красивого вывода
try:
    from rich.logging import RichHandler

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Глобальный флаг, чтобы гарантировать, что корневой логгер настраивается только один раз
_is_configured = False


def get_logger(name: str, debug: bool = False) -> logging.Logger:
    """
    Создает и настраивает экземпляр логгера.

    Args:
        name: Имя логгера (обычно __name__).
        debug: Если True, устанавливает уровень логирования на DEBUG.

    Returns:
        Настроенный экземпляр logging.Logger.
    """
    global _is_configured
    logger = logging.getLogger(name)

    # Устанавливаем уровень в зависимости от флага debug
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)

    # Настраиваем обработчик корневого логгера только один раз, чтобы избежать дублирования сообщений
    if not _is_configured:
        # Если rich доступен, используем его обработчик для красивого форматирования
        if RICH_AVAILABLE:
            handler = RichHandler(
                rich_tracebacks=True,
                show_path=False,  # Для чистоты вывода
                log_time_format="[%H:%M:%S]",
            )
            formatter = logging.Formatter("%(message)s")  # Rich позаботится об остальном
        else:
            # Стандартный обработчик в качестве запасного варианта
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )

        handler.setFormatter(formatter)

        # Очищаем существующие обработчики и добавляем новый
        # Это важно, чтобы избежать дублирования вывода при запуске в интерактивной сессии
        root_logger = logging.getLogger()
        if root_logger.hasHandlers():
            root_logger.handlers.clear()
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.INFO)  # Устанавливаем базовый уровень для корневого логгера

        _is_configured = True

    # Убеждаемся, что у конкретного логгера правильный уровень
    logger.setLevel(level)

    return logger
