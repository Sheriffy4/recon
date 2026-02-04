from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class LoggingConfig:
    # "DEBUG", "INFO", "WARNING", "ERROR"
    verbosity_level: str = "INFO"

    enable_conversion_logging: bool = True
    enable_deduplication: bool = True

    include_session_context: bool = True

    # Формат логов конверсии стратегий на INFO:
    #  - "INFO": краткий формат-строка
    #  - "DEBUG": подробности + многострочно
    conversion_log_format: str = "summary"  # "summary" or "detailed"

    def validate(self) -> "LoggingConfig":
        level = (self.verbosity_level or "INFO").upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            level = "INFO"
        self.verbosity_level = level

        if self.conversion_log_format not in {"summary", "detailed"}:
            self.conversion_log_format = "summary"
        return self
