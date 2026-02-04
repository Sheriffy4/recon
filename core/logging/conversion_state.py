from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Set


@dataclass
class ConversionState:
    logged_strategies: Set[str] = field(default_factory=set)
    session_start_time: datetime = field(default_factory=datetime.utcnow)
    conversion_count: int = 0
    last_log_time: datetime = field(default_factory=datetime.utcnow)
