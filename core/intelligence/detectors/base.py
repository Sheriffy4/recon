"""
Базовый интерфейс для детекторов паттернов блокировки
"""

from abc import ABC, abstractmethod
from typing import List


class BaseDetector(ABC):
    """Базовый класс для всех детекторов блокировок"""

    @abstractmethod
    async def detect(
        self, packets: List, domain: str, target_ip: str
    ) -> List:  # List[BlockingEvidence]
        """
        Детекция паттернов блокировки

        Args:
            packets: Список пакетов для анализа
            domain: Доменное имя
            target_ip: IP адрес цели

        Returns:
            Список найденных паттернов блокировки (BlockingEvidence)
        """
        raise NotImplementedError
