"""
Реестр детекторов паттернов блокировки

Управляет всеми детекторами и координирует процесс детекции.
"""

import logging
from typing import Any, Dict, List

from .base import BaseDetector
from .dns_detector import DNSDetector
from .rst_detector import RSTDetector
from .tls_detector import TLSDetector
from .http_detector import HTTPDetector
from .timeout_detector import TimeoutDetector

LOG = logging.getLogger("DetectorRegistry")


class DetectorRegistry:
    """
    Реестр и фабрика детекторов блокировок

    Управляет жизненным циклом детекторов и координирует
    процесс детекции паттернов блокировки.
    """

    def __init__(self):
        """Инициализация реестра с детекторами по умолчанию"""
        self._detectors: List[BaseDetector] = []
        self._detector_stats: Dict[str, Dict[str, Any]] = {}

        # Регистрируем детекторы по умолчанию
        self._register_default_detectors()

        LOG.info(f"✅ DetectorRegistry инициализирован с {len(self._detectors)} детекторами")

    def _register_default_detectors(self):
        """Регистрация детекторов по умолчанию"""
        self.register_detector(RSTDetector(), "rst_injections_found")
        self.register_detector(DNSDetector(), "dns_poisoning_found")
        self.register_detector(TLSDetector(), "tls_interrupts_found")
        self.register_detector(HTTPDetector(), "http_redirects_found")
        self.register_detector(TimeoutDetector(), "connection_timeouts_found")

    def register_detector(self, detector: BaseDetector, stat_key: str = None):
        """
        Регистрация нового детектора

        Args:
            detector: Экземпляр детектора
            stat_key: Ключ для статистики (опционально)
        """
        self._detectors.append(detector)

        if stat_key:
            detector_name = detector.__class__.__name__
            self._detector_stats[detector_name] = {
                "stat_key": stat_key,
                "detections": 0,
                "errors": 0,
            }

        LOG.debug(f"Зарегистрирован детектор: {detector.__class__.__name__}")

    def unregister_detector(self, detector_class: type):
        """
        Удаление детектора из реестра

        Args:
            detector_class: Класс детектора для удаления
        """
        self._detectors = [d for d in self._detectors if not isinstance(d, detector_class)]
        detector_name = detector_class.__name__
        if detector_name in self._detector_stats:
            del self._detector_stats[detector_name]

        LOG.debug(f"Удален детектор: {detector_name}")

    async def detect_all(
        self, packets: List, domain: str, target_ip: str
    ) -> List:  # List[BlockingEvidence]
        """
        Запуск всех зарегистрированных детекторов

        Args:
            packets: Список пакетов для анализа
            domain: Доменное имя
            target_ip: IP адрес цели

        Returns:
            Объединенный список найденных паттернов блокировки
        """
        all_evidence = []

        for detector in self._detectors:
            detector_name = detector.__class__.__name__

            try:
                LOG.debug(f"🔍 Запуск детектора: {detector_name}")
                evidence = await detector.detect(packets, domain, target_ip)

                if evidence:
                    all_evidence.extend(evidence)

                    # Обновляем статистику
                    if detector_name in self._detector_stats:
                        self._detector_stats[detector_name]["detections"] += len(evidence)

                    LOG.debug(f"✅ {detector_name}: найдено {len(evidence)} паттернов")

            except Exception as e:
                LOG.error(f"❌ Ошибка в детекторе {detector_name}: {e}", exc_info=True)

                # Обновляем статистику ошибок
                if detector_name in self._detector_stats:
                    self._detector_stats[detector_name]["errors"] += 1

        LOG.info(f"🎯 Детекция завершена: найдено {len(all_evidence)} паттернов")

        return all_evidence

    def get_detector_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Получение статистики по детекторам

        Returns:
            Словарь со статистикой каждого детектора
        """
        return {k: v.copy() for k, v in self._detector_stats.items()}

    def get_registered_detectors(self) -> List[str]:
        """
        Получение списка зарегистрированных детекторов

        Returns:
            Список имен детекторов
        """
        return [d.__class__.__name__ for d in self._detectors]

    def clear_stats(self):
        """Очистка статистики детекторов"""
        for stats in self._detector_stats.values():
            stats["detections"] = 0
            stats["errors"] = 0

        LOG.debug("Статистика детекторов очищена")
