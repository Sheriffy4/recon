"""
Enhanced Strategy Calibrator - расширение существующего калибратора с анализом неудач
Реализует требования FR-2, FR-4, FR-6 для адаптивной системы мониторинга
"""

import os
import time
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
import asyncio

# Интеграция с существующими модулями
try:
    from intelligent_bypass_monitor import StrategyCalibrator, BypassStrategy

    BASE_CALIBRATOR_AVAILABLE = True
except ImportError:
    BASE_CALIBRATOR_AVAILABLE = False

    # Fallback базовый класс
    class StrategyCalibrator:
        def __init__(self):
            self.bypass_engine = None
            self.attack_dispatcher = None


try:
    from core.strategy_failure_analyzer import (
        StrategyFailureAnalyzer,
        FailureReport,
        Strategy,
        TestResult,
        TrialArtifacts,
    )

    SFA_AVAILABLE = True
except ImportError:
    SFA_AVAILABLE = False

try:
    from core.fingerprint.dpi_fingerprint_service import DPIFingerprintService, DPIFingerprint

    DFS_AVAILABLE = True
except ImportError:
    DFS_AVAILABLE = False

# Интеграция с bypass engine
try:
    from core.bypass.engine.base_engine import WindowsBypassEngine
    from core.bypass.engine.attack_dispatcher import AttackDispatcher
    from core.bypass.attacks.attack_registry import get_attack_registry

    BYPASS_ENGINE_AVAILABLE = True
except ImportError:
    BYPASS_ENGINE_AVAILABLE = False

# Захват трафика
try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False

try:
    from scapy.all import sniff, wrpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG = logging.getLogger("EnhancedStrategyCalibrator")


@dataclass
class CalibrationBudget:
    """Бюджет для калибровки стратегий"""

    max_trials: int = 10
    max_time_seconds: int = 300
    stop_on_success: bool = True
    consumed_trials: int = 0
    start_time: datetime = field(default_factory=datetime.now)

    def is_exhausted(self) -> bool:
        """Проверка исчерпания бюджета"""
        if self.consumed_trials >= self.max_trials:
            return True

        elapsed = (datetime.now() - self.start_time).total_seconds()
        return elapsed >= self.max_time_seconds

    def consume_trial(self):
        """Потребление одной попытки"""
        self.consumed_trials += 1

    def remaining_trials(self) -> int:
        """Оставшиеся попытки"""
        return max(0, self.max_trials - self.consumed_trials)


@dataclass
class CalibrationResult:
    """Результат калибровки"""

    successful_strategies: List[BypassStrategy] = field(default_factory=list)
    total_trials: int = 0
    fingerprint_updated: bool = False
    execution_time_seconds: float = 0.0
    failure_reports: List[FailureReport] = field(default_factory=list)
    search_space_reduction: float = 0.0

    @property
    def success(self) -> bool:
        return len(self.successful_strategies) > 0


@dataclass
class EnhancedTestResult:
    """Расширенный результат тестирования с артефактами"""

    success: bool
    response_time: Optional[float] = None
    error: Optional[str] = None
    pcap_file: Optional[str] = None
    artifacts: Optional[TrialArtifacts] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrafficCapturer:
    """Захватчик трафика для анализа неудач"""

    def __init__(self, temp_dir: str = "temp_pcap"):
        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(exist_ok=True)
        self.capture_session = None
        self.capture_file = None

        # Проверка доступности инструментов захвата
        self.pydivert_available = PYDIVERT_AVAILABLE
        self.scapy_available = SCAPY_AVAILABLE

        if not (self.pydivert_available or self.scapy_available):
            LOG.warning("Инструменты захвата трафика недоступны - анализ неудач будет ограничен")

    async def start_capture(self, filter_expr: str = "tcp port 443") -> "CaptureSession":
        """Начало захвата трафика"""

        if not (self.pydivert_available or self.scapy_available):
            return DummyCaptureSession()

        # Генерируем уникальное имя файла
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.capture_file = self.temp_dir / f"capture_{timestamp}.pcap"

        LOG.info(f"Начало захвата трафика: {filter_expr} -> {self.capture_file}")

        if self.pydivert_available:
            return await self._start_pydivert_capture(filter_expr)
        elif self.scapy_available:
            return await self._start_scapy_capture(filter_expr)

        return DummyCaptureSession()

    async def _start_pydivert_capture(self, filter_expr: str) -> "PyDivertCaptureSession":
        """Захват с PyDivert"""
        try:
            # Конвертируем filter в WinDivert формат
            windivert_filter = self._convert_to_windivert_filter(filter_expr)

            session = PyDivertCaptureSession(
                filter_expr=windivert_filter, capture_file=str(self.capture_file)
            )
            await session.start()
            return session

        except Exception as e:
            LOG.error(f"Ошибка запуска PyDivert захвата: {e}")
            return DummyCaptureSession()

    async def _start_scapy_capture(self, filter_expr: str) -> "ScapyCaptureSession":
        """Захват с Scapy"""
        try:
            session = ScapyCaptureSession(
                filter_expr=filter_expr, capture_file=str(self.capture_file)
            )
            await session.start()
            return session

        except Exception as e:
            LOG.error(f"Ошибка запуска Scapy захвата: {e}")
            return DummyCaptureSession()

    def _convert_to_windivert_filter(self, tcpdump_filter: str) -> str:
        """Конвертация tcpdump фильтра в WinDivert формат"""
        # Простая конвертация основных фильтров
        conversions = {
            "tcp port 443": "tcp.DstPort == 443 or tcp.SrcPort == 443",
            "tcp port 80": "tcp.DstPort == 80 or tcp.SrcPort == 80",
            "tcp": "tcp",
        }

        return conversions.get(tcpdump_filter, "tcp")


class CaptureSession:
    """Базовый класс для сессии захвата"""

    def __init__(self, capture_file: str):
        self.capture_file = capture_file
        self.events = []
        self.is_active = False

    async def start(self):
        """Начало захвата"""
        self.is_active = True

    async def stop(self) -> str:
        """Остановка захвата и возврат файла"""
        self.is_active = False
        return self.capture_file


class DummyCaptureSession(CaptureSession):
    """Заглушка для случаев, когда захват недоступен"""

    def __init__(self):
        super().__init__("")

    async def stop(self) -> str:
        return ""


class PyDivertCaptureSession(CaptureSession):
    """Сессия захвата с PyDivert"""

    def __init__(self, filter_expr: str, capture_file: str):
        super().__init__(capture_file)
        self.filter_expr = filter_expr
        self.capture_task = None
        self.packets = []

    async def start(self):
        """Начало захвата с PyDivert"""
        await super().start()

        # Запускаем захват в отдельной задаче
        self.capture_task = asyncio.create_task(self._capture_loop())

    async def _capture_loop(self):
        """Основной цикл захвата"""
        try:
            with pydivert.WinDivert(self.filter_expr) as w:
                for packet in w:
                    if not self.is_active:
                        break

                    self.packets.append(packet)
                    self.events.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "size": len(packet.raw),
                            "direction": "inbound" if packet.is_inbound else "outbound",
                        }
                    )

                    # Пропускаем пакет дальше
                    w.send(packet)

        except Exception as e:
            LOG.error(f"Ошибка в цикле захвата PyDivert: {e}")

    async def stop(self) -> str:
        """Остановка захвата и сохранение в PCAP"""
        await super().stop()

        if self.capture_task:
            self.capture_task.cancel()
            try:
                await self.capture_task
            except asyncio.CancelledError:
                pass

        # Сохраняем пакеты в PCAP формат (упрощенно)
        if self.packets and SCAPY_AVAILABLE:
            try:
                from scapy.all import Ether, wrpcap

                scapy_packets = []

                for packet in self.packets:
                    # Конвертируем PyDivert пакет в Scapy
                    scapy_packet = Ether(packet.raw)
                    scapy_packets.append(scapy_packet)

                wrpcap(self.capture_file, scapy_packets)
                LOG.info(f"Сохранено {len(scapy_packets)} пакетов в {self.capture_file}")

            except Exception as e:
                LOG.error(f"Ошибка сохранения PCAP: {e}")

        return self.capture_file


class ScapyCaptureSession(CaptureSession):
    """Сессия захвата с Scapy"""

    def __init__(self, filter_expr: str, capture_file: str):
        super().__init__(capture_file)
        self.filter_expr = filter_expr
        self.capture_task = None
        self.packets = []

    async def start(self):
        """Начало захвата с Scapy"""
        await super().start()

        # Запускаем захват в отдельной задаче
        self.capture_task = asyncio.create_task(self._capture_loop())

    async def _capture_loop(self):
        """Основной цикл захвата"""
        try:

            def packet_handler(packet):
                if self.is_active:
                    self.packets.append(packet)
                    self.events.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "size": len(packet),
                            "protocol": packet.name if hasattr(packet, "name") else "unknown",
                        }
                    )

            # Запускаем sniff в отдельном потоке
            sniff(
                filter=self.filter_expr,
                prn=packet_handler,
                timeout=30,  # Максимум 30 секунд захвата
                store=False,
            )

        except Exception as e:
            LOG.error(f"Ошибка в цикле захвата Scapy: {e}")

    async def stop(self) -> str:
        """Остановка захвата и сохранение"""
        await super().stop()

        if self.capture_task:
            self.capture_task.cancel()
            try:
                await self.capture_task
            except asyncio.CancelledError:
                pass

        # Сохраняем пакеты
        if self.packets:
            try:
                wrpcap(self.capture_file, self.packets)
                LOG.info(f"Сохранено {len(self.packets)} пакетов в {self.capture_file}")
            except Exception as e:
                LOG.error(f"Ошибка сохранения PCAP: {e}")

        return self.capture_file


class EnhancedStrategyCalibrator(StrategyCalibrator):
    """
    Расширенный калибратор стратегий с анализом неудач и DPI fingerprinting.

    Основные улучшения:
    - Интеграция с StrategyFailureAnalyzer для анализа причин неудач
    - Использование DPIFingerprintService для накопления знаний о DPI
    - Захват PCAP во время тестирования для детального анализа
    - Система negative knowledge для избежания повторных ошибок
    - Сокращение пространства поиска на основе DPI характеристик
    """

    def __init__(self, temp_dir: str = "temp_pcap"):
        """
        Инициализация расширенного калибратора.

        Args:
            temp_dir: Директория для временных PCAP файлов
        """
        super().__init__()

        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(exist_ok=True)

        # Инициализация компонентов анализа
        self.failure_analyzer = None
        self.fingerprint_service = None
        self.traffic_capturer = None

        if SFA_AVAILABLE:
            self.failure_analyzer = StrategyFailureAnalyzer(str(self.temp_dir))
            LOG.info("✅ StrategyFailureAnalyzer инициализирован")
        else:
            LOG.warning("⚠️ StrategyFailureAnalyzer недоступен")

        if DFS_AVAILABLE:
            self.fingerprint_service = DPIFingerprintService("dpi_fingerprints.json")
            LOG.info("✅ DPIFingerprintService инициализирован")
        else:
            LOG.warning("⚠️ DPIFingerprintService недоступен")

        self.traffic_capturer = TrafficCapturer(str(self.temp_dir))

        # Negative knowledge - стратегии, которые точно не работают
        self.negative_knowledge = {}
        self._load_negative_knowledge()

        LOG.info("🚀 EnhancedStrategyCalibrator инициализирован")

    def _load_negative_knowledge(self):
        """Загрузка negative knowledge из файла"""
        nk_file = Path("negative_knowledge.json")

        if nk_file.exists():
            try:
                import json

                with open(nk_file, "r", encoding="utf-8") as f:
                    self.negative_knowledge = json.load(f)
                LOG.info(f"📚 Загружено {len(self.negative_knowledge)} записей negative knowledge")
            except Exception as e:
                LOG.error(f"Ошибка загрузки negative knowledge: {e}")
                self.negative_knowledge = {}
        else:
            self.negative_knowledge = {}

    def _save_negative_knowledge(self):
        """Сохранение negative knowledge в файл"""
        try:
            import json

            with open("negative_knowledge.json", "w", encoding="utf-8") as f:
                json.dump(self.negative_knowledge, f, indent=2, ensure_ascii=False)
        except Exception as e:
            LOG.error(f"Ошибка сохранения negative knowledge: {e}")

    async def calibrate_domain(self, domain: str, budget: CalibrationBudget) -> CalibrationResult:
        """
        Расширенная калибровка домена с адаптивной логикой и анализом неудач.

        Реализует требования FR-2 и FR-6:
        - Динамическое изменение стратегии тестирования на основе результатов
        - Раннюю остановку при обнаружении паттернов в неудачах
        - Систему обратной связи для улучшения генерации стратегий
        - Интеграцию с системой бюджетов для контроля времени тестирования

        Args:
            domain: Домен для калибровки
            budget: Бюджет калибровки (время, попытки)

        Returns:
            CalibrationResult с результатами калибровки
        """
        start_time = datetime.now()
        LOG.info(f"🎯 Начало адаптивной калибровки для {domain}")
        LOG.info(f"📊 Бюджет: {budget.max_trials} попыток, {budget.max_time_seconds}с")

        result = CalibrationResult()

        # Адаптивные переменные
        failure_pattern_detector = FailurePatternDetector()
        failure_pattern_detector.reset_patterns()  # Сброс паттернов для нового домена
        strategy_feedback_system = StrategyFeedbackSystem()
        adaptive_budget_manager = AdaptiveBudgetManager(budget)

        try:
            # Шаг 1: Получение или создание DPI fingerprint
            fingerprint = None
            if self.fingerprint_service:
                fingerprint = await self.fingerprint_service.get_or_create(domain)
                LOG.info(
                    f"🔍 DPI fingerprint: тип={fingerprint.dpi_type.value}, режим={fingerprint.dpi_mode.value}"
                )

            # Шаг 2: Генерация целевых стратегий (сокращенное пространство поиска)
            strategies = await self._generate_targeted_strategies(domain, fingerprint)

            # Шаг 3: Фильтрация на основе negative knowledge
            filtered_strategies = self._filter_negative_knowledge(strategies, domain)

            search_space_reduction = 1.0 - (len(filtered_strategies) / max(1, len(strategies)))
            result.search_space_reduction = search_space_reduction

            LOG.info(
                f"🎯 Сгенерировано {len(strategies)} стратегий, отфильтровано до {len(filtered_strategies)}"
            )
            LOG.info(f"📉 Сокращение пространства поиска: {search_space_reduction:.1%}")

            # Шаг 4: Адаптивное тестирование стратегий
            consecutive_failures = 0
            last_failure_causes = []

            for i, strategy in enumerate(filtered_strategies):
                # Проверка бюджета с адаптивным управлением
                if adaptive_budget_manager.should_stop(result):
                    LOG.info(f"⏰ Адаптивная остановка после {budget.consumed_trials} попыток")
                    break

                # Проверка паттернов неудач для ранней остановки
                if failure_pattern_detector.should_stop_early(
                    last_failure_causes, consecutive_failures
                ):
                    LOG.info(f"🛑 Ранняя остановка: обнаружен паттерн неудач")
                    break

                LOG.info(f"🧪 Тест {i+1}/{len(filtered_strategies)}: {strategy.name}")

                # Адаптивная настройка стратегии на основе предыдущих результатов
                adapted_strategy = strategy_feedback_system.adapt_strategy(
                    strategy, result.failure_reports
                )

                # Тестируем стратегию с захватом трафика
                test_result = await self._test_strategy_with_capture(domain, adapted_strategy)
                budget.consume_trial()
                result.total_trials += 1

                if test_result.success:
                    LOG.info(f"✅ Успешная стратегия: {adapted_strategy.name}")
                    result.successful_strategies.append(adapted_strategy)

                    # Сброс счетчика неудач
                    consecutive_failures = 0

                    # Обновляем fingerprint с успешным результатом
                    if self.fingerprint_service:
                        await self.fingerprint_service.add_attack_result(
                            domain, adapted_strategy.attack_type, adapted_strategy.parameters, True
                        )

                    # Обратная связь для улучшения генерации стратегий
                    strategy_feedback_system.record_success(adapted_strategy, test_result)

                    if budget.stop_on_success:
                        LOG.info("🎯 Остановка на первом успехе")
                        break
                else:
                    LOG.info(f"❌ Неудача: {adapted_strategy.name}")
                    consecutive_failures += 1

                    # Анализируем неудачу
                    failure_report = None
                    if self.failure_analyzer and test_result.pcap_file:
                        failure_report = await self._analyze_failure(
                            test_result.pcap_file, adapted_strategy, domain
                        )
                        result.failure_reports.append(failure_report)

                        # Добавляем причину неудачи для анализа паттернов
                        last_failure_causes.append(failure_report.root_cause)
                        if len(last_failure_causes) > 5:  # Храним только последние 5
                            last_failure_causes.pop(0)

                        # Обновляем fingerprint на основе анализа неудач
                        if self.fingerprint_service:
                            await self._update_fingerprint_from_failure(domain, failure_report)
                            result.fingerprint_updated = True

                        # Сохраняем negative knowledge
                        await self._save_negative_knowledge_entry(
                            domain, adapted_strategy, failure_report
                        )

                    # Обратная связь для улучшения генерации стратегий
                    strategy_feedback_system.record_failure(
                        adapted_strategy, test_result, failure_report
                    )

                    # Динамическая адаптация: генерируем новые стратегии на основе неудач
                    if consecutive_failures >= 3 and failure_report:
                        LOG.info("🔄 Генерация новых стратегий на основе анализа неудач")
                        LOG.info(f"   Причина последней неудачи: {failure_report.root_cause}")
                        LOG.info(f"   Уверенность в анализе: {failure_report.confidence:.2f}")

                        new_strategies = await self._generate_adaptive_strategies(
                            domain, fingerprint, failure_report, strategy_feedback_system
                        )

                        # Добавляем новые стратегии в очередь тестирования
                        if new_strategies:
                            filtered_strategies.extend(new_strategies)
                            strategy_names = [s.name for s in new_strategies]
                            LOG.info(
                                f"➕ Добавлено {len(new_strategies)} адаптивных стратегий: {', '.join(strategy_names)}"
                            )
                        else:
                            LOG.info("   Не удалось сгенерировать новые стратегии")

                # Адаптивное управление бюджетом
                adaptive_budget_manager.update_based_on_progress(result, consecutive_failures)

            # Финальная статистика
            execution_time = (datetime.now() - start_time).total_seconds()
            result.execution_time_seconds = execution_time

            # Расчет дополнительных метрик эффективности
            success_rate = len(result.successful_strategies) / max(1, result.total_trials)
            avg_time_per_trial = execution_time / max(1, result.total_trials)

            LOG.info(f"🏁 Адаптивная калибровка завершена за {execution_time:.1f}с")
            LOG.info(f"✅ Найдено {len(result.successful_strategies)} рабочих стратегий")
            LOG.info(f"📊 Проанализировано {len(result.failure_reports)} неудач")
            LOG.info(f"🔄 Последовательных неудач: {consecutive_failures}")
            LOG.info(f"📈 Успешность: {success_rate:.1%}")
            LOG.info(f"⏱️ Среднее время на попытку: {avg_time_per_trial:.1f}с")
            LOG.info(f"🎯 Сокращение пространства поиска: {result.search_space_reduction:.1%}")

            # Анализ эффективности адаптивных компонентов
            if (
                hasattr(failure_pattern_detector, "detected_patterns")
                and failure_pattern_detector.detected_patterns
            ):
                LOG.info(
                    f"🔍 Обнаружено паттернов неудач: {len(failure_pattern_detector.detected_patterns)}"
                )

            if (
                hasattr(strategy_feedback_system, "adaptation_history")
                and strategy_feedback_system.adaptation_history
            ):
                LOG.info(
                    f"🔧 Выполнено адаптаций стратегий: {len(strategy_feedback_system.adaptation_history)}"
                )

            # Сохраняем обратную связь для будущих калибровок
            strategy_feedback_system.save_feedback(domain)

            return result

        except Exception as e:
            LOG.error(f"❌ Ошибка калибровки: {e}")
            result.execution_time_seconds = (datetime.now() - start_time).total_seconds()
            return result

    async def _generate_targeted_strategies(
        self, domain: str, fingerprint: Optional[DPIFingerprint]
    ) -> List[BypassStrategy]:
        """Генерация целевых стратегий на основе DPI fingerprint"""

        strategies = []

        if not fingerprint:
            # Fallback к базовым стратегиям
            return await self._generate_basic_strategies(domain)

        # Генерируем стратегии на основе характеристик DPI
        if fingerprint.dpi_mode.value == "active_rst":
            # DPI инжектирует RST - используем TTL манипуляции
            strategies.extend(
                [
                    BypassStrategy(
                        name="fake_ttl_low",
                        attack_type="fake",
                        parameters={"split_pos": "sni", "ttl": 1, "fooling": "badseq"},
                        success_rate=0.0,
                        test_count=0,
                    ),
                    BypassStrategy(
                        name="disorder_badseq",
                        attack_type="disorder",
                        parameters={"split_pos": 3, "fooling": "badseq"},
                        success_rate=0.0,
                        test_count=0,
                    ),
                ]
            )

        if fingerprint.behavioral_signatures.get("sni_filtering"):
            # SNI фильтрация - скрываем SNI
            strategies.extend(
                [
                    BypassStrategy(
                        name="multisplit_sni",
                        attack_type="multisplit",
                        parameters={"split_count": 8, "split_pos": "sni"},
                        success_rate=0.0,
                        test_count=0,
                    ),
                    BypassStrategy(
                        name="fake_sni_split",
                        attack_type="fake",
                        parameters={"split_pos": "sni", "fooling": "badsum"},
                        success_rate=0.0,
                        test_count=0,
                    ),
                ]
            )

        if fingerprint.dpi_type.value == "stateless":
            # Stateless DPI - используем переупорядочивание
            strategies.append(
                BypassStrategy(
                    name="disorder_reorder",
                    attack_type="disorder",
                    parameters={"split_pos": 2, "fooling": "none"},
                    success_rate=0.0,
                    test_count=0,
                )
            )

        # Если нет специфичных стратегий, используем известные уязвимости
        if not strategies and fingerprint.known_weaknesses:
            for weakness in fingerprint.known_weaknesses:
                if "vulnerable_to_fake" in weakness:
                    strategies.append(
                        BypassStrategy(
                            name="fake_known_good",
                            attack_type="fake",
                            parameters={"split_pos": "sni", "ttl": 2},
                            success_rate=0.0,
                            test_count=0,
                        )
                    )

        # Если все еще нет стратегий, используем базовые
        if not strategies:
            strategies = await self._generate_basic_strategies(domain)

        return strategies

    async def _generate_basic_strategies(self, domain: str) -> List[BypassStrategy]:
        """Генерация базовых стратегий как fallback"""

        return [
            BypassStrategy(
                name="fake_basic",
                attack_type="fake",
                parameters={"split_pos": "sni", "ttl": 1, "fooling": "badseq"},
                success_rate=0.0,
                test_count=0,
            ),
            BypassStrategy(
                name="multisplit_basic",
                attack_type="multisplit",
                parameters={"split_count": 5, "split_pos": "sni"},
                success_rate=0.0,
                test_count=0,
            ),
            BypassStrategy(
                name="disorder_basic",
                attack_type="disorder",
                parameters={"split_pos": 3, "fooling": "badsum"},
                success_rate=0.0,
                test_count=0,
            ),
        ]

    def _filter_negative_knowledge(
        self, strategies: List[BypassStrategy], domain: str
    ) -> List[BypassStrategy]:
        """Фильтрация стратегий на основе negative knowledge"""

        if domain not in self.negative_knowledge:
            return strategies

        domain_nk = self.negative_knowledge[domain]
        filtered = []

        for strategy in strategies:
            # Создаем ключ для проверки
            strategy_key = (
                f"{strategy.attack_type}_{hash(str(sorted(strategy.parameters.items())))}"
            )

            if strategy_key not in domain_nk:
                filtered.append(strategy)
            else:
                LOG.debug(f"🚫 Пропуск стратегии из negative knowledge: {strategy.name}")

        return filtered

    async def _test_strategy_with_capture(
        self, domain: str, strategy: BypassStrategy
    ) -> EnhancedTestResult:
        """
        Тестирование стратегии с захватом PCAP для анализа неудач.

        Это ключевой метод, который интегрирует захват трафика в процесс тестирования.
        """
        LOG.info(f"🔬 Тестирование {strategy.name} с захватом трафика")

        # Начинаем захват трафика
        capture_session = await self.traffic_capturer.start_capture(
            filter_expr=f"host {domain} and port 443"
        )

        pcap_file = None
        artifacts = None

        try:
            # Даем время на инициализацию захвата
            await asyncio.sleep(0.1)

            # Инициализируем метаданные для измерения времени
            self._current_test_metadata = {}

            # Выполняем тест стратегии
            if self.bypass_engine and BYPASS_ENGINE_AVAILABLE:
                # Используем существующий bypass engine
                test_result = await self._test_with_bypass_engine(domain, strategy)
            else:
                # Fallback к простому HTTP тесту
                test_result = await self._test_with_http_fallback(domain, strategy)

            # Останавливаем захват и получаем файл
            pcap_file = await capture_session.stop()

            # Создаем артефакты
            test_metadata = {
                "strategy_name": strategy.name,
                "attack_type": strategy.attack_type,
                "parameters": strategy.parameters,
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
            }

            # Добавляем метаданные времени если они есть
            if hasattr(self, "_current_test_metadata"):
                test_metadata.update(self._current_test_metadata)

            artifacts = TrialArtifacts(
                pcap_file=pcap_file if pcap_file else None,
                engine_logs=[],
                network_events=capture_session.events,
                test_metadata=test_metadata,
            )

            # Измеряем время ответа
            response_time = None
            if test_result and artifacts and artifacts.test_metadata:
                start_time = artifacts.test_metadata.get("start_time")
                end_time = artifacts.test_metadata.get("end_time")
                if start_time and end_time:
                    response_time = end_time - start_time

            return EnhancedTestResult(
                success=test_result,
                response_time=response_time,
                error=None if test_result else "Strategy failed",
                pcap_file=pcap_file,
                artifacts=artifacts,
            )

        except Exception as e:
            LOG.error(f"Ошибка тестирования стратегии: {e}")

            # Все равно останавливаем захват
            try:
                pcap_file = await capture_session.stop()
            except:
                pass

            return EnhancedTestResult(
                success=False, error=str(e), pcap_file=pcap_file, artifacts=artifacts
            )

    async def _test_with_bypass_engine(self, domain: str, strategy: BypassStrategy) -> bool:
        """Тестирование с использованием bypass engine"""
        try:
            # Интеграция с существующим bypass engine
            # Это упрощенная версия - в реальности нужна более глубокая интеграция

            import requests
            import time

            # Применяем стратегию (здесь должна быть интеграция с bypass engine)
            # Пока делаем простой HTTP запрос как placeholder

            start_time = time.time()
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=False, verify=False)
            end_time = time.time()

            # Сохраняем время для измерения производительности
            if hasattr(self, "_current_test_metadata"):
                self._current_test_metadata["start_time"] = start_time
                self._current_test_metadata["end_time"] = end_time

            # Любой HTTP ответ считаем успехом
            return response.status_code in [200, 301, 302, 304, 403, 404]

        except Exception as e:
            LOG.debug(f"Bypass engine тест неудачен: {e}")
            return False

    async def _test_with_http_fallback(self, domain: str, strategy: BypassStrategy) -> bool:
        """Fallback тестирование с простым HTTP запросом"""
        try:
            import requests
            import time

            start_time = time.time()
            url = f"https://{domain}"
            response = requests.get(url, timeout=5, allow_redirects=False, verify=False)
            end_time = time.time()

            # Сохраняем время для измерения производительности
            if hasattr(self, "_current_test_metadata"):
                self._current_test_metadata["start_time"] = start_time
                self._current_test_metadata["end_time"] = end_time

            return response.status_code in [200, 301, 302, 304, 403, 404]

        except Exception as e:
            LOG.debug(f"HTTP fallback тест неудачен: {e}")
            return False

    async def _analyze_failure(
        self, pcap_file: str, strategy: BypassStrategy, domain: str
    ) -> FailureReport:
        """Анализ неудачи стратегии"""

        if not self.failure_analyzer:
            # Создаем простой отчет без детального анализа
            return FailureReport(
                strategy_id=strategy.name,
                domain=domain,
                analyzed_at=datetime.now(),
                root_cause="unknown",
                root_cause_details="Анализатор неудач недоступен",
                confidence=0.0,
            )

        # Конвертируем BypassStrategy в Strategy для анализатора
        analyzer_strategy = Strategy(
            name=strategy.name,
            attack_name=strategy.attack_type,
            parameters=strategy.parameters,
            id=strategy.name,
        )

        return await self.failure_analyzer.analyze_pcap(pcap_file, analyzer_strategy)

    async def _update_fingerprint_from_failure(self, domain: str, failure_report: FailureReport):
        """Обновление DPI fingerprint на основе анализа неудач"""

        if not self.fingerprint_service:
            return

        # Конвертируем FailureReport в формат для DPIFingerprintService
        failure_data = {
            "root_cause": (
                failure_report.root_cause.value
                if hasattr(failure_report.root_cause, "value")
                else str(failure_report.root_cause)
            ),
            "confidence": failure_report.confidence,
            "block_timing": failure_report.block_timing,
            "failure_details": failure_report.failure_details,
        }

        self.fingerprint_service.update_from_failure(domain, failure_data)
        LOG.info(f"🔄 Обновлен DPI fingerprint для {domain} на основе анализа неудач")

    async def _save_negative_knowledge_entry(
        self, domain: str, strategy: BypassStrategy, failure_report: FailureReport
    ):
        """Сохранение записи в negative knowledge"""

        if domain not in self.negative_knowledge:
            self.negative_knowledge[domain] = {}

        # Создаем ключ стратегии
        strategy_key = f"{strategy.attack_type}_{hash(str(sorted(strategy.parameters.items())))}"

        # Сохраняем информацию о неудаче
        self.negative_knowledge[domain][strategy_key] = {
            "strategy_name": strategy.name,
            "attack_type": strategy.attack_type,
            "parameters": strategy.parameters,
            "failure_cause": (
                failure_report.root_cause.value
                if hasattr(failure_report.root_cause, "value")
                else str(failure_report.root_cause)
            ),
            "confidence": failure_report.confidence,
            "failed_at": datetime.now().isoformat(),
        }

        # Сохраняем в файл
        self._save_negative_knowledge()

        LOG.info(f"📚 Добавлена запись в negative knowledge: {domain} -> {strategy.name}")

    async def _generate_adaptive_strategies(
        self,
        domain: str,
        fingerprint: Optional[DPIFingerprint],
        failure_report: FailureReport,
        feedback_system: "StrategyFeedbackSystem",
    ) -> List[BypassStrategy]:
        """
        Генерация новых стратегий на основе анализа неудач.
        Реализует динамическое изменение стратегии тестирования.
        """
        adaptive_strategies = []

        # Получаем рекомендации от анализатора неудач
        if self.failure_analyzer:
            recommendations = self.failure_analyzer.generate_recommendations(failure_report)

            for rec in recommendations[:3]:  # Берем топ-3 рекомендации
                if rec.action.startswith("apply_intent_"):
                    intent_key = rec.action.replace("apply_intent_", "")

                    # Создаем стратегию на основе Intent'а
                    strategy = self._create_strategy_from_intent(intent_key, rec.parameters)
                    if strategy:
                        adaptive_strategies.append(strategy)

        # Генерируем стратегии на основе обратной связи
        feedback_strategies = feedback_system.suggest_strategies(failure_report)
        adaptive_strategies.extend(feedback_strategies)

        return adaptive_strategies

    def _create_strategy_from_intent(
        self, intent_key: str, parameters: Dict[str, Any]
    ) -> Optional[BypassStrategy]:
        """Создание стратегии на основе Intent'а"""

        intent_to_strategy = {
            "short_ttl_decoy": {
                "attack_type": "fake",
                "base_params": {"ttl": 1, "fooling": "badseq", "split_pos": "sni"},
            },
            "conceal_sni": {
                "attack_type": "multisplit",
                "base_params": {"split_count": 8, "split_pos": "sni"},
            },
            "record_fragmentation": {
                "attack_type": "multisplit",
                "base_params": {"split_count": 10, "split_pos": "random"},
            },
            "packet_reordering": {
                "attack_type": "disorder",
                "base_params": {"split_pos": 2, "fooling": "none"},
            },
            "sequence_overlap": {
                "attack_type": "disorder",
                "base_params": {"split_pos": 3, "fooling": "badseq"},
            },
        }

        strategy_config = intent_to_strategy.get(intent_key)
        if not strategy_config:
            return None

        # Объединяем базовые параметры с параметрами из рекомендации
        final_params = strategy_config["base_params"].copy()
        final_params.update(parameters)

        return BypassStrategy(
            name=f"adaptive_{intent_key}",
            attack_type=strategy_config["attack_type"],
            parameters=final_params,
            success_rate=0.0,
            test_count=0,
        )


class FailurePatternDetector:
    """Детектор паттернов неудач для ранней остановки"""

    def __init__(self):
        self.failure_threshold = 5  # Остановка после 5 одинаковых неудач подряд
        self.pattern_threshold = 3  # Минимум 3 неудачи для определения паттерна
        self.detected_patterns = {}  # Кэш обнаруженных паттернов

    def should_stop_early(self, failure_causes: List, consecutive_failures: int) -> bool:
        """
        Определяет, нужно ли остановить тестирование досрочно.
        Реализует раннюю остановку при обнаружении паттернов в неудачах.

        Args:
            failure_causes: Список последних причин неудач
            consecutive_failures: Количество последовательных неудач

        Returns:
            True если нужно остановить тестирование
        """
        # Остановка при слишком многих последовательных неудачах
        if consecutive_failures >= self.failure_threshold:
            LOG.info(f"🛑 Слишком много последовательных неудач: {consecutive_failures}")
            return True

        # Остановка при обнаружении повторяющегося паттерна неудач
        if len(failure_causes) >= self.pattern_threshold:
            # Проверяем различные типы паттернов

            # Паттерн 1: Все последние неудачи имеют одинаковую причину
            recent_causes = failure_causes[-self.pattern_threshold :]
            if len(set(str(cause) for cause in recent_causes)) == 1:
                pattern_key = f"same_cause_{recent_causes[0]}"
                if pattern_key not in self.detected_patterns:
                    self.detected_patterns[pattern_key] = 1
                    LOG.info(f"🛑 Обнаружен паттерн одинаковых неудач: {recent_causes[0]}")
                    return True

            # Паттерн 2: Циклический паттерн неудач (A-B-A-B)
            if len(failure_causes) >= 4:
                last_four = failure_causes[-4:]
                if (
                    str(last_four[0]) == str(last_four[2])
                    and str(last_four[1]) == str(last_four[3])
                    and str(last_four[0]) != str(last_four[1])
                ):
                    pattern_key = f"cycle_{last_four[0]}_{last_four[1]}"
                    if pattern_key not in self.detected_patterns:
                        self.detected_patterns[pattern_key] = 1
                        LOG.info(
                            f"🛑 Обнаружен циклический паттерн неудач: {last_four[0]} ↔ {last_four[1]}"
                        )
                        return True

            # Паттерн 3: Доминирующая причина неудач (>80% последних неудач)
            if len(failure_causes) >= 5:
                cause_counts = {}
                for cause in failure_causes[-5:]:
                    cause_str = str(cause)
                    cause_counts[cause_str] = cause_counts.get(cause_str, 0) + 1

                max_count = max(cause_counts.values())
                if max_count >= 4:  # 4 из 5 последних неудач
                    dominant_cause = max(cause_counts.keys(), key=lambda k: cause_counts[k])
                    pattern_key = f"dominant_{dominant_cause}"
                    if pattern_key not in self.detected_patterns:
                        self.detected_patterns[pattern_key] = 1
                        LOG.info(
                            f"🛑 Обнаружена доминирующая причина неудач: {dominant_cause} ({max_count}/5)"
                        )
                        return True

        return False

    def reset_patterns(self):
        """Сброс обнаруженных паттернов для нового домена"""
        self.detected_patterns.clear()


class StrategyFeedbackSystem:
    """Система обратной связи для улучшения генерации стратегий"""

    def __init__(self):
        self.success_patterns = {}  # Паттерны успешных стратегий
        self.failure_patterns = {}  # Паттерны неудачных стратегий
        self.adaptation_history = []  # История адаптаций

    def adapt_strategy(
        self, strategy: BypassStrategy, failure_reports: List[FailureReport]
    ) -> BypassStrategy:
        """
        Адаптирует стратегию на основе предыдущих неудач.

        Args:
            strategy: Исходная стратегия
            failure_reports: Список отчетов о неудачах

        Returns:
            Адаптированная стратегия
        """
        if not failure_reports:
            return strategy

        # Создаем копию стратегии для адаптации
        adapted_params = strategy.parameters.copy()
        adaptations_made = []

        # Анализируем последние неудачи для адаптации параметров
        for report in failure_reports[-3:]:  # Последние 3 неудачи

            # Адаптация для RST инъекций
            if "rst_injection" in str(report.root_cause):
                if strategy.attack_type == "fake" and "ttl" in adapted_params:
                    # Увеличиваем TTL если предыдущий был слишком низкий
                    current_ttl = adapted_params.get("ttl", 1)
                    adapted_params["ttl"] = min(5, current_ttl + 1)
                    adaptations_made.append(f"ttl: {current_ttl} -> {adapted_params['ttl']}")

            # Адаптация для фрагментации
            elif "reassembles_fragments" in str(report.root_cause):
                if strategy.attack_type == "multisplit" and "split_count" in adapted_params:
                    # Увеличиваем количество фрагментов
                    current_count = adapted_params.get("split_count", 5)
                    adapted_params["split_count"] = min(20, current_count * 2)
                    adaptations_made.append(
                        f"split_count: {current_count} -> {adapted_params['split_count']}"
                    )

            # Адаптация для SNI фильтрации
            elif "sni_filtering" in str(report.root_cause):
                if "split_pos" in adapted_params and adapted_params["split_pos"] != "sni":
                    adapted_params["split_pos"] = "sni"
                    adaptations_made.append("split_pos -> sni")

        # Создаем адаптированную стратегию
        if adaptations_made:
            adapted_strategy = BypassStrategy(
                name=f"{strategy.name}_adapted",
                attack_type=strategy.attack_type,
                parameters=adapted_params,
                success_rate=strategy.success_rate,
                test_count=strategy.test_count,
            )

            LOG.info(f"🔧 Адаптирована стратегия {strategy.name}: {', '.join(adaptations_made)}")

            # Записываем историю адаптации
            self.adaptation_history.append(
                {
                    "original_strategy": strategy.name,
                    "adapted_strategy": adapted_strategy.name,
                    "adaptations": adaptations_made,
                    "timestamp": datetime.now().isoformat(),
                }
            )

            return adapted_strategy

        return strategy

    def record_success(self, strategy: BypassStrategy, test_result: EnhancedTestResult):
        """Записывает успешную стратегию для анализа паттернов"""

        strategy_key = f"{strategy.attack_type}_{strategy.name}"

        if strategy_key not in self.success_patterns:
            self.success_patterns[strategy_key] = {
                "count": 0,
                "parameters": [],
                "response_times": [],
            }

        self.success_patterns[strategy_key]["count"] += 1
        self.success_patterns[strategy_key]["parameters"].append(strategy.parameters.copy())

        if test_result.response_time:
            self.success_patterns[strategy_key]["response_times"].append(test_result.response_time)

    def record_failure(
        self,
        strategy: BypassStrategy,
        test_result: EnhancedTestResult,
        failure_report: Optional[FailureReport],
    ):
        """Записывает неудачную стратегию для анализа паттернов"""

        strategy_key = f"{strategy.attack_type}_{strategy.name}"

        if strategy_key not in self.failure_patterns:
            self.failure_patterns[strategy_key] = {
                "count": 0,
                "failure_causes": [],
                "parameters": [],
            }

        self.failure_patterns[strategy_key]["count"] += 1
        self.failure_patterns[strategy_key]["parameters"].append(strategy.parameters.copy())

        if failure_report:
            self.failure_patterns[strategy_key]["failure_causes"].append(
                str(failure_report.root_cause)
            )

    def suggest_strategies(self, failure_report: FailureReport) -> List[BypassStrategy]:
        """
        Предлагает новые стратегии на основе накопленной обратной связи.
        Реализует систему обратной связи для улучшения генерации стратегий.
        """
        suggestions = []

        # Анализируем успешные паттерны для похожих случаев
        for strategy_key, pattern in self.success_patterns.items():
            if pattern["count"] >= 2:  # Стратегия была успешной минимум 2 раза

                # Берем наиболее частые параметры
                if pattern["parameters"]:
                    # Анализируем параметры для поиска оптимальных значений
                    optimal_params = self._find_optimal_parameters(pattern["parameters"])

                    attack_type = strategy_key.split("_")[0]

                    suggestion = BypassStrategy(
                        name=f"feedback_{strategy_key}",
                        attack_type=attack_type,
                        parameters=optimal_params,
                        success_rate=pattern["count"]
                        / (pattern["count"] + 1),  # Приблизительная оценка
                        test_count=0,
                    )

                    suggestions.append(suggestion)

        # Генерируем контр-стратегии на основе анализа неудач
        counter_strategies = self._generate_counter_strategies(failure_report)
        suggestions.extend(counter_strategies)

        # Ранжируем предложения по вероятности успеха
        suggestions.sort(key=lambda s: s.success_rate, reverse=True)

        return suggestions[:3]  # Максимум 3 предложения

    def _find_optimal_parameters(self, parameter_history: List[Dict]) -> Dict:
        """Находит оптимальные параметры на основе истории успехов"""
        if not parameter_history:
            return {}

        # Анализируем частоту использования каждого параметра
        param_frequency = {}

        for params in parameter_history:
            for key, value in params.items():
                if key not in param_frequency:
                    param_frequency[key] = {}

                value_str = str(value)
                if value_str not in param_frequency[key]:
                    param_frequency[key][value_str] = 0
                param_frequency[key][value_str] += 1

        # Выбираем наиболее частые значения для каждого параметра
        optimal_params = {}
        for param_name, value_counts in param_frequency.items():
            most_common_value = max(value_counts.keys(), key=lambda v: value_counts[v])

            # Пытаемся конвертировать обратно в исходный тип
            try:
                if most_common_value.isdigit():
                    optimal_params[param_name] = int(most_common_value)
                elif most_common_value.replace(".", "").isdigit():
                    optimal_params[param_name] = float(most_common_value)
                else:
                    optimal_params[param_name] = most_common_value
            except:
                optimal_params[param_name] = most_common_value

        return optimal_params

    def _generate_counter_strategies(self, failure_report: FailureReport) -> List[BypassStrategy]:
        """Генерирует контр-стратегии на основе анализа неудач"""
        counter_strategies = []

        # Анализируем причину неудачи и предлагаем противоположные подходы
        failure_cause = str(failure_report.root_cause)

        if "rst_injection" in failure_cause.lower():
            # Если DPI инжектирует RST, пробуем стратегии с низким TTL
            counter_strategies.append(
                BypassStrategy(
                    name="counter_rst_low_ttl",
                    attack_type="fake",
                    parameters={"ttl": 1, "fooling": "badseq", "split_pos": "sni"},
                    success_rate=0.6,  # Высокая вероятность для контр-стратегии
                    test_count=0,
                )
            )

        elif "reassembles_fragments" in failure_cause.lower():
            # Если DPI собирает фрагменты, увеличиваем их количество
            counter_strategies.append(
                BypassStrategy(
                    name="counter_reassembly_multisplit",
                    attack_type="multisplit",
                    parameters={"split_count": 15, "split_pos": "random"},
                    success_rate=0.5,
                    test_count=0,
                )
            )

        elif "sni_filtering" in failure_cause.lower():
            # Если DPI фильтрует SNI, используем обфускацию
            counter_strategies.append(
                BypassStrategy(
                    name="counter_sni_obfuscation",
                    attack_type="fake",
                    parameters={"split_pos": "sni", "fooling": "badsum"},
                    success_rate=0.7,
                    test_count=0,
                )
            )

        elif "stateful_tracking" in failure_cause.lower():
            # Если DPI отслеживает состояние, используем переупорядочивание
            counter_strategies.append(
                BypassStrategy(
                    name="counter_stateful_disorder",
                    attack_type="disorder",
                    parameters={"split_pos": 2, "fooling": "none"},
                    success_rate=0.4,
                    test_count=0,
                )
            )

        return counter_strategies

    def save_feedback(self, domain: str):
        """Сохраняет накопленную обратную связь для будущих калибровок"""

        feedback_data = {
            "domain": domain,
            "success_patterns": self.success_patterns,
            "failure_patterns": self.failure_patterns,
            "adaptation_history": self.adaptation_history,
            "saved_at": datetime.now().isoformat(),
        }

        try:
            import json

            feedback_file = Path(f"strategy_feedback_{domain.replace('.', '_')}.json")

            with open(feedback_file, "w", encoding="utf-8") as f:
                json.dump(feedback_data, f, indent=2, ensure_ascii=False)

            LOG.info(f"💾 Сохранена обратная связь для {domain}")

        except Exception as e:
            LOG.error(f"Ошибка сохранения обратной связи: {e}")


class AdaptiveBudgetManager:
    """Адаптивное управление бюджетом тестирования"""

    def __init__(self, budget: CalibrationBudget):
        self.original_budget = budget
        self.efficiency_threshold = 0.2  # Минимальная эффективность для продолжения
        self.time_extension_factor = 1.2  # Коэффициент продления времени при успехах

    def should_stop(self, result: CalibrationResult) -> bool:
        """
        Определяет, нужно ли остановить тестирование на основе адаптивной логики.

        Args:
            result: Текущие результаты калибровки

        Returns:
            True если нужно остановить тестирование
        """
        # Базовая проверка бюджета
        if self.original_budget.is_exhausted():
            return True

        # Адаптивная логика: если есть успехи, можем продлить время
        if result.successful_strategies and result.total_trials > 0:
            success_rate = len(result.successful_strategies) / result.total_trials

            # Если успешность высокая, продлеваем время
            if success_rate > 0.5:
                remaining_time = (
                    self.original_budget.max_time_seconds
                    - (datetime.now() - self.original_budget.start_time).total_seconds()
                )

                if remaining_time > 0:
                    # Виртуально продлеваем время
                    extended_time = remaining_time * self.time_extension_factor
                    LOG.info(
                        f"⏰ Продление времени тестирования: +{extended_time - remaining_time:.1f}с"
                    )
                    return False

        # Остановка при низкой эффективности
        if result.total_trials >= 5:  # Минимум 5 попыток для оценки эффективности
            efficiency = len(result.successful_strategies) / result.total_trials

            if efficiency < self.efficiency_threshold:
                LOG.info(f"📉 Низкая эффективность тестирования: {efficiency:.1%}")
                return True

        return False

    def update_based_on_progress(self, result: CalibrationResult, consecutive_failures: int):
        """
        Обновляет бюджет на основе прогресса тестирования.
        Реализует динамическое управление ресурсами на основе результатов.

        Args:
            result: Текущие результаты
            consecutive_failures: Количество последовательных неудач
        """
        # Анализируем эффективность текущего подхода
        if result.total_trials > 0:
            success_rate = len(result.successful_strategies) / result.total_trials

            # Сокращаем бюджет при многих последовательных неудачах
            if consecutive_failures >= 4:
                # Сокращаем оставшиеся попытки
                remaining_trials = self.original_budget.remaining_trials()
                if remaining_trials > 2:
                    reduction = min(2, remaining_trials // 2)
                    self.original_budget.max_trials -= reduction
                    LOG.info(f"📉 Сокращение бюджета на {reduction} попыток из-за неудач")

            # Увеличиваем бюджет при успехах и хорошей эффективности
            elif result.successful_strategies and consecutive_failures == 0:
                # Небольшое увеличение попыток при успехах
                if self.original_budget.remaining_trials() < 3 and success_rate > 0.3:
                    self.original_budget.max_trials += 1
                    LOG.info("📈 Увеличение бюджета на 1 попытку из-за успеха")

            # Адаптивное управление временем на основе прогресса
            elapsed_time = (datetime.now() - self.original_budget.start_time).total_seconds()
            time_per_trial = elapsed_time / result.total_trials if result.total_trials > 0 else 0

            # Если тесты выполняются быстро и есть успехи, можем продлить время
            if time_per_trial < 10 and success_rate > 0.2:  # Быстрые тесты и есть успехи
                remaining_time = self.original_budget.max_time_seconds - elapsed_time
                if remaining_time > 0 and remaining_time < 60:  # Осталось меньше минуты
                    extension = min(30, time_per_trial * 3)  # Продлеваем на 3 быстрых теста
                    self.original_budget.max_time_seconds += extension
                    LOG.info(f"⏰ Продление времени на {extension:.1f}с из-за быстрого прогресса")

            # Сокращаем время при очень медленных тестах без результата
            elif time_per_trial > 30 and success_rate == 0 and result.total_trials >= 3:
                reduction = min(60, self.original_budget.max_time_seconds * 0.2)
                self.original_budget.max_time_seconds -= reduction
                LOG.info(f"⏰ Сокращение времени на {reduction:.1f}с из-за медленного прогресса")


# Удобные функции для использования
async def calibrate_domain_enhanced(
    domain: str, max_trials: int = 10, max_time: int = 300, stop_on_success: bool = True
) -> CalibrationResult:
    """
    Удобная функция для расширенной калибровки домена.

    Args:
        domain: Домен для калибровки
        max_trials: Максимальное количество попыток
        max_time: Максимальное время в секундах
        stop_on_success: Остановиться на первом успехе

    Returns:
        CalibrationResult с результатами
    """
    calibrator = EnhancedStrategyCalibrator()

    budget = CalibrationBudget(
        max_trials=max_trials, max_time_seconds=max_time, stop_on_success=stop_on_success
    )

    return await calibrator.calibrate_domain(domain, budget)


def create_enhanced_calibrator(temp_dir: str = "temp_pcap") -> EnhancedStrategyCalibrator:
    """Фабричная функция для создания расширенного калибратора"""
    return EnhancedStrategyCalibrator(temp_dir=temp_dir)


# Пример использования
if __name__ == "__main__":

    async def main():
        # Создаем калибратор
        calibrator = EnhancedStrategyCalibrator()

        # Настраиваем бюджет
        budget = CalibrationBudget(max_trials=5, max_time_seconds=120, stop_on_success=True)

        # Калибруем домен
        result = await calibrator.calibrate_domain("example.com", budget)

        print(f"Результат калибровки:")
        print(f"- Успешных стратегий: {len(result.successful_strategies)}")
        print(f"- Всего попыток: {result.total_trials}")
        print(f"- Время выполнения: {result.execution_time_seconds:.1f}с")
        print(f"- Сокращение пространства поиска: {result.search_space_reduction:.1%}")
        print(f"- Fingerprint обновлен: {result.fingerprint_updated}")

    # Запуск примера
    import asyncio

    asyncio.run(main())
