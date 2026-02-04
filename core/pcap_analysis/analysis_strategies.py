"""
Analysis Strategies - Strategy pattern for PCAP analysis methods.

This module implements different analysis strategies for PCAP files:
- Scapy-based analysis (full packet inspection)
- JSON converter analysis (lightweight)
- Fallback analysis (minimal dependencies)

Requirements: FR-13.1, FR-13.2
"""

import os
import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass

# Попытка импорта Scapy
try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Интеграция с JSON конвертером
try:
    from ...pcap_to_json_analyzer import analyze_pcap

    PCAP_JSON_AVAILABLE = True
except ImportError:
    PCAP_JSON_AVAILABLE = False

from .flow_analyzer import FlowAnalyzer, FlowAnalysis
from .blocking_analyzer import BlockingAnalyzer
from .signature_extractor import DPISignatureExtractor, DPISignature

LOG = logging.getLogger("AnalysisStrategies")


@dataclass
class AnalysisContext:
    """Контекст для анализа PCAP файла."""

    pcap_file: str
    max_packets_to_analyze: int
    enable_signature_extraction: bool
    flow_analyzer: FlowAnalyzer
    blocking_analyzer: BlockingAnalyzer
    signature_extractor: DPISignatureExtractor


class AnalysisStrategy:
    """Базовый класс для стратегий анализа."""

    def __init__(self, context: AnalysisContext):
        """
        Инициализация стратегии.

        Args:
            context: Контекст анализа
        """
        self.context = context

    async def analyze(self) -> Dict[str, Any]:
        """
        Выполнение анализа.

        Returns:
            Словарь с результатами анализа

        Raises:
            NotImplementedError: Должен быть реализован в подклассах
        """
        raise NotImplementedError("Subclasses must implement analyze()")

    def _create_base_result(self, **kwargs) -> Dict[str, Any]:
        """Создание базового результата анализа."""
        return {
            "pcap_file": self.context.pcap_file,
            "analysis_timestamp": datetime.now(),
            "total_packets": kwargs.get("total_packets", 0),
            "total_flows": kwargs.get("total_flows", 0),
            "flows": kwargs.get("flows", []),
            "dpi_signatures": kwargs.get("dpi_signatures", []),
            "blocking_evidence": kwargs.get("blocking_evidence", {}),
            "bypass_recommendations": kwargs.get("bypass_recommendations", []),
            "technical_details": kwargs.get("technical_details", {}),
        }


class ScapyAnalysisStrategy(AnalysisStrategy):
    """Стратегия анализа с использованием Scapy."""

    async def analyze(self) -> Dict[str, Any]:
        """Анализ с использованием Scapy."""
        try:
            # Загрузка пакетов
            # NOTE: rdpcap() is blocking; run it off the event loop
            packets = await asyncio.to_thread(rdpcap, self.context.pcap_file)
            total_packets = len(packets)

            # Ограничение количества пакетов
            if total_packets > self.context.max_packets_to_analyze:
                LOG.warning(
                    f"Слишком много пакетов ({total_packets}), "
                    f"анализируем первые {self.context.max_packets_to_analyze}"
                )
                packets = packets[: self.context.max_packets_to_analyze]

            LOG.info(f"Загружено {len(packets)} пакетов для анализа")

            # Группировка пакетов по потокам
            flows = self.context.flow_analyzer.group_packets_by_flow(packets)
            LOG.info(f"Обнаружено {len(flows)} TCP потоков")

            # Анализ каждого потока
            flow_analyses = []
            # Optional parallel processor injected by orchestrator (no interface change required)
            parallel_processor = getattr(self.context, "parallel_processor", None)
            if parallel_processor and flows:
                LOG.info("Анализ потоков: используется параллельная обработка")
                flow_analyses = await parallel_processor.process_flows_parallel(
                    flows, self.context.flow_analyzer.analyze_flow
                )
            else:
                for flow_id, flow_packets in flows.items():
                    flow_analysis = await self.context.flow_analyzer.analyze_flow(
                        flow_id, flow_packets
                    )
                    flow_analyses.append(flow_analysis)

            # Определение основного типа блокировки
            primary_blocking_type, confidence = (
                self.context.blocking_analyzer.determine_primary_blocking_type(flow_analyses)
            )

            # Определение поведения DPI
            dpi_behavior = self.context.blocking_analyzer.determine_dpi_behavior(flow_analyses)

            # Извлечение DPI сигнатур
            dpi_signatures = []
            if self.context.enable_signature_extraction:
                dpi_signatures = await self._extract_dpi_signatures(packets, flow_analyses)

            # Сбор доказательств блокировки
            blocking_evidence = self.context.blocking_analyzer.collect_blocking_evidence(
                flow_analyses
            )

            # Генерация рекомендаций
            bypass_recommendations = self.context.blocking_analyzer.generate_bypass_recommendations(
                primary_blocking_type, dpi_behavior, flow_analyses
            )

            # Создание результата
            result = self._create_base_result(
                total_packets=total_packets,
                total_flows=len(flows),
                flows=flow_analyses,
                dpi_signatures=dpi_signatures,
                blocking_evidence=blocking_evidence,
                bypass_recommendations=bypass_recommendations,
                technical_details={
                    "analysis_method": "scapy",
                    "packets_analyzed": len(packets),
                    "flows_analyzed": len(flows),
                },
            )

            # Добавляем информацию о блокировке
            result["blocking_detected"] = primary_blocking_type.value != "no_blocking"
            result["primary_blocking_type"] = primary_blocking_type
            result["dpi_behavior"] = dpi_behavior
            result["confidence"] = confidence

            return result

        except FileNotFoundError as e:
            LOG.error(f"PCAP файл не найден: {e}")
            raise
        except ImportError as e:
            LOG.error(f"Ошибка импорта Scapy: {e}")
            raise
        except Exception as e:
            LOG.error(f"Ошибка Scapy анализа: {e}", exc_info=True)
            raise

    async def _extract_dpi_signatures(
        self, packets: List, flow_analyses: List[FlowAnalysis]
    ) -> List[DPISignature]:
        """Извлечение DPI сигнатур из трафика."""
        signatures = []

        try:
            # Извлечение сигнатур RST инъекций
            rst_signatures = await self.context.signature_extractor.extract_rst_signatures(packets)
            signatures.extend(rst_signatures)

            # Извлечение сигнатур тайминга
            timing_signatures = await self.context.signature_extractor.extract_timing_signatures(
                flow_analyses
            )
            signatures.extend(timing_signatures)

            # Извлечение сигнатур контента
            content_signatures = await self.context.signature_extractor.extract_content_signatures(
                packets
            )
            signatures.extend(content_signatures)

        except Exception as e:
            LOG.warning(f"Ошибка извлечения сигнатур: {e}", exc_info=True)

        return signatures


class JsonConverterAnalysisStrategy(AnalysisStrategy):
    """Стратегия анализа с использованием JSON конвертера."""

    async def analyze(self) -> Dict[str, Any]:
        """Анализ с использованием JSON конвертера."""
        try:
            # Конвертация PCAP в JSON
            # NOTE: converter is usually blocking; run it off the event loop
            json_data = await asyncio.to_thread(analyze_pcap, self.context.pcap_file)

            # Анализ JSON данных
            flows = json_data.get("flows", {})
            total_flows = len(flows)

            # Простой анализ на основе JSON данных
            flow_analyses = []
            for flow_name, packets in flows.items():
                flow_analysis = await self.context.flow_analyzer.analyze_flow_from_json(
                    flow_name, packets
                )
                flow_analyses.append(flow_analysis)

            # Определение типа блокировки
            primary_blocking_type, confidence = (
                self.context.blocking_analyzer.determine_primary_blocking_type(flow_analyses)
            )

            # Создание результата
            result = self._create_base_result(
                total_packets=sum(len(packets) for packets in flows.values()),
                total_flows=total_flows,
                flows=flow_analyses,
                technical_details={
                    "analysis_method": "json_converter",
                    "flows_analyzed": total_flows,
                },
            )

            # Добавляем информацию о блокировке
            result["blocking_detected"] = primary_blocking_type.value != "no_blocking"
            result["primary_blocking_type"] = primary_blocking_type
            result["dpi_behavior"] = "unknown"  # DPIBehavior.UNKNOWN
            result["confidence"] = confidence * 0.8  # Снижаем уверенность для JSON анализа

            return result

        except FileNotFoundError as e:
            LOG.error(f"PCAP файл не найден: {e}")
            raise
        except ImportError as e:
            LOG.error(f"JSON конвертер недоступен: {e}")
            raise
        except KeyError as e:
            LOG.error(f"Ошибка структуры JSON данных: {e}")
            raise
        except Exception as e:
            LOG.error(f"Ошибка JSON анализа: {e}", exc_info=True)
            raise


class FallbackAnalysisStrategy(AnalysisStrategy):
    """Fallback стратегия анализа без внешних зависимостей."""

    async def analyze(self) -> Dict[str, Any]:
        """Fallback анализ без внешних зависимостей."""
        try:
            # Простой анализ на основе размера файла и метаданных
            file_size = os.path.getsize(self.context.pcap_file)
            file_stat = os.stat(self.context.pcap_file)

            # Эвристический анализ
            if file_size == 0:
                blocking_type_value = "connection_timeout"
                confidence = 0.8
            elif file_size < 1000:
                blocking_type_value = "packet_drop"
                confidence = 0.6
            else:
                blocking_type_value = "unknown"
                confidence = 0.3

            result = self._create_base_result(
                total_packets=0,
                total_flows=0,
                technical_details={
                    "analysis_method": "fallback",
                    "file_size": file_size,
                    "file_mtime": file_stat.st_mtime,
                },
            )

            # Добавляем информацию о блокировке
            # "unknown" should not be treated as "blocking detected"
            result["blocking_detected"] = blocking_type_value not in ("no_blocking", "unknown")
            result["primary_blocking_type_value"] = blocking_type_value
            result["dpi_behavior"] = "unknown"
            result["confidence"] = confidence

            return result

        except FileNotFoundError as e:
            LOG.error(f"PCAP файл не найден: {e}")
            raise
        except OSError as e:
            LOG.error(f"Ошибка доступа к файлу: {e}")
            raise
        except Exception as e:
            LOG.error(f"Ошибка fallback анализа: {e}", exc_info=True)
            raise


class AnalysisStrategyFactory:
    """Фабрика для создания стратегий анализа."""

    @staticmethod
    def create_strategy(context: AnalysisContext) -> AnalysisStrategy:
        """
        Создание подходящей стратегии анализа.

        Args:
            context: Контекст анализа

        Returns:
            Экземпляр стратегии анализа
        """
        # Выбор стратегии на основе доступных зависимостей
        if SCAPY_AVAILABLE:
            LOG.info("Используется Scapy стратегия анализа")
            return ScapyAnalysisStrategy(context)
        elif PCAP_JSON_AVAILABLE:
            LOG.info("Используется JSON конвертер стратегия анализа")
            return JsonConverterAnalysisStrategy(context)
        else:
            LOG.warning("Используется fallback стратегия анализа")
            return FallbackAnalysisStrategy(context)
