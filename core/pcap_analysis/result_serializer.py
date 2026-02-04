"""
Result Serializer - сериализация результатов анализа PCAP.

Этот модуль отвечает за:
- Конвертацию результатов анализа в JSON-совместимый формат
- Сохранение результатов в файлы
- Загрузку результатов из файлов
- Валидацию формата данных

Requirements: FR-13.4 (Result Persistence)
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

LOG = logging.getLogger("ResultSerializer")


class ResultSerializer:
    """
    Сериализатор результатов анализа PCAP.

    Обеспечивает:
    - Конвертацию dataclass → JSON
    - Сохранение в файл с обработкой ошибок
    - Загрузку из файла
    - Валидацию данных
    """

    def __init__(self, indent: int = 2, ensure_ascii: bool = False):
        """
        Инициализация сериализатора.

        Args:
            indent: Отступ для форматирования JSON
            ensure_ascii: Использовать только ASCII символы
        """
        self.indent = indent
        self.ensure_ascii = ensure_ascii

    def serialize_result(self, result) -> Dict[str, Any]:
        """
        Конвертация PCAPAnalysisResult в JSON-совместимый словарь.

        Args:
            result: PCAPAnalysisResult для сериализации

        Returns:
            Словарь с данными результата

        Raises:
            TypeError: Если результат имеет неподдерживаемый тип
            ValueError: Если данные невалидны
        """
        try:
            primary_blocking_type = getattr(result, "primary_blocking_type", None)
            dpi_behavior = getattr(result, "dpi_behavior", None)

            result_dict = {
                "pcap_file": result.pcap_file,
                "analysis_timestamp": result.analysis_timestamp.isoformat(),
                "total_packets": result.total_packets,
                "total_flows": result.total_flows,
                "analysis_duration": result.analysis_duration,
                "blocking_detected": result.blocking_detected,
                "primary_blocking_type": (
                    primary_blocking_type.value
                    if primary_blocking_type is not None and hasattr(primary_blocking_type, "value")
                    else "unknown"
                ),
                "dpi_behavior": (
                    dpi_behavior.value
                    if dpi_behavior is not None and hasattr(dpi_behavior, "value")
                    else "unknown"
                ),
                "confidence": result.confidence,
                "flows": self._serialize_flows(result.flows),
                "dpi_signatures": self._serialize_signatures(result.dpi_signatures),
                "blocking_evidence": result.blocking_evidence,
                "bypass_recommendations": result.bypass_recommendations,
                "strategy_hints": result.strategy_hints,
                "technical_details": result.technical_details,
            }

            return result_dict

        except AttributeError as e:
            raise TypeError(f"Invalid result object: {e}") from e
        except Exception as e:
            raise ValueError(f"Failed to serialize result: {e}") from e

    def _serialize_flows(self, flows) -> list:
        """Сериализация списка потоков."""
        return [
            {
                "flow_id": f.flow_id,
                "src_endpoint": f.src_endpoint,
                "dst_endpoint": f.dst_endpoint,
                "packet_count": f.packet_count,
                "total_bytes": f.total_bytes,
                "duration": f.duration,
                "connection_established": f.connection_established,
                "tls_handshake_completed": f.tls_handshake_completed,
                "blocking_detected": f.blocking_detected,
                "blocking_type": f.blocking_type.value,
                "blocking_details": f.blocking_details,
            }
            for f in flows
        ]

    def _serialize_signatures(self, signatures) -> list:
        """Сериализация списка DPI сигнатур."""
        return [
            {
                "signature_id": s.signature_id,
                "signature_type": s.signature_type,
                "pattern_data": s.pattern_data,
                "confidence": s.confidence,
                "detection_method": s.detection_method,
                "samples_count": s.samples_count,
                "first_seen": s.first_seen.isoformat(),
                "last_seen": s.last_seen.isoformat(),
            }
            for s in signatures
        ]

    def save_to_file(self, result, output_file: str) -> bool:
        """
        Сохранение результата анализа в JSON файл.

        Args:
            result: PCAPAnalysisResult для сохранения
            output_file: Путь к выходному файлу

        Returns:
            True если успешно, False при ошибке
        """
        try:
            # Конвертация в словарь
            result_dict = self.serialize_result(result)

            # Создание директории если не существует
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Сохранение в файл
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result_dict, f, indent=self.indent, ensure_ascii=self.ensure_ascii)

            LOG.info(f"Результат анализа сохранен в {output_file}")
            return True

        except (IOError, OSError) as e:
            LOG.error(f"Ошибка записи файла {output_file}: {e}")
            return False
        except (TypeError, ValueError) as e:
            LOG.error(f"Ошибка сериализации результата: {e}")
            return False
        except Exception as e:
            LOG.error(f"Неожиданная ошибка сохранения результата: {e}", exc_info=True)
            return False

    def load_from_file(self, input_file: str) -> Optional[Dict[str, Any]]:
        """
        Загрузка результата анализа из JSON файла.

        Args:
            input_file: Путь к входному файлу

        Returns:
            Словарь с данными результата или None при ошибке
        """
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                result_dict = json.load(f)

            # Базовая валидация
            required_fields = [
                "pcap_file",
                "analysis_timestamp",
                "blocking_detected",
                "primary_blocking_type",
            ]

            for field in required_fields:
                if field not in result_dict:
                    raise ValueError(f"Missing required field: {field}")

            LOG.info(f"Результат анализа загружен из {input_file}")
            # Non-breaking: warn only; allow caller to decide what to do.
            if not self.validate_result_dict(result_dict):
                LOG.warning("Loaded result dict did not pass full validation: %s", input_file)

            return result_dict

        except FileNotFoundError:
            LOG.error(f"Файл не найден: {input_file}")
            return None
        except json.JSONDecodeError as e:
            LOG.error(f"Ошибка парсинга JSON: {e}")
            return None
        except ValueError as e:
            LOG.error(f"Невалидный формат данных: {e}")
            return None
        except Exception as e:
            LOG.error(f"Неожиданная ошибка загрузки результата: {e}", exc_info=True)
            return None

    def validate_result_dict(self, result_dict: Dict[str, Any]) -> bool:
        """
        Валидация словаря результата.

        Args:
            result_dict: Словарь для валидации

        Returns:
            True если валиден, False иначе
        """
        try:
            # Проверка обязательных полей
            required_fields = {
                "pcap_file": str,
                "analysis_timestamp": str,
                "total_packets": int,
                "total_flows": int,
                "blocking_detected": bool,
                "primary_blocking_type": str,
                "dpi_behavior": str,
                "confidence": (int, float),
            }

            for field, expected_type in required_fields.items():
                if field not in result_dict:
                    LOG.warning(f"Missing required field: {field}")
                    return False

                if not isinstance(result_dict[field], expected_type):
                    LOG.warning(
                        f"Invalid type for {field}: "
                        f"expected {expected_type}, got {type(result_dict[field])}"
                    )
                    return False

            # Проверка диапазонов
            if not 0.0 <= result_dict["confidence"] <= 1.0:
                LOG.warning(f"Confidence out of range: {result_dict['confidence']}")
                return False

            if result_dict["total_packets"] < 0 or result_dict["total_flows"] < 0:
                LOG.warning("Negative packet/flow count")
                return False

            return True

        except Exception as e:
            LOG.error(f"Validation error: {e}")
            return False


# Удобные функции для быстрого использования
def save_result(result, output_file: str, **kwargs) -> bool:
    """
    Быстрое сохранение результата в файл.

    Args:
        result: PCAPAnalysisResult для сохранения
        output_file: Путь к выходному файлу
        **kwargs: Дополнительные параметры для ResultSerializer

    Returns:
        True если успешно, False при ошибке
    """
    serializer = ResultSerializer(**kwargs)
    return serializer.save_to_file(result, output_file)


def load_result(input_file: str) -> Optional[Dict[str, Any]]:
    """
    Быстрая загрузка результата из файла.

    Args:
        input_file: Путь к входному файлу

    Returns:
        Словарь с данными результата или None при ошибке
    """
    serializer = ResultSerializer()
    return serializer.load_from_file(input_file)


def validate_result(result_dict: Dict[str, Any]) -> bool:
    """
    Быстрая валидация словаря результата.

    Args:
        result_dict: Словарь для валидации

    Returns:
        True если валиден, False иначе
    """
    serializer = ResultSerializer()
    return serializer.validate_result_dict(result_dict)
