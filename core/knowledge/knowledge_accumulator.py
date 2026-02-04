"""
Knowledge Accumulator - система накопления знаний о паттернах блокировок.

Этот модуль реализует базу знаний для замкнутого цикла обучения,
позволяя системе накапливать опыт и автоматически применять
решения к новым доменам с похожими паттернами блокировок.
"""

import json
import logging
import os
import shutil
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

LOG = logging.getLogger("KnowledgeAccumulator")


@dataclass
class PatternRule:
    """
    Правило паттерна блокировки для базы знаний.

    Содержит условия для сопоставления с FailureReport и рекомендации
    по intent'ам и tweaks для обхода блокировки.
    """

    id: str
    description: str
    conditions: Dict[str, Any]
    recommend: List[Dict[str, Any]]  # [{"intent": "key", "weight": 0.9}]
    tweaks: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь для JSON."""
        return {
            "id": self.id,
            "description": self.description,
            "conditions": self.conditions,
            "recommend": self.recommend,
            "tweaks": self.tweaks,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PatternRule":
        """Десериализация из словаря."""
        return cls(
            id=data["id"],
            description=data["description"],
            conditions=data["conditions"],
            recommend=data["recommend"],
            tweaks=data.get("tweaks", {}),
            metadata=data.get("metadata", {}),
        )

    def validate(self) -> bool:
        """
        Валидация правила.

        Returns:
            True если правило валидно
        """
        # Проверка обязательных полей
        if not self.id or not self.description:
            return False

        if not isinstance(self.conditions, dict) or not self.conditions:
            return False

        if not isinstance(self.recommend, list) or not self.recommend:
            return False

        # Проверка структуры рекомендаций
        for rec in self.recommend:
            if not isinstance(rec, dict):
                return False
            if "intent" not in rec or "weight" not in rec:
                return False
            if not isinstance(rec["weight"], (int, float)):
                return False
            if not (0.0 <= rec["weight"] <= 1.0):
                return False

        return True


class KnowledgeAccumulator:
    """
    Система накопления знаний о паттернах блокировок.

    Основные функции:
    - Загрузка и сохранение правил из pattern_rules.json
    - Обновление метаданных правил на основе результатов
    - Автоматическое создание новых правил из успешных обходов
    - Удаление устаревших или неэффективных правил
    - Batch обновления для повышения производительности
    """

    def __init__(self, rules_file: str = "knowledge/pattern_rules.json"):
        """
        Инициализация Knowledge Accumulator.

        Args:
            rules_file: Путь к файлу с правилами
        """
        self.rules_file = Path(rules_file)
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)

        self.patterns: List[PatternRule] = []
        self.global_settings: Dict[str, Any] = {}

        # Batch обновления для производительности
        self._pending_updates = []
        self._update_count = 0
        self._last_save_time = datetime.now()
        self._batch_size = 10  # Сохранение раз в 10 обновлений
        self._batch_timeout = 60  # Или каждые 60 секунд
        self._save_lock = threading.RLock()

        self._load_patterns()

        LOG.info(f"KnowledgeAccumulator инициализирован с {len(self.patterns)} правилами")

    def _load_patterns(self):
        """Загрузка правил из файла."""
        if not self.rules_file.exists():
            LOG.warning(f"Файл правил не найден: {self.rules_file}, создаем дефолтные")
            self._create_default_patterns()
            return

        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.global_settings = data.get("global_settings", {})

            for pattern_data in data.get("patterns", []):
                try:
                    pattern = PatternRule.from_dict(pattern_data)
                    if pattern.validate():
                        self.patterns.append(pattern)
                    else:
                        LOG.warning(
                            f"Невалидное правило пропущено: {pattern_data.get('id', 'unknown')}"
                        )
                except Exception as e:
                    LOG.error(f"Ошибка загрузки правила: {e}")

            LOG.info(f"Загружено {len(self.patterns)} правил из {self.rules_file}")

        except Exception as e:
            LOG.error(f"Ошибка загрузки правил: {e}")
            self._create_default_patterns()

    def save_patterns(self, force: bool = False):
        """
        Сохранение правил в файл с поддержкой batch обновлений.

        Args:
            force: Принудительное сохранение, игнорируя batch логику
        """
        with self._save_lock:
            # Проверяем условия для batch сохранения
            time_since_last_save = datetime.now() - self._last_save_time

            if (
                not force
                and self._update_count < self._batch_size
                and time_since_last_save.total_seconds() < self._batch_timeout
            ):
                # Добавляем в очередь pending updates
                LOG.debug(
                    f"Отложено сохранение: {self._update_count}/{self._batch_size} обновлений, "
                    f"{time_since_last_save.total_seconds():.1f}s с последнего сохранения"
                )
                return

            self._perform_save()

    def _perform_save(self):
        """Выполнение фактического сохранения."""
        import shutil
        import os

        try:
            data = {
                "patterns": [pattern.to_dict() for pattern in self.patterns],
                "global_settings": self.global_settings,
                "batch_info": {
                    "last_save": datetime.now().isoformat(),
                    "pending_updates_processed": len(self._pending_updates),
                    "total_updates": self._update_count,
                },
            }

            # Skip backup during testing to avoid file conflicts
            is_testing = (
                os.getenv("PYTEST_CURRENT_TEST") is not None
                or os.getenv("TESTING") is not None
                or "test" in str(self.rules_file).lower()
            )

            backup_file = None
            if not is_testing and self.rules_file.exists():
                backup_file = self.rules_file.with_suffix(".json.backup")

                # Remove existing backup file if it exists (Windows requirement)
                if backup_file.exists():
                    try:
                        os.remove(backup_file)
                    except OSError:
                        pass  # Ignore if can't remove

                # Use shutil.move instead of rename for better Windows compatibility
                try:
                    shutil.move(str(self.rules_file), str(backup_file))
                except (OSError, shutil.Error):
                    # If backup fails, continue without backup (better than failing completely)
                    LOG.warning("Could not create backup file, proceeding without backup")
                    backup_file = None

            # Write new file
            with open(self.rules_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Обновляем статистику batch операций
            self._last_save_time = datetime.now()
            processed_updates = len(self._pending_updates)
            self._pending_updates.clear()
            self._update_count = 0

            LOG.info(
                f"💾 Batch сохранение: {len(self.patterns)} правил, "
                f"обработано {processed_updates} отложенных обновлений"
            )

        except Exception as e:
            LOG.error(f"Ошибка сохранения правил: {e}")
            # Восстанавливаем backup при ошибке (только если backup был создан)
            if backup_file and backup_file.exists():
                try:
                    if self.rules_file.exists():
                        os.remove(str(self.rules_file))
                    shutil.move(str(backup_file), str(self.rules_file))
                    LOG.info("Восстановлен backup файл правил")
                except (OSError, shutil.Error) as restore_error:
                    LOG.error(f"Не удалось восстановить backup: {restore_error}")
            raise

    def update_success_pattern(
        self,
        failure_report: Any,  # FailureReport
        successful_strategy: Any,
        context: Dict[str, Any],
    ):
        """
        Обновление правила после успешного обхода с batch накоплением.

        Args:
            failure_report: Отчет об анализе неудачи
            successful_strategy: Стратегия, которая сработала
            context: Контекст (ASN, IP, domain и т.д.)
        """
        # Находим подходящее правило
        matching_pattern = self._find_matching_pattern(failure_report, context)

        update_info = {"type": "success", "timestamp": datetime.now(), "context": context.copy()}

        if matching_pattern:
            # Обновляем существующее правило
            matching_pattern.metadata["success_count"] = (
                matching_pattern.metadata.get("success_count", 0) + 1
            )
            matching_pattern.metadata["last_success"] = datetime.now().isoformat()

            # Обновляем confidence
            total = matching_pattern.metadata.get(
                "success_count", 0
            ) + matching_pattern.metadata.get("failure_count", 0)
            matching_pattern.metadata["confidence"] = (
                matching_pattern.metadata.get("success_count", 0) / total if total > 0 else 0.5
            )

            # Добавляем домен в список
            domains = matching_pattern.metadata.get("domains_applied", [])
            if context.get("domain") and context["domain"] not in domains:
                domains.append(context["domain"])
                matching_pattern.metadata["domains_applied"] = domains

            update_info["pattern_id"] = matching_pattern.id
            update_info["action"] = "updated_existing"

            LOG.info(
                f"Обновлено правило {matching_pattern.id}: "
                f"success={matching_pattern.metadata['success_count']}, "
                f"confidence={matching_pattern.metadata['confidence']:.2f}"
            )
        else:
            # Создаем новое правило
            new_pattern = self._create_pattern_from_success(
                failure_report, successful_strategy, context
            )
            self.patterns.append(new_pattern)

            update_info["pattern_id"] = new_pattern.id
            update_info["action"] = "created_new"

            LOG.info(f"Создано новое правило: {new_pattern.id}")

        # Добавляем в batch обновления
        self._add_pending_update(update_info)

        # Проверяем условия для сохранения
        self._check_and_save()

    def update_failure_pattern(
        self, failure_report: Any, failed_strategy: Any, context: Dict[str, Any]  # FailureReport
    ):
        """Обновление правила после неудачи с batch накоплением."""
        matching_pattern = self._find_matching_pattern(failure_report, context)

        update_info = {"type": "failure", "timestamp": datetime.now(), "context": context.copy()}

        if matching_pattern:
            matching_pattern.metadata["failure_count"] = (
                matching_pattern.metadata.get("failure_count", 0) + 1
            )

            # Обновляем confidence
            total = matching_pattern.metadata.get(
                "success_count", 0
            ) + matching_pattern.metadata.get("failure_count", 0)
            matching_pattern.metadata["confidence"] = (
                matching_pattern.metadata.get("success_count", 0) / total if total > 0 else 0.5
            )

            update_info["pattern_id"] = matching_pattern.id
            update_info["action"] = "updated_failure"

            LOG.info(
                f"Обновлено правило {matching_pattern.id} после неудачи: "
                f"confidence={matching_pattern.metadata['confidence']:.2f}"
            )
        else:
            update_info["pattern_id"] = None
            update_info["action"] = "no_matching_pattern"

        # Добавляем в batch обновления
        self._add_pending_update(update_info)

        # Проверяем условия для сохранения
        self._check_and_save()

    def _find_matching_pattern(
        self, failure_report: Any, context: Dict[str, Any]  # FailureReport
    ) -> Optional[PatternRule]:
        """Поиск подходящего правила."""
        for pattern in self.patterns:
            if self._matches_conditions(pattern.conditions, failure_report, context):
                return pattern
        return None

    def _matches_conditions(
        self,
        conditions: Dict[str, Any],
        failure_report: Any,  # FailureReport
        context: Dict[str, Any],
    ) -> bool:
        """Проверка соответствия условиям правила."""
        # Проверка root_cause
        if "root_cause" in conditions:
            if failure_report.root_cause.value != conditions["root_cause"]:
                return False

        # Проверка indicators (any)
        if "indicators.any" in conditions:
            required_indicators = conditions["indicators.any"]
            failure_indicators = failure_report.failure_details.get("indicators", [])
            if not any(ind in failure_indicators for ind in required_indicators):
                return False

        # Проверка ASN
        if "asn.any" in conditions:
            required_asns = conditions["asn.any"]
            context_asn = context.get("asn")
            if context_asn not in required_asns:
                return False

        # Проверка timing
        if "rst_timing_ms.lt" in conditions:
            max_timing = conditions["rst_timing_ms.lt"]
            actual_timing = failure_report.failure_details.get("rst_timing_ms", float("inf"))
            if actual_timing >= max_timing:
                return False

        # Проверка connection_established
        if "connection_established" in conditions:
            required = conditions["connection_established"]
            actual = failure_report.failure_details.get("connection_established", False)
            if required != actual:
                return False

        return True

    def _create_pattern_from_success(
        self,
        failure_report: Any,  # FailureReport
        successful_strategy: Any,
        context: Dict[str, Any],
    ) -> PatternRule:
        """Создание нового правила из успешного обхода."""
        pattern_id = (
            f"auto_{failure_report.root_cause.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        # Извлекаем условия из failure_report
        conditions = {"root_cause": failure_report.root_cause.value}

        # Добавляем indicators
        if failure_report.failure_details.get("indicators"):
            conditions["indicators.any"] = failure_report.failure_details["indicators"]

        # Добавляем ASN если есть
        if context.get("asn"):
            conditions["asn.any"] = [context["asn"]]

        # Создаем рекомендации из successful_strategy
        recommend = []
        if hasattr(successful_strategy, "source_intents"):
            for intent_key in successful_strategy.source_intents:
                recommend.append({"intent": intent_key, "weight": 0.8})  # Начальный вес
        elif hasattr(successful_strategy, "name"):
            # Fallback: пытаемся извлечь intent из имени стратегии
            strategy_name = successful_strategy.name.lower()
            if "sni" in strategy_name:
                recommend.append({"intent": "conceal_sni", "weight": 0.8})
            elif "frag" in strategy_name:
                recommend.append({"intent": "record_fragmentation", "weight": 0.8})
            elif "ttl" in strategy_name:
                recommend.append({"intent": "short_ttl_decoy", "weight": 0.8})

        # Если нет рекомендаций, используем базовые из suggested_intents
        if not recommend and hasattr(failure_report, "suggested_intents"):
            for intent_key in failure_report.suggested_intents[:3]:  # Максимум 3
                recommend.append({"intent": intent_key, "weight": 0.7})

        # Создаем tweaks из параметров стратегии
        tweaks = {}
        if hasattr(successful_strategy, "parameters"):
            params = successful_strategy.parameters
            if "ttl" in params:
                tweaks["ttl_adjustment"] = params["ttl"] - 64
            if "split_pos" in params:
                tweaks["split_position_hint"] = params["split_pos"]
            if "timeout" in params:
                tweaks["strategy_timeout_factor"] = params["timeout"] / 5.0  # Нормализация

        return PatternRule(
            id=pattern_id,
            description=f"Auto-generated from {failure_report.domain}",
            conditions=conditions,
            recommend=recommend,
            tweaks=tweaks,
            metadata={
                "success_count": 1,
                "failure_count": 0,
                "last_success": datetime.now().isoformat(),
                "confidence": 1.0,
                "domains_applied": [context.get("domain", "unknown")],
                "auto_generated": True,
                "created_at": datetime.now().isoformat(),
            },
        )

    def _create_default_patterns(self):
        """Создание дефолтных правил."""
        default_patterns = [
            PatternRule(
                id="sni_block_rst_fast",
                description="SNI блокировка с быстрым RST",
                conditions={
                    "root_cause": "DPI_SNI_FILTERING",
                    "indicators.any": ["rst_after_client_hello"],
                },
                recommend=[
                    {"intent": "conceal_sni", "weight": 0.95},
                    {"intent": "record_fragmentation", "weight": 0.85},
                ],
                tweaks={"strategy_timeout_factor": 1.5},
                metadata={
                    "success_count": 0,
                    "failure_count": 0,
                    "confidence": 0.5,
                    "created_at": datetime.now().isoformat(),
                },
            ),
            PatternRule(
                id="content_inspection_blackhole",
                description="Глубокая инспекция контента с черной дырой",
                conditions={"root_cause": "DPI_CONTENT_INSPECTION", "connection_established": True},
                recommend=[
                    {"intent": "payload_obfuscation", "weight": 0.9},
                    {"intent": "sequence_overlap", "weight": 0.8},
                    {"intent": "tls_extension_manipulation", "weight": 0.7},
                ],
                tweaks={"strategy_timeout_factor": 2.0, "enable_ipv6_fallback": True},
                metadata={
                    "success_count": 0,
                    "failure_count": 0,
                    "confidence": 0.5,
                    "created_at": datetime.now().isoformat(),
                },
            ),
            PatternRule(
                id="stateless_dpi_fragment_bypass",
                description="Stateless DPI обходится фрагментацией",
                conditions={"root_cause": "DPI_REASSEMBLES_FRAGMENTS", "fragments_detected": True},
                recommend=[
                    {"intent": "packet_reordering", "weight": 0.9},
                    {"intent": "out_of_order_decoy", "weight": 0.85},
                ],
                tweaks={"split_count_multiplier": 2, "disorder_enabled": True},
                metadata={
                    "success_count": 0,
                    "failure_count": 0,
                    "confidence": 0.5,
                    "created_at": datetime.now().isoformat(),
                },
            ),
        ]

        self.patterns = default_patterns

        # Дефолтные глобальные настройки
        self.global_settings = {
            "min_confidence_threshold": 0.7,
            "max_patterns_per_match": 3,
            "pattern_ttl_days": 30,
            "auto_prune_low_confidence": True,
        }

        self.save_patterns()
        LOG.info(f"Созданы {len(default_patterns)} дефолтных правил")

    def prune_low_confidence_patterns(self, min_confidence: float = None):
        """Удаление правил с низкой эффективностью."""
        if min_confidence is None:
            min_confidence = self.global_settings.get("min_confidence_threshold", 0.3)

        before_count = len(self.patterns)

        self.patterns = [
            p for p in self.patterns if p.metadata.get("confidence", 0.5) >= min_confidence
        ]

        removed_count = before_count - len(self.patterns)
        if removed_count > 0:
            LOG.info(f"Удалено {removed_count} правил с низкой confidence (< {min_confidence})")
            self.save_patterns()

    def get_statistics(self) -> Dict[str, Any]:
        """Статистика базы знаний."""
        if not self.patterns:
            return {
                "total_patterns": 0,
                "total_success": 0,
                "total_failure": 0,
                "average_confidence": 0.0,
                "auto_generated_count": 0,
            }

        total_success = sum(p.metadata.get("success_count", 0) for p in self.patterns)
        total_failure = sum(p.metadata.get("failure_count", 0) for p in self.patterns)
        avg_confidence = sum(p.metadata.get("confidence", 0.5) for p in self.patterns) / len(
            self.patterns
        )
        auto_generated_count = sum(1 for p in self.patterns if p.metadata.get("auto_generated"))

        return {
            "total_patterns": len(self.patterns),
            "total_success": total_success,
            "total_failure": total_failure,
            "average_confidence": avg_confidence,
            "auto_generated_count": auto_generated_count,
            "success_rate": total_success / max(1, total_success + total_failure),
        }

    def get_pattern_by_id(self, pattern_id: str) -> Optional[PatternRule]:
        """Получение правила по ID."""
        for pattern in self.patterns:
            if pattern.id == pattern_id:
                return pattern
        return None

    def get_all_patterns(self) -> List[PatternRule]:
        """Получение всех правил."""
        return self.patterns.copy()

    def remove_pattern(self, pattern_id: str) -> bool:
        """Удаление правила по ID."""
        for i, pattern in enumerate(self.patterns):
            if pattern.id == pattern_id:
                removed_pattern = self.patterns.pop(i)
                LOG.info(f"Удалено правило: {removed_pattern.id}")
                self.save_patterns()
                return True
        return False

    def add_pattern(self, pattern: PatternRule) -> bool:
        """Добавление нового правила."""
        if not pattern.validate():
            LOG.error(f"Невалидное правило: {pattern.id}")
            return False

        # Проверяем на дубликаты по ID
        if self.get_pattern_by_id(pattern.id):
            LOG.warning(f"Правило с ID {pattern.id} уже существует")
            return False

        self.patterns.append(pattern)
        LOG.info(f"Добавлено новое правило: {pattern.id}")

        # Добавляем в batch обновления
        update_info = {
            "type": "add_pattern",
            "timestamp": datetime.now(),
            "pattern_id": pattern.id,
            "action": "added_new_pattern",
        }
        self._add_pending_update(update_info)
        self._check_and_save()

        return True

    def _add_pending_update(self, update_info: Dict[str, Any]):
        """Добавление обновления в очередь batch операций."""
        with self._save_lock:
            self._pending_updates.append(update_info)
            self._update_count += 1

            LOG.debug(
                f"Добавлено обновление в batch: {update_info['type']} "
                f"({self._update_count}/{self._batch_size})"
            )

    def _check_and_save(self):
        """Проверка условий для batch сохранения."""
        with self._save_lock:
            time_since_last_save = datetime.now() - self._last_save_time

            # Условия для сохранения:
            # 1. Достигнут размер batch
            # 2. Прошло достаточно времени
            # 3. Критическое обновление (можно добавить флаг в будущем)
            should_save = (
                self._update_count >= self._batch_size
                or time_since_last_save.total_seconds() >= self._batch_timeout
            )

            if should_save:
                LOG.debug(
                    f"Условия для batch сохранения выполнены: "
                    f"updates={self._update_count}/{self._batch_size}, "
                    f"time={time_since_last_save.total_seconds():.1f}s/{self._batch_timeout}s"
                )
                self._perform_save()

    def flush_pending_updates(self):
        """Принудительное сохранение всех отложенных обновлений."""
        with self._save_lock:
            if self._pending_updates:
                LOG.info(
                    f"Принудительное сохранение {len(self._pending_updates)} отложенных обновлений"
                )
                self._perform_save()
            else:
                LOG.debug("Нет отложенных обновлений для сохранения")

    def get_batch_statistics(self) -> Dict[str, Any]:
        """Статистика batch операций."""
        with self._save_lock:
            time_since_last_save = datetime.now() - self._last_save_time

            return {
                "pending_updates": len(self._pending_updates),
                "update_count": self._update_count,
                "batch_size": self._batch_size,
                "batch_timeout_seconds": self._batch_timeout,
                "time_since_last_save_seconds": time_since_last_save.total_seconds(),
                "last_save_time": self._last_save_time.isoformat(),
                "next_save_trigger": {
                    "by_count": max(0, self._batch_size - self._update_count),
                    "by_time": max(0, self._batch_timeout - time_since_last_save.total_seconds()),
                },
            }
