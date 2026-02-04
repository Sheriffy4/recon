"""
DPI Change Notifier - Система уведомлений об изменениях в DPI
Реализует требования FR-4, FR-8 для адаптивной системы мониторинга.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

LOG = logging.getLogger("dpi_change_notifier")


class ChangeType(Enum):
    """Типы изменений в DPI"""

    NEW_BLOCKING = "new_blocking"
    BLOCKING_REMOVED = "blocking_removed"
    DPI_BEHAVIOR_CHANGE = "dpi_behavior_change"
    STRATEGY_EFFECTIVENESS_CHANGE = "strategy_effectiveness_change"
    NEW_DPI_SIGNATURE = "new_dpi_signature"


@dataclass
class DPIChangeEvent:
    """Событие изменения в DPI"""

    change_type: ChangeType
    timestamp: datetime
    domain: str

    # Детали изменения
    old_state: Optional[Dict[str, Any]] = None
    new_state: Optional[Dict[str, Any]] = None
    confidence: float = 0.0

    # Метаданные
    source: str = "unknown"  # rtm, base_monitoring, adaptive_engine
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "change_type": self.change_type.value,
            "timestamp": self.timestamp.isoformat(),
            "domain": self.domain,
            "old_state": self.old_state,
            "new_state": self.new_state,
            "confidence": self.confidence,
            "source": self.source,
            "evidence": self.evidence,
        }


class DPIChangeNotifier:
    """
    Система уведомлений об изменениях в DPI системах.

    Отслеживает изменения в поведении DPI и отправляет уведомления
    через различные каналы (webhook, email, файл, консоль).
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config

        # Каналы уведомлений
        self.notification_channels = []
        self._setup_notification_channels()

        # История изменений
        self.change_history: List[DPIChangeEvent] = []
        self.domain_states: Dict[str, Dict[str, Any]] = {}

        # Статистика
        self.stats = {
            "changes_detected": 0,
            "notifications_sent": 0,
            "channels_active": len(self.notification_channels),
        }

        LOG.info("DPIChangeNotifier initialized")

    def _setup_notification_channels(self):
        """Настройка каналов уведомлений"""
        channels_config = self.config.get("notification_channels", {})

        # Webhook канал
        if channels_config.get("webhook", {}).get("enabled", False):
            webhook_config = channels_config["webhook"]
            self.notification_channels.append(WebhookNotificationChannel(webhook_config))

        # Файловый канал
        if channels_config.get("file", {}).get("enabled", True):
            file_config = channels_config.get("file", {})
            self.notification_channels.append(FileNotificationChannel(file_config))

        # Консольный канал
        if channels_config.get("console", {}).get("enabled", True):
            self.notification_channels.append(ConsoleNotificationChannel({}))

    async def detect_and_notify_changes(
        self, domain: str, current_state: Dict[str, Any], source: str = "unknown"
    ):
        """Обнаружение и уведомление об изменениях"""

        if domain not in self.domain_states:
            # Первое наблюдение домена
            self.domain_states[domain] = current_state
            return

        old_state = self.domain_states[domain]
        changes = self._detect_changes(domain, old_state, current_state, source)

        if changes:
            # Обновляем состояние
            self.domain_states[domain] = current_state

            # Отправляем уведомления
            for change in changes:
                await self._send_notifications(change)
                self.change_history.append(change)
                self.stats["changes_detected"] += 1

    def _detect_changes(
        self, domain: str, old_state: Dict[str, Any], new_state: Dict[str, Any], source: str
    ) -> List[DPIChangeEvent]:
        """Обнаружение изменений в состоянии DPI"""
        changes = []

        # Изменение доступности
        old_accessible = old_state.get("is_accessible", True)
        new_accessible = new_state.get("is_accessible", True)

        if old_accessible and not new_accessible:
            changes.append(
                DPIChangeEvent(
                    change_type=ChangeType.NEW_BLOCKING,
                    timestamp=datetime.now(),
                    domain=domain,
                    old_state={"is_accessible": old_accessible},
                    new_state={"is_accessible": new_accessible},
                    confidence=0.8,
                    source=source,
                )
            )
        elif not old_accessible and new_accessible:
            changes.append(
                DPIChangeEvent(
                    change_type=ChangeType.BLOCKING_REMOVED,
                    timestamp=datetime.now(),
                    domain=domain,
                    old_state={"is_accessible": old_accessible},
                    new_state={"is_accessible": new_accessible},
                    confidence=0.8,
                    source=source,
                )
            )

        return changes

    async def _send_notifications(self, change: DPIChangeEvent):
        """Отправка уведомлений через все каналы"""

        notification_tasks = []

        for channel in self.notification_channels:
            task = asyncio.create_task(channel.send_notification(change))
            notification_tasks.append(task)

        # Ждем завершения всех уведомлений
        results = await asyncio.gather(*notification_tasks, return_exceptions=True)

        successful_notifications = sum(1 for result in results if not isinstance(result, Exception))
        self.stats["notifications_sent"] += successful_notifications

        if successful_notifications < len(self.notification_channels):
            LOG.warning(f"Some notification channels failed for change: {change.change_type.value}")


class NotificationChannel:
    """Базовый класс для каналов уведомлений"""

    async def send_notification(self, change: DPIChangeEvent) -> bool:
        """Отправка уведомления"""
        raise NotImplementedError


class WebhookNotificationChannel(NotificationChannel):
    """Канал уведомлений через webhook"""

    def __init__(self, config: Dict[str, Any]):
        self.url = config.get("url")
        self.headers = config.get("headers", {})
        self.timeout = config.get("timeout", 10)

    async def send_notification(self, change: DPIChangeEvent) -> bool:
        """Отправка webhook уведомления"""
        try:
            import aiohttp

            payload = {"event": "dpi_change", "data": change.to_dict()}

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    return response.status < 400

        except Exception as e:
            LOG.error(f"Webhook notification failed: {e}")
            return False


class FileNotificationChannel(NotificationChannel):
    """Канал уведомлений в файл"""

    def __init__(self, config: Dict[str, Any]):
        self.file_path = Path(config.get("file_path", "dpi_changes.jsonl"))
        self.max_file_size_mb = config.get("max_file_size_mb", 10)

    async def send_notification(self, change: DPIChangeEvent) -> bool:
        """Запись уведомления в файл"""
        try:
            # Проверяем размер файла
            if (
                self.file_path.exists()
                and self.file_path.stat().st_size > self.max_file_size_mb * 1024 * 1024
            ):
                # Ротация файла
                backup_path = self.file_path.with_suffix(
                    f".{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
                )
                self.file_path.rename(backup_path)

            # Записываем событие
            with open(self.file_path, "a", encoding="utf-8") as f:
                json.dump(change.to_dict(), f, ensure_ascii=False)
                f.write("\n")

            return True

        except Exception as e:
            LOG.error(f"File notification failed: {e}")
            return False


class ConsoleNotificationChannel(NotificationChannel):
    """Канал уведомлений в консоль"""

    async def send_notification(self, change: DPIChangeEvent) -> bool:
        """Вывод уведомления в консоль"""
        try:
            icon = {
                ChangeType.NEW_BLOCKING: "🚫",
                ChangeType.BLOCKING_REMOVED: "✅",
                ChangeType.DPI_BEHAVIOR_CHANGE: "🔄",
                ChangeType.STRATEGY_EFFECTIVENESS_CHANGE: "📊",
                ChangeType.NEW_DPI_SIGNATURE: "🔍",
            }.get(change.change_type, "📢")

            message = (
                f"{icon} DPI Change: {change.change_type.value} "
                f"for {change.domain} (confidence: {change.confidence:.2f})"
            )

            LOG.info(message)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

            return True

        except Exception as e:
            LOG.error(f"Console notification failed: {e}")
            return False
