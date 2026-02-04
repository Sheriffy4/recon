"""
Real-Time Monitor - Task 6.2 Implementation
Реализует пассивный анализ трафика для автоматического обнаружения новых блокировок
и интеграцию с существующим monitoring_system.py

Требования FR-4, FR-8 для адаптивной системы мониторинга.
"""

import asyncio
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
import hashlib

# Импорты для работы с сетью
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls import TLS

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None

# Импорты для захвата пакетов на Windows
try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    pydivert = None

# Интеграция с существующими компонентами
try:
    from core.adaptive_refactored.facade import AdaptiveEngine
    from core.fingerprint.dpi_fingerprint_service import DPIFingerprintService

    ADAPTIVE_COMPONENTS_AVAILABLE = True
except ImportError:
    ADAPTIVE_COMPONENTS_AVAILABLE = False

LOG = logging.getLogger("real_time_monitor")


class BlockType(Enum):
    """Типы блокировок"""

    TLS_HANDSHAKE_BLOCKING = "tls_handshake_blocking"
    SNI_BLOCKING = "sni_blocking"
    TCP_RST_BLOCKING = "tcp_rst_blocking"
    DNS_BLOCKING = "dns_blocking"
    TIMEOUT_BLOCKING = "timeout_blocking"
    UNKNOWN = "unknown"


class TrafficEventType(Enum):
    """Типы событий трафика"""

    CONNECTION_ATTEMPT = "connection_attempt"
    CONNECTION_SUCCESS = "connection_success"
    CONNECTION_BLOCKED = "connection_blocked"
    RST_INJECTION = "rst_injection"
    TLS_HANDSHAKE_FAIL = "tls_handshake_fail"
    SUSPICIOUS_TIMING = "suspicious_timing"


@dataclass
class TrafficEvent:
    """Событие в трафике"""

    event_type: TrafficEventType
    timestamp: datetime
    source_ip: str
    dest_ip: str
    dest_port: int
    domain: Optional[str] = None

    # Детали события
    block_type: Optional[BlockType] = None
    packet_count: int = 0
    duration_ms: float = 0.0

    # Метаданные
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "domain": self.domain,
            "block_type": self.block_type.value if self.block_type else None,
            "packet_count": self.packet_count,
            "duration_ms": self.duration_ms,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class MonitoringConfig:
    """Конфигурация Real-Time Monitor"""

    # Основные параметры
    enabled: bool = True
    capture_interface: str = "auto"  # auto, eth0, или конкретный интерфейс
    capture_filter: str = "tcp port 443"  # BPF фильтр

    # Детекция блокировок
    rst_injection_threshold: float = 0.1  # Порог для детекции RST инъекций (секунды)
    connection_timeout_threshold: float = 10.0  # Таймаут соединения
    suspicious_timing_threshold: float = 0.05  # Подозрительный тайминг

    # Производительность
    max_concurrent_connections: int = 1000
    packet_buffer_size: int = 10000
    analysis_batch_size: int = 100

    # Интеграция
    enable_adaptive_engine_integration: bool = True
    enable_dpi_fingerprinting: bool = True
    auto_trigger_calibration: bool = True

    # Уведомления
    notification_cooldown_seconds: int = 300  # 5 минут между уведомлениями для одного домена

    # Хранение данных
    events_retention_hours: int = 24
    pcap_samples_enabled: bool = True
    pcap_samples_max_size_mb: int = 100


class ConnectionTracker:
    """Отслеживание TCP соединений"""

    def __init__(self):
        self.connections: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()

    def _get_connection_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        """Генерация ключа соединения"""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

    def track_connection_start(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        """Отслеживание начала соединения"""
        key = self._get_connection_key(src_ip, src_port, dst_ip, dst_port)

        with self.lock:
            self.connections[key] = {
                "start_time": datetime.now(),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "packets_sent": 0,
                "packets_received": 0,
                "last_activity": datetime.now(),
                "state": "connecting",
                "rst_received": False,
                "tls_handshake_started": False,
                "tls_handshake_completed": False,
            }

    def update_connection(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, packet_info: Dict[str, Any]
    ):
        """Обновление информации о соединении"""
        key = self._get_connection_key(src_ip, src_port, dst_ip, dst_port)

        with self.lock:
            if key in self.connections:
                conn = self.connections[key]
                conn["last_activity"] = datetime.now()

                # Обновляем счетчики пакетов
                if packet_info.get("direction") == "outbound":
                    conn["packets_sent"] += 1
                else:
                    conn["packets_received"] += 1

                # Обновляем состояние на основе флагов TCP
                tcp_flags = packet_info.get("tcp_flags", {})
                if tcp_flags.get("RST"):
                    conn["rst_received"] = True
                    conn["state"] = "reset"
                elif tcp_flags.get("SYN") and tcp_flags.get("ACK"):
                    conn["state"] = "established"

                # Отслеживаем TLS handshake
                if packet_info.get("has_tls"):
                    if not conn["tls_handshake_started"]:
                        conn["tls_handshake_started"] = True
                    if packet_info.get("tls_handshake_complete"):
                        conn["tls_handshake_completed"] = True

    def get_connection_info(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> Optional[Dict[str, Any]]:
        """Получение информации о соединении"""
        key = self._get_connection_key(src_ip, src_port, dst_ip, dst_port)

        with self.lock:
            return self.connections.get(key)

    def cleanup_old_connections(self, max_age_minutes: int = 30):
        """Очистка старых соединений"""
        cutoff_time = datetime.now() - timedelta(minutes=max_age_minutes)

        with self.lock:
            old_keys = [
                key for key, conn in self.connections.items() if conn["last_activity"] < cutoff_time
            ]

            for key in old_keys:
                del self.connections[key]

        if old_keys:
            LOG.debug(f"Cleaned up {len(old_keys)} old connections")


class TrafficAnalyzer:
    """Анализатор сетевого трафика для обнаружения блокировок"""

    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.connection_tracker = ConnectionTracker()

        # Статистика
        self.stats = {
            "packets_analyzed": 0,
            "connections_tracked": 0,
            "blocks_detected": 0,
            "rst_injections_detected": 0,
            "tls_failures_detected": 0,
            "analysis_time_ms": 0.0,
        }

    def analyze_packet(self, packet) -> List[TrafficEvent]:
        """Анализ одного пакета"""
        if not SCAPY_AVAILABLE:
            return []

        events = []
        analysis_start = time.time()

        try:
            # Проверяем, что это TCP пакет
            if not packet.haslayer(TCP):
                return events

            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            # Извлекаем информацию о пакете
            packet_info = {
                "direction": "outbound" if dst_port == 443 else "inbound",
                "tcp_flags": {
                    "SYN": bool(tcp_layer.flags.S),
                    "ACK": bool(tcp_layer.flags.A),
                    "RST": bool(tcp_layer.flags.R),
                    "FIN": bool(tcp_layer.flags.F),
                },
                "has_tls": packet.haslayer(TLS),
                "packet_size": len(packet),
            }

            # Отслеживаем соединение
            if packet_info["tcp_flags"]["SYN"] and not packet_info["tcp_flags"]["ACK"]:
                # Начало нового соединения
                self.connection_tracker.track_connection_start(src_ip, src_port, dst_ip, dst_port)

                events.append(
                    TrafficEvent(
                        event_type=TrafficEventType.CONNECTION_ATTEMPT,
                        timestamp=datetime.now(),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        dest_port=dst_port,
                        confidence=1.0,
                    )
                )

            # Обновляем информацию о соединении
            self.connection_tracker.update_connection(
                src_ip, src_port, dst_ip, dst_port, packet_info
            )

            # Анализируем на предмет блокировок
            block_events = self._analyze_for_blocks(src_ip, src_port, dst_ip, dst_port, packet_info)
            events.extend(block_events)

            self.stats["packets_analyzed"] += 1

        except Exception as e:
            LOG.warning(f"Error analyzing packet: {e}")

        finally:
            analysis_time = (time.time() - analysis_start) * 1000
            self.stats["analysis_time_ms"] = (
                (
                    (
                        self.stats["analysis_time_ms"] * (self.stats["packets_analyzed"] - 1)
                        + analysis_time
                    )
                    / self.stats["packets_analyzed"]
                )
                if self.stats["packets_analyzed"] > 0
                else analysis_time
            )

        return events

    def _analyze_for_blocks(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, packet_info: Dict[str, Any]
    ) -> List[TrafficEvent]:
        """Анализ пакета на предмет блокировок"""
        events = []

        # Получаем информацию о соединении
        conn_info = self.connection_tracker.get_connection_info(src_ip, src_port, dst_ip, dst_port)
        if not conn_info:
            return events

        # Детекция RST инъекций
        if packet_info["tcp_flags"]["RST"]:
            connection_duration = (datetime.now() - conn_info["start_time"]).total_seconds()

            # Подозрительно быстрый RST может указывать на инъекцию
            if connection_duration < self.config.rst_injection_threshold:
                events.append(
                    TrafficEvent(
                        event_type=TrafficEventType.RST_INJECTION,
                        timestamp=datetime.now(),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        dest_port=dst_port,
                        block_type=BlockType.TCP_RST_BLOCKING,
                        duration_ms=connection_duration * 1000,
                        confidence=0.8,
                        evidence={
                            "rst_timing_ms": connection_duration * 1000,
                            "packets_exchanged": conn_info["packets_sent"]
                            + conn_info["packets_received"],
                        },
                    )
                )

                self.stats["rst_injections_detected"] += 1

        # Детекция проблем с TLS handshake
        if packet_info["has_tls"] and conn_info["tls_handshake_started"]:
            connection_duration = (datetime.now() - conn_info["start_time"]).total_seconds()

            # Если TLS handshake не завершился в разумное время
            if (
                connection_duration > 5.0
                and not conn_info["tls_handshake_completed"]
                and conn_info["packets_sent"] > 3
            ):

                events.append(
                    TrafficEvent(
                        event_type=TrafficEventType.TLS_HANDSHAKE_FAIL,
                        timestamp=datetime.now(),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        dest_port=dst_port,
                        block_type=BlockType.TLS_HANDSHAKE_BLOCKING,
                        duration_ms=connection_duration * 1000,
                        confidence=0.7,
                        evidence={
                            "handshake_duration_ms": connection_duration * 1000,
                            "packets_sent": conn_info["packets_sent"],
                        },
                    )
                )

                self.stats["tls_failures_detected"] += 1

        # Детекция таймаутов соединений
        if conn_info["state"] == "connecting":
            connection_duration = (datetime.now() - conn_info["start_time"]).total_seconds()

            if connection_duration > self.config.connection_timeout_threshold:
                events.append(
                    TrafficEvent(
                        event_type=TrafficEventType.CONNECTION_BLOCKED,
                        timestamp=datetime.now(),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        dest_port=dst_port,
                        block_type=BlockType.TIMEOUT_BLOCKING,
                        duration_ms=connection_duration * 1000,
                        confidence=0.6,
                        evidence={
                            "timeout_duration_ms": connection_duration * 1000,
                            "packets_sent": conn_info["packets_sent"],
                            "packets_received": conn_info["packets_received"],
                        },
                    )
                )

        return events

    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики анализатора"""
        return {**self.stats, "active_connections": len(self.connection_tracker.connections)}


class RealTimeMonitor:
    """
    Real-Time Monitor для пассивного анализа трафика и обнаружения блокировок.

    Основные функции:
    - Пассивный захват и анализ TCP трафика на порту 443
    - Автоматическое обнаружение новых блокировок
    - Интеграция с AdaptiveEngine для запуска калибровки
    - Система уведомлений об изменениях в DPI
    """

    def __init__(self, config: MonitoringConfig, adaptive_engine: Optional[Any] = None):
        self.config = config
        self.adaptive_engine = adaptive_engine

        # Компоненты
        self.traffic_analyzer = TrafficAnalyzer(config)

        # Состояние мониторинга
        self.is_running = False
        self.capture_task: Optional[asyncio.Task] = None
        self.analysis_task: Optional[asyncio.Task] = None

        # Буферы и очереди
        self.packet_queue = asyncio.Queue(maxsize=config.packet_buffer_size)
        self.event_queue = asyncio.Queue(maxsize=1000)

        # Уведомления и кэширование
        self.notification_cache: Dict[str, datetime] = {}
        self.detected_blocks: Dict[str, TrafficEvent] = {}

        # Статистика
        self.monitor_stats = {
            "start_time": None,
            "packets_captured": 0,
            "events_generated": 0,
            "calibrations_triggered": 0,
            "notifications_sent": 0,
            "capture_errors": 0,
        }

        # Интеграция с существующими компонентами
        self.dpi_fingerprint_service = None
        if ADAPTIVE_COMPONENTS_AVAILABLE:
            try:
                self.dpi_fingerprint_service = DPIFingerprintService()
            except Exception as e:
                LOG.warning(f"Failed to initialize DPI fingerprint service: {e}")

        LOG.info("RealTimeMonitor initialized")

    async def start(self):
        """Запуск Real-Time Monitor"""
        if self.is_running:
            LOG.warning("RealTimeMonitor is already running")
            return

        if not SCAPY_AVAILABLE:
            LOG.error("Scapy not available - cannot start packet capture")
            return

        LOG.info("Starting RealTimeMonitor...")

        self.is_running = True
        self.monitor_stats["start_time"] = datetime.now()

        # Запускаем задачи
        self.capture_task = asyncio.create_task(self._packet_capture_loop())
        self.analysis_task = asyncio.create_task(self._analysis_loop())

        # Запускаем периодическую очистку
        asyncio.create_task(self._cleanup_loop())

        LOG.info("RealTimeMonitor started successfully")

    async def stop(self):
        """Остановка Real-Time Monitor"""
        if not self.is_running:
            return

        LOG.info("Stopping RealTimeMonitor...")

        self.is_running = False

        # Отменяем задачи
        if self.capture_task:
            self.capture_task.cancel()
        if self.analysis_task:
            self.analysis_task.cancel()

        # Ждем завершения
        try:
            if self.capture_task:
                await self.capture_task
        except asyncio.CancelledError:
            pass

        try:
            if self.analysis_task:
                await self.analysis_task
        except asyncio.CancelledError:
            pass

        LOG.info("RealTimeMonitor stopped")

    async def _packet_capture_loop(self):
        """Основной цикл захвата пакетов"""
        LOG.info("Starting packet capture loop")

        try:
            if PYDIVERT_AVAILABLE and self.config.capture_interface == "auto":
                # Используем PyDivert на Windows
                await self._capture_with_pydivert()
            else:
                # Используем Scapy
                await self._capture_with_scapy()

        except Exception as e:
            LOG.error(f"Error in packet capture loop: {e}")
            self.monitor_stats["capture_errors"] += 1

    async def _capture_with_scapy(self):
        """Захват пакетов с помощью Scapy"""

        def packet_handler(packet):
            """Обработчик пакетов для Scapy"""
            if not self.is_running:
                return

            try:
                # Добавляем пакет в очередь неблокирующим способом
                if not self.packet_queue.full():
                    asyncio.create_task(self.packet_queue.put(packet))
                    self.monitor_stats["packets_captured"] += 1
                else:
                    LOG.warning("Packet queue is full, dropping packet")
            except Exception as e:
                LOG.warning(f"Error handling packet: {e}")

        # Запускаем захват в отдельном потоке
        def run_capture():
            try:
                scapy.sniff(
                    filter=self.config.capture_filter,
                    prn=packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.is_running,
                )
            except Exception as e:
                LOG.error(f"Scapy capture error: {e}")

        # Запускаем в executor чтобы не блокировать event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, run_capture)

    async def _capture_with_pydivert(self):
        """Захват пакетов с помощью PyDivert (Windows)"""
        try:
            with pydivert.WinDivert(self.config.capture_filter) as w:
                LOG.info("Started PyDivert packet capture")

                while self.is_running:
                    try:
                        # Захватываем пакет с таймаутом
                        packet = w.recv(timeout=1000)  # 1 секунда таймаут

                        if packet:
                            # Конвертируем в Scapy пакет для анализа
                            scapy_packet = scapy.Ether(packet.raw)

                            if not self.packet_queue.full():
                                await self.packet_queue.put(scapy_packet)
                                self.monitor_stats["packets_captured"] += 1

                            # Пропускаем пакет дальше (пассивный мониторинг)
                            w.send(packet)

                    except pydivert.WinDivertError as e:
                        if "timeout" not in str(e).lower():
                            LOG.warning(f"PyDivert error: {e}")
                    except Exception as e:
                        LOG.error(f"Error in PyDivert capture: {e}")
                        break

        except Exception as e:
            LOG.error(f"Failed to initialize PyDivert: {e}")
            # Fallback к Scapy
            await self._capture_with_scapy()

    async def _analysis_loop(self):
        """Основной цикл анализа пакетов"""
        LOG.info("Starting packet analysis loop")

        batch = []

        while self.is_running:
            try:
                # Собираем батч пакетов
                while len(batch) < self.config.analysis_batch_size and self.is_running:
                    try:
                        packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                        batch.append(packet)
                    except asyncio.TimeoutError:
                        break

                if not batch:
                    continue

                # Анализируем батч
                await self._analyze_packet_batch(batch)
                batch.clear()

            except Exception as e:
                LOG.error(f"Error in analysis loop: {e}")
                await asyncio.sleep(1)

    async def _analyze_packet_batch(self, packets: List[Any]):
        """Анализ батча пакетов"""
        for packet in packets:
            try:
                events = self.traffic_analyzer.analyze_packet(packet)

                for event in events:
                    await self._handle_traffic_event(event)

            except Exception as e:
                LOG.warning(f"Error analyzing packet: {e}")

    async def _handle_traffic_event(self, event: TrafficEvent):
        """Обработка события трафика"""
        self.monitor_stats["events_generated"] += 1

        # Добавляем в очередь событий
        if not self.event_queue.full():
            await self.event_queue.put(event)

        # Обрабатываем блокировки
        if event.event_type in [
            TrafficEventType.CONNECTION_BLOCKED,
            TrafficEventType.RST_INJECTION,
            TrafficEventType.TLS_HANDSHAKE_FAIL,
        ]:

            await self._handle_blocking_event(event)

    async def _handle_blocking_event(self, event: TrafficEvent):
        """Обработка события блокировки"""
        domain_key = f"{event.dest_ip}:{event.dest_port}"

        # Проверяем cooldown для уведомлений
        if domain_key in self.notification_cache:
            time_since_last = datetime.now() - self.notification_cache[domain_key]
            if time_since_last.total_seconds() < self.config.notification_cooldown_seconds:
                return

        # Сохраняем событие блокировки
        self.detected_blocks[domain_key] = event
        self.notification_cache[domain_key] = datetime.now()

        LOG.warning(
            f"🚨 Detected blocking: {event.block_type.value if event.block_type else 'unknown'} "
            f"for {event.dest_ip}:{event.dest_port}"
        )

        # Отправляем уведомление
        await self._send_notification(event)

        # Запускаем калибровку если включена интеграция
        if self.config.auto_trigger_calibration and self.adaptive_engine and event.domain:

            await self._trigger_adaptive_calibration(event)

    async def _send_notification(self, event: TrafficEvent):
        """Отправка уведомления о блокировке"""
        notification = {
            "type": "blocking_detected",
            "timestamp": event.timestamp.isoformat(),
            "event": event.to_dict(),
            "severity": "high" if event.confidence > 0.7 else "medium",
        }

        # Здесь можно добавить интеграцию с системами уведомлений
        # (email, Slack, webhook и т.д.)

        LOG.info(f"📢 Notification sent: {notification['type']}")
        self.monitor_stats["notifications_sent"] += 1

    async def _trigger_adaptive_calibration(self, event: TrafficEvent):
        """Запуск адаптивной калибровки"""
        if not self.adaptive_engine or not event.domain:
            return

        try:
            LOG.info(f"🔧 Triggering adaptive calibration for {event.domain}")

            # Запускаем калибровку в фоне
            calibration_task = asyncio.create_task(
                self.adaptive_engine.find_best_strategy(event.domain)
            )

            self.monitor_stats["calibrations_triggered"] += 1

            # Не ждем завершения, чтобы не блокировать мониторинг

        except Exception as e:
            LOG.error(f"Error triggering calibration: {e}")

    async def _cleanup_loop(self):
        """Периодическая очистка данных"""
        while self.is_running:
            try:
                await asyncio.sleep(300)  # Каждые 5 минут

                # Очищаем старые соединения
                self.traffic_analyzer.connection_tracker.cleanup_old_connections()

                # Очищаем старые уведомления
                cutoff_time = datetime.now() - timedelta(hours=self.config.events_retention_hours)

                old_notifications = [
                    key
                    for key, timestamp in self.notification_cache.items()
                    if timestamp < cutoff_time
                ]

                for key in old_notifications:
                    del self.notification_cache[key]

                # Очищаем старые события блокировок
                old_blocks = [
                    key
                    for key, event in self.detected_blocks.items()
                    if event.timestamp < cutoff_time
                ]

                for key in old_blocks:
                    del self.detected_blocks[key]

                if old_notifications or old_blocks:
                    LOG.debug(
                        f"Cleaned up {len(old_notifications)} notifications and {len(old_blocks)} block events"
                    )

            except Exception as e:
                LOG.error(f"Error in cleanup loop: {e}")

    def get_status_report(self) -> Dict[str, Any]:
        """Получение отчета о состоянии монитора"""
        uptime_seconds = 0
        if self.monitor_stats["start_time"]:
            uptime_seconds = (datetime.now() - self.monitor_stats["start_time"]).total_seconds()

        return {
            "is_running": self.is_running,
            "uptime_seconds": uptime_seconds,
            "config": {
                "capture_filter": self.config.capture_filter,
                "auto_calibration": self.config.auto_trigger_calibration,
                "dpi_fingerprinting": self.config.enable_dpi_fingerprinting,
            },
            "statistics": {**self.monitor_stats, **self.traffic_analyzer.get_statistics()},
            "current_state": {
                "packet_queue_size": self.packet_queue.qsize(),
                "event_queue_size": self.event_queue.qsize(),
                "active_notifications": len(self.notification_cache),
                "detected_blocks": len(self.detected_blocks),
            },
            "recent_blocks": [
                event.to_dict() for event in list(self.detected_blocks.values())[-10:]
            ],
        }

    def get_detected_blocks(self) -> List[Dict[str, Any]]:
        """Получение списка обнаруженных блокировок"""
        return [event.to_dict() for event in self.detected_blocks.values()]

    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Получение последних событий"""
        events = []
        temp_queue = []

        # Извлекаем события из очереди
        while not self.event_queue.empty() and len(events) < limit:
            try:
                event = self.event_queue.get_nowait()
                events.append(event.to_dict())
                temp_queue.append(event)
            except asyncio.QueueEmpty:
                break

        # Возвращаем события обратно в очередь
        for event in temp_queue:
            if not self.event_queue.full():
                await self.event_queue.put(event)

        return events


# Интеграция с существующим monitoring_system.py
class MonitoringSystemIntegration:
    """Интеграция Real-Time Monitor с существующим MonitoringSystem"""

    def __init__(self, monitoring_system, real_time_monitor: RealTimeMonitor):
        self.monitoring_system = monitoring_system
        self.real_time_monitor = real_time_monitor

        # Подписываемся на события блокировок
        self._setup_event_handlers()

    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        # Здесь можно добавить интеграцию с событиями MonitoringSystem
        pass

    async def sync_monitored_domains(self):
        """Синхронизация доменов между системами"""
        if hasattr(self.monitoring_system, "monitored_sites"):
            for site_key, health in self.monitoring_system.monitored_sites.items():
                # Добавляем домены из MonitoringSystem в Real-Time Monitor
                # для более точного анализа
                pass

    def get_combined_status(self) -> Dict[str, Any]:
        """Получение объединенного статуса обеих систем"""
        monitoring_status = self.monitoring_system.get_status_report()
        rtm_status = self.real_time_monitor.get_status_report()

        return {
            "monitoring_system": monitoring_status,
            "real_time_monitor": rtm_status,
            "integration": {"active": True, "synchronized_domains": 0},  # Можно добавить подсчет
        }


# Пример использования
if __name__ == "__main__":
    import asyncio

    async def test_real_time_monitor():
        # Создаем конфигурацию
        config = MonitoringConfig(
            capture_filter="tcp port 443",
            auto_trigger_calibration=False,  # Отключаем для теста
            notification_cooldown_seconds=60,
        )

        # Создаем монитор
        monitor = RealTimeMonitor(config)

        try:
            # Запускаем мониторинг
            await monitor.start()

            print("Real-Time Monitor started. Monitoring traffic...")
            print("Press Ctrl+C to stop")

            # Мониторим в течение некоторого времени
            for i in range(30):  # 30 секунд
                await asyncio.sleep(1)

                if i % 10 == 0:
                    status = monitor.get_status_report()
                    print(
                        f"Status: {status['statistics']['packets_captured']} packets captured, "
                        f"{status['statistics']['events_generated']} events generated"
                    )

        except KeyboardInterrupt:
            print("\nStopping monitor...")
        finally:
            await monitor.stop()

            # Финальный отчет
            final_status = monitor.get_status_report()
            print(f"\nFinal statistics:")
            print(f"  Packets captured: {final_status['statistics']['packets_captured']}")
            print(f"  Events generated: {final_status['statistics']['events_generated']}")
            print(f"  Blocks detected: {len(final_status['recent_blocks'])}")

    # Запускаем тест
    asyncio.run(test_real_time_monitor())
