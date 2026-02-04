"""
Real-Time Traffic Analyzer для онлайн анализа трафика

Задача 9.1: Создать Real-Time Traffic Analyzer
- Захват трафика в реальном времени с помощью PyDivert
- Детектор блокировок в режиме реального времени
- Анализ паттернов трафика для выявления DPI характеристик
- Система уведомлений о новых типах блокировок
- Буферизация и анализ трафика для последующей обработки
"""

import asyncio
import logging
import threading
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
import json
from pathlib import Path

# PyDivert imports with fallback
PYDIVERT_AVAILABLE = False
try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    pydivert = None

# Scapy imports for packet analysis
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, TLS, DNS, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    pass

LOG = logging.getLogger("RealTimeTrafficAnalyzer")


class TrafficEvent(Enum):
    """Типы событий трафика"""

    CONNECTION_BLOCKED = "connection_blocked"
    RST_INJECTION_DETECTED = "rst_injection_detected"
    DNS_POISONING_DETECTED = "dns_poisoning_detected"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    SUSPICIOUS_REDIRECT = "suspicious_redirect"
    NEW_BLOCKING_PATTERN = "new_blocking_pattern"
    DPI_BEHAVIOR_CHANGE = "dpi_behavior_change"


@dataclass
class PacketInfo:
    """Информация о пакете"""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    flags: str = ""
    payload_snippet: str = ""


@dataclass
class TrafficAlert:
    """Алерт о событии в трафике"""

    event_type: TrafficEvent
    timestamp: datetime
    domain: Optional[str]
    target_ip: str
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    packet_info: Optional[PacketInfo] = None


@dataclass
class ConnectionFlow:
    """Поток соединения"""

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    start_time: datetime
    last_activity: datetime
    packets: List[PacketInfo] = field(default_factory=list)
    state: str = "ACTIVE"
    domain: Optional[str] = None


class RealTimeTrafficAnalyzer:
    """
    Анализатор трафика в реальном времени

    Реализует требования FR-14.1, FR-14.2, FR-14.3:
    - Захват трафика в реальном времени
    - Детекция блокировок в режиме реального времени
    - Анализ паттернов трафика
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()

        # Состояние анализатора
        self.is_running = False
        self.capture_thread = None
        self.analysis_thread = None

        # Буферы данных
        self.packet_buffer = deque(maxlen=self.config["buffer_size"])
        self.connection_flows = {}  # flow_id -> ConnectionFlow
        self.recent_alerts = deque(maxlen=1000)

        # Статистика
        self.stats = {
            "packets_captured": 0,
            "packets_analyzed": 0,
            "alerts_generated": 0,
            "connections_tracked": 0,
            "start_time": None,
            "last_activity": None,
        }

        # Обработчики событий
        self.event_handlers = defaultdict(list)

        # Детекторы паттернов
        self.pattern_detectors = self._initialize_pattern_detectors()

        # Кэш DNS резолвинга
        self.dns_cache = {}

        LOG.info("✅ RealTimeTrafficAnalyzer инициализирован")

    def _default_config(self) -> Dict[str, Any]:
        """Конфигурация по умолчанию"""
        return {
            "capture_filter": "tcp port 443 or tcp port 80 or udp port 53",
            "buffer_size": 10000,
            "analysis_interval": 1.0,  # секунды
            "connection_timeout": 300,  # 5 минут
            "alert_cooldown": 30,  # секунды между одинаковыми алертами
            "max_packet_size": 1500,
            "enable_payload_analysis": True,
            "enable_dns_resolution": True,
            "debug_mode": False,
        }

    def _initialize_pattern_detectors(self) -> Dict[str, Callable]:
        """Инициализация детекторов паттернов"""
        return {
            "rst_injection": self._detect_rst_injection,
            "dns_poisoning": self._detect_dns_poisoning,
            "tls_handshake_failure": self._detect_tls_handshake_failure,
            "connection_blocking": self._detect_connection_blocking,
            "suspicious_redirect": self._detect_suspicious_redirect,
        }

    async def start_monitoring(self):
        """Запуск мониторинга трафика"""
        if self.is_running:
            LOG.warning("⚠️ Анализатор уже запущен")
            return

        if not PYDIVERT_AVAILABLE:
            LOG.error("❌ PyDivert недоступен - невозможно захватывать трафик")
            raise RuntimeError("PyDivert not available")

        LOG.info("🚀 Запуск мониторинга трафика в реальном времени")

        try:
            self.is_running = True
            self.stats["start_time"] = datetime.now()

            # Запускаем поток захвата пакетов
            self.capture_thread = threading.Thread(target=self._capture_packets_thread, daemon=True)
            self.capture_thread.start()

            # Запускаем поток анализа
            self.analysis_thread = threading.Thread(target=self._analysis_thread, daemon=True)
            self.analysis_thread.start()

            LOG.info("✅ Мониторинг трафика запущен")

        except Exception as e:
            LOG.error(f"❌ Ошибка запуска мониторинга: {e}")
            self.is_running = False
            raise

    async def stop_monitoring(self):
        """Остановка мониторинга трафика"""
        if not self.is_running:
            return

        LOG.info("🛑 Остановка мониторинга трафика")

        self.is_running = False

        # Ждем завершения потоков
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5.0)

        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5.0)

        LOG.info("✅ Мониторинг трафика остановлен")

    def _capture_packets_thread(self):
        """Поток захвата пакетов"""
        LOG.info("📡 Запуск потока захвата пакетов")

        try:
            with pydivert.WinDivert(self.config["capture_filter"]) as w:
                for packet in w:
                    if not self.is_running:
                        break

                    try:
                        # Обрабатываем пакет
                        packet_info = self._process_packet(packet)
                        if packet_info:
                            self.packet_buffer.append(packet_info)
                            self.stats["packets_captured"] += 1
                            self.stats["last_activity"] = datetime.now()

                        # Пропускаем пакет дальше
                        w.send(packet)

                    except Exception as e:
                        if self.config["debug_mode"]:
                            LOG.debug(f"Ошибка обработки пакета: {e}")
                        continue

        except Exception as e:
            LOG.error(f"❌ Ошибка захвата пакетов: {e}")
            self.is_running = False

    def _process_packet(self, packet) -> Optional[PacketInfo]:
        """Обработка захваченного пакета"""
        try:
            # Парсим пакет через Scapy если доступен
            if SCAPY_AVAILABLE:
                scapy_packet = IP(packet.raw)

                packet_info = PacketInfo(
                    timestamp=time.time(),
                    src_ip=scapy_packet.src,
                    dst_ip=scapy_packet.dst,
                    src_port=0,
                    dst_port=0,
                    protocol="IP",
                    size=len(packet.raw),
                )

                # Дополнительная информация для TCP
                if TCP in scapy_packet:
                    packet_info.src_port = scapy_packet[TCP].sport
                    packet_info.dst_port = scapy_packet[TCP].dport
                    packet_info.protocol = "TCP"
                    packet_info.flags = str(scapy_packet[TCP].flags)

                    # Извлекаем snippet payload
                    if Raw in scapy_packet and self.config["enable_payload_analysis"]:
                        payload = scapy_packet[Raw].load
                        packet_info.payload_snippet = payload[:100].decode("utf-8", errors="ignore")

                # Дополнительная информация для DNS
                elif DNS in scapy_packet:
                    packet_info.protocol = "DNS"
                    if scapy_packet[DNS].qr == 0:  # Query
                        packet_info.payload_snippet = f"DNS Query: {scapy_packet[DNS].qd.qname.decode('utf-8', errors='ignore')}"
                    else:  # Response
                        packet_info.payload_snippet = f"DNS Response: {scapy_packet[DNS].rcode}"

                return packet_info

            else:
                # Базовая обработка без Scapy
                return PacketInfo(
                    timestamp=time.time(),
                    src_ip="unknown",
                    dst_ip="unknown",
                    src_port=0,
                    dst_port=0,
                    protocol="unknown",
                    size=len(packet.raw),
                )

        except Exception as e:
            if self.config["debug_mode"]:
                LOG.debug(f"Ошибка парсинга пакета: {e}")
            return None

    def _analysis_thread(self):
        """Поток анализа трафика"""
        LOG.info("🔍 Запуск потока анализа трафика")

        while self.is_running:
            try:
                # Анализируем накопленные пакеты
                self._analyze_buffered_packets()

                # Очищаем старые соединения
                self._cleanup_old_connections()

                # Спим до следующего цикла анализа
                time.sleep(self.config["analysis_interval"])

            except Exception as e:
                LOG.error(f"❌ Ошибка анализа трафика: {e}")
                time.sleep(1.0)

    def _analyze_buffered_packets(self):
        """Анализ буферизованных пакетов"""
        if not self.packet_buffer:
            return

        # Копируем буфер для анализа
        packets_to_analyze = list(self.packet_buffer)

        try:
            # Обновляем соединения
            self._update_connection_flows(packets_to_analyze)

            # Запускаем детекторы паттернов
            for detector_name, detector_func in self.pattern_detectors.items():
                try:
                    alerts = detector_func(packets_to_analyze)
                    for alert in alerts:
                        self._handle_alert(alert)
                except Exception as e:
                    if self.config["debug_mode"]:
                        LOG.debug(f"Ошибка детектора {detector_name}: {e}")

            self.stats["packets_analyzed"] += len(packets_to_analyze)

        except Exception as e:
            LOG.error(f"❌ Ошибка анализа буфера: {e}")

    def _update_connection_flows(self, packets: List[PacketInfo]):
        """Обновление потоков соединений"""
        for packet in packets:
            if packet.protocol != "TCP":
                continue

            # Создаем ID потока
            flow_id = self._create_flow_id(packet)

            # Получаем или создаем поток
            if flow_id not in self.connection_flows:
                self.connection_flows[flow_id] = ConnectionFlow(
                    flow_id=flow_id,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    start_time=datetime.fromtimestamp(packet.timestamp),
                    last_activity=datetime.fromtimestamp(packet.timestamp),
                )
                self.stats["connections_tracked"] += 1

            # Обновляем поток
            flow = self.connection_flows[flow_id]
            flow.last_activity = datetime.fromtimestamp(packet.timestamp)
            flow.packets.append(packet)

            # Ограничиваем количество пакетов в потоке
            if len(flow.packets) > 100:
                flow.packets = flow.packets[-50:]  # Оставляем последние 50

            # Резолвим домен если возможно
            if not flow.domain and self.config["enable_dns_resolution"]:
                flow.domain = self._resolve_domain(packet.dst_ip)

    def _create_flow_id(self, packet: PacketInfo) -> str:
        """Создание ID потока соединения"""
        # Нормализуем направление потока
        if packet.src_ip < packet.dst_ip:
            return f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}"
        else:
            return f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}"

    def _resolve_domain(self, ip: str) -> Optional[str]:
        """Резолвинг домена по IP (с кэшированием)"""
        if ip in self.dns_cache:
            return self.dns_cache[ip]

        try:
            import socket

            domain = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = domain
            return domain
        except:
            self.dns_cache[ip] = None
            return None

    def _cleanup_old_connections(self):
        """Очистка старых соединений"""
        cutoff_time = datetime.now() - timedelta(seconds=self.config["connection_timeout"])

        old_flows = [
            flow_id
            for flow_id, flow in self.connection_flows.items()
            if flow.last_activity < cutoff_time
        ]

        for flow_id in old_flows:
            del self.connection_flows[flow_id]

        if old_flows and self.config["debug_mode"]:
            LOG.debug(f"🧹 Очищено {len(old_flows)} старых соединений")

    # Детекторы паттернов
    def _detect_rst_injection(self, packets: List[PacketInfo]) -> List[TrafficAlert]:
        """Детекция RST инъекций в реальном времени"""
        alerts = []

        try:
            rst_packets = [p for p in packets if p.protocol == "TCP" and "R" in p.flags]

            for rst_packet in rst_packets:
                # Ищем соответствующий поток
                flow_id = self._create_flow_id(rst_packet)
                flow = self.connection_flows.get(flow_id)

                if flow and len(flow.packets) > 1:
                    # Анализируем подозрительность RST
                    suspicion_score = self._calculate_rst_suspicion(rst_packet, flow)

                    if suspicion_score > 0.6:
                        alert = TrafficAlert(
                            event_type=TrafficEvent.RST_INJECTION_DETECTED,
                            timestamp=datetime.fromtimestamp(rst_packet.timestamp),
                            domain=flow.domain,
                            target_ip=rst_packet.dst_ip,
                            confidence=suspicion_score,
                            details={
                                "rst_src_ip": rst_packet.src_ip,
                                "flow_packets_count": len(flow.packets),
                                "flow_duration": (
                                    flow.last_activity - flow.start_time
                                ).total_seconds(),
                            },
                            packet_info=rst_packet,
                        )
                        alerts.append(alert)

        except Exception as e:
            if self.config["debug_mode"]:
                LOG.debug(f"Ошибка детекции RST: {e}")

        return alerts

    def _calculate_rst_suspicion(self, rst_packet: PacketInfo, flow: ConnectionFlow) -> float:
        """Вычисление подозрительности RST пакета"""
        suspicion = 0.0

        # Быстрый RST после начала соединения
        time_since_start = rst_packet.timestamp - flow.start_time.timestamp()
        if time_since_start < 0.1:  # Меньше 100ms
            suspicion += 0.4

        # RST от неожиданного источника
        expected_ips = {flow.src_ip, flow.dst_ip}
        if rst_packet.src_ip not in expected_ips:
            suspicion += 0.5

        # Малое количество пакетов в потоке
        if len(flow.packets) < 5:
            suspicion += 0.2

        return min(suspicion, 1.0)

    def _detect_dns_poisoning(self, packets: List[PacketInfo]) -> List[TrafficAlert]:
        """Детекция DNS poisoning"""
        alerts = []

        try:
            dns_packets = [p for p in packets if p.protocol == "DNS"]

            for packet in dns_packets:
                if "DNS Response" in packet.payload_snippet:
                    # Простая проверка на подозрительные ответы
                    if (
                        "NXDOMAIN" in packet.payload_snippet
                        or "127.0.0.1" in packet.payload_snippet
                    ):
                        alert = TrafficAlert(
                            event_type=TrafficEvent.DNS_POISONING_DETECTED,
                            timestamp=datetime.fromtimestamp(packet.timestamp),
                            domain=None,
                            target_ip=packet.src_ip,
                            confidence=0.7,
                            details={
                                "dns_response": packet.payload_snippet,
                                "response_src": packet.src_ip,
                            },
                            packet_info=packet,
                        )
                        alerts.append(alert)

        except Exception as e:
            if self.config["debug_mode"]:
                LOG.debug(f"Ошибка детекции DNS poisoning: {e}")

        return alerts

    def _detect_tls_handshake_failure(self, packets: List[PacketInfo]) -> List[TrafficAlert]:
        """Детекция неудач TLS handshake"""
        alerts = []

        try:
            # Ищем потоки с TLS трафиком
            for flow in self.connection_flows.values():
                if not flow.packets:
                    continue

                # Проверяем наличие TLS трафика
                tls_packets = [p for p in flow.packets if p.dst_port == 443 or p.src_port == 443]

                if tls_packets and len(tls_packets) < 5:  # Мало пакетов для успешного handshake
                    # Проверяем время с начала соединения
                    duration = (flow.last_activity - flow.start_time).total_seconds()

                    if duration > 5.0:  # Долгое соединение без успеха
                        alert = TrafficAlert(
                            event_type=TrafficEvent.TLS_HANDSHAKE_FAILED,
                            timestamp=flow.last_activity,
                            domain=flow.domain,
                            target_ip=flow.dst_ip,
                            confidence=0.6,
                            details={
                                "tls_packets_count": len(tls_packets),
                                "connection_duration": duration,
                                "total_packets": len(flow.packets),
                            },
                        )
                        alerts.append(alert)

        except Exception as e:
            if self.config["debug_mode"]:
                LOG.debug(f"Ошибка детекции TLS handshake: {e}")

        return alerts

    def _detect_connection_blocking(self, packets: List[PacketInfo]) -> List[TrafficAlert]:
        """Детекция блокировки соединений"""
        alerts = []

        try:
            # Анализируем потоки на предмет блокировки
            for flow in self.connection_flows.values():
                if len(flow.packets) < 2:
                    continue

                # Ищем паттерны блокировки
                syn_packets = [p for p in flow.packets if "S" in p.flags]
                rst_packets = [p for p in flow.packets if "R" in p.flags]

                # SYN без ответа + RST = возможная блокировка
                if syn_packets and rst_packets and len(flow.packets) < 5:
                    alert = TrafficAlert(
                        event_type=TrafficEvent.CONNECTION_BLOCKED,
                        timestamp=flow.last_activity,
                        domain=flow.domain,
                        target_ip=flow.dst_ip,
                        confidence=0.5,
                        details={
                            "syn_packets": len(syn_packets),
                            "rst_packets": len(rst_packets),
                            "total_packets": len(flow.packets),
                        },
                    )
                    alerts.append(alert)

        except Exception as e:
            if self.config["debug_mode"]:
                LOG.debug(f"Ошибка детекции блокировки: {e}")

        return alerts

    def _detect_suspicious_redirect(self, packets: List[PacketInfo]) -> List[TrafficAlert]:
        """Детекция подозрительных редиректов"""
        alerts = []

        try:
            http_packets = [
                p
                for p in packets
                if p.protocol == "TCP"
                and (p.dst_port == 80 or p.src_port == 80)
                and "HTTP" in p.payload_snippet
            ]

            for packet in http_packets:
                if any(code in packet.payload_snippet for code in ["301", "302", "303"]):
                    # Проверяем на подозрительные редиректы
                    if any(
                        keyword in packet.payload_snippet.lower()
                        for keyword in ["blocked", "forbidden", "restricted"]
                    ):

                        alert = TrafficAlert(
                            event_type=TrafficEvent.SUSPICIOUS_REDIRECT,
                            timestamp=datetime.fromtimestamp(packet.timestamp),
                            domain=None,
                            target_ip=packet.src_ip,
                            confidence=0.7,
                            details={
                                "http_response": packet.payload_snippet[:200],
                                "response_src": packet.src_ip,
                            },
                            packet_info=packet,
                        )
                        alerts.append(alert)

        except Exception as e:
            if self.config["debug_mode"]:
                LOG.debug(f"Ошибка детекции редиректов: {e}")

        return alerts

    def _handle_alert(self, alert: TrafficAlert):
        """Обработка алерта"""
        try:
            # Проверяем cooldown для предотвращения спама
            if self._is_alert_in_cooldown(alert):
                return

            # Добавляем в буфер алертов
            self.recent_alerts.append(alert)
            self.stats["alerts_generated"] += 1

            # Вызываем обработчики событий
            handlers = self.event_handlers.get(alert.event_type, [])
            for handler in handlers:
                try:
                    handler(alert)
                except Exception as e:
                    LOG.error(f"❌ Ошибка обработчика события: {e}")

            # Логируем алерт
            LOG.info(
                f"🚨 {alert.event_type.value}: {alert.target_ip} "
                f"(confidence: {alert.confidence:.2f})"
            )

        except Exception as e:
            LOG.error(f"❌ Ошибка обработки алерта: {e}")

    def _is_alert_in_cooldown(self, alert: TrafficAlert) -> bool:
        """Проверка cooldown для алерта"""
        cooldown_period = timedelta(seconds=self.config["alert_cooldown"])
        cutoff_time = alert.timestamp - cooldown_period

        # Ищем похожие алерты в недавнем прошлом
        for recent_alert in self.recent_alerts:
            if (
                recent_alert.event_type == alert.event_type
                and recent_alert.target_ip == alert.target_ip
                and recent_alert.timestamp > cutoff_time
            ):
                return True

        return False

    # Публичные методы для управления
    def add_event_handler(self, event_type: TrafficEvent, handler: Callable[[TrafficAlert], None]):
        """Добавление обработчика события"""
        self.event_handlers[event_type].append(handler)
        LOG.info(f"➕ Добавлен обработчик для {event_type.value}")

    def remove_event_handler(
        self, event_type: TrafficEvent, handler: Callable[[TrafficAlert], None]
    ):
        """Удаление обработчика события"""
        if handler in self.event_handlers[event_type]:
            self.event_handlers[event_type].remove(handler)
            LOG.info(f"➖ Удален обработчик для {event_type.value}")

    def get_recent_alerts(self, limit: int = 100) -> List[TrafficAlert]:
        """Получение недавних алертов"""
        return list(self.recent_alerts)[-limit:]

    def get_active_connections(self) -> List[ConnectionFlow]:
        """Получение активных соединений"""
        return list(self.connection_flows.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики анализатора"""
        stats = self.stats.copy()

        # Добавляем текущее состояние
        stats.update(
            {
                "is_running": self.is_running,
                "buffer_size": len(self.packet_buffer),
                "active_connections": len(self.connection_flows),
                "recent_alerts_count": len(self.recent_alerts),
                "event_handlers_count": sum(
                    len(handlers) for handlers in self.event_handlers.values()
                ),
            }
        )

        # Вычисляем производительность
        if stats["start_time"]:
            uptime = (datetime.now() - stats["start_time"]).total_seconds()
            stats["uptime_seconds"] = uptime

            if uptime > 0:
                stats["packets_per_second"] = stats["packets_captured"] / uptime
                stats["analysis_rate"] = stats["packets_analyzed"] / uptime

        return stats

    def export_alerts_to_file(self, filename: str = "traffic_alerts.json"):
        """Экспорт алертов в файл"""
        try:
            alerts_data = []

            for alert in self.recent_alerts:
                alert_dict = {
                    "event_type": alert.event_type.value,
                    "timestamp": alert.timestamp.isoformat(),
                    "domain": alert.domain,
                    "target_ip": alert.target_ip,
                    "confidence": alert.confidence,
                    "details": alert.details,
                }

                if alert.packet_info:
                    alert_dict["packet_info"] = {
                        "src_ip": alert.packet_info.src_ip,
                        "dst_ip": alert.packet_info.dst_ip,
                        "protocol": alert.packet_info.protocol,
                        "size": alert.packet_info.size,
                    }

                alerts_data.append(alert_dict)

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(alerts_data, f, indent=2, ensure_ascii=False)

            LOG.info(f"📊 Экспортировано {len(alerts_data)} алертов в {filename}")

        except Exception as e:
            LOG.error(f"❌ Ошибка экспорта алертов: {e}")

    def clear_alerts(self):
        """Очистка буфера алертов"""
        self.recent_alerts.clear()
        LOG.info("🧹 Буфер алертов очищен")

    def update_config(self, new_config: Dict[str, Any]):
        """Обновление конфигурации"""
        self.config.update(new_config)
        LOG.info(f"🔧 Конфигурация обновлена: {len(new_config)} параметров")
