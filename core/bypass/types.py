# recon/core/bypass/types.py

"""
Централизованные и строго типизированные определения для системы обхода DPI.
Этот модуль является фундаментом для всех компонентов, обеспечивая консистентность данных.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# --- Типовые псевдонимы для ясности ---
# Рецепт сегмента: (данные_payload, смещение_seq, {опции_модификации})
SegmentTuple = Tuple[bytes, int, Dict[str, Any]]


# --- Перечисления (Enums) ---


class EngineStatus(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class PacketDirection(Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"


class ProtocolType(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class BlockType(Enum):
    """
    Типы блокировок, обнаруженные при тестировании.
    Единый источник истины для всей системы.
    """
    # Успешные или нейтральные состояния
    NONE = "none"                          # Блокировки нет
    # Типы блокировок, определенные по поведению сети
    RST_INJECTION = "rst_injection"        # Получен RST-пакет (инжекция DPI)
    TIMEOUT = "timeout"                    # Соединение истекло по таймауту
    CONNECTION_REFUSED = "connection_refused"  # Соединение активно отклонено
    ICMP_UNREACH = "icmp_unreach"          # ICMP destination unreachable
    # Типы блокировок, определенные по содержимому ответа
    HTTP_BLOCK_PAGE = "http_block_page"    # HTTP-страница-заглушка
    CONTENT = "content"                    # Блокировка по содержимому
    HTTP_ERROR = "http_error"              # Общая HTTP-ошибка (4xx, 5xx)
    # Типы блокировок на уровне протоколов
    TLS_ALERT = "tls_alert"                # Получен TLS Alert
    TLS_HANDSHAKE_FAILURE = "tls_handshake_failure"  # Ошибка TLS handshake
    # Прочее
    INVALID = "invalid"                    # Невалидный/неожиданный ответ
    UNKNOWN = "unknown"                    # Не удалось классифицировать


# --- Основные структуры данных ---


@dataclass
class PacketInfo:
    """Унифицированная информация о сетевом пакете."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: ProtocolType
    direction: PacketDirection

    ip_version: int = 4
    ip_ttl: int = 64
    ip_id: int = 0

    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_window: Optional[int] = None

    payload: bytes = b""
    payload_size: int = 0
    raw_data: bytes = b""

    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        """Краткая сводка по пакету для логов."""
        proto_details = ""
        if self.protocol == ProtocolType.TCP:
            proto_details = (
                f"seq={self.tcp_seq} ack={self.tcp_ack} flags={self.tcp_flags}"
            )
        return (
            f"PacketInfo({self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
            f"proto={self.protocol.value} size={self.payload_size} {proto_details})"
        )


@dataclass
class SystemTestResult:
    """Результат одного реального HTTP/TLS теста."""

    domain: str
    success: bool
    latency_ms: Optional[float]
    status_code: Optional[int] = None
    error: Optional[str] = None
    block_type: Optional[BlockType] = None
    interceptor_used: Optional[str] = None
    content_length: Optional[int] = None
    headers: Optional[Dict[str, str]] = None


@dataclass
class AttackResult:
    """
    Результат выполнения атаки. Содержит "рецепт" для движка.
    """

    status: "AttackStatus"
    technique_used: Optional[str] = None
    error_message: Optional[str] = None
    latency_ms: float = 0.0

    # Ключевое поле: рецепт для отправки
    segments: Optional[List[SegmentTuple]] = None

    # Для обратной совместимости и простых атак
    modified_payload: Optional[bytes] = None

    # Статистика
    packets_sent: int = 0
    bytes_sent: int = 0

    # Дополнительные данные для анализа
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_segments(self) -> bool:
        return self.segments is not None and len(self.segments) > 0


@dataclass
class EngineStats:
    """Более структурированная статистика для движков."""

    packets: Dict[str, int] = field(
        default_factory=lambda: {
            "captured": 0,
            "processed": 0,
            "bypassed": 0,
            "dropped": 0,
            "error": 0,
        }
    )
    strategies: Dict[str, int] = field(
        default_factory=lambda: {"applied": 0, "success": 0, "failed": 0}
    )
    bytes: Dict[str, int] = field(
        default_factory=lambda: {"processed": 0, "modified": 0}
    )
    timing: Dict[str, float] = field(
        default_factory=lambda: {"start_time": time.time(), "total_processing_ms": 0.0}
    )

    def to_dict(self) -> Dict[str, Any]:
        uptime = time.time() - self.timing["start_time"]
        success_rate = (
            self.strategies["success"] / self.strategies["applied"]
            if self.strategies["applied"] > 0
            else 0.0
        )
        return {
            "uptime_seconds": uptime,
            "packets": self.packets,
            "strategies": {**self.strategies, "success_rate": success_rate},
            "bytes": self.bytes,
            "avg_processing_ms": (
                self.timing["total_processing_ms"] / self.packets["processed"]
                if self.packets["processed"] > 0
                else 0.0
            ),
        }

    def merge(self, other: "EngineStats") -> None:
        """Объединяет статистику из другого объекта."""
        for key in self.packets:
            self.packets[key] += other.packets.get(key, 0)
        for key in self.strategies:
            self.strategies[key] += other.strategies.get(key, 0)
        for key in self.bytes:
            self.bytes[key] += other.bytes.get(key, 0)
        self.timing["total_processing_ms"] += other.timing.get(
            "total_processing_ms", 0.0
        )


# --- Структуры для Фингерпринтинга (значительно расширены) ---


@dataclass
class StrategyResult:
    """Result of strategy execution."""

    success: bool
    technique_used: str
    execution_time_ms: float
    packets_sent: int = 0
    packets_modified: int = 0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return not self.success


@dataclass
class BehavioralFingerprint:
    """Поведенческие характеристики DPI."""

    rst_injection: bool = False
    timeout_pattern: bool = False
    stateful_tracking: bool = False
    rate_limiting_detected: bool = False


@dataclass
class TLSFingerprint:
    """Характеристики обработки TLS."""

    sni_sensitivity: str = "none"  # "none", "case", "midsld"
    ech_support: str = "unknown"  # "unknown", "supported", "blocked"
    tls_version_tolerance: List[str] = field(default_factory=list)
    cipher_suite_preference: Optional[str] = None


@dataclass
class HTTPFingerprint:
    """Характеристики обработки HTTP."""

    header_inspection: bool = False
    method_blocking: List[str] = field(default_factory=list)
    host_header_sensitivity: bool = False


@dataclass
class EnhancedDPIFingerprint:
    """
    Экспертная, структурированная модель фингерпринта DPI.
    """

    domain: str
    behavioral: BehavioralFingerprint = field(default_factory=BehavioralFingerprint)
    tls: TLSFingerprint = field(default_factory=TLSFingerprint)
    http: HTTPFingerprint = field(default_factory=HTTPFingerprint)

    # Общая классификация
    dpi_vendor_prediction: Optional[str] = None
    confidence_score: float = 0.0

    # Техническая информация
    effective_techniques: List[str] = field(default_factory=list)
    ineffective_techniques: List[str] = field(default_factory=list)

    # Метаданные
    created_at: float = field(default_factory=time.time)
    raw_probe_data: Dict[str, Any] = field(default_factory=dict)

    def short_hash(self) -> str:
        """Создает короткий, стабильный хеш для кэширования."""
        import hashlib

        data_str = (
            f"{self.dpi_vendor_prediction}:{self.behavioral.rst_injection}:"
            f"{self.tls.sni_sensitivity}:{self.http.header_inspection}"
        )
        return hashlib.sha1(data_str.encode()).hexdigest()[:12]
