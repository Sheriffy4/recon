"""
Data models and constants for failure analysis.

Contains dataclasses for failure patterns and analysis results,
plus knowledge base of failure patterns and technique effectiveness.
"""

from typing import List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class FailurePattern:
    """Represents a detected failure pattern."""

    pattern_type: str
    frequency: int
    confidence: float
    likely_causes: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    affected_techniques: List[str] = field(default_factory=list)


@dataclass
class FailureAnalysisResult:
    """Complete result of failure analysis."""

    total_failures: int
    failure_breakdown: Dict[str, int]
    detected_patterns: List[FailurePattern]
    strategic_recommendations: List[str] = field(default_factory=list)
    next_iteration_focus: List[str] = field(default_factory=list)
    dpi_behavior_insights: Dict[str, Any] = field(default_factory=dict)


# Knowledge base of failure patterns and their characteristics
FAILURE_PATTERNS = {
    "TIMEOUT_ON_SYN": {
        "причины": [
            "Порт закрыт файрволом (локальным или на сервере)",
            "IP-адрес заблокирован на уровне маршрутизации (blackhole)",
            "Неверный IP-адрес или домен недоступен",
        ],
        "решения": [
            "Убедитесь, что домен правильно резолвится (nslookup/dig)",
            "Попробуйте другой порт (e.g., 80, 8080, 8443)",
            "Используйте VPN для проверки, не заблокирован ли ваш IP",
        ],
        "strategic_focus": ["connection_establishment", "network_layer_bypass"],
    },
    "RST_RECEIVED": {
        "причины": [
            "DPI обнаружил сигнатуру в TLS ClientHello и сбросил соединение",
            "Выбранная стратегия обхода неэффективна против этого DPI",
            "Сервер сам отклонил соединение (редко для TLS)",
        ],
        "решения": [
            "Попробуйте стратегии с другим типом фрагментации (multisplit, fakeddisorder)",
            "Измените TTL для фейковых пакетов (--dpi-desync-ttl)",
            'Попробуйте более сложные "гоночные" атаки (badsum_race, md5_fool)',
        ],
        "strategic_focus": [
            "tls_obfuscation",
            "packet_manipulation",
            "timing_attacks",
        ],
    },
    "MIDDLEBOX_RST_RECEIVED": {
        "причины": [
            "DPI (middlebox) активно вмешивается и отправляет RST пакеты.",
            "Атака была обнаружена по сигнатуре или поведению.",
        ],
        "решения": [
            "Используйте атаки, которые не похожи на известные сигнатуры (например, `pacing_attack`).",
            "Попробуйте обфускацию полезной нагрузки или техники, меняющие 'форму' трафика.",
            "Избегайте простых техник фрагментации, которые легко детектируются.",
        ],
        "strategic_focus": [
            "payload_obfuscation",
            "traffic_mimicry",
            "stateful_tcp_manipulation",
        ],
    },
    "NO_SITES_WORKING": {
        "причины": [
            "Выбранная стратегия не работает ни для одного из тестовых сайтов",
            "DPI успешно противодействует данной технике",
        ],
        "решения": [
            "Запустите поиск с большим количеством стратегий (--count)",
            "Попробуйте полностью изменить подход (например, если использовали split, попробуйте race)",
        ],
        "strategic_focus": ["technique_diversification", "advanced_evasion"],
    },
    "TIMEOUT": {
        "причины": [
            "Пакеты были отброшены по пути (возможно, из-за низкого TTL)",
            'DPI "тихо" отбрасывает пакеты (packet drop) вместо отправки RST',
            "Сильная загрузка сети или медленный ответ сервера",
        ],
        "решения": [
            "Увеличьте таймауты в config.py (SOCKET_TIMEOUT)",
            "Используйте стратегии, не основанные на TTL (например, tlsrec)",
            "Проверьте базовое соединение с сайтом через ping или traceroute",
        ],
        "strategic_focus": ["timeout_resilient_attacks", "alternative_protocols"],
    },
    "CONNECTION_REFUSED": {
        "причины": [
            "Сервер активно отклоняет соединения",
            "Порт заблокирован на уровне сервера",
            "Неправильная конфигурация атаки",
        ],
        "решения": [
            "Проверьте доступность порта через telnet",
            "Попробуйте альтернативные порты (80, 8080, 8443)",
            "Используйте техники туннелирования",
        ],
        "strategic_focus": ["port_hopping", "tunneling_attacks"],
    },
    "TLS_HANDSHAKE_FAILURE": {
        "причины": [
            "DPI блокирует TLS handshake на уровне протокола",
            "Несовместимость версий TLS",
            "Блокировка по SNI или сертификату",
        ],
        "решения": [
            "Используйте TLS fragmentation атаки",
            "Попробуйте ECH (Encrypted Client Hello)",
            "Применяйте domain fronting техники",
        ],
        "strategic_focus": [
            "tls_evasion",
            "sni_obfuscation",
            "protocol_manipulation",
        ],
    },
}

# Mapping of attack techniques to failure patterns they're most effective against
TECHNIQUE_EFFECTIVENESS = {
    "tcp_fragmentation": ["RST_RECEIVED", "TLS_HANDSHAKE_FAILURE"],
    "tcp_multisplit": ["RST_RECEIVED", "TIMEOUT"],
    "tcp_fakeddisorder": ["RST_RECEIVED", "TLS_HANDSHAKE_FAILURE"],
    "tls_record_manipulation": ["TLS_HANDSHAKE_FAILURE", "RST_RECEIVED"],
    "quic_fragmentation": ["TIMEOUT", "CONNECTION_REFUSED"],
    "http2_frame_splitting": ["TLS_HANDSHAKE_FAILURE", "TIMEOUT"],
    "ech_fragmentation": ["TLS_HANDSHAKE_FAILURE", "RST_RECEIVED"],
    "traffic_mimicry": ["NO_SITES_WORKING", "RST_RECEIVED"],
    "dns_tunneling": ["TIMEOUT_ON_SYN", "CONNECTION_REFUSED"],
    "icmp_tunneling": ["TIMEOUT_ON_SYN", "CONNECTION_REFUSED"],
}
