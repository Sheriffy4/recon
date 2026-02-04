"""
Утилиты для работы с DNS пакетами

Общие функции для парсинга и анализа DNS ответов.
"""

import logging
from typing import Any, Dict, List

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import DNS

    SCAPY_AVAILABLE = True
except ImportError:
    DNS = None

LOG = logging.getLogger("DNSUtils")


def _safe_decode_dns_name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def extract_dns_answers(response) -> List[Dict[str, Any]]:
    """
    Извлечение DNS ответов из пакета

    Args:
        response: DNS response пакет (scapy)

    Returns:
        Список словарей с информацией об ответах
    """
    answers = []

    if not SCAPY_AVAILABLE or DNS is None:
        return answers

    try:
        if response[DNS].ancount > 0:
            for i in range(response[DNS].ancount):
                try:
                    answer = response[DNS].an[i]
                    rrname = _safe_decode_dns_name(getattr(answer, "rrname", b"")).rstrip(".")
                    answers.append(
                        {
                            "name": rrname,
                            "type": getattr(answer, "type", None),
                            "rdata": str(getattr(answer, "rdata", "")),
                            "ttl": getattr(answer, "ttl", None),
                        }
                    )
                except Exception as e:
                    LOG.debug(f"Ошибка парсинга DNS ответа {i}: {e}")
    except Exception as e:
        LOG.debug(f"Ошибка извлечения DNS ответов: {e}")

    return answers
