"""
Attack helper functions.

Utilities for fake packet generation and parameter extraction.
"""

import logging
import os
from typing import Any, Dict, Iterable, Tuple

from .attack_constants import AttackConstants

logger = logging.getLogger(__name__)


def get_fake_params(params: Dict[str, Any]) -> Tuple[int, str]:
    """
    Safely extract TTL and fooling method.

    Raises:
        ValueError: if TTL not found
    """
    def _first_str(value: Any) -> str | None:
        """
        Accept both str and list/tuple of str (RecipeResolver may provide list),
        returning the first non-empty string.
        """
        if value is None:
            return None
        if isinstance(value, str):
            v = value.strip()
            return v or None
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str) and item.strip():
                    return item.strip()
        return None

    # Get TTL - required
    ttl = params.get("ttl") or params.get("fake_ttl")
    if ttl is None:
        raise ValueError(
            "TTL is required for fake packets. " "Please specify 'ttl' or 'fake_ttl' parameter."
        )

    # Coerce TTL to int safely (configs/CLI may supply strings)
    try:
        ttl_int = int(ttl)
    except Exception as e:
        raise ValueError(f"Invalid TTL value: {ttl!r}") from e

    # Validate TTL (only minimum, no maximum restriction)
    ttl_int = max(ttl_int, AttackConstants.MIN_FAKE_TTL)

    # Get fooling method with safe fallback
    fooling = _first_str(params.get("fooling"))
    if not fooling:
        fooling_methods = params.get("fooling_methods", [])
        # allow both list[str] and single str
        fooling = _first_str(fooling_methods)
        if not fooling:
            fooling = AttackConstants.DEFAULT_FOOLING

    # Validate fooling method
    if fooling not in AttackConstants.VALID_FOOLING:
        logger.warning(f"Unknown fooling method '{fooling}', using default")
        fooling = AttackConstants.DEFAULT_FOOLING

    return ttl_int, fooling


def generate_fake_payload(real_payload: bytes, fooling: str) -> bytes:
    """
    Generate fake payload efficiently.

    Для TLS: сохраняем заголовок, рандомизируем содержимое.
    Для HTTP: создаём правдоподобный запрос.
    Для остального: используем шаблоны по fooling методу.
    """
    length = len(real_payload)

    # TLS - сохраняем заголовок для правдоподобности
    if length >= 5 and real_payload.startswith(b"\x16\x03"):
        header = real_payload[:5]
        # Всегда новый random для каждого пакета (безопасность)
        return header + os.urandom(length - 5)

    # HTTP - правдоподобный запрос
    if real_payload.startswith((b"GET ", b"POST ", b"HEAD ")):
        fake = b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n"
        if len(fake) >= length:
            return fake[:length]
        # FIX: Use spaces instead of null bytes for padding (Expert 2 fix #3)
        padding_needed = length - len(fake)
        return fake + (b" " * padding_needed)

    # По fooling методу (без кэширования для простоты)
    if fooling == AttackConstants.FOOLING_BADSUM:
        return bytes([0xFF] * length)
    elif fooling == AttackConstants.FOOLING_MD5SIG:
        return bytes([0xAA] * length)
    else:  # badseq или неизвестный
        return bytes(length)
