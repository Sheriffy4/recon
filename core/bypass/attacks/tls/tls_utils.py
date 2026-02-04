"""
TLS parsing/manipulation helpers (best-effort).

Goals:
 - reduce duplication across TLS evasion attacks
 - keep logic local and resilient (never raise, return original payload on failure)
 - avoid changing public interfaces of existing attacks

NOTE: This is not a full TLS parser. It only supports enough structure for
ClientHello extensions area and record/handshake length patching.

DEPRECATED:
  Prefer using:
    - core.bypass.attacks.tls.tls_helpers
    - core.bypass.attacks.tls.tls_parser
    - core.bypass.attacks.tls.tls_extension_utils
  This module remains as a compatibility shim to minimize breakage risk.
"""

from __future__ import annotations

import logging
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

LOG = logging.getLogger(__name__)

Extension = Tuple[int, bytes]

from core.bypass.attacks.tls.tls_extension_utils import (  # noqa: E402
    parse_extensions as _parse_extensions_raw,
    serialize_extensions as _serialize_extensions_raw,
)
from core.bypass.attacks.tls.tls_helpers import (  # noqa: E402
    is_tls_handshake_payload as _is_tls_handshake_payload,
    is_tls_record as _is_tls_record,
)
from core.bypass.attacks.tls.tls_parser import (  # noqa: E402
    find_extensions_offset_client_hello as _find_extensions_offset_client_hello,
    recalculate_tls_handshake_lengths as _recalculate_tls_handshake_lengths,
    normalize_tls_version_key as _normalize_tls_version_key,
)


def is_tls_handshake(payload: bytes) -> bool:
    """Best-effort check for a TLS Handshake record containing ClientHello."""
    return _is_tls_handshake_payload(payload)


def is_tls_record(payload: bytes) -> bool:
    """Best-effort check for a TLS record header."""
    return _is_tls_record(payload)


def find_client_hello_extensions_offset(payload: bytes) -> int:
    """
    Find the offset of the extensions length field within ClientHello.
    Returns -1 if cannot be determined.
    """
    return _find_extensions_offset_client_hello(payload)


def parse_extensions(payload: bytes, extensions_start: int) -> Optional[Tuple[int, List[Extension], int]]:
    """
    Parse extensions block at `extensions_start` (points to extensions_len field).
    Returns (original_extensions_len, extensions_list, extensions_end_offset) or None.
    """
    try:
        if extensions_start < 0 or extensions_start + 2 > len(payload):
            return None
        ext_total_len = struct.unpack("!H", payload[extensions_start : extensions_start + 2])[0]
        ext_data_start = extensions_start + 2
        ext_end = ext_data_start + ext_total_len
        if ext_end > len(payload):
            return None

        ext_data = payload[ext_data_start:ext_end]
        exts = _parse_extensions_raw(ext_data)

        return ext_total_len, exts, ext_end
    except Exception:
        return None


def build_extensions_data(extensions: Iterable[Extension]) -> bytes:
    """Build extensions bytes (without the 2-byte extensions_len prefix)."""
    # Delegate to canonical serializer for consistent behavior/perf.
    return _serialize_extensions_raw(list(extensions))


def replace_extensions(payload: bytes, extensions_start: int, old_ext_len: int, new_extensions: List[Extension]) -> bytes:
    """
    Replace extensions block (length + data) with new list.
    Returns original payload on failure.
    """
    try:
        new_data = build_extensions_data(new_extensions)
        new_payload = bytearray()
        new_payload += payload[:extensions_start]
        new_payload += struct.pack("!H", len(new_data))
        new_payload += new_data
        new_payload += payload[extensions_start + 2 + old_ext_len :]
        return bytes(new_payload)
    except Exception:
        return payload


def looks_like_tls_record_at(payload: bytes, offset: int) -> bool:
    """Heuristic: check whether payload[offset:] starts with a plausible TLS record header."""
    try:
        if offset < 0 or offset + 5 > len(payload):
            return False
        ct = payload[offset]
        if ct not in (20, 21, 22, 23):
            return False
        if payload[offset + 1] != 3:
            return False
        rec_len = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
        # rec_len may be 0, but header must fit in remaining data
        return offset + 5 + rec_len <= len(payload)
    except Exception:
        return False


def fix_single_record_client_hello_lengths(payload: bytes) -> bytes:
    """
    Patch TLS record length and handshake length for a *single-record* ClientHello.

    Safe behavior:
      - if payload appears to contain multiple records (old record end points to a plausible next record),
        do NOT expand first record to cover the rest.
      - if record_len is stale (common after extension insertion), patch lengths to match actual buffer size.
    """
    try:
        if len(payload) < 9 or not is_tls_handshake(payload):
            return payload

        old_record_len = struct.unpack("!H", payload[3:5])[0]
        old_record_end = 5 + old_record_len

        # If old_record_end points to a plausible next record header, treat as multi-record and don't patch.
        if old_record_end < len(payload) and looks_like_tls_record_at(payload, old_record_end):
            return payload

        # Otherwise patch as single-record ClientHello using canonical helper.
        return _recalculate_tls_handshake_lengths(payload)
    except Exception:
        return payload


def normalize_tls_version_name(v: str) -> str:
    """Normalize inputs like 'tls1.2'/'TLS1.2'/'tls12' -> 'tls12'."""
    try:
        return _normalize_tls_version_key(v)
    except Exception:
        s = (v or "").strip().lower()
        s = s.replace("tls1.", "tls").replace("tls1", "tls")
        s = s.replace(".", "")
        return s
