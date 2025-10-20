# core/attacks/alias_map.py
import re

_ALIAS_MAP = {
    # fakeddisorder family
    "fakeddisorder": "fakeddisorder",
    "fakedisorder": "fakeddisorder",
    "fake_fakeddisorder": "fakeddisorder",
    "tcp_fakeddisorder": "fakeddisorder",
    "fake,disorder": "fakeddisorder",
    "fake+disorder": "fakeddisorder",
    "fakeddisorder_seqovl": "fakeddisorder",
    "seqovl_fakeddisorder": "fakeddisorder",
    # multisplit family
    "multisplit": "multisplit",
    "tcp_multisplit": "multisplit",
    # multidisorder family
    "multidisorder": "multidisorder",
    "tcp_multidisorder": "multidisorder",
    # seqovl family
    "seqovl": "seqovl",
    "tcp_seqovl": "seqovl",
    # fake
    "fake_packet": "fake",
    "fakeonly": "fake",
    "fake-desync": "fake",
    # generic DSL alias
    "desync": "fakeddisorder",
    # ✅ FIX: Add split and disorder aliases
    "split": "split",
    "disorder": "disorder",
    "tcp_split": "split",
    "tcp_disorder": "disorder",
}

def normalize_attack_name(name: str) -> str:
    if not name:
        return "unknown"
    norm = str(name).lower().strip().replace("-", "_").replace(" ", "")
    return _ALIAS_MAP.get(norm, norm)