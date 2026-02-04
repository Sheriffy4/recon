from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List


def _normalize_value(key: str, value: Any) -> Any:
    # Нормализация значений для хеша параметров
    if isinstance(value, dict):
        return {
            str(k): _normalize_value(str(k), v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }

    if isinstance(value, (list, tuple)):
        items = [_normalize_value(key, v) for v in value]
        # В params может быть поле "attacks": ['split','multisplit'] и порядок не важен
        if key == "attacks":
            try:
                return sorted(items, key=lambda x: str(x))
            except Exception:
                return items
        return items

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    # Для других объектов/Enum и т.д.
    return str(value)


def normalize_params(params: Dict[str, Any]) -> Dict[str, Any]:
    params = params or {}
    return _normalize_value("", params)


def generate_strategy_key(attacks: List[str], params: Dict[str, Any]) -> str:
    """
    Unique key:
    - attacks сортируем (как и был в design doc)
    - params нормализуем с детерминированным порядком
    - sha256 хеширование не зависит от hash seed
    """
    attacks = [a for a in (attacks or []) if isinstance(a, str) and a]
    attacks_sorted = sorted(attacks)

    norm = normalize_params(params or {})
    payload = {
        "attacks": attacks_sorted,
        "params": norm,
    }
    dumped = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()
