"""
Утилита для работы с feature flags
"""

import json
from pathlib import Path
from typing import Optional


def is_feature_enabled(feature_name: str, config_path: str = "config/feature_flags.json") -> bool:
    """
    Проверяет, включена ли функция в feature flags

    Args:
        feature_name: Название функции
        config_path: Путь к файлу конфигурации

    Returns:
        True если функция включена, False иначе
    """
    try:
        config_file = Path(config_path)
        if not config_file.exists():
            return False

        with open(config_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Проверяем в массиве features
        features = data.get("features", [])
        for feature in features:
            if feature.get("name") == feature_name:
                return feature.get("enabled", False)

        # Проверяем на верхнем уровне (legacy формат)
        return data.get(feature_name, False)

    except Exception:
        return False


def get_feature_config(
    feature_name: str, config_path: str = "config/feature_flags.json"
) -> Optional[dict]:
    """
    Получает полную конфигурацию функции

    Args:
        feature_name: Название функции
        config_path: Путь к файлу конфигурации

    Returns:
        Словарь с конфигурацией или None
    """
    try:
        config_file = Path(config_path)
        if not config_file.exists():
            return None

        with open(config_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        features = data.get("features", [])
        for feature in features:
            if feature.get("name") == feature_name:
                return feature

        return None

    except Exception:
        return None
