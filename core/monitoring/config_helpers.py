"""Configuration helpers for monitoring system."""

import json
import logging
from pathlib import Path
from dataclasses import asdict

logger = logging.getLogger(__name__)


def load_monitoring_config(
    config_class,
    config_file: str = "monitoring_config.json",
):
    """Загружает конфигурацию мониторинга из файла.

    Args:
        config_class: MonitoringConfig class
        config_file: Path to configuration file

    Returns:
        MonitoringConfig instance
    """
    config_path = Path(config_file)
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return config_class(**data)
        except Exception as e:
            logger.warning(f"Failed to load config from {config_file}: {e}")
    return config_class()


def save_monitoring_config(config, config_file: str = "monitoring_config.json"):
    """Сохраняет конфигурацию мониторинга в файл.

    Args:
        config: MonitoringConfig instance
        config_file: Path to configuration file
    """
    try:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(asdict(config), f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to save config to {config_file}: {e}")
