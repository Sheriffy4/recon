"""
Persistence layer for DPI signature database.

Handles JSON file operations, backup management, and data integrity.
"""

import json
import os
import shutil
import logging
from typing import Dict, Any

LOG = logging.getLogger("SignaturePersistence")


def load_signatures_from_file(db_path: str) -> Dict[str, Any]:
    """
    Load signatures from JSON file.

    Args:
        db_path: Path to the signature database file

    Returns:
        Dictionary of signatures, empty dict if file doesn't exist or is invalid
    """
    if not os.path.exists(db_path):
        LOG.info(f"Файл базы данных сигнатур '{db_path}' не найден. Будет создан новый.")
        return {}

    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            LOG.info(f"✅ Загружено {len(data)} сигнатур из '{db_path}'.")
            return data
    except (json.JSONDecodeError, IOError) as e:
        LOG.error(
            f"❌ Не удалось загрузить базу данных сигнатур: {e}. " "Будет использована пустая база."
        )
        return {}


def create_backup(db_path: str) -> bool:
    """
    Create a backup of the database file.

    Args:
        db_path: Path to the database file

    Returns:
        True if backup was created, False otherwise
    """
    if not os.path.exists(db_path):
        return False

    try:
        backup_path = f"{db_path}.bak"
        shutil.copy2(db_path, backup_path)
        LOG.debug(f"Создана резервная копия: {backup_path}")
        return True
    except (IOError, OSError) as e:
        LOG.warning(f"Не удалось создать резервную копию: {e}")
        return False


def save_signatures_to_file(db_path: str, signatures: Dict[str, Any]) -> bool:
    """
    Save signatures to JSON file with automatic backup.

    Args:
        db_path: Path to the signature database file
        signatures: Dictionary of signatures to save

    Returns:
        True if save was successful, False otherwise
    """
    try:
        # Create backup before overwriting
        create_backup(db_path)

        with open(db_path, "w", encoding="utf-8") as f:
            json.dump(signatures, f, indent=2, ensure_ascii=False)

        LOG.debug(f"База данных сигнатур сохранена в '{db_path}'.")
        return True
    except IOError as e:
        LOG.error(f"❌ Не удалось сохранить базу данных сигнатур: {e}")
        return False
