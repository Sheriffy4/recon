"""
Import/Export operations for signature database.

Handles data exchange with community and external sources.
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, Tuple, Optional

try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

LOG = logging.getLogger("SignatureIO")


def sanitize_entry_for_export(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize signature entry for export (remove sensitive data).

    Args:
        entry: Raw signature entry

    Returns:
        Cleaned entry suitable for sharing
    """
    return {
        "fingerprint_details": {
            "dpi_type": entry.get("fingerprint_details", {}).get("dpi_type"),
            "dpi_family": entry.get("fingerprint_details", {}).get("dpi_family"),
        },
        "working_strategy": {
            "strategy": entry.get("working_strategy", {}).get("strategy"),
            "success_rate": entry.get("working_strategy", {}).get("success_rate"),
        },
        "metadata": {"update_count": entry.get("metadata", {}).get("update_count", 0)},
    }


def export_signatures(signatures: Dict[str, Any], export_path: str) -> bool:
    """
    Export signatures to JSON file for sharing.

    Args:
        signatures: Signature database to export
        export_path: Output file path

    Returns:
        True if export successful, False otherwise
    """
    export_data = {
        "version": "2.0",
        "exported_at": datetime.now().isoformat(),
        "signatures_count": len(signatures),
        "signatures": {},
    }

    for fp_hash, entry in signatures.items():
        export_data["signatures"][fp_hash] = sanitize_entry_for_export(entry)

    try:
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        LOG.info(f"📤 База сигнатур экспортирована в '{export_path}' для обмена.")
        return True
    except IOError as e:
        LOG.error(f"Ошибка экспорта базы сигнатур: {e}")
        return False


def import_signatures(
    import_path: str, schema: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], int, int]:
    """
    Import signatures from JSON file.

    Args:
        import_path: Path to import file
        schema: Optional JSON schema for validation

    Returns:
        Tuple of (imported_signatures, imported_count, skipped_count)
    """
    if not JSONSCHEMA_AVAILABLE and schema:
        LOG.error("Библиотека 'jsonschema' не установлена. Импорт невозможен.")
        return {}, 0, 0

    if not os.path.exists(import_path):
        LOG.error(f"Файл для импорта не найден: '{import_path}'")
        return {}, 0, 0

    try:
        with open(import_path, "r", encoding="utf-8") as f:
            import_data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        LOG.error(f"Ошибка чтения файла импорта: {e}")
        return {}, 0, 0

    imported = {}
    imported_count = 0
    skipped_count = 0

    for fp_hash, entry in import_data.get("signatures", {}).items():
        # Validate if schema provided
        if schema and JSONSCHEMA_AVAILABLE:
            try:
                jsonschema.validate(instance=entry, schema=schema)
            except jsonschema.ValidationError as e:
                LOG.warning(
                    f"Пропущена невалидная сигнатура {fp_hash} " f"из '{import_path}': {e.message}"
                )
                skipped_count += 1
                continue

        # Add import metadata
        if "metadata" not in entry:
            entry["metadata"] = {}
        entry["metadata"]["imported_from"] = import_path

        imported[fp_hash] = entry
        imported_count += 1

    return imported, imported_count, skipped_count
