"""
Remote synchronization for DPI signature database.

Handles fetching signatures from remote sources, validation, and merging.
"""

import json
import logging
import requests
from typing import Dict, Any, Tuple, Optional

try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

LOG = logging.getLogger("SignatureSync")


def fetch_remote_signatures(url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Fetch signatures from remote URL.

    Args:
        url: Remote database URL
        timeout: Request timeout in seconds

    Returns:
        Dictionary of remote signatures, or None if fetch failed
    """
    try:
        response = requests.get(url, timeout=timeout, verify=True)
        response.raise_for_status()
        remote_data = response.json().get("signatures", {})
        return remote_data
    except requests.RequestException as e:
        LOG.warning(f"⚠️ Не удалось получить данные с {url}: {e}")
        return None
    except json.JSONDecodeError:
        LOG.error(
            "⚠️ Не удалось разобрать ответ от удаленного сервера. " "Возможно, файл поврежден."
        )
        return None


def validate_signature_entry(entry: Dict[str, Any], schema: Dict[str, Any]) -> bool:
    """
    Validate a signature entry against schema.

    Args:
        entry: Signature entry to validate
        schema: JSON schema for validation

    Returns:
        True if valid, False otherwise
    """
    if not JSONSCHEMA_AVAILABLE:
        return True  # Skip validation if jsonschema not available

    try:
        jsonschema.validate(instance=entry, schema=schema)
        return True
    except jsonschema.ValidationError as e:
        LOG.warning(f"Невалидная сигнатура: {e.message}")
        return False


def merge_signatures(
    local: Dict[str, Any], remote: Dict[str, Any], schema: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Merge remote signatures into local database.

    Args:
        local: Local signature database
        remote: Remote signatures to merge
        schema: Optional JSON schema for validation

    Returns:
        Tuple of (merged_signatures, new_count)
    """
    merged = local.copy()
    new_count = 0

    for key, entry in remote.items():
        if key not in merged:
            # Validate if schema provided
            if schema and not validate_signature_entry(entry, schema):
                LOG.warning(f"Пропущена невалидная сигнатура {key} из удаленной базы")
                continue

            merged[key] = entry
            new_count += 1

    return merged, new_count


def sync_from_remote_source(
    local_signatures: Dict[str, Any],
    remote_url: str,
    schema: Optional[Dict[str, Any]] = None,
    timeout: int = 10,
) -> Tuple[Dict[str, Any], int]:
    """
    Complete sync operation: fetch, validate, and merge.

    Args:
        local_signatures: Current local signature database
        remote_url: URL of remote signature database
        schema: Optional JSON schema for validation
        timeout: Request timeout in seconds

    Returns:
        Tuple of (updated_signatures, new_count)
    """
    LOG.info(f"Синхронизация с удаленной базой: {remote_url}")

    remote_data = fetch_remote_signatures(remote_url, timeout)
    if remote_data is None:
        return local_signatures, 0

    merged, new_count = merge_signatures(local_signatures, remote_data, schema)

    if new_count > 0:
        LOG.info(f"✅ База синхронизирована: добавлено {new_count} новых сигнатур.")
    else:
        LOG.info("Локальная база данных сигнатур уже актуальна.")

    return merged, new_count
