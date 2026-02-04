"""
Update operations for signature database.

Handles signature creation, modification, and history management.
"""

import logging
import time
from typing import Dict, Any, List, TYPE_CHECKING

if TYPE_CHECKING:
    from recon.core.fingerprint import Fingerprint

LOG = logging.getLogger("SignatureUpdates")


def build_strategy_info(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build strategy info dictionary from test result.

    Args:
        result: Strategy test result

    Returns:
        Formatted strategy info
    """
    return {
        "strategy": result.get("strategy"),
        "success_rate": result.get("success_rate"),
        "avg_latency_ms": result.get("avg_latency_ms"),
        "successful_sites": result.get("successful_sites", 0),
        "total_sites": result.get("total_sites", 0),
    }


def manage_history(existing_entry: Dict[str, Any], max_history: int = 5) -> List[Dict[str, Any]]:
    """
    Extract and manage strategy history.

    Args:
        existing_entry: Existing signature entry
        max_history: Maximum history entries to keep

    Returns:
        Updated history list
    """
    history = existing_entry.get("strategy_history", [])

    # Add current strategy to history if it exists
    if "working_strategy" in existing_entry:
        old_entry = existing_entry["working_strategy"].copy()
        old_entry["timestamp"] = existing_entry.get("metadata", {}).get("last_seen")
        history.append(old_entry)

    # Keep only last N entries
    return history[-max_history:]


def create_signature_entry(
    fp: "Fingerprint", strategy_result: Dict[str, Any], existing_entry: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create complete signature entry with metadata.

    Args:
        fp: Fingerprint object
        strategy_result: Strategy test result
        existing_entry: Existing entry (if any) for history preservation

    Returns:
        Complete signature entry
    """
    strategy_info = build_strategy_info(strategy_result)
    history = manage_history(existing_entry)

    entry = {
        "fingerprint_details": fp.to_dict(),
        "working_strategy": strategy_info,
        "strategy_history": history,
        "metadata": {
            "first_seen": existing_entry.get("metadata", {}).get("first_seen", time.time()),
            "last_seen": time.time(),
            "update_count": existing_entry.get("metadata", {}).get("update_count", 0) + 1,
        },
    }

    return entry


def update_strategy_in_place(entry: Dict[str, Any], strategy: str, success_rate: float) -> None:
    """
    Update strategy in existing entry (modifies in place).

    Args:
        entry: Signature entry to update
        strategy: New strategy string
        success_rate: New success rate
    """
    # Preserve history
    history = entry.get("strategy_history", [])
    if "working_strategy" in entry:
        old_entry = entry["working_strategy"].copy()
        old_entry["timestamp"] = entry.get("metadata", {}).get("last_seen")
        history.append(old_entry)

    # Update strategy
    entry["working_strategy"]["strategy"] = strategy
    entry["working_strategy"]["success_rate"] = success_rate
    entry["strategy_history"] = history[-5:]

    # Update metadata
    entry["metadata"]["last_seen"] = time.time()
    entry["metadata"]["update_count"] = entry["metadata"].get("update_count", 0) + 1
