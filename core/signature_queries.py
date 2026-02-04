"""
Query operations for signature database.

Provides lookup and matching functionality for DPI signatures.
"""

import logging
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from recon.core.fingerprint import Fingerprint

LOG = logging.getLogger("SignatureQueries")


def find_exact_match(signatures: Dict[str, Any], fp_hash: str) -> Optional[Dict[str, Any]]:
    """
    Find exact signature match by fingerprint hash.

    Args:
        signatures: Signature database
        fp_hash: Fingerprint hash to search for

    Returns:
        Matching signature entry or None
    """
    if fp_hash in signatures:
        LOG.info(f"🔍 Найдена точная сигнатура DPI в базе (hash: {fp_hash}).")
        return signatures[fp_hash]
    return None


def find_by_dpi_type(signatures: Dict[str, Any], dpi_type: str) -> Optional[Dict[str, Any]]:
    """
    Find signature by DPI type (fuzzy match).

    Args:
        signatures: Signature database
        dpi_type: DPI type to search for

    Returns:
        First matching signature entry or None
    """
    for sig_hash, entry in signatures.items():
        entry_dpi_type = entry.get("fingerprint_details", {}).get("dpi_type")
        if entry_dpi_type == dpi_type:
            LOG.info(f"🔍 Найдена похожая сигнатура (по типу DPI: {dpi_type})")
            return entry
    return None


def find_matching_signature(
    signatures: Dict[str, Any], fp: "Fingerprint"
) -> Optional[Dict[str, Any]]:
    """
    Find best matching signature for a fingerprint.

    Tries exact match first, then falls back to DPI type matching.

    Args:
        signatures: Signature database
        fp: Fingerprint object to match

    Returns:
        Best matching signature entry or None
    """
    # Try exact match first
    fp_hash = fp.short_hash()
    exact = find_exact_match(signatures, fp_hash)
    if exact:
        return exact

    # Fall back to DPI type matching
    if fp.dpi_type:
        return find_by_dpi_type(signatures, fp.dpi_type)

    return None
