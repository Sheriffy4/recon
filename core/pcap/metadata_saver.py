"""
PCAP Metadata Saver

Saves metadata about executed attacks alongside PCAP files for simple validation.

Task: Testing-Production Parity - Single Source of Truth
Instead of complex PCAP analysis logic, we save the executed attack string from the log
and use simple string comparison for validation.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

LOG = logging.getLogger(__name__)


def save_pcap_metadata(
    pcap_file: Optional[str] = None,
    executed_attacks: Optional[str] = None,
    strategy_name: Optional[str] = None,
    strategy_id: Optional[str] = None,
    domain: Optional[str] = None,
    additional_data: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Save metadata about executed attacks.

    Can work in two modes:
    1. With pcap_file: Creates JSON file alongside PCAP
       capture_domain_123.pcap → capture_domain_123.json

    2. With strategy_id + domain: Creates JSON in temp dir for later lookup
       strategy_<id>.json in temp/recon_pcap/

    Args:
        pcap_file: Path to PCAP file (optional)
        executed_attacks: Final attack string from log (e.g., "split,fake")
        strategy_name: Strategy name (e.g., "smart_combo_split_fake")
        strategy_id: Strategy test ID (optional, for lookup)
        domain: Domain name (optional, for lookup)
        additional_data: Additional metadata to save

    Returns:
        True if saved successfully, False otherwise
    """
    try:
        metadata = {
            "executed_attacks": executed_attacks,
            "strategy_name": strategy_name,
            "strategy_id": strategy_id,
            "domain": domain,
        }

        if additional_data:
            metadata.update(additional_data)

        # Mode 1: Save alongside PCAP file with unique name per strategy
        if pcap_file:
            pcap_path = Path(pcap_file)

            # Create unique metadata filename based on strategy_name to avoid overwriting
            if strategy_name:
                # Use strategy name in metadata filename to prevent overwriting
                safe_strategy = strategy_name.replace(".", "_").replace(",", "_").replace(":", "_")
                metadata_file = pcap_path.parent / f"{pcap_path.stem}_{safe_strategy}.json"
            else:
                # Fallback to simple .json extension (may overwrite)
                metadata_file = pcap_path.with_suffix(".json")

            metadata["pcap_file"] = str(pcap_path.name)

        # Mode 2: Save by strategy_id for later lookup
        elif strategy_id:
            import tempfile

            temp_dir = Path(tempfile.gettempdir()) / "recon_pcap"
            temp_dir.mkdir(exist_ok=True)
            metadata_file = temp_dir / f"strategy_{strategy_id}.json"

        else:
            LOG.warning("⚠️ Neither pcap_file nor strategy_id provided, cannot save metadata")
            return False

        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

        LOG.debug(f"✅ Saved PCAP metadata to {metadata_file}")
        return True

    except Exception as e:
        LOG.warning(f"⚠️ Failed to save PCAP metadata: {e}")
        return False


def load_pcap_metadata(
    pcap_file: str, strategy_name: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Load metadata for a PCAP file.

    Tries multiple strategies:
    1. Look for strategy-specific JSON file (capture_domain_123_strategy_name.json)
    2. Look for generic JSON file alongside PCAP (capture_domain_123.json)
    3. Look for ANY metadata files for this PCAP and return the most recent
    4. Look for strategy_*.json files in temp dir and match by domain

    Args:
        pcap_file: Path to PCAP file
        strategy_name: Strategy name (optional, for finding strategy-specific metadata)

    Returns:
        Metadata dict if found, None otherwise
    """
    try:
        pcap_path = Path(pcap_file)

        # Strategy 1: Look for strategy-specific JSON file
        if strategy_name:
            safe_strategy = strategy_name.replace(".", "_").replace(",", "_").replace(":", "_")
            metadata_file = pcap_path.parent / f"{pcap_path.stem}_{safe_strategy}.json"
            if metadata_file.exists():
                with open(metadata_file, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                LOG.debug(f"✅ Loaded PCAP metadata from {metadata_file} (strategy-specific)")
                return metadata

        # Strategy 2: Look for generic JSON alongside PCAP
        metadata_file = pcap_path.with_suffix(".json")
        if metadata_file.exists():
            with open(metadata_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            LOG.debug(f"✅ Loaded PCAP metadata from {metadata_file}")
            return metadata

        # Strategy 3: Look for ANY metadata files for this PCAP (pattern: capture_domain_123_*.json)
        # Return the most recent one
        pattern = f"{pcap_path.stem}_*.json"
        metadata_files = list(pcap_path.parent.glob(pattern))
        if metadata_files:
            # Sort by modification time, newest first
            metadata_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            metadata_file = metadata_files[0]

            with open(metadata_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            LOG.debug(f"✅ Loaded PCAP metadata from {metadata_file} (most recent)")
            return metadata

        # Strategy 2: Look for strategy_*.json files in temp dir
        # Extract domain from PCAP filename (e.g., capture_pagead2_googlesyndication_com_123.pcap)
        import re
        import tempfile

        filename = pcap_path.stem  # capture_pagead2_googlesyndication_com_123
        # Extract domain (everything between capture_ and last _timestamp)
        match = re.match(r"capture_(.+)_\d+$", filename)
        if match:
            domain_part = match.group(1)  # pagead2_googlesyndication_com
            domain = domain_part.replace("_", ".")  # pagead2.googlesyndication.com

            # Look for strategy files with matching domain
            temp_dir = Path(tempfile.gettempdir()) / "recon_pcap"
            if temp_dir.exists():
                for strategy_file in temp_dir.glob("strategy_*.json"):
                    try:
                        with open(strategy_file, "r", encoding="utf-8") as f:
                            metadata = json.load(f)

                        # Check if domain matches
                        if metadata.get("domain") == domain:
                            LOG.debug(
                                f"✅ Loaded PCAP metadata from {strategy_file} (matched by domain)"
                            )
                            return metadata
                    except Exception:
                        continue

        LOG.debug(f"No metadata file found for {pcap_file}")
        return None

    except Exception as e:
        LOG.warning(f"⚠️ Failed to load PCAP metadata: {e}")
        return None
