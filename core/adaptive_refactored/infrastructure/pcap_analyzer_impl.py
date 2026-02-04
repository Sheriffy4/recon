"""
Concrete implementation of IPCAPAnalyzer interface.

This module provides a concrete implementation that wraps existing PCAP analysis
functionality to satisfy the IPCAPAnalyzer interface.
"""

import logging
from typing import Dict, Any
from pathlib import Path

from ..interfaces import IPCAPAnalyzer

LOG = logging.getLogger(__name__)


class PCAPAnalyzerImpl(IPCAPAnalyzer):
    """
    Concrete implementation of IPCAPAnalyzer using UnifiedPCAPAnalyzer.

    This implementation wraps the existing UnifiedPCAPAnalyzer to provide
    PCAP analysis capabilities through the standard interface.
    """

    def __init__(self):
        """Initialize the PCAP analyzer implementation."""
        self._analyzer = None
        self._initialize_analyzer()

    def _initialize_analyzer(self):
        """Initialize the underlying PCAP analyzer."""
        try:
            from core.pcap.unified_analyzer import UnifiedPCAPAnalyzer

            self._analyzer = UnifiedPCAPAnalyzer()
            LOG.info("✅ UnifiedPCAPAnalyzer initialized successfully")
        except ImportError as e:
            LOG.warning(f"⚠️ Could not import UnifiedPCAPAnalyzer: {e}")
            self._analyzer = None
        except Exception as e:
            LOG.warning(f"⚠️ Error initializing UnifiedPCAPAnalyzer: {e}")
            self._analyzer = None

    async def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Analyze PCAP file and return results.

        Args:
            pcap_path: Path to the PCAP file to analyze

        Returns:
            Dictionary containing analysis results with keys:
            - success: bool indicating if analysis succeeded
            - packets_analyzed: number of packets analyzed
            - attacks_detected: list of detected attacks
            - dpi_indicators: DPI blocking indicators found
            - error: error message if analysis failed
        """
        if not self._analyzer:
            LOG.warning("⚠️ PCAP analyzer not available")
            return {
                "success": False,
                "error": "PCAP analyzer not initialized",
                "packets_analyzed": 0,
                "attacks_detected": [],
                "dpi_indicators": [],
            }

        try:
            # Validate file exists
            pcap_file = Path(pcap_path)
            if not pcap_file.exists():
                LOG.error(f"❌ PCAP file not found: {pcap_path}")
                return {
                    "success": False,
                    "error": f"PCAP file not found: {pcap_path}",
                    "packets_analyzed": 0,
                    "attacks_detected": [],
                    "dpi_indicators": [],
                }

            LOG.info(f"🔍 Analyzing PCAP file: {pcap_path}")

            # Perform analysis using the underlying analyzer
            result = self._analyzer.analyze_pcap(str(pcap_file))

            # Normalize result format
            if isinstance(result, dict):
                return {
                    "success": True,
                    "packets_analyzed": result.get("packets_analyzed", 0),
                    "attacks_detected": result.get("attacks_detected", []),
                    "dpi_indicators": result.get("dpi_indicators", []),
                    "flows": result.get("flows", []),
                    "metadata": result.get("metadata", {}),
                }
            else:
                LOG.warning(f"⚠️ Unexpected result format from analyzer: {type(result)}")
                return {
                    "success": True,
                    "packets_analyzed": 0,
                    "attacks_detected": [],
                    "dpi_indicators": [],
                    "raw_result": str(result),
                }

        except Exception as e:
            LOG.error(f"❌ Error analyzing PCAP file {pcap_path}: {e}")
            return {
                "success": False,
                "error": str(e),
                "packets_analyzed": 0,
                "attacks_detected": [],
                "dpi_indicators": [],
            }

    def validate_pcap(self, pcap_path: str) -> bool:
        """
        Validate PCAP file format and content.

        Args:
            pcap_path: Path to the PCAP file to validate

        Returns:
            True if PCAP file is valid, False otherwise
        """
        try:
            pcap_file = Path(pcap_path)

            # Check file exists
            if not pcap_file.exists():
                LOG.warning(f"⚠️ PCAP file does not exist: {pcap_path}")
                return False

            # Check file is not empty
            if pcap_file.stat().st_size == 0:
                LOG.warning(f"⚠️ PCAP file is empty: {pcap_path}")
                return False

            # Check file extension
            if pcap_file.suffix.lower() not in [".pcap", ".pcapng", ".cap"]:
                LOG.warning(f"⚠️ Invalid PCAP file extension: {pcap_file.suffix}")
                return False

            # Try to read the file header to validate format
            try:
                with open(pcap_file, "rb") as f:
                    header = f.read(24)

                    # Check for PCAP magic number (0xa1b2c3d4 or 0xd4c3b2a1)
                    if len(header) >= 4:
                        magic = int.from_bytes(header[:4], byteorder="little")
                        if magic in [0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1]:
                            LOG.debug(f"✅ Valid PCAP file: {pcap_path}")
                            return True

                    LOG.warning(f"⚠️ Invalid PCAP magic number in file: {pcap_path}")
                    return False

            except Exception as e:
                LOG.warning(f"⚠️ Error reading PCAP file header: {e}")
                return False

        except Exception as e:
            LOG.error(f"❌ Error validating PCAP file {pcap_path}: {e}")
            return False
