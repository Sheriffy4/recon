"""
Error Classification and Pattern Analysis Module

Provides error categorization, pattern analysis, and severity determination
for diagnostic system error handling.
"""

import logging
from typing import Dict, List, Any

from core.diagnostic_system.types import PacketProcessingEvent


class ErrorClassifier:
    """Handles error categorization, pattern analysis, and severity determination."""

    def __init__(self, recommendation_engine, debug: bool = False):
        """
        Initialize ErrorClassifier.

        Args:
            recommendation_engine: RecommendationEngine instance for error fix suggestions
            debug: Enable debug logging
        """
        self.recommendation_engine = recommendation_engine
        self.debug = debug
        self.logger = logging.getLogger("ErrorClassifier")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def categorize_error(self, error_message: str) -> str:
        """
        Categorize error message into pattern type.

        Args:
            error_message: Error message to categorize

        Returns:
            Error category string
        """
        error_lower = error_message.lower()
        if "winerror 87" in error_lower or "invalid parameter" in error_lower:
            return "winerror_87"
        elif "validation" in error_lower or "invalid packet" in error_lower:
            return "packet_validation"
        elif "timeout" in error_lower:
            return "timeout"
        elif "checksum" in error_lower:
            return "checksum_error"
        elif "localhost" in error_lower or "127.0.0.1" in error_lower:
            return "localhost_handling"
        elif "reconstruction" in error_lower:
            return "packet_reconstruction"
        elif "technique" in error_lower:
            return "technique_failure"
        else:
            return "unknown_error"

    def analyze_error_pattern(
        self, error_type: str, events: List[PacketProcessingEvent]
    ) -> Dict[str, Any]:
        """
        Analyze a specific error pattern.

        Args:
            error_type: Type of error to analyze
            events: List of packet processing events with this error type

        Returns:
            Dictionary with error pattern analysis
        """
        return {
            "error_type": error_type,
            "frequency": len(events),
            "first_seen": min((e.timestamp for e in events)),
            "last_seen": max((e.timestamp for e in events)),
            "affected_domains": list(set((e.dst_addr for e in events))),
            "severity": self.determine_severity(error_type, len(events)),
            "suggested_fixes": self.recommendation_engine.get_error_fixes(error_type),
        }

    def determine_severity(self, error_type: str, frequency: int) -> str:
        """
        Determine severity level of error pattern.

        Args:
            error_type: Type of error
            frequency: Number of occurrences

        Returns:
            Severity level: 'critical', 'high', 'medium', or 'low'
        """
        if error_type == "winerror_87" and frequency > 10:
            return "critical"
        elif frequency > 50:
            return "high"
        elif frequency > 20:
            return "medium"
        else:
            return "low"
