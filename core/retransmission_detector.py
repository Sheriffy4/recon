#!/usr/bin/env python3
"""
Retransmission Detection for Strategy Validation

High retransmission count indicates strategy is not working
"""

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger("RetransmissionDetector")


class RetransmissionDetector:
    """Detects high retransmission counts that indicate strategy failure"""

    def __init__(self, threshold: int = 3):
        self.threshold = threshold
        self.retrans_counts: Dict[str, int] = {}

    def analyze_log_for_retransmissions(self, log_content: str) -> Dict[str, int]:
        """
        Analyze log content for retransmission indicators

        Returns:
            Dict mapping flow/connection to retransmission count
        """
        retrans_patterns = [
            r"retransmission count \((\d+)\)",
            r"High retransmission.*?(\d+)",
            r"TCP Retransmission.*?(\d+)",
            r"Retrans.*?(\d+)",
        ]

        results = {}

        for line in log_content.split("\n"):
            for pattern in retrans_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    count = int(match.group(1))
                    if count > self.threshold:
                        # Extract connection identifier
                        conn_id = self._extract_connection_id(line)
                        results[conn_id] = count
                        logger.warning(f"High retransmissions detected: {conn_id} = {count}")

        return results

    def _extract_connection_id(self, line: str) -> str:
        """Extract connection identifier from log line"""
        # Look for domain names or IP addresses
        domain_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
        if domain_match:
            return domain_match.group(1)

        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if ip_match:
            return ip_match.group(1)

        return "unknown"

    def is_strategy_failing(self, log_content: str, domain: str) -> bool:
        """
        Check if strategy is failing based on retransmissions

        Args:
            log_content: Log content to analyze
            domain: Domain being tested

        Returns:
            True if strategy appears to be failing
        """
        retrans = self.analyze_log_for_retransmissions(log_content)

        for conn_id, count in retrans.items():
            if domain in conn_id and count > self.threshold:
                logger.error(f"❌ Strategy failing for {domain}: {count} retransmissions")
                return True

        return False


# Integration function for existing code
def check_retransmissions_in_strategy_test(log_content: str, domain: str) -> bool:
    """
    Check if retransmissions indicate strategy failure

    Returns:
        True if strategy is working (low retransmissions)
        False if strategy is failing (high retransmissions)
    """
    detector = RetransmissionDetector(threshold=3)
    is_failing = detector.is_strategy_failing(log_content, domain)
    return not is_failing  # Return True for success, False for failure
