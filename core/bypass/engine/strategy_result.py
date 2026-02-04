#!/usr/bin/env python3
"""
Strategy Result Data Model

This module defines the StrategyResult dataclass used by the DomainStrategyEngine
to return strategy information along with domain metadata for enhanced logging.

Requirements addressed: 3.1, 3.2, 3.3, 4.4
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ConflictInfo:
    """
    Records information about domain conflicts for debugging.

    When SNI-extracted domain differs from IP-resolved domain,
    this dataclass captures the conflict details for analysis.

    Requirements:
    - 4.4: Record domain conflicts in conflict_history for debugging

    Attributes:
        timestamp: When the conflict was detected
        sni_domain: Domain extracted from TLS SNI extension
        ip_domain: Domain resolved from IP address (reverse DNS or cache)
        ip_address: The IP address involved in the conflict
        strategy_used: Name of the strategy that was applied (SNI-based)
    """

    timestamp: datetime
    sni_domain: str
    ip_domain: str
    ip_address: str
    strategy_used: str

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert ConflictInfo to dictionary for serialization.

        Returns:
            Dictionary representation with ISO format timestamp
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "sni_domain": self.sni_domain,
            "ip_domain": self.ip_domain,
            "ip_address": self.ip_address,
            "strategy_used": self.strategy_used,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConflictInfo":
        """
        Create ConflictInfo from dictionary.

        Args:
            data: Dictionary with conflict info data

        Returns:
            ConflictInfo instance
        """
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            sni_domain=data["sni_domain"],
            ip_domain=data["ip_domain"],
            ip_address=data["ip_address"],
            strategy_used=data["strategy_used"],
        )

    def __str__(self) -> str:
        """String representation for logging."""
        return (
            f"ConflictInfo(timestamp={self.timestamp.isoformat()}, "
            f"sni_domain={self.sni_domain}, ip_domain={self.ip_domain}, "
            f"ip_address={self.ip_address}, strategy_used={self.strategy_used})"
        )


@dataclass
class StrategyResult:
    """
    Result of strategy lookup including domain information for logging.

    This allows the bypass engine to log detailed information about
    which domain was matched and how it was discovered.

    Requirements:
    - 3.1: Log when IP not found in cache and domain discovered via reverse DNS
    - 3.2: Log which strategy is selected and why (exact/wildcard/default)
    - 3.3: Log strategy mismatch warnings with expected vs actual
    - 1.5: Detect conflicts between SNI and IP-based domain lookups
    - 4.2: Log conflict warnings when SNI and IP domains differ
    """

    strategy: Dict[str, Any]  # Strategy configuration to apply
    domain: Optional[str]  # Domain name (None if unknown)
    source: str  # How domain was discovered: "sni", "reverse_dns", "cache", "unknown"
    ip_address: str  # Destination IP address
    matched_rule: Optional[str] = None  # Which domain rule was matched (for debugging)
    conflict_detected: bool = False  # Whether SNI and IP domain conflict was detected
    sni_domain: Optional[str] = None  # Domain from SNI (if available)
    ip_domain: Optional[str] = None  # Domain from IP lookup (reverse DNS or cache)

    def format_log_message(self) -> str:
        """
        Format a log message for strategy application.

        Returns:
            Formatted string suitable for logging

        Example outputs:
            "dst=172.217.130.232:443 (r1---sn-abc.googlevideo.com [SNI]), strategy=split"
            "dst=172.217.130.232:443 (mrs08s08-in-f8.1e100.net [DNS]), strategy=split"
            "dst=172.217.130.232:443 (googlevideo.com [CACHE]), strategy=split"
            "dst=172.217.130.232:443 (unknown [DEFAULT]), strategy=disorder"
        """
        # Get strategy name
        strategy_name = (
            self.strategy.get("type")
            or self.strategy.get("name")
            or "unknown"
        )

        # Format domain part
        if self.domain:
            domain_part = f"{self.domain} [{self.source.upper()}]"
        else:
            domain_part = f"unknown [{self.source.upper()}]"

        return f"dst={self.ip_address} ({domain_part}), strategy={strategy_name}"

    def format_detailed_log(self) -> str:
        """
        Format a detailed log message including strategy parameters and conflict information.

        Returns:
            Detailed formatted string with strategy parameters and conflict metadata

        Example:
            "dst=172.217.130.232:443 (r1---sn-abc.googlevideo.com [SNI]),
             strategy=split, params={'ttl': 1, 'fooling': 'badseq', 'split_pos': 3}"
            "dst=172.217.130.232:443 (youtube.com [SNI]), strategy=split,
             conflict_detected=True (SNI=youtube.com, IP=googlevideo.com)"
        """
        base_msg = self.format_log_message()

        # Strategy schema is usually: {"type": ..., "params": {...}, "attacks": [...]}
        # Log only params (not whole strategy dict).
        params_obj = self.strategy.get("params", {})
        params = dict(params_obj) if isinstance(params_obj, dict) else {}

        # Build the message with params
        if params:
            msg = f"{base_msg}, params={params}"
        else:
            msg = base_msg

        # Add conflict information to metadata if conflict detected (Requirement 4.2)
        if self.conflict_detected and self.sni_domain and self.ip_domain:
            msg += f", conflict_detected=True (SNI={self.sni_domain}, IP={self.ip_domain})"

        return msg

    def get_source_emoji(self) -> str:
        """
        Get an emoji representing the domain source.

        Returns:
            Emoji string for visual identification in logs
        """
        emoji_map = {
            "sni": "🔐",  # Lock for TLS SNI
            "reverse_dns": "🔍",  # Magnifying glass for DNS lookup
            "cache": "💾",  # Floppy disk for cache
            "unknown": "❓",  # Question mark for unknown
        }
        return emoji_map.get(self.source, "❓")

    def log_strategy_application(self, log_level: str = "info"):
        """
        Log the strategy application with appropriate formatting.

        Args:
            log_level: Logging level ("debug", "info", "warning", "error")
        """
        emoji = self.get_source_emoji()
        message = f"{emoji} APPLY_BYPASS: {self.format_detailed_log()}"

        log_func = getattr(logger, log_level, logger.info)
        log_func(message)

    def log_domain_discovery(self):
        """
        Log domain discovery information.

        This is called when a new domain is discovered for an IP address
        to help with debugging and monitoring.
        """
        if self.source == "reverse_dns":
            logger.info(f"🆕 NEW IP discovered: {self.ip_address} → {self.domain}")
            if self.matched_rule:
                logger.info(f"📋 Matched to rule: {self.matched_rule}")
        elif self.source == "cache":
            logger.debug(f"✅ Cache hit: {self.ip_address} → {self.domain}")

    def log_strategy_mismatch(self, expected_strategy: str):
        """
        Log a warning when strategy mismatch is detected.

        Args:
            expected_strategy: The strategy that was expected to be applied
        """
        actual_strategy = self.strategy.get("name", "unknown")
        if actual_strategy != expected_strategy:
            logger.warning(
                f"⚠️ Strategy mismatch for {self.ip_address}: "
                f"expected={expected_strategy}, actual={actual_strategy}, "
                f"domain={self.domain}, source={self.source}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert StrategyResult to dictionary for serialization.

        Returns:
            Dictionary representation of the result
        """
        return {
            "strategy": self.strategy,
            "domain": self.domain,
            "source": self.source,
            "ip_address": self.ip_address,
            "matched_rule": self.matched_rule,
            "conflict_detected": self.conflict_detected,
            "sni_domain": self.sni_domain,
            "ip_domain": self.ip_domain,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StrategyResult":
        """
        Create StrategyResult from dictionary.

        Args:
            data: Dictionary with strategy result data

        Returns:
            StrategyResult instance
        """
        return cls(
            strategy=data["strategy"],
            domain=data.get("domain"),
            source=data["source"],
            ip_address=data["ip_address"],
            matched_rule=data.get("matched_rule"),
            conflict_detected=data.get("conflict_detected", False),
            sni_domain=data.get("sni_domain"),
            ip_domain=data.get("ip_domain"),
        )

    def __str__(self) -> str:
        """String representation for debugging."""
        return self.format_log_message()

    def __repr__(self) -> str:
        """Detailed representation for debugging."""
        base = (
            f"StrategyResult(strategy={self.strategy.get('name', 'unknown')}, "
            f"domain={self.domain}, source={self.source}, "
            f"ip_address={self.ip_address}, matched_rule={self.matched_rule}"
        )
        if self.conflict_detected:
            base += f", conflict_detected=True, sni_domain={self.sni_domain}, ip_domain={self.ip_domain}"
        return base + ")"
