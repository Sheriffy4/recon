"""
Blocking detection and monitoring for automatic strategy recovery.

This module provides the BlockingMonitor class that tracks domain health
and detects when domains become blocked by DPI systems.
"""

import time
from typing import Dict, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

# Import DomainHealth from models
import sys
from pathlib import Path

# Add parent directory to path for imports
_parent = Path(__file__).parent.parent
if str(_parent) not in sys.path:
    sys.path.insert(0, str(_parent))

from optimization.models import DomainHealth

if TYPE_CHECKING:
    from monitoring.auto_recovery import AutoRecoveryManager


class BlockingMonitor:
    """
    Monitors domain health and detects blocking.

    Tracks:
    - Consecutive connection failures
    - Retransmission counts
    - Connection timeouts

    Triggers recovery when blocking is detected.

    Thresholds:
    - FAILURE_THRESHOLD: 3 consecutive failures
    - RETRANSMISSION_THRESHOLD: 10 retransmissions per connection
    - TIMEOUT_THRESHOLD: 10.0 seconds
    """

    FAILURE_THRESHOLD = 3
    RETRANSMISSION_THRESHOLD = 10
    TIMEOUT_THRESHOLD = 10.0  # seconds

    def __init__(self, recovery_manager: Optional["AutoRecoveryManager"] = None):
        """
        Initialize BlockingMonitor.

        Args:
            recovery_manager: Optional AutoRecoveryManager for triggering recovery
        """
        self.recovery_manager = recovery_manager
        self.domain_health: Dict[str, DomainHealth] = {}

    def record_connection_result(
        self,
        domain: str,
        success: bool,
        retransmissions: int,
        duration: float,
    ) -> None:
        """
        Record connection result and check for blocking.

        Updates domain health tracking and checks if blocking thresholds
        are exceeded. If blocking is detected, triggers recovery.

        Args:
            domain: Domain name
            success: Whether connection succeeded
            retransmissions: Number of TCP retransmissions
            duration: Connection duration in seconds
        """
        # Get or create domain health record
        if domain not in self.domain_health:
            self.domain_health[domain] = DomainHealth(domain=domain)

        health = self.domain_health[domain]

        # Update health based on result
        if success:
            health.consecutive_failures = 0
            health.last_success_time = time.time()
            health.is_blocked = False
            health.block_reason = None
        else:
            health.consecutive_failures += 1

        # Track retransmissions (keep last 10)
        health.recent_retransmissions.append(retransmissions)
        if len(health.recent_retransmissions) > 10:
            health.recent_retransmissions.pop(0)

        # Check for blocking
        if self.check_blocking(domain, duration):
            # Determine reason
            reason = self._determine_block_reason(health, duration)
            health.is_blocked = True
            health.block_reason = reason

            # Trigger recovery if manager is available
            if self.recovery_manager is not None:
                # Note: This would be async in real implementation
                # For now, we just mark it
                pass

    def check_blocking(self, domain: str, last_duration: float = 0.0) -> bool:
        """
        Check if domain appears to be blocked.

        A domain is considered blocked if ANY of:
        - consecutive_failures > FAILURE_THRESHOLD (3)
        - last_duration > TIMEOUT_THRESHOLD (10 seconds)
        - any recent retransmissions > RETRANSMISSION_THRESHOLD (10)

        Args:
            domain: Domain to check
            last_duration: Duration of last connection attempt in seconds

        Returns:
            True if domain appears blocked, False otherwise
        """
        if domain not in self.domain_health:
            return False

        health = self.domain_health[domain]

        # Check consecutive failures
        if health.consecutive_failures > self.FAILURE_THRESHOLD:
            return True

        # Check timeout
        if last_duration > self.TIMEOUT_THRESHOLD:
            return True

        # Check retransmissions
        for retrans in health.recent_retransmissions:
            if retrans > self.RETRANSMISSION_THRESHOLD:
                return True

        return False

    def _determine_block_reason(self, health: DomainHealth, duration: float) -> str:
        """
        Determine the reason for blocking.

        Args:
            health: Domain health record
            duration: Last connection duration

        Returns:
            Human-readable reason string
        """
        reasons = []

        if health.consecutive_failures > self.FAILURE_THRESHOLD:
            reasons.append(f"{health.consecutive_failures} consecutive failures")

        if duration > self.TIMEOUT_THRESHOLD:
            reasons.append(f"timeout ({duration:.1f}s)")

        high_retrans = [
            r for r in health.recent_retransmissions if r > self.RETRANSMISSION_THRESHOLD
        ]
        if high_retrans:
            reasons.append(f"high retransmissions (max: {max(high_retrans)})")

        return "; ".join(reasons) if reasons else "unknown"

    def get_domain_health(self, domain: str) -> Optional[DomainHealth]:
        """
        Get health record for a domain.

        Args:
            domain: Domain name

        Returns:
            DomainHealth record or None if not tracked
        """
        return self.domain_health.get(domain)

    def reset_domain_health(self, domain: str) -> None:
        """
        Reset health tracking for a domain.

        Useful after successful recovery.

        Args:
            domain: Domain name
        """
        if domain in self.domain_health:
            self.domain_health[domain] = DomainHealth(domain=domain)

    def get_blocked_domains(self) -> list[str]:
        """
        Get list of currently blocked domains.

        Returns:
            List of domain names flagged as blocked
        """
        return [domain for domain, health in self.domain_health.items() if health.is_blocked]
