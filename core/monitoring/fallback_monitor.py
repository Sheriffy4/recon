"""
Fallback Auto-Recovery Monitor

Provides auto-recovery functionality when DomainStrategyEngine callback
is not available. Monitors connection patterns and triggers recovery
based on failure detection.

Requirements: Fallback auto-recovery when callback registration fails
"""

import logging
import time
import threading
from typing import Dict, Set, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import json

logger = logging.getLogger(__name__)


@dataclass
class FailurePattern:
    """Represents a detected failure pattern for a domain."""

    domain: str
    failure_count: int
    last_failure_time: float
    failure_window_start: float
    retransmission_total: int
    consecutive_failures: int


class FallbackAutoRecoveryMonitor:
    """
    Fallback auto-recovery monitor for when callback registration fails.

    Monitors:
    - Log files for connection failures
    - PCAP files for retransmission patterns
    - Domain-specific failure rates
    - Triggers recovery when thresholds are exceeded
    """

    def __init__(
        self,
        auto_recovery_manager,
        monitored_domains: Set[str],
        failure_threshold: int = 3,
        failure_window_seconds: float = 60.0,
        check_interval: float = 10.0,
    ):
        """
        Initialize fallback monitor.

        Args:
            auto_recovery_manager: AutoRecoveryManager instance
            monitored_domains: Set of domains to monitor
            failure_threshold: Number of failures to trigger recovery
            failure_window_seconds: Time window for failure counting
            check_interval: How often to check for failures
        """
        self.auto_recovery_manager = auto_recovery_manager
        self.monitored_domains = monitored_domains
        self.failure_threshold = failure_threshold
        self.failure_window_seconds = failure_window_seconds
        self.check_interval = check_interval

        # Failure tracking
        self.failure_patterns: Dict[str, FailurePattern] = {}
        self.last_check_time = time.time()

        # Control
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None

        logger.info(f"FallbackAutoRecoveryMonitor initialized")
        logger.info(f"  Monitored domains: {len(monitored_domains)}")
        logger.info(f"  Failure threshold: {failure_threshold}")
        logger.info(f"  Failure window: {failure_window_seconds}s")
        logger.info(f"  Check interval: {check_interval}s")

    def start(self):
        """Start the monitoring thread."""
        if self.running:
            logger.warning("Monitor already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="FallbackAutoRecoveryMonitor"
        )
        self.monitor_thread.start()
        logger.info("🔍 Fallback auto-recovery monitor started")

    def stop(self):
        """Stop the monitoring thread."""
        if not self.running:
            return

        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
            if self.monitor_thread.is_alive():
                logger.warning("Monitor thread did not stop gracefully")

        logger.info("🔍 Fallback auto-recovery monitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        logger.info("🔍 Fallback monitor loop started")

        while self.running:
            try:
                # Check for failures
                self._check_for_failures()

                # Clean up old failure patterns
                self._cleanup_old_patterns()

                # Sleep until next check
                time.sleep(self.check_interval)

            except Exception as e:
                logger.error(f"Error in fallback monitor loop: {e}")
                import traceback

                logger.debug(traceback.format_exc())
                time.sleep(self.check_interval * 2)  # Wait longer on error

        logger.info("🔍 Fallback monitor loop stopped")

    def _check_for_failures(self):
        """Check for connection failures that might indicate blocking."""
        current_time = time.time()

        # Method 1: Check recent log files for failure patterns
        self._check_log_files()

        # Method 2: Check PCAP files for retransmission patterns
        self._check_pcap_files()

        # Method 3: Check domain rules for recently failed domains
        self._check_domain_rules_failures()

        # Trigger recovery for domains that exceed threshold
        for domain, pattern in self.failure_patterns.items():
            if self._should_trigger_recovery(pattern, current_time):
                logger.info(f"🚨 Triggering fallback auto-recovery for {domain}")
                logger.info(f"   Failures: {pattern.failure_count}/{self.failure_threshold}")
                logger.info(f"   Retransmissions: {pattern.retransmission_total}")

                # Trigger recovery
                self._trigger_recovery(domain, pattern)

    def _check_log_files(self):
        """Check log files for connection failure patterns."""
        try:
            # Look for recent log files
            log_files = []

            # Check common log locations
            for log_path in ["recon_service.log", "log.txt", "simple_service.log"]:
                if Path(log_path).exists():
                    log_files.append(log_path)

            # Check logs directory
            logs_dir = Path("logs")
            if logs_dir.exists():
                for log_file in logs_dir.glob("*.log"):
                    log_files.append(str(log_file))

            # Parse recent entries from log files
            for log_file in log_files:
                self._parse_log_file(log_file)

        except Exception as e:
            logger.debug(f"Error checking log files: {e}")

    def _parse_log_file(self, log_file: str):
        """Parse log file for failure patterns."""
        try:
            current_time = time.time()
            cutoff_time = current_time - self.failure_window_seconds

            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                # Read last 1000 lines to avoid processing entire file
                lines = f.readlines()[-1000:]

            for line in lines:
                # Look for failure indicators
                if any(
                    indicator in line.lower()
                    for indicator in [
                        "retransmission",
                        "timeout",
                        "connection failed",
                        "rst packet",
                        "blocking detected",
                        "strategy failed",
                    ]
                ):
                    # Try to extract domain from line
                    domain = self._extract_domain_from_log_line(line)
                    if domain and domain in self.monitored_domains:
                        # Try to extract timestamp
                        log_time = self._extract_timestamp_from_log_line(line)
                        if log_time and log_time > cutoff_time:
                            self._record_failure(domain, log_time, line)

        except Exception as e:
            logger.debug(f"Error parsing log file {log_file}: {e}")

    def _extract_domain_from_log_line(self, line: str) -> Optional[str]:
        """Extract domain name from log line."""
        import re

        # Common domain patterns in logs
        patterns = [
            r"domain[:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"for\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
            r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*:",
            r"testing\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                domain = match.group(1).lower()
                # Validate domain format
                if "." in domain and len(domain) > 3:
                    return domain

        return None

    def _extract_timestamp_from_log_line(self, line: str) -> Optional[float]:
        """Extract timestamp from log line."""
        import re
        from datetime import datetime

        # Try different timestamp formats
        timestamp_patterns = [
            r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",  # 2024-01-01 12:00:00
            r"(\d{2}:\d{2}:\d{2})",  # 12:00:00
            r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})",  # 01/01/2024 12:00:00
        ]

        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)

                    # Parse different formats
                    if len(timestamp_str) == 8:  # HH:MM:SS
                        # Use today's date
                        today = datetime.now().date()
                        time_part = datetime.strptime(timestamp_str, "%H:%M:%S").time()
                        dt = datetime.combine(today, time_part)
                    elif "/" in timestamp_str:
                        dt = datetime.strptime(timestamp_str, "%m/%d/%Y %H:%M:%S")
                    else:
                        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                    return dt.timestamp()

                except ValueError:
                    continue

        # Fallback: use current time
        return time.time()

    def _check_pcap_files(self):
        """Check PCAP files for retransmission patterns."""
        try:
            # Look for recent PCAP files
            pcap_files = []

            for pcap_path in Path(".").glob("*.pcap"):
                # Check if file is recent (within last hour)
                if pcap_path.stat().st_mtime > time.time() - 3600:
                    pcap_files.append(str(pcap_path))

            # Quick analysis of PCAP files
            for pcap_file in pcap_files:
                self._analyze_pcap_file(pcap_file)

        except Exception as e:
            logger.debug(f"Error checking PCAP files: {e}")

    def _analyze_pcap_file(self, pcap_file: str):
        """Analyze PCAP file for failure patterns."""
        try:
            # Simple analysis - count retransmissions per domain
            # This is a basic implementation

            # TODO: Implement proper PCAP analysis
            # For now, just log that we're checking
            logger.debug(f"Checking PCAP file: {pcap_file}")

        except Exception as e:
            logger.debug(f"Error analyzing PCAP file {pcap_file}: {e}")

    def _check_domain_rules_failures(self):
        """Check domain rules for recently failed domains."""
        try:
            # Check if domain_rules.json has failure indicators
            rules_file = Path("domain_rules.json")
            if not rules_file.exists():
                return

            with open(rules_file, "r", encoding="utf-8") as f:
                rules_data = json.load(f)

            # Look for domains with failure metadata
            domain_rules = rules_data.get("domain_rules", {})

            for domain, rule in domain_rules.items():
                if domain in self.monitored_domains:
                    metadata = rule.get("metadata", {})

                    # Check for failure indicators in metadata
                    if metadata.get("last_failure_time"):
                        failure_time = metadata.get("last_failure_time", 0)
                        if failure_time > time.time() - self.failure_window_seconds:
                            self._record_failure(domain, failure_time, "domain_rules failure")

        except Exception as e:
            logger.debug(f"Error checking domain rules failures: {e}")

    def _record_failure(self, domain: str, failure_time: float, context: str):
        """Record a failure for a domain."""
        current_time = time.time()

        if domain not in self.failure_patterns:
            self.failure_patterns[domain] = FailurePattern(
                domain=domain,
                failure_count=0,
                last_failure_time=0,
                failure_window_start=current_time,
                retransmission_total=0,
                consecutive_failures=0,
            )

        pattern = self.failure_patterns[domain]

        # Update failure count
        pattern.failure_count += 1
        pattern.last_failure_time = failure_time

        # Extract retransmission count from context if available
        if "retransmission" in context.lower():
            import re

            match = re.search(r"(\d+)", context)
            if match:
                pattern.retransmission_total += int(match.group(1))

        # Update consecutive failures
        if failure_time > pattern.last_failure_time - 30:  # Within 30 seconds
            pattern.consecutive_failures += 1
        else:
            pattern.consecutive_failures = 1

        logger.debug(
            f"Recorded failure for {domain}: count={pattern.failure_count}, retrans={pattern.retransmission_total}"
        )

    def _should_trigger_recovery(self, pattern: FailurePattern, current_time: float) -> bool:
        """Check if recovery should be triggered for a failure pattern."""
        # Check if we're within the failure window
        if current_time - pattern.failure_window_start > self.failure_window_seconds:
            # Reset window
            pattern.failure_window_start = current_time
            pattern.failure_count = 0
            return False

        # Check if failure threshold is exceeded
        if pattern.failure_count >= self.failure_threshold:
            return True

        # Check for high retransmission count
        if pattern.retransmission_total >= 10:
            return True

        # Check for many consecutive failures
        if pattern.consecutive_failures >= 3:
            return True

        return False

    def _trigger_recovery(self, domain: str, pattern: FailurePattern):
        """Trigger auto-recovery for a domain."""
        try:
            # Create a basic strategy object for recovery
            from core.optimization.models import Strategy

            # Use a default strategy as current (since we don't know the actual one)
            current_strategy = Strategy(
                type="unknown", attacks=["split"], params={"split_pos": 2}  # Default fallback
            )

            # Trigger recovery
            import asyncio

            async def run_recovery():
                try:
                    success = await self.auto_recovery_manager.recover(
                        domain=domain,
                        current_strategy=current_strategy,
                    )

                    if success:
                        logger.info(f"✅ Fallback auto-recovery successful for {domain}")
                        # Reset failure pattern
                        if domain in self.failure_patterns:
                            del self.failure_patterns[domain]
                    else:
                        logger.warning(f"❌ Fallback auto-recovery failed for {domain}")

                except Exception as e:
                    logger.error(f"Error in fallback recovery for {domain}: {e}")

            # Run recovery in background
            def run_recovery_thread():
                try:
                    asyncio.run(run_recovery())
                except Exception as e:
                    logger.error(f"Error in recovery thread: {e}")

            recovery_thread = threading.Thread(
                target=run_recovery_thread, daemon=True, name=f"FallbackRecovery-{domain}"
            )
            recovery_thread.start()

        except Exception as e:
            logger.error(f"Error triggering fallback recovery for {domain}: {e}")

    def _cleanup_old_patterns(self):
        """Clean up old failure patterns outside the window."""
        current_time = time.time()
        cutoff_time = current_time - self.failure_window_seconds * 2  # Keep for 2x window

        domains_to_remove = []
        for domain, pattern in self.failure_patterns.items():
            if pattern.last_failure_time < cutoff_time:
                domains_to_remove.append(domain)

        for domain in domains_to_remove:
            del self.failure_patterns[domain]
            logger.debug(f"Cleaned up old failure pattern for {domain}")

    def get_failure_stats(self) -> Dict[str, any]:
        """Get failure statistics."""
        return {
            "monitored_domains": len(self.monitored_domains),
            "active_patterns": len(self.failure_patterns),
            "failure_threshold": self.failure_threshold,
            "failure_window_seconds": self.failure_window_seconds,
            "patterns": {
                domain: {
                    "failure_count": pattern.failure_count,
                    "retransmission_total": pattern.retransmission_total,
                    "consecutive_failures": pattern.consecutive_failures,
                    "last_failure_time": pattern.last_failure_time,
                }
                for domain, pattern in self.failure_patterns.items()
            },
        }
