"""
Auto Discovery Domain Integration

This module integrates the domain filtering infrastructure with the existing
auto discovery system, providing seamless domain-based filtering during
strategy discovery sessions.

Requirements: All requirements from auto-strategy-discovery spec
"""

import logging
import time
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

from core.domain_filter import DomainFilter, FilterMode
from core.domain_filter_config import DomainFilterConfigManager
from core.packet_filter_methods import PacketFilterIntegration

LOG = logging.getLogger(__name__)


class AutoDiscoveryDomainIntegration:
    """
    Integration layer between domain filtering and auto discovery system.

    Provides seamless integration of domain-based filtering with the existing
    auto discovery infrastructure, ensuring that discovery sessions only
    process traffic for the specified target domain.
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize auto discovery domain integration.

        Args:
            config_file: Optional path to domain filter config file
        """
        self.domain_filter = DomainFilter()
        self.config_manager = DomainFilterConfigManager(config_file)
        self.packet_integration = PacketFilterIntegration(self.domain_filter)

        # Track active discovery sessions
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

        LOG.info("AutoDiscoveryDomainIntegration initialized")

    @contextmanager
    def discovery_session(self, target_domain: str, session_id: Optional[str] = None):
        """
        Context manager for domain-filtered discovery sessions.

        Args:
            target_domain: Domain to filter for during discovery
            session_id: Optional session identifier

        Usage:
            with integration.discovery_session("mail.ru") as session:
                # Run discovery operations
                results = run_strategy_discovery()
        """
        if not session_id:
            import time

            session_id = f"discovery_{int(time.time())}"

        LOG.info(f"Starting discovery session {session_id} for domain: {target_domain}")

        try:
            # Configure domain filtering for discovery
            self._start_discovery_session(target_domain, session_id)

            # Yield session context
            session_context = {
                "session_id": session_id,
                "target_domain": target_domain,
                "domain_filter": self.domain_filter,
                "packet_integration": self.packet_integration,
            }

            yield session_context

        finally:
            # Clean up discovery session
            self._end_discovery_session(session_id)
            LOG.info(f"Ended discovery session {session_id}")

    def _start_discovery_session(self, target_domain: str, session_id: str) -> None:
        """Start a new discovery session with domain filtering."""
        # Configure domain filter for discovery mode
        self.domain_filter.configure_filter(target_domain, FilterMode.DISCOVERY)

        # Add rule to config manager
        self.config_manager.add_rule(target_domain, FilterMode.DISCOVERY)

        # Track session
        self._active_sessions[session_id] = {
            "target_domain": target_domain,
            "start_time": time.time(),
            "stats": self.domain_filter.get_stats(),
        }

        LOG.info(f"Started discovery session for {target_domain}")

    def _end_discovery_session(self, session_id: str) -> None:
        """End a discovery session and clean up."""
        if session_id in self._active_sessions:
            session_info = self._active_sessions[session_id]
            target_domain = session_info["target_domain"]

            # Log session summary
            self.domain_filter.log_filtering_summary()

            # Remove from active sessions
            del self._active_sessions[session_id]

            # Optionally remove rule (keep for now for analysis)
            # self.config_manager.remove_rule(target_domain)

            LOG.info(f"Cleaned up discovery session for {target_domain}")


# Global integration instance for easy access
_global_integration: Optional[AutoDiscoveryDomainIntegration] = None


def get_integration() -> AutoDiscoveryDomainIntegration:
    """Get or create global integration instance."""
    global _global_integration
    if _global_integration is None:
        _global_integration = AutoDiscoveryDomainIntegration()
    return _global_integration


def configure_discovery_filtering(target_domain: str) -> None:
    """
    Configure domain filtering for discovery mode.

    Args:
        target_domain: Domain to filter for
    """
    integration = get_integration()
    integration.domain_filter.configure_filter(target_domain, FilterMode.DISCOVERY)
    LOG.info(f"Configured discovery filtering for: {target_domain}")


def disable_discovery_filtering() -> None:
    """Disable discovery filtering and return to normal mode."""
    integration = get_integration()
    integration.domain_filter.clear_rules()
    LOG.info("Disabled discovery filtering")
