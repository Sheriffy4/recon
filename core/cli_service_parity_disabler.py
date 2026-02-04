"""
CLI/Service Parity Override Disabler

This module provides functionality to disable CLI/service parity overrides
during auto discovery mode, ensuring strategy diversity instead of forcing
a single strategy like fakeddisorder.

Requirements: 1.1, 1.3 from cli-auto-mode-fixes spec
"""

import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CLIServiceParityStatus:
    """Status of CLI/service parity override system"""

    parity_override_active: bool
    domain_strategy_override_active: bool
    parity_override_disabled: bool
    current_override_strategy: Optional[str]


class CLIServiceParityDisabler:
    """
    Manages CLI/service parity override disabling during auto discovery.

    This class provides functionality to disable the CLI/service parity override
    that forces fakeddisorder strategy during auto discovery mode, enabling
    strategy diversity instead.

    Requirements: 1.1, 1.3
    """

    def __init__(self, bypass_engine=None):
        """
        Initialize the CLI/service parity disabler.

        Args:
            bypass_engine: The bypass engine to manage parity overrides for
        """
        self.bypass_engine = bypass_engine
        self.logger = logger

    def disable_parity_override(self) -> None:
        """
        Disable CLI/service parity override during auto discovery.

        This method enables discovery mode in the bypass engine, which
        automatically disables domain strategy overrides including the
        CLI/service parity mechanism.
        """
        if not self.bypass_engine:
            self.logger.warning("No bypass engine available to disable parity override")
            return

        if hasattr(self.bypass_engine, "enable_discovery_mode"):
            self.bypass_engine.enable_discovery_mode()
            self.logger.info("🔍 CLI/service parity override disabled via discovery mode")
        else:
            self.logger.warning("Bypass engine does not support discovery mode")

    def is_parity_override_active(self) -> bool:
        """
        Check if CLI/service parity override is currently active.

        Returns:
            True if parity override is active, False otherwise
        """
        if not self.bypass_engine:
            return False

        if hasattr(self.bypass_engine, "is_parity_override_active"):
            return self.bypass_engine.is_parity_override_active()

        # Fallback: check if discovery mode is inactive (which means parity could be active)
        if hasattr(self.bypass_engine, "is_discovery_mode_active"):
            return not self.bypass_engine.is_discovery_mode_active()

        return False

    def should_bypass_domain_strategy_override(self) -> bool:
        """
        Check if domain strategy override should be bypassed.

        Returns:
            True if override should be bypassed (during discovery mode), False otherwise
        """
        if not self.bypass_engine:
            return False

        if hasattr(self.bypass_engine, "should_bypass_domain_strategy_override"):
            return self.bypass_engine.should_bypass_domain_strategy_override()

        # Fallback: check if discovery mode is active
        if hasattr(self.bypass_engine, "is_discovery_mode_active"):
            return self.bypass_engine.is_discovery_mode_active()

        return False

    def get_parity_status(self) -> CLIServiceParityStatus:
        """
        Get the current status of CLI/service parity override system.

        Returns:
            CLIServiceParityStatus with current system state
        """
        parity_active = self.is_parity_override_active()
        domain_override_active = not self.should_bypass_domain_strategy_override()
        parity_disabled = not parity_active

        current_strategy = None
        if self.bypass_engine and hasattr(self.bypass_engine, "strategy_override"):
            override = getattr(self.bypass_engine, "strategy_override", None)
            if override:
                current_strategy = override.get("type", "unknown")

        return CLIServiceParityStatus(
            parity_override_active=parity_active,
            domain_strategy_override_active=domain_override_active,
            parity_override_disabled=parity_disabled,
            current_override_strategy=current_strategy,
        )
