"""
Hot configuration reloader for strategy updates.

This module provides the ConfigHotReloader class that monitors configuration
files and applies changes without interrupting existing connections.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional, Set
import sys

# Add parent directory to path for imports
_parent = Path(__file__).parent.parent
if str(_parent) not in sys.path:
    sys.path.insert(0, str(_parent))

from optimization.models import Strategy


LOG = logging.getLogger(__name__)


class ConfigHotReloader:
    """
    Handles hot configuration reload without service restart.

    Monitors configuration files and applies changes to new connections
    without interrupting existing ones.

    Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
    """

    def __init__(
        self,
        domain_registry=None,
        config_file: str = "domain_rules.json",
        sites_file: str = "sites.txt",
        check_interval: float = 5.0,
    ):
        """
        Initialize ConfigHotReloader.

        Args:
            domain_registry: DomainRuleRegistry instance (optional, for type checking)
            config_file: Path to domain rules configuration file
            sites_file: Path to sites.txt file
            check_interval: How often to check for config changes (seconds)
        """
        self.domain_registry = domain_registry
        self.config_file = config_file
        self.sites_file = sites_file
        self.check_interval = check_interval
        self._last_config_hash: Optional[str] = None
        self._monitoring_task: Optional[asyncio.Task] = None
        self._stop_monitoring = False
        self.logger = LOG

        # Calculate initial hash
        self._update_config_hash()

    def _calculate_file_hash(self, filepath: str) -> Optional[str]:
        """
        Calculate MD5 hash of a file.

        Args:
            filepath: Path to file

        Returns:
            MD5 hash string or None if file doesn't exist
        """
        try:
            if not os.path.exists(filepath):
                return None

            with open(filepath, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()

            return file_hash

        except Exception as e:
            self.logger.error(f"Error calculating hash for {filepath}: {e}")
            return None

    def _update_config_hash(self) -> None:
        """Update the stored configuration file hash."""
        self._last_config_hash = self._calculate_file_hash(self.config_file)

    def _has_config_changed(self) -> bool:
        """
        Check if configuration file has changed.

        Returns:
            True if config file has been modified
        """
        current_hash = self._calculate_file_hash(self.config_file)

        if current_hash is None:
            return False

        if self._last_config_hash is None:
            return True

        return current_hash != self._last_config_hash

    async def start_monitoring(self) -> None:
        """
        Start configuration file monitoring.

        Monitors the configuration file for changes and triggers reload
        when changes are detected.

        Requirements: 7.1
        """
        self.logger.info(
            f"🔄 Starting configuration monitoring " f"(check interval: {self.check_interval}s)"
        )

        self._stop_monitoring = False

        while not self._stop_monitoring:
            try:
                # Wait for check interval
                await asyncio.sleep(self.check_interval)

                # Check if config has changed
                if self._has_config_changed():
                    self.logger.info("📝 Configuration file changed, reloading...")

                    # Reload configuration
                    success = self.reload_configuration()

                    if success:
                        self.logger.info("✅ Configuration reloaded successfully")
                        # Update hash after successful reload
                        self._update_config_hash()
                    else:
                        self.logger.error("❌ Configuration reload failed")
                        # Don't update hash so we can retry

            except asyncio.CancelledError:
                self.logger.info("Configuration monitoring cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in configuration monitoring: {e}", exc_info=True)
                # Continue monitoring despite errors
                await asyncio.sleep(self.check_interval)

    def stop_monitoring(self) -> None:
        """Stop configuration file monitoring."""
        self.logger.info("Stopping configuration monitoring")
        self._stop_monitoring = True

        if self._monitoring_task and not self._monitoring_task.done():
            self._monitoring_task.cancel()

    def update_domain_strategy(
        self,
        domain: str,
        strategy: Strategy,
    ) -> bool:
        """
        Update strategy for domain and trigger reload.

        This method:
        1. Loads current configuration
        2. Updates the strategy for the domain
        3. Adds domain to sites.txt if not present
        4. Saves configuration
        5. Triggers reload

        Args:
            domain: Domain to update
            strategy: New strategy to apply

        Returns:
            True if update successful

        Requirements: 7.2, 7.4, 7.5
        """
        try:
            self.logger.info(f"📝 Updating strategy for {domain}")

            # Load current configuration
            if not os.path.exists(self.config_file):
                self.logger.error(f"Configuration file not found: {self.config_file}")
                return False

            with open(self.config_file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            # Convert Strategy object to dict format
            # Handle both Strategy objects and dicts
            if isinstance(strategy, dict):
                strategy_dict = {
                    "type": strategy.get("type", "unknown"),
                    "attacks": strategy.get("attacks", []),
                    "params": strategy.get("params", {}),
                }
            else:
                strategy_dict = {
                    "type": strategy.type,
                    "attacks": strategy.attacks,
                    "params": strategy.params,
                }

            # Update domain rule
            if "domain_rules" not in config_data:
                config_data["domain_rules"] = {}

            config_data["domain_rules"][domain.lower()] = strategy_dict

            # Save updated configuration
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"   ✅ Configuration file updated")

            # Add domain to sites.txt if not present
            self._add_domain_to_sites(domain)

            # Reload configuration in domain registry
            if self.domain_registry:
                reload_success = self.reload_configuration()
                if not reload_success:
                    self.logger.warning("   ⚠️ Configuration reload failed")
                    return False

            # Update hash to reflect the change we just made
            self._update_config_hash()

            self.logger.info(f"✅ Strategy updated successfully for {domain}")
            return True

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parsing error in {self.config_file}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error updating domain strategy for {domain}: {e}", exc_info=True)
            return False

    async def remove_domain_strategy(self, domain: str) -> bool:
        """
        Remove domain-specific strategy from configuration.

        This makes the engine use the default strategy for this domain.

        Args:
            domain: Domain to remove

        Returns:
            True if removal successful
        """
        try:
            self.logger.info(f"🗑️ Removing strategy for {domain}")

            # Load current configuration
            if not os.path.exists(self.config_file):
                self.logger.error(f"Configuration file not found: {self.config_file}")
                return False

            with open(self.config_file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            # Remove domain rule if exists
            if "domain_rules" in config_data and domain.lower() in config_data["domain_rules"]:
                del config_data["domain_rules"][domain.lower()]
                self.logger.info(f"   ✅ Removed domain rule for {domain}")
            else:
                self.logger.warning(f"   ⚠️ Domain {domain} not found in rules")
                return True  # Not an error, just nothing to remove

            # Save updated configuration
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"   ✅ Configuration file updated")

            # Reload configuration in domain registry
            if self.domain_registry:
                reload_success = self.reload_configuration()
                if not reload_success:
                    self.logger.warning("   ⚠️ Configuration reload failed")
                    return False

            # Update hash to reflect the change we just made
            self._update_config_hash()

            self.logger.info(f"✅ Domain rule removed successfully for {domain}")
            return True

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parsing error in {self.config_file}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error removing domain strategy for {domain}: {e}", exc_info=True)
            return False

    def _add_domain_to_sites(self, domain: str) -> bool:
        """
        Add domain to sites.txt if not already present.

        Args:
            domain: Domain to add

        Returns:
            True if domain was added or already exists

        Requirements: 7.5
        """
        try:
            # Read current sites
            existing_sites: Set[str] = set()

            if os.path.exists(self.sites_file):
                with open(self.sites_file, "r", encoding="utf-8") as f:
                    existing_sites = {line.strip().lower() for line in f if line.strip()}

            # Check if domain already exists
            domain_lower = domain.lower()
            if domain_lower in existing_sites:
                self.logger.debug(f"   Domain {domain} already in {self.sites_file}")
                return True

            # Add domain to sites.txt
            with open(self.sites_file, "a", encoding="utf-8") as f:
                f.write(f"{domain_lower}\n")

            self.logger.info(f"   ✅ Added {domain} to {self.sites_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error adding domain to {self.sites_file}: {e}", exc_info=True)
            return False

    def reload_configuration(self) -> bool:
        """
        Reload configuration from files.

        This method reloads the domain rules without interrupting
        existing connections. New connections will use the updated rules.

        Returns:
            True if reload successful

        Requirements: 7.2, 7.3
        """
        try:
            if not self.domain_registry:
                self.logger.warning("No domain registry available for reload")
                return False

            # Reload configuration
            # The domain registry's load_configuration method handles
            # validation and error handling
            success = self.domain_registry.load_configuration()

            if success:
                self.logger.info("✅ Configuration reloaded successfully")
            else:
                self.logger.error("❌ Configuration reload failed")

            return success

        except Exception as e:
            self.logger.error(f"Error reloading configuration: {e}", exc_info=True)
            return False

    def get_last_config_hash(self) -> Optional[str]:
        """
        Get the last known configuration file hash.

        Returns:
            MD5 hash string or None
        """
        return self._last_config_hash
