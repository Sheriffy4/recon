"""
Override Manager

This module manages domain rule overrides during discovery mode, providing
functionality to temporarily disable domain-specific rules and enable
adaptive strategy testing.

Requirements: 2.3, 4.1, 4.2, 4.3, 4.5
"""

import json
import os
import hashlib
import logging
from typing import Dict, Any, Optional, Set
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class OverrideManager:
    """
    Manages domain rule overrides during discovery mode.

    This class provides functionality to temporarily disable domain-specific rules
    during discovery sessions, enabling adaptive strategy testing without being
    constrained by existing configurations.

    Responsibilities:
    - Disable existing domain-specific strategy rules for target domains
    - Override configured domain rules with adaptive strategy testing
    - Manage conflict resolution between discovery mode and domain rules
    - Restore normal domain rule processing after discovery sessions
    - Prioritize discovery mode behavior when conflicts exist
    """

    def __init__(self, config_file: str = "domain_rules.json"):
        """
        Initialize the override manager.

        Args:
            config_file: Path to the domain rules configuration file
        """
        env_path = os.environ.get("RECON_DOMAIN_RULES_PATH", "").strip()
        self.config_file = env_path or config_file
        self.backup_file = f"{self.config_file}.discovery_backup"
        self.is_discovery_active = False
        self.active_target_domain: Optional[str] = None
        self.overridden_rules: Dict[str, Dict[str, Any]] = {}
        self.discovery_session_id: Optional[str] = None

        logger.info(f"OverrideManager initialized with config: {config_file}")

    def _marker_path(self) -> Path:
        """Marker file must be рядом с domain_rules.json, иначе при другом cwd не сработает."""
        try:
            return Path(self.config_file).resolve().with_name(".domain_rules_updated")
        except Exception:
            return Path(".domain_rules_updated")

    @staticmethod
    def _sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _normalize_domain_rules_schema(raw: Any) -> Dict[str, Any]:
        """
        Support both:
          - new schema: {domain_rules: {...}, default_strategy: {...}, ...}
          - legacy schema: { "<domain>": {...}, ... }
        """
        now = datetime.now().isoformat()
        if (
            isinstance(raw, dict)
            and "domain_rules" in raw
            and isinstance(raw["domain_rules"], dict)
        ):
            raw.setdefault("version", "1.0")
            raw.setdefault("last_updated", now)
            raw.setdefault("default_strategy", {})
            return raw
        if isinstance(raw, dict):
            return {
                "version": "1.0",
                "last_updated": now,
                "domain_rules": raw,
                "default_strategy": {},
            }
        return {
            "version": "1.0",
            "last_updated": now,
            "domain_rules": {},
            "default_strategy": {},
        }

    def _should_preserve_current_rule(self, rule_domain: str, target_domain: str) -> bool:
        """
        Decide whether rule from CURRENT config should override BACKUP during restore.
        Preserve:
          - exact target domain rule
          - wildcard rules matching target (e.g., *.googlevideo.com for www.googlevideo.com)
          - any rule that wasn't in backup (newly discovered)
        """
        if not rule_domain or not target_domain:
            return False
        rd = rule_domain.lower().strip().rstrip(".")
        td = target_domain.lower().strip().rstrip(".")
        if rd == td:
            return True
        if rd.startswith("*.") and td.endswith(rd[2:]):
            return True
        return False

    def enable_discovery_mode(self, target_domain: str, session_id: str = None) -> bool:
        """
        Enable discovery mode for a target domain.

        This method disables existing domain-specific strategy rules for the target domain
        and enables adaptive strategy testing. It creates a backup of the current
        configuration before making changes.

        Args:
            target_domain: The domain to enable discovery mode for
            session_id: Optional session identifier for tracking

        Returns:
            True if discovery mode enabled successfully, False otherwise

        Requirements: 4.1, 4.2, 4.3
        """
        try:
            if self.is_discovery_active:
                logger.warning(
                    f"Discovery mode already active for domain: {self.active_target_domain}"
                )
                if self.active_target_domain == target_domain.lower().strip().rstrip("."):
                    logger.info("Same target domain, continuing with existing discovery mode")
                    return True
                else:
                    logger.error(
                        "Cannot enable discovery mode for different domain while another is active"
                    )
                    return False

            target_domain_lower = target_domain.lower().strip().rstrip(".")

            # Create backup of current configuration
            if not self._create_backup():
                logger.error("Failed to create configuration backup")
                return False

            # Load current domain rules
            domain_rules = self._load_domain_rules()
            if domain_rules is None:
                logger.error("Failed to load domain rules")
                return False

            # Find and override rules for target domain
            overridden_count = self._override_target_domain_rules(domain_rules, target_domain_lower)

            # Save modified configuration
            if not self._save_domain_rules(domain_rules):
                logger.error("Failed to save modified domain rules")
                self._restore_from_backup()
                return False

            # Update state
            self.is_discovery_active = True
            self.active_target_domain = target_domain_lower
            self.discovery_session_id = (
                session_id or f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )

            logger.info(f"✅ Discovery mode enabled for domain: {target_domain_lower}")
            logger.info(f"   Session ID: {self.discovery_session_id}")
            logger.info(f"   Overridden rules: {overridden_count}")

            return True

        except Exception as e:
            logger.error(f"Error enabling discovery mode for '{target_domain}': {e}")
            self._restore_from_backup()
            return False

    def disable_discovery_mode(self) -> bool:
        """
        Disable discovery mode and restore normal domain rule processing.

        This method restores the original domain rules configuration from backup,
        effectively ending the discovery session and returning to normal operation.

        Returns:
            True if discovery mode disabled successfully, False otherwise

        Requirements: 4.4
        """
        try:
            if not self.is_discovery_active:
                logger.warning("Discovery mode is not currently active")
                return True

            # Store current state for logging and for merge-restore policy
            target_domain = self.active_target_domain
            session_id = self.discovery_session_id

            # Attempt to restore from backup WITH MERGE (preserve newly discovered rules)
            backup_restored = self._restore_from_backup_merge(target_domain=target_domain or "")
            if not backup_restored:
                logger.error(
                    "Failed to restore configuration from backup, but discovery mode state has been reset"
                )
                logger.warning("Manual configuration restoration may be required")

            # Clear state AFTER restoration attempt (do not lose context needed for restore)
            self.is_discovery_active = False
            self.active_target_domain = None
            self.overridden_rules.clear()
            self.discovery_session_id = None

            logger.info(f"✅ Discovery mode disabled for domain: {target_domain}")
            logger.info(f"   Session ID: {session_id}")
            if backup_restored:
                logger.info("   Normal domain rule processing restored")
            else:
                logger.warning(
                    "   Discovery mode state reset, but configuration restoration failed"
                )

            return backup_restored

        except Exception as e:
            logger.error(f"Error disabling discovery mode: {e}")
            # Even in case of exception, ensure state is reset
            self.is_discovery_active = False
            self.active_target_domain = None
            self.overridden_rules.clear()
            self.discovery_session_id = None
            return False

    def is_override_active(self, domain: str = None) -> bool:
        """
        Check if discovery mode override is currently active.

        Args:
            domain: Optional domain to check specifically

        Returns:
            True if override is active (and matches domain if specified), False otherwise

        Requirements: 4.1, 4.2, 4.3
        """
        if not self.is_discovery_active:
            return False

        if domain is None:
            return True

        domain_lower = domain.lower().strip().rstrip(".")
        return self.active_target_domain == domain_lower

    def get_discovery_status(self) -> Dict[str, Any]:
        """
        Get current discovery mode status information.

        Returns:
            Dictionary containing discovery mode status details
        """
        return {
            "is_active": self.is_discovery_active,
            "target_domain": self.active_target_domain,
            "session_id": self.discovery_session_id,
            "overridden_rules_count": len(self.overridden_rules),
            "config_file": self.config_file,
            "backup_exists": os.path.exists(self.backup_file),
        }

    def resolve_conflict(
        self, domain: str, existing_rule: Dict[str, Any], discovery_rule: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Resolve conflicts between discovery mode and existing domain rules.

        This method implements the conflict resolution logic where discovery mode
        behavior takes precedence over existing domain rules.

        Args:
            domain: The domain where conflict occurs
            existing_rule: The existing domain rule
            discovery_rule: The discovery mode rule

        Returns:
            The resolved rule (prioritizes discovery mode)

        Requirements: 4.5
        """
        try:
            domain_lower = domain.lower().strip().rstrip(".")

            # Discovery mode always takes precedence
            if self.is_override_active(domain_lower):
                logger.info(
                    f"🔧 Conflict resolution: Discovery mode takes precedence for {domain_lower}"
                )
                logger.debug(f"   Existing rule: {existing_rule.get('type', 'unknown')}")
                logger.debug(f"   Discovery rule: {discovery_rule.get('type', 'unknown')}")
                return discovery_rule.copy()

            # If discovery mode is not active for this domain, use existing rule
            logger.debug(f"No discovery mode conflict for {domain_lower}, using existing rule")
            return existing_rule.copy()

        except Exception as e:
            logger.error(f"Error resolving conflict for domain '{domain}': {e}")
            # Fallback to existing rule in case of error
            return existing_rule.copy()

    def _create_backup(self) -> bool:
        """
        Create a backup of the current domain rules configuration.

        Returns:
            True if backup created successfully, False otherwise
        """
        try:
            if not os.path.exists(self.config_file):
                logger.warning(
                    f"Config file {self.config_file} does not exist, creating empty backup"
                )
                # Create empty backup for non-existent config
                empty_config = {
                    "version": "1.0",
                    "last_updated": datetime.now().isoformat(),
                    "domain_rules": {},
                    "default_strategy": {},
                }
                with open(self.backup_file, "w", encoding="utf-8") as f:
                    json.dump(empty_config, f, indent=2, ensure_ascii=False)
                return True

            # Copy existing config to backup
            import shutil

            shutil.copy2(self.config_file, self.backup_file)

            logger.debug(f"Created backup: {self.backup_file}")
            return True

        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return False

    def _restore_from_backup(self) -> bool:
        """
        Restore domain rules configuration from backup.

        Returns:
            True if restored successfully, False otherwise
        """
        try:
            if not os.path.exists(self.backup_file):
                logger.error(f"Backup file not found: {self.backup_file}")
                return False

            # Restore from backup
            import shutil

            shutil.copy2(self.backup_file, self.config_file)

            # Remove backup file
            os.remove(self.backup_file)

            logger.debug(f"Restored configuration from backup")
            return True

        except Exception as e:
            logger.error(f"Error restoring from backup: {e}")
            return False

    def _restore_from_backup_merge(self, target_domain: str) -> bool:
        """
        Restore domain rules configuration from backup, but preserve any new/updated rules
        written during discovery (e.g., by StrategySaver).

        This prevents the classic issue:
          discovery backup restore overwrites newly discovered strategy rules.
        """
        try:
            if not os.path.exists(self.backup_file):
                logger.error(f"Backup file not found: {self.backup_file}")
                return False

            # Load backup config
            with open(self.backup_file, "r", encoding="utf-8") as f:
                backup_raw = json.load(f)
            backup_cfg = self._normalize_domain_rules_schema(backup_raw)

            # Load current config (may contain discovered rules)
            current_cfg = None
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    current_raw = json.load(f)
                current_cfg = self._normalize_domain_rules_schema(current_raw)
            else:
                current_cfg = self._normalize_domain_rules_schema({})

            backup_rules = (
                backup_cfg.get("domain_rules", {})
                if isinstance(backup_cfg.get("domain_rules"), dict)
                else {}
            )
            current_rules = (
                current_cfg.get("domain_rules", {})
                if isinstance(current_cfg.get("domain_rules"), dict)
                else {}
            )

            # Merge strategy rules:
            # - Start with backup (restores removed rules)
            # - Overlay current rules for:
            #     a) target domain and matching wildcard rules
            #     b) any new rules (not present in backup)
            merged_rules = dict(backup_rules)

            for d, rule in current_rules.items():
                if d not in backup_rules:
                    merged_rules[d] = rule
                    continue
                if self._should_preserve_current_rule(d, target_domain):
                    merged_rules[d] = rule

            backup_cfg["domain_rules"] = merged_rules
            # Keep default_strategy from backup unless current has a newer non-empty one
            if isinstance(current_cfg.get("default_strategy"), dict) and current_cfg.get(
                "default_strategy"
            ):
                backup_cfg["default_strategy"] = current_cfg["default_strategy"]

            backup_cfg["last_updated"] = datetime.now().isoformat()

            # Write merged config atomically (same method as _save_domain_rules uses)
            self._save_domain_rules(backup_cfg)

            # Remove backup file
            os.remove(self.backup_file)

            # Signal external update for services that keep in-memory registries
            try:
                self._marker_path().touch()
            except Exception:
                pass

            logger.debug("Restored configuration from backup with merge preservation")
            return True

        except Exception as e:
            logger.error(f"Error restoring from backup (merge): {e}", exc_info=True)
            return False

    def _load_domain_rules(self) -> Optional[Dict[str, Any]]:
        """
        Load domain rules from configuration file.

        Returns:
            Domain rules configuration or None if failed
        """
        try:
            if not os.path.exists(self.config_file):
                # Return empty configuration if file doesn't exist
                return {
                    "version": "1.0",
                    "last_updated": datetime.now().isoformat(),
                    "domain_rules": {},
                    "default_strategy": {},
                }

            with open(self.config_file, "r", encoding="utf-8") as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Error loading domain rules: {e}")
            return None

    def _save_domain_rules(self, domain_rules: Dict[str, Any]) -> bool:
        """
        Save domain rules to configuration file.

        Args:
            domain_rules: Domain rules configuration to save

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Update timestamp
            domain_rules["last_updated"] = datetime.now().isoformat()

            # Atomic write
            p = Path(self.config_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(p.name + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(domain_rules, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)

            # Create marker file to signal external update
            try:
                marker = p.with_name(".domain_rules_updated")
                marker.touch()
            except Exception as e:
                logger.warning(f"Failed to create marker file: {e}")

            return True

        except Exception as e:
            logger.error(f"Error saving domain rules: {e}")
            return False

    def _override_target_domain_rules(
        self, domain_rules: Dict[str, Any], target_domain: str
    ) -> int:
        """
        Override rules for the target domain and related domains.

        This method finds all rules that match the target domain (exact match,
        wildcard patterns, subdomains) and temporarily disables them by storing
        them in the overridden_rules dictionary and removing them from active rules.

        Args:
            domain_rules: The domain rules configuration
            target_domain: The target domain for discovery

        Returns:
            Number of rules overridden
        """
        try:
            rules = domain_rules.get("domain_rules", {})
            overridden_count = 0

            # Clear previous overridden rules
            self.overridden_rules.clear()

            # Find rules to override
            rules_to_remove = []

            for domain, rule in rules.items():
                should_override = False

                # Exact match
                if domain == target_domain:
                    should_override = True
                    logger.debug(f"Found exact match rule for {domain}")

                # Wildcard pattern match
                elif domain.startswith("*."):
                    wildcard_domain = domain[2:]  # Remove "*."
                    if target_domain.endswith(wildcard_domain):
                        should_override = True
                        logger.debug(f"Found wildcard rule {domain} matching {target_domain}")

                # Parent domain match (target is subdomain)
                elif target_domain.endswith(f".{domain}"):
                    should_override = True
                    logger.debug(f"Found parent domain rule {domain} for subdomain {target_domain}")

                # Subdomain match (rule is subdomain of target)
                elif domain.endswith(f".{target_domain}"):
                    should_override = True
                    logger.debug(f"Found subdomain rule {domain} under target {target_domain}")

                if should_override:
                    # Store the rule for potential restoration
                    self.overridden_rules[domain] = rule.copy()
                    rules_to_remove.append(domain)
                    overridden_count += 1

                    logger.info(f"🔧 Overriding rule for {domain}: {rule.get('type', 'unknown')}")

            # Remove overridden rules from active configuration
            for domain in rules_to_remove:
                del rules[domain]

            return overridden_count

        except Exception as e:
            logger.error(f"Error overriding target domain rules: {e}")
            return 0

    def get_overridden_rules(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the currently overridden rules.

        Returns:
            Dictionary of overridden domain rules
        """
        return self.overridden_rules.copy()

    def cleanup_backup_files(self) -> bool:
        """
        Clean up any leftover backup files.

        This method can be called to clean up backup files that may have been
        left behind due to unexpected shutdowns or errors.

        Returns:
            True if cleanup successful, False otherwise
        """
        try:
            if os.path.exists(self.backup_file):
                os.remove(self.backup_file)
                logger.info(f"Cleaned up backup file: {self.backup_file}")

            return True

        except Exception as e:
            logger.error(f"Error cleaning up backup files: {e}")
            return False
