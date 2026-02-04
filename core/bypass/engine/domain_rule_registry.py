#!/usr/bin/env python3
"""
Domain Rule Registry

This module manages Domain → Strategy configuration from JSON files,
providing a single source of truth for domain-based bypass rules.
"""

import json
import os
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class DomainRuleRegistry:
    """
    Manages Domain → Strategy configuration from JSON file.

    This class provides a single source of truth containing Domain → Strategy
    mappings, supporting configuration validation and error handling.
    """

    def __init__(self, config_file: str = "domain_rules.json"):
        """
        Initialize the domain rule registry.

        Args:
            config_file: Path to the domain rules configuration file
        """
        env_path = os.environ.get("RECON_DOMAIN_RULES_PATH", "").strip()
        self.config_file = env_path or config_file
        self.domain_rules: Dict[str, Dict[str, Any]] = {}
        self.default_strategy: Dict[str, Any] = {}
        self._config_version = "1.0"
        self._dirty = False

        # Load configuration on initialization
        self.load_configuration()

        logger.info("DomainRuleRegistry initialized with config: %s", self.config_file)

    def _marker_path(self) -> Path:
        # Marker must live рядом с domain_rules.json, иначе при разном cwd не работает
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

    def _normalize_strategy_schema(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Accept both 'params' and legacy 'parameters'.
        Add 'params' when only 'parameters' exists, without removing legacy key.
        """
        if not isinstance(strategy, dict):
            return {}
        if (
            "params" not in strategy
            and "parameters" in strategy
            and isinstance(strategy["parameters"], dict)
        ):
            strategy["params"] = strategy["parameters"]

        # Canonicalize well-known legacy parameter names (do not delete legacy keys).
        params = strategy.get("params")
        if isinstance(params, dict):
            # split_position -> split_pos
            if "split_pos" not in params and "split_position" in params:
                params["split_pos"] = params.get("split_position")
            # split_cnt -> split_count
            if "split_count" not in params and "split_cnt" in params:
                params["split_count"] = params.get("split_cnt")
            # splitPosition alias at top-level (some configs may store it mistakenly)
            if "split_pos" not in params and "splitPosition" in params:
                params["split_pos"] = params.get("splitPosition")
        return strategy

    def _normalize_config_schema(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(cfg, dict):
            return {
                "version": "1.0",
                "last_updated": "",
                "domain_rules": {},
                "default_strategy": {},
            }
        cfg.setdefault("domain_rules", {})
        cfg.setdefault("default_strategy", {})
        cfg.setdefault("version", "1.0")
        # normalize individual strategies
        if isinstance(cfg.get("domain_rules"), dict):
            for d, st in list(cfg["domain_rules"].items()):
                if isinstance(st, dict):
                    cfg["domain_rules"][d] = self._normalize_strategy_schema(st)
        if isinstance(cfg.get("default_strategy"), dict):
            cfg["default_strategy"] = self._normalize_strategy_schema(cfg["default_strategy"])
        return cfg

    def _atomic_write_json(self, path: str, data: Dict[str, Any]) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)

    def load_configuration(self) -> bool:
        """
        Load domain rules configuration from JSON file.

        Returns:
            True if configuration loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(self.config_file):
                logger.warning(f"Configuration file not found: {self.config_file}")
                self._load_default_configuration()
                return False

            with open(self.config_file, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            config_data = self._normalize_config_schema(config_data)

            # Validate and load configuration
            if self._validate_configuration(config_data):
                self.domain_rules = config_data.get("domain_rules", {})
                self.default_strategy = config_data.get("default_strategy", {})
                self._config_version = config_data.get("version", "1.0")
                self._dirty = False

                logger.info(f"Loaded {len(self.domain_rules)} domain rules from {self.config_file}")

                # Run comprehensive startup conflict detection (Task 10)
                self._run_startup_conflict_detection()

                return True
            else:
                logger.error(f"Invalid configuration format in {self.config_file}")
                self._load_default_configuration()
                return False

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error in {self.config_file}: {e}")
            self._load_default_configuration()
            return False
        except Exception as e:
            logger.error(f"Error loading configuration from {self.config_file}: {e}")
            self._load_default_configuration()
            return False

    def get_strategy_for_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get strategy configuration for exact domain match.

        This method performs exact domain matching only. For hierarchical
        matching, use HierarchicalDomainMatcher.

        Args:
            domain: The domain to find a strategy for

        Returns:
            Strategy configuration dictionary, or None if no exact match
        """
        if not domain:
            return None

        domain_lower = domain.lower().strip()
        return self.domain_rules.get(domain_lower)

    def get_default_strategy(self) -> Dict[str, Any]:
        """
        Get the default strategy for fallback behavior.

        Returns:
            Default strategy configuration dictionary
        """
        return self.default_strategy.copy()

    def get_all_domain_rules(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all domain rules.

        Returns:
            Dictionary of all domain rules
        """
        return self.domain_rules.copy()

    def _validate_configuration(self, config_data: Dict[str, Any]) -> bool:
        """
        Validate configuration data structure.

        Args:
            config_data: Configuration data to validate

        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Check required top-level keys
            if "domain_rules" not in config_data:
                logger.error("Missing 'domain_rules' in configuration")
                return False

            if "default_strategy" not in config_data:
                logger.error("Missing 'default_strategy' in configuration")
                return False

            # Validate domain rules structure
            domain_rules = config_data["domain_rules"]
            if not isinstance(domain_rules, dict):
                logger.error("'domain_rules' must be a dictionary")
                return False

            # Validate each domain rule
            for domain, strategy in domain_rules.items():
                if not isinstance(domain, str) or not domain.strip():
                    logger.error(f"Invalid domain key: {domain}")
                    return False

                if not isinstance(strategy, dict):
                    logger.error(f"Strategy for domain '{domain}' must be a dictionary")
                    return False

                if "type" not in strategy:
                    logger.error(f"Strategy for domain '{domain}' missing 'type' field")
                    return False

            # Validate default strategy
            default_strategy = config_data["default_strategy"]
            if not isinstance(default_strategy, dict):
                logger.error("'default_strategy' must be a dictionary")
                return False

            if "type" not in default_strategy:
                logger.error("Default strategy missing 'type' field")
                return False

            return True

        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return False

    def _load_default_configuration(self):
        """Load built-in default configuration as fallback."""
        self.domain_rules = {
            "googlevideo.com": {
                "type": "multisplit",
                "params": {"split_pos": 2, "split_count": 3, "split_position": 2},
            },
            "youtube.com": {
                "type": "multisplit",
                "params": {"split_pos": 2, "split_count": 3, "split_position": 2},
            },
        }

        self.default_strategy = {
            "type": "fakeddisorder",
            "params": {"fake_count": 10, "disorder_count": 10},
        }

        self._config_version = "1.0"

        logger.info("Loaded built-in default configuration")

    def save_configuration(self) -> bool:
        """
        Save current configuration to JSON file.

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            from datetime import datetime

            marker = self._marker_path()
            if marker.exists() and not self._dirty:
                # Внешнее обновление было, а мы сами не меняли rules -> просто reload, не затираем файл
                try:
                    marker.unlink()
                except Exception:
                    pass
                logger.info(
                    "External update marker detected; reloading config and skipping save to avoid stale overwrite"
                )
                self.load_configuration()
                return True

            abs_path = str(Path(self.config_file).resolve())
            cwd = os.getcwd()
            before_hash = (
                self._sha256_file(self.config_file) if os.path.exists(self.config_file) else None
            )

            config_data = {
                "version": self._config_version,
                "last_updated": datetime.now().isoformat(),
                "default_strategy": self.default_strategy,
                "domain_rules": self.domain_rules,
            }

            self._atomic_write_json(self.config_file, config_data)
            self._dirty = False

            after_hash = (
                self._sha256_file(self.config_file) if os.path.exists(self.config_file) else None
            )
            if before_hash is not None and after_hash == before_hash:
                logger.warning(
                    "Configuration saved but file hash did not change. path=%s cwd=%s",
                    abs_path,
                    cwd,
                )

            logger.info("Configuration saved to %s (cwd=%s)", abs_path, cwd)
            return True

        except Exception as e:
            logger.error(f"Error saving configuration to {self.config_file}: {e}")
            return False

    def add_domain_rule(
        self, domain: str, strategy: Dict[str, Any], check_parent: bool = True
    ) -> bool:
        """
        Add or update a domain rule.

        Args:
            domain: Domain name to add rule for
            strategy: Strategy configuration dictionary
            check_parent: If True, check if parent domain strategy exists and log recommendation

        Returns:
            True if rule added successfully, False otherwise

        Requirements: 10.3, 4.1, 4.2, 4.3, 4.5 (Task 12.1)
        """
        logger.info(f"🔍 add_domain_rule called for domain: {domain}")
        try:
            if not domain or not isinstance(strategy, dict):
                logger.error("Invalid domain or strategy for rule addition")
                return False

            # Infer 'type' from 'attacks' if not provided
            if "type" not in strategy:
                attacks = strategy.get("attacks", [])
                if attacks:
                    # Build type from attacks list
                    strategy["type"] = ",".join(attacks) if len(attacks) > 1 else attacks[0]
                    logger.info(f"Inferred type '{strategy['type']}' from attacks {attacks}")
                else:
                    logger.error("Strategy must have either 'type' or 'attacks' field")
                    return False

            domain_lower = domain.lower().strip()

            # Task 12.1: Validate parameter completeness before saving
            from .parameter_preservation_validator import (
                ParameterPreservationValidator,
                ensure_complete_strategy,
            )

            validator = ParameterPreservationValidator()

            # Validate strategy has all required parameters
            if not validator.validate_before_save(domain_lower, strategy):
                logger.error(
                    f"❌ Strategy validation failed for '{domain_lower}' - missing required parameters"
                )
                logger.error("   Strategy will be saved but may not work correctly in production")

            # Ensure strategy has complete parameters (with inference if needed)
            strategy = ensure_complete_strategy(strategy, domain_lower)

            # Check for parent domain strategy before adding (Requirement 10.3)
            if check_parent:
                self._check_parent_domain_before_adding(domain_lower, strategy)

            self.domain_rules[domain_lower] = strategy
            self._dirty = True

            logger.info(f"Added domain rule: {domain_lower} -> {strategy.get('type')}")
            return True

        except Exception as e:
            logger.error(f"Error adding domain rule for '{domain}': {e}")
            return False

    def add_or_update_rule(
        self, domain: str, strategy: Dict[str, Any], check_parent: bool = True
    ) -> bool:
        """
        Add or update a domain rule (alias for add_domain_rule).

        This method is an alias for add_domain_rule, provided for backward compatibility
        with cli.py and other code that uses this method name.

        Args:
            domain: Domain name to add rule for
            strategy: Strategy configuration dictionary
            check_parent: If True, check if parent domain strategy exists and log recommendation

        Returns:
            True if rule added/updated successfully, False otherwise
        """
        # If external writer updated file (CLI), reload first to avoid saving stale memory
        marker = self._marker_path()
        if marker.exists():
            try:
                marker.unlink()
            except Exception:
                pass
            self.load_configuration()

        success = self.add_domain_rule(domain, strategy, check_parent)

        # Save to file after adding (now safe, memory is fresh)
        if success:
            self.save_configuration()

        return success

    def _check_parent_domain_before_adding(self, domain: str, strategy: Dict[str, Any]):
        """
        Check if parent domain strategy exists before adding subdomain strategy.

        This method logs a recommendation if a parent domain strategy already exists,
        suggesting that the user consider using the parent strategy instead.

        Args:
            domain: Domain being added
            strategy: Strategy being added

        Requirements: 10.3
        """
        try:
            # Check if domain has a parent
            if not domain or "." not in domain:
                return

            parts = domain.split(".")
            if len(parts) <= 2:
                # Already at top level
                return

            parent_domain = ".".join(parts[1:])

            # Check if parent domain has a strategy
            parent_strategy = None
            parent_key = None

            if parent_domain in self.domain_rules:
                parent_strategy = self.domain_rules[parent_domain]
                parent_key = parent_domain
            else:
                # Check for wildcard pattern
                wildcard_pattern = f"*.{parent_domain}"
                if wildcard_pattern in self.domain_rules:
                    parent_strategy = self.domain_rules[wildcard_pattern]
                    parent_key = wildcard_pattern

            if parent_strategy:
                logger.warning("=" * 80)
                logger.warning("ℹ️  PARENT DOMAIN STRATEGY EXISTS")
                logger.warning("=" * 80)
                logger.warning(f"Domain being added: {domain}")
                logger.warning(f"Parent domain: {parent_key}")
                logger.warning(f"Parent strategy type: {parent_strategy.get('type', 'unknown')}")
                logger.warning("")
                logger.warning("💡 RECOMMENDATION:")
                logger.warning(
                    f"   A strategy already exists for the parent domain '{parent_key}'."
                )
                logger.warning(
                    f"   Consider testing if the parent domain strategy works for '{domain}'"
                )
                logger.warning("   before creating a subdomain-specific strategy.")
                logger.warning("")
                logger.warning("   Benefits of using parent domain strategy:")
                logger.warning("   • Simpler configuration (fewer rules)")
                logger.warning("   • Easier maintenance")
                logger.warning("   • Consistent behavior across subdomains")
                logger.warning("")
                logger.warning(
                    "   If the parent strategy works, you can skip creating this subdomain rule."
                )
                logger.warning("=" * 80)

        except Exception as e:
            logger.error(f"Error checking parent domain for '{domain}': {e}")

    def remove_domain_rule(self, domain: str) -> bool:
        """
        Remove a domain rule.

        Args:
            domain: Domain name to remove rule for

        Returns:
            True if rule removed successfully, False otherwise
        """
        try:
            domain_lower = domain.lower().strip()
            if domain_lower in self.domain_rules:
                del self.domain_rules[domain_lower]
                logger.info(f"Removed domain rule for: {domain_lower}")
                return True
            else:
                logger.warning(f"No rule found for domain: {domain_lower}")
                return False

        except Exception as e:
            logger.error(f"Error removing domain rule for '{domain}': {e}")
            return False

    def _run_startup_conflict_detection(self):
        """
        Run comprehensive startup conflict detection.

        This method uses the StartupConflictDetector to scan for all types of conflicts
        at service startup, providing detailed warnings and resolution guidance.

        Requirements: 6.1, 6.2, 6.3, 6.4, 6.5 (Task 10)
        """
        try:
            from .startup_conflict_detector import run_startup_conflict_detection

            # Run conflict detection
            report = run_startup_conflict_detection(self.config_file)

            # Store conflict report for later access
            self._conflict_report = report

        except ImportError as e:
            logger.warning(f"Could not import startup conflict detector: {e}")
            logger.warning("Falling back to basic IP conflict check")
            self._check_ip_conflicts()
        except Exception as e:
            logger.error(f"Error running startup conflict detection: {e}")
            logger.warning("Falling back to basic IP conflict check")
            self._check_ip_conflicts()

    def _check_ip_conflicts(self):
        """
        Check for potential IP conflicts where multiple domains might resolve to the same IP.

        This method warns about domains that are likely to share IPs (e.g., www.youtube.com and yt3.ggpht.com)
        and suggests using consistent strategies or relying on hierarchical fallback.

        NOTE: This is a fallback method. The preferred method is _run_startup_conflict_detection()
        which provides more comprehensive conflict detection.
        """
        try:
            import socket
            from collections import defaultdict

            # Group domains by their resolved IPs
            ip_to_domains = defaultdict(list)

            for domain in self.domain_rules.keys():
                # Skip wildcard patterns
                if domain.startswith("*"):
                    continue

                try:
                    # Try to resolve domain to IP
                    ip = socket.gethostbyname(domain)
                    ip_to_domains[ip].append(domain)
                except (socket.gaierror, socket.herror):
                    # Domain resolution failed, skip
                    continue
                except Exception as e:
                    logger.debug(f"Could not resolve {domain}: {e}")
                    continue

            # Check for conflicts (multiple domains on same IP with different strategies)
            conflicts_found = False
            for ip, domains in ip_to_domains.items():
                if len(domains) > 1:
                    # Multiple domains on same IP - check if they have different strategies
                    strategies = {}
                    for domain in domains:
                        strategy = self.domain_rules[domain]
                        strategy_type = strategy.get("type", "unknown")
                        strategy_params = str(strategy.get("params", {}))
                        strategy_key = f"{strategy_type}:{strategy_params}"
                        strategies[domain] = strategy_key

                    # Check if all strategies are the same
                    unique_strategies = set(strategies.values())
                    if len(unique_strategies) > 1:
                        conflicts_found = True
                        logger.warning(f"⚠️ IP CONFLICT DETECTED: {ip}")
                        logger.warning(
                            "   Multiple domains resolve to this IP with DIFFERENT strategies:"
                        )
                        for domain in domains:
                            strategy = self.domain_rules[domain]
                            logger.warning(
                                f"   - {domain}: {strategy.get('type')} {strategy.get('params', {})}"
                            )
                        logger.warning(
                            "   ℹ️  Domain-based filtering will use SNI to select the correct strategy"
                        )
                        logger.warning(
                            "   ℹ️  If a strategy doesn't work, consider using the same strategy for all domains on this IP"
                        )

            if conflicts_found:
                logger.warning("=" * 80)
                logger.warning("⚠️ IP CONFLICTS SUMMARY:")
                logger.warning("   Some domains share the same IP but have different strategies.")
                logger.warning(
                    "   The system will use SNI (Server Name Indication) to apply the correct strategy."
                )
                logger.warning("   If you experience issues, consider:")
                logger.warning("   1. Using the same strategy for all domains on the same IP")
                logger.warning("   2. Removing subdomain rules to use parent domain fallback")
                logger.warning("   3. Testing strategies individually with 'cli.py test <domain>'")
                logger.warning("=" * 80)
            else:
                logger.info("✅ No IP conflicts detected in domain rules")

        except Exception as e:
            logger.debug(f"Could not check for IP conflicts: {e}")

    def get_conflict_report(self):
        """
        Get the conflict report from the last startup conflict detection.

        Returns:
            ConflictReport object or None if not available
        """
        return getattr(self, "_conflict_report", None)
