#!/usr/bin/env python3
"""
Domain Strategy Engine

This module implements the core domain-based strategy engine that replaces
IP-based strategy mapping with domain-based hierarchical matching.
"""

from typing import Dict, Any, Optional, List, Callable
import logging
import time

from .sni_domain_extractor import SNIDomainExtractor
from .hierarchical_domain_matcher import HierarchicalDomainMatcher
from .runtime_ip_resolver import RuntimeIPResolver
from .strategy_result import StrategyResult

try:
    from .strategy_validator import StrategyValidator  # type: ignore
except Exception:  # pragma: no cover - optional dependency / backward compat
    StrategyValidator = None  # type: ignore

from .strategy_application_logger import StrategyApplicationLogger
from .parent_domain_recommender import ParentDomainRecommender
from .strategy_failure_tracker import StrategyFailureTracker

# Import feature flag checker
try:
    from core.bypass.filtering.feature_flags import is_runtime_ip_resolution_enabled
except ImportError:
    # Fallback if feature flags not available
    def is_runtime_ip_resolution_enabled(context=None):
        return True  # Default to enabled for backward compatibility


logger = logging.getLogger(__name__)


class _FallbackValidationResult:
    __slots__ = ("valid", "reason", "warning", "recommendation", "mismatches")

    def __init__(self):
        self.valid = True
        self.reason = None
        self.warning = "validator_unavailable"
        self.recommendation = None
        self.mismatches = []


class _FallbackStrategyValidator:
    """Fail-open validator to avoid crashing when StrategyValidator is unavailable."""

    def __init__(self, *_args, **_kwargs):
        pass

    def validate_strategy_application(self, *args, **kwargs):
        return _FallbackValidationResult()

    def reload_domain_rules(self):
        return None


class DomainStrategyEngine:
    """
    Core engine that maps domains to strategies without IP pre-resolution.

    This engine extracts domains from packets in real-time and uses hierarchical
    domain matching to determine the appropriate bypass strategy.
    """

    def __init__(
        self,
        domain_rules: Dict[str, Dict[str, Any]],
        default_strategy: Dict[str, Any],
        enable_ip_resolution: Optional[bool] = None,
        domain_rules_path: str = "domain_rules.json",
        auto_recovery_callback: Optional[Callable[[str, Dict[str, Any], int], None]] = None,
        revalidation_threshold: int = 5,
    ):
        """
        Initialize the domain strategy engine.

        Args:
            domain_rules: Dictionary mapping domains to strategy configurations
            default_strategy: Default strategy to use when no domain rule matches
            enable_ip_resolution: Enable runtime IP-to-domain resolution.
                                 If None, checks feature flag (default: None)
            domain_rules_path: Path to domain_rules.json for validation
            auto_recovery_callback: Optional callback for auto-recovery when strategy fails.
                                   Signature: callback(domain: str, strategy: Dict, retransmissions: int) -> None
            revalidation_threshold: Number of failures before triggering auto-recovery (default: 5)
        """
        self.domain_rules = domain_rules
        self.default_strategy = default_strategy

        # ✅ Single unified extractor (TLS SNI + HTTP Host + normalization)
        self.domain_extractor = SNIDomainExtractor(enable_fast_sni=True)

        self.domain_matcher = HierarchicalDomainMatcher(domain_rules, default_strategy)

        # Initialize strategy validator and application logger (Task 4)
        # StrategyValidator may be absent in some builds; do not crash.
        if StrategyValidator is None:
            self.strategy_validator = _FallbackStrategyValidator(domain_rules_path)
            logger.warning("StrategyValidator not available; validation is disabled (fail-open).")
        else:
            self.strategy_validator = StrategyValidator(domain_rules_path)
        # Verbose mode can be enabled via set_verbose_mode() method
        self.strategy_application_logger = StrategyApplicationLogger(verbose=False)

        # Initialize parent domain recommender (Task 8)
        self.parent_domain_recommender = ParentDomainRecommender(
            domain_rules_path, failure_threshold=3
        )

        # Initialize strategy failure tracker (Task 12)
        # Use revalidation_threshold parameter for auto-recovery integration
        self.strategy_failure_tracker = StrategyFailureTracker(
            domain_rules_path,
            failure_threshold=3,
            revalidation_threshold=revalidation_threshold,
        )

        # Auto-recovery callback (Task 16.1 - integration with monitoring)
        self._auto_recovery_callback = auto_recovery_callback

        # Conflict tracking data structures (Requirement 4.4)
        self.conflict_history = []  # List of conflict events for debugging
        self.conflict_count = 0  # Total number of conflicts detected

        # Determine if IP resolution should be enabled
        if enable_ip_resolution is None:
            try:
                enable_ip_resolution = is_runtime_ip_resolution_enabled()
                logger.info(
                    "Runtime IP resolution feature flag: %s",
                    "enabled" if enable_ip_resolution else "disabled",
                )
            except Exception as e:
                logger.warning(
                    "Failed to check runtime IP resolution feature flag: %s, defaulting to enabled",
                    e,
                )
                enable_ip_resolution = True

        # Initialize IP resolver if enabled
        self.ip_resolver = RuntimeIPResolver() if enable_ip_resolution else None
        self._ip_resolution_enabled = bool(enable_ip_resolution)

        logger.info(
            f"DomainStrategyEngine initialized with {len(domain_rules)} domain rules, "
            f"IP resolution: {'enabled' if enable_ip_resolution else 'disabled'}"
        )

    def get_strategy_for_packet(self, packet) -> StrategyResult:
        """
        Extract domain from packet and return appropriate strategy with domain info.

        Enhanced logic with payload-domain priority:
        1. Extract domain from TLS SNI / HTTP Host (highest priority)
        2. Only attempt IP resolution if payload-domain extraction fails
        3. Optionally detect conflicts against cached IP→domain (without doing reverse DNS)
        4. Match domain to strategy using hierarchical matching
        5. Return strategy + domain info for enhanced logging

        Args:
            packet: The network packet to process (pydivert.Packet or similar)

        Returns:
            StrategyResult with strategy config and domain information
        """
        ip_address = None
        dst_port = None
        try:
            ip_address = getattr(packet, "dst_addr", None) or getattr(packet, "dst", None)
            dst_port = getattr(packet, "dst_port", None) or getattr(packet, "dport", None)
        except Exception:
            ip_address = None
            dst_port = None

        ip_address_str = str(ip_address) if ip_address is not None else "unknown"
        dst_port_str = str(dst_port) if dst_port is not None else "unknown"

        source = "unknown"
        matched_rule = None

        try:
            # Step 1: Extract domain from payload (TLS SNI / HTTP Host)
            logger.debug("🔍 Packet to %s:%s - extracting domain...", ip_address_str, dst_port_str)

            payload_obj = getattr(packet, "payload", None)
            payload_bytes: Optional[bytes]
            if payload_obj is None:
                payload_bytes = None
            else:
                # pydivert often provides memoryview; accept any bytes-like safely.
                try:
                    payload_bytes = bytes(payload_obj)
                except Exception:
                    payload_bytes = None

            extracted = self.domain_extractor.extract_from_payload(payload_bytes)

            sni_domain = extracted.domain if extracted.source == "tls_sni" else None
            http_domain = extracted.domain if extracted.source == "http_host" else None

            if extracted.domain:
                logger.info("✅ Domain extracted (%s): %s", extracted.source, extracted.domain)

            # Step 2: Only attempt IP resolution if payload-domain extraction fails
            ip_domain = None
            ip_domain_from_cache = False
            if not extracted.domain and self.ip_resolver is not None and ip_address is not None:
                logger.info("⚠️ No domain in payload, performing reverse DNS lookup...")

                cached_domain = self.ip_resolver.get_cached_domain(ip_address_str)
                if cached_domain:
                    ip_domain = cached_domain
                    ip_domain_from_cache = True
                    logger.debug("✅ Cache hit: %s → %s", ip_address_str, ip_domain)
                else:
                    resolved_domain = self.ip_resolver.resolve_ip_to_domain(ip_address_str)
                    if resolved_domain:
                        ip_domain = resolved_domain
                        logger.info("✅ Resolved %s → %s", ip_address_str, ip_domain)
                    else:
                        logger.warning("❌ Reverse DNS lookup failed for %s", ip_address_str)
            elif not extracted.domain:
                logger.debug("IP resolution disabled or IP unknown; no domain available")

            # Step 3: final domain priority: payload-domain (tls_sni/http_host) > ip_domain
            final_domain = (sni_domain or http_domain) or ip_domain

            # Step 4: source labeling
            if sni_domain:
                source = "sni"
            elif http_domain:
                source = "http_host"
            elif ip_domain:
                # Determine if IP domain came from cache or reverse DNS
                if ip_domain_from_cache:
                    source = "cache"
                else:
                    source = "reverse_dns"

            # Step 5: conflict detection (cache-only, no reverse DNS when payload-domain exists)
            conflict_detected = False
            if (
                final_domain
                and extracted.domain
                and self.ip_resolver is not None
                and ip_address is not None
            ):
                cached = self.ip_resolver.get_cached_domain(ip_address_str)
                if cached and cached != final_domain:
                    self._log_domain_conflict(final_domain, cached, ip_address_str)
                    conflict_detected = True

            # Step 6: Match domain to strategy
            if final_domain:
                strategy, matched_rule, match_type = self.domain_matcher.find_matching_rule(
                    final_domain
                )

                if strategy is None:
                    strategy = self.default_strategy
                    match_type = "none"

                # Step 7: Validate strategy if matched_rule present
                if matched_rule:
                    validation_result = self.strategy_validator.validate_strategy_application(
                        domain=final_domain,
                        applied_strategy=strategy,
                        match_type=match_type,
                    )

                    self.strategy_application_logger.log_strategy_application(
                        domain=final_domain,
                        sni=sni_domain or final_domain,
                        matched_rule=matched_rule,
                        match_type=match_type,
                        strategy=strategy,
                        validation_result=validation_result,
                    )

                    if not validation_result.valid:
                        logger.error(f"❌ Strategy validation failed for {final_domain}")
                        logger.error(f"Reason: {validation_result.reason}")

                        # Optional parent domain fallback on validation failure (Task 4)
                        if match_type == "exact":
                            logger.warning("Attempting parent domain fallback...")
                            parent_strategy, parent_rule, parent_match_type = (
                                self._try_parent_domain_fallback(final_domain)
                            )

                            if parent_strategy and parent_rule:
                                logger.warning(f"✅ Using parent domain strategy: {parent_rule}")
                                strategy = parent_strategy
                                matched_rule = parent_rule
                                match_type = parent_match_type
                            else:
                                logger.warning(
                                    "⚠️ No parent domain fallback available, using strategy despite validation failure"
                                )
                        else:
                            logger.warning("⚠️ Using strategy despite validation failure")
                else:
                    logger.debug(f"📋 Using default strategy for domain: {final_domain}")
            else:
                logger.warning("⚠️ No domain found for packet, applying default strategy")
                strategy = self.default_strategy
                matched_rule = None
                match_type = "none"

            result = StrategyResult(
                strategy=strategy,
                domain=final_domain,
                source=source,
                ip_address=f"{ip_address_str}:{dst_port_str}",
                matched_rule=matched_rule,
                conflict_detected=conflict_detected,
                sni_domain=sni_domain,
                ip_domain=ip_domain,
            )

            # Log domain discovery for new IPs
            if source == "reverse_dns" and final_domain:
                logger.info("🆕 NEW IP discovered: %s → %s", ip_address_str, final_domain)
                if matched_rule:
                    logger.info("💾 Cached IP-to-domain mapping (TTL: 300s)")

            return result

        except Exception as e:
            logger.error("Error processing packet for domain extraction: %s", e)
            return StrategyResult(
                strategy=self.default_strategy,
                domain=None,
                source="unknown",
                ip_address=f"{ip_address_str}:{dst_port_str}",
                matched_rule=None,
                conflict_detected=False,
                sni_domain=None,
                ip_domain=None,
            )

    def get_strategy_for_domain(self, domain: str) -> Dict[str, Any]:
        """
        Get strategy for domain using hierarchical domain matching.

        Args:
            domain: The domain name to find a strategy for

        Returns:
            Strategy configuration dictionary (never None, falls back to default)
        """
        if not domain:
            return self.default_strategy

        try:
            strategy, matched_rule, match_type = self.domain_matcher.find_matching_rule(domain)

            if strategy is not None:
                logger.debug(
                    f"Found strategy for domain '{domain}': {strategy.get('type', 'unknown')} "
                    f"(match_type: {match_type})"
                )
                return strategy

            logger.debug(f"No rule found for domain '{domain}', using default strategy")
            return self.default_strategy

        except Exception as e:
            logger.error(f"Error finding strategy for domain '{domain}': {e}")
            return self.default_strategy

    def _find_matched_rule(self, domain: str) -> Optional[str]:
        """
        Find which domain rule was matched for the given domain.

        Args:
            domain: The domain name to find a matching rule for

        Returns:
            The matched domain rule key, or None if using default strategy
        """
        if not domain:
            return None

        try:
            _, matched_rule, _match_type = self.domain_matcher.find_matching_rule(domain)
            return matched_rule
        except Exception as e:
            logger.error(f"Error finding matched rule for domain '{domain}': {e}")
            return None

    def _try_parent_domain_fallback(self, domain: str) -> tuple:
        """
        Try to find a parent domain strategy when validation fails.

        Args:
            domain: The domain to find a parent strategy for

        Returns:
            Tuple of (strategy, matched_rule, match_type) or (None, None, 'none')
        """
        try:
            parent_domains = self.domain_matcher.get_parent_domains(domain)

            for parent_domain in parent_domains[1:]:
                strategy, matched_rule, match_type = self.domain_matcher.find_matching_rule(
                    parent_domain, strict=False
                )

                if strategy and matched_rule:
                    validation_result = self.strategy_validator.validate_strategy_application(
                        domain=parent_domain,
                        applied_strategy=strategy,
                        match_type=match_type,
                    )

                    if validation_result.valid:
                        logger.info(f"✅ Found valid parent domain strategy: {matched_rule}")
                        return (strategy, matched_rule, "parent")

            return (None, None, "none")

        except Exception as e:
            logger.error(f"Error trying parent domain fallback for '{domain}': {e}")
            return (None, None, "none")

    def reload_configuration(
        self, domain_rules: Dict[str, Dict[str, Any]], default_strategy: Dict[str, Any]
    ):
        """
        Reload the domain rules configuration.

        Args:
            domain_rules: New dictionary mapping domains to strategy configurations
            default_strategy: New default strategy configuration
        """
        self.domain_rules = domain_rules
        self.default_strategy = default_strategy
        self.domain_matcher = HierarchicalDomainMatcher(domain_rules, default_strategy)

        self.strategy_validator.reload_domain_rules()
        self.parent_domain_recommender.reload_domain_rules()
        self.strategy_failure_tracker._load_failure_data()

        logger.info(
            f"DomainStrategyEngine configuration reloaded with {len(domain_rules)} domain rules"
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics for monitoring and debugging.

        Returns:
            Dictionary containing engine statistics including conflict tracking data
        """
        stats = {
            "total_domain_rules": len(self.domain_rules),
            "default_strategy_type": self.default_strategy.get("type", "unknown"),
            "ip_resolution_enabled": self._ip_resolution_enabled,
            "cache_stats": (
                self.domain_matcher.get_cache_statistics()
                if hasattr(self.domain_matcher, "get_cache_statistics")
                else {}
            ),
        }

        if self.ip_resolver is not None:
            stats["ip_resolver_stats"] = self.ip_resolver.get_statistics()

        stats["conflict_stats"] = {
            "total_conflicts": self.conflict_count,
            "recent_conflicts": self.conflict_history[-10:] if self.conflict_history else [],
            "conflict_rate": self._calculate_conflict_rate(),
        }

        return stats

    def _calculate_conflict_rate(self) -> float:
        """
        Calculate the conflict rate (conflicts per minute) based on recent history.

        Returns:
            Conflicts per minute, or 0.0 if insufficient data
        """
        try:
            if not self.conflict_history:
                return 0.0

            import time

            current_time = time.time()
            oldest_conflict_time = self.conflict_history[0]["timestamp"]
            time_range_seconds = current_time - oldest_conflict_time

            if time_range_seconds <= 0:
                return 0.0

            conflicts_in_history = len(self.conflict_history)
            time_range_minutes = time_range_seconds / 60.0
            conflict_rate = conflicts_in_history / time_range_minutes

            return round(conflict_rate, 2)

        except Exception as e:
            logger.error(f"Error calculating conflict rate: {e}")
            return 0.0

    def get_conflict_statistics(self) -> Dict[str, Any]:
        """
        Get detailed conflict statistics for monitoring and debugging.
        """
        return {
            "total_conflicts": self.conflict_count,
            "recent_conflicts": self.conflict_history[-10:] if self.conflict_history else [],
            "conflict_rate": self._calculate_conflict_rate(),
        }

    def enable_ip_resolution(self) -> bool:
        """
        Enable runtime IP-to-domain resolution.

        Returns:
            True if IP resolution was enabled successfully
        """
        if self._ip_resolution_enabled and self.ip_resolver is not None:
            logger.info("Runtime IP resolution is already enabled")
            return True

        try:
            self.ip_resolver = RuntimeIPResolver()
            self._ip_resolution_enabled = True
            logger.info("✅ Runtime IP resolution enabled")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to enable runtime IP resolution: {e}")
            return False

    def disable_ip_resolution(self) -> bool:
        """
        Disable runtime IP-to-domain resolution and fall back to SNI/Host-only.

        Returns:
            True if IP resolution was disabled successfully
        """
        if not self._ip_resolution_enabled:
            logger.info("Runtime IP resolution is already disabled")
            return True

        try:
            self.ip_resolver = None
            self._ip_resolution_enabled = False
            logger.warning(
                "🔄 Runtime IP resolution disabled, falling back to SNI/Host-only domain extraction"
            )
            logger.info("   Packets without TLS SNI / HTTP Host will use default strategy")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to disable runtime IP resolution: {e}")
            return False

    def is_ip_resolution_enabled(self) -> bool:
        """
        Check if runtime IP resolution is currently enabled.
        """
        return self._ip_resolution_enabled

    def _log_domain_conflict(self, sni_domain: str, ip_domain: str, ip_address: str):
        """
        Log and record a domain conflict when payload-domain and cached IP-domain differ.
        """
        try:
            logger.warning(
                "⚠️ Domain conflict detected: payload=%s, cached_ip_domain=%s, IP=%s. Using payload domain for strategy selection.",
                sni_domain,
                ip_domain,
                ip_address,
            )

            conflict_info = {
                "timestamp": time.time(),
                "sni_domain": sni_domain,
                "ip_domain": ip_domain,
                "ip_address": ip_address,
            }
            self._record_conflict(conflict_info)

        except Exception as e:
            logger.error("Error logging domain conflict: %s", e)

    def _record_conflict(self, conflict_info: Dict[str, Any]):
        """
        Record a conflict in the conflict history with FIFO logic.
        """
        try:
            self.conflict_count += 1
            self.conflict_history.append(conflict_info)

            if len(self.conflict_history) > 100:
                self.conflict_history.pop(0)

        except Exception as e:
            logger.error(f"Error recording conflict: {e}")

    def record_strategy_failure(
        self,
        domain: str,
        strategy: Dict[str, Any],
        retransmissions: int,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Record a strategy failure and check if revalidation is needed.

        Returns:
            True if revalidation is recommended, False otherwise
        """
        try:
            needs_revalidation = self.strategy_failure_tracker.record_failure(
                domain=domain,
                strategy=strategy,
                retransmissions=retransmissions,
                reason=reason,
            )

            self.strategy_application_logger.log_strategy_failure(
                domain=domain,
                strategy=strategy,
                retransmissions=retransmissions,
                reason=reason,
            )

            if needs_revalidation and self._auto_recovery_callback:
                try:
                    logger.info(f"🔧 Triggering auto-recovery callback for {domain}")
                    self._auto_recovery_callback(domain, strategy, retransmissions)
                except Exception as callback_error:
                    logger.error(f"Auto-recovery callback failed: {callback_error}")

            return needs_revalidation

        except Exception as e:
            logger.error(f"Error recording strategy failure: {e}")
            return False

    def get_domains_needing_revalidation(self) -> List[str]:
        """
        Get list of domains that need revalidation.
        """
        return self.strategy_failure_tracker.get_domains_needing_revalidation()

    def reset_failure_count(self, domain: str):
        """
        Reset failure count for a domain (e.g., after successful revalidation).
        """
        self.strategy_failure_tracker.reset_failure_count(domain)

    def set_auto_recovery_callback(
        self, callback: Optional[Callable[[str, Dict[str, Any], int], None]]
    ):
        """
        Set callback for auto-recovery when strategy fails.
        """
        self._auto_recovery_callback = callback
        if callback:
            logger.info("✅ Auto-recovery callback registered")
        else:
            logger.info("ℹ️ Auto-recovery callback disabled")

    def update_strategy(
        self,
        domain: str,
        new_strategy: Dict[str, Any],
        metadata_updates: Optional[Dict[str, Any]] = None,
    ):
        """
        Update strategy in domain_rules.json and reset failure count.
        """
        self.strategy_failure_tracker.update_strategy_in_domain_rules(
            domain=domain,
            new_strategy=new_strategy,
            metadata_updates=metadata_updates,
        )

    def set_verbose_mode(self, enabled: bool, log_file: Optional[str] = None):
        """
        Enable or disable verbose strategy application logging.
        """
        try:
            from .strategy_application_logger import StrategyApplicationLogger

            self.strategy_application_logger = StrategyApplicationLogger(
                verbose=enabled,
                log_file=log_file,
            )

            logger.info(f"Verbose strategy logging {'enabled' if enabled else 'disabled'}")
            if log_file:
                logger.info(f"Verbose logs will be written to: {log_file}")

        except Exception as e:
            logger.error(f"Failed to set verbose mode: {e}")
