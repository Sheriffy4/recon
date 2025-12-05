"""
Domain Strategy Engine

This module implements the core domain-based strategy engine that replaces
IP-based strategy mapping with domain-based hierarchical matching.
"""

from typing import Dict, Any, Optional, Set, List
import logging
from .sni_domain_extractor import SNIDomainExtractor
from .hierarchical_domain_matcher import HierarchicalDomainMatcher
from .domain_rule_registry import DomainRuleRegistry
from .runtime_ip_resolver import RuntimeIPResolver
from .strategy_result import StrategyResult
from .strategy_validator import StrategyValidator
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
        domain_rules_path: str = "domain_rules.json"
    ):
        """
        Initialize the domain strategy engine.
        
        Args:
            domain_rules: Dictionary mapping domains to strategy configurations
            default_strategy: Default strategy to use when no domain rule matches
            enable_ip_resolution: Enable runtime IP-to-domain resolution. 
                                 If None, checks feature flag (default: None)
            domain_rules_path: Path to domain_rules.json for validation
        """
        self.domain_rules = domain_rules
        self.default_strategy = default_strategy
        self.sni_extractor = SNIDomainExtractor()
        self.domain_matcher = HierarchicalDomainMatcher(domain_rules, default_strategy)
        
        # Initialize strategy validator and application logger (Task 4)
        self.strategy_validator = StrategyValidator(domain_rules_path)
        # Verbose mode can be enabled via set_verbose_mode() method
        self.strategy_application_logger = StrategyApplicationLogger(verbose=False)
        
        # Initialize parent domain recommender (Task 8)
        self.parent_domain_recommender = ParentDomainRecommender(domain_rules_path, failure_threshold=3)
        
        # Initialize strategy failure tracker (Task 12)
        self.strategy_failure_tracker = StrategyFailureTracker(domain_rules_path, failure_threshold=3, revalidation_threshold=5)
        
        # Conflict tracking data structures (Requirement 4.4)
        self.conflict_history = []  # List of conflict events for debugging
        self.conflict_count = 0     # Total number of conflicts detected
        
        # Determine if IP resolution should be enabled
        if enable_ip_resolution is None:
            # Check feature flag
            try:
                enable_ip_resolution = is_runtime_ip_resolution_enabled()
                logger.info(f"Runtime IP resolution feature flag: {'enabled' if enable_ip_resolution else 'disabled'}")
            except Exception as e:
                logger.warning(f"Failed to check runtime IP resolution feature flag: {e}, defaulting to enabled")
                enable_ip_resolution = True
        
        # Initialize IP resolver if enabled
        self.ip_resolver = RuntimeIPResolver() if enable_ip_resolution else None
        self._ip_resolution_enabled = enable_ip_resolution
        
        logger.info(
            f"DomainStrategyEngine initialized with {len(domain_rules)} domain rules, "
            f"IP resolution: {'enabled' if enable_ip_resolution else 'disabled'}"
        )
    
    def get_strategy_for_packet(self, packet) -> StrategyResult:
        """
        Extract domain from packet and return appropriate strategy with domain info.
        
        Enhanced logic with SNI priority:
        1. Extract domain from TLS SNI (highest priority)
        2. Only attempt IP resolution if SNI extraction fails
        3. Detect conflicts when both SNI and IP domains exist and differ
        4. Match domain to strategy using hierarchical matching
        5. Return strategy + domain info for enhanced logging
        
        Args:
            packet: The network packet to process (pydivert.Packet or similar)
            
        Returns:
            StrategyResult with strategy config and domain information
        """
        ip_address = packet.dst_addr
        source = "unknown"
        matched_rule = None
        
        try:
            # Step 1: Extract SNI domain first and store separately (Requirement 1.1)
            logger.debug(f"🔍 Packet to {ip_address}:{packet.dst_port} - extracting domain...")
            sni_domain = self.sni_extractor.extract_domain_from_packet(packet)
            ip_domain = None
            
            if sni_domain:
                logger.info(f"✅ SNI extracted: {sni_domain}")
            
            # Step 2: Only attempt IP resolution if SNI extraction fails (Requirement 1.3)
            if not sni_domain and self.ip_resolver is not None:
                logger.info(f"⚠️ No SNI found, performing reverse DNS lookup...")
                
                # Check cache first
                cached_domain = self.ip_resolver.get_cached_domain(ip_address)
                if cached_domain:
                    ip_domain = cached_domain
                    logger.debug(f"✅ Cache hit: {ip_address} → {ip_domain}")
                else:
                    # Perform reverse DNS lookup
                    resolved_domain = self.ip_resolver.resolve_ip_to_domain(ip_address)
                    if resolved_domain:
                        ip_domain = resolved_domain
                        logger.info(f"✅ Resolved {ip_address} → {ip_domain}")
                    else:
                        logger.warning(f"❌ Reverse DNS lookup failed for {ip_address}")
            elif not sni_domain:
                logger.debug("IP resolution disabled, no domain available")
            
            # Step 3: Use SNI domain if available, fall back to IP domain (Requirement 1.2)
            final_domain = sni_domain or ip_domain
            
            # Set source correctly based on which method succeeded (Requirement 1.2)
            if sni_domain:
                source = "sni"
            elif ip_domain:
                # Determine if IP domain came from cache or reverse DNS
                if self.ip_resolver and self.ip_resolver.get_cached_domain(ip_address):
                    source = "cache"
                else:
                    source = "reverse_dns"
            
            # Step 4: Detect conflicts when both SNI and IP domains exist and differ (Requirement 1.4, 4.1)
            conflict_detected = False
            if sni_domain and ip_domain and sni_domain != ip_domain:
                self._log_domain_conflict(sni_domain, ip_domain, ip_address)
                conflict_detected = True
            
            # Step 5: Match domain to strategy using new matcher signature (Task 4)
            if final_domain:
                # Use hierarchical matcher with new signature that returns (strategy, matched_rule, match_type)
                strategy, matched_rule, match_type = self.domain_matcher.find_matching_rule(final_domain)
                
                # If no rule found, use default strategy
                if strategy is None:
                    strategy = self.default_strategy
                    match_type = 'none'
                
                # Step 6: Validate strategy before returning (Task 4)
                if matched_rule:
                    validation_result = self.strategy_validator.validate_strategy_application(
                        domain=final_domain,
                        applied_strategy=strategy,
                        match_type=match_type
                    )
                    
                    # Log strategy application with validation results (Task 4)
                    self.strategy_application_logger.log_strategy_application(
                        domain=final_domain,
                        sni=sni_domain or final_domain,
                        matched_rule=matched_rule,
                        match_type=match_type,
                        strategy=strategy,
                        validation_result=validation_result
                    )
                    
                    # Handle validation failures (Task 4)
                    if not validation_result.valid:
                        logger.error(f"❌ Strategy validation failed for {final_domain}")
                        logger.error(f"Reason: {validation_result.reason}")
                        
                        # Optional parent domain fallback on validation failure (Task 4)
                        if match_type == 'exact':
                            logger.warning(f"Attempting parent domain fallback...")
                            parent_strategy, parent_rule, parent_match_type = self._try_parent_domain_fallback(final_domain)
                            
                            if parent_strategy and parent_rule:
                                logger.warning(f"✅ Using parent domain strategy: {parent_rule}")
                                strategy = parent_strategy
                                matched_rule = parent_rule
                                match_type = parent_match_type
                            else:
                                logger.warning(f"⚠️ No parent domain fallback available, using validated strategy anyway")
                        else:
                            logger.warning(f"⚠️ Using strategy despite validation failure")
                else:
                    logger.debug(f"📋 Using default strategy for domain: {final_domain}")
            else:
                # No domain found, use default strategy
                logger.warning(f"⚠️ No domain found for packet, applying default strategy")
                strategy = self.default_strategy
                matched_rule = None
                match_type = 'none'
            
            # Step 6: Create and return StrategyResult (will be enhanced in subtask 3.4)
            result = StrategyResult(
                strategy=strategy,
                domain=final_domain,
                source=source,
                ip_address=f"{ip_address}:{packet.dst_port}",
                matched_rule=matched_rule,
                conflict_detected=conflict_detected,
                sni_domain=sni_domain,
                ip_domain=ip_domain
            )
            
            # Log domain discovery for new IPs
            if source == "reverse_dns":
                logger.info(f"🆕 NEW IP discovered: {ip_address} → {final_domain}")
                if matched_rule:
                    logger.info(f"💾 Cached IP-to-domain mapping (TTL: 300s)")
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing packet for domain extraction: {e}")
            # Return default strategy on error
            return StrategyResult(
                strategy=self.default_strategy,
                domain=None,
                source="unknown",
                ip_address=f"{ip_address}:{packet.dst_port}",
                matched_rule=None,
                conflict_detected=False,
                sni_domain=None,
                ip_domain=None
            )
    
    def get_strategy_for_domain(self, domain: str) -> Dict[str, Any]:
        """
        Get strategy for domain using hierarchical domain matching.
        
        This method uses the hierarchical domain matcher to find the most specific
        rule that applies to the given domain, walking up the domain hierarchy
        if necessary.
        
        Args:
            domain: The domain name to find a strategy for
            
        Returns:
            Strategy configuration dictionary (never None, falls back to default)
        """
        if not domain:
            return self.default_strategy
        
        try:
            # Use hierarchical matching to find the best rule
            strategy, matched_rule, match_type = self.domain_matcher.find_matching_rule(domain)
            
            if strategy is not None:
                logger.debug(f"Found strategy for domain '{domain}': {strategy.get('type', 'unknown')} (match_type: {match_type})")
                return strategy
            
            # No rule found, use default
            logger.debug(f"No rule found for domain '{domain}', using default strategy")
            return self.default_strategy
            
        except Exception as e:
            logger.error(f"Error finding strategy for domain '{domain}': {e}")
            return self.default_strategy
    
    def _find_matched_rule(self, domain: str) -> Optional[str]:
        """
        Find which domain rule was matched for the given domain.
        
        This is used for logging and debugging purposes to show which
        rule in domain_rules.json was applied.
        
        Args:
            domain: The domain name to find a matching rule for
            
        Returns:
            The matched domain rule key, or None if using default strategy
        """
        if not domain:
            return None
        
        try:
            # Use the hierarchical matcher to get the matched rule name
            _, matched_rule, match_type = self.domain_matcher.find_matching_rule(domain)
            return matched_rule
        except Exception as e:
            logger.error(f"Error finding matched rule for domain '{domain}': {e}")
            return None
    
    def _try_parent_domain_fallback(self, domain: str) -> tuple:
        """
        Try to find a parent domain strategy when validation fails.
        
        This method attempts to find a working strategy by checking parent domains
        when the exact match strategy fails validation.
        
        Args:
            domain: The domain to find a parent strategy for
            
        Returns:
            Tuple of (strategy, matched_rule, match_type) or (None, None, 'none')
        """
        try:
            # Get parent domains
            parent_domains = self.domain_matcher.get_parent_domains(domain)
            
            # Skip the first domain (already tried as exact match)
            for parent_domain in parent_domains[1:]:
                # Try to find a rule for this parent domain
                strategy, matched_rule, match_type = self.domain_matcher.find_matching_rule(parent_domain, strict=False)
                
                if strategy and matched_rule:
                    # Validate the parent domain strategy
                    validation_result = self.strategy_validator.validate_strategy_application(
                        domain=parent_domain,
                        applied_strategy=strategy,
                        match_type=match_type
                    )
                    
                    if validation_result.valid:
                        logger.info(f"✅ Found valid parent domain strategy: {matched_rule}")
                        return (strategy, matched_rule, 'parent')
            
            # No valid parent domain strategy found
            return (None, None, 'none')
            
        except Exception as e:
            logger.error(f"Error trying parent domain fallback for '{domain}': {e}")
            return (None, None, 'none')
    
    def reload_configuration(self, domain_rules: Dict[str, Dict[str, Any]], default_strategy: Dict[str, Any]):
        """
        Reload the domain rules configuration.
        
        Args:
            domain_rules: New dictionary mapping domains to strategy configurations
            default_strategy: New default strategy configuration
        """
        self.domain_rules = domain_rules
        self.default_strategy = default_strategy
        self.domain_matcher = HierarchicalDomainMatcher(domain_rules, default_strategy)
        
        # Reload validator with updated rules (Task 4)
        self.strategy_validator.reload_domain_rules()
        
        # Reload parent domain recommender (Task 8)
        self.parent_domain_recommender.reload_domain_rules()
        
        # Reload failure tracker (Task 12)
        self.strategy_failure_tracker._load_failure_data()
        
        logger.info(f"DomainStrategyEngine configuration reloaded with {len(domain_rules)} domain rules")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics for monitoring and debugging.
        
        Returns:
            Dictionary containing engine statistics including conflict tracking data
            
        Requirements: 4.3
        """
        stats = {
            "total_domain_rules": len(self.domain_rules),
            "default_strategy_type": self.default_strategy.get("type", "unknown"),
            "ip_resolution_enabled": self._ip_resolution_enabled,
            "cache_stats": self.domain_matcher.get_cache_statistics() if hasattr(self.domain_matcher, 'get_cache_statistics') else {}
        }
        
        # Add IP resolver statistics if enabled
        if self.ip_resolver is not None:
            stats["ip_resolver_stats"] = self.ip_resolver.get_statistics()
        
        # Add conflict statistics (Requirement 4.3)
        stats["conflict_stats"] = {
            "total_conflicts": self.conflict_count,
            "recent_conflicts": self.conflict_history[-10:] if self.conflict_history else [],  # Last 10 conflicts
            "conflict_rate": self._calculate_conflict_rate()
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
            
            # Get time range of conflicts in history
            import time
            current_time = time.time()
            oldest_conflict_time = self.conflict_history[0]["timestamp"]
            time_range_seconds = current_time - oldest_conflict_time
            
            # Avoid division by zero
            if time_range_seconds <= 0:
                return 0.0
            
            # Calculate rate: conflicts per minute
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
        
        Returns:
            Dictionary containing:
            - total_conflicts: Total number of conflicts detected
            - recent_conflicts: List of recent conflict events (last 10)
            - conflict_rate: Conflicts per minute
            
        Requirements: 4.3
        """
        return {
            "total_conflicts": self.conflict_count,
            "recent_conflicts": self.conflict_history[-10:] if self.conflict_history else [],
            "conflict_rate": self._calculate_conflict_rate()
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
        Disable runtime IP-to-domain resolution and fall back to legacy IP-based strategy selection.
        
        When disabled, the engine will only use SNI extraction for domain discovery.
        If SNI extraction fails, it will fall back to the default strategy.
        
        Returns:
            True if IP resolution was disabled successfully
        """
        if not self._ip_resolution_enabled:
            logger.info("Runtime IP resolution is already disabled")
            return True
        
        try:
            self.ip_resolver = None
            self._ip_resolution_enabled = False
            logger.warning("🔄 Runtime IP resolution disabled, falling back to SNI-only domain extraction")
            logger.info("   Packets without SNI will use default strategy")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to disable runtime IP resolution: {e}")
            return False
    
    def is_ip_resolution_enabled(self) -> bool:
        """
        Check if runtime IP resolution is currently enabled.
        
        Returns:
            True if IP resolution is enabled, False otherwise
        """
        return self._ip_resolution_enabled
    
    def _log_domain_conflict(self, sni_domain: str, ip_domain: str, ip_address: str):
        """
        Log and record a domain conflict when SNI and IP domains differ.
        
        This method is called when both SNI extraction and IP resolution succeed
        but return different domains, indicating a potential configuration issue
        or shared IP scenario (e.g., CDN).
        
        Args:
            sni_domain: Domain extracted from TLS SNI
            ip_domain: Domain resolved from IP address
            ip_address: The IP address in question
            
        Requirements: 4.1, 4.4, 4.5
        """
        try:
            # Log warning message (Requirement 4.1)
            logger.warning(
                f"⚠️ Domain conflict detected: SNI={sni_domain}, IP-resolved={ip_domain}, "
                f"IP={ip_address}. Using SNI domain for strategy selection."
            )
            
            # Record conflict in history (Requirement 4.4)
            conflict_info = {
                "timestamp": __import__("time").time(),
                "sni_domain": sni_domain,
                "ip_domain": ip_domain,
                "ip_address": ip_address
            }
            self._record_conflict(conflict_info)
            
        except Exception as e:
            # Never block packet processing due to conflict tracking errors
            logger.error(f"Error logging domain conflict: {e}")
    
    def _record_conflict(self, conflict_info: Dict[str, Any]):
        """
        Record a conflict in the conflict history with FIFO logic.
        
        Maintains a maximum of 100 conflict entries. When the limit is reached,
        the oldest conflict is removed (FIFO - First In, First Out).
        
        Args:
            conflict_info: Dictionary containing conflict details
            
        Requirements: 4.4, 4.5
        """
        try:
            # Increment total conflict counter
            self.conflict_count += 1
            
            # Add to history
            self.conflict_history.append(conflict_info)
            
            # Maintain max 100 entries (FIFO) (Requirement 4.5)
            if len(self.conflict_history) > 100:
                self.conflict_history.pop(0)  # Remove oldest entry
                
        except Exception as e:
            # Log error but don't raise - conflict tracking is non-critical
            logger.error(f"Error recording conflict: {e}")
    
    def record_strategy_failure(
        self,
        domain: str,
        strategy: Dict[str, Any],
        retransmissions: int,
        reason: Optional[str] = None
    ) -> bool:
        """
        Record a strategy failure and check if revalidation is needed.
        
        Args:
            domain: Domain that failed
            strategy: Strategy that was applied
            retransmissions: Number of retransmissions detected
            reason: Optional reason for failure
        
        Returns:
            True if revalidation is recommended, False otherwise
        
        Requirements: 8.1, 8.2
        """
        try:
            needs_revalidation = self.strategy_failure_tracker.record_failure(
                domain=domain,
                strategy=strategy,
                retransmissions=retransmissions,
                reason=reason
            )
            
            # Log failure with application logger
            self.strategy_application_logger.log_strategy_failure(
                domain=domain,
                strategy=strategy,
                retransmissions=retransmissions,
                reason=reason
            )
            
            return needs_revalidation
            
        except Exception as e:
            logger.error(f"Error recording strategy failure: {e}")
            return False
    
    def get_domains_needing_revalidation(self) -> List[str]:
        """
        Get list of domains that need revalidation.
        
        Returns:
            List of domain names that need revalidation
        
        Requirements: 8.2
        """
        return self.strategy_failure_tracker.get_domains_needing_revalidation()
    
    def reset_failure_count(self, domain: str):
        """
        Reset failure count for a domain (e.g., after successful revalidation).
        
        Args:
            domain: Domain to reset
        
        Requirements: 8.4
        """
        self.strategy_failure_tracker.reset_failure_count(domain)
    
    def update_strategy(
        self,
        domain: str,
        new_strategy: Dict[str, Any],
        metadata_updates: Optional[Dict[str, Any]] = None
    ):
        """
        Update strategy in domain_rules.json and reset failure count.
        
        Args:
            domain: Domain to update
            new_strategy: New strategy configuration
            metadata_updates: Optional metadata updates
        
        Requirements: 8.5
        """
        self.strategy_failure_tracker.update_strategy_in_domain_rules(
            domain=domain,
            new_strategy=new_strategy,
            metadata_updates=metadata_updates
        )
    
    def set_verbose_mode(self, enabled: bool, log_file: Optional[str] = None):
        """
        Enable or disable verbose strategy application logging.
        
        Args:
            enabled: Whether to enable verbose mode
            log_file: Optional file to write verbose logs to
        
        Requirements: 7.1, 7.3, 7.4, 7.5
        """
        try:
            from .strategy_application_logger import StrategyApplicationLogger
            
            # Recreate logger with new settings
            self.strategy_application_logger = StrategyApplicationLogger(
                verbose=enabled,
                log_file=log_file
            )
            
            logger.info(f"Verbose strategy logging {'enabled' if enabled else 'disabled'}")
            if log_file:
                logger.info(f"Verbose logs will be written to: {log_file}")
                
        except Exception as e:
            logger.error(f"Failed to set verbose mode: {e}")