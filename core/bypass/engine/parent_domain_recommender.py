#!/usr/bin/env python3
"""
Parent Domain Strategy Recommender

Provides recommendations for using parent domain strategies when subdomain
strategies fail, helping simplify configuration and improve reliability.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

import logging
import json
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

LOG = logging.getLogger(__name__)


class ParentDomainRecommendation:
    """Data class for parent domain recommendations."""
    
    def __init__(
        self,
        subdomain: str,
        parent_domain: str,
        subdomain_strategy: Dict[str, Any],
        parent_strategy: Optional[Dict[str, Any]],
        failure_count: int,
        recommendation_type: str,
        reason: str
    ):
        self.subdomain = subdomain
        self.parent_domain = parent_domain
        self.subdomain_strategy = subdomain_strategy
        self.parent_strategy = parent_strategy
        self.failure_count = failure_count
        self.recommendation_type = recommendation_type  # 'remove_subdomain', 'use_parent', 'test_parent'
        self.reason = reason


class ParentDomainRecommender:
    """
    Recommends using parent domain strategies when subdomain strategies fail.
    
    This component tracks strategy failures and provides intelligent recommendations
    for simplifying domain rules by using parent domain strategies instead of
    subdomain-specific strategies.
    """
    
    def __init__(self, domain_rules_path: str = "domain_rules.json", failure_threshold: int = 3):
        """
        Initialize the Parent Domain Recommender.
        
        Args:
            domain_rules_path: Path to domain_rules.json file
            failure_threshold: Number of failures before recommending parent domain
        """
        self.domain_rules_path = domain_rules_path
        self.failure_threshold = failure_threshold
        self.domain_rules = self._load_domain_rules()
        
        # Track recommendations that have been made
        self.recommendations_made = {}  # domain -> recommendation
        
        LOG.debug(f"ParentDomainRecommender initialized with threshold={failure_threshold}")
    
    def _load_domain_rules(self) -> Dict[str, Any]:
        """Load domain rules from JSON file."""
        try:
            if Path(self.domain_rules_path).exists():
                with open(self.domain_rules_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('domain_rules', {})
            return {}
        except Exception as e:
            LOG.error(f"Error loading domain rules: {e}")
            return {}
    
    def reload_domain_rules(self):
        """Reload domain rules from file."""
        self.domain_rules = self._load_domain_rules()
        LOG.debug(f"Domain rules reloaded: {len(self.domain_rules)} rules")
    
    def get_parent_domain(self, domain: str) -> Optional[str]:
        """
        Get parent domain for a given domain.
        
        Args:
            domain: Domain to get parent for (e.g., "www.youtube.com")
            
        Returns:
            Parent domain (e.g., "youtube.com") or None if no parent
        """
        if not domain or '.' not in domain:
            return None
        
        parts = domain.split('.')
        if len(parts) <= 2:
            # Already at top level (e.g., "youtube.com")
            return None
        
        # Return parent domain
        return '.'.join(parts[1:])
    
    def check_parent_domain_exists(self, domain: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Check if parent domain strategy exists in domain_rules.json.
        
        Args:
            domain: Subdomain to check (e.g., "www.youtube.com")
            
        Returns:
            Tuple of (exists, parent_domain, parent_strategy)
            
        Requirements: 10.3
        """
        parent_domain = self.get_parent_domain(domain)
        
        if not parent_domain:
            return False, None, None
        
        # Check if parent domain has a strategy
        if parent_domain in self.domain_rules:
            parent_strategy = self.domain_rules[parent_domain]
            LOG.debug(f"Parent domain '{parent_domain}' exists for '{domain}'")
            return True, parent_domain, parent_strategy
        
        # Also check for wildcard pattern
        wildcard_pattern = f"*.{parent_domain}"
        if wildcard_pattern in self.domain_rules:
            wildcard_strategy = self.domain_rules[wildcard_pattern]
            LOG.debug(f"Wildcard parent '{wildcard_pattern}' exists for '{domain}'")
            return True, wildcard_pattern, wildcard_strategy
        
        return False, parent_domain, None
    
    def should_recommend_parent_domain(
        self,
        domain: str,
        failure_count: int
    ) -> Tuple[bool, Optional[ParentDomainRecommendation]]:
        """
        Determine if parent domain strategy should be recommended.
        
        Args:
            domain: Domain that is failing
            failure_count: Number of failures for this domain
            
        Returns:
            Tuple of (should_recommend, recommendation)
            
        Requirements: 10.1, 10.4
        """
        # Check if we've already made a recommendation for this domain
        if domain in self.recommendations_made:
            LOG.debug(f"Recommendation already made for '{domain}'")
            return False, None
        
        # Check if failure count meets threshold (Requirement 10.4)
        if failure_count < self.failure_threshold:
            LOG.debug(f"Failure count {failure_count} below threshold {self.failure_threshold}")
            return False, None
        
        # Check if domain has a subdomain
        parent_domain = self.get_parent_domain(domain)
        if not parent_domain:
            LOG.debug(f"Domain '{domain}' has no parent domain")
            return False, None
        
        # Check if subdomain strategy exists
        if domain not in self.domain_rules:
            LOG.debug(f"No strategy found for '{domain}'")
            return False, None
        
        subdomain_strategy = self.domain_rules[domain]
        
        # Check if parent domain strategy exists (Requirement 10.1)
        parent_exists, parent_key, parent_strategy = self.check_parent_domain_exists(domain)
        
        if parent_exists and parent_strategy:
            # Parent domain strategy exists - recommend removing subdomain strategy
            recommendation = ParentDomainRecommendation(
                subdomain=domain,
                parent_domain=parent_key,
                subdomain_strategy=subdomain_strategy,
                parent_strategy=parent_strategy,
                failure_count=failure_count,
                recommendation_type='remove_subdomain',
                reason=f"Subdomain strategy failing ({failure_count} retransmissions), parent domain '{parent_key}' strategy available"
            )
            
            LOG.info(f"✅ Recommendation generated: Remove '{domain}' to use parent '{parent_key}'")
            return True, recommendation
        else:
            # Parent domain strategy doesn't exist - recommend testing parent domain
            recommendation = ParentDomainRecommendation(
                subdomain=domain,
                parent_domain=parent_domain,
                subdomain_strategy=subdomain_strategy,
                parent_strategy=None,
                failure_count=failure_count,
                recommendation_type='test_parent',
                reason=f"Subdomain strategy failing ({failure_count} retransmissions), consider testing parent domain '{parent_domain}'"
            )
            
            LOG.info(f"✅ Recommendation generated: Test parent domain '{parent_domain}'")
            return True, recommendation
    
    def log_recommendation(self, recommendation: ParentDomainRecommendation):
        """
        Log a parent domain recommendation.
        
        Args:
            recommendation: The recommendation to log
            
        Requirements: 10.1, 10.2
        """
        LOG.warning("=" * 80)
        LOG.warning("PARENT DOMAIN STRATEGY RECOMMENDATION")
        LOG.warning("=" * 80)
        LOG.warning(f"Subdomain: {recommendation.subdomain}")
        LOG.warning(f"Parent Domain: {recommendation.parent_domain}")
        LOG.warning(f"Failure Count: {recommendation.failure_count}")
        LOG.warning(f"Reason: {recommendation.reason}")
        LOG.warning("")
        
        if recommendation.recommendation_type == 'remove_subdomain':
            # Recommend removing subdomain strategy (Requirement 10.2)
            LOG.warning(f"💡 RECOMMENDATION: Remove subdomain strategy")
            LOG.warning(f"   The parent domain '{recommendation.parent_domain}' has a working strategy.")
            LOG.warning(f"   Removing the subdomain strategy will simplify configuration and may improve reliability.")
            LOG.warning("")
            LOG.warning(f"   To apply this recommendation:")
            LOG.warning(f"   1. Edit {self.domain_rules_path}")
            LOG.warning(f"   2. Remove the entry for '{recommendation.subdomain}'")
            LOG.warning(f"   3. Restart the bypass service")
            LOG.warning("")
            LOG.warning(f"   Parent domain strategy details:")
            LOG.warning(f"   - Type: {recommendation.parent_strategy.get('type', 'unknown')}")
            LOG.warning(f"   - Params: {recommendation.parent_strategy.get('params', {})}")
            
        elif recommendation.recommendation_type == 'test_parent':
            # Recommend testing parent domain (Requirement 10.3)
            LOG.warning(f"💡 RECOMMENDATION: Test parent domain strategy")
            LOG.warning(f"   The subdomain '{recommendation.subdomain}' strategy is failing.")
            LOG.warning(f"   Consider testing the parent domain '{recommendation.parent_domain}' to find a working strategy.")
            LOG.warning("")
            LOG.warning(f"   To apply this recommendation:")
            LOG.warning(f"   1. Run: cli.py auto {recommendation.parent_domain}")
            LOG.warning(f"   2. If successful, remove the entry for '{recommendation.subdomain}' from {self.domain_rules_path}")
            LOG.warning(f"   3. Restart the bypass service")
        
        LOG.warning("=" * 80)
        
        # Mark recommendation as made
        self.recommendations_made[recommendation.subdomain] = recommendation
    
    def detect_and_recommend(
        self,
        domain: str,
        failure_count: int,
        strategy: Dict[str, Any]
    ) -> Optional[ParentDomainRecommendation]:
        """
        Detect if parent domain recommendation should be made and log it.
        
        This is the main entry point for the recommendation system.
        
        Args:
            domain: Domain that is failing
            failure_count: Number of failures for this domain
            strategy: Strategy that is failing
            
        Returns:
            Recommendation if one was made, None otherwise
            
        Requirements: 10.1, 10.4
        """
        should_recommend, recommendation = self.should_recommend_parent_domain(domain, failure_count)
        
        if should_recommend and recommendation:
            self.log_recommendation(recommendation)
            return recommendation
        
        return None
    
    def find_strategy_conflicts(self) -> List[Dict[str, Any]]:
        """
        Find conflicts between subdomain and parent domain strategies.
        
        A conflict exists when:
        1. Both subdomain and parent domain have strategies
        2. The strategies are different
        
        Returns:
            List of conflict dictionaries with details
            
        Requirements: 10.2, 10.5
        """
        conflicts = []
        
        for domain, strategy in self.domain_rules.items():
            # Skip wildcard patterns for now
            if domain.startswith('*.'):
                continue
            
            # Check if this domain has a parent
            parent_exists, parent_key, parent_strategy = self.check_parent_domain_exists(domain)
            
            if parent_exists and parent_strategy:
                # Check if strategies are different
                subdomain_type = strategy.get('type', 'unknown')
                parent_type = parent_strategy.get('type', 'unknown')
                
                if subdomain_type != parent_type:
                    conflicts.append({
                        'subdomain': domain,
                        'parent_domain': parent_key,
                        'subdomain_strategy_type': subdomain_type,
                        'parent_strategy_type': parent_type,
                        'subdomain_strategy': strategy,
                        'parent_strategy': parent_strategy,
                        'conflict_type': 'different_strategy_types'
                    })
                else:
                    # Same type, check if parameters differ significantly
                    subdomain_params = strategy.get('params', {})
                    parent_params = parent_strategy.get('params', {})
                    
                    # Check critical parameters
                    critical_params = ['split_pos', 'split_count', 'ttl', 'fooling', 'disorder_method']
                    param_diffs = []
                    
                    for param in critical_params:
                        if param in subdomain_params or param in parent_params:
                            subdomain_val = subdomain_params.get(param)
                            parent_val = parent_params.get(param)
                            
                            if subdomain_val != parent_val:
                                param_diffs.append({
                                    'param': param,
                                    'subdomain_value': subdomain_val,
                                    'parent_value': parent_val
                                })
                    
                    if param_diffs:
                        conflicts.append({
                            'subdomain': domain,
                            'parent_domain': parent_key,
                            'subdomain_strategy_type': subdomain_type,
                            'parent_strategy_type': parent_type,
                            'subdomain_strategy': strategy,
                            'parent_strategy': parent_strategy,
                            'conflict_type': 'different_parameters',
                            'parameter_differences': param_diffs
                        })
        
        return conflicts
    
    def log_strategy_conflicts(self, conflicts: List[Dict[str, Any]]):
        """
        Log strategy conflicts in a readable format.
        
        Args:
            conflicts: List of conflicts from find_strategy_conflicts()
            
        Requirements: 10.2, 10.5
        """
        if not conflicts:
            LOG.info("✅ No strategy conflicts detected")
            return
        
        LOG.warning("=" * 80)
        LOG.warning(f"STRATEGY CONFLICTS DETECTED: {len(conflicts)} conflicts")
        LOG.warning("=" * 80)
        
        for i, conflict in enumerate(conflicts, 1):
            LOG.warning(f"\nConflict #{i}:")
            LOG.warning(f"  Subdomain: {conflict['subdomain']}")
            LOG.warning(f"  Parent Domain: {conflict['parent_domain']}")
            LOG.warning(f"  Conflict Type: {conflict['conflict_type']}")
            
            if conflict['conflict_type'] == 'different_strategy_types':
                LOG.warning(f"  Subdomain Strategy: {conflict['subdomain_strategy_type']}")
                LOG.warning(f"  Parent Strategy: {conflict['parent_strategy_type']}")
                LOG.warning(f"  💡 Consider removing subdomain strategy to use parent domain strategy")
            
            elif conflict['conflict_type'] == 'different_parameters':
                LOG.warning(f"  Strategy Type: {conflict['subdomain_strategy_type']}")
                LOG.warning(f"  Parameter Differences:")
                for diff in conflict['parameter_differences']:
                    LOG.warning(f"    - {diff['param']}: subdomain={diff['subdomain_value']}, parent={diff['parent_value']}")
                LOG.warning(f"  💡 Consider testing if parent domain parameters work for subdomain")
        
        LOG.warning("")
        LOG.warning(f"💡 To resolve conflicts:")
        LOG.warning(f"   1. Test parent domain strategies with subdomains")
        LOG.warning(f"   2. Remove subdomain entries if parent strategy works")
        LOG.warning(f"   3. Use wildcard patterns (*.domain.com) for consistency")
        LOG.warning("=" * 80)
    
    def get_recommendation_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about recommendations made.
        
        Returns:
            Dictionary with recommendation statistics
        """
        return {
            'total_recommendations': len(self.recommendations_made),
            'recommendations_by_type': {
                'remove_subdomain': sum(1 for r in self.recommendations_made.values() if r.recommendation_type == 'remove_subdomain'),
                'test_parent': sum(1 for r in self.recommendations_made.values() if r.recommendation_type == 'test_parent')
            },
            'domains_with_recommendations': list(self.recommendations_made.keys())
        }
