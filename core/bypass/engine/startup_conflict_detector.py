"""
Startup Conflict Detector

This module detects and reports strategy conflicts at service startup,
helping identify potential issues before they affect production traffic.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""

import json
import socket
import logging
from typing import Dict, Any, List, Tuple, Set
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


class ConflictReport:
    """Represents a conflict detection report."""
    
    def __init__(self):
        self.ip_conflicts: List[Dict[str, Any]] = []
        self.parent_child_conflicts: List[Dict[str, Any]] = []
        self.wildcard_conflicts: List[Dict[str, Any]] = []
        self.total_domains: int = 0
        self.total_ips_checked: int = 0
        self.has_conflicts: bool = False
    
    def add_ip_conflict(self, conflict: Dict[str, Any]):
        """Add an IP-based conflict."""
        self.ip_conflicts.append(conflict)
        self.has_conflicts = True
    
    def add_parent_child_conflict(self, conflict: Dict[str, Any]):
        """Add a parent-child domain conflict."""
        self.parent_child_conflicts.append(conflict)
        self.has_conflicts = True
    
    def add_wildcard_conflict(self, conflict: Dict[str, Any]):
        """Add a wildcard pattern conflict."""
        self.wildcard_conflicts.append(conflict)
        self.has_conflicts = True


class StartupConflictDetector:
    """
    Detects strategy conflicts at service startup.
    
    This detector scans domain_rules.json and identifies:
    - Multiple domains on same IP with different strategies
    - Parent-child domain conflicts
    - Wildcard pattern conflicts
    
    Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
    """
    
    def __init__(self, domain_rules_path: str = "domain_rules.json"):
        """
        Initialize the startup conflict detector.
        
        Args:
            domain_rules_path: Path to domain_rules.json file
        """
        self.domain_rules_path = domain_rules_path
        self.domain_rules: Dict[str, Dict[str, Any]] = {}
        self.default_strategy: Dict[str, Any] = {}
    
    def load_domain_rules(self) -> bool:
        """
        Load domain rules from JSON file.
        
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            if not Path(self.domain_rules_path).exists():
                logger.error(f"Domain rules file not found: {self.domain_rules_path}")
                return False
            
            with open(self.domain_rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.domain_rules = data.get('domain_rules', {})
            self.default_strategy = data.get('default_strategy', {})
            
            logger.info(f"Loaded {len(self.domain_rules)} domain rules from {self.domain_rules_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading domain rules: {e}")
            return False
    
    def detect_all_conflicts(self) -> ConflictReport:
        """
        Detect all types of conflicts in domain rules.
        
        Returns:
            ConflictReport with all detected conflicts
            
        Requirements: 6.1, 6.2, 6.3
        """
        report = ConflictReport()
        report.total_domains = len(self.domain_rules)
        
        # Detect IP-based conflicts (Requirement 6.1)
        ip_conflicts = self._detect_ip_conflicts()
        for conflict in ip_conflicts:
            report.add_ip_conflict(conflict)
        
        report.total_ips_checked = len(ip_conflicts)
        
        # Detect parent-child conflicts (Requirement 6.2)
        parent_child_conflicts = self._detect_parent_child_conflicts()
        for conflict in parent_child_conflicts:
            report.add_parent_child_conflict(conflict)
        
        # Detect wildcard conflicts (Requirement 6.3)
        wildcard_conflicts = self._detect_wildcard_conflicts()
        for conflict in wildcard_conflicts:
            report.add_wildcard_conflict(conflict)
        
        return report
    
    def _detect_ip_conflicts(self) -> List[Dict[str, Any]]:
        """
        Detect domains on same IP with different strategies.
        
        Returns:
            List of IP conflict dictionaries
            
        Requirements: 6.1
        """
        conflicts = []
        ip_to_domains = defaultdict(list)
        
        # Resolve all domains to IPs
        for domain in self.domain_rules.keys():
            # Skip wildcard patterns
            if domain.startswith('*'):
                continue
            
            try:
                # Try to resolve domain to IP
                ip = socket.gethostbyname(domain)
                ip_to_domains[ip].append(domain)
            except (socket.gaierror, socket.herror, socket.timeout):
                # Domain resolution failed, skip
                logger.debug(f"Could not resolve {domain}")
                continue
            except Exception as e:
                logger.debug(f"Error resolving {domain}: {e}")
                continue
        
        # Check for conflicts
        for ip, domains in ip_to_domains.items():
            if len(domains) > 1:
                # Multiple domains on same IP - check strategies
                strategies_map = {}
                for domain in domains:
                    strategy = self.domain_rules[domain]
                    strategy_type = strategy.get('type', 'unknown')
                    strategy_params = strategy.get('params', {})
                    
                    # Create strategy signature
                    critical_params = ['split_pos', 'split_count', 'ttl', 'fooling', 'disorder_method']
                    param_sig = {k: strategy_params.get(k) for k in critical_params if k in strategy_params}
                    
                    strategies_map[domain] = {
                        'type': strategy_type,
                        'params': param_sig,
                        'full_strategy': strategy
                    }
                
                # Check if all strategies are identical
                strategy_signatures = set()
                for domain, strat_info in strategies_map.items():
                    sig = f"{strat_info['type']}:{json.dumps(strat_info['params'], sort_keys=True)}"
                    strategy_signatures.add(sig)
                
                if len(strategy_signatures) > 1:
                    # Conflict detected!
                    conflicts.append({
                        'ip': ip,
                        'domains': domains,
                        'strategies': strategies_map,
                        'conflict_type': 'different_strategies'
                    })
        
        return conflicts
    
    def _detect_parent_child_conflicts(self) -> List[Dict[str, Any]]:
        """
        Detect conflicts between parent and child domains.
        
        Returns:
            List of parent-child conflict dictionaries
            
        Requirements: 6.2
        """
        conflicts = []
        
        for domain in self.domain_rules.keys():
            # Skip wildcard patterns
            if domain.startswith('*'):
                continue
            
            # Check if parent domain exists
            parent_exists, parent_key, parent_strategy = self._check_parent_domain(domain)
            
            if parent_exists and parent_strategy:
                subdomain_strategy = self.domain_rules[domain]
                
                # Compare strategies
                subdomain_type = subdomain_strategy.get('type', 'unknown')
                parent_type = parent_strategy.get('type', 'unknown')
                
                if subdomain_type != parent_type:
                    conflicts.append({
                        'subdomain': domain,
                        'parent_domain': parent_key,
                        'subdomain_strategy_type': subdomain_type,
                        'parent_strategy_type': parent_type,
                        'subdomain_strategy': subdomain_strategy,
                        'parent_strategy': parent_strategy,
                        'conflict_type': 'different_types'
                    })
                else:
                    # Same type, check parameters
                    param_diffs = self._compare_strategy_params(
                        subdomain_strategy.get('params', {}),
                        parent_strategy.get('params', {})
                    )
                    
                    if param_diffs:
                        conflicts.append({
                            'subdomain': domain,
                            'parent_domain': parent_key,
                            'subdomain_strategy_type': subdomain_type,
                            'parent_strategy_type': parent_type,
                            'subdomain_strategy': subdomain_strategy,
                            'parent_strategy': parent_strategy,
                            'conflict_type': 'different_parameters',
                            'parameter_differences': param_diffs
                        })
        
        return conflicts
    
    def _detect_wildcard_conflicts(self) -> List[Dict[str, Any]]:
        """
        Detect conflicts involving wildcard patterns.
        
        Returns:
            List of wildcard conflict dictionaries
            
        Requirements: 6.3
        """
        conflicts = []
        
        # Find all wildcard patterns
        wildcard_patterns = {domain: strategy for domain, strategy in self.domain_rules.items() 
                            if domain.startswith('*')}
        
        # Check each non-wildcard domain against wildcard patterns
        for domain in self.domain_rules.keys():
            if domain.startswith('*'):
                continue
            
            # Check if domain matches any wildcard pattern
            for wildcard, wildcard_strategy in wildcard_patterns.items():
                wildcard_base = wildcard[2:]  # Remove "*."
                
                if domain.endswith(wildcard_base):
                    # Domain matches wildcard pattern
                    domain_strategy = self.domain_rules[domain]
                    
                    # Compare strategies
                    domain_type = domain_strategy.get('type', 'unknown')
                    wildcard_type = wildcard_strategy.get('type', 'unknown')
                    
                    if domain_type != wildcard_type:
                        conflicts.append({
                            'domain': domain,
                            'wildcard_pattern': wildcard,
                            'domain_strategy_type': domain_type,
                            'wildcard_strategy_type': wildcard_type,
                            'domain_strategy': domain_strategy,
                            'wildcard_strategy': wildcard_strategy,
                            'conflict_type': 'wildcard_override'
                        })
        
        return conflicts
    
    def _check_parent_domain(self, domain: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Check if parent domain strategy exists.
        
        Args:
            domain: Subdomain to check
            
        Returns:
            Tuple of (exists, parent_domain, parent_strategy)
        """
        if not domain or '.' not in domain:
            return False, None, None
        
        parts = domain.split('.')
        if len(parts) <= 2:
            return False, None, None
        
        parent_domain = '.'.join(parts[1:])
        
        # Check exact parent domain
        if parent_domain in self.domain_rules:
            return True, parent_domain, self.domain_rules[parent_domain]
        
        # Check wildcard pattern
        wildcard_pattern = f"*.{parent_domain}"
        if wildcard_pattern in self.domain_rules:
            return True, wildcard_pattern, self.domain_rules[wildcard_pattern]
        
        return False, parent_domain, None
    
    def _compare_strategy_params(self, params1: Dict[str, Any], params2: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Compare strategy parameters and return differences.
        
        Args:
            params1: First parameter set
            params2: Second parameter set
            
        Returns:
            List of parameter differences
        """
        diffs = []
        critical_params = ['split_pos', 'split_count', 'ttl', 'fooling', 'disorder_method']
        
        for param in critical_params:
            if param in params1 or param in params2:
                val1 = params1.get(param)
                val2 = params2.get(param)
                
                if val1 != val2:
                    diffs.append({
                        'param': param,
                        'value1': val1,
                        'value2': val2
                    })
        
        return diffs
    
    def print_conflict_report(self, report: ConflictReport):
        """
        Print detailed conflict report to logs.
        
        Args:
            report: ConflictReport to print
            
        Requirements: 6.4, 6.5
        """
        if not report.has_conflicts:
            logger.info("=" * 80)
            logger.info("✅ NO STRATEGY CONFLICTS DETECTED")
            logger.info("=" * 80)
            logger.info(f"Scanned {report.total_domains} domain rules")
            logger.info("All domain strategies are consistent")
            logger.info("=" * 80)
            return
        
        logger.warning("=" * 80)
        logger.warning("⚠️  STRATEGY CONFLICTS DETECTED AT STARTUP")
        logger.warning("=" * 80)
        logger.warning(f"Scanned {report.total_domains} domain rules")
        logger.warning(f"Found {len(report.ip_conflicts)} IP conflicts")
        logger.warning(f"Found {len(report.parent_child_conflicts)} parent-child conflicts")
        logger.warning(f"Found {len(report.wildcard_conflicts)} wildcard conflicts")
        logger.warning("=" * 80)
        
        # Print IP conflicts (Requirement 6.4)
        if report.ip_conflicts:
            logger.warning("")
            logger.warning("📍 IP-BASED CONFLICTS:")
            logger.warning("   Multiple domains resolve to the same IP with different strategies")
            logger.warning("")
            
            for i, conflict in enumerate(report.ip_conflicts, 1):
                logger.warning(f"   Conflict #{i}: IP {conflict['ip']}")
                logger.warning(f"   Domains on this IP:")
                
                for domain in conflict['domains']:
                    strat_info = conflict['strategies'][domain]
                    logger.warning(f"      - {domain}")
                    logger.warning(f"        Strategy: {strat_info['type']}")
                    logger.warning(f"        Params: {strat_info['params']}")
                
                logger.warning(f"   ℹ️  SNI-based selection will be used to apply correct strategy")
                logger.warning("")
        
        # Print parent-child conflicts (Requirement 6.4)
        if report.parent_child_conflicts:
            logger.warning("")
            logger.warning("👨‍👦 PARENT-CHILD DOMAIN CONFLICTS:")
            logger.warning("   Subdomains have different strategies than their parent domains")
            logger.warning("")
            
            for i, conflict in enumerate(report.parent_child_conflicts, 1):
                logger.warning(f"   Conflict #{i}:")
                logger.warning(f"      Subdomain: {conflict['subdomain']}")
                logger.warning(f"      Parent: {conflict['parent_domain']}")
                
                if conflict['conflict_type'] == 'different_types':
                    logger.warning(f"      Subdomain strategy: {conflict['subdomain_strategy_type']}")
                    logger.warning(f"      Parent strategy: {conflict['parent_strategy_type']}")
                elif conflict['conflict_type'] == 'different_parameters':
                    logger.warning(f"      Strategy type: {conflict['subdomain_strategy_type']}")
                    logger.warning(f"      Parameter differences:")
                    for diff in conflict['parameter_differences']:
                        logger.warning(f"         - {diff['param']}: subdomain={diff['value1']}, parent={diff['value2']}")
                
                logger.warning("")
        
        # Print wildcard conflicts (Requirement 6.4)
        if report.wildcard_conflicts:
            logger.warning("")
            logger.warning("🔀 WILDCARD PATTERN CONFLICTS:")
            logger.warning("   Specific domain rules override wildcard patterns")
            logger.warning("")
            
            for i, conflict in enumerate(report.wildcard_conflicts, 1):
                logger.warning(f"   Conflict #{i}:")
                logger.warning(f"      Domain: {conflict['domain']}")
                logger.warning(f"      Wildcard: {conflict['wildcard_pattern']}")
                logger.warning(f"      Domain strategy: {conflict['domain_strategy_type']}")
                logger.warning(f"      Wildcard strategy: {conflict['wildcard_strategy_type']}")
                logger.warning(f"      ℹ️  Specific domain rule takes precedence")
                logger.warning("")
        
        # Print resolution guide (Requirement 6.5)
        self._print_resolution_guide(report)
    
    def _print_resolution_guide(self, report: ConflictReport):
        """
        Print conflict resolution guide.
        
        Args:
            report: ConflictReport with detected conflicts
            
        Requirements: 6.5
        """
        logger.warning("")
        logger.warning("=" * 80)
        logger.warning("💡 CONFLICT RESOLUTION GUIDE")
        logger.warning("=" * 80)
        
        if report.ip_conflicts:
            logger.warning("")
            logger.warning("For IP-based conflicts:")
            logger.warning("   1. SNI-based selection will automatically use the correct strategy")
            logger.warning("   2. If issues occur, consider using the same strategy for all domains on the IP")
            logger.warning("   3. Test each domain individually: cli.py test <domain>")
            logger.warning("   4. Monitor logs for 'Domain conflict detected' warnings during operation")
        
        if report.parent_child_conflicts:
            logger.warning("")
            logger.warning("For parent-child conflicts:")
            logger.warning("   1. Test if parent domain strategy works for subdomain:")
            logger.warning("      cli.py test <subdomain> --use-parent-strategy")
            logger.warning("   2. If parent strategy works, remove subdomain rule:")
            logger.warning("      Edit domain_rules.json and remove subdomain entry")
            logger.warning("   3. Consider using wildcard patterns for consistency:")
            logger.warning("      Replace subdomain rules with '*.parent.com' pattern")
            logger.warning("   4. Use strategy conflict checker:")
            logger.warning("      python -m core.cli.strategy_conflict_checker")
        
        if report.wildcard_conflicts:
            logger.warning("")
            logger.warning("For wildcard conflicts:")
            logger.warning("   1. Specific domain rules always take precedence over wildcards")
            logger.warning("   2. If subdomain needs different strategy, keep specific rule")
            logger.warning("   3. If subdomain can use wildcard strategy, remove specific rule")
            logger.warning("   4. Review all wildcard patterns for consistency")
        
        logger.warning("")
        logger.warning("General recommendations:")
        logger.warning("   • Keep domain rules simple and consistent")
        logger.warning("   • Use parent domain strategies when possible")
        logger.warning("   • Test strategies after making changes")
        logger.warning("   • Monitor service logs for strategy application issues")
        logger.warning("   • Run conflict checker regularly: python -m core.cli.strategy_conflict_checker")
        logger.warning("")
        logger.warning("=" * 80)


def run_startup_conflict_detection(domain_rules_path: str = "domain_rules.json") -> ConflictReport:
    """
    Run conflict detection at service startup.
    
    This is the main entry point for startup conflict detection.
    Call this function during service initialization.
    
    Args:
        domain_rules_path: Path to domain_rules.json file
        
    Returns:
        ConflictReport with all detected conflicts
        
    Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
    """
    detector = StartupConflictDetector(domain_rules_path)
    
    if not detector.load_domain_rules():
        logger.error("Failed to load domain rules, skipping conflict detection")
        return ConflictReport()
    
    logger.info("Running startup conflict detection...")
    report = detector.detect_all_conflicts()
    
    detector.print_conflict_report(report)
    
    return report
