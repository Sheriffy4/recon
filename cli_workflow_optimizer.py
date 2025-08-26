"""
CLI Workflow Optimizer

Optimizes CLI workflow to avoid fingerprinting duplication and provides
mutually exclusive execution modes for better performance.
"""
import logging
import time
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from core.fingerprint.models import EnhancedFingerprint
from core.integration.attack_adapter import AttackAdapter
from core.integration.result_processor import ResultProcessor
LOG = logging.getLogger(__name__)

class ExecutionMode(Enum):
    """CLI execution modes that are mutually exclusive."""
    SINGLE_STRATEGY = 'single_strategy'
    HYBRID_DISCOVERY = 'hybrid_discovery'
    CLOSED_LOOP = 'closed_loop'
    EVOLUTIONARY_SEARCH = 'evolutionary_search'
    PARAMETER_OPTIMIZATION = 'parameter_optimization'

@dataclass
class FingerprintCache:
    """Cache for fingerprinting results to avoid duplication."""
    fingerprints: Dict[str, EnhancedFingerprint] = field(default_factory=dict)
    domain_to_fingerprint: Dict[str, str] = field(default_factory=dict)
    ip_to_fingerprint: Dict[str, str] = field(default_factory=dict)
    creation_times: Dict[str, float] = field(default_factory=dict)
    cache_ttl: float = 3600.0

    def get_fingerprint_for_domain(self, domain: str) -> Optional[EnhancedFingerprint]:
        """Get cached fingerprint for domain."""
        fp_hash = self.domain_to_fingerprint.get(domain)
        if fp_hash and self._is_valid(fp_hash):
            return self.fingerprints.get(fp_hash)
        return None

    def get_fingerprint_for_ip(self, ip: str) -> Optional[EnhancedFingerprint]:
        """Get cached fingerprint for IP."""
        fp_hash = self.ip_to_fingerprint.get(ip)
        if fp_hash and self._is_valid(fp_hash):
            return self.fingerprints.get(fp_hash)
        return None

    def cache_fingerprint(self, domain: str, ip: str, fingerprint: EnhancedFingerprint):
        """Cache fingerprint for domain and IP."""
        fp_hash = fingerprint.short_hash()
        current_time = time.time()
        self.fingerprints[fp_hash] = fingerprint
        self.domain_to_fingerprint[domain] = fp_hash
        self.ip_to_fingerprint[ip] = fp_hash
        self.creation_times[fp_hash] = current_time
        LOG.debug(f'Cached fingerprint {fp_hash} for domain {domain} and IP {ip}')

    def _is_valid(self, fp_hash: str) -> bool:
        """Check if cached fingerprint is still valid."""
        creation_time = self.creation_times.get(fp_hash, 0)
        return time.time() - creation_time < self.cache_ttl

    def clear_expired(self):
        """Clear expired fingerprints from cache."""
        current_time = time.time()
        expired_hashes = [fp_hash for fp_hash, creation_time in self.creation_times.items() if current_time - creation_time > self.cache_ttl]
        for fp_hash in expired_hashes:
            self.fingerprints.pop(fp_hash, None)
            self.creation_times.pop(fp_hash, None)
            domains_to_remove = [domain for domain, cached_hash in self.domain_to_fingerprint.items() if cached_hash == fp_hash]
            ips_to_remove = [ip for ip, cached_hash in self.ip_to_fingerprint.items() if cached_hash == fp_hash]
            for domain in domains_to_remove:
                self.domain_to_fingerprint.pop(domain, None)
            for ip in ips_to_remove:
                self.ip_to_fingerprint.pop(ip, None)
        if expired_hashes:
            LOG.debug(f'Cleared {len(expired_hashes)} expired fingerprints from cache')

@dataclass
class WorkflowState:
    """State management for CLI workflow optimization."""
    execution_mode: ExecutionMode
    fingerprint_cache: FingerprintCache = field(default_factory=FingerprintCache)
    processed_domains: Set[str] = field(default_factory=set)
    dns_cache: Dict[str, str] = field(default_factory=dict)
    domain_groups: Dict[str, List[str]] = field(default_factory=dict)
    optimization_results: Dict[str, Any] = field(default_factory=dict)

    def mark_domain_processed(self, domain: str):
        """Mark domain as processed to avoid reprocessing."""
        self.processed_domains.add(domain)
        LOG.debug(f'Marked domain {domain} as processed')

    def is_domain_processed(self, domain: str) -> bool:
        """Check if domain has already been processed."""
        return domain in self.processed_domains

    def get_unprocessed_domains(self, domains: List[str]) -> List[str]:
        """Get list of domains that haven't been processed yet."""
        return [domain for domain in domains if not self.is_domain_processed(domain)]

class CLIWorkflowOptimizer:
    """
    Optimizes CLI workflow to avoid duplication and improve performance.
    """

    def __init__(self, attack_adapter: AttackAdapter, result_processor: ResultProcessor):
        self.attack_adapter = attack_adapter
        self.result_processor = result_processor
        self.workflow_state: Optional[WorkflowState] = None

    def initialize_workflow(self, execution_mode: ExecutionMode) -> WorkflowState:
        """
        Initialize workflow state for the specified execution mode.

        Args:
            execution_mode: The execution mode to use

        Returns:
            Initialized workflow state
        """
        self.workflow_state = WorkflowState(execution_mode=execution_mode)
        LOG.info(f'Initialized CLI workflow in {execution_mode.value} mode')
        return self.workflow_state

    def should_skip_fingerprinting(self, domain: str, ip: str) -> Tuple[bool, Optional[EnhancedFingerprint]]:
        """
        Determine if fingerprinting should be skipped for a domain/IP.

        Args:
            domain: Target domain
            ip: Target IP address

        Returns:
            Tuple of (should_skip, cached_fingerprint)
        """
        if not self.workflow_state:
            return (False, None)
        cached_fp = self.workflow_state.fingerprint_cache.get_fingerprint_for_domain(domain)
        if cached_fp:
            LOG.debug(f'Found cached fingerprint for domain {domain}')
            return (True, cached_fp)
        cached_fp = self.workflow_state.fingerprint_cache.get_fingerprint_for_ip(ip)
        if cached_fp:
            LOG.debug(f'Found cached fingerprint for IP {ip}')
            return (True, cached_fp)
        return (False, None)

    def cache_fingerprint_result(self, domain: str, ip: str, fingerprint: EnhancedFingerprint):
        """
        Cache fingerprint result to avoid future duplication.

        Args:
            domain: Target domain
            ip: Target IP address
            fingerprint: Generated fingerprint
        """
        if not self.workflow_state:
            return
        self.workflow_state.fingerprint_cache.cache_fingerprint(domain, ip, fingerprint)

    def optimize_domain_grouping(self, domains: List[str], dns_cache: Dict[str, str]) -> Dict[str, List[str]]:
        """
        Optimize domain grouping to minimize redundant fingerprinting.

        Args:
            domains: List of domains to group
            dns_cache: DNS resolution cache

        Returns:
            Dictionary mapping fingerprint hash to list of domains
        """
        if not self.workflow_state:
            return {}
        ip_groups: Dict[str, List[str]] = {}
        for domain in domains:
            ip = dns_cache.get(domain)
            if ip:
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(domain)
        optimized_groups: Dict[str, List[str]] = {}
        for ip, ip_domains in ip_groups.items():
            cached_fp = self.workflow_state.fingerprint_cache.get_fingerprint_for_ip(ip)
            if cached_fp:
                fp_hash = cached_fp.short_hash()
                if fp_hash not in optimized_groups:
                    optimized_groups[fp_hash] = []
                optimized_groups[fp_hash].extend(ip_domains)
                for domain in ip_domains:
                    self.workflow_state.fingerprint_cache.domain_to_fingerprint[domain] = fp_hash
                LOG.debug(f'Reused cached fingerprint {fp_hash} for {len(ip_domains)} domains with IP {ip}')
            else:
                representative_domain = ip_domains[0]
                optimized_groups[f'pending_{ip}'] = ip_domains
        self.workflow_state.domain_groups = optimized_groups
        return optimized_groups

    def should_skip_evolutionary_search(self, current_effectiveness: float) -> bool:
        """
        Determine if evolutionary search should be skipped based on current results.

        Args:
            current_effectiveness: Current best effectiveness score

        Returns:
            True if evolutionary search should be skipped
        """
        if not self.workflow_state:
            return False
        if current_effectiveness > 0.95:
            LOG.info(f'Skipping evolutionary search - current effectiveness {current_effectiveness:.2f} is already very high')
            return True
        if self.workflow_state.execution_mode == ExecutionMode.SINGLE_STRATEGY:
            return True
        return False

    def optimize_parameter_testing_order(self, attack_names: List[str], fingerprint: EnhancedFingerprint) -> List[str]:
        """
        Optimize the order of parameter testing based on fingerprint characteristics.

        Args:
            attack_names: List of attack names to test
            fingerprint: DPI fingerprint

        Returns:
            Optimized order of attack names
        """
        if not attack_names:
            return []
        attack_scores = {}
        for attack_name in attack_names:
            score = 0.0
            if hasattr(fingerprint, 'dpi_type') and fingerprint.dpi_type:
                if 'tcp' in attack_name and 'tcp' in fingerprint.dpi_type.lower():
                    score += 0.3
                if 'tls' in attack_name and fingerprint.tls_inspection:
                    score += 0.3
                if 'http' in attack_name and fingerprint.http_inspection:
                    score += 0.3
            if hasattr(fingerprint, 'rst_injection') and fingerprint.rst_injection:
                if 'timing' in attack_name or 'delay' in attack_name:
                    score += 0.2
            if hasattr(fingerprint, 'payload_inspection') and fingerprint.payload_inspection:
                if 'obfuscation' in attack_name or 'encryption' in attack_name:
                    score += 0.2
            if hasattr(fingerprint, 'http2_support') and fingerprint.http2_support:
                if 'http2' in attack_name:
                    score += 0.4
            if hasattr(fingerprint, 'quic_support') and fingerprint.quic_support:
                if 'quic' in attack_name:
                    score += 0.4
            attack_scores[attack_name] = score
        optimized_order = sorted(attack_names, key=lambda x: attack_scores.get(x, 0), reverse=True)
        LOG.debug(f'Optimized attack testing order based on fingerprint: {optimized_order[:5]}...')
        return optimized_order

    def should_use_fast_mode(self, domain_count: int, time_budget_seconds: Optional[int]=None) -> bool:
        """
        Determine if fast mode should be used based on domain count and time budget.

        Args:
            domain_count: Number of domains to test
            time_budget_seconds: Optional time budget in seconds

        Returns:
            True if fast mode should be used
        """
        if not self.workflow_state:
            return False
        if domain_count > 50:
            LOG.info(f'Using fast mode due to large domain count ({domain_count})')
            return True
        if time_budget_seconds and time_budget_seconds < 300:
            LOG.info(f'Using fast mode due to tight time budget ({time_budget_seconds}s)')
            return True
        if self.workflow_state.execution_mode in [ExecutionMode.SINGLE_STRATEGY]:
            return True
        return False

    def get_workflow_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the current workflow optimization.

        Returns:
            Dictionary with workflow statistics
        """
        if not self.workflow_state:
            return {}
        cache = self.workflow_state.fingerprint_cache
        return {'execution_mode': self.workflow_state.execution_mode.value, 'cached_fingerprints': len(cache.fingerprints), 'processed_domains': len(self.workflow_state.processed_domains), 'domain_groups': len(self.workflow_state.domain_groups), 'dns_cache_size': len(self.workflow_state.dns_cache), 'cache_hit_rate': self._calculate_cache_hit_rate(), 'optimization_results': len(self.workflow_state.optimization_results)}

    def _calculate_cache_hit_rate(self) -> float:
        """Calculate fingerprint cache hit rate."""
        if not self.workflow_state:
            return 0.0
        total_requests = len(self.workflow_state.processed_domains)
        cache_hits = len(self.workflow_state.fingerprint_cache.fingerprints)
        if total_requests == 0:
            return 0.0
        return min(1.0, cache_hits / total_requests)

    def cleanup_workflow(self):
        """Clean up workflow state and resources."""
        if self.workflow_state:
            self.workflow_state.fingerprint_cache.clear_expired()
            LOG.info('Cleaned up workflow state')

    def export_workflow_state(self) -> Dict[str, Any]:
        """
        Export workflow state for persistence or analysis.

        Returns:
            Serializable workflow state
        """
        if not self.workflow_state:
            return {}
        return {'execution_mode': self.workflow_state.execution_mode.value, 'processed_domains': list(self.workflow_state.processed_domains), 'dns_cache': self.workflow_state.dns_cache.copy(), 'domain_groups': self.workflow_state.domain_groups.copy(), 'optimization_results': self.workflow_state.optimization_results.copy(), 'cache_statistics': {'fingerprint_count': len(self.workflow_state.fingerprint_cache.fingerprints), 'domain_mappings': len(self.workflow_state.fingerprint_cache.domain_to_fingerprint), 'ip_mappings': len(self.workflow_state.fingerprint_cache.ip_to_fingerprint)}}

def detect_execution_mode(args) -> ExecutionMode:
    """
    Detect execution mode from CLI arguments.

    Args:
        args: Parsed CLI arguments

    Returns:
        Detected execution mode
    """
    if hasattr(args, 'strategy') and args.strategy:
        return ExecutionMode.SINGLE_STRATEGY
    elif hasattr(args, 'closed_loop') and args.closed_loop:
        return ExecutionMode.CLOSED_LOOP
    elif hasattr(args, 'evolve') and args.evolve:
        return ExecutionMode.EVOLUTIONARY_SEARCH
    elif hasattr(args, 'optimize_parameters') and args.optimize_parameters:
        return ExecutionMode.PARAMETER_OPTIMIZATION
    else:
        return ExecutionMode.HYBRID_DISCOVERY

def create_workflow_optimizer(attack_adapter: AttackAdapter, result_processor: ResultProcessor, args) -> CLIWorkflowOptimizer:
    """
    Create and initialize workflow optimizer.

    Args:
        attack_adapter: Attack adapter instance
        result_processor: Result processor instance
        args: CLI arguments

    Returns:
        Configured workflow optimizer
    """
    optimizer = CLIWorkflowOptimizer(attack_adapter, result_processor)
    execution_mode = detect_execution_mode(args)
    optimizer.initialize_workflow(execution_mode)
    LOG.info(f'Created workflow optimizer in {execution_mode.value} mode')
    return optimizer