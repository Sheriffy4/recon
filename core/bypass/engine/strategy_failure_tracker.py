#!/usr/bin/env python3
"""
Strategy Failure Tracker

Tracks strategy failures and suggests re-validation when strategies
consistently fail in production.

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict

LOG = logging.getLogger(__name__)


@dataclass
class StrategyFailureRecord:
    """Record of a strategy failure."""
    domain: str
    strategy_type: str
    failure_count: int
    last_failure_time: str
    retransmissions: int
    failure_reason: Optional[str] = None
    needs_revalidation: bool = False


@dataclass
class StrategyHistoryEntry:
    """Historical record of a strategy for a domain."""
    strategy_type: str
    params: Dict[str, Any]
    attacks: List[str]
    discovered_at: str
    replaced_at: str
    failure_count: int
    replacement_reason: str


class StrategyFailureTracker:
    """
    Tracks strategy failures and manages re-validation recommendations.
    
    This component monitors strategy effectiveness in production and suggests
    re-testing when strategies consistently fail.
    """
    
    def __init__(
        self,
        domain_rules_path: str = "domain_rules.json",
        failure_threshold: int = 3,
        revalidation_threshold: int = 5
    ):
        """
        Initialize the Strategy Failure Tracker.
        
        Args:
            domain_rules_path: Path to domain_rules.json file
            failure_threshold: Number of failures before logging warning (default: 3)
            revalidation_threshold: Number of failures before suggesting re-validation (default: 5)
        """
        self.domain_rules_path = domain_rules_path
        self.failure_threshold = failure_threshold
        self.revalidation_threshold = revalidation_threshold
        
        # In-memory failure tracking
        self.failure_records: Dict[str, StrategyFailureRecord] = {}
        
        # Load existing failure data from domain_rules.json metadata
        self._load_failure_data()
    
    def _load_failure_data(self):
        """Load failure data from domain_rules.json metadata."""
        try:
            rules_path = Path(self.domain_rules_path)
            if not rules_path.exists():
                LOG.warning(f"Domain rules file not found: {self.domain_rules_path}")
                return
            
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract failure data from metadata
            domain_rules = data.get('domain_rules', {})
            
            for domain, rule in domain_rules.items():
                metadata = rule.get('metadata', {})
                
                # Load failure count from metadata
                failure_count = metadata.get('failure_count', 0)
                last_failure = metadata.get('last_failure_time')
                
                if failure_count > 0:
                    self.failure_records[domain] = StrategyFailureRecord(
                        domain=domain,
                        strategy_type=rule.get('type', 'unknown'),
                        failure_count=failure_count,
                        last_failure_time=last_failure or datetime.now().isoformat(),
                        retransmissions=0,
                        needs_revalidation=failure_count >= self.revalidation_threshold
                    )
            
            LOG.info(f"Loaded failure data for {len(self.failure_records)} domains")
            
        except Exception as e:
            LOG.error(f"Failed to load failure data: {e}")
    
    def record_failure(
        self,
        domain: str,
        strategy: Dict[str, Any],
        retransmissions: int,
        reason: Optional[str] = None
    ) -> bool:
        """
        Record a strategy failure.
        
        Args:
            domain: Domain that failed
            strategy: Strategy that was applied
            retransmissions: Number of retransmissions detected
            reason: Optional reason for failure
        
        Returns:
            True if revalidation is recommended, False otherwise
        
        Requirements: 8.1, 8.2
        """
        strategy_type = strategy.get('type', 'unknown')
        
        # Get or create failure record
        if domain not in self.failure_records:
            self.failure_records[domain] = StrategyFailureRecord(
                domain=domain,
                strategy_type=strategy_type,
                failure_count=0,
                last_failure_time=datetime.now().isoformat(),
                retransmissions=retransmissions,
                failure_reason=reason
            )
        
        # Update failure record
        record = self.failure_records[domain]
        record.failure_count += 1
        record.last_failure_time = datetime.now().isoformat()
        record.retransmissions = retransmissions
        record.failure_reason = reason
        
        # Check if revalidation is needed
        if record.failure_count >= self.revalidation_threshold:
            record.needs_revalidation = True
        
        # Log failure
        self._log_failure(record)
        
        # Save to domain_rules.json
        self._save_failure_to_metadata(domain, record)
        
        return record.needs_revalidation
    
    def _log_failure(self, record: StrategyFailureRecord):
        """
        Log strategy failure with appropriate severity.
        
        Args:
            record: Failure record to log
        
        Requirements: 8.1, 8.2
        """
        if record.failure_count == self.failure_threshold:
            LOG.warning("=" * 80)
            LOG.warning(f"STRATEGY FAILURE THRESHOLD REACHED")
            LOG.warning("=" * 80)
            LOG.warning(f"Domain: {record.domain}")
            LOG.warning(f"Strategy Type: {record.strategy_type}")
            LOG.warning(f"Failure Count: {record.failure_count}")
            LOG.warning(f"Retransmissions: {record.retransmissions}")
            if record.failure_reason:
                LOG.warning(f"Reason: {record.failure_reason}")
            LOG.warning(f"💡 Strategy may not be working correctly")
            LOG.warning("=" * 80)
        
        elif record.failure_count >= self.revalidation_threshold:
            LOG.error("=" * 80)
            LOG.error(f"STRATEGY REVALIDATION RECOMMENDED")
            LOG.error("=" * 80)
            LOG.error(f"Domain: {record.domain}")
            LOG.error(f"Strategy Type: {record.strategy_type}")
            LOG.error(f"Failure Count: {record.failure_count}")
            LOG.error(f"Retransmissions: {record.retransmissions}")
            if record.failure_reason:
                LOG.error(f"Reason: {record.failure_reason}")
            LOG.error(f"🚨 CRITICAL: Strategy has failed {record.failure_count} times")
            LOG.error(f"💡 RECOMMENDATIONS:")
            LOG.error(f"  1. Run 'python cli.py revalidate {record.domain}' to re-test strategy")
            LOG.error(f"  2. Run 'python cli.py auto {record.domain}' to find new strategy")
            LOG.error(f"  3. Check if DPI behavior has changed")
            LOG.error(f"  4. Consider using parent domain strategy")
            LOG.error("=" * 80)
    
    def _save_failure_to_metadata(self, domain: str, record: StrategyFailureRecord):
        """
        Save failure data to domain_rules.json metadata.
        
        Args:
            domain: Domain to update
            record: Failure record to save
        
        Requirements: 8.3, 8.4
        """
        try:
            rules_path = Path(self.domain_rules_path)
            if not rules_path.exists():
                LOG.warning(f"Domain rules file not found: {self.domain_rules_path}")
                return
            
            # Load current rules
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Update metadata
            domain_rules = data.get('domain_rules', {})
            
            if domain in domain_rules:
                if 'metadata' not in domain_rules[domain]:
                    domain_rules[domain]['metadata'] = {}
                
                metadata = domain_rules[domain]['metadata']
                metadata['failure_count'] = record.failure_count
                metadata['last_failure_time'] = record.last_failure_time
                metadata['needs_revalidation'] = record.needs_revalidation
                
                if record.failure_reason:
                    metadata['last_failure_reason'] = record.failure_reason
                
                # Save updated rules
                with open(rules_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                LOG.debug(f"Saved failure data for {domain} to metadata")
            else:
                LOG.warning(f"Domain {domain} not found in domain_rules.json")
            
        except Exception as e:
            LOG.error(f"Failed to save failure data to metadata: {e}")
    
    def reset_failure_count(self, domain: str):
        """
        Reset failure count for a domain (e.g., after successful revalidation).
        
        Args:
            domain: Domain to reset
        
        Requirements: 8.4
        """
        if domain in self.failure_records:
            del self.failure_records[domain]
        
        # Also remove from metadata
        try:
            rules_path = Path(self.domain_rules_path)
            if not rules_path.exists():
                return
            
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            domain_rules = data.get('domain_rules', {})
            
            if domain in domain_rules and 'metadata' in domain_rules[domain]:
                metadata = domain_rules[domain]['metadata']
                metadata['failure_count'] = 0
                metadata['needs_revalidation'] = False
                metadata.pop('last_failure_time', None)
                metadata.pop('last_failure_reason', None)
                
                with open(rules_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                LOG.info(f"Reset failure count for {domain}")
        
        except Exception as e:
            LOG.error(f"Failed to reset failure count in metadata: {e}")
    
    def get_domains_needing_revalidation(self) -> List[str]:
        """
        Get list of domains that need revalidation.
        
        Returns:
            List of domain names that need revalidation
        
        Requirements: 8.2
        """
        return [
            domain
            for domain, record in self.failure_records.items()
            if record.needs_revalidation
        ]
    
    def get_failure_record(self, domain: str) -> Optional[StrategyFailureRecord]:
        """
        Get failure record for a domain.
        
        Args:
            domain: Domain to get record for
        
        Returns:
            StrategyFailureRecord or None if no failures recorded
        """
        return self.failure_records.get(domain)
    
    def get_all_failure_records(self) -> Dict[str, StrategyFailureRecord]:
        """
        Get all failure records.
        
        Returns:
            Dictionary mapping domains to failure records
        """
        return self.failure_records.copy()
    
    def save_strategy_history(
        self,
        domain: str,
        old_strategy: Dict[str, Any],
        new_strategy: Dict[str, Any],
        replacement_reason: str
    ):
        """
        Save strategy replacement to history in domain_rules.json metadata.
        
        Args:
            domain: Domain being updated
            old_strategy: Strategy being replaced
            new_strategy: New strategy
            replacement_reason: Reason for replacement
        
        Requirements: 8.3, 8.4
        """
        try:
            rules_path = Path(self.domain_rules_path)
            if not rules_path.exists():
                LOG.warning(f"Domain rules file not found: {self.domain_rules_path}")
                return
            
            # Load current rules
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            domain_rules = data.get('domain_rules', {})
            
            if domain in domain_rules:
                if 'metadata' not in domain_rules[domain]:
                    domain_rules[domain]['metadata'] = {}
                
                metadata = domain_rules[domain]['metadata']
                
                # Initialize history if not exists
                if 'strategy_history' not in metadata:
                    metadata['strategy_history'] = []
                
                # Get failure count for old strategy
                failure_count = self.failure_records.get(domain, StrategyFailureRecord(
                    domain=domain,
                    strategy_type='',
                    failure_count=0,
                    last_failure_time='',
                    retransmissions=0
                )).failure_count
                
                # Create history entry
                history_entry = StrategyHistoryEntry(
                    strategy_type=old_strategy.get('type', 'unknown'),
                    params=old_strategy.get('params', {}),
                    attacks=old_strategy.get('attacks', []),
                    discovered_at=metadata.get('discovered_at', datetime.now().isoformat()),
                    replaced_at=datetime.now().isoformat(),
                    failure_count=failure_count,
                    replacement_reason=replacement_reason
                )
                
                # Add to history
                metadata['strategy_history'].append(asdict(history_entry))
                
                # Limit history to last 10 entries
                if len(metadata['strategy_history']) > 10:
                    metadata['strategy_history'] = metadata['strategy_history'][-10:]
                
                # Save updated rules
                with open(rules_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                LOG.info(f"Saved strategy history for {domain}")
            
        except Exception as e:
            LOG.error(f"Failed to save strategy history: {e}")
    
    def update_strategy_in_domain_rules(
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
        try:
            rules_path = Path(self.domain_rules_path)
            if not rules_path.exists():
                LOG.warning(f"Domain rules file not found: {self.domain_rules_path}")
                return
            
            # Load current rules
            with open(rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            domain_rules = data.get('domain_rules', {})
            
            # Save old strategy to history if it exists
            if domain in domain_rules:
                old_strategy = domain_rules[domain]
                self.save_strategy_history(
                    domain,
                    old_strategy,
                    new_strategy,
                    "Strategy revalidation - new strategy found"
                )
            
            # Update strategy
            domain_rules[domain] = new_strategy
            
            # Update metadata
            if 'metadata' not in domain_rules[domain]:
                domain_rules[domain]['metadata'] = {}
            
            metadata = domain_rules[domain]['metadata']
            metadata['last_updated'] = datetime.now().isoformat()
            metadata['failure_count'] = 0
            metadata['needs_revalidation'] = False
            metadata.pop('last_failure_time', None)
            metadata.pop('last_failure_reason', None)
            
            # Apply additional metadata updates
            if metadata_updates:
                metadata.update(metadata_updates)
            
            # Update last_updated timestamp at root level
            data['last_updated'] = datetime.now().isoformat()
            
            # Save updated rules
            with open(rules_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Reset in-memory failure count
            self.reset_failure_count(domain)
            
            LOG.info(f"✅ Updated strategy for {domain} in domain_rules.json")
            LOG.info(f"   Strategy type: {new_strategy.get('type', 'unknown')}")
            LOG.info(f"   Failure count reset to 0")
            
        except Exception as e:
            LOG.error(f"Failed to update strategy in domain_rules.json: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get failure tracker statistics.
        
        Returns:
            Dictionary containing statistics
        """
        total_failures = sum(r.failure_count for r in self.failure_records.values())
        domains_needing_revalidation = len(self.get_domains_needing_revalidation())
        
        return {
            "tracked_domains": len(self.failure_records),
            "total_failures": total_failures,
            "domains_needing_revalidation": domains_needing_revalidation,
            "failure_threshold": self.failure_threshold,
            "revalidation_threshold": self.revalidation_threshold
        }
