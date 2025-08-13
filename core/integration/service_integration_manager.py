# core/integration/service_integration_manager.py
"""
Service Integration Manager

Manages integration between strategy testing and service components.
Handles loading, validation, and application of strategies for service use.
"""

import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

LOG = logging.getLogger("ServiceIntegrationManager")

@dataclass
class ServiceStrategy:
    """Represents a strategy loaded for service use."""
    fingerprint_hash: str
    attack_name: str
    strategy_command: str
    success_rate: float
    avg_latency_ms: float
    domains: List[str]
    parameters: Dict[str, Any]
    bypass_effective: bool
    timestamp: float
    validated: bool = False

class ServiceIntegrationManager:
    """
    Manages integration between strategy testing and service components.
    Handles proper loading of strategies from best_strategy.json with validation
    and graceful error handling.
    """
    
    def __init__(self, strategy_file: str = "best_strategy.json"):
        """
        Initialize service integration manager.
        
        Args:
            strategy_file: Path to strategy file
        """
        self.strategy_file = strategy_file
        self.loaded_strategies: Dict[str, ServiceStrategy] = {}
        self.domain_strategy_mapping: Dict[str, str] = {}
        self.last_load_time: float = 0
        self.load_errors: List[str] = []
        
        # Configuration
        self.min_success_rate = 0.7
        self.max_latency_ms = 10000  # 10 seconds max latency
        self.strategy_cache_ttl = 300  # 5 minutes cache TTL        

    def load_strategies_for_service(self) -> Dict[str, ServiceStrategy]:
        """
        Load and validate strategies for service use.
        
        Returns:
            Dict mapping fingerprint hash to ServiceStrategy objects
            
        Requirements: 2.1, 2.2
        """
        try:
            # Check if file exists
            if not Path(self.strategy_file).exists():
                LOG.warning(f"Strategy file {self.strategy_file} not found, returning empty strategies")
                return {}
            
            # Check if we need to reload (cache TTL)
            current_time = time.time()
            if (current_time - self.last_load_time) < self.strategy_cache_ttl and self.loaded_strategies:
                LOG.debug("Using cached strategies")
                return self.loaded_strategies
            
            # Load strategy file
            with open(self.strategy_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate file structure
            if not self._validate_strategy_file_structure(data):
                LOG.error("Invalid strategy file structure")
                return {}
            
            # Process strategies
            strategies = {}
            strategies_by_fingerprint = data.get('strategies_by_fingerprint', {})
            
            for fingerprint_hash, strategy_data in strategies_by_fingerprint.items():
                try:
                    service_strategy = self._convert_to_service_strategy(fingerprint_hash, strategy_data)
                    if service_strategy and self._validate_strategy_data(service_strategy):
                        strategies[fingerprint_hash] = service_strategy
                        self._update_domain_mapping(service_strategy)
                        LOG.debug(f"Loaded strategy for fingerprint {fingerprint_hash}: {service_strategy.attack_name}")
                    else:
                        LOG.warning(f"Skipping invalid strategy for fingerprint {fingerprint_hash}")
                        
                except Exception as e:
                    LOG.error(f"Error processing strategy {fingerprint_hash}: {e}")
                    self.load_errors.append(f"Strategy {fingerprint_hash}: {str(e)}")
                    continue
            
            self.loaded_strategies = strategies
            self.last_load_time = current_time
            self.load_errors.clear()
            
            LOG.info(f"Successfully loaded {len(strategies)} strategies from {self.strategy_file}")
            return strategies
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in strategy file {self.strategy_file}: {e}"
            LOG.error(error_msg)
            self.load_errors.append(error_msg)
            return {}
            
        except Exception as e:
            error_msg = f"Error loading strategies from {self.strategy_file}: {e}"
            LOG.error(error_msg)
            self.load_errors.append(error_msg)
            return {}    
    
    def _validate_strategy_file_structure(self, data: Dict) -> bool:
        """
        Validate the basic structure of the strategy file.
        
        Args:
            data: Loaded JSON data
            
        Returns:
            True if structure is valid
        """
        try:
            # Check for required top-level keys
            if not isinstance(data, dict):
                LOG.error("Strategy file must contain a JSON object")
                return False
                
            if 'strategies_by_fingerprint' not in data:
                LOG.error("Strategy file missing 'strategies_by_fingerprint' key")
                return False
                
            if not isinstance(data['strategies_by_fingerprint'], dict):
                LOG.error("'strategies_by_fingerprint' must be an object")
                return False
                
            return True
            
        except Exception as e:
            LOG.error(f"Error validating strategy file structure: {e}")
            return False
    
    def _convert_to_service_strategy(self, fingerprint_hash: str, strategy_data: Dict) -> Optional[ServiceStrategy]:
        """
        Convert raw strategy data to ServiceStrategy object.
        
        Args:
            fingerprint_hash: The fingerprint hash key
            strategy_data: Raw strategy data from JSON
            
        Returns:
            ServiceStrategy object or None if conversion fails
        """
        try:
            # Extract required fields with defaults
            attack_name = strategy_data.get('attack_name', 'unknown')
            strategy_command = strategy_data.get('strategy', '')
            success_rate = float(strategy_data.get('success_rate', 0.0))
            avg_latency_ms = float(strategy_data.get('avg_latency_ms', 0.0))
            domains = strategy_data.get('domains', [])
            bypass_effective = bool(strategy_data.get('bypass_effective', False))
            timestamp = float(strategy_data.get('timestamp', time.time()))
            
            # Extract parameters from task or metadata
            parameters = {}
            if 'task' in strategy_data and isinstance(strategy_data['task'], dict):
                parameters.update(strategy_data['task'].get('params', {}))
            if 'metadata' in strategy_data and isinstance(strategy_data['metadata'], dict):
                parameters.update(strategy_data['metadata'])
            
            # Create ServiceStrategy object
            service_strategy = ServiceStrategy(
                fingerprint_hash=fingerprint_hash,
                attack_name=attack_name,
                strategy_command=strategy_command,
                success_rate=success_rate,
                avg_latency_ms=avg_latency_ms,
                domains=domains if isinstance(domains, list) else [],
                parameters=parameters,
                bypass_effective=bypass_effective,
                timestamp=timestamp,
                validated=False
            )
            
            return service_strategy
            
        except Exception as e:
            LOG.error(f"Error converting strategy data for {fingerprint_hash}: {e}")
            return None   
 
    def _validate_strategy_data(self, strategy: ServiceStrategy) -> bool:
        """
        Validate strategy data for service use.
        
        Args:
            strategy: ServiceStrategy to validate
            
        Returns:
            True if strategy is valid for service use
        """
        try:
            # Check required fields
            if not strategy.attack_name or strategy.attack_name == 'unknown':
                LOG.warning(f"Strategy {strategy.fingerprint_hash} has invalid attack name")
                return False
            
            # Check success rate
            if strategy.success_rate < self.min_success_rate:
                LOG.warning(f"Strategy {strategy.fingerprint_hash} has low success rate: {strategy.success_rate}")
                return False
            
            # Check latency (if bypass is effective, latency should be reasonable)
            if strategy.bypass_effective and strategy.avg_latency_ms > self.max_latency_ms:
                LOG.warning(f"Strategy {strategy.fingerprint_hash} has high latency: {strategy.avg_latency_ms}ms")
                return False
            
            # Check if strategy is actually effective
            if not strategy.bypass_effective:
                LOG.warning(f"Strategy {strategy.fingerprint_hash} is not marked as bypass effective")
                return False
            
            # Check domains
            if not strategy.domains:
                LOG.warning(f"Strategy {strategy.fingerprint_hash} has no associated domains")
                return False
            
            # Mark as validated
            strategy.validated = True
            return True
            
        except Exception as e:
            LOG.error(f"Error validating strategy {strategy.fingerprint_hash}: {e}")
            return False
    
    def _update_domain_mapping(self, strategy: ServiceStrategy) -> None:
        """
        Update domain to strategy mapping.
        
        Args:
            strategy: ServiceStrategy to map
        """
        try:
            for domain in strategy.domains:
                if domain and isinstance(domain, str):
                    self.domain_strategy_mapping[domain] = strategy.fingerprint_hash
                    
        except Exception as e:
            LOG.error(f"Error updating domain mapping for strategy {strategy.fingerprint_hash}: {e}")
    
    def get_strategy_for_domain(self, domain: str) -> Optional[ServiceStrategy]:
        """
        Get the best strategy for a specific domain.
        
        Args:
            domain: Domain name to get strategy for
            
        Returns:
            ServiceStrategy object or None if no strategy found
        """
        try:
            # Ensure strategies are loaded
            if not self.loaded_strategies:
                self.load_strategies_for_service()
            
            # Check direct domain mapping
            if domain in self.domain_strategy_mapping:
                fingerprint_hash = self.domain_strategy_mapping[domain]
                return self.loaded_strategies.get(fingerprint_hash)
            
            # Check for partial domain matches (e.g., subdomain matches)
            for mapped_domain, fingerprint_hash in self.domain_strategy_mapping.items():
                if domain.endswith(mapped_domain) or mapped_domain.endswith(domain):
                    return self.loaded_strategies.get(fingerprint_hash)
            
            LOG.debug(f"No strategy found for domain {domain}")
            return None
            
        except Exception as e:
            LOG.error(f"Error getting strategy for domain {domain}: {e}")
            return None 
   
    def get_all_strategies(self) -> Dict[str, ServiceStrategy]:
        """
        Get all loaded strategies.
        
        Returns:
            Dict mapping fingerprint hash to ServiceStrategy objects
        """
        if not self.loaded_strategies:
            return self.load_strategies_for_service()
        return self.loaded_strategies.copy()
    
    def reload_strategies(self) -> bool:
        """
        Force reload strategies from file.
        
        Returns:
            True if reload was successful
        """
        try:
            self.last_load_time = 0  # Force reload
            self.loaded_strategies.clear()
            self.domain_strategy_mapping.clear()
            
            strategies = self.load_strategies_for_service()
            return len(strategies) > 0
            
        except Exception as e:
            LOG.error(f"Error reloading strategies: {e}")
            return False
    
    def get_load_errors(self) -> List[str]:
        """
        Get list of errors that occurred during loading.
        
        Returns:
            List of error messages
        """
        return self.load_errors.copy()
    
    def get_strategy_stats(self) -> Dict[str, Any]:
        """
        Get statistics about loaded strategies.
        
        Returns:
            Dict with strategy statistics
        """
        try:
            if not self.loaded_strategies:
                self.load_strategies_for_service()
            
            total_strategies = len(self.loaded_strategies)
            validated_strategies = sum(1 for s in self.loaded_strategies.values() if s.validated)
            effective_strategies = sum(1 for s in self.loaded_strategies.values() if s.bypass_effective)
            total_domains = len(self.domain_strategy_mapping)
            
            avg_success_rate = 0.0
            avg_latency = 0.0
            if self.loaded_strategies:
                avg_success_rate = sum(s.success_rate for s in self.loaded_strategies.values()) / total_strategies
                avg_latency = sum(s.avg_latency_ms for s in self.loaded_strategies.values()) / total_strategies
            
            return {
                'total_strategies': total_strategies,
                'validated_strategies': validated_strategies,
                'effective_strategies': effective_strategies,
                'total_domains': total_domains,
                'avg_success_rate': avg_success_rate,
                'avg_latency_ms': avg_latency,
                'last_load_time': self.last_load_time,
                'load_errors': len(self.load_errors)
            }
            
        except Exception as e:
            LOG.error(f"Error getting strategy stats: {e}")
            return {}