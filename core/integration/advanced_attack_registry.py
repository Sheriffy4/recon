#!/usr/bin/env python3
"""
Advanced Attack Registry - Registry system for managing and discovering advanced attacks.
"""

import logging
from typing import Dict, List, Optional, Type, Any
from dataclasses import dataclass
from datetime import datetime

# Import base classes - avoid circular import
ADVANCED_ATTACK_BASE_AVAILABLE = True
try:
    # We'll import these when needed to avoid circular imports
    pass
except ImportError:
    ADVANCED_ATTACK_BASE_AVAILABLE = False
    logging.warning("Advanced attack base classes not available")

LOG = logging.getLogger("advanced_attack_registry")

@dataclass
class AttackRegistration:
    """Registration information for an advanced attack."""
    attack_class: Type[Any]  # Will be AdvancedAttack when imported
    config: Any  # Will be AdvancedAttackConfig when imported
    registration_time: datetime
    enabled: bool = True
    metadata: Dict[str, Any] = None

class AdvancedAttackRegistry:
    """
    Registry system for managing and discovering advanced attacks.
    Provides attack discovery, selection, and lifecycle management.
    """
    
    def __init__(self):
        self.registered_attacks: Dict[str, AttackRegistration] = {}
        self.attack_instances: Dict[str, Any] = {}
        self.signature_mappings: Dict[str, List[str]] = {}  # DPI signature -> attack names
        self.protocol_mappings: Dict[str, List[str]] = {}   # Protocol -> attack names
        
        LOG.info("Advanced Attack Registry initialized")
    
    def register_attack(self, 
                       attack_class: Type[Any], 
                       config: Any,
                       metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Register an advanced attack class.
        
        Args:
            attack_class: The attack class to register
            config: Attack configuration
            metadata: Optional metadata
            
        Returns:
            True if registration successful, False otherwise
        """
        
        if not ADVANCED_ATTACK_BASE_AVAILABLE:
            LOG.error("Cannot register attack: base classes not available")
            return False
        
        attack_name = config.name
        
        if attack_name in self.registered_attacks:
            LOG.warning(f"Attack {attack_name} already registered, updating")
        
        try:
            # Create registration
            registration = AttackRegistration(
                attack_class=attack_class,
                config=config,
                registration_time=datetime.now(),
                enabled=True,
                metadata=metadata or {}
            )
            
            # Store registration
            self.registered_attacks[attack_name] = registration
            
            # Update signature mappings
            for signature in config.dpi_signatures:
                if signature not in self.signature_mappings:
                    self.signature_mappings[signature] = []
                if attack_name not in self.signature_mappings[signature]:
                    self.signature_mappings[signature].append(attack_name)
            
            # Update protocol mappings
            for protocol in config.target_protocols:
                if protocol not in self.protocol_mappings:
                    self.protocol_mappings[protocol] = []
                if attack_name not in self.protocol_mappings[protocol]:
                    self.protocol_mappings[protocol].append(attack_name)
            
            LOG.info(f"Registered advanced attack: {attack_name} (priority: {config.priority})")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to register attack {attack_name}: {e}")
            return False
    
    def get_attacks_for_signature(self, signature: Any) -> List[Any]:
        """
        Get attacks suitable for a specific DPI signature.
        
        Args:
            signature: DPI signature to match against
            
        Returns:
            List of suitable AdvancedAttack instances
        """
        
        suitable_attacks = []
        
        # Find attacks by DPI type
        attack_names = self.signature_mappings.get(signature.dpi_type, [])
        
        # Also check for attacks that handle "all" signatures
        attack_names.extend(self.signature_mappings.get("all", []))
        
        # Remove duplicates
        attack_names = list(set(attack_names))
        
        for attack_name in attack_names:
            attack_instance = self.get_attack_instance(attack_name)
            if attack_instance and attack_instance.enabled:
                # Additional filtering based on sophistication level
                if self._is_attack_suitable_for_sophistication(
                    attack_instance, signature.sophistication_level
                ):
                    suitable_attacks.append(attack_instance)
        
        # Sort by priority (lower number = higher priority)
        suitable_attacks.sort(key=lambda a: a.config.priority)
        
        LOG.debug(f"Found {len(suitable_attacks)} attacks for DPI signature: {signature.dpi_type}")
        return suitable_attacks
    
    def get_attacks_for_protocol(self, protocol: str) -> List[Any]:
        """
        Get attacks suitable for a specific protocol.
        
        Args:
            protocol: Protocol to match against
            
        Returns:
            List of suitable AdvancedAttack instances
        """
        
        suitable_attacks = []
        attack_names = self.protocol_mappings.get(protocol, [])
        
        for attack_name in attack_names:
            attack_instance = self.get_attack_instance(attack_name)
            if attack_instance and attack_instance.enabled:
                suitable_attacks.append(attack_instance)
        
        # Sort by priority
        suitable_attacks.sort(key=lambda a: a.config.priority)
        
        LOG.debug(f"Found {len(suitable_attacks)} attacks for protocol: {protocol}")
        return suitable_attacks
    
    def get_attack_by_name(self, name: str) -> Optional[Any]:
        """
        Get attack instance by name.
        
        Args:
            name: Attack name
            
        Returns:
            AdvancedAttack instance or None
        """
        
        return self.get_attack_instance(name)
    
    def get_attack_instance(self, attack_name: str) -> Optional[Any]:
        """
        Get or create attack instance.
        
        Args:
            attack_name: Name of the attack
            
        Returns:
            AdvancedAttack instance or None
        """
        
        if attack_name not in self.registered_attacks:
            LOG.warning(f"Attack {attack_name} not registered")
            return None
        
        # Return cached instance if available
        if attack_name in self.attack_instances:
            return self.attack_instances[attack_name]
        
        # Create new instance
        try:
            registration = self.registered_attacks[attack_name]
            attack_instance = registration.attack_class(registration.config)
            
            # Cache the instance
            self.attack_instances[attack_name] = attack_instance
            
            LOG.debug(f"Created attack instance: {attack_name}")
            return attack_instance
            
        except Exception as e:
            LOG.error(f"Failed to create attack instance {attack_name}: {e}")
            return None
    
    def get_all_attacks(self) -> List[Any]:
        """
        Get all registered attack instances.
        
        Returns:
            List of all AdvancedAttack instances
        """
        
        all_attacks = []
        
        for attack_name in self.registered_attacks.keys():
            attack_instance = self.get_attack_instance(attack_name)
            if attack_instance:
                all_attacks.append(attack_instance)
        
        # Sort by priority
        all_attacks.sort(key=lambda a: a.config.priority)
        
        return all_attacks
    
    def get_enabled_attacks(self) -> List[Any]:
        """
        Get all enabled attack instances.
        
        Returns:
            List of enabled AdvancedAttack instances
        """
        
        enabled_attacks = []
        
        for attack_name, registration in self.registered_attacks.items():
            if registration.enabled:
                attack_instance = self.get_attack_instance(attack_name)
                if attack_instance and attack_instance.enabled:
                    enabled_attacks.append(attack_instance)
        
        # Sort by priority
        enabled_attacks.sort(key=lambda a: a.config.priority)
        
        return enabled_attacks
    
    def enable_attack(self, attack_name: str) -> bool:
        """
        Enable an attack.
        
        Args:
            attack_name: Name of the attack to enable
            
        Returns:
            True if successful, False otherwise
        """
        
        if attack_name not in self.registered_attacks:
            LOG.warning(f"Cannot enable unknown attack: {attack_name}")
            return False
        
        # Enable in registration
        self.registered_attacks[attack_name].enabled = True
        
        # Enable instance if it exists
        if attack_name in self.attack_instances:
            self.attack_instances[attack_name].enabled = True
        
        LOG.info(f"Enabled attack: {attack_name}")
        return True
    
    def disable_attack(self, attack_name: str) -> bool:
        """
        Disable an attack.
        
        Args:
            attack_name: Name of the attack to disable
            
        Returns:
            True if successful, False otherwise
        """
        
        if attack_name not in self.registered_attacks:
            LOG.warning(f"Cannot disable unknown attack: {attack_name}")
            return False
        
        # Disable in registration
        self.registered_attacks[attack_name].enabled = False
        
        # Disable instance if it exists
        if attack_name in self.attack_instances:
            self.attack_instances[attack_name].enabled = False
        
        LOG.info(f"Disabled attack: {attack_name}")
        return True
    
    def unregister_attack(self, attack_name: str) -> bool:
        """
        Unregister an attack.
        
        Args:
            attack_name: Name of the attack to unregister
            
        Returns:
            True if successful, False otherwise
        """
        
        if attack_name not in self.registered_attacks:
            LOG.warning(f"Cannot unregister unknown attack: {attack_name}")
            return False
        
        try:
            registration = self.registered_attacks[attack_name]
            
            # Remove from signature mappings
            for signature in registration.config.dpi_signatures:
                if signature in self.signature_mappings:
                    if attack_name in self.signature_mappings[signature]:
                        self.signature_mappings[signature].remove(attack_name)
                    if not self.signature_mappings[signature]:
                        del self.signature_mappings[signature]
            
            # Remove from protocol mappings
            for protocol in registration.config.target_protocols:
                if protocol in self.protocol_mappings:
                    if attack_name in self.protocol_mappings[protocol]:
                        self.protocol_mappings[protocol].remove(attack_name)
                    if not self.protocol_mappings[protocol]:
                        del self.protocol_mappings[protocol]
            
            # Remove registration
            del self.registered_attacks[attack_name]
            
            # Remove instance if cached
            if attack_name in self.attack_instances:
                del self.attack_instances[attack_name]
            
            LOG.info(f"Unregistered attack: {attack_name}")
            return True
            
        except Exception as e:
            LOG.error(f"Failed to unregister attack {attack_name}: {e}")
            return False
    
    def _is_attack_suitable_for_sophistication(self, 
                                             attack: Any, 
                                             sophistication_level: str) -> bool:
        """
        Check if attack is suitable for DPI sophistication level.
        
        Args:
            attack: AdvancedAttack instance
            sophistication_level: DPI sophistication level
            
        Returns:
            True if suitable, False otherwise
        """
        
        # Map sophistication levels to complexity requirements
        sophistication_to_complexity = {
            "basic": ["Low", "Medium", "High"],
            "intermediate": ["Medium", "High"],
            "advanced": ["High"],
            "sophisticated": ["High"]
        }
        
        required_complexities = sophistication_to_complexity.get(sophistication_level, ["High"])
        
        return attack.config.complexity in required_complexities
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics.
        
        Returns:
            Dictionary with registry statistics
        """
        
        total_registered = len(self.registered_attacks)
        total_enabled = len([r for r in self.registered_attacks.values() if r.enabled])
        total_instances = len(self.attack_instances)
        
        # Count by complexity
        complexity_counts = {}
        for registration in self.registered_attacks.values():
            complexity = registration.config.complexity
            complexity_counts[complexity] = complexity_counts.get(complexity, 0) + 1
        
        # Count by priority
        priority_counts = {}
        for registration in self.registered_attacks.values():
            priority = registration.config.priority
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
        
        return {
            "total_registered": total_registered,
            "total_enabled": total_enabled,
            "total_instances": total_instances,
            "complexity_distribution": complexity_counts,
            "priority_distribution": priority_counts,
            "signature_mappings": len(self.signature_mappings),
            "protocol_mappings": len(self.protocol_mappings),
            "base_classes_available": ADVANCED_ATTACK_BASE_AVAILABLE
        }
    
    def list_attacks(self) -> List[Dict[str, Any]]:
        """
        List all registered attacks with their information.
        
        Returns:
            List of attack information dictionaries
        """
        
        attacks_info = []
        
        for attack_name, registration in self.registered_attacks.items():
            config = registration.config
            
            # Get instance stats if available
            instance_stats = {}
            if attack_name in self.attack_instances:
                instance = self.attack_instances[attack_name]
                instance_stats = {
                    "executions": instance.stats['executions'],
                    "successes": instance.stats['successes'],
                    "success_rate": instance.get_success_rate(),
                    "average_latency_ms": instance.get_average_latency()
                }
            
            attack_info = {
                "name": attack_name,
                "priority": config.priority,
                "complexity": config.complexity,
                "expected_improvement": config.expected_improvement,
                "target_protocols": config.target_protocols,
                "dpi_signatures": config.dpi_signatures,
                "ml_integration": config.ml_integration,
                "learning_enabled": config.learning_enabled,
                "enabled": registration.enabled,
                "registration_time": registration.registration_time.isoformat(),
                "instance_created": attack_name in self.attack_instances,
                "stats": instance_stats
            }
            
            attacks_info.append(attack_info)
        
        # Sort by priority
        attacks_info.sort(key=lambda x: x["priority"])
        
        return attacks_info
    
    def clear_instances(self):
        """Clear all cached attack instances."""
        
        self.attack_instances.clear()
        LOG.info("Cleared all attack instances")
    
    def reload_attack(self, attack_name: str) -> bool:
        """
        Reload an attack instance.
        
        Args:
            attack_name: Name of the attack to reload
            
        Returns:
            True if successful, False otherwise
        """
        
        if attack_name not in self.registered_attacks:
            LOG.warning(f"Cannot reload unknown attack: {attack_name}")
            return False
        
        try:
            # Remove cached instance
            if attack_name in self.attack_instances:
                del self.attack_instances[attack_name]
            
            # Create new instance
            new_instance = self.get_attack_instance(attack_name)
            
            if new_instance:
                LOG.info(f"Reloaded attack: {attack_name}")
                return True
            else:
                LOG.error(f"Failed to reload attack: {attack_name}")
                return False
                
        except Exception as e:
            LOG.error(f"Error reloading attack {attack_name}: {e}")
            return False

# Global instance for easy access
_global_advanced_attack_registry = None

def get_advanced_attack_registry() -> AdvancedAttackRegistry:
    """Get global advanced attack registry instance."""
    global _global_advanced_attack_registry
    if _global_advanced_attack_registry is None:
        _global_advanced_attack_registry = AdvancedAttackRegistry()
    return _global_advanced_attack_registry