"""
Configuration data models for bypass engine modernization.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
import json


class ConfigurationVersion(Enum):
    """Configuration format versions."""
    LEGACY_V1 = "legacy_v1"  # Original best_strategy.json format
    POOL_V1 = "pool_v1"      # New pool-based format
    POOL_V2 = "pool_v2"      # Enhanced pool format with subdomains


@dataclass
class LegacyConfiguration:
    """Legacy best_strategy.json configuration format."""
    strategy: str
    result_status: str = "UNKNOWN"
    successful_sites: int = 0
    total_sites: int = 0
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    fingerprint_used: bool = False
    dpi_type: str = "unknown"
    dpi_confidence: float = 0.0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LegacyConfiguration':
        """Create from dictionary."""
        return cls(
            strategy=data.get('strategy', ''),
            result_status=data.get('result_status', 'UNKNOWN'),
            successful_sites=data.get('successful_sites', 0),
            total_sites=data.get('total_sites', 0),
            success_rate=data.get('success_rate', 0.0),
            avg_latency_ms=data.get('avg_latency_ms', 0.0),
            fingerprint_used=data.get('fingerprint_used', False),
            dpi_type=data.get('dpi_type', 'unknown'),
            dpi_confidence=data.get('dpi_confidence', 0.0)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'strategy': self.strategy,
            'result_status': self.result_status,
            'successful_sites': self.successful_sites,
            'total_sites': self.total_sites,
            'success_rate': self.success_rate,
            'avg_latency_ms': self.avg_latency_ms,
            'fingerprint_used': self.fingerprint_used,
            'dpi_type': self.dpi_type,
            'dpi_confidence': self.dpi_confidence
        }


@dataclass
class BypassStrategy:
    """Enhanced bypass strategy definition."""
    id: str
    name: str
    attacks: List[str]  # Attack IDs from registry
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_ports: List[int] = field(default_factory=lambda: [443])
    subdomain_overrides: Dict[str, 'BypassStrategy'] = field(default_factory=dict)
    compatibility_mode: str = "native"
    priority: int = 1
    success_rate: float = 0.0
    last_tested: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'attacks': self.attacks,
            'parameters': self.parameters,
            'target_ports': self.target_ports,
            'subdomain_overrides': {k: v.to_dict() for k, v in self.subdomain_overrides.items()},
            'compatibility_mode': self.compatibility_mode,
            'priority': self.priority,
            'success_rate': self.success_rate,
            'last_tested': self.last_tested.isoformat() if self.last_tested else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BypassStrategy':
        """Create from dictionary."""
        subdomain_overrides = {}
        for k, v in data.get('subdomain_overrides', {}).items():
            subdomain_overrides[k] = cls.from_dict(v)
        
        return cls(
            id=data['id'],
            name=data['name'],
            attacks=data.get('attacks', []),
            parameters=data.get('parameters', {}),
            target_ports=data.get('target_ports', [443]),
            subdomain_overrides=subdomain_overrides,
            compatibility_mode=data.get('compatibility_mode', 'native'),
            priority=data.get('priority', 1),
            success_rate=data.get('success_rate', 0.0),
            last_tested=datetime.fromisoformat(data['last_tested']) if data.get('last_tested') else None
        )


@dataclass
class DomainRule:
    """Rule for automatic domain assignment to pools."""
    pattern: str  # Regex pattern for domain matching
    pool_id: str
    priority: int
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'pattern': self.pattern,
            'pool_id': self.pool_id,
            'priority': self.priority,
            'conditions': self.conditions
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DomainRule':
        """Create from dictionary."""
        return cls(
            pattern=data['pattern'],
            pool_id=data['pool_id'],
            priority=data['priority'],
            conditions=data.get('conditions', {})
        )


@dataclass
class StrategyPool:
    """Strategy pool for domain grouping."""
    id: str
    name: str
    description: str
    strategy: BypassStrategy
    domains: List[str] = field(default_factory=list)
    subdomains: Dict[str, BypassStrategy] = field(default_factory=dict)
    ports: Dict[int, BypassStrategy] = field(default_factory=dict)
    priority: int = 1
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'strategy': self.strategy.to_dict(),
            'domains': self.domains,
            'subdomains': {k: v.to_dict() for k, v in self.subdomains.items()},
            'ports': {str(k): v.to_dict() for k, v in self.ports.items()},
            'priority': self.priority,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StrategyPool':
        """Create from dictionary."""
        subdomains = {}
        for k, v in data.get('subdomains', {}).items():
            subdomains[k] = BypassStrategy.from_dict(v)
        
        ports = {}
        for k, v in data.get('ports', {}).items():
            ports[int(k)] = BypassStrategy.from_dict(v)
        
        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            strategy=BypassStrategy.from_dict(data['strategy']),
            domains=data.get('domains', []),
            subdomains=subdomains,
            ports=ports,
            priority=data.get('priority', 1),
            created_at=datetime.fromisoformat(data['created_at']),
            updated_at=datetime.fromisoformat(data['updated_at'])
        )


@dataclass
class PoolConfiguration:
    """Complete pool-based configuration."""
    version: ConfigurationVersion
    pools: List[StrategyPool] = field(default_factory=list)
    default_pool: Optional[str] = None
    fallback_strategy: Optional[BypassStrategy] = None
    auto_assignment_rules: List[DomainRule] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'version': self.version.value,
            'pools': [pool.to_dict() for pool in self.pools],
            'default_pool': self.default_pool,
            'fallback_strategy': self.fallback_strategy.to_dict() if self.fallback_strategy else None,
            'auto_assignment_rules': [rule.to_dict() for rule in self.auto_assignment_rules],
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PoolConfiguration':
        """Create from dictionary."""
        pools = [StrategyPool.from_dict(pool_data) for pool_data in data.get('pools', [])]
        
        fallback_strategy = None
        if data.get('fallback_strategy'):
            fallback_strategy = BypassStrategy.from_dict(data['fallback_strategy'])
        
        auto_assignment_rules = [
            DomainRule.from_dict(rule_data) 
            for rule_data in data.get('auto_assignment_rules', [])
        ]
        
        return cls(
            version=ConfigurationVersion(data.get('version', ConfigurationVersion.POOL_V1.value)),
            pools=pools,
            default_pool=data.get('default_pool'),
            fallback_strategy=fallback_strategy,
            auto_assignment_rules=auto_assignment_rules,
            metadata=data.get('metadata', {}),
            created_at=datetime.fromisoformat(data.get('created_at', datetime.now().isoformat())),
            updated_at=datetime.fromisoformat(data.get('updated_at', datetime.now().isoformat()))
        )
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'PoolConfiguration':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


@dataclass
class MigrationResult:
    """Result of configuration migration."""
    success: bool
    source_version: ConfigurationVersion
    target_version: ConfigurationVersion
    migrated_pools: int = 0
    migrated_domains: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    backup_path: Optional[str] = None
    migration_time: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'success': self.success,
            'source_version': self.source_version.value,
            'target_version': self.target_version.value,
            'migrated_pools': self.migrated_pools,
            'migrated_domains': self.migrated_domains,
            'warnings': self.warnings,
            'errors': self.errors,
            'backup_path': self.backup_path,
            'migration_time': self.migration_time.isoformat()
        }


@dataclass
class ConfigurationBackup:
    """Configuration backup metadata."""
    id: str
    original_path: str
    backup_path: str
    version: ConfigurationVersion
    created_at: datetime
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'original_path': self.original_path,
            'backup_path': self.backup_path,
            'version': self.version.value,
            'created_at': self.created_at.isoformat(),
            'description': self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigurationBackup':
        """Create from dictionary."""
        return cls(
            id=data['id'],
            original_path=data['original_path'],
            backup_path=data['backup_path'],
            version=ConfigurationVersion(data['version']),
            created_at=datetime.fromisoformat(data['created_at']),
            description=data.get('description', '')
        )