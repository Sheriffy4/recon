# recon/core/bypass/attacks/attack_definition.py

"""
Enhanced attack definition system for the modernized bypass engine.
Provides comprehensive metadata and categorization for all attacks.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List, Set
from datetime import datetime


class AttackCategory(Enum):
    """Categories of DPI bypass attacks."""
    TCP_FRAGMENTATION = "tcp_fragmentation"
    HTTP_MANIPULATION = "http_manipulation"
    TLS_EVASION = "tls_evasion"
    DNS_TUNNELING = "dns_tunneling"
    PACKET_TIMING = "packet_timing"
    PROTOCOL_OBFUSCATION = "protocol_obfuscation"
    HEADER_MODIFICATION = "header_modification"
    PAYLOAD_SCRAMBLING = "payload_scrambling"
    COMBO_ATTACK = "combo_attack"
    EXPERIMENTAL = "experimental"


class AttackComplexity(Enum):
    """Complexity levels for attacks."""
    SIMPLE = 1      # Basic attacks with minimal parameters
    MODERATE = 2    # Medium complexity attacks
    ADVANCED = 3    # Advanced attacks requiring careful tuning
    EXPERT = 4      # Expert-level attacks with complex parameters
    EXPERIMENTAL = 5 # Experimental attacks that may be unstable


class AttackStability(Enum):
    """Stability levels for attacks."""
    STABLE = "stable"           # Well-tested, reliable attacks
    MOSTLY_STABLE = "mostly_stable"  # Generally stable with minor issues
    UNSTABLE = "unstable"       # Known stability issues
    EXPERIMENTAL = "experimental"    # Experimental, may cause problems
    DEPRECATED = "deprecated"   # No longer recommended for use


class CompatibilityMode(Enum):
    """Compatibility modes with external tools."""
    ZAPRET = "zapret"
    GOODBYEDPI = "goodbyedpi"
    BYEBYEDPI = "byebyedpi"
    NATIVE = "native"
    UNIVERSAL = "universal"


@dataclass
class TestCase:
    """Test case definition for attack validation."""
    id: str
    name: str
    description: str
    target_domain: str
    expected_success: bool
    test_parameters: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 30
    validation_criteria: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.validation_criteria:
            self.validation_criteria = ["http_response", "content_check"]


@dataclass
class AttackDefinition:
    """
    Comprehensive attack definition with metadata.
    Contains all information needed for attack registration, execution, and testing.
    """
    
    # Basic identification
    id: str
    name: str
    description: str
    category: AttackCategory
    complexity: AttackComplexity
    stability: AttackStability
    
    # Technical specifications
    parameters: Dict[str, Any] = field(default_factory=dict)
    default_parameters: Dict[str, Any] = field(default_factory=dict)
    required_parameters: List[str] = field(default_factory=list)
    
    # Compatibility information
    compatibility: List[CompatibilityMode] = field(default_factory=list)
    external_tool_mappings: Dict[str, str] = field(default_factory=dict)
    
    # Performance and reliability metrics
    stability_score: float = 0.0  # 0.0 to 1.0
    effectiveness_score: float = 0.0  # 0.0 to 1.0
    performance_score: float = 0.0  # 0.0 to 1.0
    
    # Testing information
    test_cases: List[TestCase] = field(default_factory=list)
    last_tested: Optional[datetime] = None
    test_results: Dict[str, Any] = field(default_factory=dict)
    
    # Operational information
    enabled: bool = True
    deprecated: bool = False
    deprecation_reason: Optional[str] = None
    replacement_attack: Optional[str] = None
    
    # Protocol and port specifications
    supported_protocols: List[str] = field(default_factory=lambda: ["tcp"])
    supported_ports: List[int] = field(default_factory=lambda: [80, 443])
    requires_handshake: bool = False
    
    # Dependencies and requirements
    dependencies: List[str] = field(default_factory=list)
    conflicts_with: List[str] = field(default_factory=list)
    requires_root: bool = False
    platform_specific: List[str] = field(default_factory=list)
    
    # Documentation and examples
    documentation_url: Optional[str] = None
    examples: List[Dict[str, Any]] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    version: str = "1.0.0"
    author: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization validation and setup."""
        # Ensure tags is a set
        if isinstance(self.tags, list):
            self.tags = set(self.tags)
        
        # Set default compatibility if none specified
        if not self.compatibility:
            self.compatibility = [CompatibilityMode.NATIVE]
        
        # Validate scores are in valid range
        self._validate_scores()
        
        # Set updated_at to now
        self.updated_at = datetime.now()
    
    def _validate_scores(self):
        """Validate that all scores are in the valid range [0.0, 1.0]."""
        for score_name in ['stability_score', 'effectiveness_score', 'performance_score']:
            score = getattr(self, score_name)
            if not (0.0 <= score <= 1.0):
                setattr(self, score_name, max(0.0, min(1.0, score)))
    
    def add_test_case(self, test_case: TestCase) -> None:
        """Add a test case to this attack definition."""
        if test_case not in self.test_cases:
            self.test_cases.append(test_case)
            self.updated_at = datetime.now()
    
    def remove_test_case(self, test_case_id: str) -> bool:
        """Remove a test case by ID. Returns True if removed, False if not found."""
        for i, test_case in enumerate(self.test_cases):
            if test_case.id == test_case_id:
                del self.test_cases[i]
                self.updated_at = datetime.now()
                return True
        return False
    
    def get_test_case(self, test_case_id: str) -> Optional[TestCase]:
        """Get a test case by ID."""
        for test_case in self.test_cases:
            if test_case.id == test_case_id:
                return test_case
        return None
    
    def update_scores(self, stability: float = None, effectiveness: float = None, performance: float = None) -> None:
        """Update performance scores."""
        if stability is not None:
            self.stability_score = max(0.0, min(1.0, stability))
        if effectiveness is not None:
            self.effectiveness_score = max(0.0, min(1.0, effectiveness))
        if performance is not None:
            self.performance_score = max(0.0, min(1.0, performance))
        self.updated_at = datetime.now()
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to this attack."""
        self.tags.add(tag)
        self.updated_at = datetime.now()
    
    def remove_tag(self, tag: str) -> bool:
        """Remove a tag from this attack. Returns True if removed, False if not found."""
        if tag in self.tags:
            self.tags.remove(tag)
            self.updated_at = datetime.now()
            return True
        return False
    
    def has_tag(self, tag: str) -> bool:
        """Check if attack has a specific tag."""
        return tag in self.tags
    
    def is_compatible_with(self, mode: CompatibilityMode) -> bool:
        """Check if attack is compatible with a specific mode."""
        return mode in self.compatibility or CompatibilityMode.UNIVERSAL in self.compatibility
    
    def supports_protocol(self, protocol: str) -> bool:
        """Check if attack supports a specific protocol."""
        return protocol.lower() in [p.lower() for p in self.supported_protocols]
    
    def supports_port(self, port: int) -> bool:
        """Check if attack supports a specific port."""
        return port in self.supported_ports
    
    def can_run_on_platform(self, platform: str) -> bool:
        """Check if attack can run on a specific platform."""
        if not self.platform_specific:
            return True  # No platform restrictions
        return platform.lower() in [p.lower() for p in self.platform_specific]
    
    def has_conflicts_with(self, other_attack_id: str) -> bool:
        """Check if this attack conflicts with another attack."""
        return other_attack_id in self.conflicts_with
    
    def get_external_tool_mapping(self, tool: str) -> Optional[str]:
        """Get the external tool mapping for a specific tool."""
        return self.external_tool_mappings.get(tool)
    
    def set_external_tool_mapping(self, tool: str, mapping: str) -> None:
        """Set an external tool mapping."""
        self.external_tool_mappings[tool] = mapping
        self.updated_at = datetime.now()
    
    def deprecate(self, reason: str, replacement: str = None) -> None:
        """Mark this attack as deprecated."""
        self.deprecated = True
        self.deprecation_reason = reason
        self.replacement_attack = replacement
        self.enabled = False
        self.updated_at = datetime.now()
    
    def enable(self) -> None:
        """Enable this attack."""
        if not self.deprecated:
            self.enabled = True
            self.updated_at = datetime.now()
    
    def disable(self) -> None:
        """Disable this attack."""
        self.enabled = False
        self.updated_at = datetime.now()
    
    def get_overall_score(self) -> float:
        """Calculate overall score based on stability, effectiveness, and performance."""
        # Weighted average: stability is most important, then effectiveness, then performance
        weights = {'stability': 0.5, 'effectiveness': 0.3, 'performance': 0.2}
        return (
            self.stability_score * weights['stability'] +
            self.effectiveness_score * weights['effectiveness'] +
            self.performance_score * weights['performance']
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert attack definition to dictionary for serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category.value,
            'complexity': self.complexity.value,
            'stability': self.stability.value,
            'parameters': self.parameters,
            'default_parameters': self.default_parameters,
            'required_parameters': self.required_parameters,
            'compatibility': [c.value for c in self.compatibility],
            'external_tool_mappings': self.external_tool_mappings,
            'stability_score': self.stability_score,
            'effectiveness_score': self.effectiveness_score,
            'performance_score': self.performance_score,
            'overall_score': self.get_overall_score(),
            'test_cases': [
                {
                    'id': tc.id,
                    'name': tc.name,
                    'description': tc.description,
                    'target_domain': tc.target_domain,
                    'expected_success': tc.expected_success,
                    'test_parameters': tc.test_parameters,
                    'timeout_seconds': tc.timeout_seconds,
                    'validation_criteria': tc.validation_criteria
                }
                for tc in self.test_cases
            ],
            'last_tested': self.last_tested.isoformat() if self.last_tested else None,
            'test_results': self.test_results,
            'enabled': self.enabled,
            'deprecated': self.deprecated,
            'deprecation_reason': self.deprecation_reason,
            'replacement_attack': self.replacement_attack,
            'supported_protocols': self.supported_protocols,
            'supported_ports': self.supported_ports,
            'requires_handshake': self.requires_handshake,
            'dependencies': self.dependencies,
            'conflicts_with': self.conflicts_with,
            'requires_root': self.requires_root,
            'platform_specific': self.platform_specific,
            'documentation_url': self.documentation_url,
            'examples': self.examples,
            'tags': list(self.tags),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'version': self.version,
            'author': self.author
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackDefinition':
        """Create attack definition from dictionary."""
        # Convert enum values back to enums
        category = AttackCategory(data['category'])
        complexity = AttackComplexity(data['complexity'])
        stability = AttackStability(data['stability'])
        compatibility = [CompatibilityMode(c) for c in data.get('compatibility', [])]
        
        # Convert test cases
        test_cases = []
        for tc_data in data.get('test_cases', []):
            test_case = TestCase(
                id=tc_data['id'],
                name=tc_data['name'],
                description=tc_data['description'],
                target_domain=tc_data['target_domain'],
                expected_success=tc_data['expected_success'],
                test_parameters=tc_data.get('test_parameters', {}),
                timeout_seconds=tc_data.get('timeout_seconds', 30),
                validation_criteria=tc_data.get('validation_criteria', [])
            )
            test_cases.append(test_case)
        
        # Convert datetime strings
        created_at = datetime.fromisoformat(data['created_at']) if data.get('created_at') else datetime.now()
        updated_at = datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else datetime.now()
        last_tested = datetime.fromisoformat(data['last_tested']) if data.get('last_tested') else None
        
        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            category=category,
            complexity=complexity,
            stability=stability,
            parameters=data.get('parameters', {}),
            default_parameters=data.get('default_parameters', {}),
            required_parameters=data.get('required_parameters', []),
            compatibility=compatibility,
            external_tool_mappings=data.get('external_tool_mappings', {}),
            stability_score=data.get('stability_score', 0.0),
            effectiveness_score=data.get('effectiveness_score', 0.0),
            performance_score=data.get('performance_score', 0.0),
            test_cases=test_cases,
            last_tested=last_tested,
            test_results=data.get('test_results', {}),
            enabled=data.get('enabled', True),
            deprecated=data.get('deprecated', False),
            deprecation_reason=data.get('deprecation_reason'),
            replacement_attack=data.get('replacement_attack'),
            supported_protocols=data.get('supported_protocols', ['tcp']),
            supported_ports=data.get('supported_ports', [80, 443]),
            requires_handshake=data.get('requires_handshake', False),
            dependencies=data.get('dependencies', []),
            conflicts_with=data.get('conflicts_with', []),
            requires_root=data.get('requires_root', False),
            platform_specific=data.get('platform_specific', []),
            documentation_url=data.get('documentation_url'),
            examples=data.get('examples', []),
            tags=set(data.get('tags', [])),
            created_at=created_at,
            updated_at=updated_at,
            version=data.get('version', '1.0.0'),
            author=data.get('author')
        )
    
    def __str__(self) -> str:
        """String representation of attack definition."""
        return f"AttackDefinition(id='{self.id}', name='{self.name}', category={self.category.value}, complexity={self.complexity.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation."""
        return (f"AttackDefinition(id='{self.id}', name='{self.name}', "
                f"category={self.category.value}, complexity={self.complexity.value}, "
                f"stability={self.stability.value}, enabled={self.enabled}, "
                f"overall_score={self.get_overall_score():.2f})")