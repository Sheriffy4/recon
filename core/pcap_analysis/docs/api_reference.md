# API Reference

## Table of Contents

1. [Core Classes](#core-classes)
2. [Data Models](#data-models)
3. [Utility Functions](#utility-functions)
4. [CLI Interface](#cli-interface)
5. [Configuration API](#configuration-api)
6. [Extension Points](#extension-points)

## Core Classes

### PCAPComparator

Main class for comparing PCAP files.

```python
class PCAPComparator:
    """Compare PCAP files at packet level."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize PCAP comparator.
        
        Args:
            config: Optional configuration dictionary
        """
    
    def compare_pcaps(self, recon_pcap: str, zapret_pcap: str, 
                     domain: Optional[str] = None) -> ComparisonResult:
        """
        Compare two PCAP files.
        
        Args:
            recon_pcap: Path to recon PCAP file
            zapret_pcap: Path to zapret PCAP file
            domain: Optional domain filter
            
        Returns:
            ComparisonResult with detailed analysis
            
        Raises:
            FileNotFoundError: If PCAP files don't exist
            PCAPParsingError: If PCAP files are corrupted
        """
    
    def extract_packets(self, pcap_file: str, 
                       filter_expr: Optional[str] = None) -> List[PacketInfo]:
        """
        Extract packets from PCAP file.
        
        Args:
            pcap_file: Path to PCAP file
            filter_expr: Optional BPF filter expression
            
        Returns:
            List of PacketInfo objects
        """
    
    def align_sequences(self, recon_packets: List[PacketInfo], 
                       zapret_packets: List[PacketInfo]) -> AlignmentResult:
        """
        Align packet sequences for comparison.
        
        Args:
            recon_packets: Recon packet sequence
            zapret_packets: Zapret packet sequence
            
        Returns:
            AlignmentResult with aligned sequences
        """
```

### StrategyAnalyzer

Analyze DPI bypass strategies.

```python
class StrategyAnalyzer:
    """Analyze DPI bypass strategies from PCAP data."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize strategy analyzer."""
    
    def analyze_strategy_from_pcap(self, pcap_file: str) -> StrategyConfig:
        """
        Extract strategy configuration from PCAP patterns.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            StrategyConfig with detected parameters
        """
    
    def compare_strategies(self, recon_strategy: StrategyConfig, 
                          zapret_strategy: StrategyConfig) -> StrategyDifferences:
        """
        Compare two strategy configurations.
        
        Args:
            recon_strategy: Recon strategy configuration
            zapret_strategy: Zapret strategy configuration
            
        Returns:
            StrategyDifferences with detailed comparison
        """
    
    def validate_strategy_parameters(self, strategy: StrategyConfig) -> ValidationResult:
        """
        Validate strategy parameter correctness.
        
        Args:
            strategy: Strategy configuration to validate
            
        Returns:
            ValidationResult with validation status
        """
```

### PacketSequenceAnalyzer

Analyze packet sequences in detail.

```python
class PacketSequenceAnalyzer:
    """Analyze packet sequences for DPI bypass patterns."""
    
    def analyze_fake_disorder_sequence(self, packets: List[PacketInfo]) -> FakeDisorderAnalysis:
        """
        Analyze fake disorder packet sequence.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            FakeDisorderAnalysis with sequence details
        """
    
    def detect_split_positions(self, packets: List[PacketInfo]) -> List[SplitPosition]:
        """
        Detect packet split positions.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            List of detected split positions
        """
    
    def analyze_ttl_patterns(self, packets: List[PacketInfo]) -> TTLAnalysis:
        """
        Analyze TTL patterns in packet sequence.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            TTLAnalysis with TTL pattern information
        """
```

### DifferenceDetector

Detect and categorize differences.

```python
class DifferenceDetector:
    """Detect critical differences between packet sequences."""
    
    def detect_critical_differences(self, comparison: ComparisonResult) -> List[CriticalDifference]:
        """
        Detect critical differences from comparison result.
        
        Args:
            comparison: Comparison result to analyze
            
        Returns:
            List of critical differences
        """
    
    def prioritize_differences(self, differences: List[CriticalDifference]) -> List[PrioritizedDifference]:
        """
        Prioritize differences by impact and confidence.
        
        Args:
            differences: List of differences to prioritize
            
        Returns:
            List of prioritized differences
        """
    
    def categorize_differences(self, differences: List[CriticalDifference]) -> DifferenceCategories:
        """
        Categorize differences by type.
        
        Args:
            differences: List of differences to categorize
            
        Returns:
            DifferenceCategories with categorized differences
        """
```

### PatternRecognizer

Recognize DPI evasion patterns.

```python
class PatternRecognizer:
    """Recognize DPI evasion patterns and anomalies."""
    
    def recognize_dpi_evasion_patterns(self, packets: List[PacketInfo]) -> List[EvasionPattern]:
        """
        Recognize DPI evasion patterns in packet sequence.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            List of recognized evasion patterns
        """
    
    def detect_anomalies(self, recon_patterns: List[EvasionPattern], 
                        zapret_patterns: List[EvasionPattern]) -> List[Anomaly]:
        """
        Detect anomalies between pattern sets.
        
        Args:
            recon_patterns: Recon evasion patterns
            zapret_patterns: Zapret evasion patterns
            
        Returns:
            List of detected anomalies
        """
    
    def classify_packet_roles(self, packets: List[PacketInfo]) -> Dict[int, PacketRole]:
        """
        Classify role of each packet in sequence.
        
        Args:
            packets: List of packets to classify
            
        Returns:
            Dictionary mapping packet index to role
        """
```

### RootCauseAnalyzer

Analyze root causes of failures.

```python
class RootCauseAnalyzer:
    """Analyze root causes of DPI bypass failures."""
    
    def analyze_failure_causes(self, differences: List[CriticalDifference], 
                              patterns: List[EvasionPattern]) -> List[RootCause]:
        """
        Analyze failure causes from differences and patterns.
        
        Args:
            differences: List of critical differences
            patterns: List of evasion patterns
            
        Returns:
            List of identified root causes
        """
    
    def correlate_with_historical_data(self, causes: List[RootCause], 
                                      summary_data: Dict) -> List[CorrelatedCause]:
        """
        Correlate causes with historical data.
        
        Args:
            causes: List of root causes
            summary_data: Historical summary data
            
        Returns:
            List of correlated causes
        """
    
    def generate_hypotheses(self, causes: List[RootCause]) -> List[Hypothesis]:
        """
        Generate hypotheses for root causes.
        
        Args:
            causes: List of root causes
            
        Returns:
            List of generated hypotheses
        """
```

### FixGenerator

Generate automated code fixes.

```python
class FixGenerator:
    """Generate automated code fixes for identified issues."""
    
    def generate_fixes(self, root_causes: List[RootCause]) -> List[CodeFix]:
        """
        Generate code fixes for root causes.
        
        Args:
            root_causes: List of root causes to fix
            
        Returns:
            List of generated code fixes
        """
    
    def create_strategy_patches(self, strategy_differences: StrategyDifferences) -> List[StrategyPatch]:
        """
        Create patches for strategy differences.
        
        Args:
            strategy_differences: Strategy differences to patch
            
        Returns:
            List of strategy patches
        """
    
    def generate_test_cases(self, fix: CodeFix) -> List[TestCase]:
        """
        Generate test cases for a code fix.
        
        Args:
            fix: Code fix to test
            
        Returns:
            List of test cases
        """
```

### StrategyValidator

Validate generated fixes.

```python
class StrategyValidator:
    """Validate strategy fixes and measure effectiveness."""
    
    def validate_fix(self, fix: CodeFix, test_domains: List[str]) -> ValidationResult:
        """
        Validate a code fix against test domains.
        
        Args:
            fix: Code fix to validate
            test_domains: List of domains to test against
            
        Returns:
            ValidationResult with validation metrics
        """
    
    def test_strategy_effectiveness(self, strategy: StrategyConfig, 
                                   domains: List[str]) -> EffectivenessResult:
        """
        Test strategy effectiveness across domains.
        
        Args:
            strategy: Strategy to test
            domains: List of domains to test
            
        Returns:
            EffectivenessResult with success metrics
        """
    
    def compare_before_after(self, original_results: Dict, 
                            fixed_results: Dict) -> ComparisonResult:
        """
        Compare results before and after fix application.
        
        Args:
            original_results: Results before fix
            fixed_results: Results after fix
            
        Returns:
            ComparisonResult with improvement metrics
        """
```

## Data Models

### PacketInfo

```python
@dataclass
class PacketInfo:
    """Information about a network packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sequence_num: int
    ack_num: int
    ttl: int
    flags: List[str]
    payload_length: int
    payload_hex: str
    checksum: int
    checksum_valid: bool
    is_client_hello: bool
    tls_info: Optional[TLSInfo] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PacketInfo':
        """Create from dictionary."""
    
    def is_fake_packet(self) -> bool:
        """Check if this is a fake packet (low TTL, bad checksum)."""
    
    def get_payload_size(self) -> int:
        """Get payload size in bytes."""
```

### StrategyConfig

```python
@dataclass
class StrategyConfig:
    """DPI bypass strategy configuration."""
    name: str
    dpi_desync: str
    split_pos: Optional[int] = None
    split_seqovl: Optional[int] = None
    ttl: Optional[int] = None
    autottl: Optional[int] = None
    fooling: List[str] = field(default_factory=list)
    fake_tls: Optional[str] = None
    fake_http: Optional[str] = None
    repeats: int = 1
    
    def to_zapret_args(self) -> List[str]:
        """Convert to zapret command line arguments."""
    
    def to_recon_config(self) -> Dict[str, Any]:
        """Convert to recon configuration format."""
    
    def validate(self) -> List[str]:
        """Validate configuration and return error messages."""
```

### ComparisonResult

```python
@dataclass
class ComparisonResult:
    """Result of PCAP comparison."""
    recon_packets: List[PacketInfo]
    zapret_packets: List[PacketInfo]
    differences: List[CriticalDifference]
    similarity_score: float
    analysis_metadata: Dict[str, Any]
    alignment_result: Optional[AlignmentResult] = None
    
    def get_critical_differences(self) -> List[CriticalDifference]:
        """Get only critical differences."""
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comparison summary."""
    
    def export_to_json(self) -> str:
        """Export to JSON format."""
```

### CriticalDifference

```python
@dataclass
class CriticalDifference:
    """A critical difference between recon and zapret."""
    id: str
    category: str  # 'sequence', 'timing', 'checksum', 'ttl', 'strategy'
    description: str
    recon_value: Any
    zapret_value: Any
    impact_level: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    confidence: float  # 0.0 to 1.0
    fix_priority: int  # 1 (highest) to 10 (lowest)
    evidence: List[str] = field(default_factory=list)
    
    def is_critical(self) -> bool:
        """Check if difference is critical."""
    
    def get_fix_suggestion(self) -> Optional[str]:
        """Get fix suggestion for this difference."""
```

### CodeFix

```python
@dataclass
class CodeFix:
    """A generated code fix."""
    id: str
    type: str  # 'parameter_change', 'sequence_fix', 'checksum_fix', 'timing_fix'
    description: str
    file_path: str
    function_name: str
    old_code: str
    new_code: str
    test_cases: List[str]
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH'
    confidence: float
    
    def apply(self, backup_dir: str) -> bool:
        """Apply the fix with backup."""
    
    def rollback(self, backup_dir: str) -> bool:
        """Rollback the fix from backup."""
    
    def validate_syntax(self) -> bool:
        """Validate new code syntax."""
```

### ValidationResult

```python
@dataclass
class ValidationResult:
    """Result of fix validation."""
    success: bool
    domains_tested: int
    domains_successful: int
    success_rate: float
    performance_metrics: Dict[str, float]
    error_details: Optional[str] = None
    pcap_generated: Optional[str] = None
    test_duration: float = 0.0
    
    def is_acceptable(self, threshold: float = 0.8) -> bool:
        """Check if validation result is acceptable."""
    
    def get_failed_domains(self) -> List[str]:
        """Get list of domains that failed validation."""
```

## Utility Functions

### PCAP Utilities

```python
def validate_pcap_file(pcap_path: str) -> bool:
    """
    Validate PCAP file integrity.
    
    Args:
        pcap_path: Path to PCAP file
        
    Returns:
        True if valid, False otherwise
    """

def extract_domain_packets(pcap_path: str, domain: str) -> List[PacketInfo]:
    """
    Extract packets for specific domain.
    
    Args:
        pcap_path: Path to PCAP file
        domain: Domain to filter for
        
    Returns:
        List of packets for the domain
    """

def merge_pcap_files(pcap_files: List[str], output_path: str) -> bool:
    """
    Merge multiple PCAP files into one.
    
    Args:
        pcap_files: List of PCAP files to merge
        output_path: Output file path
        
    Returns:
        True if successful, False otherwise
    """

def filter_pcap_by_expression(pcap_path: str, filter_expr: str, 
                             output_path: str) -> bool:
    """
    Filter PCAP file by BPF expression.
    
    Args:
        pcap_path: Input PCAP file
        filter_expr: BPF filter expression
        output_path: Output file path
        
    Returns:
        True if successful, False otherwise
    """
```

### Network Utilities

```python
def resolve_domain_ips(domain: str) -> List[str]:
    """
    Resolve domain to IP addresses.
    
    Args:
        domain: Domain name to resolve
        
    Returns:
        List of IP addresses
    """

def check_connectivity(domain: str, port: int = 443, timeout: int = 10) -> bool:
    """
    Check network connectivity to domain.
    
    Args:
        domain: Domain to check
        port: Port to check
        timeout: Connection timeout
        
    Returns:
        True if reachable, False otherwise
    """

def get_network_interfaces() -> List[str]:
    """
    Get list of available network interfaces.
    
    Returns:
        List of interface names
    """

def capture_packets(interface: str, filter_expr: str, 
                   output_path: str, duration: int = 60) -> bool:
    """
    Capture packets to PCAP file.
    
    Args:
        interface: Network interface to capture on
        filter_expr: BPF filter expression
        output_path: Output PCAP file path
        duration: Capture duration in seconds
        
    Returns:
        True if successful, False otherwise
    """
```

### Analysis Utilities

```python
def calculate_similarity_score(packets1: List[PacketInfo], 
                              packets2: List[PacketInfo]) -> float:
    """
    Calculate similarity score between packet sequences.
    
    Args:
        packets1: First packet sequence
        packets2: Second packet sequence
        
    Returns:
        Similarity score between 0.0 and 1.0
    """

def detect_dpi_patterns(packets: List[PacketInfo]) -> List[str]:
    """
    Detect DPI evasion patterns in packet sequence.
    
    Args:
        packets: Packet sequence to analyze
        
    Returns:
        List of detected pattern names
    """

def extract_tls_info(packet: PacketInfo) -> Optional[TLSInfo]:
    """
    Extract TLS information from packet.
    
    Args:
        packet: Packet to analyze
        
    Returns:
        TLS information if available, None otherwise
    """

def calculate_timing_differences(recon_packets: List[PacketInfo], 
                               zapret_packets: List[PacketInfo]) -> Dict[str, float]:
    """
    Calculate timing differences between packet sequences.
    
    Args:
        recon_packets: Recon packet sequence
        zapret_packets: Zapret packet sequence
        
    Returns:
        Dictionary of timing metrics
    """
```

## CLI Interface

### Main Commands

```python
def compare_command(recon_pcap: str, zapret_pcap: str, **kwargs) -> int:
    """
    Compare two PCAP files.
    
    Args:
        recon_pcap: Path to recon PCAP file
        zapret_pcap: Path to zapret PCAP file
        **kwargs: Additional options
        
    Returns:
        Exit code (0 for success)
    """

def analyze_strategy_command(pcap_file: str, **kwargs) -> int:
    """
    Analyze strategy from PCAP file.
    
    Args:
        pcap_file: Path to PCAP file
        **kwargs: Additional options
        
    Returns:
        Exit code (0 for success)
    """

def generate_fixes_command(analysis_file: str, **kwargs) -> int:
    """
    Generate fixes from analysis results.
    
    Args:
        analysis_file: Path to analysis results file
        **kwargs: Additional options
        
    Returns:
        Exit code (0 for success)
    """

def validate_command(fix_file: str, **kwargs) -> int:
    """
    Validate generated fixes.
    
    Args:
        fix_file: Path to fix file
        **kwargs: Additional options
        
    Returns:
        Exit code (0 for success)
    """
```

### Utility Commands

```python
def doctor_command(**kwargs) -> int:
    """
    Run system diagnostics.
    
    Returns:
        Exit code (0 for success)
    """

def config_command(action: str, **kwargs) -> int:
    """
    Configuration management.
    
    Args:
        action: Configuration action (show, validate, test)
        **kwargs: Additional options
        
    Returns:
        Exit code (0 for success)
    """

def cleanup_command(**kwargs) -> int:
    """
    Clean up temporary files and cache.
    
    Returns:
        Exit code (0 for success)
    """
```

## Configuration API

### Configuration Management

```python
class ConfigManager:
    """Manage application configuration."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration manager."""
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file and environment."""
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
    
    def validate(self) -> List[str]:
        """Validate configuration and return errors."""
    
    def save(self, config_file: str) -> bool:
        """Save configuration to file."""
```

### Environment Integration

```python
def load_environment_config() -> Dict[str, Any]:
    """Load configuration from environment variables."""

def set_environment_defaults() -> None:
    """Set default environment variables."""

def get_config_file_path() -> str:
    """Get configuration file path from environment or defaults."""
```

## Extension Points

### Custom Analyzers

```python
class BaseAnalyzer(ABC):
    """Base class for custom analyzers."""
    
    @abstractmethod
    def analyze(self, data: AnalysisData) -> AnalysisResult:
        """Perform analysis on data."""
    
    def get_name(self) -> str:
        """Get analyzer name."""
    
    def get_version(self) -> str:
        """Get analyzer version."""
```

### Custom Fix Generators

```python
class BaseFixGenerator(ABC):
    """Base class for custom fix generators."""
    
    @abstractmethod
    def can_handle(self, root_cause: RootCause) -> bool:
        """Check if generator can handle root cause."""
    
    @abstractmethod
    def generate_fix(self, root_cause: RootCause) -> CodeFix:
        """Generate fix for root cause."""
    
    def get_priority(self) -> int:
        """Get generator priority (lower = higher priority)."""
```

### Custom Validators

```python
class BaseValidator(ABC):
    """Base class for custom validators."""
    
    @abstractmethod
    def validate(self, fix: CodeFix, context: ValidationContext) -> ValidationResult:
        """Validate a code fix."""
    
    def get_supported_fix_types(self) -> List[str]:
        """Get list of supported fix types."""
```

### Plugin System

```python
class PluginManager:
    """Manage plugins and extensions."""
    
    def register_analyzer(self, name: str, analyzer_class: Type[BaseAnalyzer]) -> None:
        """Register custom analyzer."""
    
    def register_fix_generator(self, name: str, generator_class: Type[BaseFixGenerator]) -> None:
        """Register custom fix generator."""
    
    def register_validator(self, name: str, validator_class: Type[BaseValidator]) -> None:
        """Register custom validator."""
    
    def load_plugins(self, plugin_dir: str) -> None:
        """Load plugins from directory."""
```

This API reference provides comprehensive documentation for all public interfaces and extension points in the PCAP Analysis System.