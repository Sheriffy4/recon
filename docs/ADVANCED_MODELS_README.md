# Advanced DPI Fingerprinting Models - Task 1 Implementation

This document describes the implementation of Task 1 from the Advanced DPI Fingerprinting specification: "Create base fingerprinting infrastructure".

## Overview

The advanced fingerprinting infrastructure provides:

- **DPIFingerprint**: Enhanced dataclass with 20+ detailed metrics
- **Exception Hierarchy**: Robust error handling for fingerprinting operations
- **Enum Classes**: Type-safe DPI classification and confidence levels
- **Comprehensive Testing**: Unit tests for all components

## Components

### 1. DPIFingerprint Dataclass

The `DPIFingerprint` class is the core data structure containing 20+ detailed metrics organized into categories:

#### Basic Information
- `target`: Target domain/IP being analyzed
- `timestamp`: Analysis timestamp
- `analysis_duration`: Time taken for analysis

#### ML Classification Results
- `dpi_type`: Classified DPI type (DPIType enum)
- `confidence`: Classification confidence (0.0-1.0)
- `alternative_types`: Alternative classifications with confidence scores

#### TCP Behavior Metrics (10 metrics)
- `rst_injection_detected`: RST packet injection detection
- `rst_source_analysis`: Source of RST packets (server/middlebox/unknown)
- `tcp_window_manipulation`: TCP window size manipulation
- `sequence_number_anomalies`: TCP sequence number anomalies
- `tcp_options_filtering`: TCP options filtering
- `connection_reset_timing`: Connection reset timing
- `handshake_anomalies`: List of handshake anomalies
- `fragmentation_handling`: IP fragmentation handling
- `mss_clamping_detected`: MSS clamping detection
- `tcp_timestamp_manipulation`: TCP timestamp manipulation

#### HTTP Behavior Metrics (10 metrics)
- `http_header_filtering`: HTTP header filtering
- `content_inspection_depth`: Depth of content inspection
- `user_agent_filtering`: User-Agent header filtering
- `host_header_manipulation`: Host header manipulation
- `http_method_restrictions`: Restricted HTTP methods
- `content_type_filtering`: Content-Type filtering
- `redirect_injection`: HTTP redirect injection
- `http_response_modification`: HTTP response modification
- `keep_alive_manipulation`: Keep-Alive header manipulation
- `chunked_encoding_handling`: Chunked encoding handling

#### DNS Behavior Metrics (10 metrics)
- `dns_hijacking_detected`: DNS hijacking detection
- `dns_response_modification`: DNS response modification
- `dns_query_filtering`: DNS query filtering
- `doh_blocking`: DNS-over-HTTPS blocking
- `dot_blocking`: DNS-over-TLS blocking
- `dns_cache_poisoning`: DNS cache poisoning
- `dns_timeout_manipulation`: DNS timeout manipulation
- `recursive_resolver_blocking`: Recursive resolver blocking
- `dns_over_tcp_blocking`: DNS-over-TCP blocking
- `edns_support`: EDNS support

#### Additional Advanced Metrics (6+ metrics)
- `supports_ipv6`: IPv6 support
- `ip_fragmentation_handling`: IP fragmentation handling
- `packet_size_limitations`: Packet size limitations
- `protocol_whitelist`: Allowed protocols
- `geographic_restrictions`: Geographic restrictions
- `time_based_filtering`: Time-based filtering

### 2. Enum Classes

#### DPIType
Defines the types of DPI systems that can be classified:
- `UNKNOWN`: Unknown DPI type
- `ROSKOMNADZOR_TSPU`: Russian TSPU-based DPI
- `ROSKOMNADZOR_DPI`: Russian DPI systems
- `COMMERCIAL_DPI`: Commercial DPI solutions
- `FIREWALL_BASED`: Firewall-based filtering
- `ISP_TRANSPARENT_PROXY`: ISP transparent proxy
- `CLOUDFLARE_PROTECTION`: Cloudflare protection
- `GOVERNMENT_CENSORSHIP`: Government censorship systems

#### ConfidenceLevel
Defines confidence levels for classifications:
- `VERY_LOW`: 0.2
- `LOW`: 0.4
- `MEDIUM`: 0.6
- `HIGH`: 0.8
- `VERY_HIGH`: 0.9

### 3. Exception Hierarchy

Robust error handling with specialized exceptions:

```
FingerprintingError (base)
├── NetworkAnalysisError
├── MLClassificationError
├── CacheError
└── MetricsCollectionError
```

## Key Methods

### DPIFingerprint Methods

#### Serialization
- `to_dict()`: Convert to dictionary for serialization
- `from_dict(data)`: Create from dictionary
- `to_json()`: Serialize to JSON string
- `from_json(json_str)`: Deserialize from JSON string

#### Analysis
- `get_recommended_strategies()`: Get bypass strategies based on DPI characteristics
- `get_confidence_level()`: Get confidence level enum
- `calculate_evasion_difficulty()`: Calculate evasion difficulty (0.0-1.0)
- `get_summary()`: Get human-readable summary

#### Data Management
- `merge_with(other)`: Merge with another fingerprint
- `validate()`: Validate fingerprint data
- `short_hash()`: Generate unique hash for fingerprint

## Usage Examples

### Basic Usage

```python
from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType

# Create a fingerprint
fp = DPIFingerprint(
    target="example.com",
    dpi_type=DPIType.ROSKOMNADZOR_TSPU,
    confidence=0.85,
    rst_injection_detected=True,
    http_header_filtering=True
)

# Get recommended strategies
strategies = fp.get_recommended_strategies()
print(f"Recommended strategies: {strategies}")

# Get summary
print(f"Summary: {fp.get_summary()}")
```

### Serialization

```python
# Serialize to JSON
json_str = fp.to_json()

# Deserialize from JSON
fp_restored = DPIFingerprint.from_json(json_str)

# Serialize to dictionary
fp_dict = fp.to_dict()

# Deserialize from dictionary
fp_restored = DPIFingerprint.from_dict(fp_dict)
```

### Merging Fingerprints

```python
# Merge two fingerprints
fp1 = DPIFingerprint(target="test.com", confidence=0.6)
fp2 = DPIFingerprint(target="test.com", confidence=0.8)

merged = fp1.merge_with(fp2)
# Uses higher confidence classification and merges metrics
```

### Error Handling

```python
from recon.core.fingerprint.advanced_models import (
    FingerprintingError, NetworkAnalysisError
)

try:
    # Some fingerprinting operation
    pass
except NetworkAnalysisError as e:
    print(f"Network analysis failed: {e}")
except FingerprintingError as e:
    print(f"General fingerprinting error: {e}")
```

## Testing

The implementation includes comprehensive unit tests covering:

- Enum value validation
- Exception hierarchy
- Fingerprint creation and validation
- Serialization/deserialization
- Strategy recommendation
- Confidence level calculation
- Evasion difficulty calculation
- Fingerprint merging
- Data validation

Run tests with:
```bash
cd recon/core/fingerprint
python test_advanced_models.py
python test_integration.py
```

## Requirements Compliance

This implementation satisfies the following requirements from the specification:

- **Requirement 1.1**: ML-Based DPI Classification System
  - Implements DPIType enum for classification
  - Supports confidence scoring and alternative classifications
  
- **Requirement 2.1**: Comprehensive DPI Metrics Collection
  - Implements 20+ detailed metrics across TCP, HTTP, DNS, and advanced categories
  - Supports extensible metric collection through raw_metrics field
  
- **Requirement 7.1**: Backward Compatibility and Data Migration
  - Provides serialization/deserialization for data migration
  - Includes validation methods for data integrity
  - Supports merging of fingerprints for data consolidation

## Integration Points

The advanced models are designed to integrate with:

1. **MetricsCollector**: Populates fingerprint metrics
2. **MLClassifier**: Provides DPI type classification
3. **FingerprintCache**: Stores and retrieves fingerprints
4. **HybridEngine**: Uses fingerprints for strategy selection
5. **ZapretStrategyGenerator**: Generates strategies based on fingerprints

## Future Extensions

The design supports future extensions through:

- `raw_metrics` field for additional custom metrics
- `analysis_methods_used` for tracking analysis techniques
- Extensible enum classes for new DPI types
- Flexible serialization format for schema evolution

## Performance Considerations

- Lightweight dataclass design for minimal memory overhead
- Efficient serialization using built-in JSON support
- Optimized merging operations for real-time updates
- Validation methods for data integrity without performance impact