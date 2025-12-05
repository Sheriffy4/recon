"""
Core data models for test result coordination.

This module defines the data structures used by the TestResultCoordinator
to track test execution, validation, and saving operations.

Feature: strategy-testing-production-parity
Requirements: 1.1, 1.2, 8.1
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class TestVerdict(Enum):
    """
    Possible test outcomes for strategy testing.
    
    The verdict determines whether a strategy should be saved and
    represents the final determination of test success.
    """
    SUCCESS = "success"  # Strategy worked perfectly, all checks passed
    FAIL = "fail"  # Strategy failed (retransmissions >= 3 or timeout)
    PARTIAL_SUCCESS = "partial"  # Some attacks applied, not all
    MISMATCH = "mismatch"  # Declared strategy != applied strategy
    INCONCLUSIVE = "inconclusive"  # Cannot determine (no PCAP, errors, etc.)


@dataclass
class TestSession:
    """
    Tracks all data for a single strategy test.
    
    This is the central data structure that accumulates evidence
    during test execution and is used to make the final verdict.
    """
    session_id: str
    domain: str
    strategy_name: str
    pcap_file: str
    start_time: float
    
    # Task: Testing-Production Parity - track executed attacks for simple comparison
    executed_attacks: Optional[str] = None  # Final attack string from log (e.g., "split,fake")
    
    # Evidence collected during test execution
    retransmission_count: int = 0
    response_received: bool = False
    response_status: Optional[int] = None
    timeout: bool = False
    
    # Analysis results (populated after test completes)
    pcap_analysis: Optional['PCAPAnalysisResult'] = None
    validation_result: Optional['ValidationResult'] = None
    
    # Final verdict (determined by coordinator)
    verdict: Optional[TestVerdict] = None
    verdict_reason: str = ""
    
    # Metadata
    end_time: Optional[float] = None
    error: Optional[str] = None


@dataclass
class PCAPAnalysisResult:
    """
    Results from PCAP analysis.
    
    This structured result replaces the previous dict-based approach
    and ensures all components have access to the same analysis data.
    
    New fields for PCAP Validator Combo Detection (Requirements 3.1, 3.5):
    - strategy_type: The determined strategy type from detected attacks.
                     This is the primary source for StrategyValidator to determine
                     applied_strategy. Set to None only when no attacks detected.
                     Examples: "smart_combo_disorder_multisplit", "multisplit", "fakeddisorder"
    - combo_attacks: List of core attacks only (fooling attacks filtered out).
                     Used for detailed analysis and debugging.
                     Examples: ['disorder', 'multisplit'], ['fake', 'split']
    """
    pcap_file: str
    packet_count: int
    
    # Detected attacks (e.g., ['split', 'fake'])
    detected_attacks: List[str] = field(default_factory=list)
    
    # Task: Testing-Production Parity - store executed attacks from log for simple comparison
    executed_attacks_from_log: Optional[str] = None  # e.g., "split,fake"
    
    # Task: PCAP Validator Combo Detection - strategy type determination
    strategy_type: Optional[str] = None  # e.g., "smart_combo_disorder_multisplit"
    combo_attacks: List[str] = field(default_factory=list)  # Core attacks only (e.g., ['disorder', 'multisplit'])
    
    # Extracted parameters (e.g., {'split_pos': 3, 'ttl': 64})
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Evidence details
    split_positions: List[int] = field(default_factory=list)
    fake_packets_detected: int = 0
    sni_values: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_time: float = 0.0
    analyzer_version: str = "1.0"
    
    # Error tracking
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    """
    Results from strategy validation.
    
    This contains the outcome of validating that the declared strategy
    matches what was actually applied, and that all parameters were extracted.
    
    Feature: pcap-validator-combo-detection
    Requirements: 4.1, 4.4
    
    New fields for PCAP Validator Combo Detection:
    - applied_strategy_source: Tracks which source was used to determine applied_strategy.
                               Values: "metadata" (from executed_attacks_from_log),
                                      "pcap_analyzer" (from strategy_type),
                                      "reconstruction" (from detected_attacks fallback),
                                      "unknown" (default/error state)
                               This enables debugging and understanding the 3-tier priority logic.
                               (Requirement 4.1)
    - declared_normalized: The normalized version of declared_strategy used for comparison.
                          Normalization removes prefixes, sorts attacks, and applies equivalences.
                          Stored for debugging and transparency. (Requirement 4.4)
    - applied_normalized: The normalized version of applied_strategy used for comparison.
                         Stored for debugging and transparency. (Requirement 4.4)
    """
    is_valid: bool
    
    # Completeness checks
    all_attacks_applied: bool
    declared_strategy: str
    applied_strategy: str
    strategy_match: bool
    
    # Task 3.4: Source tracking for applied_strategy determination
    # Requirement 4.1: Track which source was used (metadata/pcap_analyzer/reconstruction)
    applied_strategy_source: str = "unknown"
    
    # Task 3.4: Normalization tracking
    # Requirement 4.4: Store both original and normalized names for debugging
    declared_normalized: str = ""
    applied_normalized: str = ""
    
    # Parameter validation
    parameters_extracted: bool = False
    parameter_count: int = 0
    
    # Issues found
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Missing components (for combo strategies)
    missing_components: List[str] = field(default_factory=list)


@dataclass
class SaveResult:
    """
    Result of a strategy save operation.
    
    Tracks which files were updated and whether the save was
    deduplicated (already saved).
    """
    success: bool
    files_updated: List[str] = field(default_factory=list)
    was_duplicate: bool = False
    error: Optional[str] = None
    
    # Details about what was saved
    domain: str = ""
    strategy_name: str = ""
    timestamp: float = 0.0
