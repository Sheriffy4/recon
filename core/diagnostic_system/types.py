"""
Shared Type Definitions for Diagnostic System

Provides common dataclass types used across the diagnostic system modules.
This ensures type consistency and prevents duplicate definitions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


@dataclass
class PacketProcessingEvent:
    """Event data for packet processing."""

    timestamp: float
    packet_size: int
    src_addr: str
    dst_addr: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    action: str
    technique_used: Optional[str]
    processing_time_ms: float
    error_message: Optional[str] = None
    strategy_type: Optional[str] = None
    success: bool = True


@dataclass
class TechniquePerformanceMetrics:
    """Performance metrics for bypass techniques."""

    technique_name: str
    total_applications: int
    successful_applications: int
    failed_applications: int
    avg_processing_time_ms: float
    success_rate: float
    error_patterns: List[str]
    optimal_parameters: Dict[str, Any]
    last_used: float


@dataclass
class FailurePattern:
    """Pattern analysis for failures."""

    pattern_type: str
    frequency: int
    first_occurrence: float
    last_occurrence: float
    affected_domains: Set[str]
    error_messages: List[str]
    suggested_fixes: List[str]


@dataclass
class PerformanceReport:
    """Comprehensive performance report."""

    report_timestamp: float
    total_packets_processed: int
    bypass_success_rate: float
    avg_processing_time_ms: float
    top_performing_techniques: List[str]
    problematic_techniques: List[str]
    top_performing_attacks: List[str]
    problematic_attacks: List[str]
    attack_category_performance: Dict[str, float]
    optimization_recommendations: List[str]
    system_health_score: float
