#!/usr/bin/env python3
"""
Data models for advanced reporting system.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Any


@dataclass
class AdvancedAttackReport:
    """Report for advanced attack execution."""

    attack_name: str
    target_domain: str
    dpi_type: str
    execution_time_ms: float
    success: bool
    effectiveness_score: float
    timestamp: datetime
    performance_metrics: Dict[str, Any]
    ml_insights: Dict[str, Any]
    recommendations: List[str]


@dataclass
class SystemPerformanceReport:
    """System-wide performance report."""

    report_period: str
    total_attacks: int
    successful_attacks: int
    average_effectiveness: float
    performance_trends: Dict[str, Any]
    top_performing_attacks: List[str]
    problematic_targets: List[str]
    system_health_score: float
    recommendations: List[str]
