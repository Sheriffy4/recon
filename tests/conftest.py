#!/usr/bin/env python3
"""
Pytest configuration and fixtures for reporting tests.
"""

import pytest
from datetime import datetime
from core.integration.reporting_models import AdvancedAttackReport


@pytest.fixture
def sample_attack_report():
    """Fixture providing a sample attack report."""
    return AdvancedAttackReport(
        attack_name="http_fragmentation",
        target_domain="example.com",
        dpi_type="deep_packet_inspection",
        execution_time_ms=1250.5,
        success=True,
        effectiveness_score=0.85,
        timestamp=datetime.now(),
        performance_metrics={"cpu": 45.2, "memory": 128.5},
        ml_insights={"prediction_accuracy": "accurate"},
        recommendations=["Optimize parameters", "Monitor performance"],
    )


@pytest.fixture
def sample_failed_report():
    """Fixture providing a failed attack report."""
    return AdvancedAttackReport(
        attack_name="http_fragmentation",
        target_domain="example.com",
        dpi_type="deep_packet_inspection",
        execution_time_ms=5250.0,
        success=False,
        effectiveness_score=0.25,
        timestamp=datetime.now(),
        performance_metrics={"cpu": 85.2, "memory": 256.5},
        ml_insights={"prediction_accuracy": "inaccurate"},
        recommendations=["Review configuration", "Consider alternative attack"],
    )


@pytest.fixture
def sample_performance_data():
    """Fixture providing sample performance data."""
    return {
        "attack_metrics": [
            {
                "attack_name": "http_fragmentation",
                "target_domain": "example.com",
                "timestamp": datetime.now().isoformat(),
                "success": True,
                "effectiveness_score": 0.85,
            },
            {
                "attack_name": "tcp_segmentation",
                "target_domain": "test.com",
                "timestamp": datetime.now().isoformat(),
                "success": True,
                "effectiveness_score": 0.75,
            },
            {
                "attack_name": "http_fragmentation",
                "target_domain": "example.com",
                "timestamp": datetime.now().isoformat(),
                "success": False,
                "effectiveness_score": 0.35,
            },
        ]
    }


@pytest.fixture
def multiple_attack_reports():
    """Fixture providing multiple attack reports."""
    base_time = datetime.now()
    return [
        AdvancedAttackReport(
            attack_name="http_fragmentation",
            target_domain="example.com",
            dpi_type="deep_packet_inspection",
            execution_time_ms=1250.5,
            success=True,
            effectiveness_score=0.85,
            timestamp=base_time,
            performance_metrics={},
            ml_insights={},
            recommendations=[],
        ),
        AdvancedAttackReport(
            attack_name="tcp_segmentation",
            target_domain="test.com",
            dpi_type="stateful_inspection",
            execution_time_ms=980.0,
            success=True,
            effectiveness_score=0.75,
            timestamp=base_time,
            performance_metrics={},
            ml_insights={},
            recommendations=[],
        ),
        AdvancedAttackReport(
            attack_name="http_fragmentation",
            target_domain="example.com",
            dpi_type="deep_packet_inspection",
            execution_time_ms=3500.0,
            success=False,
            effectiveness_score=0.35,
            timestamp=base_time,
            performance_metrics={},
            ml_insights={},
            recommendations=[],
        ),
    ]
