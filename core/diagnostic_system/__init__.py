"""
Diagnostic System Package

Provides comprehensive monitoring, analysis, and optimization recommendations
for byte-level DPI bypass operations with unified attack system integration.

This package has been refactored into specialized modules for better maintainability,
testability, and separation of concerns.

Modules:
--------
- metrics_manager: Attack metrics tracking and failure analysis
- packet_analyzer: Byte-level packet analysis and protocol detection
- protocol_logger: Protocol-specific logging (TLS, HTTP, QUIC)
- recommendation_engine: Optimization and troubleshooting recommendations
- attack_logger: Unified attack result logging
- error_classifier: Error categorization and pattern analysis
- report_generator: Performance report generation
- monitoring_coordinator: Real-time monitoring coordination
- statistics_manager: Statistics collection and health scoring

Main Classes:
-------------
- DiagnosticSystem: Main facade for diagnostic operations
- MetricsManager: Attack performance metrics management
- PacketAnalyzer: Packet byte-level analysis
- ProtocolLogger: Protocol-specific logging
- RecommendationEngine: Recommendation generation
- AttackLogger: Attack result logging
- ErrorClassifier: Error categorization
- ReportGenerator: Performance report generation
- MonitoringCoordinator: Monitoring coordination
- StatisticsManager: Statistics and health scoring

Data Classes:
-------------
- AttackPerformanceMetrics: Attack performance data
- AttackFailureAnalysis: Attack failure analysis data
- PacketProcessingEvent: Packet processing event data
- TechniquePerformanceMetrics: Technique performance data
- FailurePattern: Failure pattern data
- PerformanceReport: Performance report data

Usage:
------
    from core.diagnostic_system import DiagnosticSystem

    # Create diagnostic system
    diagnostic = DiagnosticSystem(attack_adapter, debug=True)

    # Start monitoring
    diagnostic.start_monitoring(fast_bypass_engine)

    # Log packet processing
    diagnostic.log_packet_processing(packet, action="bypassed", ...)

    # Generate report
    report = diagnostic.generate_performance_report()

    # Analyze effectiveness
    analysis = diagnostic.analyze_bypass_effectiveness(time_window_minutes=60)

Backward Compatibility:
-----------------------
All original APIs are preserved. The refactoring is purely structural
and maintains 100% backward compatibility with existing code.
"""

from .metrics_manager import MetricsManager, AttackPerformanceMetrics, AttackFailureAnalysis
from .packet_analyzer import PacketAnalyzer
from .protocol_logger import ProtocolLogger
from .recommendation_engine import RecommendationEngine
from .attack_logger import AttackLogger
from .error_classifier import ErrorClassifier
from .report_generator import ReportGenerator
from .monitoring_coordinator import MonitoringCoordinator
from .statistics_manager import StatisticsManager

# Import main DiagnosticSystem class from the main module
# Prefer normal import; keep sys.path hack only as fallback for legacy layouts.
try:
    from core.diagnostic_system_main import DiagnosticSystem
    from core.diagnostic_system.types import (
        PacketProcessingEvent,
        TechniquePerformanceMetrics,
        FailurePattern,
        PerformanceReport,
    )
except ImportError:  # pragma: no cover (environment/layout dependent)
    import sys
    import os

    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    from core.diagnostic_system_main import DiagnosticSystem
    from core.diagnostic_system.types import (
        PacketProcessingEvent,
        TechniquePerformanceMetrics,
        FailurePattern,
        PerformanceReport,
    )

__all__ = [
    # Main facade
    "DiagnosticSystem",
    # Component modules
    "MetricsManager",
    "PacketAnalyzer",
    "ProtocolLogger",
    "RecommendationEngine",
    "AttackLogger",
    "ErrorClassifier",
    "ReportGenerator",
    "MonitoringCoordinator",
    "StatisticsManager",
    # Data classes
    "AttackPerformanceMetrics",
    "AttackFailureAnalysis",
    "PacketProcessingEvent",
    "TechniquePerformanceMetrics",
    "FailurePattern",
    "PerformanceReport",
]

__version__ = "2.0.0"  # Major refactoring complete
__author__ = "DPI Bypass Team"
