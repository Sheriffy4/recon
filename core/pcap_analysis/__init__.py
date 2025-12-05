"""
Core PCAP analysis infrastructure for recon-zapret comparison.
"""

from .pcap_comparator import PCAPComparator
from .packet_info import PacketInfo, TLSInfo
from .comparison_result import ComparisonResult
from .strategy_config import (
    StrategyConfig,
    StrategyDifference,
    StrategyComparison,
    StrategyType,
    FoolingMethod,
)
from .strategy_analyzer import StrategyAnalyzer, FakeDisorderPattern
from .packet_sequence_analyzer import (
    PacketSequenceAnalyzer,
    FakePacketAnalysis,
    SplitPositionAnalysis,
)
from .critical_difference import (
    CriticalDifference,
    DifferenceCategory,
    ImpactLevel,
    FixComplexity,
    Evidence,
    DifferenceGroup,
)
from .difference_detector import DifferenceDetector, DetectionConfig
from .pattern_recognizer import (
    PatternRecognizer,
    EvasionPattern,
    FakePacketPattern,
    SplitPattern,
    Anomaly,
    PacketRole,
    EvasionTechnique,
    AnomalyType,
)
from .root_cause_analyzer import (
    RootCauseAnalyzer,
    RootCause,
    CorrelatedCause,
    Hypothesis,
    ValidatedHypothesis,
    RootCauseType,
    ConfidenceLevel,
    Evidence as RCAEvidence,
)
from .fix_generator import (
    FixGenerator,
    CodeFix,
    StrategyPatch,
    SequenceFix,
    RegressionTest,
    FixType,
    RiskLevel,
)
from .strategy_validator import (
    StrategyValidator,
    ValidationResult,
    EffectivenessResult,
    BeforeAfterComparison,
    TestDomain,
    DomainSelector,
)
from .analysis_reporter import (
    AnalysisReporter,
    ReportFormat,
    ExecutiveSummary,
    AnalysisReport,
    ReportSection,
    VisualizationType,
)
from .visualization_helper import VisualizationHelper, VisualizationData
# from .regression_tester import (
#     RegressionTester,
#     RegressionTest,
#     PerformanceMetrics,
#     RollbackInfo,
# )
from .recon_integration import ReconIntegrationManager, create_recon_integration_manager
from .enhanced_rst_compatibility import (
    EnhancedRSTCompatibilityLayer,
    create_enhanced_rst_compatibility_layer,
)
from .strategy_management_integration import (
    StrategyManagementIntegration,
    create_strategy_management_integration,
)
from .historical_data_integration import (
    HistoricalDataIntegration,
    create_historical_data_integration,
)

# Error handling and recovery
from .error_handling import (
    AnalysisError,
    PCAPParsingError,
    StrategyAnalysisError,
    FixGenerationError,
    ValidationError,
    ErrorCategory,
    ErrorSeverity,
    ErrorHandler,
    PartialResult,
    get_error_handler,
    handle_pcap_error,
    safe_execute,
)
from .graceful_degradation import (
    GracefulPCAPParser,
    PCAPFileInfo,
    get_graceful_parser,
    parse_pcap_with_fallback,
)
from .diagnostics import (
    DiagnosticChecker,
    PerformanceMonitor,
    DebugLogger,
    SystemMetrics,
    PerformanceProfile,
    DiagnosticResult,
    get_diagnostic_checker,
    get_performance_monitor,
    get_debug_logger,
    run_system_diagnostics,
    debug_operation,
)
from .logging_config import (
    setup_logging,
    get_logger,
    get_contextual_logger,
    log_operation_start,
    log_operation_end,
    log_error_with_context,
    log_performance_metric,
)

__all__ = [
    "PCAPComparator",
    "PacketInfo",
    "TLSInfo",
    "ComparisonResult",
    "StrategyConfig",
    "StrategyDifference",
    "StrategyComparison",
    "StrategyType",
    "FoolingMethod",
    "StrategyAnalyzer",
    "FakeDisorderPattern",
    "PacketSequenceAnalyzer",
    "FakePacketAnalysis",
    "SplitPositionAnalysis",
    "CriticalDifference",
    "DifferenceCategory",
    "ImpactLevel",
    "FixComplexity",
    "Evidence",
    "DifferenceGroup",
    "DifferenceDetector",
    "DetectionConfig",
    "PatternRecognizer",
    "EvasionPattern",
    "FakePacketPattern",
    "SplitPattern",
    "Anomaly",
    "PacketRole",
    "EvasionTechnique",
    "AnomalyType",
    "RootCauseAnalyzer",
    "RootCause",
    "CorrelatedCause",
    "Hypothesis",
    "ValidatedHypothesis",
    "RootCauseType",
    "ConfidenceLevel",
    "RCAEvidence",
    "FixGenerator",
    "CodeFix",
    "StrategyPatch",
    "SequenceFix",
    "RegressionTest",
    "FixType",
    "RiskLevel",
    "StrategyValidator",
    "ValidationResult",
    "EffectivenessResult",
    "BeforeAfterComparison",
    "TestDomain",
    "DomainSelector",
    "AnalysisReporter",
    "ReportFormat",
    "ExecutiveSummary",
    "AnalysisReport",
    "ReportSection",
    "VisualizationType",
    "VisualizationHelper",
    "VisualizationData",
    # "RegressionTester",
    # "RegressionTest",
    # "PerformanceMetrics",
    # "RollbackInfo",
    "ReconIntegrationManager",
    "create_recon_integration_manager",
    "EnhancedRSTCompatibilityLayer",
    "create_enhanced_rst_compatibility_layer",
    "StrategyManagementIntegration",
    "create_strategy_management_integration",
    "HistoricalDataIntegration",
    "create_historical_data_integration",
    # Error handling and recovery
    "AnalysisError",
    "PCAPParsingError",
    "StrategyAnalysisError",
    "FixGenerationError",
    "ValidationError",
    "ErrorCategory",
    "ErrorSeverity",
    "ErrorHandler",
    "PartialResult",
    "get_error_handler",
    "handle_pcap_error",
    "safe_execute",
    # Graceful degradation
    "GracefulPCAPParser",
    "PCAPFileInfo",
    "get_graceful_parser",
    "parse_pcap_with_fallback",
    # Diagnostics
    "DiagnosticChecker",
    "PerformanceMonitor",
    "DebugLogger",
    "SystemMetrics",
    "PerformanceProfile",
    "DiagnosticResult",
    "get_diagnostic_checker",
    "get_performance_monitor",
    "get_debug_logger",
    "run_system_diagnostics",
    "debug_operation",
    # Logging
    "setup_logging",
    "get_logger",
    "get_contextual_logger",
    "log_operation_start",
    "log_operation_end",
    "log_error_with_context",
    "log_performance_metric",
]
